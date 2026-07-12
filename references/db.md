# db group — Postgres over an ssh alias

Deep reference for `src/db.ts` + `src/targets.ts`, which back the `db` group. v1 is
**Postgres-only, read-only**.

## The pg-target model

A `<pg-target>` is the `db` group's equivalent of an ssh alias: a name declared once in
`~/.config/sshepherd/targets.toml` (override via `SSHEPHERD_TARGETS_PATH`, tests only) that
resolves to *how* to reach `psql` on a host — never a database password.

```toml
# Compose-hosted Postgres:
[prod]
alias = "lms-server"                        # ssh alias this pg-target rides on
compose_file = "/opt/lms/docker-compose.yml" # path to the compose file ON THE REMOTE
service = "db"                               # compose service name for the db container
user = "sshepherd_ro"                        # read-only role — see below
database = "lms"

# Plain-container Postgres:
[staging]
alias = "staging-1"
container = "staging_postgres_1"             # container name or ID ON THE REMOTE
user = "sshepherd_ro"
database = "app"
```

A target declares either `{compose_file, service}` or `{container}` — never both
(`readTarget` in `targets.ts` throws if a target declares both, or neither). Missing
`targets.toml` yields an empty target map, same missing-config behavior as
`~/.ssh/config` for the `hosts` group — every target refused until declared.

`buildDbOpContext(targetName, extraArgs)` resolves the target and returns an `OpContext`
whose `alias` is the target's ssh alias and whose `args` carry the connection fields
flattened (`compose_file`, `service`, `container`, `db_user`, `db_name`) alongside
whatever the CLI already collected — so a `db` op's `buildRemote` stays a pure function of
`ctx`, exactly like every other op in the registry.

## Password handling

sshepherd never transports a database password, full stop. The client (`psql`) runs
**inside the container** via `docker exec`/`docker compose exec`, so auth is whatever that
container already trusts: Postgres `peer`/`trust` auth for the exec'd user, or a
`~/.pgpass` file already present on the remote (baked into the image or a mounted volume)
that `psql` reads on its own. If neither is configured, `psql` prompts for a password and
the non-interactive `-qAt -c` invocation simply fails — set up peer/trust or `.pgpass` on
the target *before* declaring it in `targets.toml`.

Running the client on the remote (rather than tunneling a local connection) is also why
sshepherd never needs to expose the database on a published port — a compose-hosted
Postgres usually has none, and running remotely means one never needs to open one either.

## Read-only enforcement — three layers, only the first is your responsibility

1. **Read-only DB role (the real boundary, engine-side).** The `user` declared on a target
   should be a role with SELECT-only grants:
   ```sql
   CREATE ROLE sshepherd_ro WITH LOGIN;
   GRANT pg_read_all_data TO sshepherd_ro;                    -- PG14+
   ALTER ROLE sshepherd_ro SET default_transaction_read_only = on;
   ```
   This is the layer that actually catches a writable CTE (`WITH x AS (INSERT ...)
   SELECT ...`) or a volatile function — no client-side parser can reliably detect either.
2. **`wrapReadOnlyTxn`** — every query sshepherd sends is wrapped in
   `BEGIN TRANSACTION READ ONLY; <sql>; ROLLBACK;`. Defense in depth, **not** a
   substitute for layer 1: Postgres itself documents that a session can revoke read-only
   on itself mid-transaction.
3. **`assertSelectOnly`** (pure-JS `node-sql-parser`, never `libpg_query` — native
   bindings pull a `.node` addon that breaks `bun build --compile`, same reasoning as
   avoiding `ssh2`) — a fast, friendly local rejection of an unambiguously non-SELECT
   top-level statement (`INSERT`/`UPDATE`/`DELETE`/DDL/...). This is a **UX guardrail
   only**: a writable CTE parses as `select` at the top level and passes this check on
   purpose (it's caught by layer 1 instead), and a statement the parser can't parse at all
   is let through rather than blocked, because the parser must never reject a legitimate
   SELECT it doesn't understand.

`assertNoMultiStatementSql` is a separate, narrower guard that applies **only** to
`db query`'s free-text `sql` argument (never to sshepherd's own static SQL for
`tables`/`activity`/`connections`/`slow`/`size`, which legitimately contains `;`): any bare
`;` in the input is rejected outright, before `node-sql-parser` or the `json_agg` wrapper
ever see the string. This closes a specific injection shape — a payload closing
`wrapAsJsonAgg`'s `FROM (<sql>) t` parenthesis early and appending a bare `COMMIT` to end
the read-only transaction before injected DDL/DML runs, which `node-sql-parser` would
throw on and `assertSelectOnly`'s catch-and-pass-through would then let through unblocked.
A legitimate single ad hoc SELECT never needs a `;`, so rejecting it outright is safe.

## Output shapes per op

All sizes are in **bytes**, never a human string like `3.9Gi`.

| Op | Shape |
|---|---|
| `db list` | `{ targets: string[] }` — target *names* only, host-local, no ssh call |
| `db tables` | `Array<{ schema, table, size_bytes }>` — every user table, indexes+toast included, sorted largest-first |
| `db activity` | `{ backends_total, max_connections, backends: Array<{pid, usename, application_name, state, query_start, query_seconds, wait_event, blocked_by: number[]}> }` — `blocked_by` comes from `pg_blocking_pids(pid)` |
| `db connections` | `{ backends_total, max_connections, by_state: Record<string, number> }` |
| `db slow` | `{ available, reason, queries: [...] }` — `available: false` with a `reason` string when `pg_stat_statements` isn't installed (checked in a separate round trip before ever referencing the extension, because Postgres validates catalog references at parse time even inside an untaken branch); otherwise the top 20 queries by `mean_exec_time` |
| `db size` | `{ databases: Array<{ datname, size_bytes }> }` — every non-template database |
| `db query` | a bare JSON array — whatever the `SELECT` returns, via `json_agg` |

`wrapAsJsonAgg` turns zero result rows into SQL `NULL`, which `psql -qAt` prints as an
empty string — `parseJsonArray` in `registry.ts` normalizes that back to `[]`.

## `-qAt` and why the transaction doesn't leak noise

`buildPsqlCommand` always passes `-v ON_ERROR_STOP=1 -qAt`: `-q` (quiet) suppresses the
`BEGIN`/`ROLLBACK` command-completion tags the read-only transaction wrapper adds, `-A`
unaligned and `-t` tuples-only leave exactly the query's own output — one clean JSON value
per call. `ON_ERROR_STOP=1` makes `psql` abort the whole `-c` buffer, including the
trailing `ROLLBACK`, the instant the engine rejects a write inside the transaction — the
error surfaces as a normal `COMMAND_FAILED`, not a silent partial success.

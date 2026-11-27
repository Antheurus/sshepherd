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
alias = "web-01"                        # ssh alias this pg-target rides on
compose_file = "/opt/myapp/docker-compose.yml" # path to the compose file ON THE REMOTE
service = "db"                               # compose service name for the db container
user = "sshepherd_ro"                        # read-only role — see below
database = "myapp"

# Plain-container Postgres:
[staging]
alias = "staging-1"
container = "staging_postgres_1"             # container name or ID ON THE REMOTE
user = "sshepherd_ro"
database = "app"
```

Two more `kind`s reach psql another way:

```toml
# The app container's DATABASE_URL, read inside one remote shell and decoded into PG* env vars,
# so the URL never reaches sshepherd, an argv (`ps`) or the audit log. psql runs in
# psql_container when the app image has none (default: the container itself).
[app]
alias = "myserver"
kind = "container-env"
container = "app_web_1"
env_key = "DATABASE_URL"          # default
psql_container = "app_db_1"       # optional

# psql installed on the host; sudo_user for peer auth, pg_host/pg_port for TCP.
[hostdb]
alias = "myserver"
kind = "host"
sudo_user = "postgres"            # optional
user = "sshepherd_ro"
database = "app"
```

`setup db-target ro-role <target> --print-sql` prints the SQL that creates a read-only LOGIN role
(`USAGE` on schema `public`, `SELECT` on its tables and the matching default privileges,
`default_transaction_read_only`, statement/lock/temp-file limits) and the checks that prove it; a
human applies it, sshepherd never does. That default keeps `pg_authid` (every role's password
verifier) out of reach. `--all-data` prints the `pg_read_all_data` variant instead, which reads every
table, the system catalogs and `pg_authid` included; its SQL says so, and says that `db query`
masks `rolpassword`/`passwd` only by column name, so a function-wrapped read (`substr`, `encode`,
`replace` of `rolpassword`) comes back unmasked. `--tables-only` is still accepted and means the
default. `doctor` lists the targets whose `user` does not name such a role under
`pg_targets_without_ro_role`.

A table with only `alias` and `containers` is not a pg-target: it declares the containers whose env
key names `env keys --container` and `services inspect` may read. `db list` leaves it out, and a db
op (or `ro-role`) naming it is refused with `VALIDATION_ERROR`.

Two optional fields work on every kind:

- `deny_columns = ["regex", ...]` — `db query` replaces the value of every column whose name
  matches one of these (case-insensitive) with `***` after the rows arrive, and lists those
  columns in `masked_columns`. Absent, the default list applies:
  `pass(word)?|secret|token|api_?key|private_?key|credential|salt|hash` and `rolpassword|passwd`
  (Postgres's own verifier columns). A list here replaces the default, so copy the entries you
  want to keep; an empty list is refused.
- `containers = ["name", ...]` — the containers on this target's ssh alias whose env key names
  `env keys <alias> --container <name>` may read. The lists of every target on one alias add up;
  an undeclared container is a `VALIDATION_ERROR` before any ssh call.

A `container` target declares either `{compose_file, service}` or `{container}` — never both
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
   GRANT USAGE ON SCHEMA public TO sshepherd_ro;
   GRANT SELECT ON ALL TABLES IN SCHEMA public TO sshepherd_ro;
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

`assertSelfContainedSql` is the second guard on `db query`'s `sql`: the statement runs inside
`SELECT json_agg(t) FROM (\nSELECT * FROM (\n<sql>\n) sshepherd_q LIMIT n\n) t`, each wrapper
part on its own line so a trailing `--` comment ends at the newline after the caller's text. The
guard scans the text with Postgres's lexical rules — `'...'` strings (doubled quotes), `E'...'`
(backslash escapes, also in every `'...'` segment that continues it after a newline), dollar quotes, `"quoted"` names, `--` comments ending at `\n` or `\r`, nested
`/* */` comments — and refuses (`VALIDATION_ERROR`, no ssh call) a statement that closes a
parenthesis it never opened (`... FROM big) sshepherd_q) t, (SELECT (SELECT 1` would otherwise
aggregate every row past the limit) or leaves a string, quoted name, dollar quote, `/*` comment or
parenthesis open for the wrapper's tail to fall into. The session buffer pins
`standard_conforming_strings = on`, so a backslash inside a plain string means the same to the
server as to the scan. The row cap still rests on that scan: a `FETCH n` from a cursor would cap
rows without it, but `db query` returns one `json_agg` value, and a cursor's rows cannot be
aggregated back into one in plain SQL, so moving to it changes the op's output path. The
read-only transaction does not rest on the scan at all (`;` is refused outright).

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
| `db query` | `{ rows, row_count, truncated, masked_columns }` — at most `--max-rows` rows (default 500, max 10,000) of whatever the `SELECT` returns, via `json_agg`; `truncated: true` when the query had more; `masked_columns` names the columns whose values `deny_columns` masked (`[]` when none). **Shape change:** before 0.4.0 `data` was the bare row array; read `data.rows` now (`--fields data.rows` keeps just the rows) |
| `db describe` | `{ schema, table, columns: [{name, type, nullable, default}], indexes: [{name, unique, primary, definition}], foreign_keys: [{name, columns, references_table, references_columns, definition}] }` — an unknown table is a `VALIDATION_ERROR` naming `db tables` |
| `db count` | `{ count }` — `count(*)` of the table, `--where-eq col=value` for one equality filter (the column becomes a quoted identifier, the value a literal) |
| `db migrations` | `{ tables: [{framework, table, current, migrations: [{name, applied_at}], pending}] }` — newest 50 per table, from whichever of `_prisma_migrations`, `knex_migrations`, `migrations_typeorm`, `schema_migrations` (rails) and `migrations` (laravel) exist (`--table <name>` reads just that one, schema-qualified if need be; an absent one is a `VALIDATION_ERROR`); `current` is the newest applied name (null for an empty table); `applied_at` is null where the table keeps no time. `pending` is null unless `--dir <remote dir>` (files-allowlist.toml, exact entry) is given: then it lists the directory's entries that start with a digit and match no applied name — by the name itself, the name less its extension, or its leading version (rails `20260901000000_x.rb`, typeorm `1700000000000-Init.ts` against `Init1700000000000`). Past 10,000 applied names or entries the op refuses with `OUTPUT_TOO_LARGE` rather than report a partial list |

Every bounded read (`query`, `describe`, `count`, `migrations`) sends `SET statement_timeout`/`SET
lock_timeout` as its own psql buffer before the read-only transaction. The statement limit is the
call's budget (`--timeout`, default 75 s for `query`, 60 s for the others) less 15 s, so Postgres
cancels a runaway statement itself and the envelope says `COMMAND_TIMEOUT` with
`Postgres cancelled the statement at statement_timeout (60 s)`; a lock wait past 2 s is a
`COMMAND_TIMEOUT` naming `lock_timeout`.

`wrapAsJsonAgg` turns zero result rows into SQL `NULL`, which `psql -qAt` prints as an
empty string — `parseJsonArray` in `registry.ts` normalizes that back to `[]`.

## `-qAt` and why the transaction doesn't leak noise

`buildPsqlCommand` always passes `-v ON_ERROR_STOP=1 -qAt`: `-q` (quiet) suppresses the
`BEGIN`/`ROLLBACK` command-completion tags the read-only transaction wrapper adds, `-A`
unaligned and `-t` tuples-only leave exactly the query's own output — one clean JSON value
per call. `ON_ERROR_STOP=1` makes `psql` abort the whole `-c` buffer, including the
trailing `ROLLBACK`, the instant the engine rejects a write inside the transaction — the
error surfaces as a normal `COMMAND_FAILED`, not a silent partial success.

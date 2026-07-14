---
name: sshepherd
description: Use this skill whenever the user mentions "sshepherd" by name, or wants to check on a remote server (health, disk, memory, CPU, ports, OOM history), inspect or restart docker/systemd services, tail remote logs, read or write remote config files, deploy a project via a named recipe, introspect a remote Postgres database, or audit SSH/security posture on a box — while keeping the agent zero-knowledge about credentials (no password, private key, or host/user/port ever reaches the agent's context or a tool response). Covers all 9 registry-driven command groups (hosts, check, logs, services, deploy, config, db, files, security) via a single compiled Bun/TypeScript CLI that shells out to the system `ssh` binary — the agent only ever passes an ssh alias, a pg-target name, or a recipe name, never a credential. `setup` is a separate group (deliberately not one of the 9) that writes sshepherd's own local config files; every `setup` action is agent-invocable, with one narrow exception — `setup ssh-alias install` opens a one-shot browser form that only a human can type a password into.
---

# sshepherd

`sshepherd` is a compiled Bun/TypeScript CLI for server operations over SSH — health
checks, service/container control, log tailing, config edits, Postgres introspection, and
declarative deploys — built so an agent can drive a real server without ever seeing a
password, private key, host, user, or port. Every op resolves through an ssh alias already
configured in `~/.ssh/config` (or a `db`-group pg-target / `deploy`-group recipe name that
itself resolves to an alias); OpenSSH does the actual authentication, entirely outside this
process.

**Binary:** `/Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd/dist/sshepherd`

If the binary is missing, build it first:

```bash
cd /Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd && just build
```

Call the binary by its absolute path — it is not on `PATH`. Every example below uses the
bare `sshepherd` name for brevity; substitute the absolute path when invoking.

**Deep references (read on demand, not upfront):**

- `references/transport.md` — the zero-knowledge SSH model, ControlMaster lifecycle,
  the error classification enum, why stderr is discarded entirely.
- `references/recipes.md` — the TOML deploy-recipe format, every step kind, `depends_on`
  ordering, the `[rollback]` block, `--dry-run` plan shape, a complete worked recipe.
- `references/db.md` — the pg-target model, read-only enforcement layers, the `db` ops'
  output shapes, why `db query` rejects multi-statement SQL.
- `references/output-shapes.md` — the `Envelope` shape, log-line objects, verdict fields,
  the `ErrorInfo` shape — read this before parsing any command's `data`.

## The zero-knowledge model

The agent never types, sees, or passes a hostname, IP, username, port, password, or private
key through sshepherd — not as an argument, not in a response.

- The agent passes only a **name**: an ssh alias (`lms-server`), a pg-target name (`prod`),
  or a recipe name (`demo`). Every alias/target/recipe is declared once, ahead of time, in
  `~/.ssh/config`, `~/.config/sshepherd/targets.toml`, or a recipe TOML — never on the
  command line.
- OpenSSH resolves the real connection tuple (`HostName`/`User`/`Port`/`IdentityFile`)
  internally; sshepherd shells out to the system `ssh` binary (never the `ssh2` npm
  library) so credential handling stays entirely inside OpenSSH's own trusted code path.
- Every response `Envelope` echoes back only the `alias` it was given — there is no
  host/user/port/ip field anywhere in the response shape, structurally.
- ssh's own stderr is discarded entirely (never surfaced, never logged) — it's classified
  into a small error enum instead, because OpenSSH's stderr phrasing varies by
  version/locale and can leak a hostname no redaction allowlist would catch.
- `hosts list` returns alias *names* only, never `HostName`/`User`/`Port`.
- `.env`-shaped files (`files cat`) are masked by default (`KEY=***MASKED***`); an agent
  must pass `--reveal KEY1,KEY2` to unmask specific keys.
- `files download` writes the remote file straight to a local destination path and never
  returns its content in the JSON envelope — the safe way to pull any secrets-bearing file
  to disk (see Gotchas #10 for the incident this closed).
- Every mutating op writes an audit line (`~/.local/state/sshepherd/audit.jsonl`) —
  timestamp, alias, command, an arg hash (not raw args), and outcome — success or failure.

## Command shape

```
sshepherd <group> <action> [positionals...] [--flag value]
```

```bash
sshepherd --help                # lists 9 registry groups + the setup group
sshepherd <group> --help        # lists that group's actions + args/flags
sshepherd <group> <action> --help   # shows one action's args
```

The **first positional** differs by group:

| Group | First positional | Resolves via |
|---|---|---|
| `db` (except `list`) | `<target>` — a pg-target name from `targets.toml` | `targets.ts` |
| `deploy` (all actions) | `<recipe>` — a recipe name | `recipes.ts` |
| `hosts list`, `db list` | *(none — host-local, no ssh)* | — |
| every other group | `<alias>` — an ssh alias from `~/.ssh/config` | — |

## Global flags

| Flag | Effect |
|---|---|
| `--yes` | confirm a mutating op — required; sshepherd never prompts interactively |
| `--dry-run` | `deploy run` only: print the resolved plan, execute nothing, no `--yes` needed |
| `--pretty` | render a human table/key-value view instead of JSON |
| `--reveal <keys>` | `files cat` only: comma-separated env-var keys to unmask |
| `--from <path>` | `config put` only: local file to read + base64-encode (instead of typing `--content-base64` by hand) |

Output is JSON to stdout by default (one `Envelope` per call — see `references/output-shapes.md`).
Exit codes: `0` success, `1` the op ran and failed (transport/command error, or a refused
`CONFIRMATION_REQUIRED`), `2` a usage error (unknown group/action, missing required
argument — no ssh connection was attempted).

## Quick reference — 9 registry-driven groups (52 ops) + 1 `setup` group (4 sub-groups, 7 actions)

```bash
# hosts
sshepherd hosts list
sshepherd hosts test lms-server
sshepherd hosts info lms-server

# check
sshepherd check overview lms-server
sshepherd check mem lms-server
sshepherd check disk lms-server
sshepherd check cpu lms-server
sshepherd check ports lms-server
sshepherd check oom-history lms-server
sshepherd check kernel lms-server

# logs
sshepherd logs docker lms-server lms-app --tail 100
sshepherd logs service lms-server nginx --tail 100
sshepherd logs docker-daemon lms-server --tail 100
sshepherd logs nginx lms-server error --tail 100

# services
sshepherd services ps lms-server
sshepherd services stats lms-server
sshepherd services inspect lms-server lms-app
sshepherd services compose-ps lms-server /opt/lms/docker-compose.yml
sshepherd services healthcheck lms-server lms-app
sshepherd services systemctl-status lms-server nginx
sshepherd services restart lms-server lms-app --yes
sshepherd services systemctl-start lms-server nginx --yes
sshepherd services systemctl-stop lms-server nginx --yes
sshepherd services systemctl-restart lms-server nginx --yes
sshepherd services systemctl-reload lms-server nginx --yes

# files
sshepherd files ls lms-server /opt/lms
sshepherd files cat lms-server /opt/lms/.env --reveal DB_HOST
sshepherd files tail lms-server /var/log/syslog --n 100
sshepherd files download lms-server /opt/lms/backup.sql ./backup.sql
sshepherd files disk-usage lms-server /var/lib/docker
sshepherd files upload lms-server ./local.conf /opt/lms/local.conf --yes

# config
sshepherd config get lms-server /etc/nginx/nginx.conf
sshepherd config validate lms-server /etc/nginx/nginx.conf
sshepherd config put lms-server /etc/nginx/nginx.conf --from ./nginx.conf --yes
sshepherd config reload lms-server nginx --yes

# db
sshepherd db list
sshepherd db tables prod
sshepherd db activity prod
sshepherd db connections prod
sshepherd db slow prod
sshepherd db size prod
sshepherd db query prod "SELECT count(*) FROM users"

# deploy
sshepherd deploy run demo --dry-run
sshepherd deploy run demo --yes
sshepherd deploy status demo
sshepherd deploy rollback demo --yes
sshepherd deploy logs demo --tail 100
sshepherd deploy migrate demo --yes

# security
sshepherd security harden lms-server --yes
sshepherd security ssh-audit lms-server
sshepherd security listeners lms-server
sshepherd security authorized-keys lms-server
sshepherd security fail2ban lms-server

# setup — agent-invocable; install's password boundary is the one exception (see Gotchas #9)
sshepherd setup ssh-alias register myserver --host 1.2.3.4 --user deploy --yes
sshepherd setup ssh-alias keygen myserver --yes
sshepherd setup ssh-alias install myserver --yes
sshepherd setup ssh-alias remove myserver --yes
sshepherd setup db-target scaffold prod --alias myserver --user app --database appdb --container app_db --yes
sshepherd setup config-allowlist scaffold myserver --paths /etc/nginx/nginx.conf,/opt/app/.env --yes
sshepherd setup deploy-recipe scaffold demo --alias myserver --workdir /opt/app --yes
```

## Gotchas

1. **Zero-knowledge is not optional per-call.** There is no flag to pass a raw host/user/
   port/password — the only way to reach a server is to declare it as an ssh alias (or a
   pg-target/recipe pointing at one) ahead of time, outside this tool.
2. **Every mutating op needs `--yes`, always writes an audit line.** sshepherd never
   prompts interactively (agent-first design) — without `--yes` a mutating op returns a
   `CONFIRMATION_REQUIRED` envelope and refuses before touching ssh. Success *and* failure
   both get an audit line in `~/.local/state/sshepherd/audit.jsonl`.
3. **No raw exec, ever.** There is no `sshepherd exec "<any command>"`. A genuinely novel
   need is authored as a named, versioned recipe step (`references/recipes.md`) —
   reviewable, not a free-text shell escape hatch. `plain ssh <alias>` remains the
   intentional human break-glass for one-off exploration.
4. **`deploy rollback` refuses without a `[rollback]` block.** A recipe that doesn't
   declare one has no inferred rollback — sshepherd never guesses.
5. **`config put` backs up before writing, always.** The existing file is copied to
   `<path>.bak-<UTC-timestamp>` in the same remote round trip, before the overwrite.
   `config put` also refuses any path not declared on that alias's allowlist
   (`~/.config/sshepherd/config-allowlist.toml`) — a local refusal, before any ssh call.
6. **`db` is Postgres-only, read-only, v1.** `db query` takes a single `SELECT` — a bare
   `;` is rejected before the SQL is even parsed (multi-statement guard), on top of a
   parser check and a `BEGIN TRANSACTION READ ONLY` wrapper. The real boundary is the
   read-only DB role declared on the target (`references/db.md`) — treat the client-side
   checks as UX guardrails, not the security boundary.
7. **A deploy failure names the step that failed.** `deploy run`/`deploy migrate` surface
   `data.failed_step` (`{index, kind, name}`) on a `COMMAND_FAILED` error, recovered from a
   marker each step echoes on non-zero exit — never guess which step broke from the raw
   output alone.
8. **`security harden` won't lock out the current session unless told to.** Directives
   that could disable the session's own auth method (`PermitRootLogin`,
   `PasswordAuthentication`) are only applied when `--keep-session=false` is passed
   explicitly; the safe subset always applies.
9. **`setup`'s only wall is `install`'s password.** `register`, `keygen`, `remove`,
   `install`, and the three scaffolders (`db-target`, `config-allowlist`, `deploy-recipe`)
   are all agent-invocable, gated by `--yes` the same way as every other mutating op — none
   of them needs a human at the keyboard. The one narrow exception is
   `ssh-alias install`: it opens a one-shot local browser form and a *human*, not the agent,
   types the password into it. The agent may trigger `install` and wait on it, but it
   structurally cannot see, log, or relay that password — the password goes straight from
   the browser submission into `sshpass`'s stdin and never crosses back into the agent's
   context; the agent only ever receives the resulting `SetupResult` (success or a typed
   error code), never the password itself.
10. **`files download` used to inline the whole file as base64 in the JSON envelope —
    fixed, but treat any `dist/sshepherd` built before this fix as unsafe on secrets.** A
    real incident: an
    agent ran `files download <alias> <remote .env.docker path> /tmp/dest.tmp` expecting
    scp-like behavior (write to `/tmp/dest.tmp`, never see the bytes). The old
    implementation took only one positional (`<path>`, remote-only) — the local
    destination the agent typed was silently discarded (`mapArgsToCtx` ignores extra
    positionals with no error), and the entire file was base64-encoded into
    `data.content_base64` in the envelope printed to stdout, i.e. straight into the
    agent's tool-result context, in a trivially-reversible encoding (`base64 -d`, no
    special access needed). Unlike `files cat`, the old `files download` applied **no**
    `.env` masking at all — it inlined any file's raw bytes regardless of shape, up to the
    10 MiB `DOWNLOAD_MAX_BYTES` guard (above that it refused with `truncated: true`, not a
    partial leak). This defeated the zero-knowledge promise for exactly the op whose name
    most strongly implies "goes to disk, not to you." Fixed in `src/registry.ts`
    (`filesDownload`): the op now takes **two** required positionals — `<path>` (remote
    source) `<local_path>` (local destination) — and `shape()` decodes the base64 and
    `writeFileSync`s it straight to `local_path` inside the CLI process; the envelope's
    `data` is now `{found, truncated, size_bytes, written, local_path}` with **no**
    `content_base64` field, ever. The raw bytes still transit the ssh channel and briefly
    sit in local process memory to decode — that's the same local-process exposure
    `files cat` already has before masking runs, not a new one; what changed is that the
    content never crosses back into the envelope the agent reads. If a script or an older
    compiled `dist/sshepherd` binary predates this fix, do not point `files download` at
    any `.env`-shaped, key, or credential file until confirmed rebuilt — check the
    envelope's `data` keys: `content_base64` present means the vulnerable version is
    running.

## Errors

| Code | Meaning |
|---|---|
| `UNKNOWN_ALIAS` | the ssh alias isn't defined in `~/.ssh/config` |
| `CONNECT_TIMEOUT` | couldn't reach the host within the connect timeout |
| `AUTH_FAILED` | SSH authentication failed for this alias |
| `HOST_KEY_MISMATCH` | the remote host key doesn't match the known-hosts entry |
| `SSH_TRANSPORT_ERROR` | ssh failed before the remote command could run, unclassified |
| `COMMAND_FAILED` | the remote command exited non-zero (`error.remote_exit` carries the code) |
| `COMMAND_TIMEOUT` | the remote command exceeded its timeout |
| `CONFIRMATION_REQUIRED` | a mutating op ran without `--yes` — refused before any ssh call |

Exit codes: `0` on `ok: true`; `1` when the envelope's `ok` is `false` (any code above);
`2` on a usage error (unknown group/action, missing required argument) — no ssh connection
is ever attempted for an exit-`2`.

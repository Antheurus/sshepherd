---
name: sshepherd
description: >-
  Use this skill whenever the user mentions "sshepherd" by name, or wants to check on a remote server
  (health, disk, memory, CPU, ports, OOM history), inspect or restart docker/systemd services, tail
  remote logs, read or write remote config files, deploy a project via a named recipe, introspect a
  remote Postgres database, or audit SSH/security posture on a box. Indonesian triggers: "cek server",
  "server gua kenapa", "servernya down", "disk penuh", "restart service", "liat log server", "deploy ke
  server", "ssh ke", "cek RAM server", "kenapa lemot servernya", "port apa aja yang kebuka". Keeps the
  agent zero-knowledge about credentials — no password, private key, or host/user/port ever reaches the
  agent context or a tool response. Covers all 16 registry-driven command groups (hosts, check, logs,
  services, files, env, config, db, deploy, security, tunnel, audit, http, wait, git, exec) via a single compiled
  Bun/TypeScript CLI that shells out to the system ssh binary; the agent only ever passes an ssh alias, a pg-target name, or a recipe
  name. setup is a separate group that writes sshepherd own local config files; every setup action is
  agent-invocable except setup ssh-alias install, which opens a one-shot browser form only a human can
  type a password into.
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
key through sshepherd — not as an argument, not in a response — with one narrow, scoped
exception noted below.

- The agent passes only a **name**: an ssh alias (`web-01`), a pg-target name (`prod`),
  or a recipe name (`demo`). Every alias/target/recipe is declared once, ahead of time, in
  `~/.ssh/config`, `~/.config/sshepherd/targets.toml`, or a recipe TOML — never on the
  command line.
- OpenSSH resolves the real connection tuple (`HostName`/`User`/`Port`/`IdentityFile`)
  internally; sshepherd shells out to the system `ssh` binary (never the `ssh2` npm
  library) so credential handling stays entirely inside OpenSSH's own trusted code path.
- Every response `Envelope` echoes back only the `alias` it was given — there is no
  host/user/port/ip field anywhere in the response shape, structurally.
- The one scoped exception: `setup ssh-alias status <alias>` echoes that alias's own
  `host`/`user`/`port` (plus `hasKey`) back in `data` — not new exposure, since the caller
  already supplied those same values to `register` in the first place. `setup ssh-alias
  list` stays name-only, and every other command in the tool, including all 11 registry
  groups, still returns only the alias/target/recipe name.
- ssh's own stderr is discarded entirely (never surfaced, never logged) — it's classified
  into a small error enum instead, because OpenSSH's stderr phrasing varies by
  version/locale and can leak a hostname no redaction allowlist would catch.
- `hosts list` and `setup ssh-alias list` return alias *names* only, never
  `HostName`/`User`/`Port`.
- Every `files` op (`ls`/`cat`/`tail`/`download`/`disk-usage`/`upload`) refuses any remote
  path not pre-declared for that alias in `~/.config/sshepherd/files-allowlist.toml` —
  fail-closed, same rule as `config get`/`put`/`validate` and `config-allowlist.toml`. See
  Gotchas #11. `logs compose`'s project directory is checked against the same file (on, or
  under, a declared entry), and must hold its own `compose.yaml`/`compose.yml`/`docker-compose.y(a)ml`:
  without one the op fails (`no configuration file provided`) instead of reading a parent's.
- Secret-shaped files — a basename containing `.env` (`.env`, `.env.local`, `prod.env`), ending
  `.vars`/`.secrets`, `credentials*`, `*.pem`, `id_*` — are masked by default
  (`KEY=***MASKED***`, `export` and quoted/continued values included) in `files cat`, `files tail`,
  `files download` (the bytes written to disk) and `config get`; an agent
  must pass `--reveal KEY1,KEY2` (`files cat`/`files download`) to unmask specific keys, and each key must clear a
  hardcoded secret-pattern denylist (`PASSWORD`, `SECRET`, `TOKEN`, `PRIVATE_KEY`,
  `CREDENTIAL`, `API_KEY`, ...) *and* be pre-declared in
  `~/.config/sshepherd/reveal-allowlist.toml` — the denylist wins even over a mistaken
  allowlist entry. See Gotchas #11.
- `files download` writes the remote file straight to a local destination path and never
  returns its content in the JSON envelope — the safe way to pull any secrets-bearing file
  to disk (see Gotchas #10 for the incident this closed).
- Every mutating op writes an audit line (`~/.local/state/sshepherd/audit.jsonl`) —
  timestamp, alias, command, an arg hash (not raw args), and outcome — success or failure.
  `SSHEPHERD_STATE_DIR` moves the directory, `SSHEPHERD_AUDIT_PATH` names the file; both are read on
  every call.
- `tunnel open`'s `--remote`/`--local` flags describe the forward target/exposed service as seen from
  the alias's own network (almost always `localhost:<port>`) — they are NOT the alias's own connection
  identity, so accepting them as free text doesn't weaken the zero-knowledge boundary; the response
  still never carries `HostName`/`User`/`Port`.

## Command shape

```
sshepherd <group> <action> [positionals...] [--flag value]
```

```bash
sshepherd --help                # lists 15 registry groups + the setup group
sshepherd <group> --help        # lists that group's actions + args/flags
sshepherd <group> <action> --help   # shows one action's args
```

The **first positional** differs by group:

| Group | First positional | Resolves via |
|---|---|---|
| `db` (except `list`) | `<target>` — a pg-target name from `targets.toml` | `targets.ts` |
| `deploy` (all actions) | `<recipe>` — a recipe name | `recipes.ts` |
| `hosts list`, `db list` | *(none — host-local, no ssh)* | — |
| `tunnel list`, `tunnel close` | *(none — `list` is host-local; `close` takes `<id>` instead)* | — |
| `audit tail` | *(none — reads the local audit log, no ssh)* | — |
| every other group | `<alias>` — an ssh alias from `~/.ssh/config` | — |

## Global flags

| Flag | Effect |
|---|---|
| `--yes` | confirm a mutating op — required; sshepherd never prompts interactively |
| `--dry-run` | `deploy run` only: print the resolved plan, execute nothing, no `--yes` needed |
| `--timeout <sec>` | any op: seconds the remote command may run, 1-3600 (each op has its own default); out of range returns `INVALID_ARGS` |
| `--max-bytes <n>` | any op: the printed JSON never exceeds n bytes, 8192-2097152 (default 65536); a cut sets `output_truncated: true` and keeps `error` whole |
| `--fields <a,b.c>` | any op: keep only these dot paths of `data` (a leading `data.` is optional; a list is walked per item); paths that matched nothing come back in `fields_unmatched` |
| `--limit <n>` | any op: keep the first n items of `data`, or of each list directly under it (1-100000) |
| `--pretty` | render a human table/key-value view instead of JSON |
| `--reveal <keys>` | `files cat`/`files download`: comma-separated env-var keys to unmask |
| `--from <path>` | `config put` only: local file to read + base64-encode (instead of typing `--content-base64` by hand) |

Output is JSON to stdout by default (one `Envelope` per call — see `references/output-shapes.md`).
Every op output that can carry remote text passes one scrubber before it is printed: secret-named
values (`DB_PASSWORD=`, `token:`, `"api_key":`), JWTs, `sk-`/`ghp_`/`xox?-` tokens, AWS key ids,
PEM private keys, the password in `scheme://user:pass@` and `Bearer` tokens become `***`;
`PORT=3000` or `DB_HOST=…` stay visible — except in `deploy run` output, where 3 or more `KEY=value` /
`KEY = value` lines in a row (a step printing a `.env`) have every value masked whatever the key; a
lone `BUILD_ID=123` stays. The envelope's `scrubbed` is how many values were masked
(a count, never the originals). A per-alias `[<alias>.scrub] extra_patterns = ["regex"]` table in
`reveal-allowlist.toml` masks anything else that is secret for that host. A command that ran and
failed (any exit but ssh's own 255) carries `error.stderr_tail` — its last 20 lines / 2 KB of
stderr, scrubbed (not for `files cat`/`config get`); `db` ops add `error.data.sql_error`
`{message, detail?, hint?}` from psql's `ERROR:` lines, with the target's user/database masked.
Every envelope carries `schema_version: 1` (fields are only ever added within a version); the JSON
Schema of the envelope and of each op is under `docs/schema/`. The audit log (`audit tail`) records
every mutating op and every op that exposes content: `args_sha256` of the args (never the values),
the recipe/target/container/unit name, `duration_ms`, `remote_exit`, `error_code` and `bytes`.
Exit codes: `0` success, `1` the op ran and failed (transport/command error, or a refused
`CONFIRMATION_REQUIRED`), `2` a usage error (unknown group/action, missing required
argument — no ssh connection was attempted).

## Quick reference — 16 registry-driven groups (76 ops) + 1 `setup` group (7 sub-groups, 16 actions)

```bash
# hosts
sshepherd hosts list
sshepherd hosts test web-01
sshepherd hosts test web-01 --diagnose   # stages master, dns, tcp, banner, auth, echo, each with a verdict
sshepherd hosts info web-01
sshepherd hosts disconnect web-01   # or --all; connections self-close after 5 idle minutes
sshepherd hosts trust web-01 --dry-run                          # the host key fingerprint it presents
sshepherd hosts trust web-01 --fingerprint SHA256:<fp> --yes    # record it once a human confirmed it
sshepherd hosts trust web-01 --fingerprint SHA256:<fp> --all-types --yes   # and every other key type it presents

# check
sshepherd check overview web-01
sshepherd check mem web-01
sshepherd check disk web-01
sshepherd check cpu web-01
sshepherd check ports web-01
sshepherd check oom-history web-01
sshepherd check kernel web-01

# logs
sshepherd logs docker web-01 myapp --tail 100
sshepherd logs docker web-01 myapp --grep 'ERROR|boom' --since 60m --context 2 --max-lines 100   # stdout and stderr merged
sshepherd logs docker web-01 myapp --since 2026-11-27T10:00:00Z --max-lines 200   # oldest first; repeat with --since <next_since> while truncated
sshepherd logs compose web-01 /opt/myapp --grep timeout --tail 200
sshepherd logs service web-01 nginx --tail 100
sshepherd logs docker-daemon web-01 --tail 100
sshepherd logs nginx web-01 error --tail 100

# services
sshepherd services ps web-01
sshepherd services stats web-01
sshepherd services inspect web-01 myapp --fields networks,cmd   # also mounts, ports, health, image, restart
sshepherd services compose-ps web-01 /opt/myapp/docker-compose.yml
sshepherd services healthcheck web-01 myapp
sshepherd services systemctl-status web-01 nginx
sshepherd services restart web-01 myapp --yes
sshepherd services systemctl-start web-01 nginx --yes
sshepherd services systemctl-stop web-01 nginx --yes
sshepherd services systemctl-restart web-01 nginx --yes
sshepherd services systemctl-reload web-01 nginx --yes

# files
sshepherd files ls web-01 /opt/myapp
sshepherd files cat web-01 /opt/myapp/.env --reveal DB_HOST
sshepherd files tail web-01 /var/log/syslog --n 100
sshepherd files head web-01 /opt/myapp/.env --n 20
sshepherd files cat web-01 /opt/myapp/app.log --lines 120:180   # head/tail/cat: lines A to B only
sshepherd files grep web-01 /opt/myapp 'ERROR' --context 2
sshepherd files find web-01 /opt/myapp --name '*.log'
sshepherd files download web-01 /opt/myapp/backup.sql ./backup.sql
sshepherd files disk-usage web-01 /var/lib/docker
sshepherd files upload web-01 ./local.conf /opt/myapp/local.conf --yes

# env (key names only — values never leave the host)
sshepherd env keys web-01 --container myapp   # only a container listed in containers = [...] in targets.toml
sshepherd env keys web-01 --path /opt/myapp/.env
sshepherd env diff web-01 --path /opt/myapp/.env --against ./.env.example

# config
sshepherd config get web-01 /etc/nginx/nginx.conf
sshepherd config validate web-01 /etc/nginx/nginx.conf
sshepherd config put web-01 /etc/nginx/nginx.conf --from ./nginx.conf --yes
sshepherd config reload web-01 nginx --yes

# db
sshepherd db list
sshepherd db tables prod
sshepherd db activity prod
sshepherd db connections prod
sshepherd db slow prod
sshepherd db size prod
sshepherd db query prod "SELECT count(*) FROM users"
sshepherd db describe prod users
sshepherd db count prod users --where-eq org_id=1
sshepherd db migrations prod
sshepherd db migrations prod --table schema_migrations --dir /opt/myapp/migrations   # current version + pending

# deploy
sshepherd deploy run demo --dry-run
sshepherd deploy run demo --yes
sshepherd deploy status demo
sshepherd deploy rollback demo --yes
sshepherd deploy logs demo --tail 100
sshepherd deploy migrate demo --yes

# security
sshepherd security harden web-01 --yes
sshepherd security ssh-audit web-01
sshepherd security listeners web-01
sshepherd security authorized-keys web-01
sshepherd security fail2ban web-01

# tunnel
sshepherd tunnel open web-01 --kind local --remote localhost:5432 --duration 1800 --yes
sshepherd tunnel list
sshepherd tunnel close t-a1b2c3d4 --yes

# audit
sshepherd audit tail --n 20 --op "deploy run" --alias web-01

# http (curl runs ON the host; localhost URLs only; --auth value read there, never returned)
sshepherd http get web-01 http://127.0.0.1:8080/health --auth env:API_KEY@container=myapp   # shorthand: http web-01 GET <url>
sshepherd http get web-01 http://127.0.0.1:8080/me --auth env:API_KEY@file=/opt/myapp/.env --auth-header X-Api-Key
sshepherd http send web-01 POST http://127.0.0.1:8080/jobs --json @job.json --yes   # PUT/PATCH/DELETE too; shorthand: http web-01 POST <url> --yes

# wait (one ssh session polls every 2 s; --timeout 10-3600, default 600)
sshepherd wait for web-01 --until healthy@container=myapp --timeout 120   # shorthand: wait web-01 --until ...
sshepherd wait for web-01 --until 'log-contains:listening on@container=myapp' --since 2m
sshepherd wait for web-01 --until port-open:5432
sshepherd wait for web-01 --until url:http://127.0.0.1:8080/health:status=200

# git (read-only; the path is an allowlisted repository root; remote URLs come back without credentials)
sshepherd git head web-01 /opt/myapp
sshepherd git log web-01 /opt/myapp --n 10
sshepherd git diff-stat web-01 /opt/myapp

# exec (only commands a human declared in ~/.config/sshepherd/exec/<alias>.toml, 0600; see references/exec.md)
sshepherd exec list web-01                                                        # names, params, mutating
sshepherd exec run web-01 app-artisan --param cmd=migrate:status                  # shorthand: exec web-01 app-artisan ...
sshepherd exec change web-01 restart-worker --param c=worker --yes                # mutating = true: --yes, profile deploy

# setup — agent-invocable; install's credential boundary is the one exception (see Gotchas #9)
sshepherd setup ssh-alias register myserver --host 1.2.3.4 --user deploy --yes
sshepherd setup ssh-alias keygen myserver --yes
sshepherd setup ssh-alias install myserver --yes
sshepherd setup ssh-alias list
sshepherd setup ssh-alias status myserver
sshepherd setup ssh-alias update myserver --host 5.6.7.8 --port 2222 --yes
sshepherd setup ssh-alias remove myserver --yes
sshepherd setup db-target scaffold prod --alias myserver --user app --database appdb --container app_db --yes
sshepherd setup db-target ro-role prod --print-sql              # default: SELECT on the app tables only, no pg_authid
sshepherd setup db-target ro-role prod --print-sql --all-data   # pg_read_all_data: reads pg_authid; a function-wrapped rolpassword read is not masked
sshepherd setup db-target discover myserver
sshepherd setup config-allowlist scaffold myserver --paths /etc/nginx/nginx.conf,/opt/app/.env --yes
sshepherd setup deploy-recipe scaffold demo --alias myserver --workdir /opt/app --yes
sshepherd setup files-allowlist scaffold myserver --paths /opt/app/backup.sql,/opt/app/.env --yes
sshepherd setup reveal-allowlist scaffold myserver --keys NODE_ENV,APP_REGION --yes
sshepherd setup host add myserver --host 1.2.3.4 --user deploy --yes   # register, keygen, host key, install form (a human types the password), hosts test -> data.steps[]
sshepherd setup host add myserver --fingerprint SHA256:... --yes       # re-run after HOST_KEY_UNKNOWN, with a fingerprint a human confirmed from data.fingerprints
sshepherd setup ssh-alias adopt-env ./my-project --yes                 # SSH_* / <PREFIX>_SSH_* groups in its .env -> [{alias, key_installed}]; no .env value is printed
# doctor is local and off the registry: `sshepherd doctor hosts` lists aliases whose server still accepts password login, names only
```

## Gotchas

1. **Zero-knowledge is not optional per-call.** There is no flag to pass a raw host/user/
   port/password — the only way to reach a server is to declare it as an ssh alias (or a
   pg-target/recipe pointing at one) ahead of time, outside this tool.
2. **Every mutating op needs `--yes`, always writes an audit line.** sshepherd never
   prompts interactively (agent-first design) — without `--yes` a mutating op returns a
   `CONFIRMATION_REQUIRED` envelope and refuses before touching ssh. Success *and* failure
   both get an audit line in `~/.local/state/sshepherd/audit.jsonl`.
   **`SSHEPHERD_PROFILE` caps what a caller may run, before any ssh call:** `read` (every
   read-only op and any `--dry-run`), `deploy` (adds services/config/files/deploy/tunnel
   changes), `admin` (adds `security harden` and `hosts trust`). Unset means `admin`; any other
   value (`root`, an empty string) is refused with `PROFILE_DENIED` rather than read as admin. A
   pg-target's `max_profile = "read"` in `targets.toml` caps every db op on that target. A
   subagent verifier runs with `SSHEPHERD_PROFILE=read`; only a human raises it.
   **Host keys are checked strictly** (`StrictHostKeyChecking=yes` on every connection): an
   unknown key is `HOST_KEY_UNKNOWN`, a different one `HOST_KEY_CHANGED`, and the only way to
   record one is `hosts trust <alias> --fingerprint SHA256:... --yes` after a human confirmed
   the fingerprint `--dry-run` shows (`--all-types` records every key type the host presents once
   that fingerprint matched one of them).
3. **No raw exec, ever.** There is no `sshepherd exec "<any command>"`. A genuinely novel
   need is a named, typed definition a human writes in `~/.config/sshepherd/exec/<alias>.toml`
   (`exec run`/`exec change`, `references/exec.md`) or a recipe step (`references/recipes.md`) —
   reviewable, never a free-text shell escape hatch. `plain ssh <alias>` remains the
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
   checks as UX guardrails, not the security boundary. `db query` returns
   `data: {rows, row_count, truncated}` (a bare row array before 0.4.0): at most `--max-rows`
   (500) rows, `statement_timeout` 60 s, `lock_timeout` 2 s.
7. **A deploy failure names the step that failed.** `deploy run`/`deploy migrate` surface
   `data.failed_step` (`{index, kind, name}`) on a `COMMAND_FAILED` error, recovered from a
   marker each step echoes on non-zero exit — never guess which step broke from the raw
   output alone.
8. **`security harden` won't lock out the current session unless told to.** Directives
   that could disable the session's own auth method (`PermitRootLogin`,
   `PasswordAuthentication`) are only applied when `--keep-session=false` is passed
   explicitly; the safe subset always applies.
9. **`setup`'s only wall is `install`'s credential entry — and even that has a smart bypass
   first.** `register`, `keygen`, `remove`, `list`, `status`, `update`, `install`, and the
   five scaffolders (`db-target`, `config-allowlist`, `deploy-recipe`, `files-allowlist`,
   `reveal-allowlist`) are all agent-invocable, gated by `--yes` the same way as every other
   mutating op — none of them needs a human at the keyboard, except the one narrow case
   below. Before `install` ever opens a browser form, it runs two cheap, non-interactive
   pre-checks in order: a raw-socket Tailscale-SSH banner peek (a Tailscale-fronted target
   refuses key install outright — `TAILSCALE_SSH_DETECTED`, since Tailscale SSH doesn't use
   `authorized_keys`), then an already-trusted probe with zero new credentials (if the key
   is already authorized, `install` short-circuits with `data.method: 'already_trusted'`
   and no form ever opens). Only when both pre-checks come back negative does `install`
   open a one-shot local browser form, and a *human*, not the agent, supplies the
   credential there — either a password, or a pasted existing private key (rejected with
   `INVALID_PRIVATE_KEY` if it doesn't parse, or `PASSPHRASE_PROTECTED_KEY_UNSUPPORTED` if
   it's passphrase-protected). The agent may trigger `install` and wait on it, but it
   structurally cannot see, log, or relay either credential — both go straight from the
   browser submission into the install flow and never cross back into the agent's context;
   the agent only ever receives the resulting `SetupResult` (success or a typed error
   code), never the password or key itself.
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
11. **`files` and `--reveal` are fail-closed as of v0.2.2 — a fresh install can't `files
    ls`/`cat`/`download`/`upload`/etc. anywhere until an allowlist exists.** Before v0.2.2,
    `files download`/`upload` had no allowlist at all (any remote path, in or out) and
    `--reveal` could unmask any key name the agent typed, including an actually-secret one
    (`DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`) — flagged by an external code review and
    closed the same way `config`'s allowlist already worked. Now every `files` op checks
    the path against `~/.config/sshepherd/files-allowlist.toml` (missing file = every path
    refused, same fail-closed rule as `config-allowlist.toml`), and `files cat --reveal`
    additionally checks each key against a hardcoded, non-overridable secret-pattern
    denylist (`PASSWORD`, `PASSWD`, `SECRET`, `TOKEN`, `PRIVATE_KEY`, `CREDENTIAL`,
    `API_KEY`, trailing `_KEY`/`_PASS`) *before* checking
    `~/.config/sshepherd/reveal-allowlist.toml` — the denylist wins even if a key was
    mistakenly added to the allowlist. Run `setup files-allowlist scaffold` and, if
    `--reveal` is needed, `setup reveal-allowlist scaffold` before using the `files` group
    on a fresh alias. The gate lives in exactly one place — `enforceAllowlist()` in
    `registry.ts`, called from `executeOp()` before any op's `buildRemote` runs — not
    hand-copied per op.
12. **`tunnel open` self-expires via a re-invoked hidden supervisor process, not an external `timeout`
    binary — and `tunnel list` is NOT side-effect-free.** GNU `timeout` isn't reliably present on macOS,
    so `--duration` is enforced by `sshepherd` re-invoking itself in a hidden `tunnel __supervise` mode
    that holds the expiry timer in-process and force-kills the real `ssh -N -L/-R/-D` process (and its
    own process group) when the timer fires — no new external dependency, portable across every release
    target. Calling `tunnel list` can itself terminate a tunnel: while scanning for active tunnels, it
    force-kills (and removes the state record for) any tunnel that's past its expiry but whose
    supervisor's own timer hasn't fired yet, rather than reporting a stale entry as still active — treat
    `tunnel list` as a mutating, potentially process-killing call, not a pure read, even though it needs
    no `--yes` (it's still `mutating: false` at the `OpSpec` level — the confirm gate the mutating flag
    controls is a separate axis from "is idempotent"). **Known limitation, deliberately not hardened
    against:** a tunnel's local process-tracking state is keyed on PID alone. If a tunnel's supervisor
    process exits and, in a since-widened window, the OS reuses that same PID for an unrelated
    process-group leader, `tunnel close`/`tunnel list`'s cleanup could in principle signal the wrong
    process group. This requires reused-PID-happens-to-be-a-group-leader, which is a low-probability
    edge case for a single-operator local dev tool — tracked as a known limitation of the PID-only state
    schema rather than solved with start-time/cmdline verification, which was judged out of scope for
    this build. Also: `tunnel open` returning `ok: true` confirms only that the supervisor process was
    spawned — NOT that `ssh` actually bound the port or that the target is reachable; a failure at that
    stage surfaces later (the next `tunnel list` prunes the now-dead entry), not in the `open` call's own
    response.

## Errors

| Code | Meaning |
|---|---|
| `UNKNOWN_ALIAS` | the ssh alias isn't defined in `~/.ssh/config` (or any file it `Include`s) and no wildcard `Host` line or `Match` block could apply to it |
| `CONNECT_TIMEOUT` | couldn't reach the host within the connect timeout |
| `AUTH_FAILED` | SSH authentication failed for this alias |
| `HOST_KEY_CHANGED` | the host presented a different key than `known_hosts` holds for the alias (a reinstalled server, or someone in the middle); from `hosts trust`, `known_hosts` holds a key the host no longer presents and none it presents matches `--fingerprint` — find out why before trusting anything; `next` is `hosts trust <alias> --dry-run` |
| `HOST_KEY_FINGERPRINT_MISMATCH` | `hosts trust --fingerprint` named no key the host presents, while `known_hosts` trusts no key for the host yet or already trusts one it presents (a stale key beside it does not change that): a mistyped or wrong fingerprint, not a changed key; compare with the provider console or `ssh-keygen -l` on the host; exit `2` |
| `KNOWN_HOSTS_UNWRITABLE` | `hosts trust` cannot record the key: the alias's `known_hosts` (or its directory) is not writable, is `/dev/null` or not a regular file, or the write did not read back; nothing was recorded; exit `2` |
| `HOST_KEY_UNKNOWN` | `known_hosts` has no key for the alias; sshepherd never accepts one on first use — confirm it with `hosts trust` |
| `SSH_TRANSPORT_ERROR` | ssh failed before the remote command could run, unclassified |
| `COMMAND_FAILED` | the remote command exited non-zero (`error.remote_exit` carries the code) |
| `COMMAND_TIMEOUT` | the remote command exceeded its timeout (`error.budget_sec`, `error.elapsed_ms`; `data.partial_stdout` holds what it printed) |
| `INVALID_ARGS` | a flag or positional was malformed, missing or out of range (e.g. `--timeout 9999`, a container or path starting with `-`) — refused before any ssh call |
| `PARSE_ERROR` | an unknown or malformed flag (`did_you_mean` lists the near flags) |
| `UNKNOWN_SUBGROUP` | an unknown group, action or setup sub-group (`did_you_mean` lists the valid names) |
| `VALIDATION_ERROR` | an argument or config value the op refuses locally: an unknown pg-target or recipe (`did_you_mean` lists near names), a path not on its allowlist, a non-SELECT query |
| `CONFIG_PARSE_ERROR` | a sshepherd config file is malformed: the message names the file (`targets.toml`) and the line, never the line's content |
| `AUDIT_WRITE_FAILED` | a content read (`logs *`, `files cat`, …) finished but its audit line could not be written; `data` keeps the op's result, `error.op_outcome` says how it ended (`ok`/`error` ran, `refused` did not) and `error.op_error` holds its own error. A mutating op is never failed for this: it keeps its own envelope plus a `warnings[]` entry `AUDIT_UNWRITABLE` (`path_role` `state_dir`/`audit_archive`/`audit_file`, `errno`, a `hint` naming the fix) — do not re-run either just to record it |
| `INTERNAL_ERROR` | sshepherd failed while running the op (a bug or an unparseable reply from the host); the message names only the error class |
| `CONFIRMATION_REQUIRED` | a mutating op ran without `--yes` — refused before any ssh call |
| `PROFILE_DENIED` | the op needs a higher `SSHEPHERD_PROFILE` than the caller holds (or a target's `max_profile` caps it, or the profile value is unknown) — refused before any ssh call |

Every failure is a JSON envelope whose `error` carries `hint` (what to do), `retryable` (whether the
same command can succeed on a re-run) and, when one exists, `next` (an exact command to run) and
`did_you_mean` (close names). Usage errors print the envelope on stdout too, never bare stderr text.

Exit codes: `0` on `ok: true`; `1` when the run failed (`COMMAND_FAILED`, a timeout, a transport
or internal error, `AUDIT_WRITE_FAILED`); `2` when the command line or its config was wrong (`INVALID_ARGS`,
`PARSE_ERROR`, `UNKNOWN_SUBGROUP`, `VALIDATION_ERROR`, `CONFIG_PARSE_ERROR`, `UNKNOWN_ALIAS`, `CONFIRMATION_REQUIRED`, `PROFILE_DENIED`, `HOST_KEY_FINGERPRINT_MISMATCH`, `KNOWN_HOSTS_UNWRITABLE`) —
no ssh command is ever run for an exit-`2` other than the alias check behind `UNKNOWN_ALIAS`.

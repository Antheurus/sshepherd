# sshepherd Changelog

## v0.4.0-rc.3 — Errors now tell you the next command

- Every failure is now a JSON envelope with a `hint` (what to do), `retryable` (whether running it again can help) and, where one exists, `next` (an exact command to run) and `did_you_mean` (close names). This includes typos in the group, action, flag, pg-target or recipe name, which used to print bare text on stderr.
- `hosts test <unknown alias>` now answers `UNKNOWN_ALIAS` with `next: sshepherd hosts list` instead of a generic transport error.
- An unknown flag is refused with `PARSE_ERROR` instead of being silently ignored (`--tial 5` no longer runs a full-length tail). A container, unit, service or path that starts with `-` is refused with `INVALID_ARGS` before any ssh call, so it can never be read as an option.
- Exit code `2` now means the command line or its config was wrong; `1` means the run itself failed.
- `setup <sub-group> <action> --help` shows help even when required arguments are missing.
- The audit log can be redirected with `SSHEPHERD_STATE_DIR` or `SSHEPHERD_AUDIT_PATH`, and the test suite no longer writes to your real audit log. Every mutating op still writes its audit line even if it fails halfway.

## v0.4.0-rc.2 — Faster repeated calls and clearer timeouts

- Repeated calls to the same server now reuse one SSH connection for 5 idle minutes instead of reconnecting each time. `sshepherd hosts disconnect <alias>` (or `--all`) closes it on demand, for example after you change `~/.ssh/config`.
- Every op accepts `--timeout <seconds>` (1 to 3600). A value outside that range returns an `INVALID_ARGS` error without touching the server. Defaults changed per op: check 30 s, services 20 s, db 60 s, `hosts test` 10 s.
- A server that cannot be reached now reports `CONNECT_TIMEOUT` or `AUTH_FAILED` straight away. A command that runs out of time reports `COMMAND_TIMEOUT` with the budget it had, how long it ran, and whatever it had printed so far.
- `--yes`, `--dry-run` and `--pretty` no longer swallow the argument after them (`deploy run --yes demo` now works), and `--` ends flag parsing.

## v0.4.0-rc.1 — internal: registry split by group

- Internal change, no user-visible effect.

## v0.3.0 — New `tunnel` command: forward a port through a server without ever seeing its address

- Added: `sshepherd tunnel open <alias> --kind local --remote <host:port> --duration <seconds> --yes`
  opens an SSH port forward (local, remote, or dynamic/SOCKS) through a declared alias — useful for
  reaching a database or internal service that only listens on the server itself. The tunnel closes
  itself automatically after `--duration` seconds (default 1 hour, max 24 hours) so it never needs to be
  remembered and cleaned up by hand.
- Added: `sshepherd tunnel list` shows every tunnel currently open, with how much time is left on each.
- Added: `sshepherd tunnel close <id> --yes` closes a tunnel early. Closing one that's already gone is
  not an error.
- Note: `tunnel open` confirms the connection process started, not that it fully succeeded — if the
  target port turns out to be unreachable, that shows up on the next `tunnel list` (the tunnel will be
  gone) rather than in the `open` response itself.
- No action required for existing setups — this only adds a new command, nothing existing changed.

## v0.2.2 — `files` and `--reveal` now require an allowlist (breaking change)

- Fixed: the `files` group (`ls`/`cat`/`tail`/`download`/`disk-usage`/`upload`) had no
  restriction on which remote paths it could touch — any path was readable or writable.
  Every `files` op now refuses a path that isn't pre-declared for that alias in
  `~/.config/sshepherd/files-allowlist.toml`, the same rule `config get`/`put` already
  followed.
- Fixed: `files cat --reveal` could unmask any key name, including a genuinely secret one
  (`DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`). Each requested key is now checked against a
  hardcoded list of secret-looking patterns (refused unconditionally, no override) and must
  also be pre-declared in `~/.config/sshepherd/reveal-allowlist.toml`.
- Action required: run `sshepherd setup files-allowlist scaffold <alias> --paths
  <path1,path2> --yes` before using any `files` op on that alias, and — only if you use
  `--reveal` — `sshepherd setup reveal-allowlist scaffold <alias> --keys <key1,key2> --yes`
  for the specific env keys you need unmasked.

## v0.2.1 — `files download` now writes to disk instead of returning file contents

- Fixed: `files download` was silently returning the entire downloaded file's contents
  (base64-encoded) in its response instead of writing it to a local path — meaning secrets
  files (`.env`, credentials) downloaded this way could end up visible wherever that
  response was read. `files download` now requires a local destination path as a second
  argument and writes the file straight to disk; the response only confirms the write
  succeeded and never contains the file's contents.
- Action required: if you use `files download`, add a local destination path as the second
  argument, e.g. `sshepherd files download myserver /opt/lms/backup.sql ./backup.sql`.

## v0.2.0 — `setup`: onboard a new server without hand-editing config files

- New: `sshepherd setup`, a separate command group you run yourself in your own terminal —
  never something an agent should type on your behalf — for writing sshepherd's own local
  config files instead of hand-authoring them. `setup ssh-alias register/keygen/remove`
  adds, generates a dedicated keypair for, or removes an alias in `~/.ssh/config`; `setup
  db-target` scaffolds a new entry in `targets.toml`; `setup config-allowlist` scaffolds the
  paths an alias is allowed to read/write via `config get`/`config put`; and `setup
  deploy-recipe` scaffolds a starter recipe TOML you fill in with your real deploy steps.
  Every action still requires `--yes` and writes an audit line, same as the other 9 groups,
  and none of it opens an SSH connection or touches a remote server — it only ever writes
  local files on the machine `sshepherd` runs on.

## v0.1.0 — sshepherd v1: safe SSH server ops from Claude Code

- New: `sshepherd`, a single CLI you (or an agent driving Claude Code) can use to check on
  and manage a remote server over SSH — health checks, docker/systemd control, log tailing,
  config edits, read-only database introspection, and one-command deploys — without ever
  typing or exposing a password, private key, hostname, or port to the agent.
- Nine command groups, 52 operations total: `hosts`, `check`, `logs`, `services`, `deploy`,
  `config`, `db`, `files`, `security`. Every response comes back as one consistent JSON
  shape (or a readable table with `--pretty`).
- Read-only Postgres introspection (`db` group): table sizes, active queries, connection
  counts, slow queries, database sizes, and ad hoc `SELECT`-only queries — enforced
  read-only at the database role, the query wrapper, and the client, so it's safe to point
  at a production database.
- Declarative deploys (`deploy` group): describe a deploy as a TOML recipe (build, migrate,
  restart, health-check, in whatever order they actually depend on each other) and run it
  with one command, preview it first with `--dry-run`, or roll it back if you declared how.
- Anything that changes something on the server requires an explicit `--yes` and is
  recorded in a local audit log — nothing runs by accident.
- Install via `npx skills add Antheurus/sshepherd`, `/plugin marketplace add
  Antheurus/sshepherd`, a prebuilt release binary, or build from source with `just build`.
  See the README for all four options.

**Action required before first use:**
- Add the servers you want to manage as aliases in your `~/.ssh/config` (with `ssh-agent`
  or a key file already working for each one) — `sshepherd` only ever takes an alias name,
  never a host, user, or password.
- To use the `db` group, declare each database as a named target in
  `~/.config/sshepherd/targets.toml` (see `targets.example.toml` for the format).

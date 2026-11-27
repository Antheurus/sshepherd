# sshepherd Changelog

## v0.4.0-rc.12 — Run your own declared commands on a server, safely

- New `sshepherd exec`: you write the commands an alias may run in `~/.config/sshepherd/exec/<alias>.toml` (chmod 600), each as an argv list with typed values (a fixed list, a number range, a path under a folder, a pattern, or a declared container). The agent can then run `sshepherd exec <alias> <name> --param key=value` and nothing else; free-text commands still do not exist.
- A command marked `mutating = true` needs `--yes` and the `deploy` profile, and every run is written to the audit log. Read-only ones run under the `read` profile.
- Values are refused before anything runs when they could change what the command does: a leading `-`, shell characters, line breaks, more than 16 values, more than 512 bytes, or a path that leaves its folder (also through a symbolic link, checked on the server).
- The file itself is refused if others can read or write it, if it is a link, or if another user owns it.
- `sshepherd exec list <alias>` shows what you declared. Output is masked like every other command. See `references/exec.md` for the format.

## v0.4.0-rc.19 — Add a server in one command

- `sshepherd setup host add <alias> --host <ip> --user <user> --yes` now does the whole onboarding: it registers the alias, creates its key, checks the server's host key, opens the one-time browser form where you type the password, and confirms key login works. The result lists each step it took.
- If the server's host key is not known yet, it stops and shows the fingerprints. Compare one with your provider's console, then run the same command again with `--fingerprint SHA256:...`.
- `sshepherd setup ssh-alias adopt-env <project-dir> --yes` reads the `SSH_*` settings in a project's `.env`, creates an alias per server and installs a key using the password or key already there. It only reports which aliases got a key, never any value from the file. After it, rotate those passwords.
- `sshepherd doctor hosts` lists the aliases whose server still accepts password login, by name only, so you know which ones to harden.
- Fixed: after a successful key install, the command no longer sits waiting until the form's timeout before exiting.

## v0.4.0-rc.11 — Probe local services, wait for a condition, read git state

- New `sshepherd http get <alias> <url>` (or `http <alias> GET <url>`) calls a service on the server itself, from the server: only `127.0.0.1`, `::1` and `localhost` URLs are allowed. It returns the status, the time taken, the response header names (never their values) and the body, capped at 64 KiB with secrets masked.
- `--auth env:KEY@container=NAME` or `--auth env:KEY@file=PATH` sends a key the server already holds, as `Authorization: Bearer ...` or under `--auth-header NAME`. The key is read on the server and never shown, logged or sent back. The container has to be listed in `targets.toml`, and the file has to be on the files allowlist.
- `sshepherd http send <alias> POST|PUT|PATCH|DELETE <url> [--json @body.json] --yes` sends a change the same way. Without `--yes` it returns `CONFIRMATION_REQUIRED`.
- New `sshepherd wait for <alias> --until <condition>` (or `wait <alias> --until ...`) waits for a container to become healthy, a log line, a listening port or a localhost URL status, checking every 2 seconds over one connection. It returns `attempts` and `elapsed_ms`. `--timeout` is 10 to 3600 seconds (default 600).
- New `sshepherd git head|log|diff-stat <alias> <repo>` reads a repository on the server without changing it: branch, commit, dirty state, ahead/behind, recent commits, and changed-file counts. The repository root has to be on the files allowlist. Remote URLs come back with any embedded password or token removed.
- Internal: the test servers now include a local web app, a container with a healthcheck and git repositories, and the leak test covers all three new commands.

## v0.4.0-rc.7 — Permission profiles, strict host keys and a leak gate

- `SSHEPHERD_PROFILE=read|deploy|admin` limits what a session may run. `read` allows every read-only command and any `--dry-run`, `deploy` adds service, config, file, deploy and tunnel changes, `admin` adds `security harden` and `hosts trust`. Anything above the profile returns `PROFILE_DENIED` (exit 2) before connecting. Unset means `admin`, as before. Any other value is refused.
- A db target in `targets.toml` can set `max_profile = "read"` so db commands on it never run above that profile.
- Every connection now checks host keys strictly. A host whose key isn't in known_hosts returns `HOST_KEY_UNKNOWN`, and one whose key changed returns `HOST_KEY_CHANGED` (this replaces `HOST_KEY_MISMATCH`; update anything that matched the old name).
- New `sshepherd hosts trust <alias> --dry-run` shows the fingerprint the host presents. After a human has confirmed it out of band, `hosts trust <alias> --fingerprint SHA256:... --yes` records it and replaces that host's old entry. A fingerprint that doesn't match is refused and nothing is written.
- Internal: a canary test now plants a random secret in 19 places on the local test servers and checks that no command ever returns it.
- `setup` now obeys `SSHEPHERD_PROFILE` too: every setup action that writes local config (and `setup ssh-alias install`) needs `admin`, and returns `PROFILE_DENIED` (exit 2) under `read` or `deploy`; `setup ssh-alias list` and `status` stay available under `read`.
- A `db query` whose cast or constraint fails no longer echoes the row value through the error (`invalid input syntax for type integer: "..."`, `Key (...)=(...) already exists`, `Failing row contains (...)` and the other psql texts that quote data).
- Secrets and IP addresses are now masked in everything sshepherd prints outside a command run as well: `doctor`, argument errors, unexpected-error envelopes and every `setup` result.
- Internal: the local test fixture can run as several copies at once (`SSHEPHERD_SMOKE_PROJECT`), and the canary test now also covers the connection's host, user and port and a peer address.

## v0.4.0-rc.6 — Output limits, field selection and a readable audit log

- No command prints more than 64 KiB by default (`--max-bytes <n>`, 8,192 to 2,097,152). A cut is marked `output_truncated: true`; errors are never cut. A container that logs megabytes now returns a readable slice instead of flooding the session, and the connection stays usable afterwards.
- `--fields a,b.c` keeps only the parts of `data` you name (`--fields data.rows` is accepted too) and `--limit <n>` keeps the first n items of a list. A field that matched nothing is listed in `fields_unmatched`. `--tail` must be 1 to 5000.
- Every response carries `schema_version: 1`. JSON Schemas for the envelope and for each command are in `docs/schema/`.
- New `sshepherd audit tail [--n 50] [--alias X] [--op "deploy run"]` shows the newest audit rows: what ran (recipe, target, container or unit name), how long it took, the remote exit status and a sha256 of the arguments. Argument values are never logged. Commands that show content (`db query`, `files cat`, logs) are audited too, and the log rotates at 50 MiB keeping 5 files.
- A deploy that prints more than 2 MiB is never interrupted; its last 64 KiB is returned.
- New error `OUTPUT_TOO_LARGE`: a command printed more than sshepherd reads and the result could not be parsed.
- Internal: unit tests no longer read your real allowlist files.

## v0.4.0-rc.5 — Secrets in command output are masked everywhere

- Every command's output now passes one secret filter: passwords, tokens, API keys, JWTs, private keys, the password inside connection URLs and Bearer tokens show as `***`, while ordinary values such as `PORT=3000` or a database host stay visible. Each response says how many values were masked (`scrubbed`).
- Secret-looking files (`.env`, `prod.env`, `*.vars`, `*.secrets`, `credentials`, `*.pem`, `id_*`) are masked in `files cat`, `files tail`, `config get` and in the file `files download` writes to disk. `files download` accepts `--reveal` with the same rules as `files cat`.
- When a remote command fails, the error now includes the last lines of what it printed to stderr (masked), and a failed database query reports the database's own error message in `error.data.sql_error`.
- You can add your own patterns to mask for one server in `reveal-allowlist.toml` under `[<alias>.scrub] extra_patterns`.
- More secrets are now caught: private keys shown by `files tail` or a container log, `.env` files that `files download` writes even when they hold a non-UTF-8 byte, the content of a `.env` read that timed out, numbers and lists under a password column in `db query`, `--password <value>`, `mysql -p<value>`, `MYSQL_PWD`, `redis://:password@`, GitHub/GitLab/Google/Stripe/webhook tokens, Slack webhook URLs, PGP private keys, cookies and `<password>` XML values. `--reveal DATABASE_URL` still shows the URL but keeps its password masked.
- Fewer false alarms: plain URLs such as `APP_URL=https://...`, fields named `url` or `key`, and prose such as "a Bearer token" are no longer masked.
- Very long single-line output (hundreds of KB) no longer stalls the masking step for minutes.

## v0.4.0-rc.4 — sshepherd doctor and a safe install/rollback

- New `sshepherd doctor`: shows whether the installed binary differs from the built one, whether SKILL.md still lists exactly the commands that exist, and which db targets do not use a read-only role (names only).
- `sshepherd --version` now reports the real version plus the git commit, build time and a hash of the command list, so you can tell which build is running.
- `just release <version>` tests, builds and installs the binary in one atomic step, keeping the previous one; `just rollback` puts it back. A symlinked install is replaced by a real file and the old target is left untouched.
- Commands that hit their `--timeout` on Alpine/busybox hosts now report `COMMAND_TIMEOUT` instead of a generic failure.
- `just smoke` now runs live against a Debian and an Alpine test server (ports 8413 and 8414) and no longer touches `~/.ssh/config`; `just canary <alias>` checks a real host read-only.
- A mutating command whose audit line cannot be written (for example a state directory that is really a file) now still returns its result, flagged `AUDIT_WRITE_FAILED` with how the command ended, instead of a raw file-system error; unexpected internal errors no longer print file paths.
- A malformed `targets.toml` now reports `CONFIG_PARSE_ERROR` with the line number and how to fix it (exit 2), instead of "sshepherd failed unexpectedly".
- Aliases defined in a file your ssh config `Include`s, matched by a wildcard `Host` line, or set by a `Match` block are no longer refused as unknown; `hosts list` also shows the aliases from `Include`d files.
- File paths with spaces, brackets, `#`, accents or other characters now work in the `files` and `config` commands; only a leading `-`, a NUL or a line break is refused.
- `sshepherd doctor` says `targets_file: "missing"` (and no target list) when targets.toml does not exist, instead of an empty list that looks like all is well.
- A malformed files, config or reveal allowlist or deploy recipe now reports `CONFIG_PARSE_ERROR` with the file and line (exit 2) instead of an internal error.
- `just release` stops immediately, before tests, when the install directory is not writable, and says how to fix it; `just clean` is back.
- `setup` commands now refuse an unknown flag with `PARSE_ERROR` (exit 2) instead of silently ignoring it.

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

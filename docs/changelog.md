# sshepherd Changelog

## v0.4.0-rc.13 — Governed database writes and verified backups

- New `sshepherd db exec <target> --file ./change.sql --dry-run` runs a change file in one transaction, reports how many rows each statement touched, then rolls everything back. Run it again with `--yes` instead of `--dry-run` to commit.
- `db exec` connects as the target's `write_role`, a new `targets.toml` field, and never as the read-only login. A target without `write_role` is refused with a message naming the field.
- Statements that change the schema or privileges (`DROP`, `ALTER`, `TRUNCATE`, `CREATE`, `GRANT`, `DO`, ...) are refused with `DDL_REFUSED` unless you add `--allow-ddl`. `BEGIN`/`COMMIT`, psql backslash commands and `SET ROLE` in the file are always refused.
- Every real `db exec` run is in the audit log with the SQL's sha256 and the table names. The SQL text is kept only in a private file (`sql/<sha256>.sql` in the sshepherd state directory, owner read/write only), for 90 days and 200 MB at most.
- New `sshepherd db backup <target> --keep 7 --yes` writes a `pg_dump` file on the server and returns its path, size, sha256 and how many tables it holds. It keeps the newest 7 dumps of that target (and at most 5 GiB) and deletes older ones, never any other file.
- New `sshepherd db backup-verify <target>` restores the newest dump into a temporary database, compares the row count of every table with the live database, and deletes the temporary database again. `verified: true` means the restore had no errors and every count matched.
- New optional `targets.toml` fields: `write_role`, `backup_dir`, `backup_keep`, `backup_max_bytes` (see `targets.example.toml`).
- `db exec --dry-run` needs the `deploy` profile and is written to the audit log with `dry_run: true`. It runs the statements for real and then issues `ROLLBACK`; it is not a simulation. Sequences still advance, touched rows are locked while it runs, and triggers with outside effects fire, so avoid it on a busy production database.
- The database timers are set again before every statement, so a statement cannot lift `statement_timeout` or `lock_timeout` for the next one. A server-side watchdog cancels the running statement at the time budget and, 5 seconds later, terminates the backend, so a `db exec` that answers `COMMAND_TIMEOUT` no longer keeps running and committing. Locks it held are released.
- Settings that change how SQL is read (`standard_conforming_strings`, `client_encoding`, `backslash_quote`, `escape_string_warning`) are pinned and any attempt to change them, in any spelling and also from inside another statement, is refused with `VALIDATION_ERROR`. A `COMMIT` hidden in the file is detected and the run fails with `committed: null`.
- `DB_EXEC_MAX_COMMAND_BYTES` refuses a script whose remote command would be too long, with a `VALIDATION_ERROR` before anything runs, instead of failing on the server with "Argument list too long".
- `db backup-verify` removes its temporary database and file even when it is stopped with TERM or KILL, and two backups started in the same second no longer collide.

## v0.4.0-rc.12 — Run your own declared commands on a server, safely

- New `sshepherd exec`: you write the commands an alias may run in `~/.config/sshepherd/exec/<alias>.toml` (chmod 600), each as an argv list with typed values (a fixed list, a number range, a path under a folder, a pattern, or a declared container). The agent can then run `sshepherd exec <alias> <name> --param key=value` and nothing else; free-text commands still do not exist.
- A command marked `mutating = true` needs `--yes` and the `deploy` profile, and every run is written to the audit log. Read-only ones run under the `read` profile.
- Values are refused before anything runs when they could change what the command does: a leading `-`, shell characters, line breaks, more than 16 values, more than 512 bytes, or a path that leaves its folder (also through a symbolic link, checked on the server).
- The file itself is refused if others can read or write it, if it is a link, or if another user owns it.
- `sshepherd exec list <alias>` shows what you declared. Output is masked like every other command. See `references/exec.md` for the format.
- Behaviour change: an exec definition with a parameter is now accepted only when the parameter sits directly after a data-only program (cat, sed, find ...). A parameter behind a wrapper (nice, sudo, timeout, xargs, stdbuf, nohup, setsid, doas, chroot), behind git, after a php or docker global option, or after an abbreviated long option now needs `allow_shell = true`. `env NAME=value <data program>` is still allowed. Details are in `references/exec.md`.
- Shells and script interpreters (sh, bash, perl, python, node, awk, ssh and similar) in a definition need `allow_shell = true`, and so do options that run code (`find -exec`, `tar --to-command`, `sed` `e`/`w` commands, `php -r`). A value that names an interpreter is refused.
- A definition can set its own `timeout` in seconds; `exec list` shows it as `timeout_sec`, and `--timeout` on a call still applies.
- Every exec audit row names the definition that ran (`exec_def`).
- A `path` value is now checked and used in one step on the server, so swapping a path for a link in between no longer reads an outside file, and `path` values work inside alpine containers. Regular-expression patterns with unbalanced brackets or parentheses are refused when the file is loaded.

## v0.4.0-rc.19 — Add a server in one command

- `sshepherd setup host add <alias> --host <ip> --user <user> --yes` now does the whole onboarding: it registers the alias, creates its key, checks the server's host key, opens the one-time browser form where you type the password, and confirms key login works. The result lists each step it took.
- If the server's host key is not known yet, it stops and shows the fingerprints. Compare one with your provider's console, then run the same command again with `--fingerprint SHA256:...`.
- `sshepherd setup ssh-alias adopt-env <project-dir> --yes` reads the `SSH_*` settings in a project's `.env`, creates an alias per server and installs a key using the password or key already there. It only reports which aliases got a key, never any value from the file. After it, rotate those passwords.
- `sshepherd doctor hosts` lists the aliases whose server still accepts password login, by name only, so you know which ones to harden.
- Fixed: after a successful key install, the command no longer sits waiting until the form's timeout before exiting.
- If every host in `setup ssh-alias adopt-env` fails, the command now returns `INSTALL_FAILED` with each reason instead of `ok`; a partly successful run is still ok.
- A `setup` action whose audit row cannot be written now reports a warning (naming which path failed) instead of an internal error, so a write that already happened is not run twice.

## v0.4.0-rc.11 — Probe local services, wait for a condition, read git state

- New `sshepherd http get <alias> <url>` (or `http <alias> GET <url>`) calls a service on the server itself, from the server: only `127.0.0.1`, `::1` and `localhost` URLs are allowed. It returns the status, the time taken, the response header names (never their values) and the body, capped at 64 KiB with secrets masked.
- `--auth env:KEY@container=NAME` or `--auth env:KEY@file=PATH` sends a key the server already holds, as `Authorization: Bearer ...` or under `--auth-header NAME`. The key is read on the server and never shown, logged or sent back. The container has to be listed in `targets.toml`, and the file has to be on the files allowlist.
- `sshepherd http send <alias> POST|PUT|PATCH|DELETE <url> [--json @body.json] --yes` sends a change the same way. Without `--yes` it returns `CONFIRMATION_REQUIRED`.
- New `sshepherd wait for <alias> --until <condition>` (or `wait <alias> --until ...`) waits for a container to become healthy, a log line, a listening port or a localhost URL status, checking every 2 seconds over one connection. It returns `attempts` and `elapsed_ms`. `--timeout` is 10 to 3600 seconds (default 600).
- New `sshepherd git head|log|diff-stat <alias> <repo>` reads a repository on the server without changing it: branch, commit, dirty state, ahead/behind, recent commits, and changed-file counts. The repository root has to be on the files allowlist. Remote URLs come back with any embedded password or token removed.
- Internal: the test servers now include a local web app, a container with a healthcheck and git repositories, and the leak test covers all three new commands.
- `[<alias>.http] allow = ["host:port"]` in `files-allowlist.toml` lets `http` reach one exact extra `host:port` on the server (no wildcards, no port-less entries); everything else stays localhost-only. `wait` stays localhost-only.
- `http` and the `http-probe` deploy step use the same hardened `curl` call (`--max-time`, `--noproxy`, `--proto`), and `data.body_truncated` says when the body was cut by `--max-bytes`. A JSON secret that sat across the 64 KiB cut is now masked.
- `git head|log|diff-stat` ignore the repository's own clean/smudge filters, textconv, fsmonitor and hooks, so reading a repository cannot run anything it defines. `diff-stat` lists at most 500 files but counts insertions and deletions over all of them, and a branch without an upstream returns `ahead` and `behind` as null.
- `wait` now answers within its `--timeout` even when a probe hangs. Trust messages read `hosts trust (CODE): ...` instead of masked text.

## v0.4.0-rc.9 — Safer database queries, table introspection and a read-only role helper

- Action required: `db query` now returns `data` as an object `{rows, row_count, truncated, masked_columns}` instead of a bare list; read `data.rows`. `schema_version` stays 1 and `docs/schema/db-query.json` describes the new shape. `--fields data.rows` still works.
- A query returns at most 500 rows by default (`--max-rows`, up to 10,000) and sets `truncated: true` when it cut. The database cancels a statement after 60 seconds and gives up waiting for a lock after 2 seconds; both come back as `COMMAND_TIMEOUT`. A query cannot lift these limits from the inside, and one that tries to break out of its wrapper (a trailing `--`, a closing parenthesis, a quote that continues across lines) is refused with `VALIDATION_ERROR` before anything is sent.
- Columns whose name looks secret (`password`, `secret`, `token`, `api_key`, `private_key`, `credential`, `salt`, `hash`, `passwd`, `rolpassword`) come back as `***`, and the envelope lists them in `masked_columns`. A target can set its own `deny_columns` list; an empty list is refused. Password hashes (SCRAM, md5, bcrypt, argon2, crypt) are masked under any column name.
- New `sshepherd db describe <target> <table>` (columns, indexes, `foreign_keys`), `db count <target> <table> [--where-eq col=value]` (returns `{count}`), and `db migrations <target> [--table T] [--dir D]` for prisma and rails (current version and pending files).
- New db target kinds: `host` (psql on the server) and `container-env` (the connection URL stays inside a container's environment and is never shown). a new read-only `setup db-target discover` action inspects the server, and `doctor` names any target that still has no read-only role.
- `sshepherd setup db-target ro-role <target> --print-sql` now prints a tables-only grant by default, which cannot read `pg_authid`. Add `--all-data` for the broader `pg_read_all_data` grant; its SQL comment explains that role hashes become readable. `--tables-only` still works as an alias, and giving both is refused.
- A `targets.toml` table with only `alias` and `containers` is valid for `env` commands; database commands that name it say so and refuse.

## v0.4.0-rc.8 — Log filters, degraded health checks and connection diagnosis

- `logs docker` and `logs service` accept `--grep <pattern>` (up to 512 characters), `--context N` (0 to 20), `--since`, `--until` and `--max-lines` (1 to 100,000). The pattern is searched in the log text only, never in journal metadata. Paging works: take `next_since` from one page and pass it as `--since` for the next; `kept` says whether the page holds the oldest or the newest lines. A failing source keeps its own error message even when `--grep` is set.
- New `sshepherd logs compose <alias> <project_dir>` reads the logs of every container of a compose project. The folder has to be on the files allowlist, and a parent folder's compose file is never picked up.
- Logs larger than 2 MiB keep their newest part. Private key blocks inside a log window are masked by their shape even when the BEGIN and END lines fall outside the window.
- `check` commands no longer fail when the server lacks a tool: sections that could not be read are listed under `degraded`, and `dead_end_risk` is `true` whenever a disk or memory signal is at risk, even if another section is unreadable (`null` only when nothing known is at risk). New `risk_signals` names what is at risk, so a 91 % disk is not hidden.
- New `sshepherd hosts test <alias> --diagnose` runs master, dns, tcp, banner, auth and echo stages and reports a verdict and milliseconds for each, without the host, address or port. A hung shared connection is reported as `control-master-stale` in a few seconds instead of stalling.
- Every `check`, `logs` and `security listeners` command now runs at low CPU and disk priority on the server.
- Masking: ports shown as `:::2222->22/tcp` or `*:2222`, short hostnames in syslog lines and `scp host:/path`, and common user names in login contexts are masked, while package names such as `app@latest` stay readable.
- `deploy run` output that contains three or more consecutive `KEY=value` or `KEY = value` lines is treated as an env block and every value in it is masked, whatever the key is called. Build output that merely looks like an env file is masked too.
- If a command that changes something cannot write its audit row (unwritable log folder, full disk), it still runs and the response carries an `AUDIT_UNWRITABLE` warning that names which path failed and how to fix it.

## v0.4.0-rc.10 — Env key checks, richer service inspection and safe file search

- New `sshepherd env keys <alias> --path <file>` (or `--container <name>`) lists the keys of a `.env` file or a container's environment with `state` (`set` or `empty`) and a length bucket (`0`, `1-8`, `9-32`, `33+`). Values never leave the server. Multi-line quoted values (certificates, JSON, base64), `export`, `KEY = value`, comments and CRLF files are read correctly.
- New `sshepherd env diff` compares a server `.env` file or container with a reference given by `--against` and returns `missing`, `extra` and `empty` keys. A local `--against` file is read the same way, so a multi-line value no longer shows up as a bogus key.
- `env keys --container` and the `env` field of `services inspect` only work for containers you list under `containers = [...]` in `targets.toml`; any other container is refused before connecting. A target can now be only an alias plus `containers`, with no database.
- `sshepherd services inspect <alias> <container> --fields mounts,ports,health,env,networks,cmd` returns only the parts you name. `env` is key names only, and docker is asked for just those fields, so values never reach your machine.
- New `sshepherd files find|grep|head <alias> <path>` read files on the server inside the files allowlist, with output masked. `/`, `..` and symbolic links that leave the allowlist are refused; a pattern or `--name` is one literal argument (patterns up to 256 characters and names up to 128, no line breaks).
- `files head`, `files tail` and `files cat` accept `--lines A:B` (at most 5,000 lines) to read an exact range.
- A private key block is masked wherever it sits in a file, whatever the file is called, in every read (`head`, `tail`, `grep`, `cat`, with or without `--lines`), including a key that is joined to the next one, has no end line, or contains a NUL byte. If the server cannot report where the blocks are, every returned line of that file is masked instead. `files grep` skips binary files. Note that `files tail` now reads the whole file first, so on a very large log on a small container use the `logs` commands.
- A grep hit inside a dated release folder (`/opt/app/rel-2026-11/.env`) is now masked like any other `.env`.
- `files download` rejects a malformed size header instead of writing a partial file, and its mismatch message is clearer.
- `files grep --max-bytes` accepts 8,192 or more, the same floor as every other command.

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
- `tunnel open` only reports success once the forward is really listening; a second `-R` on a port that is taken now returns `SSH_TRANSPORT_ERROR`. The tunnel's log is capped (about 120 bytes after 200 connections instead of 60 KB), and a tunnel to a host that stops answering disappears from `tunnel list` within about 45 seconds.
- A failed `db query` keeps readable error text (`column ... does not exist`) while still masking quoted row values, and the host-key mismatch message no longer claims the file holds no stale key when it does.

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
- JSON that is escaped inside a string (`{"msg":"{\"password\":\"...\"}"}`, also with `\uXXXX` quotes) is masked up to 4 levels, a URL that is percent-encoded inside another URL up to 3 levels, and a secret value whose closing quote was cut off at the output limit is masked.
- Password hashes (SCRAM, md5, bcrypt, argon2, crypt) are masked even at the end of a sentence or followed by dots. A key ending in `AUTH` masks its value unless it is a plain boolean or a method word such as `login`, `none` or `md5`.

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

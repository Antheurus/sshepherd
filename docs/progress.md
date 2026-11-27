# sshepherd Progress

## Session — 2026-11-27 (cont) — v0.4.0-rc.12 (Phase 12: named exec, threat-model tests first)

Phase 12, two commits by design: `test(exec)` first (26 cases in `src/__tests__/exec-threat.test.ts`, red at 0 pass / 26 fail because no `exec` op existed), then `feat(exec)` turning it green. New `src/ops/exec.ts` adds three registry entries: `exec run` (definitions with `mutating = false`, profile `read`, no `--yes`), `exec change` (any definition, profile `deploy`, `--yes`, audited incl. refusals) and `exec list` (local, profile `read`); the CLI shorthand `exec <alias> <name>` reads the definition and picks run or change, and `exec run` re-reads it and refuses a mutating one so an edit between the reads fails closed. Two ops instead of one because `OpSpec.mutating` and the `OP_PROFILES` table are static per op and a definition's `mutating` has to decide both the confirm gate and the profile; adding a per-call `mutating` hook to `executeOp` was rejected (another executor owns execute.ts, and an unspecialised base op would have had to be the strict one anyway). Definitions live in `~/.config/sshepherd/exec/<alias>.toml` (`SSHEPHERD_EXEC_DIR` overrides; the test preload points it at the isolated state dir), opened with `O_NOFOLLOW` and checked on the descriptor (regular file, owned by the caller's uid, no group/other bits, at most 256 KiB), parsed whole on every call: `argv` array (1-64 literal-first elements), required `mutating`, optional `container` (must be in the alias's targets.toml `containers`), `allow_shell`, `summary`, and at most 16 typed params (`enum`, `int` 0..n, `path` with `under`, `regex` full-match, `container`), each filling one whole argv element (`"--x={p}"` is a definition error). Every value is refused before its type check when it is empty or over 512 bytes, carries a control character, starts with `-`, holds a shell metacharacter or names a shell; `path` values are refused locally for relative/`.`/`..`/outside `under`, then resolved by `realpath` on the host (inside the container when the def names one) in the same `sh -c` that runs the command, which exits 97 with a marker before the command starts on a symlink hop (`refineError` turns it into `VALIDATION_ERROR`), and the command receives the resolved path. `src/quote.ts` gained `shellJoinExact` (refuses a NUL instead of letting the remote see a cut argv element); `shq` itself is untouched (impact CRITICAL, 22 direct callers). Limits appended to `src/limits.ts`: `EXEC_TIMEOUT_SEC` 120, `EXEC_MAX_PARAMS` 16, `EXEC_MAX_PARAM_BYTES` 512, `EXEC_MAX_ARGV_ITEMS` 64, `EXEC_MAX_DEF_FILE_BYTES` 262144, `EXEC_MAX_DEFS` 200. Output is `{name, lines, lines_returned}` through the shared scrubber with `maskEnvBlocks` and the PEM line pass. The canary gate drives all three ops on both variants (artisan stand-in `/usr/local/bin/php` planted by plant.sh as placement `pa`, every /opt/canary file through a path param, the canary container's `env`, a mutating def). Also edited: registry/profiles/cli (shorthand, `--param` packed as a JSON list), registry and contract tests (new op rows, a def fixture), SKILL.md (one block, counts 16 groups / 76 ops, Gotcha 3 now names named exec), new `references/exec.md`, 3 new `docs/schema/exec-*.json`, and 6 Phase 11 schema files regenerated because the base was missing the `warnings` envelope field there. Not done: a per-definition `timeout` (the op default is 120 s, `--timeout` per call), the definition name in the audit row (audit.ts identifiers are owned elsewhere; only the args hash records it), `exec` stdin is never forwarded.

---

## Session — 2026-11-27 (cont) — v0.4.0-rc.19 (Phase 19: setup host add, setup ssh-alias adopt-env, doctor hosts)

Phase 19, one commit. `setup host add <alias> --host --user [--port] [--fingerprint] --yes` (new `src/setup-host.ts`, admin profile) chains register, keygen, the host-key step, the one-shot install form and `hosts test`, returning `data.steps[]` (each step idempotent, so a re-run reports `register already done` / `keygen already done`) and a `next` pointing at `setup files-allowlist scaffold`. The host-key step never disables checking: a pre-install `hosts test` that fails only with `AUTH_FAILED` proves the key is already trusted; `HOST_KEY_UNKNOWN`/`CHANGED` stops with `data.fingerprints` (from `hosts trust --dry-run`) and the hint to re-run with `--fingerprint`, which records it through the Phase 07 `hosts trust` op via `executeOp` (keeping its profile gate, scrub and audit row). The install connection for host add and adopt-env goes `ssh -F <config> <alias>` under `StrictHostKeyChecking=yes` (new optional `InstallTarget.sshConfigPath`), plain `install` keeps `user@host` with accept-new. `setup ssh-alias adopt-env <project-dir> --yes` parses the project's `.env` (dotenv rules: `export`, quotes, multi-line double-quoted PEM with `\n`, ` #` comments), groups `SSH_*` / `<PREFIX>_SSH_{HOST,USER,PORT,PASSWORD,PRIVATE_KEY}`, names each alias `<project>` or `<project>-<prefix>`, registers, keygens and installs in-process (password to sshpass on stdin, a private key through a 0600 temp file), and returns only `[{alias, key_installed, reason?, next?}]`; an untrusted host key is reported, never accepted. `doctor hosts` probes every alias with `PreferredAuthentications=none` under strict host-key checking and reads the server's method list from `Permission denied (...)`, returning `password_auth_targets[]` (names), `checked`, `unchecked[{alias, code}]` and the harden hint. The authorized_keys append now ends the key with a newline and adds one to a file whose last line lacks it. New limits: `ADOPT_ENV_MAX_FILE_BYTES` 1 MiB, `ADOPT_ENV_MAX_HOSTS` 32, `DOCTOR_HOSTS_CONCURRENCY` 8, `DOCTOR_HOSTS_PROBE_TIMEOUT_SEC` connect+5, `DOCTOR_HOSTS_MAX_ALIASES` 200. Fixture: a password-auth `sshd-pw` service (`Dockerfile.password`, user `deploy`), its password set per run by `smoke.sh` over `chpasswd` stdin into the 0600 state dir, its host keys written for the tests to compute fingerprints, deliberately left out of known_hosts. `SSHEPHERD_INSTALL_NO_BROWSER=1` prints the form URL without opening a browser so the harness can fill the form; it does not bypass the form. Found while building: the install form's timeout timer was never cleared, so every successful `setup ssh-alias install` (and host add) kept the process alive for the full form timeout after printing its result; the live host-add tests hit their 120 s/180 s caps on exactly this, and the fix is one `clearTimeout`. Verified: `onboard-live.test.ts` 4 pass / 0 fail on the `sshepherd-smoke-p19` fixture (host add with a known host key, host add through `--fingerprint`, adopt-env with a password and an inline PEM with 0 canary hits across stdout, stderr, the scratch ssh dir and audit log, doctor hosts names-only), `canary-leak.test.ts` 11 pass / 0 skip, `setup-host.test.ts` + `setup-profiles.test.ts` 34 pass, `bun run check` 0, the full suite with the fixture down as reported in the commit. Human steps left for od-finish: typing each password into the form, confirming fingerprints, saying which hosts are third-party password-only, harden after key login, rotating every password that sat in a `.env`.

---

## Session — 2026-11-27 (cont) — v0.4.0-rc.11 (Phase 11: http on host, wait, git read)

Phase 11, one commit, finishing a previous executor's uncommitted partial build. Three new registry groups, one entry each in `src/registry.ts` so the contract test iterates them: `http get|send` (`src/ops/http.ts`), `wait for` (`src/ops/wait.ts`) and `git head|log|diff-stat` (`src/ops/git.ts`), with CLI shorthands `http <alias> GET <url>` (= `http get`, any other method = `http send`) and `wait <alias> --until ...` (= `wait for`) in `src/cli.ts`, used only when the token after the group is not an action. `http` runs curl on the host: `localUrl` re-serialises the URL through the WHATWG parser and accepts only 127.0.0.0/8, `[::1]` and `localhost` (anything else, or a URL carrying `user:pw@`, is `INVALID_ARGS` before any ssh call); `--auth env:KEY@container=NAME` (NAME must be in the alias's targets.toml `containers`) or `env:KEY@file=PATH` (on the files allowlist) is resolved on the host into a shell variable and reaches curl only as a `-K -` config line on stdin built by awk from the environment, so it is in no argv and never on the wire; the response comes back as `{status, ms, headers_names[], body, body_bytes, body_truncated, body_binary}` with header values left on the host, the body capped at `HTTP_BODY_MAX_BYTES` (64 KiB), every occurrence of the credential masked on the host (counted into `scrubbed`) and then the normal scrubber. `http send` (POST/PUT/PATCH/DELETE, `--json @file|text`, `hiddenArgs: ['json']`) is mutating, profile `deploy`, and needs `--yes`. `wait for --until healthy@container=X | log-contains:<re>@container=X | port-open:N | url:<localhost-url>[:status=N]` polls in one ssh session every `WAIT_POLL_INTERVAL_SEC` (2 s) and stops `WAIT_REPLY_GRACE_SEC` (5 s) before its budget so its own `{met, attempts, elapsed_ms, last_state}` reaches the agent instead of a cut session; `--timeout` 10-3600 (default 600), a container without a HEALTHCHECK is `VALIDATION_ERROR` on the first check, a miss is `COMMAND_TIMEOUT` with the attempts kept in `data`. The `url:` probe reuses the recipe http-probe executor (`httpStatusCommand`, extracted from `httpProbeScript` in `src/recipes.ts` with identical output). `git` is read-only on a files-allowlisted path that must be the repository root (`GIT_OPTIONAL_LOCKS=0`, `core.hooksPath=/dev/null`, `core.fsmonitor=false`), and remote URLs lose `user:password@` on the host. Every limit is in `src/limits.ts` (16 new constants, appended). Fixture: curl and git in both sshd images, `/opt/myapp` a git repo whose remote carries a fake token, a HEALTHCHECK on `app`, and in the canary compose a `canary-app` nginx per sshd sharing its network namespace (200 only with `Bearer <canary>`, a Set-Cookie and an `api_token` body field, `/slow` at 1 KiB/s for a `ps` sampler); `plant.sh` makes `/opt/canary/repo` a repo whose remote and commit subject carry the canary. Found while finishing it: the canary gate failed on the first run because the planted compose file itself leaked the canary through `files cat|head|tail|grep|download` and `config get` — `add_header Set-Cookie "session=<v>"` is not masked by `src/scrub.ts` in file form (the header form `Set-Cookie: session=<v>` is); the fixture cookie is now `session_token`, and the scrubber gap is reported, not fixed here (another executor owns `scrub.ts`). Verified: `bun run check` 0; new + registry tests 224 pass; canary-leak with the fixture up 13 pass, 0 fail, 0 skip, http/wait/git each with ok drives and a live `ps -eo args` sampler per variant with the canary in no argv, envelope, stderr_tail or audit row; the same checks through `./dist/sshepherd` on a hand-planted canary (7452 `ps` samples on debian, 725 of them curl lines; 6734/557 on alpine) found 0 hits; `scripts/smoke.sh` under `sshepherd-smoke-p11` 153 PASS, 0 FAIL; `bun run gen-schema` added exactly the six new op schemas. No migrations, no deploy.

---

## Session — 2026-11-27 (cont) — v0.4.0-rc.7 (Phase 07 follow-ups: parallel fixture, identity canary, psql echo, setup profiles, local scrub)

Phase 07 follow-ups, one commit. Parallel fixture: `scripts/sshd-fixture/project.sh` is the one place the compose project (`SSHEPHERD_SMOKE_PROJECT`, default `sshepherd-smoke`), the container prefix (`sshepherd-fixture` for the default, `<project>-fixture` otherwise) and the state dir (`/tmp/<project>`) are derived; `smoke.sh`, `canary/plant.sh` and `canary-leak.test.ts` all source it, the compose file takes the project, prefix and ports from env (`${PORT-8413}` so an empty value means an ephemeral `127.0.0.1::22`), a non-default project binds ephemeral host ports read back with `docker compose port`, the ssh config is now written after `compose up`, and only the default project records `src/__tests__/fixtures/live/` (two fixtures must not both write it). The default fixture and `sshepherd-smoke-b` ran `just smoke` at the same time, both 0 FAIL, then both canary tests at once. Canary: the aliases now connect under a canary identity (a `h<random>.example.net` HostName reached through `ProxyCommand nc` to the published port, a uid-0 canary user sharing root's key, a random non-22 port, its own known_hosts), and the remote prints that identity plus `203.0.113.77` in a failing deploy step's stderr, fake-journalctl sshd lines (`logs service`/`logs docker-daemon`), `/var/log/auth.log`, a psql connect error from a `canary-pg` container whose PGHOST is the peer and the identity host, and an `ss` listener on the peer (compose `sysctls: net.ipv4.ip_nonlocal_bind`); every placement must be reached raw and none may reach an envelope or audit row; a second test per variant sets `reveal_addresses = true` and requires the peer back in all five drives with the identity still hidden. Psql echo: `src/scrub.ts` `PSQL_DATA_ECHO_RULES` masks the value in `invalid input syntax for type`, `invalid input value for enum`, `value "<v>" is out of range` (and the float form with no `value`), `malformed array/record/range literal`, `date/time field value|interval field value|time zone displacement|date|timestamp out of range`, `invalid value "<v>" for`, JSON `Token "<v>"` / `but found "<v>"` / `JSON data, line N:`, `Key (...)=(...) already exists|is not present|is still referenced|conflicts with existing key` and `Failing row contains (...)`; ten canary db probes (two seeded functions raise the exact unique/not-null DETAIL texts, since a read-only transaction cannot write) and 17 unit cases. Setup profiles: `SETUP_PROFILES` in `src/profiles.ts` (list/status read, the other ten admin, a missing action admin) and `setupProfileDenial`, checked in `runSetup` before dispatch with `PROFILE_DENIED` exit 2; a contract test iterates `SETUP_SUB_GROUPS` and a subprocess test per writing action proves nothing under a temp HOME changes. Local scrub: `scrubLocalOutput` (secrets + rule 2, no identity) now runs over `doctor`, the CLI argument-error envelope, the `main` catch-all (extracted as `printFailure`) and every `printSetupResult`. Found while building: the random digits canary made `::date` raise `date out of range: "<v>"` in one run (4 of 150 random values do, read off the fixture postgres), a second date text the first rule set missed, so the class was re-enumerated against the real server (date, timestamp, interval, float, smallint/bigint/oid/money casts); the canary test passed the alias, not the `target` arg, to `buildDbOpContext`, so a second db target was silently never driven; and a `PGPORT`-style key equal to the alias port is not masked (port masking needs a separate `port` word). Verified: `bun test` 731 pass / 7 skip (the canary file) / 0 fail with the fixture down, `just smoke` 100 PASS / 0 FAIL on both projects at once, canary 7 pass / 0 skip on each, the identity-scrubber run fails 51 drives per variant, the new local-output, setup-profile and psql tests each fail with their fix removed.

---

## Session — 2026-11-27 — v0.4.0-rc.7 (canary leak gate, permission profiles, strict host keys)

Phase 07. Leak gate: `src/__tests__/canary-leak.test.ts` plants a fresh random canary (24 letters/digits, no prefix) on the running smoke fixture through `scripts/sshd-fixture/canary/plant.sh` (templates in the same directory, every docker command naming a fixture container) in 19 tagged placements: the canary container's Env (API_TOKEN, DATABASE_URL password, POSTGRES_PASSWORD and four log-printed values), its compose file, five app log lines (`password=`, `Authorization: Bearer`, query-string `token=`, JSON `client_secret`, bare DATABASE_URL), `.env`, `prod.env`, `config.json`, a PEM private key body, nginx access/error logs and two columns of a `canary_users` table. It then runs every op with `exposes != none` from `listOps()` on both sshd variants (61 drives each; a required arg nobody gave a value fails the test, an undrivable op needs a reasoned entry in a reviewed `SKIP` list, currently empty) and searches the envelope JSON, `error`, `stderr_tail`, the audit row from a temp log and every `files download` output for the canary: 0 hits, and every placement was read raw by at least one op (download reach comes from decoding its base64 line). With `SSHEPHERD_TEST_SCRUB_IDENTITY=1` the test swaps `scrub`/`scrubText`/`maskEnvContent`/`maskPemLines` for identities with `spyOn` inside its own process and fails with 30 hits per variant; no shipped file reads that variable (a source-scan test), and a test compiles the binary and shows `files cat` still masks with the variable set. The gate found two things: my own compose template comment carried the placeholder (fixed), and a real gap, a psql cast error (`invalid input syntax for type integer: "<value>"`) echoing a row value into `sql_error`/`stderr_tail`, left for the scrubber owner because only `src/scrub.ts` can close it. Profiles: `src/profiles.ts` owns `read` < `deploy` < `admin` and a per-op table (every read-only op and any `--dry-run` = read, mutating ops = deploy, `security harden` and `hosts trust` = admin); `executeOp` refuses with `PROFILE_DENIED` (exit 2) before the confirm gate and before any runner call; unset `SSHEPHERD_PROFILE` = admin, any other value refused; a pg-target's `max_profile` (targets.toml, validated on load, flattened into the db op context) caps db ops on it. The table sits outside `OpSpec` because the Phase 06 fix owns `ops/files.ts`/`ops/logs.ts`; the contract test fails on a missing or stale entry. Host keys: `StrictHostKeyChecking=yes` on the ControlMaster open, the command and tunnels; `classify` returns `HOST_KEY_CHANGED` (replacing `HOST_KEY_MISMATCH`, tested first because that banner also says "verification failed") or `HOST_KEY_UNKNOWN`, both with `next: hosts trust <alias> --dry-run`. New `hosts trust` (mutating, admin) fetches the presented key with one ssh into a throwaway known_hosts (`PreferredAuthentications=none`, `ControlPath=none`), shows its fingerprint on `--dry-run`, and with `--fingerprint SHA256:... --yes` records it in the alias's own `UserKnownHostsFile` (hashed when `HashKnownHosts yes`) replacing that host's stale entries, or refuses with `HOST_KEY_CHANGED` when the fingerprint differs. The smoke fixture now writes its known_hosts from each container's own host keys and checks strictly; the matrix proves UNKNOWN, a refused wrong fingerprint, trust, CHANGED and re-trust on both variants. Both sshd Dockerfiles gained the compose plugin, which `deploy status/logs/rollback` and `services compose-ps` need. Verified: `bun run check` clean, `bun test` 632 pass / 0 fail / 0 skip with the fixture up (603 before), canary file 5 pass with the fixture and 2 pass / 5 skip without, `just smoke` 99 PASS / 0 FAIL, the real audit log unchanged at 11,704 lines. Not done: `setup` still bypasses the profile gate (it never goes through `executeOp`), and `setup ssh-alias install` keeps `accept-new` for its first human-driven connection.

---

## Session — 2026-11-26 (cont) — v0.4.0-rc.6 (output caps, field selection, schema, audit rows)

Phase 06. Transport: `defaultRunner` now reads stdout through `readCapped` with `MAX_STDOUT_BYTES` (2 MiB, `src/limits.ts`). A read op is `kill-head`: at the cap the ssh client is killed (the ControlMaster survives, proven by two ordinary calls and a live `-O check` afterwards on debian and alpine) and the call counts as a clean one that returned a prefix (`raw.outputTruncated`). A mutating op is `drain-tail`: never killed mid-run (a half-finished deploy is worse than a long log), keeps the last 2 MiB so the step-failure marker survives. A cut-short ndjson stream drops its unfinished last line; a cut-short native-json payload is the new `OUTPUT_TOO_LARGE` error. Output: `capEnvelope` runs in `executeOp` after the scrubber, `--fields`, and `--limit`, on already-masked values, so a cut cannot split a mask; it trims `data` (strings and lists keep their head, deploy ops set `truncateKeeps: 'tail'`) until the printed JSON is at most `--max-bytes` (default 65,536, range 8,192 to 2 MiB), sets `output_truncated`, and never cuts `error`. `--fields` takes dot paths relative to `data` (a leading `data.` is accepted, lists are walked per item) and reports unmatched paths in `fields_unmatched`; `--tail` is validated 1..5000. Envelope: `schema_version: 1`; `src/schema.ts` + `scripts/gen-schema.ts` (`bun run gen-schema`) write `docs/schema/envelope.json` and one schema per op, with data shapes inferred (types and keys only) from the recorded live fixtures; `schema-snapshot.test.ts` fails when a generated file differs from the committed one (proved red by adding an envelope field). Audit: rows now carry `args_sha256` (full sha256; crc32 `args_hash` kept), `recipe`/`target`/`container`/`unit` (never an op's `hiddenArgs`), `duration_ms`, `remote_exit`, `error_code`, `bytes`, `profile` and `session_id` when `SSHEPHERD_PROFILE` / `SSHEPHERD_SESSION_ID` are set; ops that expose content are audited as well as mutating ones; the log rotates at 50 MiB keeping 5 files; new op `audit tail --n --alias --op` returns `{rows, row_count}`. Test isolation: the bunfig preload points the reveal, files and config allowlist paths at a temp dir (`HOME` set to an empty dir gives the same 592 pass). Smoke: new `noisy` fixture container (5 MiB of log lines), recipe step now `echo` (it used to run `docker ps`, which lists the host daemon), 80 PASS / 0 FAIL on debian + alpine, fixtures re-recorded. Not done: per-line 4 KiB cap and `logs` ops keeping their tail on a cut (needs `truncateKeeps: 'tail'` in `src/ops/logs.ts`, held back to avoid colliding with the scrubber fix); `db query` still returns a bare array, so `--fields data.rows` matches nothing until Phase 2 gives it `{rows}`.

---

## Session — 2026-11-26 (cont) — v0.4.0-rc.5 (scrubber receipt fixes)

Phase 05 fix, from the audit receipt (F1-F10, F6b), with the auditor's 17-test leak hunt committed as `src/__tests__/audit05-leak-hunt.test.ts`. `files download` now masks the `KEY=` lines of a non-UTF-8 env-shaped file on its bytes (read as latin1, so every other byte is written back unchanged) instead of writing it raw. `files tail` and `logs docker` split output into lines before the scrubber sees it, so a PEM block's body lines were never inside one string with BEGIN/END; the new `maskPemLines` masks every line between a private-key BEGIN and END, and the unpaired-BEGIN/END shape rules no longer fire on a bare header line, so the envelope pass leaves those lines alone. A timed-out op on an env-shaped allowlisted path gets `maskEnvContent` over `partial_stdout` before the cap. `scrub` masks any string or number under a secret key at any depth (`{"password":123}`, `{"tokens":["x"]}`, `{"password_hash":{...}}`). New shapes: `--password <v>` with a space, `mysql -p<v>`, `*_PWD`/`*_PW` names (not `PWD`/`OLDPWD`), `scheme://:pass@` with an empty user, `github_pat_`, `rk_live_`, `glpat-`, `AIza`, `whsec_`, Slack webhook paths, PGP private key blocks, `Cookie:`/`Set-Cookie:` values and `<password>x</password>`. `Bearer` now needs a digit or 16 characters after it, so "a Bearer token" in prose stays. A revealed key skips only the key-name rules; the shape rules run first, so `--reveal DATABASE_URL` keeps its URL password masked. `isSecretKey` no longer treats URL/URI names or a bare `key`/`monkey` as secret. A KEY segment counts only in a multi-segment name, plus camelCase `...Key`. A URL's credentials are caught by its shape (landed together with the empty-user URL rule, so `REDIS_URL=redis://:p@h` never leaked in between). The unanchored key rules (inline, adjacent, the new spaced-flag rule) now start a name only where a run of name characters starts. Starting after every `-` rescanned the rest of the line each time, which was quadratic: a 204 KB hyphenated line took 114 s and now takes 67 ms per pass; 210 KB of `a--` takes 66 ms. The URL scheme is bounded to 32 characters. Three `scrub.test.ts` expectations changed because the receipt reverses them (DATABASE_URL/MONGO_URI secret by name, a revealed URL keeping its password), and one test pins REDIS_URL/DATABASE_URL/API_KEY/SECRET_KEY/AWS_SECRET_ACCESS_KEY/PRIVATE_KEY still masked after the narrowing. Verified: 560 tests pass, `bun run check` clean, `just smoke` run against the debian/alpine fixture. Known over-mask: `--token-file <path>` masks the path.

---

## Session — 2026-11-26 — v0.4.0-rc.5 (one scrubber for every op)

Phase 05 of the overhaul. `src/scrub.ts` is now the one owner of secret masking: `scrubText` masks values under a secret-named key (the reveal denylist plus names containing SECRET/TOKEN/PASSWORD/PASSWD/PASSPHRASE/CREDENTIAL or ending in / segmented as KEY/PASS/DSN/URL/URI) in `KEY=v`, `export KEY=v`, `key: v`, `"key": "v"`, inline `a=b&token=x` and `--token <32+ base64/hex>` forms, including double/single-quoted values that span lines (bounded at 16 KiB so an unclosed quote cannot rescan the whole text) and backslash-continued values; plus JWTs, `sk-`/`sk_live_`/`gh?_`/`xox?-` tokens, AWS key ids, PEM private keys (whole, truncated head or orphan tail), the password in `scheme://user:pass@` and `Bearer`/`Authorization: Basic` tokens. `scrub` walks any payload and masks a string under a secret key whole, which is what keeps a `db query` password column out. `PORT`, `NODE_ENV`, `DB_HOST` stay visible; exact-value redaction stays rejected. Every OpSpec now declares `exposes: none|metadata|content` (typed as required, contract-tested), and `executeOp` makes ONE `scrub` call per envelope over the shaped data (unless `none`), the error and the command stderr, then sets `envelope.scrubbed` (a count). Non-255 failures carry `error.stderr_tail` (last 20 lines, then last 2 KiB, cut after scrubbing so a cut cannot split a `KEY=` pair) unless the op sets `exposeStderr: false` (`files cat`, `config get`); ssh's own 255 stderr stays discarded (the transport already blanked it). `db` ops parse psql `ERROR:`/`DETAIL:`/`HINT:` into `error.data.sql_error` (no `position`: psql's caret points into the read-only/json_agg wrapper) and mask the target's own user/database/container/compose file/service as whole words in every error (`hiddenArgs`), which kept the existing db zero-knowledge test meaningful once stderr surfaced. Masking parity: `isEnvFile` covers any basename containing `.env`, ending `.vars`/`.secrets`, `credentials*`, `*.pem`, `id_*`; `files cat`, `files tail`, `config get` (now with `masked`) and `files download` all apply it, and download writes the masked bytes to disk (text only; a binary file is written byte for byte) with a new `--reveal` gated exactly like `files cat`'s. Per-alias extra patterns live in reveal-allowlist.toml as `[<alias>.scrub] extra_patterns`, loaded before the op runs; a pattern that does not compile is refused by index, never echoed. Found while building: the scrubber re-masked `KEY=***MASKED***` from env masking into `***` (fixed by recognising both masks), and two pre-existing tests asserted no command stderr ever reaches an envelope, which P1.4 deliberately reverses; the IP-in-stderr test now drives the real transport path (exit 255) and a second test pins the non-255 `stderr_tail`. Verified: `bun test` 542 pass / 0 fail (scrub.test 24, contract test spies `scrub` on all 39 ops that expose output (24 metadata, 15 content; 17 none) and was falsified by skipping content-op data); `bun run check` clean; `just smoke` 61 PASS / 0 FAIL on debian and alpine, including `files cat|tail|download` of fixture `/opt/myapp/prod.env` and an `export SESSION_SECRET=` script, and `db query "SELECT nonexistent"` returning `sql_error.message` `column "nonexistent" does not exist`. Not released; no migration. Files: src/scrub.ts, src/execute.ts, src/types.ts, src/output.ts, src/ops/*.ts, src/cli.ts (help line), scripts/smoke.sh, scripts/sshd-fixture/Dockerfile.{debian,alpine}, SKILL.md, canary expected-keys (`scrubbed`).

---

## Session — 2026-11-26 — v0.4.0-rc.4 (release pipeline, doctor, live smoke)

Phase 04 of the overhaul. `just release <semver>` (scripts/release.sh) runs `bun test` and `bun run check`, builds with a stamp compiled in through `bun build --define SSHEPHERD_BUILD_STAMP` (git sha, UTC time, registry hash = first 12 hex of sha256 over the sorted `group/name` list; `-dirty` suffix on an unclean tree), refuses a semver that differs from package.json, then installs to `${SSHEPHERD_INSTALL_DIR:-$HOME/.local/bin}/sshepherd` by temp file plus rename. A symlink at the target is replaced by a regular file, never followed, and the previous target's BYTES are kept as `sshepherd.prev`; `just rollback` renames a copy of `.prev` back. `--version` now prints `sshepherd <package.json version> (<sha>, <time>, registry <hash>)` (src/version.ts), which also removes the stale `VERSION = '0.3.0'` constant in cli.ts; unstamped dev/CI builds print `(dev, registry <hash>)`. `sshepherd doctor` (src/ops/doctor.ts, a top-level local command like `setup`, re-exported from registry.ts) reports installed vs dist sha256, whether SKILL.md's documented op set equals the registry, and pg-target NAMES whose user does not look like a read-only role (`ro` as a delimited word, `readonly`, `read_only`). `just smoke` now runs one compose project `sshepherd-smoke` with a debian and an alpine sshd (host ports 8413/8414, 127.0.0.1 only, env-overridable, checked free with lsof first), a fixture-only ssh config reached through SSHEPHERD_SSH_CONFIG_PATH (the transport and the tunnel supervisor now pass `-F` when it is set, so nothing touches ~/.ssh/config), audit and tunnel state in the fixture state dir, and the matrix per variant: two sequential `hosts test` leaving exactly one live master, check overview, services ps, logs docker, files ls, security listeners, db list/tables/query, deploy dry-run, a `--timeout 2` query against `pg_sleep(10)`, tunnel open/curl/list/close, `hosts disconnect`. 47 PASS, 0 FAIL; outputs under src/__tests__/fixtures/live/<variant>/ (services ps filtered to the fixture project, since the mounted host socket also lists unrelated containers). `smoke.sh canary <alias>` runs the read-only ops against a real alias and diffs envelope key sets against src/__tests__/fixtures/canary/expected-keys.json. Found on the real hosts: busybox `timeout` returns the child's status (143, or 1 from a `docker exec` client) instead of 124, so P02's exit-code-only timeout detection missed it on alpine; classify() now also calls a non-zero exit that used the whole `--timeout` budget a COMMAND_TIMEOUT. A pure-busybox host also fails `files ls` (`ls --time-style` is GNU only), so the alpine fixture installs coreutils and points `/usr/bin/timeout` back at busybox to keep the one busybox behaviour under test; ops still assume GNU coreutils. Alpine's stock sshd_config has `AllowTcpForwarding no`, which the fixture flips. The `--` insertions from P03 all ran clean against both real sshds. CI gained `just check-skill` (the skill-doc test). Gates: 500 pass, 0 fail, `bun run check` clean. The real ~/.local/bin swap is deferred to Landing; this phase installed only into temp prefixes. Receipt fix: the `clean` recipe (`rm -rf dist node_modules`) deleted in dd3d0df is back in the justfile; `release.sh` now checks the install dir is a writable directory before running tests and exits 1 with `release: install dir <dir> is not writable; set SSHEPHERD_INSTALL_DIR ...`; `doctor` reports `targets_file: "missing"` with `pg_targets_without_ro_role: null` when targets.toml is absent (was `[]`, same as all-fine); and the Bun TOML-to-CONFIG_PARSE_ERROR conversion moved out of targets.ts into one owner, src/toml-parse.ts `parseTomlFile(text, label, hint)`, now used by targets.toml, the config/files/reveal allowlists and deploy recipes, so a malformed one names the file kind and line (exit 2, line text never echoed) instead of INTERNAL_ERROR. 514 tests pass, check clean. Noted, not changed: doctor on this machine reports skill_registry_match false against the installed SKILL.md.

Phase 03 fix, from the audit receipt. An audit line that fails to write after a mutating op ran used to escape executeOp as a raw fs exception (the result lost, the message quoting the log path); the audit now runs after the op's own try/catch and a write failure returns AUDIT_WRITE_FAILED keeping `data`, with `op_outcome` (ok/error ran, refused did not) and `op_error` (the op's own error) on the ErrorInfo, exit 1 — the op is not re-run or rolled back, since it already happened. The CLI's top-level catch now withholds a non-OpError's message the same way executeOp does (internalErrorInfo, exported from execute.ts), and targets.toml problems are CONFIG_PARSE_ERROR (exit 2): Bun's TOML parser throws a BuildMessage that is not an Error, so loadTargets reads its `message` and `position.line` and never `lineText` (a target line can hold a secret); readTarget's semantic errors became the same code so they stay readable now that plain Error text is withheld. unknownAliasError refused names ssh accepts because listHostAliases skipped wildcards and ignored Include/Match; src/parsers/ssh-config.ts now follows Include (globs, `~`, relative to ~/.ssh and to the config's own dir, depth 16 like OpenSSH) and reports literal aliases, wildcard Host lines and whether any Match block exists, and an echoed `-G` name passes when it is literally declared, matched by a wildcard Host line (negations honoured, a bare `*` ignored so a `Host *` defaults block never turns every bare hostname into an alias), or any Match block exists (sshepherd does not evaluate Match, so it defers to ssh). hosts list, setup ssh-alias and the tunnel's declared-alias check all read Include'd aliases through the same function. Paths (path/local_path/remote_path/file) lost the charset allow-list: shq quotes everything, so only a leading `-` and NUL/CR/LF are refused; names keep the allow-list. setup actions refuse an unknown flag with a new setup PARSE_ERROR (exit 2) from one per-action flag table in setup.ts. Smoke fixture host ports moved to 8413/8414 (the previous defaults collided with another project's registered ports). Gates: 507 pass, 0 fail, `bun run check` clean, `just smoke` 47 PASS 0 FAIL on debian + alpine, real audit log line count unchanged by `bun test`.

---

## Session — 2026-11-26 — v0.4.0-rc.3 (errors that say what to do next)

Phase 03 of the overhaul, roadmap P0.2, P0.8 and P0.9. `ErrorInfo` gained `hint`, `retryable` and optional `next` (an exact command) and `did_you_mean`, filled per code in the new `src/errors.ts` (the old `ERROR_MESSAGES` table moved there; `errorInfo` is still re-exported from `transport.ts`). `executeOp` now wraps the whole op in try/catch and audits mutating ops in `finally`, so a throw in `buildRemote`, `shape` or `runLocal` still writes exactly one audit row and returns an envelope: an `OpError` (new base class in `types.ts`, `OpRunLocalError` extends it) keeps its code, anything else becomes `INTERNAL_ERROR` whose message names only the error class because a `JSON.parse` message quotes remote output. The CLI's top-level catch prints a JSON envelope instead of bare stderr; unknown group/action is `UNKNOWN_SUBGROUP` (the small closed set is listed in full in `did_you_mean`, which is why `check bogus` offers `disk`), an undeclared flag is `PARSE_ERROR` (before, `--tial 5` was silently dropped), a missing positional is `INVALID_ARGS`, and exit 2 now means a wrong command line or config while 1 means a run that failed. `ssh -G` exits 0 for any name, so the old alias check never fired and `hosts test nonexist` came back as `SSH_TRANSPORT_ERROR`; the transport now treats an alias as unknown when `-G` echoes the name back as the hostname and no `Host` stanza declares it (an alias reached only through an `Include` with no HostName would be misjudged unknown; noted, not handled). `assertOpPositionals` in `op-args.ts` refuses a leading `-` and out-of-charset values for alias/container/unit/service/stream/id/recipe/target and path arguments before any runner call (sql is deliberately exempt: psql takes it as the value of `-c`), and `--` now precedes the positional in docker inspect/restart, systemctl, ls, tail and du. The audit log path is read at call time from `SSHEPHERD_AUDIT_PATH` / `SSHEPHERD_STATE_DIR`, so every `setup-*` `auditMutating` call (which passes no deps) follows it without edits, and `bunfig.toml` preloads a temp `SSHEPHERD_STATE_DIR` for `bun test`; the compiled binary never sees it. Setup results carry the same `hint`/`retryable`/`next`/`did_you_mean`, `setup <sub> <action> --help` answers before required-argument validation, and `setup` usage errors exit 2. Unknown pg-target and recipe names suggest near matches. Verified: `bun run check` exit 0, `bun test` 494 pass / 0 fail (up from 423), real audit log line count unchanged across the run, and the new shape-throws contract test fails when the `finally` audit is removed. Follow-up: stderr tails are Phase 05; `VERSION` in `cli.ts` is still `0.3.0` until the Phase 04 release stamp.

---

## Session — 2026-11-26 — v0.4.0-rc.2 (transport: master reuse, timeouts, argv)

Phase 02 of the overhaul, roadmap P0.3-P0.7. `parseArgv` now treats `yes`, `dry-run`, `keep-session`, `pretty`, `help` and `all` as value-less (they used to swallow the next token, so `deploy run --yes r1` lost `r1`) and `--` ends flag parsing; the shared `BOOLEAN_FLAG_NAMES` set also drives `mapArgsToCtx`, and `runSshAliasAction` in setup.ts parses through the same function unchanged. The ControlMaster is no longer torn down by the CLI's per-invocation `finally`: it opens with `ControlPersist=300` and the next invocation's `-O check` finds it, so two sequential `run()` calls open one master (scripted-runner test); `-O exit` now runs only when `-O check` answers "Connection refused" (a stale socket), the socket name is a 16-hex sha256 prefix of the alias instead of crc32 (a 32-bit collision would have run one alias's commands on another's master), and `hosts disconnect [alias|--all]` closes masters on demand (`--all` walks the socket directory, since names are hashed). The master-open outcome was discarded before; it is now classified: a 255 goes through `classify()` into `CONNECT_TIMEOUT` / `AUTH_FAILED` / `SSH_TRANSPORT_ERROR`, a local kill of the open is `CONNECT_TIMEOUT`, and the command never runs after a failed open (ConnectTimeout=10 is also on the command call; ServerAlive options were already there and are not duplicated). The remote wrapper is now `timeout -k 10 <sec>` (short form, accepted by busybox as well as GNU), and remote exit 124 / 137 map to `COMMAND_TIMEOUT`; timeout errors carry `phase` (connect|command), `timeout_sec`, `elapsed_ms` and, for commands, `budget_sec`, and `executeOp` returns the command's stdout so far as `data.partial_stdout` (capped at 64 KiB). `--timeout <sec>` is global: the CLI validates an integer 1-3600 (else an `INVALID_ARGS` envelope, exit 2, no ssh) and passes it as `ExecuteDeps.timeoutSec`; the per-op `timeout` ArgSpecs on `deploy run`/`migrate` and the `ctx.args.timeout` path in `executeOp` are gone so there is one owner. Every limit now lives in the new `src/limits.ts` with its reason: check 30 s, services 20, db 60, hosts test 10, deploy 300, max 3600, ControlPersist 300, ConnectTimeout 10 (`op-args.ts` re-exports the three older constants). Verified: `bun run check` clean, `bun test` 423 pass / 0 fail (was 392), 16 new cli tests, 17 new transport tests; no real ssh was spawned. Deviations: `ops/check|services|db|deploy.ts`, `SKILL.md` (skill-doc drift test requires every op documented) and the three `ctx.args.timeout` tests in `registry.test.ts` were touched because the per-op defaults and the single `--timeout` owner require it. Residual: a master that outlives a changed `~/.ssh/config` keeps the old settings until `hosts disconnect --all` or 5 idle minutes; `VERSION` in cli.ts still reads 0.3.0 (pre-existing).

---

## Session — 2026-11-26 — v0.4.0-rc.1 (registry split by group)

Phase 01 of the overhaul: the 2536-line `src/registry.ts` is now a 53-line index over one module per group in `src/ops/` (hosts, check, logs, services, files, config, db, deploy, security, tunnel), each exporting its `OpSpec[]` as `<group>Ops`. `executeOp`, `ExecuteDeps` and the timeout-override clamp moved to `src/execute.ts`; helpers used by two or more groups (arg readers, shared timeout/size constants, `readRecord`, the compose-ps shaper that `deploy status` shares with `services compose-ps`) moved to `src/op-args.ts`; the allowlist loaders stay with `config`, the only group that owns them, and `registry.ts` re-exports every previously exported name so no importer or test changed. Ops modules import only from `op-args.ts`, `execute.ts`'s dependencies and the pre-existing modules, never from `registry.ts`, so there is no cycle. Op order in `listOps()` is unchanged. A new contract test, `src/__tests__/registry-contract.test.ts`, iterates `listOps()`: unique `group/name`, `0 < timeoutSec <= 3600`, and an audit spy through `executeOp` (failing fake runner, temp audit log, env-redirected allowlists, targets, recipe and tunnel state) that records which mutating ops write an audit row; at base all 14 mutating ops do (13 with outcome error, `tunnel close` ok) and no read-only op does. Verified: 392 tests pass (334 base plus 58 new), tsc and biome clean, and `--help` for the top level and every group is byte-identical between the base build and the new build. Follow-up (P03): the test suite still writes to the real audit log by default.

---

## Session — 2026-07-20 — v0.3.0 (tunnel: local/remote/dynamic SSH port forwarding)

Added a new `tunnel` op group (`open`/`list`/`close`), the first Voltius-inspired feature gap
identified during a comparison pass against that Termius-alternative GUI client — most of Voltius's
surface (local terminal, split panes, themes) solves a different problem than sshepherd's zero-knowledge
agent-CLI model, but port forwarding was a real, missing capability with no workaround. Every existing
op in the registry is a one-shot blocking `ssh <alias> <command>` round trip through `transport.ts`; a
tunnel (`ssh -N -L/-R/-D`) deliberately never exits, so it needed a genuinely new execution primitive
rather than another `OpSpec` entry. Landed as: `tunnel open` spawns a detached, self-supervising
subprocess — the compiled `sshepherd` binary re-invokes itself in a hidden `tunnel __supervise` mode,
which runs the real `ssh` as its own child and holds an in-process JS timer that force-kills it when
`--duration` elapses. This replaced the design spec's original proposal to shell out to the `timeout`
command, rejected mid-build because GNU `timeout` isn't reliably present on macOS — the in-process timer
is portable across every release target with no new external dependency. `tunnel close` kills the whole
process group (supervisor + its ssh child) via a negative PID, not just the supervisor, since a
positive-PID kill would orphan ssh — proven by an adversarial test that spawns a real parent+child
process group, temporarily patches the kill call to positive-PID, and confirms the child survives and
the test correctly fails, then reverts. `tunnel list` opportunistically prunes dead/expired state on
every read and can itself force-kill a tunnel that's past expiry but whose supervisor timer hasn't fired
yet — documented explicitly as NOT side-effect-free, since a function named `list` silently able to kill
a process is a real principle-of-least-surprise risk for an agent-facing tool. A real security gap was
found and closed mid-build, not in the original design spec: the tunnel path spawns ssh directly and
never goes through `transport.ts`, so it doesn't inherit that module's existing `ssh -G <alias>`
injection guard — `openTunnel` now validates the alias against `listHostAliases(~/.ssh/config)` (the same
mechanism `hosts list` already uses) before ever building an ssh argv, so a leading-dash alias string
(`-oProxyCommand=<cmd>`) can never reach ssh as a parsed option. Two more issues surfaced only in the
final cross-task review (reading all 11 build tasks composed together, which no single task's own review
could see): a `--duration` value that parsed to `NaN` slipped past range validation (NaN compares false
to both bounds) and would spawn a real detached process before crashing with a raw `RangeError` —
fixed with an explicit finite-number guard; and two error codes (`TUNNEL_PORT_TAKEN`,
`TUNNEL_SPAWN_FAILED`) were declared with a doc-comment promise that `openTunnel` would verify the spawn
actually succeeded, but the verification was never implemented — resolved by removing the unfulfilled
promise rather than bolting on a synchronous liveness check that would have added real latency to every
`tunnel open` call and required reworking the dependency-injection seam 117 existing tests already
depend on; `tunnel open`'s `ok:true` now honestly means "the process was spawned," with `tunnel list`'s
next call as the point where a dead tunnel actually surfaces, consistent with the feature's fire-and-forget
design. A known, deliberately-unhardened limitation is documented rather than silently fixed: tunnel
state is keyed on PID alone, so a since-exited supervisor's PID could in principle be reused by an
unrelated process-group leader before its state file is pruned — judged low-probability for a
single-operator local tool and out of scope for this build, tracked in `SKILL.md` Gotcha #12 rather than
solved with start-time/cmdline verification. Built via `subagent-driven-development` in an isolated
worktree (`.worktrees/feat-ssh-tunnel`, branch `feat/ssh-tunnel`) across 11 sequential tasks plus one
final cross-task fix, each with its own implementer → spec-compliance review → code-quality review cycle
(several review-and-fix loops along the way, all closed before moving on). Final state: 334/334 tests
passing (28 new `tunnel.ts` unit tests, 89 registry-level tests including the two new-code paths deferred
all the way back from Task 2's own review), `tsc --noEmit` clean, `SKILL.md` fully in sync with the real
registry (verified by `skill-doc.test.ts`'s drift guards). A live smoke-test section was written for
`scripts/smoke.sh` (opens a real tunnel against the disposable sshd fixture, curls through it, closes it,
confirms the port releases) but not executed — no Docker host in the build environment — joining
`just smoke`'s existing built-but-not-run status until run on a real machine. Two design-spec revisions
(the `timeout`-vs-self-supervisor change, and `tunnel close`'s idempotent-success-not-error semantics for
an unknown id) are recorded in `docs/superpowers/plans/2026-07-20-ssh-tunnel.md`'s own "Design deviations"
section. Bumped to v0.3.0 (new capability, not a fix).

---

## Session — 2026-07-16 — v0.2.2 (files-allowlist + reveal-allowlist, registry-driven allowlist enforcement)

Closed two real security gaps flagged by CodeRabbit during an external code-review pass on
a PR that copied sshepherd's SKILL.md into rohitg00/awesome-claude-code-toolkit: `files
download`/`upload` (and, by extension, `ls`/`cat`/`tail`/`disk-usage`) had no allowlist at
all — any remote path could be read or written, unlike `config get`/`put`, which already
refuse an undeclared path via `config-allowlist.toml` — and `files cat --reveal` could
unmask any key name the agent typed, including a genuinely secret one (`DB_PASSWORD`,
`AWS_SECRET_ACCESS_KEY`), since masking only checked whether a key was in the requested
`--reveal` list, never whether the key itself looked like a secret. Fixed both by
generalizing the allowlist mechanism instead of adding two more copy-pasted per-op checks:
added a declarative `allowlist?: AllowlistPolicy[]` field to `OpSpec` (`src/types.ts`) and
moved enforcement into one place, `enforceAllowlist()` called from `executeOp()` in
`registry.ts` right before `buildRemote` runs — the same "one gate, not per-op bespoke
logic" pattern the file already used for `confirmGate`. `config get`/`validate`/`put`
migrated to the same declarative mechanism (their inline `assertConfigPathAllowed` calls
are gone, replaced by an `allowlist` field); the six `files` ops gained `files-allowlist.toml`
gating (same TOML shape and fail-closed rule as `config-allowlist.toml` — missing file
refuses everything); `files cat --reveal` gained a second gate, a hardcoded
non-overridable secret-pattern denylist (`PASSWORD`, `SECRET`, `TOKEN`, `PRIVATE_KEY`,
`CREDENTIAL`, `API_KEY`, trailing `_KEY`/`_PASS`) checked before a per-alias
`reveal-allowlist.toml`. New `setup files-allowlist scaffold`/`setup reveal-allowlist
scaffold` sub-groups (mirroring `setup config-allowlist scaffold` — `src/setup-files-allowlist.ts`,
`src/setup-reveal-allowlist.ts`, wired in `src/setup.ts`) write those TOML files; the reveal
scaffolder also refuses at scaffold time if a `--keys` entry matches the denylist, so a
mistaken `DB_PASSWORD` never even makes it into `reveal-allowlist.toml`. This is a breaking
change (`files`/`--reveal` were previously unrestricted) — bumped to v0.2.2 as a
security-hardening fix, pre-1.0 so no deprecation cycle. Updated `SKILL.md` (Gotchas #11,
zero-knowledge model bullets, Quick reference — 9 groups/52 ops unchanged, `setup` now 6
sub-groups/9 actions) and `README.md` (zero-knowledge model section, `setup` group
description) to document the real command surface accurately — the copied SKILL.md in the
rohitg00 PR that triggered this had also drifted to only 39 of the 52 real ops, fixed
separately in that PR's own branch, not this repo. Verified: `just check` clean (0
typecheck/lint errors), `just test` 255/255 passing (added test coverage for files-allowlist
fail-closed behavior, `files upload`'s `remote_path`-not-`local_path` check, the reveal
denylist beating a mistaken allowlist entry, and the reveal-keys policy no-op when
`--reveal` is absent), and `just smoke` 16/16 live E2E checks passing against a real
disposable sshd fixture (added a `setup files-allowlist scaffold` step to the smoke script
before the `files ls` check, using `SSHEPHERD_FILES_ALLOWLIST_PATH` the same way the
existing fixture config uses `SSHEPHERD_TARGETS_PATH`/`SSHEPHERD_RECIPE_PATH`). Merged
directly to `main`.

---

## Session — 2026-07-14 — v0.2.1 (files download no longer inlines raw content)

Fixed a zero-knowledge-breaking bug in `files download` (`src/registry.ts`), found via a
real incident: an agent ran `files download <alias> <remote .env.docker path>
/tmp/dest.tmp`, expecting scp-like behavior (bytes land on local disk, never enter the
agent's context) based on the command's name and the old doc example. The old `filesDownload`
`OpSpec` declared only one positional arg (`<path>`, remote-only) — the local destination the
agent typed was silently discarded by `mapArgsToCtx` (extra positionals beyond an op's
declared `ArgSpec[]` are dropped with no error, not even a usage warning), and `shape()`
returned the entire file as `content_base64` in the `Envelope`'s `data`, which `cli.ts`
prints straight to stdout — i.e. straight into the calling agent's tool-result context, in a
trivially-reversible encoding. Unlike `files cat`, `files download` had never had `.env`
masking applied to it at all, so it leaked a real `.env.docker` (DB passwords, `JWT_SECRET`,
`ACCOUNT_ENC_KEY`, marketplace API secrets) into a transcript. Root cause was twofold: (1) no
local-destination arg existed on the op at all, so there was structurally no way to ask for
scp-like behavior even if the agent had read the (single-positional) example correctly, and
(2) even had it existed, the old design returned content in the JSON response regardless.
Fix: `filesDownload` now takes two required positionals, `<path>` (remote source) and
`<local_path>` (local destination); `shape()` decodes the base64 client-side and
`writeFileSync`s it directly to `local_path`, and the envelope's `data` shape changed to
`{found, truncated, size_bytes, written, local_path}` — `content_base64` no longer exists
anywhere in the type or the runtime output, success or failure. The 10 MiB
`DOWNLOAD_MAX_BYTES` guard is unchanged (still refuses via `truncated: true` above that size,
still no partial write). Updated `SKILL.md`'s quick-reference example and zero-knowledge
bullet list, and added Gotchas #10 documenting the incident and the fixed shape so a future
agent session (or an old pre-fix compiled `dist/sshepherd`) doesn't repeat it. Added three new
`bun test` cases in `src/__tests__/registry.test.ts` (`files download` describe block)
covering the found/not-found/too-large paths, asserting the local file's real bytes on disk
*and* that the serialized envelope JSON never contains the secret plaintext or
`content_base64`. `just check`, `bun test` (243 pass), and `just build` all green. Bumped
`package.json`/`cli.ts` `VERSION` to `0.2.1` (fix-level bump — bug fix, not a new
capability). This is a breaking CLI change for anyone already scripting `files download
<alias> <path>` with only one path arg — it now requires a second, local-destination
positional.

---

## Session — 2026-07-13 (cont) — v0.2.0 (setup command group)

Added `setup`, a tenth, deliberately separate command group that writes sshepherd's own
local config files instead of talking to a remote host — explicitly human-only, never
invoked by an AI agent, and dispatched through its own `runSetup` shell in `src/setup.ts`
rather than the registry-driven `OpSpec`/`executeOp` path the other 9 groups use (there's no
remote command or `Envelope<T>` to build; `SetupResult<T>` is its own return shape). Four
sub-groups: `ssh-alias` (register/keygen/remove a managed `~/.ssh/config` stanza, generating
a passphrase-less ed25519 keypair), `db-target` (scaffold a `[<name>]` table into
`targets.toml`), `config-allowlist` (scaffold/union a `[<alias>]` paths table into
`config-allowlist.toml`), and `deploy-recipe` (scaffold a minimal recipe TOML skeleton).
Each writer refuses loudly rather than guessing — `ALIAS_EXISTS`/`TARGET_EXISTS`/
`RECIPE_EXISTS` on a collision, `PARSE_MISMATCH` when a marker doesn't match the exact shape
`register` itself writes, `CONFIRMATION_REQUIRED` without `--yes` — and every mutating action
goes through the same `confirmGate`/`auditMutating` pair the other 9 groups use. Built across
6 phases plus a docs pass, then closed by a cross-phase audit that found and fixed 6 issues:
(1) CRITICAL — none of the 3 TOML scaffolders escaped `"`/`\` in interpolated values, so a
value like `my"alias` wrote a corrupt file that crashed the *next* `db list`/`deploy run`
with a raw, unhandled `Bun.TOML.parse` stack trace; fixed with a new `src/toml-quote.ts`
(`tomlQuote`), hand-rolled rather than `JSON.stringify` because `JSON.stringify`'s `\t`
escape round-trips incorrectly through `Bun.TOML.parse` (a real Bun parser bug — it comes
back as `\f`), so `tomlQuote` leaves tab literal (valid per the TOML spec) and only escapes
`"`, `\`, and the other control characters; (2) `splitLines`/`joinLines` were duplicated
byte-for-byte between `setup-ssh-alias.ts` and `setup-config-allowlist.ts`, extracted into
`setup-file-io.ts` alongside the other shared write primitives; (3) `runStubAction` in
`setup.ts` was dead code once all 4 sub-groups left stub status, deleted along with its
now-stale doc comments; (4) no test exercised the full cross-sub-command sequence a real
onboarding session runs, added `src/__tests__/setup-integration.test.ts` driving
register→keygen→db-target→config-allowlist→deploy-recipe→remove against one shared temp
environment and asserting later steps see the same alias earlier steps wrote; (5) this
progress log entry itself, previously missing across all 8 commits of the build; (6) `setup
ssh-alias` had no path-override mechanism unlike the other 3 sub-commands, added
`SSHEPHERD_SSH_CONFIG_PATH` (purely additive — the real default `~/.ssh/config` is unchanged
when unset), consistent with `SSHEPHERD_TARGETS_PATH`/`SSHEPHERD_CONFIG_ALLOWLIST_PATH`/
`SSHEPHERD_RECIPE_PATH`. `bun test` 221/221, `tsc --noEmit` and `biome check` both clean.
Version bumped to v0.2.0 (`package.json`, `src/cli.ts`'s `VERSION` const).

---

## Session — 2026-07-13 — v0.1.0 (sshepherd v1 complete)

sshepherd's v1 build finished across 7 orchestrated phases. Phase 1 scaffolded the Bun/TS/
biome/just toolchain mirrored from `anywrite`. Phase 2 built the zero-knowledge transport
core (`src/transport.ts`, `src/output.ts`, `src/audit.ts`) — every op runs through one
`transport.run()` execution path, the `Envelope<T>` type structurally has no host/user/port/
ip field, and ssh's own stderr is discarded entirely (classified into a static error enum
instead) so no allowlist-based redaction can ever leak a hostname. Phase 3 built the
registry-dispatch pattern (`src/registry.ts`) and the read-only groups — `hosts`, `check`,
`logs`, `services` (read side), `files` (read side) — with hand-written and native-JSON
parsers for df/free/uptime/ps/du/ls/ss/dmesg/journalctl/docker inspect-stats-compose-ps.
Phase 4 added the `db` group (Postgres, read-only v1) with three enforcement layers — a
recommended read-only engine role, a `BEGIN TRANSACTION READ ONLY; ...; ROLLBACK;` wrapper
around every query, and a local `node-sql-parser` SELECT-only check — and the phase audit
caught a real security defect: a crafted `db query` payload could close the `json_agg`
wrapper's subquery boundary early and inject a bare `COMMIT` to end the read-only
transaction before an injected write ran; fixed with `assertNoMultiStatementSql`, which
rejects any bare `;` in `db query`'s free-text SQL before parsing, re-verified live. Phase 5
added the mutating groups — `services` (restart/systemctl verbs), `config`, `deploy`
(TOML recipes with typed steps, topological `depends_on` ordering, dry-run planning,
declared `[rollback]` blocks), and `security harden` — behind one shared `confirmGate` +
`auditMutating` gate in `executeOp`, the only exemption being `deploy run --dry-run` (plans
locally, touches no ssh). That phase's audit found a second defect: a deploy step failure
surfaced as a bare `COMMAND_FAILED` with no indication which step broke; fixed by wrapping
each step with a `__SSHEPHERD_STEP_FAILED__ <idx> <kind> <name>` stdout marker surfaced via
a new `OpSpec.shapeError` hook into `data.failed_step`, re-verified live including an
injection-safe marker check. Phase 5B closed a scope gap (the four read-only `security` ops
and `files upload` had never been assigned a phase despite being part of the locked 9-group
set). Phase 6 wrote the real CLI dispatcher (`src/cli.ts`, replacing the Phase 1 placeholder)
and `SKILL.md` at the repo root with `references/{transport,recipes,db,output-shapes}.md`,
plus a bidirectional drift test proving the doc and the registry can't silently diverge.
Phase 7 (this session) is OSS packaging: `README.md` (four install channels — `npx skills
add`, `/plugin marketplace add`, release binaries, `just build` — plus a "What sshepherd
NEVER does" trust section), `SECURITY.md` (threat model + GitHub private vulnerability
reporting), `CONTRIBUTING.md`, `.github/workflows/ci.yml` (typecheck+lint+test+build on
every push/PR), `.github/workflows/release.yml` (cross-compiles darwin-arm64/darwin-x64/
linux-x64/linux-arm64 on tag push, generates SHA-256 checksums per binary, and attests build
provenance via `actions/attest-build-provenance`), `.claude-plugin/{marketplace,plugin}.json`
for `/plugin marketplace add`, and a Docker-based smoke fixture (`scripts/sshd-fixture/` —
an sshd container with docker CLI mounted against the host daemon, a sibling Postgres seeded
with a read-only role, and a sibling app container — plus `scripts/smoke.sh`, wired to `just
smoke`) that spot-checks a representative read-only op per group, a `db` op, and a `deploy
run --dry-run` against a real Linux host. Across the whole build the zero-knowledge
invariant held structurally the entire way — no phase ever added a host/user/port field to
any type, and both audit-found defects were injection/observability bugs in the SQL and
deploy layers, never a credential leak. The suite sits at 160 passing tests (`bun test`),
`just check` (tsc + biome) clean throughout. The one remaining gap, carried forward from
Phase 3 and closed only in shape (not in verification) by this phase: every Linux command
shape in the registry (`docker stats`/`compose ps` field names, `ss -H -tlnp` columns,
`systemctl show` properties, the `db` introspection SQL's column names across PG13/14+) was
authored from docs/man-pages on a macOS dev box, never live-captured — the smoke fixture and
script built this session are complete and correct on inspection, but Docker was not
available at the time of authoring, so `just smoke` had not yet been run. **That gap was
closed in the continuation session below — `just smoke` ran 15/15 green against a live Docker
fixture, so those command shapes are now live-verified, not doc-derived.**

---

## Session — 2026-07-13 (cont) — v0.1.0 (smoke verified live + published)

Closed the one carried verification gap and published. Docker became available, so `just
smoke` was run for real: it built the `scripts/sshd-fixture/` stack (an sshd container with
the docker CLI, a sibling Postgres seeded with a read-only `sshepherd_ro` role, and a sibling
app container), generated an ephemeral ed25519 keypair, temporarily registered a
`sshepherd-smoke` alias in `~/.ssh/config`, and drove the compiled `dist/sshepherd` binary
against the live Linux host — **15/15 checks passed**: `hosts test` (reachable), `check
overview` (dead_end_risk boolean + nproc>0), `services ps` (container list from docker
inspect), `logs docker` (LogsResult shape with next_since), `files ls`, `security listeners`
(sshd's own port 22 present), `db list`/`db tables`/`db query` (the seeded fixture row came
back through the read-only transaction wrapper), and `deploy run --dry-run` (correct plan, no
execution). The fixture torn down cleanly (`docker compose down --volumes`) and the temporary
ssh-config block removed by the exit trap — verified no residue. This promotes every registry
command shape and the db introspection SQL from doc-derived (SHIPPED-UNVERIFIED) to
VERIFIED-LIVE. The repo was then created on GitHub (`Antheurus/sshepherd`, public, MIT) and
pushed; the `v0.1.0` tag was cut to trigger `release.yml` (the 4-platform binary build +
SHA-256 + build-provenance attestation runs on GitHub's runners). Note for a future smoke
pass: the cross-phase auditor flagged that `docker compose ps --format json` on newer compose
can emit a single JSON array rather than NDJSON — `services ps` (which uses `docker ps` +
`docker inspect`, not `compose ps`) passed here, but `deploy status`/`services compose-ps`
specifically weren't in the smoke matrix, so that one parse path is still worth a targeted
check.

---

## Session — 2026-07-12 — v0.1.0 (scaffold)

Repo scaffolded to mirror anywrite's Bun/TypeScript/biome/just toolchain: package.json with build/dev/test/typecheck/lint/check scripts, tsconfig.json in strict mode targeting ESNext, biome.jsonc for lint + format, and a justfile exposing install/build/test/check/smoke/clean recipes as the only command interface. Zero runtime dependencies — only @biomejs/biome, @types/bun, and typescript as devDependencies, per the plan's constraint to keep runtime deps at or under two (Bun.TOML covers config parsing later, no toml package needed; node-sql-parser is deferred to Phase 4). Added a placeholder src/cli.ts that reads a hardcoded VERSION constant and prints it plain or via --version/-v, just enough to give `bun build --compile` a real entry point. `just build` compiles to dist/sshepherd and `just check` (tsc --noEmit + biome check) runs clean. This is Phase 1 of a 7-phase orchestrated build defined in docs/plan/2026-07-12-sshepherd-v1/plan.md; later phases add ops/transport logic and the SKILL.md content, neither of which this phase touches.

---

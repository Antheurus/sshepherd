/** Every timeout and cap sshepherd applies, one number each with its reason. Per-op defaults
 *  are what an op gets with no `--timeout`; `MAX_TIMEOUT_SEC` bounds any override. */

/** Cheap read-only probes (uptime, listing, one-shot status) finish well inside this. */
export const DEFAULT_TIMEOUT_SEC = 12;
/** `docker logs` / `journalctl` tails over a busy host. */
export const LOG_TIMEOUT_SEC = 20;
/** One file read/write through the allowlist (hash + base64 round trip). */
export const FILE_TIMEOUT_SEC = 25;
/** `check` ops: `du` and `docker system df` on a large volume need headroom. */
export const CHECK_TIMEOUT_SEC = 30;
/** `services` ops: a compose/systemd restart waits for the unit to settle. */
export const SERVICES_TIMEOUT_SEC = 20;
/** `db` ops: a catalog query or EXPLAIN over a loaded container exec. */
export const DB_TIMEOUT_SEC = 60;
/** `hosts test` is a liveness probe — a host that cannot echo in 10 s is down for our purposes. */
export const HOSTS_TEST_TIMEOUT_SEC = 10;
/** `deploy run`/`migrate`/`rollback`: a whole recipe (pull, build, up, health check). */
export const DEPLOY_TIMEOUT_SEC = 300;
/** Ceiling for any `--timeout`: room for a slow one-off migration, low enough that a typo
 *  (`--timeout 9999999999`) cannot hold a session open for days. */
export const MAX_TIMEOUT_SEC = 3_600;
/** ssh `-o ConnectTimeout`: an unreachable host fails in 10 s instead of the OS's ~2 min. */
export const CONNECT_TIMEOUT_SEC = 10;
/** How long an idle ControlMaster stays up after the last invocation, so back-to-back
 *  `sshepherd` calls reuse one authenticated connection (5 min of agent-driven work). */
export const CONTROL_PERSIST_SEC = 300;
/** Grace between the remote `timeout` TERM and its KILL. */
export const KILL_AFTER_SEC = 10;
/** Partial stdout returned with a `COMMAND_TIMEOUT` — 64 KiB keeps an envelope readable. */
export const MAX_PARTIAL_STDOUT_CHARS = 65_536;
/** Hard ceiling on stdout read from one ssh call. Past it the client is killed (or, for a
 *  mutating op, the rest is drained unread): 2 MiB is far more than any envelope can carry,
 *  low enough that a runaway `docker logs` cannot exhaust the process. */
export const MAX_STDOUT_BYTES = 2 * 1_024 * 1_024;
/** Largest file `files download` fetches; the remote side refuses anything bigger before sending. */
export const DOWNLOAD_MAX_BYTES = 10_485_760;
/** `files download`'s own stdout read ceiling, in place of `MAX_STDOUT_BYTES`: the base64 of a
 *  `DOWNLOAD_MAX_BYTES` file (13,981,016 bytes) plus 64 bytes for the `__OK__:<size>` header line.
 *  The payload goes to a local file, never into the envelope, so it does not compete with `--max-bytes`. */
export const DOWNLOAD_MAX_STDOUT_BYTES = Math.ceil(DOWNLOAD_MAX_BYTES / 3) * 4 + 64;
/** One log or tail line, cut after the scrubber: 4 KiB holds a stack-trace frame or a JSON log
 *  record, while a 100 KB minified blob on one line can no longer crowd out every other line. */
export const MAX_LINE_BYTES = 4_096;
/** `session_id` kept in an audit row: a UUID is 36 chars, 128 leaves room for any client's id
 *  format without letting an arbitrary env value bloat every row. */
export const MAX_SESSION_ID_CHARS = 128;
/** Default size of the JSON an invocation prints (`--max-bytes`): 64 KiB is roughly 16k tokens,
 *  the most an agent can usefully read from one call. */
export const DEFAULT_MAX_BYTES = 65_536;
/** Lowest `--max-bytes`: leaves room for the error block (2 KiB stderr tail, hint, next, sql_error). */
export const MIN_MAX_BYTES = 8_192;
/** Highest `--max-bytes`: nothing larger than the transport read ceiling can exist anyway. */
export const CEILING_MAX_BYTES = MAX_STDOUT_BYTES;
/** `--tail N` on any op: 5,000 lines already exceed `DEFAULT_MAX_BYTES` for typical log lines. */
export const MAX_TAIL_LINES = 5_000;
/** `--limit N` ceiling: more items than this cannot fit under `CEILING_MAX_BYTES` anyway. */
export const MAX_LIMIT_ITEMS = 100_000;
/** Audit log rotates when the active file reaches 50 MiB: ~250k rows, months of agent use. */
export const AUDIT_ROTATE_BYTES = 50 * 1_024 * 1_024;
/** Files kept including the active one (active + 4 archives = at most 250 MiB on disk). */
export const AUDIT_KEEP_FILES = 5;
/** `audit tail` rows when `--n` is absent. */
export const DEFAULT_AUDIT_TAIL = 50;
/** `audit tail --n` ceiling: 1,000 rows of ~500 bytes fit under `DEFAULT_MAX_BYTES` x 8. */
export const MAX_AUDIT_TAIL = 1_000;
/** A dotless target hostname shorter than this (`db`, `app`, `web1`) is not masked as a bare word:
 *  it is too common a word to mask in prose, and on its own it names no reachable machine. */
export const MIN_BARE_HOSTNAME_CHARS = 6;
/** A target user name shorter than this is not masked: two letters match too much (`id`, `pi`
 *  aside, nothing real is that short) and say nothing about who connects. */
export const MIN_MASKED_USER_CHARS = 3;
/** Blanks allowed between an identity keyword and its value (`for  opsuser`, `-p   2222`): a
 *  bound keeps the context rules linear on a line of spaces; real output never pads more than 8. */
export const MAX_IDENTITY_GAP_CHARS = 8;
/** How far a psql error's type name may run (`invalid input syntax for type <t>: "`): Postgres caps
 *  an identifier at 63 bytes, and a multi-word type (`timestamp with time zone`) is far shorter, so
 *  64 holds every real one while a long line with no `: "` is never rescanned past it. */
export const MAX_PSQL_TYPE_NAME_CHARS = 64;
/** How far past `user@` the scrubber reads to decide it is a login (`app@web-01`) and not a
 *  version or digest (`app@2.0.0`): 253 is the longest DNS name, and the bound keeps it linear. */
export const MAX_HOSTNAME_CHARS = 253;
/** Hex digits allowed between the last non-hex letter of a `word:` and an IPv6 literal after it
 *  (`src:` has 2, `ipv6:` 1): 16 covers every real label, and the bound keeps the lookbehind linear. */
export const MAX_LABEL_HEX_TAIL_CHARS = 16;
/** `--grep` pattern on a `logs *` op: 512 characters holds any real regular expression an agent
 *  writes, while a pasted log line or a runaway generator cannot ride in as a "pattern". */
export const MAX_GREP_PATTERN_CHARS = 512;
/** `--context N` lines either side of a `--grep` match: 20 shows a stack trace's surroundings and
 *  still fits `--max-lines` several times over. */
export const MAX_LOG_CONTEXT_LINES = 20;
/** `--max-lines` on a `logs *` op when absent: 500 lines of typical log output is about the 64 KiB
 *  `DEFAULT_MAX_BYTES`, so the line bound and the byte bound bite at the same place. */
export const DEFAULT_LOG_MAX_LINES = 500;
/** Lines a `logs *` op scans for a `--grep` match when `--tail` is absent: 200,000 lines is tens of
 *  MiB, read by a niced process inside `LOG_TIMEOUT_SEC`; past it the newest matches still win. */
export const LOG_GREP_SCAN_LINES = 200_000;
/** `nice -n` of every `check *` and `logs *` remote command: 10 yields to the host's real work
 *  without starving the probe (19 can wait minutes on a busy box). `ionice -c3` goes with it. */
export const HEAVY_NICE_LEVEL = 10;
/** One network stage of `hosts test --diagnose` (dns, tcp, banner): 5 s is past any healthy
 *  answer, so a stage that is still silent is the hang being looked for. */
export const DIAGNOSE_STAGE_TIMEOUT_SEC = 5;
/** The ssh login of `hosts test --diagnose` (auth + echo): `CONNECT_TIMEOUT_SEC` for the
 *  connection plus the same again for key exchange and the echo. */
export const DIAGNOSE_SSH_TIMEOUT_SEC = 20;
/** Upper edges of the coarse `length_bucket` an env key reports (`0`, `1-8`, `9-32`, `33+`): three
 *  cuts are enough to tell a flag from a token from a connection string, too few for a length to
 *  single out one value. */
export const ENV_LENGTH_BUCKET_BOUNDS = [8, 32] as const;
/** `files grep` pattern: a regex longer than this is a pasted blob, not a search; 256 holds any
 *  real alternation of log markers. */
export const MAX_FILES_GREP_PATTERN_CHARS = 256;
/** `files find --name` glob: file names are at most 255 bytes, a glob over half that is already odd. */
export const MAX_FIND_NAME_CHARS = 128;
/** Matching lines `files grep` returns (the remote stops one past it to say `truncated`): 500 lines
 *  of typical log text fit under `DEFAULT_MAX_BYTES`. */
export const MAX_GREP_MATCH_LINES = 500;
/** Paths `files find` returns, same ceiling and reason as `MAX_GREP_MATCH_LINES`. */
export const MAX_FIND_RESULTS = 500;
/** `files grep --context`: five lines either side shows the surrounding stack frame; more is `files head`. */
export const MAX_GREP_CONTEXT_LINES = 5;
/** `files head` lines when `--n` is absent: the top of a file (imports, a config header) is a screen long. */
export const DEFAULT_HEAD_LINES = 100;
/** `files head --n` ceiling, the same as `MAX_TAIL_LINES`. */
export const MAX_HEAD_LINES = 5_000;

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
/** How many assignments deep a value is searched for another one: `CMD="--opt=--password=v"` is
 *  two, `K8S_ARGS=--set=env=JAVA_OPTS=-Ddb.password=v` four, and a secret query parameter in a URL
 *  nested in another URL's query (`CB=https://a/?r=https://b/?token=v`) counts each `https:` too.
 *  8 doubles the deepest real one seen; each level rescans only its own value, so the cost grows
 *  with the cap, never with the chain (a 200,000-deep `a=b=c=...` chain stays linear). */
export const MAX_NESTED_ASSIGNMENT_DEPTH = 8;
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
/** `db query`/`describe`/`count`/`migrations`: server-side `statement_timeout`. Postgres cancels a
 *  runaway statement itself (an unindexed scan, a cross join), so the backend stops working instead
 *  of running on after the ssh session is gone. */
export const DB_STATEMENT_TIMEOUT_SEC = 60;
/** Room between `statement_timeout` and the ssh budget for the connect, `docker exec`, psql startup
 *  and the result transfer, so the database's own cancel fires first and names its cause. */
export const DB_STATEMENT_GRACE_SEC = 15;
/** `db query`'s ssh budget: the statement limit plus its grace (75 s). */
export const DB_QUERY_TIMEOUT_SEC = DB_STATEMENT_TIMEOUT_SEC + DB_STATEMENT_GRACE_SEC;
/** `lock_timeout` on every bounded db read: a read queued behind a migration's lock gives up in 2 s
 *  instead of waiting with it and blocking every query that queues behind the read. */
export const DB_LOCK_TIMEOUT_SEC = 2;
/** Rows `db query` returns when `--max-rows` is absent: 500 rows of a typical table already fill
 *  `DEFAULT_MAX_BYTES`; past it the envelope says `truncated: true`. */
export const DB_QUERY_ROW_LIMIT = 500;
/** `db query --max-rows` ceiling: 10,000 narrow rows are about 1 MiB, inside `MAX_STDOUT_BYTES`. */
export const DB_QUERY_MAX_ROWS = 10_000;
/** Rows `db migrations` returns per migrations table, newest first: the recent history is what
 *  says whether a deploy applied, and 50 rows stay far under `DEFAULT_MAX_BYTES`. */
export const DB_MIGRATIONS_LIMIT = 50;
/** `temp_file_limit` the read-only role SQL sets (superuser-only, so the role cannot lift it): one
 *  unbounded sort spilled 2 GB in 5 s on a shared database; 256 MiB fits any sensible ad hoc read. */
export const DB_RO_ROLE_TEMP_FILE_LIMIT_MB = 256;
/** A reused ControlMaster older than this gets a fresh strict host-key check first (one key
 *  exchange, no authentication): a master authenticates once, so a key that changed or left
 *  known_hosts would otherwise go unseen while it lives. 300 s is `CONTROL_PERSIST_SEC`'s idle life,
 *  so a busy master is rechecked about as often as an idle one would be reopened. */
export const MASTER_HOST_KEY_RECHECK_SEC = 300;
/** `tunnel open` waits this long for ssh to authenticate and set up the forward, or to exit: the
 *  connect limit plus 5 s for the key exchange and the forward request. */
export const TUNNEL_OPEN_WAIT_SEC = CONNECT_TIMEOUT_SEC + 5;
/** Lines a lone private-key END (its BEGIN cut off) looks back for the body lines its own log prefix
 *  wrote, skipping other writers' lines in between: an 8192-bit RSA key is about 100 body lines, and
 *  400 leaves room for three interleaved lines per body line while keeping the pass linear. */
export const MAX_PEM_LONE_END_SCAN_LINES = 400;
/** Bytes a `logs *` page read forward from `--since` may print: whole lines stop short of the
 *  transport read ceiling (`MAX_STDOUT_BYTES` less 64 KiB), so the ceiling never cuts the oldest
 *  lines off a page that is meant to keep them. */
export const LOG_PAGE_MAX_BYTES = MAX_STDOUT_BYTES - 65_536;
/** `hosts test --diagnose`'s `ssh -O check` on sshepherd's own ControlMaster: a local socket round
 *  trip answers in milliseconds, so a master still silent after 3 s is hung, and every op that
 *  reuses it would stall behind it. */
export const DIAGNOSE_MASTER_CHECK_TIMEOUT_SEC = 3;
/** `db migrations --dir`: applied names read and directory entries listed for the pending
 *  comparison. 10,000 migrations is decades of a busy app; past it the comparison would be cut,
 *  so the op refuses instead of reporting a partial `pending`. */
export const DB_MIGRATIONS_COMPARE_MAX = 10_000;
/** `files head|tail|cat --lines A:B`: the widest range one call returns, the same as `MAX_HEAD_LINES`. */
export const MAX_FILES_LINE_SPAN = 5_000;
/** `deploy run` output: this many `KEY=value` / `KEY = value` lines in a row (comment and blank
 *  lines between them allowed) read as an env file a step printed, and every value in the run is
 *  masked whatever its key is called. Three, because a build prints a lone `BUILD_ID=123` or a
 *  pair now and then, while a `.env` dump holds many; build output that happens to look like
 *  three assignments in a row is masked too, a cost the user accepted. */
export const ENV_BLOCK_MIN_LINES = 3;

/** PEM marker lines (`-----BEGIN ...-----` / `-----END ...-----`) `files grep` and `files head|tail
 *  --lines` read from the whole file to tell which returned lines sit inside a private-key block: a
 *  bundle of a few dozen certificates and keys stays far under it, and past it every returned line
 *  of that file is masked rather than judged from a partial list. */
export const MAX_PEM_MARKER_LINES = 256;

/** `http get|send`: curl's `--max-time` for one request to a localhost service. A local service
 *  that has not finished answering in 30 s is hung, not slow. */
export const HTTP_REQUEST_TIMEOUT_SEC = 30;
/** `http get|send`: curl's `--connect-timeout`. A localhost port answers its SYN in microseconds,
 *  so 5 s only ever expires on a host too loaded to schedule the listener. */
export const HTTP_CONNECT_TIMEOUT_SEC = 5;
/** `http get|send`'s ssh budget: the request limit plus 10 s for the session, the credential
 *  lookup and the reply. */
export const HTTP_OP_TIMEOUT_SEC = HTTP_REQUEST_TIMEOUT_SEC + 10;
/** Response body bytes `http get|send` returns (the rest is only counted): 64 KiB is a full JSON
 *  page or health payload and leaves the envelope room under `CEILING_MAX_BYTES`. */
export const HTTP_BODY_MAX_BYTES = 65_536;
/** `http send --json` body: it travels base64 inside the remote command line (64 KiB is 87 KiB of
 *  base64), under Linux's 128 KiB limit on one argument. */
export const HTTP_REQUEST_BODY_MAX_BYTES = 65_536;
/** `wait for --timeout` when absent: ten minutes covers an image build plus a slow healthcheck. */
export const WAIT_DEFAULT_TIMEOUT_SEC = 600;
/** `wait for --timeout` ceiling: the same hour every other op's budget stops at. */
export const WAIT_MAX_TIMEOUT_SEC = MAX_TIMEOUT_SEC;
/** `wait for --timeout` floor: the poll stops `WAIT_REPLY_GRACE_SEC` before the budget, so a
 *  budget under 10 s would leave almost no polling time. */
export const WAIT_MIN_TIMEOUT_SEC = 10;
/** The `wait for` poll gives up this long before its ssh budget, so its own "not met" answer (with
 *  attempts and elapsed) gets back instead of the session being cut: at least one url probe
 *  (`WAIT_URL_PROBE_TIMEOUT_SEC`, 5 s) plus one poll sleep (`WAIT_POLL_INTERVAL_SEC`, 2 s), the most
 *  one loop turn can run past the deadline. */
export const WAIT_REPLY_GRACE_SEC = 7;
/** Seconds between two `wait for` checks: a healthcheck or a log line is seen within 2 s, and one
 *  `docker inspect` every 2 s is no load on the host. */
export const WAIT_POLL_INTERVAL_SEC = 2;
/** curl `--max-time` of one `wait for --until url:` probe: a probe longer than the poll interval
 *  would stretch the interval itself. */
export const WAIT_URL_PROBE_TIMEOUT_SEC = 5;
/** `wait for --until log-contains:<re>`: the same ceiling as `MAX_FILES_GREP_PATTERN_CHARS`. */
export const MAX_WAIT_PATTERN_CHARS = 256;
/** `git log` commits when `--n` is absent: a screen of recent history answers "what is deployed". */
export const GIT_LOG_DEFAULT_COMMITS = 20;
/** `git log --n` ceiling: 200 one-line commits stay far under `DEFAULT_MAX_BYTES`. */
export const GIT_LOG_MAX_COMMITS = 200;
/** Changed files `git diff-stat` lists (the remote stops one past it to say `truncated`), the same
 *  ceiling and reason as `MAX_FIND_RESULTS`. */
export const GIT_DIFF_STAT_MAX_FILES = 500;
/** `git head|log|diff-stat` ssh budget: `git status` on a large worktree with a cold cache can take
 *  several seconds; 25 s matches `FILE_TIMEOUT_SEC`. */
export const GIT_TIMEOUT_SEC = 25;

/** `setup ssh-alias adopt-env` reads a project's `.env` only up to this size: a real one is a few KiB,
 *  and 1 MiB still fits a file carrying several PEM keys inline, while a stray multi-GB file is
 *  refused instead of read into memory. */
export const ADOPT_ENV_MAX_FILE_BYTES = 1_048_576;
/** Host groups one `adopt-env` run adopts: each installs a key one after the other (up to about 45 s
 *  of connect and install timeouts per host), so 32 hosts stay inside about 25 minutes. */
export const ADOPT_ENV_MAX_HOSTS = 32;
/** `doctor hosts` probes this many aliases at once: each probe is one credential-free key exchange,
 *  and 8 at once finishes 15 aliases in two rounds without flooding the local ssh client. */
export const DOCTOR_HOSTS_CONCURRENCY = 8;
/** Local kill for one `doctor hosts` probe: ssh's own `CONNECT_TIMEOUT_SEC` plus 5 s for the key
 *  exchange and the server's list of auth methods. */
export const DOCTOR_HOSTS_PROBE_TIMEOUT_SEC = CONNECT_TIMEOUT_SEC + 5;
/** Aliases `doctor hosts` probes in one run: 200 at `DOCTOR_HOSTS_CONCURRENCY` is at most about 6
 *  minutes against unreachable hosts; any beyond it are reported unchecked, never silently dropped. */
export const DOCTOR_HOSTS_MAX_ALIASES = 200;

/** `tunnel open`'s ssh asks the server for a reply after this many idle seconds: a frozen or
 *  unplugged host otherwise stays a listed tunnel until its duration (up to a day) runs out. */
export const TUNNEL_SERVER_ALIVE_INTERVAL_SEC = 10;
/** Unanswered keepalives before the tunnel's ssh gives up and exits, so a dead host leaves
 *  `tunnel list` within 30 s (10 s x 3); three rides out one dropped packet on a lossy link. */
export const TUNNEL_SERVER_ALIVE_COUNT_MAX = 3;
/** Bytes of ssh's stderr a tunnel supervisor keeps in its (unlinked) stderr file before the forward
 *  is up; after the forward-ready line it keeps none. That file exists only for `tunnel open` to
 *  classify a failure, and DEBUG1 otherwise adds a line per forwarded connection for up to a day.
 *  4 KiB holds ssh's error lines and a short server banner; debug lines other than the ready line
 *  are never kept. */
export const TUNNEL_STDERR_MAX_BYTES = 4_096;

/** `exec run|change` budget when `--timeout` is absent: a declared one-shot command (an artisan
 *  status, a cache clear, a queue restart) finishes in seconds; 120 s leaves room for a cold
 *  container start without letting a hung command hold the session. `--timeout` raises it. */
export const EXEC_TIMEOUT_SEC = 120;
/** Params one `exec` call passes and one definition declares: a named command takes a handful of
 *  typed values, and 16 bounds how much caller input one argv can carry (roadmap P3.2). */
export const EXEC_MAX_PARAMS = 16;
/** Bytes of one `exec --param` value: names, ids, paths and short patterns fit in 512, while a value
 *  big enough to smuggle a payload does not (roadmap P3.2). */
export const EXEC_MAX_PARAM_BYTES = 512;
/** Elements of one definition's argv: a real command line is under 20 words; 64 refuses a
 *  generated or pasted script dressed as argv. */
export const EXEC_MAX_ARGV_ITEMS = 64;
/** Size of one `exec/<alias>.toml`: 200 definitions of a few lines each are far under 256 KiB, and a
 *  stray large file is refused instead of parsed on every call. */
export const EXEC_MAX_DEF_FILE_BYTES = 262_144;
/** Definitions one `exec/<alias>.toml` may hold: keeps `exec list` one readable page. */
export const EXEC_MAX_DEFS = 200;

/** Body bytes `http get|send` reads past `HTTP_BODY_MAX_BYTES` so the scrubber sees a secret that
 *  straddles the cut whole before the body is cut back: 16 KiB holds a 4096-bit PEM private key
 *  (about 3.2 KiB) or a large JWT several times over. */
export const HTTP_BODY_SCRUB_MARGIN_BYTES = 16_384;
/** curl `--max-time` of one recipe `http-probe` attempt: a health endpoint that has not answered in
 *  10 s is failing, and the step's `retries` and `interval` decide how long it keeps trying. */
export const RECIPE_HTTP_PROBE_TIMEOUT_SEC = 10;

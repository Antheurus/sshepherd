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

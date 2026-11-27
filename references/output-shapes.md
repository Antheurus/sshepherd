# Output shapes — the Envelope contract

Deep reference for `src/output.ts` + `src/types.ts`. The authoritative reference for what
every consumer of a sshepherd response should parse — read this before writing a parser
against `sshepherd`'s stdout.

## The `Envelope`

Every invocation prints **exactly one** `Envelope<T>` to stdout as JSON (unless `--pretty`
renders it as a table/key-value view instead — same data, human layout). `buildEnvelope`
in `output.ts` is the only place one is constructed.

```ts
interface Envelope<T> {
  ok: boolean;
  alias: string;
  ran_at: string;       // ISO 8601
  command: string;       // "<group> <name>", e.g. "check overview"
  duration_ms: number;
  data: T | null;
  error: ErrorInfo | null;
  warnings?: EnvelopeWarning[]; // present only when something beside the op itself failed
}

interface EnvelopeWarning {
  code: 'AUDIT_UNWRITABLE';     // a mutating op ran, its audit line was not written
  message: string;
  hint: string;                 // how to make the audit log writable again
  path_role: 'state_dir' | 'audit_archive' | 'audit_file'; // which part refused — never the path
  errno?: string;               // EACCES, ENOSPC, EROFS, ENOTDIR
}
```

`warnings` never changes `ok`, `data` or `error`: they are still the op's own result. A mutating
op whose audit line cannot be written keeps running and carries `AUDIT_UNWRITABLE` (the user chose
run-and-warn over fail-closed); a content read in the same spot still fails with
`AUDIT_WRITE_FAILED`.

`ok` is `error === null` — the two fields are always consistent, never independently
false/set. `data` and `error` are mutually exclusive: a successful op has `data` populated
and `error: null`; a failed op has `data: null` (or, for `deploy run`/`deploy migrate`
specifically, a small `{ failed_step }` object — see `recipes.md`) and `error` populated.

**There is deliberately no host/user/port/ip field anywhere in this type.** That omission
is the structural half of the zero-knowledge guarantee — `alias` is the only identity
string that ever crosses back to a caller, and it's an echo of what the caller already
passed in. The other half is the transport layer discarding ssh's own stderr before it can
ever reach an `ErrorInfo` (see `transport.md`).

## `ErrorInfo`

```ts
interface ErrorInfo {
  code: SshErrorCode;
  message: string;       // a fixed, static string looked up by `code` — never raw ssh stderr
  remote_exit?: number;   // present only for COMMAND_FAILED
}
```

`message` is always one of a small fixed set of strings (`ERROR_MESSAGES` in
`transport.ts`), keyed by `code` — never the actual ssh/remote stderr text, which is
discarded entirely by the transport layer before an `ErrorInfo` is ever built. Consumers
that need programmatic branching should switch on `code`, not parse `message`. The full
`SshErrorCode` enum and how each value is detected is in `transport.md`.

## Sizes are always bytes

Every size field across every op (`check disk`'s `disk`/`inodes`, `services stats`'
`mem_used_bytes`, `db tables`' `size_bytes`, `files cat`'s `size_bytes`, ...) is an integer
byte count — **never** a human-formatted string like `"3.9Gi"` or `"512M"`. Anywhere the
underlying tool prints a human size (`docker stats`' `MemUsage`, `du -h`), sshepherd parses
it into bytes before it ever reaches the envelope.

## Log lines — `{ ts, stream, text }` + `next_since`

Every `logs *` op returns the shared `LogsResult` shape (`parsers/logs-shape.ts`);
`deploy logs` returns a plain `{ output: string }` instead (raw `docker compose logs`
text, not line-shaped) — check the op's own summary via `--help` before assuming a shape.

```ts
interface LogsResult {
  source: string;             // e.g. "docker:myapp", "compose:/opt/app", "service:nginx"
  lines_returned: number;
  truncated: boolean;         // more lines exist in the window than this page returned
  kept: 'oldest' | 'newest';  // which end of the window the page holds (see paging)
  lines: Array<{
    ts: string | null;
    stream: 'stdout' | 'stderr';
    text: string;
    service?: string;         // `logs compose` only: the compose service that wrote the line
  }>;
  next_since: string | null;  // exclusive cursor: the last line's instant + 1 ns
}
```

`ts` is `null` when the source has no reliable per-line timestamp (an nginx log line).
`docker logs` and `docker compose logs` fold stdout and stderr into one stream (`2>&1`, so a
line a service wrote to stderr is never lost) and print no per-line tag, so their `stream` is
always `stdout`. For journald sources `stream` is a heuristic: `shapeJournalEntry`
(`parsers/journal.ts`) maps syslog `PRIORITY <= 3` (err/crit/alert/emerg) to `stderr` and
everything else to `stdout`. Journald `ts` keeps journald's microseconds.

**Paging.** `next_since` is exclusive: passing it as the next call's `--since` never returns
the same line again (it is the last line's timestamp plus one nanosecond; journalctl gets it as
`@<epoch>.<microseconds>`). It is `null` when the page returned no line — nothing new yet; keep
the `--since` you had.

- **With `--since`** the page holds the **oldest** lines of the window (`kept: "oldest"`): it
  starts at `--since`, and `truncated: true` means a next page exists. Page forward with
  `--since <next_since>` until `truncated` is `false`; every line comes back exactly once, in
  order. `--max-lines` sizes the page, and `--limit`/`--max-bytes` cutting it still keep its
  oldest lines. When a page boundary falls inside one instant, the lines of that instant move to
  the next page and `next_since` is that instant itself. `--tail` cannot be combined with
  `--since` (`INVALID_ARGS`).
- **Without `--since`** the page holds the **newest** lines (`kept: "newest"`, as a tail does),
  and `truncated: true` means older lines were not returned; `next_since` is for following new
  lines from here, not for reaching the older ones. `--until` alone returns the newest lines at
  or before it.

A `--grep` on journald matches the entry's `MESSAGE` only, never its metadata fields; on docker,
compose and nginx it matches the raw line (for docker that includes the timestamp prefix).

## Verdict fields — `dead_end_risk`, `degraded`, `risk_signals`

`check overview`/`check mem`/`check disk` each carry:

- `degraded: string[]` — the sections whose command failed or printed nothing usable
  (`nproc`, `mem`, `disk`, `uptime`, `inodes`, `top_du`). A degraded section's own reading is
  `null` (`mem: null`, `nproc: null`), never a zero.
- `risk_signals: string[]` — the readings past their threshold: `disk` (any filesystem's
  `use_percent` above **90%**) and `mem_pressure` (PSI memory `some avg10` above **10%**).
- `dead_end_risk: boolean | null` — `computeDeadEndRisk` (`parsers/verdict.ts`, the one shared
  implementation): `true` when a reading that came back is at risk, whatever else degraded (a
  full disk stays a dead end when memory cannot be read); `null` when nothing known is at risk
  and a section the verdict reads (`disk`, `mem`) degraded — unknown, never an all-clear;
  otherwise `false`. A degraded `nproc`/`uptime`/`inodes`/`top_du` cannot change it.

Both thresholds are named constants (`DISK_USE_PERCENT_RISK_THRESHOLD`,
`PSI_MEM_SOME_AVG10_RISK_THRESHOLD`) in that one file — this is the field to check first
when triaging a host, before reading the raw `disk`/`mem`/`psi_mem` arrays yourself.

## Ports — structured, never a raw address string

`check ports`/`security listeners` never return a raw `ss` line like `0.0.0.0:8080`. Every
listening socket is `{ proto, local_addr, port, process, pid }` (or the `services`-group
`PortMapping` shape `{ host_ip, host_port, container_port, proto }` for container port
mappings) — always parsed, never string-matched by a caller.

## Verifying a response

There is no separate `sshepherd verify` composite command (unlike `anywrite`) — every
sshepherd op is already a single, complete round trip that returns its own envelope, so
there's nothing to re-fetch and compare. Confirm a mutating op landed by following it with
the matching read-only op in the same group (e.g. `services restart` then
`services healthcheck`, `config put` then `config get`, `deploy run` then `deploy status`).

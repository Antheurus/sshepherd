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
}
```

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
  source: string;             // e.g. "docker:lms-app", "service:nginx"
  lines_returned: number;
  truncated: boolean;         // true when the line count hit the requested tail limit
  lines: Array<{ ts: string | null; stream: 'stdout' | 'stderr'; text: string }>;
  next_since: string | null;  // the last line's ts — pass as the next call's --since
}
```

`ts` is `null` when the source has no reliable per-line timestamp (e.g. an nginx access
log line). `stream` is a real field for docker (`--timestamps` output distinguishes
stdout/stderr natively) and a documented heuristic for journald sources — journald has no
first-class stdout/stderr field for arbitrary units, so `shapeJournalEntry`
(`parsers/journal.ts`) maps syslog `PRIORITY <= 3` (err/crit/alert/emerg) to `stderr` and
everything else to `stdout`. `truncated: true` means more lines may exist beyond the
requested `--tail`/`-n` limit — page forward with `next_since` as the next call's
`--since`, don't assume you've seen everything.

## Verdict fields — `dead_end_risk`

`check overview`/`check mem`/`check disk` each compute a `dead_end_risk: boolean` —
`computeDeadEndRisk` (`parsers/verdict.ts`, the one shared implementation, never
duplicated per-op) is `true` when either:

- any filesystem's `use_percent` exceeds **90%**, or
- PSI memory pressure's `some avg10` exceeds **10%**.

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

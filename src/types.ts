/**
 * Shared contract for the transport, output, and (later) registry layers.
 *
 * Envelope is the zero-knowledge boundary: the only identity field it carries is
 * `alias`. There is deliberately no host/user/port/ip field anywhere in this type —
 * that omission is the structural half of the zero-knowledge guarantee (the other
 * half is the transport discarding ssh stderr before it ever reaches an ErrorInfo).
 */
export interface Envelope<T> {
  ok: boolean;
  alias: string;
  ran_at: string;
  command: string;
  duration_ms: number;
  data: T | null;
  error: ErrorInfo | null;
}

export type SshErrorCode =
  | 'UNKNOWN_ALIAS'
  | 'CONNECT_TIMEOUT'
  | 'AUTH_FAILED'
  | 'HOST_KEY_MISMATCH'
  | 'SSH_TRANSPORT_ERROR'
  | 'COMMAND_FAILED'
  | 'COMMAND_TIMEOUT'
  | 'CONFIRMATION_REQUIRED'
  | 'VALIDATION_ERROR';

/**
 * `message` is always a static human string looked up by `code`, never raw ssh
 * stderr — ssh chatter can contain hostnames/IPs, a per-code constant cannot.
 */
export interface ErrorInfo {
  code: SshErrorCode;
  message: string;
  remote_exit?: number;
}

/**
 * Thrown by an `OpSpec.runLocal` implementation that needs to fail with a structured,
 * agent-facing error instead of always succeeding — `executeOp` catches this specifically and
 * builds the `ErrorInfo` from `code`/`message` directly (bypassing the static `ERROR_MESSAGES`
 * lookup `errorInfo()` uses for transport-originated errors, since a `runLocal` validation
 * message carries no ssh-stderr leak risk and is more useful to the caller when specific).
 */
export class OpRunLocalError extends Error {
  constructor(
    public readonly code: SshErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'OpRunLocalError';
  }
}

/**
 * Internal only — the transport's raw return. `transportStderr` is consumed by the
 * error classifier and then discarded; it must never be copied into an ErrorInfo or
 * an Envelope.
 */
export interface RawResult {
  code: number;
  stdout: string;
  transportStderr: string;
  commandStderr: string;
  timedOut: boolean;
}

export type OutputMode = 'native-json' | 'ndjson' | 'raw' | { parse: (stdout: string) => unknown };

export interface OpContext {
  alias: string;
  args: Record<string, string | boolean>;
}

export interface ArgSpec {
  name: string;
  kind: 'positional' | 'flag';
  required: boolean;
  description: string;
}

/**
 * Declarative allowlist gate, enforced once in `executeOp` before `buildRemote` runs —
 * no op's `buildRemote` calls an assert function itself (see `coding-standard.md` rule 17,
 * "Centralized by Default"). `path` covers `config`/`files` ops whose named arg is a
 * remote path that must be pre-declared per-alias in that scope's `<scope>-allowlist.toml`.
 * `reveal-keys` covers `files cat --reveal`: the named arg is a comma-separated key list,
 * each checked against a hardcoded secret-pattern denylist first (never overridable), then
 * against the per-alias `reveal-allowlist.toml`.
 */
export type AllowlistPolicy =
  | { kind: 'path'; scope: 'config' | 'files'; argName: string }
  | { kind: 'reveal-keys'; argName: string };

/**
 * One registry row per op (registry-dispatch pattern — coding-standard.md rule 5/17).
 * `buildRemote` returns `null` for the handful of host-local ops (e.g. `hosts list`)
 * that never open an ssh connection; those ops must supply `runLocal` instead.
 * `shape` maps the parsed stdout (per `output`) into the envelope's `data` payload.
 */
export interface OpSpec<T = unknown> {
  group: string;
  name: string;
  summary: string;
  args: ArgSpec[];
  mutating: boolean;
  timeoutSec: number;
  output: OutputMode;
  buildRemote: (ctx: OpContext) => string | null;
  shape: (parsed: unknown, ctx: OpContext) => T;
  /** Optional: called on the failure path (`result.error` set) to pull additional
   *  structured context out of the raw transport result's stdout — e.g. which recipe
   *  step failed. Reads `raw.stdout` only, never `transportStderr`/`commandStderr`.
   *  Returns `undefined` when nothing to add, in which case `data` stays `null`. */
  shapeError?: (raw: RawResult, ctx: OpContext) => Record<string, unknown> | undefined;
  runLocal?: (ctx: OpContext, sshConfigPath: string) => T;
  /** Optional: one or more allowlist gates `executeOp` enforces before `buildRemote`. */
  allowlist?: AllowlistPolicy[];
}

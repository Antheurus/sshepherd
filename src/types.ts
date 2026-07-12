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
  | 'COMMAND_TIMEOUT';

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

/** Stub shape — Phase 3 owns the real registry. Enough here for transport/output to compile. */
export interface OpSpec {
  group: string;
  name: string;
  mutating: boolean;
  output: OutputMode;
  buildRemote: (ctx: OpContext) => string;
}

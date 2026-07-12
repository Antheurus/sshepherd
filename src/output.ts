import type { Envelope, ErrorInfo } from './types.ts';

export interface BuildEnvelopeInput<T> {
  alias: string;
  command: string;
  startedAtMs: number;
  data: T | null;
  error: ErrorInfo | null;
}

/**
 * The only place an Envelope is constructed. `Envelope` has no host/user/port/ip
 * field to begin with (see types.ts), so this is structurally safe — it echoes back
 * only the alias it was given.
 */
export function buildEnvelope<T>(input: BuildEnvelopeInput<T>): Envelope<T> {
  return {
    ok: input.error === null,
    alias: input.alias,
    ran_at: new Date().toISOString(),
    command: input.command,
    duration_ms: Date.now() - input.startedAtMs,
    data: input.data,
    error: input.error,
  };
}

/** docker/journalctl emit NDJSON, not a JSON array — split on newlines before parsing each line. */
export function splitNdjson(stdout: string): unknown[] {
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as unknown);
}

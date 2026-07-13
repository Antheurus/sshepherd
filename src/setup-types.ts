/**
 * Dedicated return shape for the `setup` command group — deliberately NOT `Envelope<T>`
 * (see research.md, "Return shape for setup's local-only commands"). `setup`'s actions
 * write local config files and never open an ssh connection, so there is no `alias` to
 * carry and no `duration_ms` worth measuring against a remote round-trip.
 */
export interface SetupResult<T> {
  ok: boolean;
  command: string;
  ran_at: string;
  data: T | null;
  error: SetupErrorInfo | null;
}

/**
 * `message` is always a static human string, matching `ErrorInfo`'s convention in
 * types.ts — never raw fs/child_process error text, which can contain local paths.
 */
export interface SetupErrorInfo {
  code: SetupErrorCode;
  message: string;
}

/**
 * String union, not a closed enum, so later phases (ssh-alias, db-target,
 * config-allowlist, deploy-recipe) can each add their own codes in this file without
 * touching every existing call site. `NOT_IMPLEMENTED` covers this phase's stub
 * sub-groups; `UNKNOWN_SUBGROUP` covers an unrecognized `setup <x>` or `setup <sub> <x>`.
 */
export type SetupErrorCode = 'NOT_IMPLEMENTED' | 'UNKNOWN_SUBGROUP';

export interface BuildSetupResultInput<T> {
  command: string;
  data?: T | null;
  error?: SetupErrorInfo | null;
}

/** The only place a `SetupResult` is constructed — mirrors `buildEnvelope` in output.ts. */
export function buildSetupResult<T>(input: BuildSetupResultInput<T>): SetupResult<T> {
  const error = input.error ?? null;
  return {
    ok: error === null,
    command: input.command,
    ran_at: new Date().toISOString(),
    data: input.data ?? null,
    error,
  };
}

/**
 * Terminal rendering for a `SetupResult` — kept separate from output.ts's
 * `printJson`/`printPretty` (those are typed for `Envelope`, which has fields
 * `SetupResult` deliberately doesn't carry).
 */
export function printSetupResult(result: SetupResult<unknown>, pretty: boolean): void {
  if (!pretty) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  const lines = [`ok: ${result.ok}`, `command: ${result.command}`, `ran_at: ${result.ran_at}`];
  if (result.error !== null) {
    lines.push('', 'error:', `  code: ${result.error.code}`, `  message: ${result.error.message}`);
  }
  if (result.data !== null && result.data !== undefined) {
    lines.push('', 'data:', JSON.stringify(result.data, null, 2));
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}

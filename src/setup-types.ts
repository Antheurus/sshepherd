import { takeSetupAuditFailures } from './audit.ts';
import { auditUnwritableWarning } from './errors.ts';
import { scrubLocalOutput } from './scrub.ts';
import type { EnvelopeWarning } from './types.ts';

/**
 * Dedicated return shape for the `setup` command group — deliberately NOT `Envelope<T>`
 * (see research.md, "Return shape for setup's local-only commands"). `setup`'s actions
 * write local config files and never open an ssh connection, so there is no `alias` to
 * carry and no `duration_ms` worth measuring against a remote round-trip.
 */
export interface SetupResult<T> {
  /** Same version as the op envelope's; fields are only ever added within it. */
  schema_version: 1;
  ok: boolean;
  command: string;
  ran_at: string;
  data: T | null;
  error: SetupErrorInfo | null;
  /** Present only when the action's audit line could not be written; the result still stands. */
  warnings?: EnvelopeWarning[];
}

/**
 * `message` is always a static human string, matching `ErrorInfo`'s convention in
 * types.ts — never raw fs/child_process error text, which can contain local paths.
 */
export interface SetupErrorInfo {
  code: SetupErrorCode;
  message: string;
  hint: string;
  retryable: boolean;
  next?: string;
  did_you_mean?: string[];
}

/** What a setup module hands `buildSetupResult`: code + message, plus guidance only where it
 *  knows better than the per-code default. */
export interface SetupErrorInput {
  code: SetupErrorCode;
  message: string;
  hint?: string;
  next?: string;
  did_you_mean?: string[];
}

/**
 * String union, not a closed enum, so later phases (ssh-alias, db-target,
 * config-allowlist, deploy-recipe) can each add their own codes in this file without
 * touching every existing call site. `NOT_IMPLEMENTED` covers this phase's stub
 * sub-groups; `UNKNOWN_SUBGROUP` covers an unrecognized `setup <x>` or `setup <sub> <x>`.
 * `INVALID_ARGS` covers CLI-level argument validation (missing/malformed flags) before a
 * sub-module is even called. `CONFIRMATION_REQUIRED`/`ALIAS_EXISTS`/`ALIAS_NOT_FOUND`/
 * `PARSE_MISMATCH`/`KEYGEN_FAILED` are `setup ssh-alias`'s codes (Phase 2).
 * `VALIDATION_ERROR`/`TARGET_EXISTS` are `setup db-target`'s codes (Phase 3).
 * `RECIPE_EXISTS` is `setup deploy-recipe`'s code (Phase 5), mirroring `TARGET_EXISTS`.
 * `SSHPASS_NOT_FOUND`/`INSTALL_TIMED_OUT`/`INSTALL_FAILED` are `setup ssh-alias install`'s
 * codes (agent-invocable install phase) — `INSTALL_FAILED` also covers the precondition
 * failure where `install` is run before `keygen` (no public key to install).
 * `TAILSCALE_SSH_DETECTED` is also `install`'s code — its pre-check found the target
 * fronted by Tailscale SSH, which never uses `authorized_keys`, before ever opening the
 * browser form.
 * `INVALID_PRIVATE_KEY`/`PASSPHRASE_PROTECTED_KEY_UNSUPPORTED` are `install`'s codes for its
 * pasted-private-key credential method (Phase 4) — `INVALID_PRIVATE_KEY` covers pasted text
 * that doesn't parse as a private key at all, `PASSPHRASE_PROTECTED_KEY_UNSUPPORTED` covers a
 * pasted key that does parse but is passphrase-protected, which install cannot supply
 * non-interactively.
 * `PROFILE_DENIED` is the op groups' code, for a setup action above the caller's `SSHEPHERD_PROFILE`.
 * `HOST_KEY_UNKNOWN`/`HOST_KEY_CHANGED`/`HOST_KEY_FINGERPRINT_MISMATCH` are `setup host add`'s
 * host-key step, the same codes `hosts test` and `hosts trust` return for that alias.
 */
export type SetupErrorCode =
  | 'NOT_IMPLEMENTED'
  | 'UNKNOWN_SUBGROUP'
  | 'INVALID_ARGS'
  | 'PARSE_ERROR'
  | 'CONFIRMATION_REQUIRED'
  | 'ALIAS_EXISTS'
  | 'ALIAS_NOT_FOUND'
  | 'PARSE_MISMATCH'
  | 'KEYGEN_FAILED'
  | 'VALIDATION_ERROR'
  | 'TARGET_EXISTS'
  | 'RECIPE_EXISTS'
  | 'SSHPASS_NOT_FOUND'
  | 'INSTALL_TIMED_OUT'
  | 'INSTALL_FAILED'
  | 'TAILSCALE_SSH_DETECTED'
  | 'INVALID_PRIVATE_KEY'
  | 'PASSPHRASE_PROTECTED_KEY_UNSUPPORTED'
  | 'PROFILE_DENIED'
  | 'REMOTE_FAILED'
  | 'HOST_KEY_UNKNOWN'
  | 'HOST_KEY_CHANGED'
  | 'HOST_KEY_FINGERPRINT_MISMATCH';

export interface BuildSetupResultInput<T> {
  command: string;
  data?: T | null;
  error?: SetupErrorInput | null;
}

interface SetupGuidance {
  hint: string;
  retryable: boolean;
  next?: string;
}

const SETUP_GUIDANCE: Record<SetupErrorCode, SetupGuidance> = {
  NOT_IMPLEMENTED: { hint: 'This sub-group is not available yet.', retryable: false },
  UNKNOWN_SUBGROUP: {
    hint: 'Pick one of the names in did_you_mean.',
    retryable: false,
    next: 'sshepherd setup --help',
  },
  INVALID_ARGS: {
    hint: 'Fix the argument the message names; --help on the sub-group lists the actions.',
    retryable: false,
    next: 'sshepherd setup --help',
  },
  PARSE_ERROR: {
    hint: 'A flag is unknown for this action; did_you_mean lists the near flags it accepts.',
    retryable: false,
  },
  CONFIRMATION_REQUIRED: {
    hint: 'This writes local config; once a human has approved it, run the same command again with --yes.',
    retryable: false,
  },
  ALIAS_EXISTS: {
    hint: 'That alias is already registered; change it with setup ssh-alias update, or pass --overwrite to register.',
    retryable: false,
    next: 'sshepherd setup ssh-alias list',
  },
  ALIAS_NOT_FOUND: {
    hint: 'No such alias is registered; the list shows the ones that are.',
    retryable: false,
    next: 'sshepherd setup ssh-alias list',
  },
  PARSE_MISMATCH: {
    hint: 'The ssh config holds a stanza sshepherd cannot edit safely; fix that entry by hand.',
    retryable: false,
  },
  KEYGEN_FAILED: {
    hint: 'ssh-keygen did not produce a key; confirm it is installed and the key directory is writable, then run it again.',
    retryable: true,
  },
  VALIDATION_ERROR: {
    hint: 'Fix the value the message names, then run the command again.',
    retryable: false,
  },
  TARGET_EXISTS: {
    hint: 'A target with this name already exists; pick another name or edit targets.toml by hand.',
    retryable: false,
    next: 'sshepherd db list',
  },
  RECIPE_EXISTS: {
    hint: 'A recipe with this name already exists; pick another name or edit that file by hand.',
    retryable: false,
  },
  SSHPASS_NOT_FOUND: {
    hint: 'install needs sshpass on this machine; install it, then run install again.',
    retryable: false,
  },
  INSTALL_TIMED_OUT: {
    hint: 'The one-shot form was not submitted in time; run install again.',
    retryable: true,
  },
  INSTALL_FAILED: {
    hint: 'The key was not installed; read the message, fix that cause, then run install again.',
    retryable: false,
  },
  TAILSCALE_SSH_DETECTED: {
    hint: 'Tailscale SSH never reads authorized_keys, so there is nothing to install; connect without a key.',
    retryable: false,
  },
  INVALID_PRIVATE_KEY: {
    hint: 'The pasted text is not a private key; paste the whole key, BEGIN and END lines included.',
    retryable: false,
  },
  PASSPHRASE_PROTECTED_KEY_UNSUPPORTED: {
    hint: 'install cannot supply a passphrase; paste a key without one, or use ssh-agent instead.',
    retryable: false,
  },
  PROFILE_DENIED: {
    hint: 'This action needs a higher SSHEPHERD_PROFILE; a human re-runs it, the agent never raises its own.',
    retryable: false,
  },
  REMOTE_FAILED: {
    hint: 'The remote command did not run; the message names the transport code, fix that (sshepherd hosts test <alias>) and retry.',
    retryable: true,
  },
  HOST_KEY_UNKNOWN: {
    hint: 'A human compares data.fingerprints with the provider console (or ssh-keygen -l on the host itself), then the same command runs again with --fingerprint <SHA256:...>.',
    retryable: false,
  },
  HOST_KEY_CHANGED: {
    hint: 'known_hosts holds a different key for this host; find out why before trusting anything, then pass the fingerprint a human confirmed with --fingerprint.',
    retryable: false,
  },
  HOST_KEY_FINGERPRINT_MISMATCH: {
    hint: 'The host presents no key with that fingerprint; compare again with the provider console and pass one the host presents.',
    retryable: false,
  },
};

/** Exit 2 for a wrong command line, 1 for a run that failed, 0 for success — same split as the
 *  op groups. */
const SETUP_USER_ERROR_CODES: ReadonlySet<SetupErrorCode> = new Set([
  'UNKNOWN_SUBGROUP',
  'INVALID_ARGS',
  'PARSE_ERROR',
  'VALIDATION_ERROR',
  'PROFILE_DENIED',
]);

export function setupExitCode(result: SetupResult<unknown>): number {
  if (result.error === null) {
    return 0;
  }
  return SETUP_USER_ERROR_CODES.has(result.error.code) ? 2 : 1;
}

/** The only place a `SetupResult` is constructed — mirrors `buildEnvelope` in output.ts. */
export function buildSetupResult<T>(input: BuildSetupResultInput<T>): SetupResult<T> {
  const raw = input.error ?? null;
  const guidance = raw === null ? null : SETUP_GUIDANCE[raw.code];
  let error: SetupErrorInfo | null = null;
  if (raw !== null && guidance !== null) {
    error = {
      code: raw.code,
      message: raw.message,
      hint: raw.hint ?? guidance.hint,
      retryable: guidance.retryable,
    };
    const next = raw.next ?? guidance.next;
    if (next !== undefined) {
      error.next = next;
    }
    if (raw.did_you_mean !== undefined && raw.did_you_mean.length > 0) {
      error.did_you_mean = raw.did_you_mean;
    }
  }
  const result: SetupResult<T> = {
    schema_version: 1,
    ok: error === null,
    command: input.command,
    ran_at: new Date().toISOString(),
    data: input.data ?? null,
    error,
  };
  const auditFailures = takeSetupAuditFailures();
  if (auditFailures.length > 0) {
    result.warnings = auditFailures.map((failure) =>
      auditUnwritableWarning(failure.role, failure.errno),
    );
  }
  return result;
}

/**
 * Terminal rendering for a `SetupResult` — kept separate from output.ts's
 * `printJson`/`printPretty` (those are typed for `Envelope`, which has fields
 * `SetupResult` deliberately doesn't carry). Every setup result is printed through here, so this
 * is where it passes the scrubber.
 */
export function printSetupResult(unscrubbed: SetupResult<unknown>, pretty: boolean): void {
  const result = scrubLocalOutput(unscrubbed).value;
  if (!pretty) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  const lines = [`ok: ${result.ok}`, `command: ${result.command}`, `ran_at: ${result.ran_at}`];
  if (result.error !== null) {
    lines.push('', 'error:', `  code: ${result.error.code}`, `  message: ${result.error.message}`);
    lines.push(`  hint: ${result.error.hint}`, `  retryable: ${result.error.retryable}`);
    if (result.error.next !== undefined) {
      lines.push(`  next: ${result.error.next}`);
    }
  }
  if (result.data !== null && result.data !== undefined) {
    lines.push('', 'data:', JSON.stringify(result.data, null, 2));
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}

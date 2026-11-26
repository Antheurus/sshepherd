import { MAX_TIMEOUT_SEC } from './limits.ts';
import type { ErrorExtras, ErrorInfo, SshErrorCode } from './types.ts';

/** Placeholder in a guidance `next` that `fillNext` swaps for the alias the op ran against. */
const ALIAS_PLACEHOLDER = '<alias>';

/**
 * `message` is always a static human string looked up by `code`, never raw ssh
 * stderr — ssh chatter can contain hostnames/IPs, a per-code constant cannot.
 */
const ERROR_MESSAGES: Record<SshErrorCode, string> = {
  UNKNOWN_ALIAS: 'SSH alias is not defined in ssh config',
  CONNECT_TIMEOUT: 'Connection to the remote host timed out',
  AUTH_FAILED: 'SSH authentication failed for this alias',
  HOST_KEY_CHANGED: 'Remote host key does not match the known_hosts entry for this alias',
  HOST_KEY_UNKNOWN: 'known_hosts has no key for this alias and strict host key checking is on',
  SSH_TRANSPORT_ERROR: 'SSH transport failed before the command could run',
  COMMAND_FAILED: 'Remote command exited with a non-zero status',
  COMMAND_TIMEOUT: 'Remote command timed out',
  CONFIRMATION_REQUIRED: 'Mutating op refused: pass --yes (or confirm interactively) to proceed',
  VALIDATION_ERROR: 'invalid arguments',
  INVALID_ARGS: 'Invalid command-line arguments',
  PARSE_ERROR: 'Command line could not be parsed',
  UNKNOWN_SUBGROUP: 'Unknown group or action',
  CONFIG_PARSE_ERROR: 'A sshepherd config file could not be parsed',
  AUDIT_WRITE_FAILED: 'The op finished but its audit line could not be written',
  OUTPUT_TOO_LARGE:
    'The command printed more than sshepherd reads and its output could not be parsed',
  PROFILE_DENIED: 'This op needs a higher SSHEPHERD_PROFILE than the caller holds',
  INTERNAL_ERROR: 'sshepherd failed while running the op',
};

interface Guidance {
  hint: string;
  retryable: boolean;
  next?: string;
}

const GUIDANCE: Record<SshErrorCode, Guidance> = {
  UNKNOWN_ALIAS: {
    hint: 'Use an alias that exists in ~/.ssh/config; the list shows every alias sshepherd can reach.',
    retryable: false,
    next: 'sshepherd hosts list',
  },
  CONNECT_TIMEOUT: {
    hint: 'The host did not answer within the connect limit; confirm it is up and reachable, then try again.',
    retryable: true,
    next: `sshepherd hosts test ${ALIAS_PLACEHOLDER}`,
  },
  AUTH_FAILED: {
    hint: 'No key offered by ssh-agent was accepted for this alias; load the right key (ssh-add) or install it with setup ssh-alias.',
    retryable: false,
    next: `sshepherd setup ssh-alias status ${ALIAS_PLACEHOLDER}`,
  },
  HOST_KEY_CHANGED: {
    hint: 'The host presented a different key than known_hosts holds (a reinstalled server, or someone in the middle); a human confirms the new fingerprint out of band, then records it with hosts trust --fingerprint <SHA256:...> --yes.',
    retryable: false,
    next: `sshepherd hosts trust ${ALIAS_PLACEHOLDER} --dry-run`,
  },
  HOST_KEY_UNKNOWN: {
    hint: 'sshepherd never accepts an unknown host key on first use; show its fingerprint, have a human confirm it out of band, then record it with hosts trust --fingerprint <SHA256:...> --yes.',
    retryable: false,
    next: `sshepherd hosts trust ${ALIAS_PLACEHOLDER} --dry-run`,
  },
  SSH_TRANSPORT_ERROR: {
    hint: 'ssh failed before the command ran; the connection test shows whether the host is reachable at all.',
    retryable: true,
    next: `sshepherd hosts test ${ALIAS_PLACEHOLDER}`,
  },
  COMMAND_FAILED: {
    hint: 'The command ran and exited non-zero; read remote_exit and the data payload, then fix the cause before re-running.',
    retryable: false,
  },
  COMMAND_TIMEOUT: {
    hint: `The command outran its budget; re-run with a larger --timeout <sec> (max ${MAX_TIMEOUT_SEC}) or narrow what it does.`,
    retryable: true,
  },
  CONFIRMATION_REQUIRED: {
    hint: 'This op changes state; once a human has approved it, run the same command again with --yes.',
    retryable: false,
  },
  VALIDATION_ERROR: {
    hint: 'Fix the argument or config value the message names, then run the command again.',
    retryable: false,
  },
  INVALID_ARGS: {
    hint: 'Fix the argument the message names; --help on the action lists every argument.',
    retryable: false,
  },
  PARSE_ERROR: {
    hint: 'A flag is unknown or malformed; --help on the action lists the flags it accepts.',
    retryable: false,
  },
  UNKNOWN_SUBGROUP: {
    hint: 'Pick one of the names in did_you_mean; --help lists every group and action.',
    retryable: false,
    next: 'sshepherd --help',
  },
  CONFIG_PARSE_ERROR: {
    hint: 'Fix the file and line the message names (TOML syntax), then run the command again.',
    retryable: false,
  },
  AUDIT_WRITE_FAILED: {
    hint: 'The op already finished (op_outcome) and is missing from the audit log; point SSHEPHERD_STATE_DIR or SSHEPHERD_AUDIT_PATH at a writable directory before the next mutating op, and do not re-run this one just to record it.',
    retryable: false,
  },
  OUTPUT_TOO_LARGE: {
    hint: 'The output passed the read ceiling before it was complete; ask for less (a smaller --tail, a WHERE or LIMIT in the query) and run again.',
    retryable: false,
  },
  PROFILE_DENIED: {
    hint: 'A human raises the profile (SSHEPHERD_PROFILE=read|deploy|admin, unset means admin) and a target max_profile in targets.toml; the agent never raises its own.',
    retryable: false,
  },
  INTERNAL_ERROR: {
    hint: 'This is a bug in sshepherd or an unexpected reply from the host; re-running rarely helps, report the command.',
    retryable: false,
  },
};

/** Exported for the registry's mutating-op confirm gate — a `CONFIRMATION_REQUIRED`
 *  refusal never touches ssh, but still wants the same static-message ErrorInfo shape. */
export function errorInfo(code: SshErrorCode, remoteExit?: number): ErrorInfo {
  const guidance = GUIDANCE[code];
  const info: ErrorInfo = {
    code,
    message: ERROR_MESSAGES[code],
    hint: guidance.hint,
    retryable: guidance.retryable,
  };
  if (guidance.next !== undefined) {
    info.next = guidance.next;
  }
  if (remoteExit !== undefined) {
    info.remote_exit = remoteExit;
  }
  return info;
}

/** An `ErrorInfo` with a caller-written message (a local validation message, never ssh stderr)
 *  and optional hint/next/did_you_mean overriding the per-code defaults. */
export function describeError(
  code: SshErrorCode,
  message: string,
  extras: ErrorExtras = {},
): ErrorInfo {
  const info = errorInfo(code);
  info.message = message;
  if (extras.hint !== undefined) {
    info.hint = extras.hint;
  }
  if (extras.next !== undefined) {
    info.next = extras.next;
  }
  if (extras.did_you_mean !== undefined && extras.did_you_mean.length > 0) {
    info.did_you_mean = extras.did_you_mean;
  }
  return info;
}

/** Makes a guidance `next` exact: the alias placeholder becomes the alias the op ran against,
 *  and a `next` that still needs an alias nobody supplied is dropped rather than shown broken. */
export function fillNext(info: ErrorInfo, alias: string): ErrorInfo {
  if (info.next === undefined || !info.next.includes(ALIAS_PLACEHOLDER)) {
    return info;
  }
  if (alias.length === 0) {
    const { next: _dropped, ...rest } = info;
    return rest;
  }
  return { ...info, next: info.next.replace(ALIAS_PLACEHOLDER, alias) };
}

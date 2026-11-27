import { describeError } from './errors.ts';
import { optBool } from './op-args.ts';
import type { ErrorInfo, OpContext, OpSpec } from './types.ts';

/**
 * Permission profiles, lowest first: `read` inspects, `deploy` changes services, files and
 * deployments, `admin` also changes host security and the local trust store. `SSHEPHERD_PROFILE`
 * sets the caller's profile (unset = `admin`, the behaviour before profiles existed); a pg-target's
 * `max_profile` in targets.toml caps it further for the db ops on that target.
 *
 * The per-op table lives here rather than as an `OpSpec` field so every op's profile reads in one
 * place; the registry contract test fails when an op is missing from it or a stale name remains.
 */
export const PROFILES = ['read', 'deploy', 'admin'] as const;

export type Profile = (typeof PROFILES)[number];

const PROFILE_RANK: Record<Profile, number> = { read: 0, deploy: 1, admin: 2 };

export const OP_PROFILES: Record<string, Profile> = {
  'hosts list': 'read',
  'hosts test': 'read',
  'hosts info': 'read',
  'hosts disconnect': 'read',
  'hosts trust': 'admin',
  'check overview': 'read',
  'check mem': 'read',
  'check disk': 'read',
  'check cpu': 'read',
  'check ports': 'read',
  'check oom-history': 'read',
  'check kernel': 'read',
  'logs docker': 'read',
  'logs compose': 'read',
  'logs service': 'read',
  'logs docker-daemon': 'read',
  'logs nginx': 'read',
  'services ps': 'read',
  'services stats': 'read',
  'services inspect': 'read',
  'services compose-ps': 'read',
  'services healthcheck': 'read',
  'services systemctl-status': 'read',
  'services restart': 'deploy',
  'services systemctl-start': 'deploy',
  'services systemctl-stop': 'deploy',
  'services systemctl-restart': 'deploy',
  'services systemctl-reload': 'deploy',
  'files ls': 'read',
  'files cat': 'read',
  'files tail': 'read',
  'files head': 'read',
  'files grep': 'read',
  'files find': 'read',
  'files download': 'read',
  'files disk-usage': 'read',
  'files upload': 'deploy',
  'env keys': 'read',
  'env diff': 'read',
  'config get': 'read',
  'config validate': 'read',
  'config put': 'deploy',
  'config reload': 'deploy',
  'db list': 'read',
  'db tables': 'read',
  'db activity': 'read',
  'db connections': 'read',
  'db slow': 'read',
  'db size': 'read',
  'db query': 'read',
  'db describe': 'read',
  'db count': 'read',
  'db migrations': 'read',
  'db exec': 'deploy',
  'db backup': 'deploy',
  'db backup-verify': 'deploy',
  'deploy run': 'deploy',
  'deploy status': 'read',
  'deploy rollback': 'deploy',
  'deploy logs': 'read',
  'deploy migrate': 'deploy',
  'security harden': 'admin',
  'security ssh-audit': 'read',
  'security listeners': 'read',
  'security authorized-keys': 'read',
  'security fail2ban': 'read',
  'tunnel open': 'deploy',
  'tunnel list': 'read',
  'tunnel close': 'deploy',
  'audit tail': 'read',
  'http get': 'read',
  'http send': 'deploy',
  'wait for': 'read',
  'git head': 'read',
  'git log': 'read',
  'git diff-stat': 'read',
  'exec run': 'read',
  'exec change': 'deploy',
  'exec list': 'read',
};

export function isProfile(value: string): value is Profile {
  return (PROFILES as readonly string[]).includes(value);
}

/** Ops whose `--dry-run` runs for real and then undoes it (`db exec`: the statements execute,
 *  then ROLLBACK), so the dry run keeps the op's own profile and writes an audit row. */
export const DRY_RUN_EXECUTES = new Set(['db exec']);

/** A `--dry-run` executes and changes nothing, so it needs only `read` (the same exemption the
 *  confirm gate makes) unless the op is in `DRY_RUN_EXECUTES`. An op missing from the table needs
 *  `admin`: a gap fails closed. */
export function requiredProfile(op: OpSpec, ctx: OpContext): Profile {
  if (
    op.mutating &&
    optBool(ctx, 'dry-run', false) &&
    !DRY_RUN_EXECUTES.has(`${op.group} ${op.name}`)
  ) {
    return 'read';
  }
  return OP_PROFILES[`${op.group} ${op.name}`] ?? 'admin';
}

/** `setup` never reaches `executeOp`, so its actions carry their own profiles, keyed
 *  `<sub-group> <action>`: an action that writes local config (an ssh alias, a key, an allowlist, a
 *  target, a recipe) or opens the key-install form needs `admin`; one that only reads it needs
 *  `read`. An action missing here needs `admin` too. */
export const SETUP_PROFILES: Record<string, Profile> = {
  'ssh-alias register': 'admin',
  'ssh-alias keygen': 'admin',
  'ssh-alias remove': 'admin',
  'ssh-alias install': 'admin',
  'ssh-alias list': 'read',
  'ssh-alias status': 'read',
  'ssh-alias update': 'admin',
  'ssh-alias adopt-env': 'admin',
  'host add': 'admin',
  'db-target scaffold': 'admin',
  'db-target ro-role': 'read',
  'db-target discover': 'read',
  'config-allowlist scaffold': 'admin',
  'deploy-recipe scaffold': 'admin',
  'files-allowlist scaffold': 'admin',
  'reveal-allowlist scaffold': 'admin',
};

/** Code points of an unrecognised `SSHEPHERD_PROFILE` echoed back: enough to see the typo, and cut
 *  by code point so an emoji is never split into a lone surrogate a strict JSON parser rejects. */
const PROFILE_VALUE_MAX_CHARS = 32;

function unknownProfileError(envProfile: string): ErrorInfo {
  return describeError(
    'PROFILE_DENIED',
    `SSHEPHERD_PROFILE='${Array.from(envProfile).slice(0, PROFILE_VALUE_MAX_CHARS).join('')}' is not a profile; expected one of ${PROFILES.join(', ')}`,
  );
}

const callerHint = (needed: Profile): string =>
  `A human re-runs it with SSHEPHERD_PROFILE=${needed} (or unset); the agent never raises its own.`;

/** `PROFILE_DENIED` when the op needs more than the caller's profile, capped by the target's
 *  `max_profile` (`ctx.args.max_profile`, set only by `buildDbOpContext`), allows; null to proceed.
 *  An unrecognised `SSHEPHERD_PROFILE` is refused outright, never read as `admin`. */
export function profileDenial(
  op: OpSpec,
  ctx: OpContext,
  envProfile: string | undefined = process.env.SSHEPHERD_PROFILE,
): ErrorInfo | null {
  const command = `${op.group} ${op.name}`;
  if (envProfile !== undefined && !isProfile(envProfile)) {
    return unknownProfileError(envProfile);
  }
  const caller: Profile = envProfile ?? 'admin';
  const cap = ctx.args.max_profile;
  const capped =
    typeof cap === 'string' && isProfile(cap) && PROFILE_RANK[cap] < PROFILE_RANK[caller];
  const effective: Profile = capped ? (cap as Profile) : caller;
  const needed = requiredProfile(op, ctx);
  if (PROFILE_RANK[needed] <= PROFILE_RANK[effective]) {
    return null;
  }
  const source = capped
    ? `target '${String(ctx.args.target)}' has max_profile = "${effective}"`
    : `SSHEPHERD_PROFILE is '${effective}'`;
  return describeError('PROFILE_DENIED', `'${command}' needs the '${needed}' profile; ${source}`, {
    hint: capped
      ? `A human raises max_profile for that target in targets.toml to '${needed}' or higher; the agent never raises its own.`
      : callerHint(needed),
  });
}

/** The same refusal for a `setup <sub-group> <action>`, from `SETUP_PROFILES`; null to proceed. */
export function setupProfileDenial(
  action: string,
  envProfile: string | undefined = process.env.SSHEPHERD_PROFILE,
): ErrorInfo | null {
  if (envProfile !== undefined && !isProfile(envProfile)) {
    return unknownProfileError(envProfile);
  }
  const caller: Profile = envProfile ?? 'admin';
  const needed = SETUP_PROFILES[action] ?? 'admin';
  if (PROFILE_RANK[needed] <= PROFILE_RANK[caller]) {
    return null;
  }
  return describeError(
    'PROFILE_DENIED',
    `'setup ${action}' needs the '${needed}' profile; SSHEPHERD_PROFILE is '${caller}'`,
    { hint: callerHint(needed) },
  );
}

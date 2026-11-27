import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  CONNECT_TIMEOUT_SEC,
  DOCTOR_HOSTS_CONCURRENCY,
  DOCTOR_HOSTS_MAX_ALIASES,
  DOCTOR_HOSTS_PROBE_TIMEOUT_SEC,
} from '../limits.ts';
import { listHostAliases } from '../parsers/ssh-config.ts';
import { listOps } from '../registry.ts';
import { defaultSshConfigPath } from '../setup-ssh-alias.ts';
import { defaultTargetsPath, loadTargets } from '../targets.ts';
import { classify, defaultRunner, type SshRunner, STRICT_HOST_KEY_ARGS } from '../transport.ts';

export interface DoctorReport {
  installed_sha: string | null;
  dist_sha: string | null;
  skill_registry_match: boolean | null;
  targets_file: 'present' | 'missing';
  pg_targets_without_ro_role: string[] | null;
  /** The command that prints the read-only role SQL for a listed target; null when none is listed. */
  pg_ro_role_next: string | null;
}

/** A target's `user` counts as a dedicated read-only role when its name says so: `ro` as a whole
 *  word between `_`/`-` delimiters (`app_ro`), or `readonly` / `read_only` anywhere. */
const READ_ONLY_ROLE_PATTERN = /(^|[_-])ro($|[_-])|readonly|read_only/i;

function sha256OfFile(path: string): string | null {
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch {
    return null;
  }
}

function installedBinaryPath(): string {
  const dir = process.env.SSHEPHERD_INSTALL_DIR;
  return join(dir && dir.length > 0 ? dir : join(homedir(), '.local', 'bin'), 'sshepherd');
}

function skillPath(): string {
  const override = process.env.SSHEPHERD_SKILL_PATH;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.claude', 'skills', 'sshepherd', 'SKILL.md');
}

/** The built binary: `./dist/sshepherd` of the working directory when it exists, else the one in
 *  the repo that SKILL.md (a symlink into it) belongs to. */
function distBinaryPath(skill: string): string {
  const override = process.env.SSHEPHERD_DIST_PATH;
  if (override && override.length > 0) {
    return override;
  }
  const inCwd = join(process.cwd(), 'dist', 'sshepherd');
  if (existsSync(inCwd)) {
    return inCwd;
  }
  try {
    return join(dirname(realpathSync(skill)), 'dist', 'sshepherd');
  } catch {
    return inCwd;
  }
}

/** Every `sshepherd <group> <action>` line in SKILL.md except `setup` and the usage-shape line. */
function documentedOps(skillMd: string): Set<string> {
  const documented = new Set<string>();
  for (const match of skillMd.matchAll(/^sshepherd (\S+) (\S+)/gm)) {
    const [, group, action] = match;
    if (group === undefined || action === undefined) {
      continue;
    }
    if (group === '<group>' || group === 'setup' || action.startsWith('--')) {
      continue;
    }
    documented.add(`${group} ${action}`);
  }
  return documented;
}

function skillMatchesRegistry(skill: string): boolean | null {
  let skillMd: string;
  try {
    skillMd = readFileSync(skill, 'utf8');
  } catch {
    return null;
  }
  const documented = documentedOps(skillMd);
  const registered = new Set(listOps().map((op) => `${op.group} ${op.name}`));
  return documented.size === registered.size && [...registered].every((op) => documented.has(op));
}

/** Target names only — never the user, alias or host behind them. */
function targetsWithoutReadOnlyRole(): string[] {
  const targets = loadTargets();
  return Object.entries(targets)
    .filter(
      ([, target]) => target.containersOnly !== true && !READ_ONLY_ROLE_PATTERN.test(target.user),
    )
    .map(([name]) => name)
    .sort();
}

export function runDoctor(): DoctorReport {
  const skill = skillPath();
  const targetsFilePresent = existsSync(defaultTargetsPath());
  const withoutRoRole = targetsFilePresent ? targetsWithoutReadOnlyRole() : null;
  return {
    installed_sha: sha256OfFile(installedBinaryPath()),
    dist_sha: sha256OfFile(distBinaryPath(skill)),
    skill_registry_match: skillMatchesRegistry(skill),
    targets_file: targetsFilePresent ? 'present' : 'missing',
    pg_targets_without_ro_role: withoutRoRole,
    pg_ro_role_next:
      withoutRoRole !== null && withoutRoRole.length > 0
        ? 'sshepherd setup db-target ro-role <target> --print-sql'
        : null,
  };
}

export interface DoctorHostsReport {
  /** Aliases whose sshd still offers password (or keyboard-interactive) login: names only. */
  password_auth_targets: string[];
  /** How many aliases answered with their list of auth methods. */
  checked: number;
  /** Aliases that could not be asked, with the transport code (a host key not trusted yet, a
   *  timeout), or `NOT_PROBED` past `DOCTOR_HOSTS_MAX_ALIASES`. */
  unchecked: Array<{ alias: string; code: string }>;
  next: string | null;
}

type HostAuthVerdict =
  | { kind: 'password' }
  | { kind: 'key_only' }
  | { kind: 'unchecked'; code: string };

/** One key exchange under strict host-key checking that offers no authentication at all, so the
 *  server answers with the methods it would accept (`Permission denied (publickey,password)`) and
 *  nothing runs; no credential is read or sent. A host that lets `none` through (Tailscale SSH)
 *  needs no password either. */
async function probeHostAuth(alias: string, runner: SshRunner): Promise<HostAuthVerdict> {
  const outcome = await runner(
    [
      ...STRICT_HOST_KEY_ARGS,
      '-T',
      '-o',
      'BatchMode=yes',
      '-o',
      `ConnectTimeout=${CONNECT_TIMEOUT_SEC}`,
      '-o',
      'LogLevel=ERROR',
      '-o',
      'ControlMaster=no',
      '-o',
      'ControlPath=none',
      '-o',
      'PreferredAuthentications=none',
      alias,
      'true',
    ],
    DOCTOR_HOSTS_PROBE_TIMEOUT_SEC * 1_000,
  );
  if (outcome.timedOut) {
    return { kind: 'unchecked', code: 'CONNECT_TIMEOUT' };
  }
  const methods = /permission denied \(([^)]*)\)/i.exec(outcome.stderr)?.[1];
  if (methods !== undefined) {
    const offered = methods.split(',').map((method) => method.trim());
    return offered.includes('password') || offered.includes('keyboard-interactive')
      ? { kind: 'password' }
      : { kind: 'key_only' };
  }
  if (outcome.code === 0) {
    return { kind: 'key_only' };
  }
  const error = classify({
    code: outcome.code,
    stdout: '',
    transportStderr: outcome.stderr,
    commandStderr: '',
    timedOut: false,
  });
  return { kind: 'unchecked', code: error?.code ?? 'SSH_TRANSPORT_ERROR' };
}

/** `doctor hosts`: every alias in the ssh config whose server still accepts password login, which
 *  `security harden <alias> --keep-session=false` turns off once key login works. */
export async function runDoctorHosts(
  runner: SshRunner = defaultRunner,
  configPath: string = defaultSshConfigPath(),
): Promise<DoctorHostsReport> {
  const aliases = listHostAliases(configPath);
  const probed = aliases.slice(0, DOCTOR_HOSTS_MAX_ALIASES);
  const verdicts: HostAuthVerdict[] = new Array(probed.length);
  let nextIndex = 0;
  const worker = async (): Promise<void> => {
    while (nextIndex < probed.length) {
      const index = nextIndex;
      nextIndex += 1;
      verdicts[index] = await probeHostAuth(probed[index] ?? '', runner);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(DOCTOR_HOSTS_CONCURRENCY, probed.length) }, worker),
  );

  const passwordTargets: string[] = [];
  const unchecked: Array<{ alias: string; code: string }> = [];
  probed.forEach((alias, index) => {
    const verdict = verdicts[index];
    if (verdict?.kind === 'password') {
      passwordTargets.push(alias);
    } else if (verdict?.kind === 'unchecked') {
      unchecked.push({ alias, code: verdict.code });
    }
  });
  for (const alias of aliases.slice(DOCTOR_HOSTS_MAX_ALIASES)) {
    unchecked.push({ alias, code: 'NOT_PROBED' });
  }
  passwordTargets.sort();
  return {
    password_auth_targets: passwordTargets,
    checked: probed.length - unchecked.filter((entry) => entry.code !== 'NOT_PROBED').length,
    unchecked,
    next:
      passwordTargets.length > 0
        ? 'sshepherd hosts test <alias> (key login works), then sshepherd security harden <alias> --keep-session=false --yes'
        : null,
  };
}

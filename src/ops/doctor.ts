import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { listOps } from '../registry.ts';
import { loadTargets } from '../targets.ts';

export interface DoctorReport {
  installed_sha: string | null;
  dist_sha: string | null;
  skill_registry_match: boolean | null;
  pg_targets_without_ro_role: string[];
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
    .filter(([, target]) => !READ_ONLY_ROLE_PATTERN.test(target.user))
    .map(([name]) => name)
    .sort();
}

export function runDoctor(): DoctorReport {
  const skill = skillPath();
  return {
    installed_sha: sha256OfFile(installedBinaryPath()),
    dist_sha: sha256OfFile(distBinaryPath(skill)),
    skill_registry_match: skillMatchesRegistry(skill),
    pg_targets_without_ro_role: targetsWithoutReadOnlyRole(),
  };
}

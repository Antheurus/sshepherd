import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SETUP_PROFILES, setupProfileDenial } from '../profiles.ts';
import { SETUP_SUB_GROUPS } from '../setup.ts';

const CLI = join(import.meta.dir, '..', 'cli.ts');
const SETUP_ACTIONS = SETUP_SUB_GROUPS.flatMap((sub) =>
  sub.actions.map((action) => `${sub.name} ${action}`),
);

/** A full, valid argument list per writing action, so an ungated action really would write. */
const WRITING_ARGS: Record<string, string[]> = {
  'ssh-alias register': ['app1', '--host', '203.0.113.10', '--user', 'deploy', '--yes'],
  'ssh-alias keygen': ['app1', '--yes'],
  'ssh-alias remove': ['app1', '--yes'],
  'ssh-alias install': ['app1', '--yes'],
  'ssh-alias update': ['app1', '--host', '203.0.113.11', '--yes'],
  'ssh-alias adopt-env': ['/srv/app-project', '--yes'],
  'host add': ['app2', '--host', '203.0.113.12', '--user', 'deploy', '--yes'],
  'db-target scaffold': [
    'app1-db',
    '--alias',
    'app1',
    '--user',
    'app_ro',
    '--database',
    'app',
    '--container',
    'app-postgres',
    '--yes',
  ],
  'config-allowlist scaffold': ['app1', '--paths', '/etc/app/app.conf', '--yes'],
  'deploy-recipe scaffold': ['app1-deploy', '--alias', 'app1', '--workdir', '/srv/app', '--yes'],
  'files-allowlist scaffold': ['app1', '--paths', '/srv/app', '--yes'],
  'reveal-allowlist scaffold': ['app1', '--keys', 'LOG_LEVEL', '--yes'],
};

function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (path: string): void => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) {
        walk(child);
      } else {
        const stat = statSync(child);
        out[child.slice(dir.length)] = `${stat.size}:${stat.mtimeMs}`;
      }
    }
  };
  walk(dir);
  return out;
}

/** A temp HOME holding every config file setup writes, pre-seeded so mtimes can be compared. */
function tempConfig(): { home: string; env: Record<string, string> } {
  const home = mkdtempSync(join(tmpdir(), 'sshepherd-setup-profiles-'));
  const config = join(home, '.config', 'sshepherd');
  mkdirSync(join(config, 'recipes'), { recursive: true });
  mkdirSync(join(home, '.ssh'), { recursive: true });
  const env = {
    HOME: home,
    // bun's transpiler cache lives under HOME; off, so the snapshot sees only what setup wrote.
    BUN_RUNTIME_TRANSPILER_CACHE_PATH: '0',
    SSHEPHERD_SSH_CONFIG_PATH: join(home, '.ssh', 'config'),
    SSHEPHERD_TARGETS_PATH: join(config, 'targets.toml'),
    SSHEPHERD_CONFIG_ALLOWLIST_PATH: join(config, 'config-allowlist.toml'),
    SSHEPHERD_FILES_ALLOWLIST_PATH: join(config, 'files-allowlist.toml'),
    SSHEPHERD_REVEAL_ALLOWLIST_PATH: join(config, 'reveal-allowlist.toml'),
    SSHEPHERD_STATE_DIR: join(home, 'state'),
  };
  writeFileSync(
    env.SSHEPHERD_SSH_CONFIG_PATH,
    '# sshepherd-managed: app1\nHost app1\n  HostName 203.0.113.10\n  User deploy\n',
  );
  for (const path of [
    env.SSHEPHERD_TARGETS_PATH,
    env.SSHEPHERD_CONFIG_ALLOWLIST_PATH,
    env.SSHEPHERD_FILES_ALLOWLIST_PATH,
    env.SSHEPHERD_REVEAL_ALLOWLIST_PATH,
  ]) {
    writeFileSync(path, '');
  }
  return { home, env };
}

describe('setup profiles', () => {
  test('every setup action has an explicit profile, and no stale name remains', () => {
    expect(SETUP_ACTIONS.filter((action) => SETUP_PROFILES[action] === undefined)).toEqual([]);
    expect(Object.keys(SETUP_PROFILES).filter((action) => !SETUP_ACTIONS.includes(action))).toEqual(
      [],
    );
  });

  test('only the actions that read local config are read; every other one is admin', () => {
    const read = SETUP_ACTIONS.filter((action) => SETUP_PROFILES[action] === 'read');
    expect(read.sort()).toEqual([
      'db-target discover',
      'db-target ro-role',
      'ssh-alias list',
      'ssh-alias status',
    ]);
    expect(Object.keys(WRITING_ARGS).sort()).toEqual(
      SETUP_ACTIONS.filter((action) => SETUP_PROFILES[action] === 'admin').sort(),
    );
  });

  test('an action missing from the table needs admin, and an unknown profile is refused', () => {
    expect(setupProfileDenial('new-sub write', 'deploy')?.code).toBe('PROFILE_DENIED');
    expect(setupProfileDenial('new-sub write', 'admin')).toBeNull();
    expect(setupProfileDenial('ssh-alias list', 'superuser')?.code).toBe('PROFILE_DENIED');
    expect(setupProfileDenial('ssh-alias list', 'read')).toBeNull();
  });

  for (const [action, args] of Object.entries(WRITING_ARGS)) {
    test(`SSHEPHERD_PROFILE=read setup ${action}: PROFILE_DENIED, exit 2, nothing written`, () => {
      const { home, env } = tempConfig();
      const before = snapshot(home);
      const proc = Bun.spawnSync(['bun', CLI, 'setup', ...action.split(' '), ...args], {
        env: { ...process.env, ...env, SSHEPHERD_PROFILE: 'read' },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const result = JSON.parse(proc.stdout.toString());
      expect({ exit: proc.exitCode, ok: result.ok, code: result.error?.code }).toEqual({
        exit: 2,
        ok: false,
        code: 'PROFILE_DENIED',
      });
      expect(result.error.message).toBe(
        `'setup ${action}' needs the 'admin' profile; SSHEPHERD_PROFILE is 'read'`,
      );
      expect(snapshot(home)).toEqual(before);
    }, 30_000);
  }

  test('SSHEPHERD_PROFILE=read still runs the read-only actions', () => {
    const { env } = tempConfig();
    for (const argv of [['list'], ['status', 'app1']]) {
      const proc = Bun.spawnSync(['bun', CLI, 'setup', 'ssh-alias', ...argv], {
        env: { ...process.env, ...env, SSHEPHERD_PROFILE: 'read' },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      expect(JSON.parse(proc.stdout.toString()).error?.code).not.toBe('PROFILE_DENIED');
    }
  });

  test('the default profile (unset) is admin: a writing action is not refused', () => {
    const { env } = tempConfig();
    const { SSHEPHERD_PROFILE: _unset, ...inherited } = process.env;
    const proc = Bun.spawnSync(
      ['bun', CLI, 'setup', 'files-allowlist', 'scaffold', 'app1', '--paths', '/srv/app', '--yes'],
      { env: { ...inherited, ...env }, stdout: 'pipe', stderr: 'pipe' },
    );
    expect(JSON.parse(proc.stdout.toString()).ok).toBe(true);
  });
});

import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditLogPath } from '../audit.ts';
import { runDoctorHosts } from '../ops/doctor.ts';
import {
  adoptEnv,
  adoptedAliasName,
  type HostCheck,
  hostAdd,
  type OnboardDeps,
  parseDotenv,
  sshGroups,
} from '../setup-host.ts';
import { status } from '../setup-ssh-alias.ts';
import { buildSshpassArgs, type ServeLikeFn } from '../setup-ssh-alias-install-server.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';

const CLI = join(import.meta.dir, '..', 'cli.ts');
const FAKE_PASSWORD = ['fake', 'pw', 'value', '7731'].join('-');
const FAKE_KEY_BODY = ['b3BlbnNzaC1rZXktdjEAAAAA', 'BG5vbmUAAAAEbm9uZQ'].join('');

function tempConfigPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-setup-host-'));
  mkdirSync(join(dir, '.ssh'));
  return join(dir, '.ssh', 'config');
}

/** Scripted `hosts test` verdicts, consumed in order; the last one repeats. */
function scriptedHostsTest(verdicts: HostCheck[]): {
  hostsTest: OnboardDeps['hostsTest'];
  calls: string[];
} {
  const calls: string[] = [];
  return {
    calls,
    hostsTest: async (alias) => {
      calls.push(alias);
      return verdicts[Math.min(calls.length - 1, verdicts.length - 1)] as HostCheck;
    },
  };
}

const AUTH_FAILED: HostCheck = { ok: false, code: 'AUTH_FAILED', message: 'auth' };
const UNKNOWN_KEY: HostCheck = { ok: false, code: 'HOST_KEY_UNKNOWN', message: 'unknown' };
const OK: HostCheck = { ok: true, code: null, message: '' };

/** Submits `password` the instant the form is served, like a human typing it. */
function submittingServe(password: string): ServeLikeFn {
  return (options) => {
    queueMicrotask(() => {
      const form = new FormData();
      form.set('method', 'password');
      form.set('password', password);
      void options.fetch(
        new Request('http://127.0.0.1:1/tok/submit', { method: 'POST', body: form }),
      );
    });
    return { port: 1, stop: () => {} };
  };
}

function onboardDeps(overrides: Partial<OnboardDeps> & { verdicts: HostCheck[] }): {
  deps: OnboardDeps;
  spawned: string[];
  trusted: string[];
  tested: string[];
} {
  const spawned: string[] = [];
  const trusted: string[] = [];
  const scripted = scriptedHostsTest(overrides.verdicts);
  const deps: OnboardDeps = {
    hostsTest: scripted.hostsTest,
    hostsTrust: async (_alias, fingerprint) => {
      trusted.push(fingerprint);
      return OK;
    },
    hostKeyFingerprints: async () => [{ type: 'ED25519', fingerprint: 'SHA256:fake' }],
    server: {
      which: () => '/usr/bin/sshpass',
      peekBanner: async () => false,
      probeReachable: async () => false,
      serve: submittingServe(FAKE_PASSWORD),
      announceUrl: () => {},
      randomToken: () => 'tok',
      timeoutMs: 2_000,
      spawnInstall: async (password, target) => {
        spawned.push(`${password}|${target.sshConfigPath ?? 'none'}`);
        return { code: 0, timedOut: false };
      },
      spawnInstallWithKey: async (key, target) => {
        spawned.push(`${key.slice(0, 30)}|${target.sshConfigPath ?? 'none'}`);
        return { kind: 'installed' };
      },
    },
  };
  const { verdicts: _verdicts, ...rest } = overrides;
  return { deps: { ...deps, ...rest }, spawned, trusted, tested: scripted.calls };
}

describe('setup host add', () => {
  test('a trusted host runs register, keygen, install form and hosts test, in that order', async () => {
    const configPath = tempConfigPath();
    const { deps, spawned } = onboardDeps({ verdicts: [AUTH_FAILED, OK] });
    const result = await hostAdd(
      'web1',
      { host: '203.0.113.20', user: 'deploy', port: 2222, yes: true },
      configPath,
      deps,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.steps).toEqual([
      'register ok',
      'keygen ok',
      'host-key already trusted',
      'install ok',
      'hosts test ok',
    ]);
    expect(result.data?.next).toContain('setup files-allowlist scaffold web1');
    // The install went through the alias in this config, strictly, never user@host.
    expect(spawned).toEqual([`${FAKE_PASSWORD}|${configPath}`]);
    expect(JSON.stringify(result)).not.toContain(FAKE_PASSWORD);
  });

  test('an untrusted host key stops before the form and returns the fingerprints to confirm', async () => {
    const configPath = tempConfigPath();
    const { deps, spawned } = onboardDeps({ verdicts: [UNKNOWN_KEY] });
    const result = await hostAdd(
      'web1',
      { host: '203.0.113.20', user: 'deploy', yes: true },
      configPath,
      deps,
    );
    expect(result.error?.code).toBe('HOST_KEY_UNKNOWN');
    expect(result.data?.steps).toEqual(['register ok', 'keygen ok']);
    expect(result.data?.fingerprints).toEqual([{ type: 'ED25519', fingerprint: 'SHA256:fake' }]);
    expect(result.error?.next).toBe(
      'sshepherd setup host add web1 --fingerprint <SHA256:...> --yes',
    );
    expect(spawned).toEqual([]);
  });

  test('a re-run with --fingerprint reuses the alias and key, trusts through hosts trust, then installs', async () => {
    const configPath = tempConfigPath();
    await hostAdd(
      'web1',
      { host: '203.0.113.20', user: 'deploy', yes: true },
      configPath,
      onboardDeps({ verdicts: [UNKNOWN_KEY] }).deps,
    );
    const { deps, trusted } = onboardDeps({ verdicts: [UNKNOWN_KEY, OK] });
    const result = await hostAdd(
      'web1',
      { fingerprint: 'SHA256:confirmed', yes: true },
      configPath,
      deps,
    );
    expect(result.data?.steps).toEqual([
      'register already done',
      'keygen already done',
      'hosts trust ok',
      'install ok',
      'hosts test ok',
    ]);
    expect(trusted).toEqual(['SHA256:confirmed']);
  });

  test('a refused trust (wrong fingerprint) stops with that code and installs nothing', async () => {
    const configPath = tempConfigPath();
    const { deps, spawned } = onboardDeps({
      verdicts: [UNKNOWN_KEY],
      hostsTrust: async () => ({
        ok: false,
        code: 'HOST_KEY_FINGERPRINT_MISMATCH',
        message: 'no such key',
      }),
    });
    const result = await hostAdd(
      'web1',
      { host: '203.0.113.20', user: 'deploy', fingerprint: 'SHA256:wrong', yes: true },
      configPath,
      deps,
    );
    expect(result.error?.code).toBe('HOST_KEY_FINGERPRINT_MISMATCH');
    expect(spawned).toEqual([]);
  });

  test('without --yes nothing is written; an unregistered alias needs --host and --user', async () => {
    const configPath = tempConfigPath();
    const refused = await hostAdd(
      'web1',
      { host: '203.0.113.20', user: 'deploy', yes: false },
      configPath,
      onboardDeps({ verdicts: [OK] }).deps,
    );
    expect(refused.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(status('web1', configPath).error?.code).toBe('ALIAS_NOT_FOUND');
    const missing = await hostAdd(
      'web1',
      { yes: true },
      configPath,
      onboardDeps({ verdicts: [OK] }).deps,
    );
    expect(missing.error?.code).toBe('INVALID_ARGS');
  });

  test('a registered alias with other values is refused instead of rewritten', async () => {
    const configPath = tempConfigPath();
    await hostAdd(
      'web1',
      { host: '203.0.113.20', user: 'deploy', yes: true },
      configPath,
      onboardDeps({ verdicts: [AUTH_FAILED, OK] }).deps,
    );
    const result = await hostAdd(
      'web1',
      { host: '203.0.113.99', user: 'deploy', yes: true },
      configPath,
      onboardDeps({ verdicts: [OK] }).deps,
    );
    expect(result.error?.code).toBe('ALIAS_EXISTS');
    expect(status('web1', configPath).data?.host).toBe('203.0.113.20');
  });

  test('the install-form connection goes through the alias with strict host-key checking', () => {
    const target = {
      alias: 'web1',
      host: '203.0.113.20',
      user: 'deploy',
      port: 2222,
      publicKeyPath: '/tmp/x.pub',
    };
    const strict = buildSshpassArgs({ ...target, sshConfigPath: '/tmp/cfg' }, 'true');
    expect(strict).toEqual([
      'sshpass',
      '-f',
      '/dev/stdin',
      'ssh',
      '-F',
      '/tmp/cfg',
      '-o',
      'StrictHostKeyChecking=yes',
      '-o',
      'ConnectTimeout=10',
      'web1',
      'true',
    ]);
    // Plain `install` keeps its old shape.
    expect(buildSshpassArgs(target, 'true')).toContain('StrictHostKeyChecking=accept-new');
    expect(buildSshpassArgs(target, 'true')).toContain('deploy@203.0.113.20');
  });
});

describe('setup ssh-alias adopt-env', () => {
  test('parseDotenv reads export, quotes, multi-line and escaped PEM values, and comments', () => {
    const values = parseDotenv(
      [
        '# comment',
        'export SSH_HOST=203.0.113.30',
        "SSH_USER='deploy'",
        'SSH_PORT=2222 # inline comment',
        `OPS_SSH_PRIVATE_KEY="-----BEGIN KEY-----\\n${FAKE_KEY_BODY}\\n-----END KEY-----"`,
        'MULTI="line one',
        'line two"',
        'SSH_PASSWORD=first',
        'SSH_PASSWORD=last',
      ].join('\r\n'),
    );
    expect(values.get('SSH_HOST')).toBe('203.0.113.30');
    expect(values.get('SSH_USER')).toBe('deploy');
    expect(values.get('SSH_PORT')).toBe('2222');
    expect(values.get('OPS_SSH_PRIVATE_KEY')).toBe(
      `-----BEGIN KEY-----\n${FAKE_KEY_BODY}\n-----END KEY-----`,
    );
    expect(values.get('MULTI')).toBe('line one\nline two');
    expect(values.get('SSH_PASSWORD')).toBe('last');
  });

  test('sshGroups splits by prefix and skips a group with no host; aliases follow the dir name', () => {
    const groups = sshGroups(
      new Map([
        ['SSH_HOST', '203.0.113.30'],
        ['SSH_USER', 'deploy'],
        ['MENDA_SSH_HOSTNAME', '203.0.113.31'],
        ['MENDA_SSH_USERNAME', 'ops'],
        ['MENDA_SSH_PASS', 'x'],
        ['ORPHAN_SSH_PASSWORD', 'y'],
        ['DB_PASSWORD', 'z'],
      ]),
    );
    expect(groups.map((group) => group.prefix)).toEqual(['', 'MENDA']);
    expect(groups[1]?.fields).toEqual({ host: '203.0.113.31', user: 'ops', password: 'x' });
    expect(adoptedAliasName('/srv/My App', '')).toBe('my-app');
    expect(adoptedAliasName('/srv/My App', 'MENDA')).toBe('my-app-menda');
  });

  function project(env: string): string {
    const dir = join(mkdtempSync(join(tmpdir(), 'sshepherd-adopt-')), 'proj');
    mkdirSync(dir);
    writeFileSync(join(dir, '.env'), env);
    return dir;
  }

  test('adopts every group with its own credential, reports {alias, key_installed} and no value', async () => {
    const configPath = tempConfigPath();
    const dir = project(
      [
        'SSH_HOST=203.0.113.30',
        'SSH_USER=deploy',
        `SSH_PASSWORD=${FAKE_PASSWORD}`,
        'KEYED_SSH_HOST=203.0.113.31',
        'KEYED_SSH_USER=ops',
        'KEYED_SSH_PORT=2200',
        `KEYED_SSH_PRIVATE_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\\n${FAKE_KEY_BODY}\\n-----END OPENSSH PRIVATE KEY-----"`,
        'HALF_SSH_HOST=203.0.113.32',
      ].join('\n'),
    );
    const audit = auditLogPath();
    const auditBefore = readFileSync(audit, { flag: 'a+' }).toString().length;
    const { deps, spawned } = onboardDeps({ verdicts: [AUTH_FAILED, OK, AUTH_FAILED, OK] });
    const result = await adoptEnv(dir, { yes: true }, configPath, deps);
    expect(result.data).toEqual([
      { alias: 'proj', key_installed: true },
      { alias: 'proj-keyed', key_installed: true },
      {
        alias: 'proj-half',
        key_installed: false,
        reason: 'INCOMPLETE',
        next: "set HALF_SSH_USER, HALF_SSH_PASSWORD or HALF_SSH_PRIVATE_KEY in the project's .env, then run adopt-env again",
      },
    ]);
    expect(spawned).toEqual([
      `${FAKE_PASSWORD}|${configPath}`,
      `-----BEGIN OPENSSH PRIVATE KEY-----`.slice(0, 30) + `|${configPath}`,
    ]);
    const auditRows = readFileSync(audit, 'utf8').slice(auditBefore);
    for (const text of [JSON.stringify(result), auditRows, readFileSync(configPath, 'utf8')]) {
      expect(text).not.toContain(FAKE_PASSWORD);
      expect(text).not.toContain(FAKE_KEY_BODY);
    }
    expect(status('proj-keyed', configPath).data?.port).toBe(2200);
  });

  test('a host key that is not trusted is reported, never accepted, and nothing is installed', async () => {
    const configPath = tempConfigPath();
    const dir = project(`SSH_HOST=203.0.113.30\nSSH_USER=deploy\nSSH_PASSWORD=${FAKE_PASSWORD}\n`);
    const { deps, spawned } = onboardDeps({ verdicts: [UNKNOWN_KEY] });
    const result = await adoptEnv(dir, { yes: true }, configPath, deps);
    expect(result.data?.[0]).toMatchObject({
      alias: 'proj',
      key_installed: false,
      reason: 'HOST_KEY_UNKNOWN',
    });
    expect(result.data?.[0]?.next).toStartWith('sshepherd hosts trust proj --dry-run');
    expect(spawned).toEqual([]);
  });

  test('a wrong .env password reports INSTALL_FAILED; a second run on an adopted host is a no-op', async () => {
    const configPath = tempConfigPath();
    const dir = project(`SSH_HOST=203.0.113.30\nSSH_USER=deploy\nSSH_PASSWORD=${FAKE_PASSWORD}\n`);
    const refused = onboardDeps({ verdicts: [AUTH_FAILED] });
    refused.deps.server.spawnInstall = async () => ({ code: 5, timedOut: false });
    expect((await adoptEnv(dir, { yes: true }, configPath, refused.deps)).data?.[0]?.reason).toBe(
      'INSTALL_FAILED',
    );
    const again = onboardDeps({ verdicts: [OK] });
    expect((await adoptEnv(dir, { yes: true }, configPath, again.deps)).data).toEqual([
      { alias: 'proj', key_installed: true },
    ]);
    expect(again.spawned).toEqual([]);
  });

  test('no .env, no SSH group, or no --yes is refused before anything is written', async () => {
    const configPath = tempConfigPath();
    const deps = onboardDeps({ verdicts: [OK] }).deps;
    const empty = join(mkdtempSync(join(tmpdir(), 'sshepherd-adopt-')), 'proj');
    mkdirSync(empty);
    expect((await adoptEnv(empty, { yes: true }, configPath, deps)).error?.code).toBe(
      'VALIDATION_ERROR',
    );
    expect((await adoptEnv(project('APP=1\n'), { yes: true }, configPath, deps)).error?.code).toBe(
      'VALIDATION_ERROR',
    );
    expect(
      (await adoptEnv(project('SSH_HOST=203.0.113.30\n'), { yes: false }, configPath, deps)).error
        ?.code,
    ).toBe('CONFIRMATION_REQUIRED');
    expect(status('proj', configPath).error?.code).toBe('ALIAS_NOT_FOUND');
  });
});

describe('doctor hosts', () => {
  function runnerFor(byAlias: Record<string, SpawnOutcome>): {
    runner: SshRunner;
    args: string[][];
  } {
    const args: string[][] = [];
    return {
      args,
      runner: async (argv) => {
        args.push(argv);
        const alias = argv[argv.length - 2] ?? '';
        return byAlias[alias] ?? { code: 255, stdout: '', stderr: '', timedOut: false };
      },
    };
  }

  test('lists only aliases whose server offers password login, by name', async () => {
    const configPath = tempConfigPath();
    writeFileSync(
      configPath,
      [
        'Host *',
        '  ServerAliveInterval 30',
        'Host pw-box',
        '  HostName 203.0.113.40',
        'Host kbd-box key-box',
        '  HostName 203.0.113.41',
        'Host ts-box new-box slow-box',
        '  HostName 203.0.113.42',
      ].join('\n'),
    );
    const denied = (methods: string): SpawnOutcome => ({
      code: 255,
      stdout: '',
      stderr: `deploy@203.0.113.40: Permission denied (${methods}).\r\n`,
      timedOut: false,
    });
    const { runner, args } = runnerFor({
      'pw-box': denied('publickey,password'),
      'kbd-box': denied('publickey,keyboard-interactive'),
      'key-box': denied('publickey'),
      'ts-box': { code: 0, stdout: '', stderr: '', timedOut: false },
      'new-box': {
        code: 255,
        stdout: '',
        stderr:
          'No ED25519 host key is known for [203.0.113.42]:22 and you have requested strict checking.\r\nHost key verification failed.\r\n',
        timedOut: false,
      },
      'slow-box': { code: 255, stdout: '', stderr: '', timedOut: true },
    });
    const report = await runDoctorHosts(runner, configPath);
    expect(report).toEqual({
      password_auth_targets: ['kbd-box', 'pw-box'],
      checked: 4,
      unchecked: [
        { alias: 'new-box', code: 'HOST_KEY_UNKNOWN' },
        { alias: 'slow-box', code: 'CONNECT_TIMEOUT' },
      ],
      next: 'sshepherd hosts test <alias> (key login works), then sshepherd security harden <alias> --keep-session=false --yes',
    });
    expect(JSON.stringify(report)).not.toContain('203.0.113');
    // Every probe is strict and credential-free.
    for (const argv of args) {
      expect(argv).toContain('StrictHostKeyChecking=yes');
      expect(argv).toContain('PreferredAuthentications=none');
    }
  });

  test('no password target means no next step', async () => {
    const configPath = tempConfigPath();
    writeFileSync(configPath, 'Host key-box\n  HostName 203.0.113.41\n');
    const { runner } = runnerFor({
      'key-box': {
        code: 255,
        stdout: '',
        stderr: 'Permission denied (publickey).',
        timedOut: false,
      },
    });
    expect(await runDoctorHosts(runner, configPath)).toEqual({
      password_auth_targets: [],
      checked: 1,
      unchecked: [],
      next: null,
    });
  });
});

describe('setup host / adopt-env CLI', () => {
  test('an unknown flag on setup host add is refused before anything runs', () => {
    const configPath = tempConfigPath();
    const proc = Bun.spawnSync(
      ['bun', CLI, 'setup', 'host', 'add', 'web1', '--hots', '203.0.113.20', '--yes'],
      {
        env: { ...process.env, SSHEPHERD_SSH_CONFIG_PATH: configPath },
        stdout: 'pipe',
        stderr: 'pipe',
      },
    );
    const result = JSON.parse(proc.stdout.toString());
    expect({ exit: proc.exitCode, code: result.error?.code }).toEqual({
      exit: 2,
      code: 'PARSE_ERROR',
    });
    expect(result.error.did_you_mean).toEqual(['--host']);
  }, 30_000);

  test('adopt-env without a project dir is INVALID_ARGS', () => {
    const proc = Bun.spawnSync(['bun', CLI, 'setup', 'ssh-alias', 'adopt-env', '--yes'], {
      env: { ...process.env, SSHEPHERD_SSH_CONFIG_PATH: tempConfigPath() },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(JSON.parse(proc.stdout.toString()).error?.code).toBe('INVALID_ARGS');
  }, 30_000);
});

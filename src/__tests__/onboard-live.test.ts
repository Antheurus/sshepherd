import { afterAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

/**
 * `setup host add`, `setup ssh-alias adopt-env` and `doctor hosts` against the smoke fixture's
 * password-auth sshd (`sshd-pw`, user `deploy`, its password set per run by scripts/smoke.sh). Every
 * run gets a scratch HOME, ssh config, known_hosts, audit log and socket dir; nothing touches
 * `~/.ssh` or `~/.config/sshepherd`. The scratch ssh config opens with a `Host *` block pointing
 * known_hosts at the scratch file and turning the ssh agent off, because ssh resolves `~` from the
 * password database, never from `$HOME`. The install form is filled the way a human would fill it:
 * the URL the CLI prints is fetched and the password POSTed to it. Skipped without the fixture.
 */

const REPO = join(import.meta.dir, '..', '..');
const CLI = join(REPO, 'src', 'cli.ts');
const FIXTURE_DIR = join(REPO, 'scripts', 'sshd-fixture');

function fixtureNames(): { prefix: string; state: string } {
  const proc = Bun.spawnSync(
    [
      'bash',
      '-c',
      '. "$1"; printf "%s\\n%s" "$SMOKE_PREFIX" "$SMOKE_STATE"',
      'bash',
      join(FIXTURE_DIR, 'project.sh'),
    ],
    { stdout: 'pipe', stderr: 'pipe' },
  );
  const [prefix = '', state = ''] = proc.stdout.toString().split('\n');
  return { prefix, state };
}

const { prefix: PREFIX, state: STATE } = fixtureNames();
const LIVE = existsSync(join(STATE, 'pw_port')) && existsSync(join(STATE, 'pw_password'));
const PW_PORT = LIVE ? readFileSync(join(STATE, 'pw_port'), 'utf8').trim() : '';
const PASSWORD = LIVE ? readFileSync(join(STATE, 'pw_password'), 'utf8') : '';
const HOST_KEYS = LIVE
  ? readFileSync(join(STATE, 'pw_host_keys.pub'), 'utf8')
      .split('\n')
      .map((line) => line.trim().split(/\s+/))
      .filter((fields) => fields.length >= 2)
  : [];

function fingerprint(type: string): string {
  const key = HOST_KEYS.find(([keyType]) => keyType === type)?.[1] ?? '';
  const digest = createHash('sha256').update(Buffer.from(key, 'base64')).digest('base64');
  return `SHA256:${digest.replace(/=+$/, '')}`;
}

function knownHostsLines(): string {
  return HOST_KEYS.map(([type, key]) => `[127.0.0.1]:${PW_PORT} ${type} ${key}`).join('\n');
}

interface Scratch {
  dir: string;
  configPath: string;
  knownHosts: string;
  auditPath: string;
  env: Record<string, string>;
}

const scratches: Scratch[] = [];

function scratch(extraConfig = ''): Scratch {
  const dir = mkdtempSync('/tmp/p19-onb-');
  mkdirSync(join(dir, '.ssh'), { mode: 0o700 });
  mkdirSync(join(dir, 'run'), { mode: 0o700 });
  const configPath = join(dir, '.ssh', 'config');
  const knownHosts = join(dir, '.ssh', 'known_hosts');
  writeFileSync(
    configPath,
    [
      'Host *',
      `  UserKnownHostsFile ${knownHosts}`,
      '  GlobalKnownHostsFile /dev/null',
      '  IdentityAgent none',
      '  IdentitiesOnly yes',
      '',
      extraConfig,
    ].join('\n'),
    { mode: 0o600 },
  );
  const auditPath = join(dir, 'state', 'audit.jsonl');
  const env: Record<string, string> = {
    HOME: dir,
    BUN_RUNTIME_TRANSPILER_CACHE_PATH: '0',
    SSHEPHERD_SSH_CONFIG_PATH: configPath,
    SSHEPHERD_STATE_DIR: join(dir, 'state'),
    SSHEPHERD_AUDIT_PATH: auditPath,
    SSHEPHERD_TARGETS_PATH: join(dir, 'targets.toml'),
    SSHEPHERD_FILES_ALLOWLIST_PATH: join(dir, 'files-allowlist.toml'),
    SSHEPHERD_REVEAL_ALLOWLIST_PATH: join(dir, 'reveal-allowlist.toml'),
    SSHEPHERD_CONFIG_ALLOWLIST_PATH: join(dir, 'config-allowlist.toml'),
    SSHEPHERD_INSTALL_NO_BROWSER: '1',
    XDG_RUNTIME_DIR: join(dir, 'run'),
  };
  const made = { dir, configPath, knownHosts, auditPath, env };
  scratches.push(made);
  return made;
}

interface CliRun {
  exit: number;
  stdout: string;
  stderr: string;
  result: {
    ok: boolean;
    data: Record<string, unknown> | Array<Record<string, unknown>> | null;
    error: { code: string; next?: string } | null;
  };
  formServed: boolean;
}

/** Runs the CLI; when it prints the install-form URL, fills the form with the fixture password the
 *  way a browser would (GET the form, POST it), then reads the rest of stdout. */
async function cli(s: Scratch, argv: string[], cwd = REPO): Promise<CliRun> {
  const { SSHEPHERD_PROFILE: _unset, ...inherited } = process.env;
  const proc = Bun.spawn(['bun', CLI, ...argv], {
    cwd,
    env: { ...inherited, ...s.env },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const stderrPromise = new Response(proc.stderr).text();
  const decoder = new TextDecoder();
  let stdout = '';
  let formServed = false;
  for await (const chunk of proc.stdout) {
    stdout += decoder.decode(chunk);
    const url =
      /Open this URL in your browser to install the key: (http:\/\/127\.0\.0\.1:\d+\/\S+)\n/.exec(
        stdout,
      )?.[1];
    if (url !== undefined && !formServed) {
      formServed = true;
      const page = await fetch(url);
      expect(page.status).toBe(200);
      expect(await page.text()).toContain('name="password"');
      const form = new FormData();
      form.set('method', 'password');
      form.set('password', PASSWORD);
      const submitted = await fetch(`${url}/submit`, { method: 'POST', body: form });
      expect(await submitted.text()).toContain('Key installed');
    }
  }
  const exit = await proc.exited;
  const stderr = await stderrPromise;
  return {
    exit,
    stdout,
    stderr,
    result: JSON.parse(stdout.slice(stdout.indexOf('{'))),
    formServed,
  };
}

/** Every file under the scratch `.ssh` (config, generated keys, known_hosts) plus the audit log. */
function writtenFiles(s: Scratch): string[] {
  const files = readdirSync(join(s.dir, '.ssh')).map((name) => join(s.dir, '.ssh', name));
  return existsSync(s.auditPath) ? [...files, s.auditPath] : files;
}

function expectNoHits(canaries: string[], texts: Record<string, string>): void {
  const hits = Object.entries(texts).flatMap(([where, text]) =>
    canaries.filter((canary) => text.includes(canary)).map(() => where),
  );
  expect(hits).toEqual([]);
}

afterAll(async () => {
  for (const s of scratches) {
    const { SSHEPHERD_PROFILE: _unset, ...inherited } = process.env;
    Bun.spawnSync(['bun', CLI, 'hosts', 'disconnect', '--all'], {
      env: { ...inherited, ...s.env },
      stdout: 'ignore',
      stderr: 'ignore',
    });
    rmSync(s.dir, { recursive: true, force: true });
  }
});

describe.skipIf(!LIVE)('onboarding against the password-auth fixture sshd', () => {
  test('setup host add on a host whose key is already known ends with hosts test ok', async () => {
    const s = scratch();
    writeFileSync(s.knownHosts, `${knownHostsLines()}\n`, { mode: 0o600 });
    const run = await cli(s, [
      'setup',
      'host',
      'add',
      'smoke-pw',
      '--host',
      '127.0.0.1',
      '--port',
      PW_PORT,
      '--user',
      'deploy',
      '--yes',
    ]);
    expect(run.result.error).toBeNull();
    expect(run.exit).toBe(0);
    expect(run.formServed).toBe(true);
    expect((run.result.data as { steps: string[] }).steps).toEqual([
      'register ok',
      'keygen ok',
      'host-key already trusted',
      'install ok',
      'hosts test ok',
    ]);
    expectNoHits([PASSWORD], {
      stdout: run.stdout,
      stderr: run.stderr,
      ...Object.fromEntries(writtenFiles(s).map((file) => [file, readFileSync(file, 'utf8')])),
    });
  }, 120_000);

  test('setup host add on an unknown host key stops for a fingerprint, then trusts it and installs', async () => {
    const s = scratch();
    const base = ['setup', 'host', 'add', 'smoke-pw2'];
    const first = await cli(s, [
      ...base,
      '--host',
      '127.0.0.1',
      '--port',
      PW_PORT,
      '--user',
      'deploy',
      '--yes',
    ]);
    expect(first.result.error?.code).toBe('HOST_KEY_UNKNOWN');
    expect(first.formServed).toBe(false);
    const data = first.result.data as {
      steps: string[];
      fingerprints: Array<{ fingerprint: string }>;
    };
    expect(data.steps).toEqual(['register ok', 'keygen ok']);
    expect(data.fingerprints.map((entry) => entry.fingerprint)).toContain(
      fingerprint('ssh-ed25519'),
    );
    expect(first.result.error?.next).toBe(
      'sshepherd setup host add smoke-pw2 --fingerprint <SHA256:...> --yes',
    );

    const second = await cli(s, [...base, '--fingerprint', fingerprint('ssh-ed25519'), '--yes']);
    expect(second.result.error).toBeNull();
    expect((second.result.data as { steps: string[] }).steps).toEqual([
      'register already done',
      'keygen already done',
      'hosts trust ok',
      'install ok',
      'hosts test ok',
    ]);
  }, 180_000);

  test('setup ssh-alias adopt-env installs keys from a .env password and private key, printing no value', async () => {
    const s = scratch();
    // A key the server already accepts, as a project's .env would carry it inline.
    const keySource = join(s.dir, 'keysrc');
    mkdirSync(keySource, { mode: 0o700 });
    Bun.spawnSync(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', join(keySource, 'k')]);
    const pub = readFileSync(join(keySource, 'k.pub'), 'utf8');
    const authorize = Bun.spawnSync(
      [
        'docker',
        'exec',
        '-i',
        `${PREFIX}-sshd-pw`,
        'sh',
        '-c',
        'mkdir -p /home/deploy/.ssh && cat >> /home/deploy/.ssh/authorized_keys && chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys',
      ],
      { stdin: new TextEncoder().encode(pub), stdout: 'ignore', stderr: 'ignore' },
    );
    expect(authorize.exitCode).toBe(0);
    const pem = readFileSync(join(keySource, 'k'), 'utf8');
    const pemCanary = pem.split('\n')[2] ?? '';
    expect(pemCanary.length).toBeGreaterThan(40);

    const projectDir = join(s.dir, 'fixtures', 'proj');
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(
      join(projectDir, '.env'),
      [
        'APP_NAME=demo',
        'SSH_HOST=127.0.0.1',
        `SSH_PORT=${PW_PORT}`,
        'SSH_USER=deploy',
        `SSH_PASSWORD=${PASSWORD}`,
        'KEYED_SSH_HOST=127.0.0.1',
        `KEYED_SSH_PORT=${PW_PORT}`,
        'KEYED_SSH_USER=deploy',
        `KEYED_SSH_PRIVATE_KEY="${pem.trim().replace(/\n/g, '\\n')}"`,
        '',
      ].join('\n'),
    );

    const argv = ['setup', 'ssh-alias', 'adopt-env', './fixtures/proj', '--yes'];
    const untrusted = await cli(s, argv, s.dir);
    expect(untrusted.result.data).toEqual([
      {
        alias: 'proj',
        key_installed: false,
        reason: 'HOST_KEY_UNKNOWN',
        next: 'sshepherd hosts trust proj --dry-run, then --fingerprint <SHA256:...> --yes once a human confirmed it, then adopt-env again',
      },
      {
        alias: 'proj-keyed',
        key_installed: false,
        reason: 'HOST_KEY_UNKNOWN',
        next: 'sshepherd hosts trust proj-keyed --dry-run, then --fingerprint <SHA256:...> --yes once a human confirmed it, then adopt-env again',
      },
    ]);

    const trust = await cli(s, [
      'hosts',
      'trust',
      'proj',
      '--fingerprint',
      fingerprint('ssh-ed25519'),
      '--yes',
    ]);
    expect(trust.result.error).toBeNull();

    const adopted = await cli(s, argv, s.dir);
    expect(adopted.exit).toBe(0);
    expect(adopted.result.data).toEqual([
      { alias: 'proj', key_installed: true },
      { alias: 'proj-keyed', key_installed: true },
    ]);
    // Key login now works for both aliases with their generated keys.
    for (const alias of ['proj', 'proj-keyed']) {
      const test = await cli(s, ['hosts', 'test', alias]);
      expect((test.result.data as { reachable: boolean }).reachable).toBe(true);
    }

    const runs = [untrusted, trust, adopted];
    expectNoHits([PASSWORD, pemCanary], {
      ...Object.fromEntries(
        runs.flatMap((run, i) => [
          [`stdout ${i}`, run.stdout],
          [`stderr ${i}`, run.stderr],
        ]),
      ),
      ...Object.fromEntries(writtenFiles(s).map((file) => [file, readFileSync(file, 'utf8')])),
    });
    const auditRows = readFileSync(s.auditPath, 'utf8').trim().split('\n');
    expect(auditRows.filter((row) => row.includes('"setup ssh-alias adopt-env"')).length).toBe(4);
  }, 240_000);

  test('doctor hosts lists the password-auth alias by name and not the key-only one', async () => {
    const debianPort = /Host smoke-debian\n(?:.*\n)*?\s+Port (\d+)/.exec(
      readFileSync(join(STATE, 'ssh_config'), 'utf8'),
    )?.[1];
    expect(debianPort).toBeDefined();
    const s = scratch(
      [
        'Host pw-target',
        '  HostName 127.0.0.1',
        `  Port ${PW_PORT}`,
        '  User deploy',
        'Host key-target',
        '  HostName 127.0.0.1',
        `  Port ${debianPort}`,
        '  User root',
        'Host untrusted-target',
        '  HostName 127.0.0.1',
        `  Port ${PW_PORT}`,
        '  User deploy',
        '  HostKeyAlias untrusted-target.invalid',
        '',
      ].join('\n'),
    );
    const fixtureKnown = readFileSync(join(STATE, 'known_hosts'), 'utf8');
    writeFileSync(s.knownHosts, `${knownHostsLines()}\n${fixtureKnown}`, { mode: 0o600 });
    const run = await cli(s, ['doctor', 'hosts']);
    expect(run.exit).toBe(0);
    expect(run.result.data).toEqual({
      password_auth_targets: ['pw-target'],
      checked: 2,
      unchecked: [{ alias: 'untrusted-target', code: 'HOST_KEY_UNKNOWN' }],
      next: 'sshepherd hosts test <alias> (key login works), then sshepherd security harden <alias> --keep-session=false --yes',
    });
    const data = JSON.stringify(run.result.data);
    for (const value of ['127.0.0.1', PW_PORT, String(debianPort), 'deploy', 'root']) {
      expect(data).not.toContain(value);
    }
  }, 60_000);
});

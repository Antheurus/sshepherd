import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { scrubText } from '../scrub.ts';
import { awaitForward } from '../tunnel.ts';

const REPO = join(import.meta.dir, '..', '..');
const BIN = join(REPO, 'dist', 'sshepherd');
const PROJECT = process.env.SSHEPHERD_SMOKE_PROJECT ?? 'sshepherd-smoke';
const PREFIX = PROJECT === 'sshepherd-smoke' ? 'sshepherd-fixture' : `${PROJECT}-fixture`;
const STATE = process.env.SSHEPHERD_SMOKE_STATE_DIR ?? `/tmp/${PROJECT}`;
const VARIANT = 'alpine';
const CONTAINER = `${PREFIX}-sshd-${VARIANT}`;
const LIVE = existsSync(join(STATE, 'ssh_config'));

const randomValue = (): string => {
  const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from(randomBytes(24), (byte) => alphabet[byte % alphabet.length]).join('');
};

function docker(...args: string[]): string {
  const proc = Bun.spawnSync(['docker', ...args], { stdout: 'pipe', stderr: 'pipe' });
  if (proc.exitCode !== 0) {
    throw new Error(`docker ${args[0]} failed: ${proc.stderr.toString().slice(-300)}`);
  }
  return proc.stdout.toString();
}

function hostKeyLines(): { type: string; key: string }[] {
  return docker('exec', CONTAINER, 'sh', '-c', 'cat /etc/ssh/ssh_host_*_key.pub')
    .split('\n')
    .map((line) => line.trim().split(/\s+/))
    .filter((fields) => fields.length >= 2)
    .map(([type = '', key = '']) => ({ type, key }));
}

function fingerprintOf(key: string): string {
  const hasher = new Bun.CryptoHasher('sha256');
  hasher.update(Buffer.from(key, 'base64'));
  return `SHA256:${hasher.digest('base64').replace(/=+$/, '')}`;
}

function fixturePort(): string {
  const text = readFileSync(join(STATE, 'ssh_config'), 'utf8');
  const block = text.split(/^Host /m).find((entry) => entry.startsWith(`smoke-${VARIANT}\n`)) ?? '';
  const port = /^\s*Port\s+(\d+)/m.exec(block)?.[1];
  if (port === undefined) {
    throw new Error(
      `fixture ${PROJECT} is not up: no smoke-${VARIANT} port in ${STATE}/ssh_config`,
    );
  }
  return port;
}

let scratch = '';
let port = '';

function stanza(alias: string, knownHosts: string): string {
  return [
    `Host ${alias}`,
    '  HostName 127.0.0.1',
    `  Port ${port}`,
    '  User root',
    `  IdentityFile ${join(STATE, 'keys', 'id_ed25519')}`,
    '  IdentitiesOnly yes',
    `  UserKnownHostsFile ${knownHosts}`,
    '',
  ].join('\n');
}

function binEnv(): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: join(scratch, 'home'),
    SSHEPHERD_SSH_CONFIG_PATH: join(scratch, 'ssh_config'),
    SSHEPHERD_STATE_DIR: join(scratch, 'state'),
    SSHEPHERD_AUDIT_PATH: join(scratch, 'state', 'audit.jsonl'),
    SSHEPHERD_TUNNEL_STATE_DIR: join(scratch, 'tunnels'),
    SSHEPHERD_TARGETS_PATH: join(scratch, 'targets.toml'),
    SSHEPHERD_FILES_ALLOWLIST_PATH: join(scratch, 'files-allowlist.toml'),
    SSHEPHERD_REVEAL_ALLOWLIST_PATH: join(scratch, 'reveal-allowlist.toml'),
    XDG_RUNTIME_DIR: join(scratch, 'run'),
  };
}

interface CliResult {
  code: number;
  json: {
    ok: boolean;
    data: Record<string, unknown> | null;
    error: {
      code: string;
      message: string;
      hint?: string;
      data?: { sql_error?: { message?: string } };
    } | null;
  };
}

function cli(...args: string[]): CliResult {
  const proc = Bun.spawnSync([BIN, ...args], { stdout: 'pipe', stderr: 'pipe', env: binEnv() });
  return { code: proc.exitCode ?? -1, json: JSON.parse(proc.stdout.toString()) };
}

const knownName = (): string => `[127.0.0.1]:${port}`;

beforeAll(() => {
  scratch = mkdtempSync('/tmp/a07r-t-');
  for (const dir of ['home', 'state', 'tunnels', 'run']) {
    mkdirSync(join(scratch, dir), { recursive: true, mode: 0o700 });
  }
  if (!LIVE) {
    return;
  }
  port = fixturePort();
  const ed = hostKeyLines().find(({ type }) => type === 'ssh-ed25519');
  writeFileSync(join(scratch, 'valid_known_hosts'), `${knownName()} ${ed?.type} ${ed?.key}\n`);
  writeFileSync(
    join(scratch, 'ssh_config'),
    [
      stanza('r07-all-types', join(scratch, 'all_known_hosts')),
      stanza('r07-valid', join(scratch, 'valid_known_hosts')),
      stanza('r07-trusted', join(scratch, 'valid_known_hosts')),
    ].join('\n'),
  );
  writeFileSync(
    join(scratch, 'targets.toml'),
    `[pg]\nalias = "r07-trusted"\ncontainer = "${PREFIX}-postgres"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
  );
});

afterAll(() => {
  if (scratch.length > 0) {
    if (LIVE) {
      Bun.spawnSync([BIN, 'hosts', 'disconnect', '--all'], { env: binEnv() });
    }
    rmSync(scratch, { recursive: true, force: true });
  }
});

describe.skipIf(!LIVE)('R07 hosts trust through the binary', () => {
  test('--all-types records every key type the host presents (CLI parses it as a boolean)', () => {
    const presented = hostKeyLines();
    const rsa = presented.find(({ type }) => type === 'ssh-rsa');
    const result = cli(
      'hosts',
      'trust',
      'r07-all-types',
      '--fingerprint',
      fingerprintOf(rsa?.key ?? ''),
      '--all-types',
      '--yes',
    );
    expect(result.json.ok).toBe(true);
    const recorded = readFileSync(join(scratch, 'all_known_hosts'), 'utf8')
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => line.split(/\s+/)[1])
      .sort();
    expect(recorded).toEqual(presented.map(({ type }) => type).sort());
  });

  test('a wrong fingerprint for a host whose presented key IS already trusted does not claim nothing was trusted', () => {
    const result = cli(
      'hosts',
      'trust',
      'r07-valid',
      '--fingerprint',
      `SHA256:${'x'.repeat(43)}`,
      '--yes',
    );
    expect(result.code).toBe(2);
    expect(result.json.error?.code).toBe('HOST_KEY_FINGERPRINT_MISMATCH');
    const text = `${result.json.error?.message ?? ''} ${result.json.error?.hint ?? ''}`;
    expect(/nothing was trusted|has no entry/i.test(text)).toBe(false);
  });
});

describe.skipIf(!LIVE)(
  'R07 psql backstop: an error that only names the SQL as written stays readable',
  () => {
    test('relation "<name>" does not exist keeps a relation name the SQL itself wrote', () => {
      const result = cli('db', 'query', 'pg', 'SELECT * FROM public.audit07r_no_such_relation');
      expect(result.json.error?.code).toBe('COMMAND_FAILED');
      expect(result.json.error?.data?.sql_error?.message ?? '').toContain(
        'audit07r_no_such_relation',
      );
    });

    test('operator does not exist keeps the operand types', () => {
      const result = cli('db', 'query', 'pg', "SELECT 1 WHERE 1 = 'a'::text");
      expect(result.json.error?.code).toBe('COMMAND_FAILED');
      expect(result.json.error?.data?.sql_error?.message ?? '').toContain('integer = text');
    });

    test('unrecognized configuration parameter keeps a parameter name the SQL itself wrote', () => {
      const result = cli('db', 'query', 'pg', "SELECT current_setting('audit07r.no_such_param')");
      expect(result.json.error?.code).toBe('COMMAND_FAILED');
      expect(result.json.error?.data?.sql_error?.message ?? '').toContain('audit07r.no_such_param');
    });

    test('green guard: a computed value echoed through a reg* cast is still masked', () => {
      const needle = new Bun.CryptoHasher('md5').update('a').digest('hex');
      const result = cli('db', 'query', 'pg', "SELECT md5('a')::regclass AS x");
      expect(result.json.error?.code).toBe('COMMAND_FAILED');
      expect(JSON.stringify(result.json).includes(needle)).toBe(false);
    });
  },
);

describe('R07 tunnel open: a refused forward is reported, not a tunnel', () => {
  async function refusedAfter(ms: number) {
    const dir = mkdtempSync('/tmp/a07r-fwd-');
    const stderrPath = join(dir, 'ssh.stderr');
    writeFileSync(
      stderrPath,
      'Authenticated to tunnel-host.example.net ([192.0.2.10]:22) using "publickey".\n',
    );
    const exited = new Promise<void>((resolve) =>
      setTimeout(() => {
        appendFileSync(stderrPath, 'Error: remote port forwarding failed for listen port 8080\n');
        resolve();
      }, ms),
    );
    try {
      return await awaitForward(stderrPath, exited, 5_000);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  test('green guard: a remote-forward refusal 300 ms after authentication is an error', async () => {
    expect(await refusedAfter(300)).not.toBeNull();
  });

  test('a remote-forward refusal 1.5 s after authentication (one round trip on a 1.2 s RTT link) is an error', async () => {
    expect(await refusedAfter(1_500)).not.toBeNull();
  });
});

describe('R07 scrubber residuals', () => {
  test('a secret query parameter inside a URL nested in another URL in an env assignment is masked', () => {
    const value = randomValue();
    const text = `CALLBACK=https://app.example.net/cb?redirect=https://login.example.net/?token=${value}`;
    expect(scrubText(text).value.includes(value)).toBe(false);
  });

  test('a secret four assignments deep is masked', () => {
    const value = randomValue();
    const text = `K8S_ARGS=--set=env=JAVA_OPTS=-Ddb.password=${value}`;
    expect(scrubText(text).value.includes(value)).toBe(false);
  });

  test.each([
    ['docker config.json', (b64: string) => `{"auths":{"registry.example.net":{"auth":"${b64}"}}}`],
    ['auth= line', (b64: string) => `auth=${b64}`],
  ])('%s: a base64 user:password under an auth key is not handed back decodable', (_name, wrap) => {
    const value = randomValue();
    const out = scrubText(wrap(Buffer.from(`deploy:${value}`).toString('base64'))).value;
    const decoded = (out.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [])
      .map((run) => Buffer.from(run, 'base64').toString('latin1'))
      .join('\n');
    expect(decoded.includes(value)).toBe(false);
  });
});

describe('R07 docs move with the code', () => {
  const skill = readFileSync(join(REPO, 'SKILL.md'), 'utf8');
  test.each([
    'HOST_KEY_FINGERPRINT_MISMATCH',
    'KNOWN_HOSTS_UNWRITABLE',
    '--all-types',
  ])('SKILL.md documents %s', (name) => {
    expect(skill.includes(name)).toBe(true);
  });
});

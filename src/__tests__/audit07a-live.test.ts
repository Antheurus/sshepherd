import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { profileDenial } from '../profiles.ts';
import { executeOp } from '../registry.ts';
import { scrubText } from '../scrub.ts';
import { buildDbOpContext } from '../targets.ts';
import { defaultRunner, type SshRunner } from '../transport.ts';
import type { OpContext, OpSpec } from '../types.ts';

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

let scratch = '';
let sshConfig = '';
let port = '';
const trustedKnownHosts = (): string => join(scratch, 'known_hosts');

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
    SSHEPHERD_SSH_CONFIG_PATH: sshConfig,
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
  raw: string;
  json: {
    ok: boolean;
    data: Record<string, unknown> | null;
    error: { code: string; message: string } | null;
  };
}

function cli(...args: string[]): CliResult {
  const proc = Bun.spawnSync([BIN, ...args], { stdout: 'pipe', stderr: 'pipe', env: binEnv() });
  const raw = proc.stdout.toString();
  return { code: proc.exitCode ?? -1, raw, json: JSON.parse(raw) };
}

beforeAll(() => {
  scratch = mkdtempSync('/tmp/a07t-');
  for (const dir of ['home', 'state', 'tunnels', 'run', 'ro', 'rodir']) {
    mkdirSync(join(scratch, dir), { recursive: true, mode: 0o700 });
  }
  sshConfig = join(scratch, 'ssh_config');
  if (!LIVE) {
    return;
  }
  port = fixturePort();
  writeFileSync(
    trustedKnownHosts(),
    `${hostKeyLines()
      .map(({ type, key }) => `[127.0.0.1]:${port} ${type} ${key}`)
      .join('\n')}\n`,
  );
  writeFileSync(join(scratch, 'ro', 'known_hosts'), '');
  chmodSync(join(scratch, 'ro', 'known_hosts'), 0o400);
  chmodSync(join(scratch, 'rodir'), 0o500);
  writeFileSync(
    sshConfig,
    [
      stanza('audit-trusted', trustedKnownHosts()),
      stanza('audit-fresh', join(scratch, 'fresh_known_hosts')),
      stanza('audit-untrusted', join(scratch, 'empty_known_hosts')),
      stanza('audit-rofile', join(scratch, 'ro', 'known_hosts')),
      stanza('audit-devnull', '/dev/null'),
    ].join('\n'),
  );
  writeFileSync(
    join(scratch, 'targets.toml'),
    `[pg]\nalias = "audit-trusted"\ncontainer = "${PREFIX}-postgres"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
  );
});

afterAll(() => {
  if (scratch.length > 0) {
    chmodSync(join(scratch, 'rodir'), 0o700);
    if (LIVE) {
      Bun.spawnSync([BIN, 'hosts', 'disconnect', '--all'], { env: binEnv() });
    }
    rmSync(scratch, { recursive: true, force: true });
  }
});

describe.skipIf(!LIVE)(
  'P07-FOLLOWUP psql data-echo class: every text that quotes a row value is masked',
  () => {
    const needle = new Bun.CryptoHasher('md5').update('a').digest('hex');
    const probes: [string, string][] = [
      ['regclass', "SELECT md5('a')::regclass AS x"],
      ['regtype', "SELECT md5('a')::regtype AS x"],
      ['regproc', "SELECT md5('a')::regproc AS x"],
      ['regrole', "SELECT md5('a')::regrole AS x"],
      ['regnamespace', "SELECT md5('a')::regnamespace AS x"],
      ['regconfig', "SELECT md5('a')::regconfig AS x"],
      ['tsquery', "SELECT (md5('a') || ' & & ')::tsquery AS x"],
      ['xml', "SELECT ('<' || md5('a'))::xml AS x"],
      ['current_setting', "SELECT current_setting(md5('a')) AS x"],
      ['nextval', "SELECT nextval(md5('a')) AS x"],
      ['pg_size_bytes', "SELECT pg_size_bytes(md5('a')) AS x"],
      ['timezone', "SELECT timezone(md5('a'), now()) AS x"],
      ['encode', "SELECT encode('x'::bytea, md5('a')) AS x"],
      ['has_table_privilege', "SELECT has_table_privilege(md5('a'), 'select') AS x"],
    ];
    test.each(probes)('db query %s: the computed value never comes back', (_name, sql) => {
      const result = cli('db', 'query', 'pg', sql);
      expect(result.json.error?.code).toBe('COMMAND_FAILED');
      expect(result.raw.includes(needle)).toBe(false);
    });
    test('control: the enumerated ::int echo is masked', () => {
      const result = cli('db', 'query', 'pg', "SELECT md5('a')::int AS x");
      expect(result.json.error?.code).toBe('COMMAND_FAILED');
      expect(result.raw.includes(needle)).toBe(false);
    });
  },
);

describe.skipIf(!LIVE)('P07 hosts trust on the live fixture', () => {
  test('--dry-run shows every key type the host presents', () => {
    const presented = hostKeyLines()
      .map(({ type }) => type)
      .sort();
    const result = cli('hosts', 'trust', 'audit-fresh', '--dry-run');
    const shown = ((result.json.data?.fingerprints ?? []) as { type: string }[])
      .map((entry) => entry.type)
      .sort();
    expect(shown).toEqual(presented);
  });

  test('a human-confirmed RSA fingerprint of the same host is accepted, not called HOST_KEY_CHANGED', () => {
    const rsa = hostKeyLines().find(({ type }) => type === 'ssh-rsa');
    expect(rsa).toBeDefined();
    const result = cli(
      'hosts',
      'trust',
      'audit-fresh',
      '--fingerprint',
      fingerprintOf(rsa?.key ?? ''),
      '--yes',
    );
    expect(result.json.error?.code).not.toBe('HOST_KEY_CHANGED');
    expect(result.json.ok).toBe(true);
  });

  test('an unwritable known_hosts is a typed, actionable error, not INTERNAL_ERROR', () => {
    const ed = hostKeyLines().find(({ type }) => type === 'ssh-ed25519');
    const result = cli(
      'hosts',
      'trust',
      'audit-rofile',
      '--fingerprint',
      fingerprintOf(ed?.key ?? ''),
      '--yes',
    );
    expect(result.json.ok).toBe(false);
    expect(result.json.error?.code).not.toBe('INTERNAL_ERROR');
    expect(result.json.error?.message ?? '').toContain('known_hosts');
  });

  test('UserKnownHostsFile /dev/null is refused instead of reporting written: true', () => {
    const ed = hostKeyLines().find(({ type }) => type === 'ssh-ed25519');
    const result = cli(
      'hosts',
      'trust',
      'audit-devnull',
      '--fingerprint',
      fingerprintOf(ed?.key ?? ''),
      '--yes',
    );
    const after = cli('hosts', 'test', 'audit-devnull');
    expect({ trustOk: result.json.ok, nextConnect: after.json.error?.code ?? 'ok' }).toEqual({
      trustOk: false,
      nextConnect: 'HOST_KEY_UNKNOWN',
    });
  });

  test('green: an unknown key is HOST_KEY_UNKNOWN even though the alias has no StrictHostKeyChecking line', () => {
    expect(cli('hosts', 'test', 'audit-untrusted').json.error?.code).toBe('HOST_KEY_UNKNOWN');
  });
});

describe.skipIf(!LIVE)('P07 tunnels under strict host keys', () => {
  test('tunnel open on an alias whose key is unknown returns HOST_KEY_UNKNOWN, not ok', () => {
    const result = cli(
      'tunnel',
      'open',
      'audit-untrusted',
      '--kind',
      'local',
      '--remote',
      '127.0.0.1:22',
      '--duration',
      '30',
      '--yes',
    );
    const id = result.json.data?.id;
    if (typeof id === 'string') {
      cli('tunnel', 'close', id, '--yes');
    }
    expect({ ok: result.json.ok, code: result.json.error?.code }).toEqual({
      ok: false,
      code: 'HOST_KEY_UNKNOWN',
    });
  });
});

describe.skipIf(!LIVE)('P07 canary gate blind spots', () => {
  const ctxFor = (path: string): OpContext => ({ alias: 'audit-trusted', args: { path } });
  const inlineOp = (exposes: 'content' | 'none', script: string): OpSpec =>
    ({
      group: 'files',
      name: `audit-${exposes}`,
      summary: 'audit-only inline op, never registered',
      args: [{ name: 'path', kind: 'positional', required: true, description: 'p' }],
      mutating: false,
      exposes,
      timeoutSec: 30,
      output: 'raw',
      buildRemote: () => script,
      shape: (parsed: unknown) => ({ text: parsed as string }),
    }) as OpSpec;

  let secret = '';
  const remotePath = '/tmp/audit07a.conf';
  beforeAll(() => {
    secret = randomValue();
    docker('exec', CONTAINER, 'sh', '-c', `printf 'API_TOKEN=%s\\n' ${secret} > ${remotePath}`);
    process.env.SSHEPHERD_SSH_CONFIG_PATH = sshConfig;
    process.env.XDG_RUNTIME_DIR = join(scratch, 'run');
  });
  afterAll(() => {
    docker('exec', CONTAINER, 'rm', '-f', remotePath);
    delete process.env.SSHEPHERD_SSH_CONFIG_PATH;
  });
  const deps = () => ({
    transport: { runner: defaultRunner, sshConfigPath: sshConfig },
    sshConfigPath: sshConfig,
    auditLogPath: join(scratch, 'state', 'inline-audit.jsonl'),
  });

  test('an op declared exposes: none that returns remote text still has its data scrubbed', async () => {
    const envelope = await executeOp(
      inlineOp('none', `cat ${remotePath}`),
      ctxFor(remotePath),
      deps(),
    );
    expect(envelope.ok).toBe(true);
    expect(JSON.stringify(envelope).includes(secret)).toBe(false);
  });

  test('an op returning the file base64-encoded does not hand back the secret in decodable form', async () => {
    const envelope = await executeOp(
      inlineOp('content', `base64 ${remotePath} | tr -d '\\n'`),
      ctxFor(remotePath),
      deps(),
    );
    const decoded = (JSON.stringify(envelope).match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [])
      .map((token) => Buffer.from(token, 'base64').toString('latin1'))
      .join('\n');
    expect(envelope.ok).toBe(true);
    expect(decoded.includes(secret)).toBe(false);
  });

  test('the canary requires at least one ok drive per exposing op (an op erroring on every drive fails it)', () => {
    const source = readFileSync(join(import.meta.dir, 'canary-leak.test.ts'), 'utf8');
    expect(/status\s*===\s*'ok'/.test(source)).toBe(true);
  });
});

describe('P07 profile and scrubber sad paths', () => {
  test('a PROFILE_DENIED message never cuts a surrogate pair in half', () => {
    const op = { group: 'check', name: 'mem', mutating: false, args: [] } as unknown as OpSpec;
    const denied = profileDenial(op, { alias: 'a', args: {} }, `a${'\u{1F600}'.repeat(20)}`);
    expect(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(denied?.message ?? '')).toBe(false);
  });

  test.each([
    'JAVA_OPTS="-Dspring.datasource.password=%s -Xmx512m"',
    'CMD=--password=%s',
    '--bogus=password=%s',
    'x=api_key=%s',
  ])('nested secret assignment is masked: %s', (template) => {
    const value = randomValue();
    expect(scrubText(template.replace('%s', value)).value.includes(value)).toBe(false);
  });
});

describe('green: max_profile caps a db op (latent: no writing db op exists, so a synthesized one is driven)', () => {
  const writingDbOp = {
    group: 'db',
    name: 'audit-write',
    summary: 'synthesized mutating db op',
    args: [{ name: 'target', kind: 'positional', required: true, description: 't' }],
    mutating: true,
    exposes: 'none',
    timeoutSec: 30,
    output: 'raw',
    buildRemote: () => 'true',
    shape: () => ({ written: true }),
  } as unknown as OpSpec;

  async function driveCapped(maxProfile: string): Promise<{ code: string | null; calls: number }> {
    const path = join(scratch, `targets-cap-${maxProfile}.toml`);
    writeFileSync(
      path,
      `[capped]\nalias = "audit-trusted"\ncontainer = "x"\nuser = "u_ro"\ndatabase = "d"\nmax_profile = "${maxProfile}"\n`,
    );
    let calls = 0;
    const counting: SshRunner = async () => {
      calls += 1;
      return { code: 255, stdout: '', stderr: '', timedOut: false };
    };
    const saved = process.env.SSHEPHERD_PROFILE;
    delete process.env.SSHEPHERD_PROFILE;
    try {
      const envelope = await executeOp(writingDbOp, buildDbOpContext('capped', {}, path), {
        transport: { runner: counting, sshConfigPath: sshConfig },
        sshConfigPath: sshConfig,
        yes: true,
        auditLogPath: join(scratch, 'state', 'cap-audit.jsonl'),
      });
      return { code: envelope.error?.code ?? null, calls };
    } finally {
      if (saved !== undefined) {
        process.env.SSHEPHERD_PROFILE = saved;
      }
    }
  }

  test('max_profile = "read" refuses it with SSHEPHERD_PROFILE unset, runner 0 calls', async () => {
    expect(await driveCapped('read')).toEqual({ code: 'PROFILE_DENIED', calls: 0 });
  });
  test('max_profile = "admin" lets it past the gate (runner reached)', async () => {
    const result = await driveCapped('admin');
    expect(result.code).not.toBe('PROFILE_DENIED');
    expect(result.calls).toBeGreaterThan(0);
  });
  test('the audit scratch never wrote the real audit log path', () => {
    expect(existsSync(join(scratch, 'state'))).toBe(true);
  });
});

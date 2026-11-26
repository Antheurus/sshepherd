import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  MAX_FILES_GREP_PATTERN_CHARS,
  MAX_FILES_LINE_SPAN,
  MAX_FIND_NAME_CHARS,
  MAX_FIND_RESULTS,
  MAX_GREP_MATCH_LINES,
  MAX_HEAD_LINES,
} from '../limits.ts';
import { assertPathAllowed } from '../ops/config.ts';
import { executeOp, getOp } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { OpContext, OpSpec } from '../types.ts';

const ALIAS = 'web-01';
let dir = '';
let allowlistPath = '';
const savedAllowlist = process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
const savedTargets = process.env.SSHEPHERD_TARGETS_PATH;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sshepherd-env-files-'));
  allowlistPath = join(dir, 'files-allowlist.toml');
  process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
  const targetsPath = join(dir, 'targets.toml');
  writeFileSync(
    targetsPath,
    `[app-db]\nalias = "${ALIAS}"\ncontainer = "app-db"\nuser = "ro"\ndatabase = "app"\ncontainers = ["app"]\n`,
  );
  process.env.SSHEPHERD_TARGETS_PATH = targetsPath;
});

afterAll(() => {
  for (const [key, value] of [
    ['SSHEPHERD_FILES_ALLOWLIST_PATH', savedAllowlist],
    ['SSHEPHERD_TARGETS_PATH', savedTargets],
  ] as const) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

function allow(...paths: string[]): void {
  writeFileSync(
    allowlistPath,
    `[${ALIAS}]\npaths = [${paths.map((path) => JSON.stringify(path)).join(', ')}]\n`,
  );
}

function op(group: string, name: string): OpSpec {
  const found = getOp(group, name);
  if (!found) {
    throw new Error(`${group} ${name} op missing`);
  }
  return found;
}

function remoteOf(group: string, name: string, args: Record<string, string>): string {
  const cmd = op(group, name).buildRemote({ alias: ALIAS, args });
  if (cmd === null) {
    throw new Error('expected a remote command');
  }
  return cmd;
}

/** Runs the remote command text through a real `sh -c`, as the host would, with `PATH` first
 *  holding `shimDir`. */
function runRemote(cmd: string, shimDir?: string): { code: number; stdout: string } {
  const proc = Bun.spawnSync(['sh', '-c', cmd], {
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env, PATH: `${shimDir ?? ''}:${process.env.PATH ?? ''}` },
  });
  return { code: proc.exitCode ?? -1, stdout: proc.stdout.toString() };
}

function spyRunner(stdout = ''): { runner: SshRunner; calls: string[][] } {
  const calls: string[][] = [];
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
    { code: 0, stdout: '', stderr: '', timedOut: false },
    { code: 0, stdout, stderr: '', timedOut: false },
  ];
  let index = 0;
  const runner: SshRunner = async (args) => {
    calls.push(args);
    const outcome = outcomes[Math.min(index, outcomes.length - 1)];
    index += 1;
    return outcome as SpawnOutcome;
  };
  return { runner, calls };
}

async function run(
  group: string,
  name: string,
  args: Record<string, string>,
  stdout = '',
): Promise<{ envelope: Awaited<ReturnType<typeof executeOp>>; ssh: number }> {
  const { runner, calls } = spyRunner(stdout);
  const ctx: OpContext = { alias: ALIAS, args };
  const envelope = await executeOp(op(group, name), ctx, {
    transport: { runner },
    auditLogPath: join(dir, 'audit.jsonl'),
  });
  return { envelope, ssh: calls.length };
}

/** A `docker` that prints a container env as `docker inspect --format` would. */
function dockerShim(envLines: string[]): string {
  const shimDir = mkdtempSync(join(dir, 'shim-'));
  const shim = join(shimDir, 'docker');
  writeFileSync(shim, `#!/bin/sh\ncat <<'EOF'\n${envLines.join('\n')}\nEOF\n`);
  chmodSync(shim, 0o755);
  return shimDir;
}

describe('env keys — the host reduces to key names, values never cross the wire', () => {
  test('a .env file: the remote command prints only key, state and bucket', () => {
    const file = join(dir, 'app.env');
    writeFileSync(
      file,
      [
        '# comment',
        'APP_NAME=demo',
        'export TOKEN="s3cr3t-token-value-0123456789abcdef0123456789"',
        "DB_URL='postgres://u:pw@db:5432/x'",
        'EMPTY=',
        'BLANKQUOTED=""',
        `LONG=${'x'.repeat(40)}`,
        'not a key line',
        '',
      ].join('\n'),
    );
    const { code, stdout } = runRemote(remoteOf('env', 'keys', { path: file }));
    expect(code).toBe(0);
    expect(stdout.split('\n').filter((line) => line.length > 0)).toEqual([
      'APP_NAME\tset\t1-8',
      'TOKEN\tset\t33+',
      'DB_URL\tset\t9-32',
      'EMPTY\tempty\t0',
      'BLANKQUOTED\tempty\t0',
      'LONG\tset\t33+',
    ]);
    expect(stdout).not.toContain('s3cr3t');
    expect(stdout).not.toContain('postgres');
  });

  test('a container: only names reach stdout even when a value spans lines', () => {
    const shimDir = dockerShim([
      '"API_TOKEN=canary-value-aaaaaaaaaaaaaaaaaaaa"',
      '"MULTI=first\\nSECOND=canary-injected"',
      '"PATH=/usr/bin"',
      '"EMPTY="',
    ]);
    const { code, stdout } = runRemote(remoteOf('env', 'keys', { container: 'app' }), shimDir);
    expect(code).toBe(0);
    expect(stdout).not.toContain('canary');
    expect(stdout.split('\n').filter((line) => line.length > 0)).toEqual([
      'API_TOKEN\tset\t33+',
      'MULTI\tset\t9-32',
      'PATH\tset\t1-8',
      'EMPTY\tempty\t0',
    ]);
  });

  test('a .env file: multi-line quoted values, KEY = value, export, CRLF, comments, empty and = in a value', () => {
    const file = join(dir, 'multi.env');
    writeFileSync(
      file,
      [
        '# comment line',
        '   # indented comment KEY_IN_COMMENT=x',
        'SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----',
        'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE',
        'CANARYml==',
        '-----END OPENSSH PRIVATE KEY-----"',
        "JSON_CFG='{",
        '  "inner": "INNERKEY=canary-json"',
        "}'",
        'B64="aGVsbG8K',
        'CANARYb64=="',
        'ESCAPED="a \\"quoted\\" word',
        'NOTAKEY=still-inside"',
        'SPACED = value',
        'export EXPORTED=1',
        'WIN=crlf\r',
        'EMPTY=',
        'EQUALS=a=b=c',
        'LAST=ok',
        '',
      ].join('\n'),
    );
    const { code, stdout } = runRemote(remoteOf('env', 'keys', { path: file }));
    expect(code).toBe(0);
    expect(stdout.split('\n').filter((line) => line.length > 0)).toEqual([
      'SSH_KEY\tset\t33+',
      'JSON_CFG\tset\t33+',
      'B64\tset\t9-32',
      'ESCAPED\tset\t33+',
      'SPACED\tset\t1-8',
      'EXPORTED\tset\t1-8',
      'WIN\tset\t1-8',
      'EMPTY\tempty\t0',
      'EQUALS\tset\t1-8',
      'LAST\tset\t1-8',
    ]);
    expect(stdout).not.toContain('CANARY');
    expect(stdout).not.toContain('INNERKEY');
    expect(stdout).not.toContain('NOTAKEY');
    expect(stdout).not.toContain('KEY_IN_COMMENT');
  });

  test('an unterminated quoted value is one key to the end of the file, its lines never keys', () => {
    const file = join(dir, 'open.env');
    writeFileSync(file, 'A=1\nOPEN="never closed\nLEAKED=text\n');
    const { stdout } = runRemote(remoteOf('env', 'keys', { path: file }));
    expect(stdout.split('\n').filter((line) => line.length > 0)).toEqual([
      'A\tset\t1-8',
      'OPEN\tset\t9-32',
    ]);
  });

  test('--container must be declared for the alias in targets.toml, before any ssh call', async () => {
    const { envelope, ssh } = await run('env', 'keys', { container: 'billing' });
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.message).toContain("container 'billing' is not declared for alias");
    expect(ssh).toBe(0);
  });

  test('a missing file answers __NOT_FOUND__ and the op refuses it', async () => {
    allow('/opt/app/.env');
    const { envelope } = await run('env', 'keys', { path: '/opt/app/.env' }, '__NOT_FOUND__\n');
    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
  });

  test('--path off the allowlist is refused before any ssh call', async () => {
    allow('/opt/app/.env');
    const { envelope, ssh } = await run('env', 'keys', { path: '/etc/shadow' });
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(ssh).toBe(0);
  });

  test('exactly one of --container and --path', async () => {
    allow('/opt/app/.env');
    const cases: Record<string, string>[] = [{}, { container: 'app', path: '/opt/app/.env' }];
    for (const args of cases) {
      const { envelope, ssh } = await run('env', 'keys', args);
      expect(envelope.error?.code).toBe('INVALID_ARGS');
      expect(ssh).toBe(0);
    }
  });

  test('a container name that could read as an option is refused', async () => {
    const { envelope, ssh } = await run('env', 'keys', { container: '-v' });
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(ssh).toBe(0);
  });

  test('the data is [{key, state, length_bucket}] and a stray line is dropped', async () => {
    const { envelope } = await run(
      'env',
      'keys',
      { container: 'app' },
      'A\tset\t1-8\nB\tempty\t0\nC=leaked-value\nD\tset\t99\n',
    );
    expect(envelope.data).toEqual([
      { key: 'A', state: 'set', length_bucket: '1-8' },
      { key: 'B', state: 'empty', length_bucket: '0' },
    ]);
  });
});

describe('env diff — key names against a local reference file', () => {
  test('missing, extra and empty, with no value in the envelope', async () => {
    allow('/opt/app/.env');
    const reference = join(dir, 'example.env');
    writeFileSync(reference, 'A=\nB=ref-value-should-not-appear\nC=\n# D=\n');
    const { envelope } = await run(
      'env',
      'diff',
      { path: '/opt/app/.env', against: reference },
      'A\tset\t1-8\nC\tempty\t0\nE\tset\t9-32\n',
    );
    expect(envelope.data).toEqual({ missing: ['B'], extra: ['E'], empty: ['C'] });
    expect(JSON.stringify(envelope)).not.toContain('ref-value');
  });

  test('an unreadable --against is refused before any ssh call', async () => {
    allow('/opt/app/.env');
    const { envelope, ssh } = await run('env', 'diff', {
      path: '/opt/app/.env',
      against: join(dir, 'nope.env'),
    });
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(ssh).toBe(0);
  });
});

describe('services inspect — env is key names only', () => {
  const DOCUMENT = JSON.stringify({
    Id: 'a'.repeat(64),
    Name: '/web',
    RestartCount: 0,
    State: { Status: 'running', Health: { Status: 'healthy' } },
    HostConfig: { Privileged: false },
    NetworkSettings: {
      Ports: { '80/tcp': [{ HostIp: '0.0.0.0', HostPort: '8080' }] },
      Networks: {
        web_default: { IPAddress: '172.18.0.4', MacAddress: '02:42:ac:12:00:04' },
        bridge: { IPAddress: '' },
      },
    },
    Config: { Image: 'nginx', Labels: null, Cmd: ['nginx', '-g', 'daemon off;'] },
    Mounts: [{ Type: 'bind', Source: '/srv/data', Destination: '/data', RW: false }],
  });

  test('the remote inspect names its fields and never asks for Config.Env values', () => {
    const cmd = remoteOf('services', 'inspect', { container: 'web' });
    expect(cmd).not.toContain('json .Config}}');
    expect(cmd).toContain('-- "$c"');
  });

  test('mounts, ports, health and env come back; env carries no value', async () => {
    const { envelope } = await run(
      'services',
      'inspect',
      { container: 'web' },
      `${DOCUMENT}\n__ENV__\nAPI_TOKEN\tset\t33+\nEMPTY\tempty\t0\n`,
    );
    const [detail] = envelope.data as Record<string, unknown>[];
    expect(detail?.mounts).toEqual([
      { type: 'bind', source: '/srv/data', destination: '/data', read_only: true },
    ]);
    expect(detail?.health).toBe('healthy');
    expect(detail?.env).toEqual([
      { key: 'API_TOKEN', state: 'set', length_bucket: '33+' },
      { key: 'EMPTY', state: 'empty', length_bucket: '0' },
    ]);
  });

  test('networks (name and address) and cmd come back; --fields networks,cmd keeps exactly those', async () => {
    const stdout = `${DOCUMENT}\n__ENV__\nA\tset\t1-8\n`;
    const { runner } = spyRunner(stdout);
    const envelope = await executeOp(
      op('services', 'inspect'),
      { alias: ALIAS, args: { container: 'web' } },
      {
        transport: { runner },
        fields: [['networks'], ['cmd']],
        auditLogPath: join(dir, 'audit.jsonl'),
      },
    );
    const [detail] = envelope.data as Record<string, unknown>[];
    expect(Object.keys(detail ?? {}).sort()).toEqual(['cmd', 'networks']);
    expect(detail?.cmd).toEqual(['nginx', '-g', 'daemon off;']);
    const networks = detail?.networks as { name: string; ip_address: string | null }[];
    expect(networks.map((network) => network.name)).toEqual(['bridge', 'web_default']);
    expect(networks[0]?.ip_address).toBeNull();
    expect(JSON.stringify(envelope)).not.toContain('172.18.0.4');
    expect(JSON.stringify(envelope)).not.toContain('02:42:ac');
  });

  test('--fields mounts,ports,health,env keeps exactly those', async () => {
    const { runner } = spyRunner(`${DOCUMENT}\n__ENV__\nA\tset\t1-8\n`);
    const envelope = await executeOp(
      op('services', 'inspect'),
      { alias: ALIAS, args: { container: 'web' } },
      {
        transport: { runner },
        fields: [['mounts'], ['ports'], ['health'], ['env']],
      },
    );
    expect(Object.keys((envelope.data as Record<string, unknown>[])[0] ?? {}).sort()).toEqual([
      'env',
      'health',
      'mounts',
      'ports',
    ]);
  });
});

describe('allowlist roots (within)', () => {
  const ctx: OpContext = { alias: ALIAS, args: {} };
  test('an entry, a path under it, and nothing else', () => {
    allow('/opt/myapp', '/');
    expect(() => assertPathAllowed('files', ctx, '/opt/myapp', true)).not.toThrow();
    expect(() => assertPathAllowed('files', ctx, '/opt/myapp/', true)).not.toThrow();
    expect(() => assertPathAllowed('files', ctx, '/opt/myapp/logs/a.log', true)).not.toThrow();
    for (const path of [
      '/',
      '/opt',
      '/opt/myapp2',
      '/opt/myapp/../etc',
      '/opt/myapp/..',
      '/etc',
      'opt/myapp',
    ]) {
      expect(() => assertPathAllowed('files', ctx, path, true)).toThrow();
    }
  });

  test('without within, a path under an entry is still refused', () => {
    allow('/opt/myapp');
    expect(() => assertPathAllowed('files', ctx, '/opt/myapp/x', false)).toThrow();
  });
});

describe('files grep / find — roots, patterns, and the shell', () => {
  test('find on /, a root off the allowlist, .. traversal: refused before any ssh call', async () => {
    allow('/opt/myapp');
    for (const path of ['/', '/etc', '/opt/myapp/../../etc', '/opt/myapp/..', '/opt/myapp2']) {
      for (const [name, args] of [
        ['find', { path, name: 'passwd' }],
        ['grep', { path, pattern: 'root' }],
      ] as const) {
        const { envelope, ssh } = await run('files', name, args);
        expect({ path, name, code: envelope.error?.code, ssh }).toEqual({
          path,
          name,
          code: 'VALIDATION_ERROR',
          ssh: 0,
        });
      }
    }
  });

  test('a symlink out of an allowed root is refused by the host-side realpath check', async () => {
    allow('/opt/myapp');
    const { envelope } = await run('files', 'find', { path: '/opt/myapp/escape' }, '__ESCAPE__\n');
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.data).toBeNull();
  });

  test('the same check on a real tree: a root, its symlink out, and a file inside', () => {
    const root = join(dir, 'tree');
    const outside = join(dir, 'outside');
    mkdirSync(root, { recursive: true });
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(root, 'app.log'), 'ERROR boom\nINFO fine\n');
    writeFileSync(join(outside, 'secret.log'), 'ERROR outside\n');
    symlinkSync(outside, join(root, 'escape'));
    symlinkSync(join(outside, 'secret.log'), join(root, 'link.log'));
    allow(root);

    const found = runRemote(remoteOf('files', 'find', { path: root, name: '*.log' }));
    expect(found.stdout.split('\n').filter((l) => l.length > 0)).toEqual(
      expect.arrayContaining([join(realpathSync(root), 'app.log')]),
    );
    const viaLink = runRemote(remoteOf('files', 'find', { path: join(root, 'escape') }));
    expect(viaLink.stdout.trim()).toBe('__ESCAPE__');

    const grep = runRemote(remoteOf('files', 'grep', { path: root, pattern: 'ERROR' }));
    expect(grep.stdout).toContain(`app.log\u00001:ERROR boom\n\u0000\u0000`);
    expect(grep.stdout).not.toContain('outside');
  });

  test('a private-key-shaped file is never searched', () => {
    const root = join(dir, 'keys');
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'server.pem'), 'KEYBODYLINE\n');
    writeFileSync(join(root, 'id_rsa'), 'KEYBODYLINE\n');
    writeFileSync(join(root, 'notes.txt'), 'KEYBODYLINE in notes\n');
    allow(root);
    const out = runRemote(remoteOf('files', 'grep', { path: root, pattern: 'KEYBODYLINE' })).stdout;
    expect(out).toContain('notes.txt');
    expect(out).not.toContain('server.pem');
    expect(out).not.toContain('id_rsa');
  });

  const HOSTILE = [
    "'",
    "x'; touch MARKER; echo '",
    '; touch MARKER',
    '$(touch MARKER)',
    '`touch MARKER`',
    '"; touch MARKER; "',
    '-e evil',
    '--version',
  ];

  test('pattern and --name travel as one quoted argv slot: nothing executes', () => {
    const root = join(dir, 'quoting');
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'a.txt'), 'plain\n');
    allow(root);
    for (const [index, hostile] of HOSTILE.entries()) {
      const marker = join(dir, `marker-${index}`);
      const text = hostile.replaceAll('MARKER', marker);
      runRemote(remoteOf('files', 'grep', { path: root, pattern: text }));
      runRemote(remoteOf('files', 'find', { path: root, name: text }));
      expect({ hostile, ran: existsSync(marker) }).toEqual({ hostile, ran: false });
    }
  });

  test('NUL, newline and an over-length pattern or name are refused before ssh', async () => {
    allow('/opt/myapp');
    const bad = ['a\nb', 'a\0b', 'a\rb', 'x'.repeat(MAX_FILES_GREP_PATTERN_CHARS + 1)];
    for (const pattern of bad) {
      const { envelope, ssh } = await run('files', 'grep', { path: '/opt/myapp', pattern });
      expect({ code: envelope.error?.code, ssh }).toEqual({ code: 'INVALID_ARGS', ssh: 0 });
    }
    for (const name of ['a\nb', 'a\0b', 'x'.repeat(MAX_FIND_NAME_CHARS + 1)]) {
      const { envelope, ssh } = await run('files', 'find', { path: '/opt/myapp', name });
      expect({ code: envelope.error?.code, ssh }).toEqual({ code: 'INVALID_ARGS', ssh: 0 });
    }
    const atLimit = await run('files', 'grep', {
      path: '/opt/myapp',
      pattern: 'x'.repeat(MAX_FILES_GREP_PATTERN_CHARS),
    });
    expect(atLimit.ssh).toBeGreaterThan(0);
  });

  test('--context outside 0..5 is refused', async () => {
    allow('/opt/myapp');
    for (const context of ['-1', '6', 'x', '1.5']) {
      const { envelope } = await run('files', 'grep', {
        path: '/opt/myapp',
        pattern: 'a',
        context,
      });
      expect(envelope.error?.code).toBe('INVALID_ARGS');
    }
  });

  /** One file's block as the per-file grep script prints it: `path NUL lines NUL whole NUL`. */
  const grepBlock = (path: string, lines: string[], whole = ''): string =>
    `${path}\u0000${lines.join('\n')}\n\u0000${whole === '' ? '' : Buffer.from(whole).toString('base64')}\u0000`;

  test('grep lines from an env file are masked, a log line is not, and the cap says truncated', async () => {
    allow('/opt/myapp');
    const envText = 'APP=x\nDB_PASSWORD=fake-secret-value-3\nAPP_NAME=smoke\n';
    const { envelope } = await run(
      'files',
      'grep',
      { path: '/opt/myapp', pattern: '.' },
      grepBlock(
        '/opt/myapp/.env',
        ['2:DB_PASSWORD=fake-secret-value-3', '3-APP_NAME=smoke'],
        envText,
      ) + grepBlock('/opt/myapp/app.log', ['2:2026-11-27 ERROR upstream refused']),
    );
    const data = envelope.data as { lines: string[]; truncated: boolean };
    expect(data.lines[0]).toBe('/opt/myapp/.env:2:DB_PASSWORD=***MASKED***');
    expect(data.lines[1]).toBe('/opt/myapp/.env-3-APP_NAME=***MASKED***');
    expect(data.lines[2]).toBe('/opt/myapp/app.log:2:2026-11-27 ERROR upstream refused');
    expect(JSON.stringify(envelope)).not.toContain('fake-secret-value');
    expect(envelope.scrubbed).toBeGreaterThanOrEqual(2);

    const many = Array.from({ length: MAX_GREP_MATCH_LINES + 1 }, (_, i) => `${i}:x`);
    const capped = await run(
      'files',
      'grep',
      { path: '/opt/myapp', pattern: 'x' },
      grepBlock('/opt/myapp/a.log', many),
    );
    const cappedData = capped.envelope.data as { lines: string[]; truncated: boolean };
    expect(cappedData.lines.length).toBe(MAX_GREP_MATCH_LINES);
    expect(cappedData.truncated).toBe(true);
  });

  test('a dated directory keeps its env file masked: the path comes from its own slot, not a split', async () => {
    allow('/opt/x');
    const envText = 'NOTE=fake-secret-dated\n';
    const { envelope } = await run(
      'files',
      'grep',
      { path: '/opt/x', pattern: 'NOTE' },
      grepBlock('/opt/x/rel-2026-11/.env', ['1:NOTE=fake-secret-dated'], envText),
    );
    expect((envelope.data as { lines: string[] }).lines).toEqual([
      '/opt/x/rel-2026-11/.env:1:NOTE=***MASKED***',
    ]);
  });

  test('PEM bodies are masked in any file, and a line inside a multi-line env value is masked whole', async () => {
    allow('/opt/x');
    const pem = [
      '1:tls key backup',
      '2:-----BEGIN RSA PRIVATE KEY-----',
      '3:MIIEowFAKEBODYLINE',
      '4:-----END RSA PRIVATE KEY-----',
    ];
    const envText =
      'A=1\nKEY="-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\nFAKEINNERml==\n-----END OPENSSH PRIVATE KEY-----"\nZ=2\n';
    const { envelope } = await run(
      'files',
      'grep',
      { path: '/opt/x', pattern: '.' },
      grepBlock('/opt/x/sub/backup.txt', pem) +
        grepBlock('/opt/x/app.env', ['4:FAKEINNERml==', '6:Z=2'], envText) +
        grepBlock('/opt/x/cut.env', ['9:FAKEPASTCUT=1'], 'A=1\n'),
    );
    const lines = (envelope.data as { lines: string[] }).lines;
    // Line 4 (the END marker) is left to the envelope scrubber, which rewrites it on its own.
    expect([...lines.slice(0, 3), ...lines.slice(4)]).toEqual([
      '/opt/x/sub/backup.txt:1:tls key backup',
      '/opt/x/sub/backup.txt:2:-----BEGIN RSA PRIVATE KEY-----',
      '/opt/x/sub/backup.txt:3:***',
      '/opt/x/app.env:4:***',
      '/opt/x/app.env:6:Z=***MASKED***',
      '/opt/x/cut.env:9:***',
    ]);
    expect(JSON.stringify(envelope)).not.toContain('FAKE');
  });

  test('the per-file script on a real tree: env-shaped files carry themselves whole, others do not', () => {
    const root = join(dir, 'grep-real');
    mkdirSync(join(root, 'rel-2026-11'), { recursive: true });
    writeFileSync(join(root, 'rel-2026-11', '.env'), 'NOTE=fake-dated\n');
    writeFileSync(join(root, 'notes.txt'), 'NOTE in notes\n');
    allow(root);
    const out = runRemote(remoteOf('files', 'grep', { path: root, pattern: 'NOTE' })).stdout;
    const parts = out.split('\u0000');
    const real = realpathSync(root);
    const envIndex = parts.indexOf(join(real, 'rel-2026-11', '.env'));
    const txtIndex = parts.indexOf(join(real, 'notes.txt'));
    expect(parts[envIndex + 1]).toBe('1:NOTE=fake-dated\n');
    expect(Buffer.from(parts[envIndex + 2] ?? '', 'base64').toString()).toBe('NOTE=fake-dated\n');
    expect(parts[txtIndex + 2]).toBe('');
  });

  test('find caps at MAX_FIND_RESULTS and says truncated', async () => {
    allow('/opt/myapp');
    const many = Array.from({ length: MAX_FIND_RESULTS + 1 }, (_, i) => `/opt/myapp/f${i}`);
    const { envelope } = await run('files', 'find', { path: '/opt/myapp' }, many.join('\n'));
    const data = envelope.data as { paths: string[]; truncated: boolean };
    expect(data.paths.length).toBe(MAX_FIND_RESULTS);
    expect(data.truncated).toBe(true);
  });
});

describe('files head', () => {
  test('--n is a whole number in 1..MAX_HEAD_LINES; default 100; the remote reads with --', async () => {
    allow('/opt/app/.env');
    expect(remoteOf('files', 'head', { path: '/opt/app/.env' })).toContain(
      "'head' '-n' '100' '--'",
    );
    for (const n of ['0', '-1', 'x', '1.5', String(MAX_HEAD_LINES + 1)]) {
      const { envelope, ssh } = await run('files', 'head', { path: '/opt/app/.env', n });
      expect({ n, code: envelope.error?.code, ssh }).toEqual({ n, code: 'INVALID_ARGS', ssh: 0 });
    }
  });

  test('the path is allowlist-gated and env-shaped files are masked', async () => {
    allow('/opt/app/.env');
    const refused = await run('files', 'head', { path: '/etc/passwd' });
    expect(refused.envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(refused.ssh).toBe(0);
    const { envelope } = await run(
      'files',
      'head',
      { path: '/opt/app/.env', n: '2' },
      'A=1\nPASSWORD=hunter2hunter2\n',
    );
    expect(envelope.data).toEqual({
      lines: ['A=***MASKED***', 'PASSWORD=***MASKED***'],
      lines_returned: 2,
    });
  });
});

describe('files head | tail | cat --lines A:B', () => {
  test('A:B is validated, at most MAX_FILES_LINE_SPAN lines, and never beside --n', async () => {
    allow('/opt/app/app.log');
    for (const name of ['head', 'tail', 'cat']) {
      for (const lines of ['0:5', '5:4', 'x:9', '1', `1:${MAX_FILES_LINE_SPAN + 1}`]) {
        const { envelope, ssh } = await run('files', name, { path: '/opt/app/app.log', lines });
        expect({ name, lines, code: envelope.error?.code, ssh }).toEqual({
          name,
          lines,
          code: 'INVALID_ARGS',
          ssh: 0,
        });
      }
    }
    const both = await run('files', 'head', { path: '/opt/app/app.log', lines: '1:2', n: '2' });
    expect(both.envelope.error?.code).toBe('INVALID_ARGS');
  });

  test('a plain file reads only lines A to B on the host; an env-shaped one from line 1, cut after masking', async () => {
    allow('/opt/app/app.log', '/opt/app/.env');
    expect(remoteOf('files', 'head', { path: '/opt/app/app.log', lines: '3:4' })).toBe(
      "'sed' '-n' '3,4p;4q' '--' '/opt/app/app.log'",
    );
    expect(remoteOf('files', 'tail', { path: '/opt/app/.env', lines: '3:4' })).toBe(
      "'head' '-n' '4' '--' '/opt/app/.env'",
    );
    const plain = await run(
      'files',
      'head',
      { path: '/opt/app/app.log', lines: '3:4' },
      'three\nfour\n',
    );
    expect(plain.envelope.data).toEqual({ lines: ['three', 'four'], lines_returned: 2 });
    const env = await run(
      'files',
      'tail',
      { path: '/opt/app/.env', lines: '3:4' },
      'A=1\nKEY="-----BEGIN\nFAKEBODYml==\nB=2\n',
    );
    expect(env.envelope.data).toEqual({ lines: ['***', '***'], lines_returned: 2 });
    expect(JSON.stringify(env.envelope)).not.toContain('FAKEBODY');
  });

  test('cat --lines cuts the size-guarded file; an env file is masked line for line first', async () => {
    allow('/opt/app/.env', '/opt/app/app.log');
    const env = await run(
      'files',
      'cat',
      { path: '/opt/app/.env', lines: '2:3' },
      'A=1\nB=fake-two\nC=3\nD=4\n',
    );
    expect((env.envelope.data as { content: string }).content).toBe(
      'B=***MASKED***\nC=***MASKED***',
    );
    const plain = await run(
      'files',
      'cat',
      { path: '/opt/app/app.log', lines: '2:2' },
      'one\ntwo\nthree\n',
    );
    expect((plain.envelope.data as { content: string }).content).toBe('two');
  });
});

describe('files download — the size header is strict', () => {
  async function download(stdout: string, localName: string) {
    allow('/opt/app/data.txt');
    const localPath = join(dir, localName);
    const { envelope } = await run(
      'files',
      'download',
      { path: '/opt/app/data.txt', local_path: localPath },
      stdout,
    );
    return { envelope, localPath };
  }
  const five = Buffer.from('hello').toString('base64');

  test('a padded header is refused and nothing is written', async () => {
    const { envelope, localPath } = await download(`__OK__:    5\n${five}`, 'padded.txt');
    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('PARSE_ERROR');
    expect(existsSync(localPath)).toBe(false);
  });

  test('every non-canonical header is refused: sign, leading zero, trailing text, CR, bare', async () => {
    for (const [index, header] of [
      '__OK__:+5',
      '__OK__:05',
      '__OK__:5 ',
      '__OK__:5\r',
      '__OK__:',
      '__OK__',
      'OK:5',
      ' __OK__:5',
    ].entries()) {
      const { envelope, localPath } = await download(`${header}\n${five}`, `bad-${index}.txt`);
      expect({ header, ok: envelope.ok, written: existsSync(localPath) }).toEqual({
        header,
        ok: false,
        written: false,
      });
    }
  });

  test('a canonical header still writes the file', async () => {
    const { envelope, localPath } = await download(`__OK__:5\n${five}`, 'good.txt');
    expect(envelope.ok).toBe(true);
    expect(readFileSync(localPath, 'utf8')).toBe('hello');
  });

  test('a size mismatch names the host figure and the received figure the right way round', async () => {
    const { envelope, localPath } = await download(`__OK__:12\n${five}`, 'short.txt');
    expect(envelope.error?.code).toBe('OUTPUT_TOO_LARGE');
    expect(envelope.error?.message).toContain('the host reported 12 bytes');
    expect(envelope.error?.message).toContain('but 5 arrived');
    expect(existsSync(localPath)).toBe(false);
  });

  test('zero-byte files are still canonical', async () => {
    const { envelope, localPath } = await download('__OK__:0\n', 'empty.txt');
    expect(envelope.ok).toBe(true);
    expect(readFileSync(localPath, 'utf8')).toBe('');
  });
});

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TUNNEL_SERVER_ALIVE_COUNT_MAX, TUNNEL_SERVER_ALIVE_INTERVAL_SEC } from '../limits.ts';
import { executeOp, getOp } from '../registry.ts';
import { scrubText } from '../scrub.ts';
import { scaffold as scaffoldConfigAllowlist } from '../setup-config-allowlist.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';

// Phase 07 fix 3: the gaps found beside the re-audit receipt — env blocks in every recipe-step
// output, setup's run-and-warn audit, a percent-encoded nested URL, a frozen tunnel host, and the
// tunnel's stderr file that DEBUG1 grew per forwarded connection.

const REPO = join(import.meta.dir, '..', '..');
const BIN = join(REPO, 'dist', 'sshepherd');
const PROJECT = process.env.SSHEPHERD_SMOKE_PROJECT ?? 'sshepherd-smoke';
const PREFIX = PROJECT === 'sshepherd-smoke' ? 'sshepherd-fixture' : `${PROJECT}-fixture`;
const STATE = process.env.SSHEPHERD_SMOKE_STATE_DIR ?? `/tmp/${PROJECT}`;
const VARIANT = 'alpine';
const CONTAINER = `${PREFIX}-sshd-${VARIANT}`;
const LIVE = existsSync(join(STATE, 'ssh_config'));

const SSH_G = 'hostname srv-01.example.net\nuser opsuser\nport 2222\n';
const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

let scratch = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-fix07d-'));
});
afterAll(() => {
  if (existsSync(join(scratch, 'locked'))) {
    chmodSync(join(scratch, 'locked'), 0o700);
  }
  rmSync(scratch, { recursive: true, force: true });
});

function opOf(group: string, name: string) {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return op;
}

function scripted(stdout: string): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok(SSH_G);
    }
    return ok(args.includes('-O') ? '' : stdout);
  };
}

describe('G-a — recipe steps of deploy migrate and deploy rollback get the env-block mask', () => {
  const canary = ['canary', 'f07d', 'spaced', '5521'].join('-');
  const stdout = [
    'running migrations',
    'APP_NAME=shop',
    `SPACED = ${canary}`,
    '# database',
    'export LOG_LEVEL=debug',
    'done',
  ].join('\n');

  for (const name of ['migrate', 'rollback']) {
    test(`deploy ${name}: SPACED = <canary> inside a 3-line env block -> 0 hits`, async () => {
      const recipe = join(scratch, `deploy.${name}.toml`);
      writeFileSync(
        recipe,
        [
          'name = "demo"',
          'alias = "edge-box"',
          'workdir = "/srv/shop"',
          '[[step]]',
          'name = "migrate"',
          'kind = "migrate"',
          'run = "docker compose run --rm app php artisan migrate --force"',
          '[rollback]',
          'strategy = "previous-tag"',
          'tag = "v1.2.2"',
          '',
        ].join('\n'),
      );
      process.env.SSHEPHERD_RECIPE_PATH = recipe;
      try {
        const env = await executeOp(
          opOf('deploy', name),
          { alias: 'edge-box', args: { recipe: 'demo' } },
          {
            transport: { runner: scripted(stdout) },
            yes: true,
            auditLogPath: join(scratch, `${name}-audit.jsonl`),
          },
        );
        expect({ ok: env.ok, hits: JSON.stringify(env).split(canary).length - 1 }).toEqual({
          ok: true,
          hits: 0,
        });
      } finally {
        delete process.env.SSHEPHERD_RECIPE_PATH;
      }
    });
  }
});

describe('G-b — an unwritable audit log warns a setup action instead of failing it', () => {
  const stateBefore = process.env.SSHEPHERD_STATE_DIR;
  const auditBefore = process.env.SSHEPHERD_AUDIT_PATH;
  let locked = '';
  beforeAll(() => {
    locked = join(scratch, 'locked');
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    process.env.SSHEPHERD_STATE_DIR = locked;
    delete process.env.SSHEPHERD_AUDIT_PATH;
  });
  afterAll(() => {
    process.env.SSHEPHERD_STATE_DIR = stateBefore;
    if (auditBefore !== undefined) {
      process.env.SSHEPHERD_AUDIT_PATH = auditBefore;
    }
  });

  test('config-allowlist scaffold still writes: ok, data kept, AUDIT_UNWRITABLE warning', () => {
    const path = join(scratch, 'config-allowlist.toml');
    const result = scaffoldConfigAllowlist(
      'edge-box',
      { paths: ['/etc/nginx/nginx.conf'], yes: true },
      path,
    );
    const warning = result.warnings?.[0];
    expect({
      ok: result.ok,
      error: result.error,
      data: result.data,
      written: readFileSync(path, 'utf8').includes('/etc/nginx/nginx.conf'),
      code: warning?.code,
      role: warning?.path_role,
      leaksPath: JSON.stringify(result).includes(scratch),
    }).toEqual({
      ok: true,
      error: null,
      data: { alias: 'edge-box', paths: ['/etc/nginx/nginx.conf'] },
      written: true,
      code: 'AUDIT_UNWRITABLE',
      role: 'audit_file',
      leaksPath: false,
    });
  });

  test('a refused scaffold (no --yes) keeps its own error and carries the warning', () => {
    const result = scaffoldConfigAllowlist(
      'edge-box',
      { paths: ['/etc/nginx/nginx.conf'], yes: false },
      join(scratch, 'refused.toml'),
    );
    expect({ code: result.error?.code, warning: result.warnings?.[0]?.code }).toEqual({
      code: 'CONFIRMATION_REQUIRED',
      warning: 'AUDIT_UNWRITABLE',
    });
  });

  test('a setup result with a writable audit log carries no warnings field', () => {
    process.env.SSHEPHERD_STATE_DIR = scratch;
    try {
      const result = scaffoldConfigAllowlist(
        'edge-box',
        { paths: ['/etc/nginx/nginx.conf'], yes: true },
        join(scratch, 'writable.toml'),
      );
      expect({ ok: result.ok, warnings: result.warnings }).toEqual({
        ok: true,
        warnings: undefined,
      });
    } finally {
      process.env.SSHEPHERD_STATE_DIR = locked;
    }
  });
});

describe('G-d — a secret inside a percent-encoded nested URL is masked', () => {
  const value = ['Zq8x', 'LmT4', 'vB9n', 'Rk2s'].join('');
  test('CALLBACK=...?redirect=https%3A%2F%2F...%3Ftoken%3D<v> -> value gone', () => {
    const text = `CALLBACK=https://a.example.net/cb?redirect=https%3A%2F%2Fb.example.net%2F%3Ftoken%3D${value}`;
    const out = scrubText(text).value;
    expect({
      leaked: out.includes(value),
      kept: out.includes('redirect=https%3A%2F%2Fb.example.net'),
    }).toEqual({
      leaked: false,
      kept: true,
    });
  });

  test('green guard: an encoded non-secret pair stays readable', () => {
    const text = 'next=https%3A%2F%2Fb.example.net%2F%3Fpage%3D2';
    expect(scrubText(text).value).toBe(text);
  });
});

describe('G-g — a cookie set by a server-config directive is masked, its name and attributes kept', () => {
  const value = ['Hq7w', 'Ty3k', 'Pz5m', 'Lc9v'].join('');
  test.each([
    [
      `add_header Set-Cookie "session=${value}; HttpOnly; Path=/";`,
      'add_header Set-Cookie "session=***; HttpOnly; Path=/";',
    ],
    [`add_header Set-Cookie sid=${value};`, 'add_header Set-Cookie sid=***;'],
    [
      `Header always set Set-Cookie 'sid=${value}; HttpOnly'`,
      "Header always set Set-Cookie 'sid=***; HttpOnly'",
    ],
  ])('%s', (text, masked) => {
    expect(scrubText(text).value).toBe(masked);
  });

  test('green guard: the header form keeps masking as before', () => {
    expect(scrubText(`Set-Cookie: session=${value}; HttpOnly`).value).toBe(
      'Set-Cookie: session=***; HttpOnly',
    );
  });
});

// ---------------------------------------------------------------------------------------------
// Live: a real tunnel through the fixture sshd.
// ---------------------------------------------------------------------------------------------

function docker(...args: string[]): string {
  const proc = Bun.spawnSync(['docker', ...args], { stdout: 'pipe', stderr: 'pipe' });
  if (proc.exitCode !== 0) {
    throw new Error(`docker ${args[0]} failed: ${proc.stderr.toString().slice(-300)}`);
  }
  return proc.stdout.toString();
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

let live = '';

function binEnv(): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: join(live, 'home'),
    SSHEPHERD_SSH_CONFIG_PATH: join(live, 'ssh_config'),
    SSHEPHERD_STATE_DIR: join(live, 'state'),
    SSHEPHERD_AUDIT_PATH: join(live, 'state', 'audit.jsonl'),
    SSHEPHERD_TUNNEL_STATE_DIR: join(live, 'tunnels'),
    XDG_RUNTIME_DIR: join(live, 'run'),
  };
}

interface CliJson {
  ok: boolean;
  data: { id?: string; localPort?: number; tunnels?: { id: string }[] } | null;
  error: { code: string } | null;
}

function cli(...args: string[]): CliJson {
  const proc = Bun.spawnSync([BIN, ...args], { stdout: 'pipe', stderr: 'pipe', env: binEnv() });
  return JSON.parse(proc.stdout.toString()) as CliJson;
}

function openLocalTunnel(): { id: string; localPort: number; pid: number } {
  const opened = cli(
    'tunnel',
    'open',
    'f07d-tunnel',
    '--kind',
    'local',
    '--remote',
    '127.0.0.1:22',
    '--duration',
    '300',
    '--yes',
  );
  const id = opened.data?.id ?? '';
  const record = JSON.parse(readFileSync(join(live, 'tunnels', `${id}.json`), 'utf8')) as {
    pid: number;
  };
  return { id, localPort: opened.data?.localPort ?? 0, pid: record.pid };
}

function listedIds(): string[] {
  return (cli('tunnel', 'list').data?.tunnels ?? []).map((tunnel) => tunnel.id);
}

/** Opens one connection through the forward and waits for the sshd banner it carries. */
async function oneConnection(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no banner within 5 s')), 5_000);
    Bun.connect({
      hostname: '127.0.0.1',
      port,
      socket: {
        data(socket) {
          clearTimeout(timer);
          socket.end();
          resolve();
        },
        error(_socket, err) {
          clearTimeout(timer);
          reject(err);
        },
      },
    }).catch(reject);
  });
}

/** Bytes the supervisor's fd 2 (the unlinked stderr file) holds, from `lsof +L1`. */
function stderrFileBytes(pid: number): number | null {
  const proc = Bun.spawnSync(['lsof', '-n', '-P', '+L1', '-a', '-d', '2', '-p', String(pid)], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const row = proc.stdout
    .toString()
    .split('\n')
    .slice(1)
    .map((line) => line.trim().split(/\s+/))
    .find((fields) => /^2[wu]$/.test(fields[3] ?? ''));
  return row === undefined ? null : Number(row[6]);
}

describe.skipIf(!LIVE)('live tunnel through the fixture sshd', () => {
  beforeAll(() => {
    live = mkdtempSync('/tmp/f07d-live-');
    for (const dir of ['home', 'state', 'tunnels', 'run']) {
      mkdirSync(join(live, dir), { recursive: true, mode: 0o700 });
    }
    const port = fixturePort();
    const knownName = `[127.0.0.1]:${port}`;
    const keys = docker('exec', CONTAINER, 'sh', '-c', 'cat /etc/ssh/ssh_host_*_key.pub')
      .split('\n')
      .map((line) => line.trim().split(/\s+/))
      .filter((fields) => fields.length >= 2)
      .map(([type, key]) => `${knownName} ${type} ${key}`);
    writeFileSync(join(live, 'known_hosts'), `${keys.join('\n')}\n`);
    writeFileSync(
      join(live, 'ssh_config'),
      [
        'Host f07d-tunnel',
        '  HostName 127.0.0.1',
        `  Port ${port}`,
        '  User root',
        `  IdentityFile ${join(STATE, 'keys', 'id_ed25519')}`,
        '  IdentitiesOnly yes',
        `  UserKnownHostsFile ${join(live, 'known_hosts')}`,
        '',
      ].join('\n'),
    );
  });
  afterAll(() => {
    for (const id of listedIds()) {
      cli('tunnel', 'close', id, '--yes');
    }
    rmSync(live, { recursive: true, force: true });
  });

  test('NEW-4: 200 connections through a -L tunnel leave fd 2 at most 4 KB', async () => {
    const tunnel = openLocalTunnel();
    try {
      for (let i = 0; i < 200; i += 1) {
        await oneConnection(tunnel.localPort);
      }
      await Bun.sleep(500);
      const bytes = stderrFileBytes(tunnel.pid);
      expect({ listed: bytes !== null, atMost4k: bytes !== null && bytes <= 4_096, bytes }).toEqual(
        {
          listed: true,
          atMost4k: true,
          bytes,
        },
      );
    } finally {
      cli('tunnel', 'close', tunnel.id, '--yes');
    }
  }, 60_000);

  const deadlineSec = TUNNEL_SERVER_ALIVE_INTERVAL_SEC * TUNNEL_SERVER_ALIVE_COUNT_MAX + 15;
  test(
    `G-e: a tunnel to a frozen host leaves tunnel list within interval x count + 15 s (${deadlineSec} s)`,
    async () => {
      const tunnel = openLocalTunnel();
      expect(listedIds()).toContain(tunnel.id);
      docker('pause', CONTAINER);
      const pausedAt = Date.now();
      let gone = false;
      try {
        while (Date.now() - pausedAt < deadlineSec * 1_000) {
          await Bun.sleep(1_000);
          if (!listedIds().includes(tunnel.id)) {
            gone = true;
            break;
          }
        }
      } finally {
        docker('unpause', CONTAINER);
        cli('tunnel', 'close', tunnel.id, '--yes');
      }
      expect({
        gone,
        withinSec: Math.round((Date.now() - pausedAt) / 1_000) <= deadlineSec,
      }).toEqual({
        gone: true,
        withinSec: true,
      });
    },
    (TUNNEL_SERVER_ALIVE_INTERVAL_SEC * TUNNEL_SERVER_ALIVE_COUNT_MAX + 60) * 1_000,
  );
});

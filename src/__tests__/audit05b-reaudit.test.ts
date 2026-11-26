import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import { scrub, scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

const ALIAS = 'leak-host';
const PW = 'plantedFakePw77';
const BODY_1 = 'MIIEowIBAAKCAQEAplantedFakeBodyLineOneAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const BODY_2 = 'plantedFakeBodyLineTwoBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const PEM_LINES = [
  '-----BEGIN RSA PRIVATE KEY-----',
  BODY_1,
  BODY_2,
  '-----END RSA PRIVATE KEY-----',
];

const ENV_KEYS = [
  'SSHEPHERD_FILES_ALLOWLIST_PATH',
  'SSHEPHERD_CONFIG_ALLOWLIST_PATH',
  'SSHEPHERD_REVEAL_ALLOWLIST_PATH',
  'SSHEPHERD_TARGETS_PATH',
] as const;
const saved: Record<string, string | undefined> = {};
let dir = '';

const PATHS = ['/opt/myapp/prod.env', '/home/deploy/.ssh/id_rsa', '/srv/app/docker-compose.yml'];

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit05b-'));
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
  }
  const allow = `[${ALIAS}]\npaths = [${PATHS.map((p) => `"${p}"`).join(', ')}]\n`;
  writeFileSync(join(dir, 'files-allowlist.toml'), allow);
  writeFileSync(join(dir, 'config-allowlist.toml'), allow);
  writeFileSync(join(dir, 'reveal-allowlist.toml'), `[${ALIAS}]\nkeys = ["NODE_ENV"]\n`);
  writeFileSync(join(dir, 'targets.toml'), '');
  process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(dir, 'files-allowlist.toml');
  process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = join(dir, 'config-allowlist.toml');
  process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = join(dir, 'reveal-allowlist.toml');
  process.env.SSHEPHERD_TARGETS_PATH = join(dir, 'targets.toml');
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = saved[key];
    }
  }
});

function runnerFor(last: SpawnOutcome): SshRunner {
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
    { code: 0, stdout: '', stderr: '', timedOut: false },
    last,
  ];
  let index = 0;
  return async () => {
    const outcome = outcomes[Math.min(index, outcomes.length - 1)] as SpawnOutcome;
    index += 1;
    return outcome;
  };
}

async function drive(
  group: string,
  name: string,
  args: Record<string, string>,
  last: SpawnOutcome,
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(op, { alias: ALIAS, args }, { transport: { runner: runnerFor(last) } });
}

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

function journal(lines: string[]): string {
  return lines
    .map((message, i) =>
      JSON.stringify({
        __REALTIME_TIMESTAMP: String(1764150000000000 + i),
        PRIORITY: '6',
        MESSAGE: message,
      }),
    )
    .join('\n');
}

describe('audit05b — guard rails the fix must keep', () => {
  test('G1 PEM whose END never arrives (truncated tail) stays masked in files tail', async () => {
    const env = await drive(
      'files',
      'tail',
      { path: '/home/deploy/.ssh/id_rsa' },
      ok(`${PEM_LINES.slice(0, 3).join('\n')}\n`),
    );
    const json = JSON.stringify(env);
    expect(json).not.toContain(BODY_1);
    expect(json).not.toContain(BODY_2);
  });

  test('G2 run-start anchoring: a secret name inside a longer run is still masked', () => {
    for (const text of [
      `xDB_PASSWORD=${PW}`,
      `my-api-key=${PW}`,
      `foo.password=${PW}`,
      `--db-password ${PW}`,
    ]) {
      expect({ text, leaked: scrubText(text).value.includes(PW) }).toEqual({ text, leaked: false });
    }
  });

  test('G3 secret-named *_KEY names in env, YAML, JSON and camelCase stay masked', () => {
    for (const text of [
      `STRIPE_KEY=${PW}`,
      `SIGNING_KEY=${PW}`,
      `ENCRYPTION_KEY=${PW}`,
      `JWT_KEY=${PW}`,
      `MASTER_KEY=${PW}`,
      `AWS_ACCESS_KEY=${PW}`,
      `OPENAI_API_KEY=${PW}`,
      `GPG_PRIVATE_KEY=${PW}`,
      `signing_key: ${PW}`,
      `{"encryption_key": "${PW}"}`,
      `masterKey: ${PW}`,
    ]) {
      expect({ text, leaked: scrubText(text).value.includes(PW) }).toEqual({ text, leaked: false });
    }
  });
});

describe('audit05b — leak checks (each red test is a receipt finding)', () => {
  test('R1 files download timeout: partial_stdout carries the file as base64 (decodes to the secret)', async () => {
    for (const [path, content] of [
      ['/opt/myapp/prod.env', `DB_PASSWORD=${PW}\n`],
      ['/opt/myapp/prod.env', `DB_PASSWORD=${PW}xy\n`],
      ['/srv/app/docker-compose.yml', `DB_PASSWORD: ${PW}\n`],
    ] as const) {
      const b64 = Buffer.from(content).toString('base64');
      const env = await drive(
        'files',
        'download',
        { path, local_path: join(dir, 'never.out') },
        { code: 124, stdout: `__OK__:${content.length}\n${b64}`, stderr: '', timedOut: false },
      );
      expect(env.error?.code).toBe('COMMAND_TIMEOUT');
      const partial = String(
        (env.data as { partial_stdout?: string } | null)?.partial_stdout ?? '',
      );
      const body = partial.slice(partial.indexOf('\n') + 1).replace(/=?\*\*\*MASKED\*\*\*$/, '');
      const decoded = Buffer.from(body, 'base64').toString('latin1');
      expect({ path, content, leaked: decoded.includes(PW) }).toEqual({
        path,
        content,
        leaked: false,
      });
    }
  });

  test('R2 logs service: a PEM printed by a unit is split per journald entry and its body survives', async () => {
    const env = await drive('logs', 'service', { unit: 'app' }, ok(`${journal(PEM_LINES)}\n`));
    const json = JSON.stringify(env);
    expect(json).not.toContain(BODY_1);
    expect(json).not.toContain(BODY_2);
  });

  test('R2b logs docker-daemon and logs nginx: same per-line PEM split', async () => {
    const daemon = await drive('logs', 'docker-daemon', {}, ok(`${journal(PEM_LINES)}\n`));
    const nginx = await drive(
      'logs',
      'nginx',
      { stream: 'error' },
      ok(`${PEM_LINES.join('\n')}\n`),
    );
    expect(JSON.stringify(daemon)).not.toContain(BODY_1);
    expect(JSON.stringify(nginx)).not.toContain(BODY_1);
  });

  test('R3 files tail / logs docker that start mid-key (BEGIN cut off by -n) return the body lines', async () => {
    const tail = await drive(
      'files',
      'tail',
      { path: '/home/deploy/.ssh/id_rsa' },
      ok(`${PEM_LINES.slice(1).join('\n')}\n`),
    );
    const docker = await drive(
      'logs',
      'docker',
      { container: 'app' },
      ok(
        `${PEM_LINES.slice(1)
          .map((line) => `2026-11-26T10:00:00.000000000Z ${line}`)
          .join('\n')}\n`,
      ),
    );
    expect(JSON.stringify(tail)).not.toContain(BODY_1);
    expect(JSON.stringify(docker)).not.toContain(BODY_1);
  });

  test('R4 F9 narrowing: a *_URL value whose credential the URL shape rule misses is now in clear', async () => {
    for (const text of [
      `DATABASE_URL=postgres://app:${PW}/x@db:5432/app`,
      `DATABASE_URL=postgres://app:${PW}#x@db:5432/app`,
      `DATABASE_URL=postgres://app:p@${PW}@db:5432/app`,
      `APP_URL=https://x.example/cb?token=${PW}`,
      `"callback_url": "https://x.example/cb?access_token=${PW}"`,
      `WEBHOOK_URL=https://discord.com/api/webhooks/123456/${PW}`,
    ]) {
      expect({ text, leaked: scrubText(text).value.includes(PW) }).toEqual({ text, leaked: false });
    }
    const compose = await drive(
      'files',
      'cat',
      { path: '/srv/app/docker-compose.yml' },
      ok(
        `services:\n  app:\n    environment:\n      DATABASE_URL: postgres://app:${PW}/x@db:5432/app\n`,
      ),
    );
    expect(JSON.stringify(compose)).not.toContain(PW);
  });

  test('R5 F9 narrowing: joined lower-case *key secret names are now in clear (monkey stays visible)', () => {
    for (const text of [
      `privkey=${PW}`,
      `ssl_privkey=${PW}`,
      `masterkey=${PW}`,
      `signingkey=${PW}`,
      `stripekey=${PW}`,
    ]) {
      expect({ text, leaked: scrubText(text).value.includes(PW) }).toEqual({ text, leaked: false });
    }
    expect(scrub({ privkey: PW }).value).toEqual({ privkey: '***' });
    expect(scrubText('monkey: george').value).toBe('monkey: george');
  });

  test('R6 PEM rules are quadratic in BEGIN-line count (F10 class, pre-existing): 188 KB under 500 ms', () => {
    const text = `${'-----BEGIN RSA PRIVATE KEY-----\n'.repeat(6000)}-----END EC PRIVATE KEY-----\n`;
    const started = performance.now();
    scrubText(text);
    expect(performance.now() - started).toBeLessThan(500);
  });

  test('R7 PHP / WordPress config forms leak (pre-existing, not from the fix)', () => {
    for (const text of [
      `$db_password = '${PW}';`,
      `define('DB_PASSWORD', '${PW}');`,
      `$cfg['Servers'][$i]['password'] = '${PW}';`,
    ]) {
      expect({ text, leaked: scrubText(text).value.includes(PW) }).toEqual({ text, leaked: false });
    }
  });
});

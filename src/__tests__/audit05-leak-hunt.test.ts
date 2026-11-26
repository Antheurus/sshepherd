import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import { scrub, scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

const ALIAS = 'leak-host';
const PW = 'plantedFakePw77';
const PEM_BODY_1 = 'MIIEowIBAAKCAQEAplantedFakeBodyLineOneAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PEM_BODY_2 = 'plantedFakeBodyLineTwoBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const PEM = [
  '-----BEGIN RSA PRIVATE KEY-----',
  PEM_BODY_1,
  PEM_BODY_2,
  '-----END RSA PRIVATE KEY-----',
].join('\n');

const ENV_KEYS = [
  'SSHEPHERD_FILES_ALLOWLIST_PATH',
  'SSHEPHERD_CONFIG_ALLOWLIST_PATH',
  'SSHEPHERD_REVEAL_ALLOWLIST_PATH',
  'SSHEPHERD_TARGETS_PATH',
] as const;
const saved: Record<string, string | undefined> = {};
let dir = '';

const PATHS = [
  '/opt/myapp/prod.env',
  '/home/deploy/.ssh/id_rsa',
  '/var/log/app/app.log',
  '/srv/certs/server.key',
];

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit05-'));
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
  }
  const allow = `[${ALIAS}]\npaths = [${PATHS.map((p) => `"${p}"`).join(', ')}]\n`;
  writeFileSync(join(dir, 'files-allowlist.toml'), allow);
  writeFileSync(join(dir, 'config-allowlist.toml'), allow);
  writeFileSync(join(dir, 'reveal-allowlist.toml'), `[${ALIAS}]\nkeys = ["NODE_ENV"]\n`);
  writeFileSync(
    join(dir, 'targets.toml'),
    `[appdb]\nalias = "${ALIAS}"\ncontainer = "app-db"\nuser = "app_ro"\ndatabase = "app"\n`,
  );
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

describe('audit05 — what the scrubber does catch (guard rails)', () => {
  test('files cat prod.env and export KEY=v', async () => {
    const env = await drive(
      'files',
      'cat',
      { path: '/opt/myapp/prod.env' },
      ok(`DB_PASSWORD=${PW}\nexport SESSION_SECRET=${PW}\nPORT=3000\n`),
    );
    expect(JSON.stringify(env)).not.toContain(PW);
  });

  test('services ps --password=x and DATABASE_URL in a command line', async () => {
    const text = `/usr/bin/app --password=${PW} DATABASE_URL=postgres://u:${PW}@db/app`;
    expect(scrubText(text).value).not.toContain(PW);
  });

  test('stderr_tail on a non-255 exit is scrubbed', async () => {
    const env = await drive(
      'check',
      'ports',
      {},
      { code: 1, stdout: '', stderr: `fatal: auth DB_PASSWORD=${PW} rejected`, timedOut: false },
    );
    expect(env.error?.stderr_tail).toBeDefined();
    expect(JSON.stringify(env)).not.toContain(PW);
  });
});

describe('audit05 — leak checks (each red test is a receipt finding)', () => {
  test('F1 files download: a .env with one NUL byte is written to disk unmasked', async () => {
    const local = join(dir, 'nul.env');
    const bytes = Buffer.concat([Buffer.from(`DB_PASSWORD=${PW}\n`), Buffer.from([0x00])]);
    await drive(
      'files',
      'download',
      { path: '/opt/myapp/prod.env', local_path: local },
      ok(`__OK__:${bytes.length}\n${bytes.toString('base64')}`),
    );
    expect(readFileSync(local).toString('latin1')).not.toContain(PW);
  });

  test('F1b files download: a latin-1 .env (one 0xE9 byte) is written to disk unmasked', async () => {
    const local = join(dir, 'latin1.env');
    const bytes = Buffer.concat([
      Buffer.from('APP_NAME=Caf'),
      Buffer.from([0xe9]),
      Buffer.from(`\nDB_PASSWORD=${PW}\n`),
    ]);
    await drive(
      'files',
      'download',
      { path: '/opt/myapp/prod.env', local_path: local },
      ok(`__OK__:${bytes.length}\n${bytes.toString('base64')}`),
    );
    expect(readFileSync(local).toString('latin1')).not.toContain(PW);
  });

  test('F2 files tail: PEM body lines survive because the array is scrubbed line by line', async () => {
    const env = await drive('files', 'tail', { path: '/var/log/app/app.log' }, ok(`${PEM}\n`));
    const json = JSON.stringify(env);
    expect(json).not.toContain(PEM_BODY_1);
    expect(json).not.toContain(PEM_BODY_2);
  });

  test('F2b files tail on an id_* / *.key path: PEM body lines survive', async () => {
    const a = await drive('files', 'tail', { path: '/home/deploy/.ssh/id_rsa' }, ok(`${PEM}\n`));
    const b = await drive('files', 'tail', { path: '/srv/certs/server.key' }, ok(`${PEM}\n`));
    expect(JSON.stringify(a)).not.toContain(PEM_BODY_1);
    expect(JSON.stringify(b)).not.toContain(PEM_BODY_1);
  });

  test('F2c logs docker: a PEM dumped into a container log survives line by line', async () => {
    const stdout = PEM.split('\n')
      .map((line) => `2026-11-26T10:00:00.000000000Z ${line}`)
      .join('\n');
    const env = await drive('logs', 'docker', { container: 'app' }, ok(`${stdout}\n`));
    expect(JSON.stringify(env)).not.toContain(PEM_BODY_1);
  });

  test('F3 files cat prod.env timeout: partial_stdout skips whole-file env masking', async () => {
    const env = await drive(
      'files',
      'cat',
      { path: '/opt/myapp/prod.env' },
      { code: 124, stdout: `MYSQL_PWD=${PW}\nSESSION_SALT=${PW}\n`, stderr: '', timedOut: false },
    );
    expect(env.error?.code).toBe('COMMAND_TIMEOUT');
    expect(JSON.stringify(env)).not.toContain(PW);
  });

  test('F4 db query: a value under a secret column survives when it is a number, array or object', async () => {
    const rows = [{ id: 1, password: 123456789, tokens: [PW], password_hash: { bcrypt: PW } }];
    const env = await drive(
      'db',
      'query',
      { target: 'appdb', sql: 'SELECT 1', container: 'app-db', db_user: 'app_ro', db_name: 'app' },
      ok(JSON.stringify(rows)),
    );
    expect(env.error).toBeNull();
    const json = JSON.stringify(env.data);
    expect(json).not.toContain('123456789');
    expect(json).not.toContain(PW);
  });

  test('F5 process command lines: --password <v>, -p<v>, MYSQL_PWD=<v>', () => {
    for (const text of [
      `/usr/bin/app --password ${PW} --port 80`,
      `mysql -uroot -p${PW} app`,
      `MYSQL_PWD=${PW}`,
    ]) {
      expect({ text, out: scrubText(text).value.includes(PW) }).toEqual({ text, out: false });
    }
  });

  test('F6 URL and token shapes named in the brief', () => {
    for (const text of [
      `REDIS=redis://:${PW}@cache:6379/0`,
      `url redis://:${PW}@cache:6379/0`,
      'github_' + 'pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV',
      'found rk_' + 'live_51Hplantedfakeabcdefghijkl in log',
      'posting to https://hooks.' + 'slack.com/services/T00000000/B00000000/plantedFakeHookSecret1',
    ]) {
      const out = scrubText(text).value;
      expect({ text, leaked: out === text }).toEqual({ text, leaked: false });
    }
  });

  test('F6b other common secret shapes', () => {
    for (const text of [
      `-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF${PW}\n-----END PGP PRIVATE KEY BLOCK-----`,
      `Cookie: session=${PW}`,
      `Set-Cookie: sessionid=${PW}; Path=/; HttpOnly`,
      `<password>${PW}</password>`,
      'glp' + 'at-plantedFake1234567890',
      'AI' + 'zaSyPlantedFake1234567890abcdefghijk',
      'wh' + 'sec_plantedFake1234567890abcdefghijkl',
    ]) {
      const out = scrubText(text).value;
      expect({ text, leaked: out === text || out.includes(PW) }).toEqual({ text, leaked: false });
    }
  });

  test('F8 a revealed key line skips the shape rules: --reveal DATABASE_URL shows the URL password', async () => {
    writeFileSync(
      join(dir, 'reveal-allowlist.toml'),
      `[${ALIAS}]\nkeys = ["NODE_ENV", "DATABASE_URL"]\n`,
    );
    try {
      const env = await drive(
        'files',
        'cat',
        { path: '/opt/myapp/prod.env', reveal: 'DATABASE_URL' },
        ok(`DATABASE_URL=postgres://app:${PW}@db:5432/app\n`),
      );
      expect(env.ok).toBe(true);
      expect(JSON.stringify(env)).not.toContain(PW);
    } finally {
      writeFileSync(join(dir, 'reveal-allowlist.toml'), `[${ALIAS}]\nkeys = ["NODE_ENV"]\n`);
    }
  });

  test('F9 over-masking: a url / key / *key value that is not a secret stays visible', () => {
    for (const text of [
      'url=https://example.com/page',
      'APP_URL=https://example.com',
      '{"homepage_url": "https://example.com"}',
      'monkey: george',
    ]) {
      expect(scrubText(text).value).toBe(text);
    }
    expect(scrub({ key: 'theme', value: 'dark' }).value).toEqual({ key: 'theme', value: 'dark' });
  });

  test('F10 scrubText is linear: a 48 KB hyphenated line scrubs in under 500 ms', () => {
    const line = Array.from({ length: 5_000 }, (_, i) => `node-${i}`).join('-');
    const started = performance.now();
    scrubText(line);
    expect(performance.now() - started).toBeLessThan(500);
  });

  test('F7 over-masking: prose with "Bearer token" stays untouched', () => {
    for (const text of ['Use a Bearer token for auth', 'missing Bearer token in request']) {
      expect(scrubText(text).value).toBe(text);
    }
  });
});

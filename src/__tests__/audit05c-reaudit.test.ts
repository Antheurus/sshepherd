import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CEILING_MAX_BYTES } from '../limits.ts';
import { executeOp, getOp } from '../registry.ts';
import { MASK, maskPemLines, scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

const ALIAS = 'leak-host';
const PW = 'plantedFakePw77';
const BODY_1 = 'MIIEowIBAAKCAQEAplantedFakeBodyLineOneAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const BODY_2 = 'plantedFakeBodyLineTwoBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const BEGIN = '-----BEGIN RSA PRIVATE KEY-----';
const END = '-----END RSA PRIVATE KEY-----';
const TS_PREFIX = `${'tsk'}${'ey-auth-'}`;

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
  dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit05c-'));
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
  maxBytes?: number,
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(
    op,
    { alias: ALIAS, args },
    { transport: { runner: runnerFor(last) }, ...(maxBytes === undefined ? {} : { maxBytes }) },
  );
}

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });
const stamp = (i: number): string =>
  `2026-11-26T10:${String(Math.floor(i / 60) % 60).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}.000000000Z`;
const dockerLines = (lines: string[]): string =>
  `${lines.map((line, i) => `${stamp(i)} ${line}`).join('\n')}\n`;
const texts = (env: Envelope<unknown>): string[] =>
  ((env.data as { lines?: { text: string }[] } | null)?.lines ?? []).map((line) => line.text);
const ordinary = (n: number): string[] =>
  Array.from({ length: n }, (_, i) => `GET /api/orders/${i} 200 ${i}ms`);

const leakOf = (text: string) => ({ text, leaked: scrubText(text).value.includes(PW) });

describe('audit05c — guard rails fix 2 must keep (green)', () => {
  test('E R1: a timed-out files download carries no content on any path, timeout or ssh failure', async () => {
    const cases: [string, string, SpawnOutcome['code'], boolean][] = [
      ['/opt/myapp/prod.env', `DB_PASSWORD=${PW}\n`, 124, false],
      ['/opt/myapp/prod.env', `DB_PASSWORD=${PW}xy\n`, 0, true],
      ['/srv/app/docker-compose.yml', `DB_PASSWORD: ${PW}\n`, 124, true],
      ['/home/deploy/.ssh/id_rsa', `${BEGIN}\n${BODY_1}\n${END}\n`, 124, false],
      ['/srv/app/docker-compose.yml', `DB_PASSWORD: ${PW}\n`, 255, false],
    ];
    for (const [path, content, code, timedOut] of cases) {
      const b64 = Buffer.from(content).toString('base64');
      const env = await drive(
        'files',
        'download',
        { path, local_path: join(dir, 'never.out') },
        { code, stdout: `__OK__:${content.length}\n${b64}`, stderr: 'Killed\n', timedOut },
      );
      const json = JSON.stringify(env);
      expect({ path, code, timedOut, error: env.error !== null }).toEqual({
        path,
        code,
        timedOut,
        error: true,
      });
      expect({ path, code, b64: json.includes(b64.slice(0, 16)), pw: json.includes(PW) }).toEqual({
        path,
        code,
        b64: false,
        pw: false,
      });
      expect(env.data).toEqual({ written: false, bytes_received: expect.any(Number) });
    }
  });

  test('D1 logs docker: interleaved stderr lines inside a PEM are masked, lines after END stay visible', async () => {
    const env = await drive(
      'logs',
      'docker',
      { container: 'app' },
      ok(
        dockerLines([
          'boot ok',
          BEGIN,
          BODY_1,
          'WARN pool exhausted',
          BODY_2,
          END,
          'GET /health 200',
          'WARN slow query 1200ms',
        ]),
      ),
    );
    const lines = texts(env);
    expect(JSON.stringify(env)).not.toContain(BODY_1);
    expect(JSON.stringify(env)).not.toContain(BODY_2);
    expect(lines).toContain('boot ok');
    expect(lines).toContain('GET /health 200');
    expect(lines).toContain('WARN slow query 1200ms');
  });

  test('D2 logs docker: a lone END near the top masks only the body before it', async () => {
    const env = await drive(
      'logs',
      'docker',
      { container: 'app', tail: '1000' },
      ok(dockerLines([BODY_2, END, ...ordinary(998)])),
      CEILING_MAX_BYTES,
    );
    const lines = texts(env);
    expect(JSON.stringify(env)).not.toContain(BODY_2);
    expect(lines.filter((line) => line.startsWith('GET /api/orders/')).length).toBe(998);
  });

  test('D3 logs service: one journald entry holding a whole PEM, and a JSON log with an escaped PEM', async () => {
    const entries = [
      `${BEGIN}\n${BODY_1}\n${END}`,
      `{"level":"info","key":"${BEGIN}\\n${BODY_2}\\n${END}"}`,
      'listening on :8080',
    ];
    const env = await drive(
      'logs',
      'service',
      { unit: 'app' },
      ok(
        `${entries
          .map((message, i) =>
            JSON.stringify({
              __REALTIME_TIMESTAMP: String(1764150000000000 + i),
              PRIORITY: '6',
              MESSAGE: message,
            }),
          )
          .join('\n')}\n`,
      ),
    );
    const json = JSON.stringify(env);
    expect(json).not.toContain(BODY_1);
    expect(json).not.toContain(BODY_2);
    expect(texts(env)).toContain('listening on :8080');
  });

  test('R5/R7 forms the brief named stay masked', () => {
    for (const text of [
      `STRIPE_KEY=${PW}`,
      `signing_key: ${PW}`,
      `{"encryption_key":"${PW}"}`,
      `  masterKey: ${PW}`,
      `x-api-key: ${PW}`,
      `appkey=${PW}`,
      `LICENSEKEY=${PW}`,
      `os.environ['DB_PASSWORD'] = '${PW}'`,
      `config.set('password', '${PW}')`,
      `ENV['SECRET_KEY'] = "${PW}"`,
    ]) {
      expect(leakOf(text)).toEqual({ text, leaked: false });
    }
    expect(scrubText(`$pw = getenv('DB_PASSWORD');`).value).toBe(`$pw = getenv('DB_PASSWORD');`);
  });

  test('URL last-@ rule: several URLs and an email in one line or JSON document are not swallowed', () => {
    const prose = 'see https://a.example/x then mail bob@corp.example';
    expect(scrubText(prose).value).toBe(prose);
    expect(
      scrubText(
        `{"a":"https://u:${PW}@h.example/x","b":"https://c.example/d","e":"bob@corp.example"}`,
      ).value,
    ).toBe('{"a":"https://u:***@h.example/x","b":"https://c.example/d","e":"bob@corp.example"}');
    const started = performance.now();
    scrubText(`${'a://b:'.repeat(68_000)}@`);
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe('audit05c — leak checks (each red test is a receipt finding)', () => {
  test('N1 joined *AUTHKEY names (Tailscale TS_AUTHKEY) leak: masked in Phase 05, lost in fix 1, not in the fix-2 prefix list', () => {
    for (const text of [
      `TS_AUTHKEY=${TS_PREFIX}${PW}`,
      `      TS_AUTHKEY: ${TS_PREFIX}${PW}`,
      `TAILSCALE_AUTHKEY=${TS_PREFIX}${PW}`,
      `authkey=${PW}`,
      `https://h.example/join?authkey=${PW}`,
    ]) {
      expect(leakOf(text)).toEqual({ text, leaked: false });
    }
  });

  test('N2 WordPress salts and *_SALT names leak (the wp-config.php file R7 targeted)', () => {
    for (const text of [
      `define( 'AUTH_SALT',        '${PW}' );`,
      `define( 'SECURE_AUTH_SALT', '${PW}' );`,
      `define( 'LOGGED_IN_SALT',   '${PW}' );`,
      `define( 'NONCE_SALT',       '${PW}' );`,
      `HASH_SALT=${PW}`,
    ]) {
      expect(leakOf(text)).toEqual({ text, leaked: false });
    }
  });

  test('N3 hash-rocket pairs not at line start leak (PHP inline array, Ruby, Perl)', () => {
    for (const text of [
      `$db = ['host' => 'db', 'password' => '${PW}'];`,
      `return array('username' => 'app', 'password' => '${PW}');`,
      `ActionMailer::Base.smtp_settings = { :user_name => 'app', :password => '${PW}' }`,
      `{ :password=>'${PW}' }`,
      `my %c = ( password => '${PW}' );`,
    ]) {
      expect(leakOf(text)).toEqual({ text, leaked: false });
    }
  });

  test('N4 signature query params (Azure SAS sig=, S3 X-Amz-Signature=) leak; SAS_URL was masked in Phase 05', () => {
    for (const text of [
      `AZURE_SAS_URL=https://acct.blob.core.windows.net/c?sv=2024-01-01&sp=r&sig=${PW}`,
      `https://h.example/f?sig=${PW}`,
      `GET https://b.s3.example/o?X-Amz-Algorithm=AWS4&X-Amz-Signature=${PW} 200`,
    ]) {
      expect(leakOf(text)).toEqual({ text, leaked: false });
    }
  });
});

describe('audit05c — fix 3: a marker or URL that only looks like a secret masks nothing else', () => {
  test('O1 a prose END or BEGIN mention is not a PEM boundary', () => {
    expect(maskPemLines(['GET /a 200', 'x: must end with -----END RSA PRIVATE KEY-----'])[0]).toBe(
      'GET /a 200',
    );
    expect(
      maskPemLines(['note: expected -----BEGIN RSA PRIVATE KEY----- header', 'GET /b 200'])[1],
    ).toBe('GET /b 200');
  });

  test('O1 real markers still mask: whole-line, quoted, and on a base64 body line', () => {
    expect(maskPemLines([BODY_1, END, 'after'])).toEqual([MASK, END, 'after']);
    expect(maskPemLines([BODY_1, `${BODY_2}${END}`, 'after'])).toEqual([
      MASK,
      `${BODY_2}${END}`,
      'after',
    ]);
    expect(maskPemLines([BODY_1, `${END}"`, 'after'])).toEqual([MASK, `${END}"`, 'after']);
    expect(maskPemLines([`private_key: "${BEGIN}`, BODY_1, `${END}"`, 'after'])).toEqual([
      `private_key: "${BEGIN}`,
      MASK,
      `${END}"`,
      'after',
    ]);
    expect(maskPemLines([`key=${BEGIN}${BODY_1}`, BODY_2, 'after'])).toEqual([
      `key=${BEGIN}${BODY_1}`,
      MASK,
      MASK,
    ]);
  });

  test('O1 logs docker: 50 ordinary lines before a prose END mention all stay visible', async () => {
    const env = await drive(
      'logs',
      'docker',
      { container: 'app' },
      ok(dockerLines([...ordinary(50), `config error: key file must end with ${END}`])),
    );
    expect(texts(env).filter((line) => line.startsWith('GET /api/orders/')).length).toBe(50);
  });

  test('O2 a port URL with an @ later, and a credential URL with a URL in its query, keep their path', () => {
    const port = 'GET http://localhost:3000/api?email=bob@corp.example 200';
    expect(scrubText(port).value).toBe(port);
    expect(scrubText(`url=https://u:${PW}@h1/x?next=https://b/y&mail=bob@corp`).value).toBe(
      'url=https://u:***@h1/x?next=https://b/y&mail=bob@corp',
    );
  });

  test('O2 R4 passwords holding / # ? @ and empty-user / srv URLs stay masked', () => {
    expect(scrubText(`postgres://app:p/w#x?y@z${PW}@db/x`).value).toBe('postgres://app:***@db/x');
    expect(scrubText(`redis://:${PW}@h`).value).toBe('redis://:***@h');
    expect(scrubText(`mongodb+srv://u:${PW}@h`).value).toBe('mongodb+srv://u:***@h');
    expect(scrubText(`postgres://u:${PW}@db:5432/app`).value).toBe('postgres://u:***@db:5432/app');
  });

  test('joined-KEY rule: ordinary words ending in KEY and KEYCLOAK_* stay visible, secret-ish prefixes mask', () => {
    for (const name of [
      'monkey',
      'turkey',
      'hockey',
      'donkey',
      'whiskey',
      'jockey',
      'key',
      'keyboard',
      'KEYCLOAK_REALM',
    ]) {
      expect({ name, text: scrubText(`${name}=visible-value`).value }).toEqual({
        name,
        text: `${name}=visible-value`,
      });
    }
    for (const name of [
      'jwtkey',
      'hmackey',
      'sessionkey',
      'encryptkey',
      'cryptkey',
      'presharedkey',
      'clientkey',
      'deploykey',
      'sshkey',
      'webhookkey',
      'passkey',
    ]) {
      expect(leakOf(`${name}=${PW}`)).toEqual({ text: `${name}=${PW}`, leaked: false });
    }
  });

  test('hash-rocket rule: an arrow function over a secret-named parameter is code, not a secret', () => {
    const code = 'const parts = tokens.map(token => token.trim());';
    expect(scrubText(code).value).toBe(code);
    expect(leakOf(`$c = ['password' => 123456${PW}];`).leaked).toBe(false);
  });
});

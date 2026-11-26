import { describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadScrubExtraPatterns } from '../ops/config.ts';
import { isEnvFile, isSecretKey, MASK, maskEnvContent, scrub, scrubText } from '../scrub.ts';

const FAKE = 'fake-secret-value-1';

function masked(text: string): string {
  return scrubText(text).value;
}

describe('scrubText — key-named values', () => {
  test('KEY=v for a denylisted key', () => {
    expect(masked(`DB_PASSWORD=${FAKE}`)).toBe(`DB_PASSWORD=${MASK}`);
  });

  test('export KEY=v', () => {
    expect(masked(`export API_TOKEN=${FAKE}`)).toBe(`export API_TOKEN=${MASK}`);
  });

  test('key: v (yaml) and "key": "v" (json)', () => {
    expect(masked(`  password: ${FAKE}`)).toBe(`  password: ${MASK}`);
    expect(masked(`{"client_secret": "${FAKE}", "region": "eu-west-1"}`)).toBe(
      `{"client_secret": "${MASK}", "region": "eu-west-1"}`,
    );
  });

  test('quoted values keep their quotes; the value never survives', () => {
    expect(masked(`SECRET_KEY_BASE="${FAKE} with spaces"`)).toBe(`SECRET_KEY_BASE="${MASK}"`);
    expect(masked(`STRIPE_KEY='${FAKE}'`)).toBe(`STRIPE_KEY='${MASK}'`);
  });

  test('a double-quoted value spanning lines is masked whole', () => {
    const out = masked(`APP_SECRET="${FAKE}\nsecond-line-of-it"\nPORT=3000`);
    expect(out).toBe(`APP_SECRET="${MASK}"\nPORT=3000`);
  });

  test('a backslash-continued value is masked whole', () => {
    const out = masked(`DATABASE_URL=${FAKE} \\\ncontinued-${FAKE}\nNODE_ENV=production`);
    expect(out).toBe(`DATABASE_URL=${MASK}\nNODE_ENV=production`);
  });

  test('inline pairs in a log line, a query string and a flag', () => {
    expect(masked(`level=info token=${FAKE} user=bob`)).toBe(`level=info token=${MASK} user=bob`);
    expect(masked(`GET /reset?password=${FAKE}&next=/home`)).toBe(
      `GET /reset?password=${MASK}&next=/home`,
    );
    expect(masked(`app --api-key=${FAKE} --port 80`)).toBe(`app --api-key=${MASK} --port 80`);
  });

  test('a long base64/hex run right after a secret-ish word', () => {
    const hex = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4';
    expect(masked(`worker --token ${hex} --verbose`)).toBe(`worker --token ${MASK} --verbose`);
  });

  test('non-secret keys stay visible: PORT, NODE_ENV, DB_HOST', () => {
    const text = 'PORT=3000\nNODE_ENV=production\nDB_HOST=db.internal\nexport LOG_LEVEL=debug';
    expect(masked(text)).toBe(text);
  });

  test('a revealed key is left as-is, every other secret still masked', () => {
    const text = `DATABASE_URL=postgres://app:${FAKE}@db/app\nAPI_TOKEN=${FAKE}`;
    const out = scrubText(text, { revealKeys: new Set(['DATABASE_URL']) }).value;
    expect(out).toBe(`DATABASE_URL=postgres://app:${FAKE}@db/app\nAPI_TOKEN=${MASK}`);
  });
});

describe('scrubText — secret-shaped values', () => {
  test('JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.ZmFrZS1zaWduYXR1cmUtdmFsdWUtMQ';
    expect(masked(`session ${jwt} accepted`)).toBe(`session ${MASK} accepted`);
  });

  test('sk-, sk_live_, ghp_, gho_, xox tokens', () => {
    const tokens = [
      'sk-fakeAbcdefghijklmnopqrstuv0123',
      'sk_live_fakeABCDEFGH0123456789',
      'ghp_fakeABCDEFGHIJKLMNOPQRSTUVWX0123',
      'gho_fakeABCDEFGHIJKLMNOPQRSTUVWX0123',
      'xoxb-0000000000-fake-token-value',
      'xoxp-0000000000-fake-token-value',
    ];
    for (const token of tokens) {
      expect(masked(`using ${token} now`)).toBe(`using ${MASK} now`);
    }
  });

  test('AWS access key id', () => {
    expect(masked('key id AKIAFAKEFAKEFAKE1234 loaded')).toBe(`key id ${MASK} loaded`);
  });

  test('PEM private key block, whole and truncated', () => {
    const pem = [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAAfakefakefakefake',
      'ZmFrZS1zZWNyZXQtdmFsdWUtMQ==',
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n');
    const out = masked(`before\n${pem}\nafter`);
    expect(out).toBe(
      `before\n-----BEGIN OPENSSH PRIVATE KEY-----\n${MASK}\n-----END OPENSSH PRIVATE KEY-----\nafter`,
    );
    const head = masked('-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefakefake\nZmFrZQ');
    expect(head).toBe(`-----BEGIN RSA PRIVATE KEY-----\n${MASK}`);
    const tail = masked('MIIEfakefakefake\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\nnext');
    expect(tail).toBe(`${MASK}\n-----END RSA PRIVATE KEY-----\nnext`);
  });

  test('scheme://user:pass@ masks the password part only', () => {
    expect(masked(`connecting to redis://cache:${FAKE}@cache.internal:6379/0`)).toBe(
      `connecting to redis://cache:${MASK}@cache.internal:6379/0`,
    );
  });

  test('Bearer x and Authorization headers', () => {
    expect(masked(`Authorization: Bearer ${FAKE}`)).toBe(`Authorization: Bearer ${MASK}`);
    expect(masked(`curl -H "Authorization: Basic ZmFrZTpzZWNyZXQ="`)).toBe(
      `curl -H "Authorization: Basic ${MASK}"`,
    );
  });

  test('extra per-alias patterns mask every match', () => {
    const out = scrubText('order ref INT-12345 and INT-67890', {
      extraPatterns: [/INT-\d+/g],
    });
    expect(out.value).toBe(`order ref ${MASK} and ${MASK}`);
    expect(out.count).toBe(2);
  });
});

describe('scrubText — leaves ordinary output alone', () => {
  test('prose, timestamps, urls without credentials, plain config', () => {
    const text = [
      'The deploy finished in 42 seconds; restart the worker if the queue backs up.',
      '2026-11-26T10:00:00Z nginx: GET /health 200 12ms',
      'Visit https://example.com/docs for the token rotation guide.',
      'PORT=3000',
      'workers: 4',
      'server_name example.com;',
    ].join('\n');
    const result = scrubText(text);
    expect(result.value).toBe(text);
    expect(result.count).toBe(0);
  });

  test('count is the number of values replaced', () => {
    expect(scrubText(`A_TOKEN=${FAKE}\nB_SECRET=${FAKE}\nPORT=1`).count).toBe(2);
  });
});

describe('scrub — structured payloads', () => {
  test('a string under a secret key is masked whole; others are scrubbed as text', () => {
    const rows = [{ id: 1, email: 'a@example.com', password: FAKE, note: `token=${FAKE}` }];
    const result = scrub(rows);
    expect(result.value).toEqual([
      { id: 1, email: 'a@example.com', password: MASK, note: `token=${MASK}` },
    ]);
    expect(result.count).toBe(2);
    expect(rows[0]?.password).toBe(FAKE);
  });
});

describe('isSecretKey / isEnvFile', () => {
  test('secret key names', () => {
    for (const key of [
      'DB_PASSWORD',
      'apiKey',
      'SECRET_KEY_BASE',
      'DATABASE_URL',
      'SENTRY_DSN',
      'DB_PASS',
      'aws_access_key_id',
      'MONGO_URI',
    ]) {
      expect({ key, secret: isSecretKey(key) }).toEqual({ key, secret: true });
    }
    for (const key of ['PORT', 'NODE_ENV', 'DB_HOST', 'LOG_LEVEL', 'KEYCLOAK_REALM', 'region']) {
      expect({ key, secret: isSecretKey(key) }).toEqual({ key, secret: false });
    }
  });

  test('secret-shaped files', () => {
    for (const path of [
      '/opt/myapp/.env',
      '/opt/myapp/.env.production',
      '/opt/myapp/prod.env',
      '/etc/app/app.vars',
      '/etc/app/db.secrets',
      '/root/.aws/credentials',
      '/etc/ssl/site.pem',
      '/root/.ssh/id_ed25519',
    ]) {
      expect({ path, env: isEnvFile(path) }).toEqual({ path, env: true });
    }
    for (const path of ['/opt/myapp/config.yml', '/etc/nginx/nginx.conf', '/opt/myapp/README.md']) {
      expect({ path, env: isEnvFile(path) }).toEqual({ path, env: false });
    }
  });
});

describe('maskEnvContent — whole env files', () => {
  test('every assignment masked, export kept, revealed key shown', () => {
    const text = `export DB_PASSWORD=${FAKE}\nNODE_ENV=production\nMULTI="${FAKE}\nline-two"\n# comment`;
    expect(maskEnvContent(text, new Set(['NODE_ENV']))).toBe(
      'export DB_PASSWORD=***MASKED***\nNODE_ENV=production\nMULTI="***MASKED***"\n# comment',
    );
  });
});

describe('loadScrubExtraPatterns — reveal-allowlist.toml [<alias>.scrub]', () => {
  test('reads the alias table only, and refuses a bad pattern by index without echoing it', () => {
    const path = join(
      mkdtempSync(join(tmpdir(), 'sshepherd-scrub-extra-')),
      'reveal-allowlist.toml',
    );
    writeFileSync(
      path,
      '[web-01]\nkeys = ["NODE_ENV"]\n\n[web-01.scrub]\nextra_patterns = ["INT-\\\\d+"]\n\n[bad.scrub]\nextra_patterns = ["ok", "(fake-secret-value-1"]\n',
    );
    expect(loadScrubExtraPatterns('web-01', path).map((pattern) => pattern.source)).toEqual([
      'INT-\\d+',
    ]);
    expect(loadScrubExtraPatterns('other', path)).toEqual([]);
    expect(() => loadScrubExtraPatterns('bad', path)).toThrow(
      'reveal-allowlist.toml: [bad.scrub] extra_patterns[1] is not a valid regular expression',
    );
  });
});

import { describe, expect, test } from 'bun:test';
import { MASK, maskPemBodyChunks, maskPemLines, scrub, scrubText } from '../scrub.ts';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const run = (length: number, offset = 0): string =>
  Array.from({ length }, (_, i) => B64[(i * 7 + offset) % 64]).join('');

describe('password verifiers are masked by their shape, whatever holds them', () => {
  const VERIFIERS: [string, string][] = [
    [
      'SCRAM-SHA-256',
      'SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0$U3RvcmVkS2V5U3RvcmVkS2V5U3RvcmVkS2V5U3Q=:U2VydmVyS2V5U2VydmVyS2V5U2VydmVyS2V5U2U=',
    ],
    ['md5 + 32 hex', 'md51f3870be274f6c49b3e31a0c6728957f'],
    ['bcrypt', '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'],
    ['argon2id', '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'],
    ['sha512-crypt', `$6$rounds=5000$saltsalt$${'x'.repeat(86)}`],
    ['sha256-crypt', `$5$saltsalt$${'y'.repeat(43)}`],
    ['yescrypt', `$y$j9T$F5Jx5fExrKuPp53xLKQ..1$${'X'.repeat(43)}`],
  ];
  test.each(VERIFIERS)('%s as a bare value', (_name, verifier) => {
    expect(scrubText(verifier).value).toBe(MASK);
  });

  test('under a column name no key rule knows (`SELECT rolpassword AS h`)', () => {
    const rows = VERIFIERS.map(([, verifier]) => ({ rolname: 'app_ro', h: verifier }));
    const out = scrub({ rows }).value as { rows: { rolname: string; h: string }[] };
    expect(out.rows.map((row) => row.h)).toEqual(VERIFIERS.map(() => MASK));
    expect(out.rows[0]?.rolname).toBe('app_ro');
  });

  test('inside an /etc/shadow line and a psql table row', () => {
    expect(scrubText(`root:$6$saltsalt$${'x'.repeat(86)}:19000:0:99999:7:::`).value).toBe(
      'root:***:19000:0:99999:7:::',
    );
    expect(scrubText(' app_ro  | md51f3870be274f6c49b3e31a0c6728957f').value).toBe(
      ' app_ro  | ***',
    );
  });

  test.each([
    'md5sum checked 3f2a',
    'md5 1f3870be274f6c49b3e31a0c6728957f',
    'cost $2 per item, $5 and $6 later',
    'SCRAM-SHA-256 is the default password_encryption',
  ])('prose that only names a scheme stays: %s', (line) => {
    expect(scrubText(line).value).toBe(line);
  });
});

describe('maskPemBodyChunks — key body lines a window or --grep cut off from both markers', () => {
  test('64- and 70-column body lines, bare or under a log prefix, and the short last line', () => {
    const lines = [
      run(64),
      `web-1  | ${run(64, 3)}`,
      `time=2026-11-27T10:00:01Z level=info msg=${run(70, 5)}`,
      `time=2026-11-27T10:00:01Z level=info msg=${run(24, 9)}==`,
      `{"msg":"${run(64, 11)}"}`,
    ];
    expect(maskPemBodyChunks(lines)).toEqual([MASK, MASK, MASK, MASK, MASK]);
  });

  test.each([
    `pulled sha256:${'3f'.repeat(32)}`,
    `digest ${'0a'.repeat(32)}`,
    `<script integrity="sha384-${run(64)}" crossorigin></script>`,
    `etag "${run(43)}="`,
    `cache key ${run(44)}`,
    `blob ${run(65)}`,
    'tick 12',
  ])('an ordinary line stays: %s', (line) => {
    expect(maskPemBodyChunks([line])).toEqual([line]);
  });

  test('a public block (certificate) keeps its body; a private one is still masked by maskPemLines', () => {
    const cert = ['-----BEGIN CERTIFICATE-----', run(64), run(64, 1), '-----END CERTIFICATE-----'];
    expect(maskPemBodyChunks(cert)).toEqual(cert);
    const [begin, end] = ['-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'];
    expect(maskPemBodyChunks(maskPemLines([begin, run(64), end]))).toEqual([begin, MASK, end]);
  });

  test('a short line after a chunk under another prefix stays', () => {
    expect(maskPemBodyChunks([`web-1 | ${run(64)}`, 'db-1 | ok'])).toEqual([MASK, 'db-1 | ok']);
  });
});

describe('maskPemLines — a prefixed lone END masks only its own writer’s body lines', () => {
  const END = '-----END RSA PRIVATE KEY-----';
  test('another writer’s lines between the body and END stay visible', () => {
    const out = maskPemLines([
      'web-1     | starting',
      `web-1     | ${run(64)}`,
      'worker-1  | processed job 12',
      `web-1     | ${run(64, 2)}`,
      `web-1     | ${run(20, 4)}`,
      `web-1     | ${END}`,
    ]);
    expect(out).toEqual([
      'web-1     | starting',
      MASK,
      'worker-1  | processed job 12',
      MASK,
      MASK,
      `web-1     | ${END}`,
    ]);
  });

  test('a prefixed END with no full chunk above it is prose, not a key', () => {
    const lines = ['INFO ok', `INFO must end with ${END}`];
    expect(maskPemLines(lines)).toEqual(lines);
  });
});

describe('KEY = value with blanks around the equals sign, under a secret-shaped name', () => {
  test.each([
    'DB_PASSWORD = hunter2',
    'api_key = hunter2',
    'db_password\t=\thunter2',
    '  export API_TOKEN = hunter2',
    'step 2 | DB_PASSWORD = hunter2',
  ])('%s', (line) => {
    expect(scrubText(line).value).not.toContain('hunter2');
  });

  test('after a multi-line quoted value in a cat of an env file (deploy run stdout)', () => {
    const file = [
      'SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE',
      '-----END OPENSSH PRIVATE KEY-----"',
      'DB_PASSWORD = hunter2',
      'LAST=ok',
    ].join('\n');
    expect(scrub({ stdout: file }).value).toEqual({
      stdout: 'SSH_KEY="***"\nDB_PASSWORD = ***\nLAST=ok',
    });
  });
});

describe('a lone END keeps its own line: the lead before the marker stays on it', () => {
  const END = '-----END RSA PRIVATE KEY-----';
  test.each([
    [`path:4:${END}`, `path:4:${END}`],
    [`a:1:QUJDREVGR0hJSktMTU5PUFFS\npath:4:${END}`, `${MASK}\npath:4:${END}`],
    [`web-1  | QUJDREVGR0hJSktMTU5PUFFS\nweb-1  | ${END}`, `${MASK}\nweb-1  | ${END}`],
    [`QUJDREVGR0hJSktMTU5PUFFSU1RVVldY${END}`, `${MASK}\n${END}`],
    [`QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n${END}`, `${MASK}\n${END}`],
  ])('%s', (input, expected) => {
    expect(scrubText(input).value).toBe(expected);
  });
});

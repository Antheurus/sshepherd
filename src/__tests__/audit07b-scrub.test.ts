import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import { maskPemLines, type ScrubOptions, scrub, scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

const BODY = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2';
const SSH_G = 'hostname srv-01.example.net\nuser opsuser\nport 2222\n';

let scratch = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit07b-'));
});
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

function scripted(last: SpawnOutcome): SshRunner {
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: SSH_G, stderr: '', timedOut: false },
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
  extra: { limit?: number; maxBytes?: number } = {},
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(
    op,
    { alias: 'edge-box', args },
    { transport: { runner: scripted(last) }, auditLogPath: join(scratch, 'audit.jsonl'), ...extra },
  );
}

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

describe('audit07b FIX-3 LEAK — a lone END with a log prefix no longer masks the body before it', () => {
  test('compose-style prefix: the body line whose BEGIN was cut off is masked', () => {
    const out = maskPemLines([`web-1  | ${BODY}`, 'web-1  | -----END RSA PRIVATE KEY-----']);
    expect(out[0]).toBe('***');
  });
  test('timestamp + level prefix: the body line is masked', () => {
    const out = maskPemLines([
      `2026-11-27T10:00:00Z INFO ${BODY}`,
      '2026-11-27T10:00:00Z INFO -----END RSA PRIVATE KEY-----',
    ]);
    expect(out[0]).toBe('***');
  });
});

describe('audit07b FIX-4 LEAK — the ssh user is masked only in identity contexts (spec: everywhere)', () => {
  const opts: ScrubOptions = { identity: { user: 'opsuser' }, maskAddresses: true };
  test.each([
    ['ls -l', '-rw-r--r-- 1 opsuser opsuser 1234 Nov 27 10:00 app.log'],
    ['ps aux', 'opsuser    4321  0.0  0.1  12345  6789 ?  Ss  10:00  0:00 node server.js'],
    ['home path', 'cwd /home/opsuser/app/releases/42'],
    ['id', 'uid=1001(opsuser) gid=1001(opsuser) groups=1001(opsuser),27(sudo)'],
    ['sudo log', 'sudo: opsuser : TTY=pts/0 ; PWD=/home/opsuser ; USER=root ; COMMAND=/bin/ls'],
  ])('%s carries no user name', (_label, input) => {
    expect(scrubText(input, opts).value).not.toContain('opsuser');
  });
});

describe('audit07b FIX-4 OVER-MASK — the user `@` and `for` contexts match package, image and loop names', () => {
  const opts: ScrubOptions = { identity: { user: 'app' }, maskAddresses: true };
  test.each([
    ['npm ls', '├── app@2.0.0'],
    [
      'image digest',
      'docker pull registry.example.net/app@sha256:4b825dc642cb6eb9a060e54bf8d69288',
    ],
    ['systemd instance', 'systemd[1]: Started app@1000.service'],
    ['shell loop', 'for app in api web worker; do systemctl restart $app; done'],
  ])('%s is left as written', (_label, input) => {
    expect(scrubText(input, opts).value).toBe(input);
  });
});

describe('audit07b FIX-4 LEAK — the non-22 port leaks outside host:port / port-keyword contexts', () => {
  const opts: ScrubOptions = { identity: { port: '2222' }, maskAddresses: true };
  test.each([
    ['ufw', '2222/tcp                   ALLOW       Anywhere'],
    ['docker HostPort', '{"HostIp":"0.0.0.0","HostPort":"2222"}'],
  ])('%s carries no port', (_label, input) => {
    expect(scrubText(input, opts).value).not.toContain('2222');
  });
});

describe('audit07b FIX-4 LEAK — a dotless hostname under 6 chars is never masked, even in host contexts', () => {
  const opts: ScrubOptions = {
    identity: { hostname: 'web1', user: 'opsuser' },
    maskAddresses: true,
  };
  test.each([
    ['ssh connect error', 'ssh: connect to host web1 port 22: Connection refused'],
    ['prompt', 'opsuser@web1:~$'],
  ])('%s carries no hostname', (_label, input) => {
    expect(scrubText(input, opts).value).not.toContain('web1');
  });
});

describe('audit07b FIX-4 LEAK — an IPv6 literal right after `word:` is not masked (IPv4 there is)', () => {
  test.each([
    ['addr:', 'addr:2001:db8::5'],
    ['client_ip:', 'client_ip:2001:db8::7'],
    ['from: link-local', 'from:fe80::1%eth0'],
  ])('%s', (_label, input) => {
    expect(scrubText(input, { maskAddresses: true }).value).toMatch(/<ip-1>/);
  });
});

describe('audit07b FIX-4 LEAK — an IPv6 hostname in non-canonical form survives reveal_addresses', () => {
  test('the expanded form of the alias hostname is still <host>', () => {
    const opts: ScrubOptions = { identity: { hostname: '2001:db8::10' }, maskAddresses: false };
    expect(scrubText('peer 2001:db8:0:0:0:0:0:10', opts).value).toBe('peer <host>');
  });
});

describe('audit07b P06-FIX — logs --limit keeps the oldest lines (F2: a capped log keeps the newest)', () => {
  test('logs docker --limit 3 returns the last 3 lines of the window', async () => {
    const lines = Array.from(
      { length: 40 },
      (_, i) => `2026-11-27T10:00:${String(i).padStart(2, '0')}.000000000Z req ${i}`,
    );
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web', tail: '40' },
      ok(`${lines.join('\n')}\n`),
      { limit: 3 },
    );
    const data = envelope.data as { lines: { text: string }[] };
    expect(data.lines.map((line) => line.text)).toEqual(['req 37', 'req 38', 'req 39']);
  });
});

describe('audit07b holds — guards for what the audit drove and found intact', () => {
  test('a URL password stays masked under identity and address masking', () => {
    const opts: ScrubOptions = {
      identity: { hostname: 'srv-01.example.net', user: 'opsuser', port: '2222' },
      maskAddresses: true,
    };
    expect(
      scrubText('dsn postgres://opsuser:pw-x9@srv-01.example.net:2222/app and @198.51.100.7', opts)
        .value,
    ).toBe('dsn postgres://<user>:***@<host>:<port>/app and @<ip-1>');
  });

  test('one <ip-N> table spans data, error and stderr', () => {
    const { value } = scrub(
      {
        data: { a: '192.0.2.9', '198.51.100.1': 'x' },
        error: { message: 'peer 198.51.100.1 and 192.0.2.9' },
        stderr: '192.0.2.9',
      },
      { maskAddresses: true },
    );
    expect(value as unknown).toEqual({
      data: { a: '<ip-1>', '<ip-2>': 'x' },
      error: { message: 'peer <ip-2> and <ip-1>' },
      stderr: '<ip-1>',
    });
  });

  test('timeout envelope: partial_stdout and stderr_tail share tokens; no identity leaks', async () => {
    const envelope = await drive(
      'logs',
      'nginx',
      { stream: 'access', tail: '50' },
      {
        code: 124,
        stdout: 'GET from 192.0.2.10 ok\nGET from 198.51.100.20 ok\n',
        stderr: 'upstream 198.51.100.20 timed out\nssh opsuser@srv-01.example.net -p 2222',
        timedOut: true,
      },
    );
    const json = JSON.stringify(envelope);
    expect({
      partial: (envelope.data as { partial_stdout: string }).partial_stdout,
      tail: envelope.error?.stderr_tail,
      leaked: ['srv-01.example.net', 'opsuser', '2222', '192.0.2.', '198.51.100.'].filter((s) =>
        json.includes(s),
      ),
    }).toEqual({
      partial: 'GET from <ip-1> ok\nGET from <ip-2> ok\n',
      tail: 'upstream <ip-2> timed out\nssh <user>@<host> -p <port>',
      leaked: [],
    });
  });

  test('the 4 KiB line cut after a masked secret never exposes any of it', async () => {
    for (const offset of [4_080, 4_090, 4_094, 4_096]) {
      const line = `2026-11-27T10:00:00.000000000Z ${'a'.repeat(offset)} password=Hunter2LongValue 203.0.113.77`;
      const envelope = await drive(
        'logs',
        'docker',
        { container: 'web', tail: '5' },
        ok(`${line}\n`),
      );
      const text = (envelope.data as { lines: { text: string }[] }).lines[0]?.text ?? '';
      expect({ offset, secret: text.includes('Hunt'), ip: text.includes('203.0.113') }).toEqual({
        offset,
        secret: false,
        ip: false,
      });
    }
  });

  test('PEM lines and a key=value in one log count once each', async () => {
    const lines = [
      '2026-11-27T10:00:00.000000000Z -----BEGIN RSA PRIVATE KEY-----',
      `2026-11-27T10:00:01.000000000Z ${BODY}`,
      `2026-11-27T10:00:02.000000000Z ${BODY}`,
      '2026-11-27T10:00:03.000000000Z -----END RSA PRIVATE KEY-----',
      '2026-11-27T10:00:04.000000000Z token=abcdef123456',
    ];
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web', tail: '5' },
      ok(`${lines.join('\n')}\n`),
    );
    expect(envelope.scrubbed).toBe(3);
  });
});

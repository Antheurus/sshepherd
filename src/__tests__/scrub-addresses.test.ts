import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadRevealAddresses } from '../ops/config.ts';
import { executeOp, getOp } from '../registry.ts';
import { type ConnectionIdentity, type ScrubOptions, scrub, scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';
import { expectLinear, LINEARITY_TEST_TIMEOUT_MS } from './linearity.ts';

const ALIAS = 'edge-box';
const IDENTITY: ConnectionIdentity = {
  hostname: 'srv-01.example.net',
  user: 'opsuser',
  port: '2222',
};
const ON: ScrubOptions = { identity: IDENTITY, maskAddresses: true };

function text(value: string, options: ScrubOptions = ON): string {
  return scrub(value, options).value;
}

let scratch = '';
let savedReveal: string | undefined;

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-scrub-addresses-'));
  savedReveal = process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
});

afterAll(() => {
  if (savedReveal === undefined) {
    delete process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
  } else {
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = savedReveal;
  }
  rmSync(scratch, { recursive: true, force: true });
});

function useRevealAllowlist(body: string | null): void {
  const path = join(scratch, `reveal-${Math.random().toString(36).slice(2)}.toml`);
  if (body !== null) {
    writeFileSync(path, body);
  }
  process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = path;
}

const SSH_G =
  'hostname srv-01.example.net\nuser opsuser\nport 2222\nidentityfile ~/.ssh/id_ed25519\n';

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

async function drive(group: string, name: string, last: SpawnOutcome): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(
    op,
    { alias: ALIAS, args: {} },
    { transport: { runner: scripted(last) }, auditLogPath: join(scratch, 'audit.jsonl') },
  );
}

describe('rule 1 — the alias identity is masked in every part of the envelope', () => {
  test('stderr_tail: an ssh connect error names <host> and <port>', () => {
    expect(text('ssh: connect to host srv-01.example.net port 2222: Connection refused')).toBe(
      'ssh: connect to host <host> port <port>: Connection refused',
    );
  });

  test('a log line: the user after "for", the peer IP, an unrelated port kept', () => {
    expect(text('Accepted publickey for opsuser from 203.0.113.7 port 51234 ssh2')).toBe(
      'Accepted publickey for <user> from <ip-1> port 51234 ssh2',
    );
  });

  test('a db error: quoted hostname, its IP in parentheses, the db port kept', () => {
    expect(
      text('could not connect to server at "srv-01.example.net" (198.51.100.4), port 5432'),
    ).toBe('could not connect to server at "<host>" (<ip-1>), port 5432');
  });

  test('every user context: user@host, -l, User, for [invalid] user, user=, "user": ', () => {
    expect(
      text(
        [
          'opsuser@srv-01.example.net:2222',
          'ssh -l opsuser -p 2222 srv-01.example.net',
          'User opsuser',
          'Failed password for invalid user opsuser from 192.0.2.44',
          'password authentication failed for user "opsuser"',
          'user=opsuser port=2222',
          '{"user": "opsuser", "port": 2222}',
          'DATABASE_URL=postgres://opsuser:hunter2@srv-01.example.net:2222/app',
        ].join('\n'),
      ),
    ).toBe(
      [
        '<user>@<host>:<port>',
        'ssh -l <user> -p <port> <host>',
        'User <user>',
        'Failed password for invalid user <user> from <ip-1>',
        'password authentication failed for user "<user>"',
        'user=<user> port=<port>',
        '{"user": "<user>", "port": <port>}',
        'DATABASE_URL=postgres://<user>:***@<host>:<port>/app',
      ].join('\n'),
    );
  });

  test('the port is never masked as a bare word in prose; a distinctive user is', () => {
    const prose = 'opsuser wrote 2222 lines; the opsuser group owns build 2222';
    expect(text(prose)).toBe('<user> wrote 2222 lines; the <user> group owns build 2222');
  });

  test('hostname: case-insensitive, whole token, a trailing sentence dot allowed', () => {
    expect(text('SRV-01.Example.NET is up. Ping srv-01.example.net.')).toBe(
      '<host> is up. Ping <host>.',
    );
    const other =
      'srv-01.example.net.evil.example www.srv-01.example.net srv-01.example.netx srv-01.example.net-old';
    expect(text(other)).toBe(other);
  });

  test('a short dotless hostname (db) is not masked as a bare word, only in a host context', () => {
    const options: ScrubOptions = { identity: { hostname: 'db' }, maskAddresses: true };
    const line = 'the db is up; connect to db failed; dbx and db.example.net';
    expect(text(line, options)).toBe(
      'the db is up; connect to <host> failed; dbx and db.example.net',
    );
  });

  test('a dotless hostname of 6+ chars is masked as a bare word', () => {
    const options: ScrubOptions = { identity: { hostname: 'edgebox01' }, maskAddresses: true };
    expect(text('edgebox01 kernel: eth0 up', options)).toBe('<host> kernel: eth0 up');
  });

  test('an IP HostName becomes <host>, not <ip-N>, with its :port kept masked', () => {
    const options: ScrubOptions = {
      identity: { hostname: '198.51.100.9', port: '2222' },
      maskAddresses: true,
    };
    expect(text('connect to 198.51.100.9:2222 via 203.0.113.1', options)).toBe(
      'connect to <host>:<port> via <ip-1>',
    );
  });

  test('check output (check ports) through executeOp carries no identity or address', async () => {
    const stdout = [
      'LISTEN 0 4096 198.51.100.4:5432 0.0.0.0:* users:(("postgres",pid=81,fd=5))',
      'LISTEN 0 128 [2001:db8::10]:2222 [::]:* users:(("sshd",pid=1,fd=3))',
      'LISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:(("node",pid=9,fd=20))',
    ].join('\n');
    const envelope = await drive('check', 'ports', {
      code: 0,
      stdout,
      stderr: '',
      timedOut: false,
    });
    const json = JSON.stringify(envelope);
    expect(envelope.ok).toBe(true);
    expect(json).not.toContain('198.51.100.4');
    expect(json).not.toContain('2001:db8::10');
    expect(json).toContain('127.0.0.1');
    expect(envelope.scrubbed).toBeGreaterThanOrEqual(2);
  });
});

describe('rule 2 — every other IP literal becomes a per-envelope <ip-N>', () => {
  test('the same address keeps one token across data and error, numbered by first appearance', () => {
    const { value, count } = scrub(
      {
        data: ['peer 203.0.113.7 joined', '198.51.100.4', { '203.0.113.7': 'seen' }],
        error: { message: 'lost 198.51.100.4 then 203.0.113.7 and 192.0.2.5' },
      },
      { maskAddresses: true },
    );
    expect(value as unknown).toEqual({
      data: ['peer <ip-1> joined', '<ip-2>', { '<ip-1>': 'seen' }],
      error: { message: 'lost <ip-2> then <ip-1> and <ip-3>' },
    });
    expect(count).toBe(6);
  });

  test('loopback and unspecified addresses stay', () => {
    const line = '127.0.0.1:8080 127.10.0.1 0.0.0.0:22 ::1 [::]:80 [::1]:5432 ::';
    expect(text(line)).toBe(line);
  });

  test('a /cidr or :port suffix stays visible', () => {
    expect(text('route 203.0.113.0/24 via 198.51.100.4:443, net 2001:db8::/32')).toBe(
      'route <ip-1>/24 via <ip-2>:443, net <ip-3>/32',
    );
  });

  test('version strings, image tags, dates, timestamps, MACs and code paths stay', () => {
    const line = [
      'kernel 1.2.3.4.5',
      'agent v10.0.0.1',
      'image nginx:1.25.3 and redis:7.2.4-alpine',
      'on 2026.11.26 at 12:34:56 (2026-11-26T12:34:56.789Z)',
      'link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff',
      'std::vector<int> and a::b and ab::cd',
    ].join('\n');
    expect(text(line)).toBe(line);
  });

  test('IPv6 global addresses are masked, in brackets, with a zone, or IPv4-mapped', () => {
    expect(
      text(
        'inet6 2001:db8:85a3::8a2e:370:7334/64 [2001:db8::1]:443 fe80::1%eth0 ::ffff:192.0.2.1 ::1',
      ),
    ).toBe('inet6 <ip-1>/64 [<ip-2>]:443 <ip-3>%eth0 <ip-4> ::1');
  });

  test('a full eight-group IPv6 address is masked', () => {
    expect(text('peer 2001:0db8:0000:0000:0000:ff00:0042:8329 up')).toBe('peer <ip-1> up');
  });

  test('plain scrubText (files download bytes) does not touch addresses', () => {
    const line = 'upstream 203.0.113.7:443;';
    expect(scrubText(line).value).toBe(line);
  });

  test('the masked addresses are counted in scrubbed', () => {
    expect(scrub('from 203.0.113.7 to 198.51.100.4', { maskAddresses: true }).count).toBe(2);
  });
});

describe('reveal_addresses opt-out', () => {
  test('maskAddresses off keeps other IPs but still masks the identity', () => {
    expect(
      text('opsuser@srv-01.example.net from 203.0.113.7 port 2222', {
        identity: IDENTITY,
        maskAddresses: false,
      }),
    ).toBe('<user>@<host> from 203.0.113.7 port <port>');
  });

  test('loadRevealAddresses: absent false, true, and a non-boolean refused without its value', () => {
    const path = join(scratch, 'reveal-load.toml');
    writeFileSync(
      path,
      `[${ALIAS}.scrub]\nreveal_addresses = true\n[other.scrub]\nextra_patterns = []\n`,
    );
    expect(loadRevealAddresses(ALIAS, path)).toBe(true);
    expect(loadRevealAddresses('other', path)).toBe(false);
    expect(loadRevealAddresses('missing', join(scratch, 'none.toml'))).toBe(false);
    writeFileSync(path, `[${ALIAS}.scrub]\nreveal_addresses = "203.0.113.7"\n`);
    expect(() => loadRevealAddresses(ALIAS, path)).toThrow(
      /reveal_addresses must be true or false/,
    );
    try {
      loadRevealAddresses(ALIAS, path);
    } catch (err) {
      expect((err as { code?: string }).code).toBe('CONFIG_PARSE_ERROR');
      expect(String((err as Error).message)).not.toContain('203.0.113.7');
    }
  });

  test('a malformed reveal_addresses fails the op as CONFIG_PARSE_ERROR', async () => {
    useRevealAllowlist(`[${ALIAS}.scrub]\nreveal_addresses = 1\n`);
    const envelope = await drive('check', 'ports', {
      code: 0,
      stdout: '',
      stderr: '',
      timedOut: false,
    });
    expect(envelope.error?.code).toBe('CONFIG_PARSE_ERROR');
    useRevealAllowlist(null);
  });
});

describe('executeOp — the ssh -G identity never reaches the envelope', () => {
  const leaked = ['srv-01.example.net', 'opsuser', '2222', '10.20.30.40'];
  const remote =
    'connected to srv-01.example.net:2222 as opsuser@srv-01.example.net from 10.20.30.40\n' +
    'ssh -l opsuser -p 2222 srv-01.example.net\n';

  test('a timed-out command: partial_stdout and stderr_tail both carry all four, none survive', async () => {
    const envelope = await drive('check', 'disk', {
      code: 124,
      stdout: remote,
      stderr: `${remote}Failed password for opsuser from 10.20.30.40 port 2222\n`,
      timedOut: false,
    });
    const json = JSON.stringify(envelope);
    expect(envelope.error?.code).toBe('COMMAND_TIMEOUT');
    expect(json).toContain('partial_stdout');
    expect(json).toContain('stderr_tail');
    for (const value of leaked) {
      expect(json).not.toContain(value);
    }
    expect(json).toContain('<host>');
    expect(json).toContain('<user>');
    expect(json).toContain('<port>');
    expect(json).toContain('<ip-1>');
  });

  test('a failed command: stderr_tail carries none of the four', async () => {
    const envelope = await drive('check', 'disk', {
      code: 1,
      stdout: '',
      stderr: remote,
      timedOut: false,
    });
    const json = JSON.stringify(envelope);
    expect(envelope.error?.code).toBe('COMMAND_FAILED');
    for (const value of leaked) {
      expect(json).not.toContain(value);
    }
  });

  test('reveal_addresses = true keeps 10.20.30.40 and still masks host, user and port', async () => {
    useRevealAllowlist(`[${ALIAS}.scrub]\nreveal_addresses = true\n`);
    const envelope = await drive('check', 'disk', {
      code: 1,
      stdout: '',
      stderr: remote,
      timedOut: false,
    });
    useRevealAllowlist(null);
    const json = JSON.stringify(envelope);
    expect(json).toContain('10.20.30.40');
    for (const value of leaked.slice(0, 3)) {
      expect(json).not.toContain(value);
    }
  });
});

describe('linear on adversarial input', () => {
  const KB50 = 50 * 1_024;
  const repeat = (unit: string) => (chars: number) => unit.repeat(Math.floor(chars / unit.length));
  const cases: [string, (chars: number) => string][] = [
    ['dotted digit run 1.1.1...', repeat('1.')],
    ['valid IPv4 run 203.0.113.7.203...', repeat('203.0.113.7.')],
    ['colons ::::...', repeat(':')],
    ['hex groups a:b:c:...', repeat('a:b:c:')],
    ['digit groups 0:1:2:...', repeat('0:1:2:3:')],
    ['compressed fe80::fe80::...', repeat('fe80::')],
    ['hostname fragments', repeat('srv-01.example.')],
    ['hostname repeated whole', repeat('srv-01.example.net ')],
    ['user contexts', repeat('for opsuser@ -l opsuser user= ')],
    ['keyword then blanks', (chars) => `for${' '.repeat(chars)}x`],
    ['port contexts', repeat('x:2222 -p 2222 port ')],
  ];
  for (const [name, make] of cases) {
    test(
      `${name}: time grows linearly from 50 KB to 200 KB`,
      () => {
        expectLinear(make, KB50, (input) => scrub(input, ON));
      },
      LINEARITY_TEST_TIMEOUT_MS,
    );
  }

  test(
    'F10: a hyphenated line with identity and addresses on grows linearly to 204 KB',
    () => {
      const hyphenated = (chars: number) =>
        Array.from({ length: Math.ceil(chars / 9.7) }, (_, i) => `node-${i}`).join('-');
      expect(hyphenated(51_000 * 4).length).toBeGreaterThan(204_000);
      expectLinear(hyphenated, 51_000, (input) => scrub(input, ON));
    },
    LINEARITY_TEST_TIMEOUT_MS,
  );
});

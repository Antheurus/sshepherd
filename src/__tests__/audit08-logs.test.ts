import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { diagnoseHost } from '../hosts-diagnose.ts';
import { executeOp, getOp } from '../registry.ts';
import { maskPemLines, scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

// Auditor file for Block 8 part a (Phase 08 + Phase 05 fix 5): every test is red by design, one
// per receipt finding. The P08 tests run the op's REAL generated remote script locally under sh,
// against stand-in `docker` / `journalctl` binaries that behave like the real ones did on the
// fixture (docker logs: --tail first, then an inclusive --since/--until window).

const SSH_G = 'hostname srv-01.example.net\nuser opsuser\nport 2222\n';
const BODY = [
  'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2',
  'd3h5ejAxMjM0NTY3ODkrL0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVm',
  'Z2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky9BQkNERUZHSElKS0xNTk9Q',
  'UVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsv',
];
const ts = (second: number): string =>
  `2026-11-27T10:${String(Math.floor(second / 60)).padStart(2, '0')}:${String(second % 60).padStart(2, '0')}.000000000Z`;

const FAKE_DOCKER = `#!/bin/sh
[ "$1" = logs ] || exit 64
shift; tail=all; since=; until=
while [ $# -gt 1 ]; do
  case "$1" in
    --tail) shift; tail=$1 ;;
    --since) shift; since=$1 ;;
    --until) shift; until=$1 ;;
  esac
  shift
done
f="$A08_LOGDIR/$1.log"
if [ ! -f "$f" ]; then echo "Error response from daemon: No such container: $1" >&2; exit 1; fi
if [ "$tail" = all ]; then cat "$f"; else tail -n "$tail" "$f"; fi |
  awk -v s="$since" -v u="$until" '(s == "" || $1 >= s) && (u == "" || $1 <= u)'
`;
const FAKE_JOURNALCTL = `#!/bin/sh
n=1000
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift; n=$1 ;;
    --grep=* | --case-sensitive=*) echo "journalctl: unrecognized option '$1'" >&2; exit 1 ;;
  esac
  shift
done
[ "$n" = 0 ] && exit 0
tail -n "$n" "$A08_JOURNAL"
`;

let scratch = '';
let bin = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit08-'));
  bin = join(scratch, 'bin');
  Bun.spawnSync(['mkdir', '-p', bin, join(scratch, 'logs')]);
  for (const [name, body] of [
    ['docker', FAKE_DOCKER],
    ['journalctl', FAKE_JOURNALCTL],
  ] as const) {
    writeFileSync(join(bin, name), body);
    chmodSync(join(bin, name), 0o755);
  }
  const ticker = Array.from({ length: 600 }, (_, i) => `${ts(i + 1)} tick ${i + 1}`);
  writeFileSync(join(scratch, 'logs', 'ticker.log'), `${ticker.join('\n')}\n`);
  const key = [
    `${ts(1)} 2026-11-27T10:00:01Z INFO loading signing key`,
    `${ts(2)} -----BEGIN RSA PRIVATE KEY-----`,
    ...BODY.map((line, i) => `${ts(3 + i)} ${line}`),
    `${ts(7)} -----END RSA PRIVATE KEY-----`,
    `${ts(8)} 2026-11-27T10:00:08Z INFO key loaded`,
  ];
  writeFileSync(join(scratch, 'logs', 'keysvc.log'), `${key.join('\n')}\n`);
  const journal = Array.from({ length: 7 }, (_, i) =>
    JSON.stringify({
      __CURSOR: `s=4f1c;i=${i}`,
      __REALTIME_TIMESTAMP: String(1_795_600_000_000_000 + i * 1_000_000),
      _SYSTEMD_UNIT: 'nginx.service',
      SYSLOG_IDENTIFIER: 'nginx',
      PRIORITY: '6',
      MESSAGE:
        i === 3
          ? 'nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address in use)'
          : `upstream request ${i} completed`,
    }),
  );
  writeFileSync(join(scratch, 'journal.ndjson'), `${journal.join('\n')}\n`);
});
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

/** ssh -G and the ControlMaster check answer canned; the remote command runs here under sh. */
function localRunner(): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok(SSH_G);
    }
    if (args.includes('-O')) {
      return ok('');
    }
    const proc = Bun.spawnSync(['sh', '-c', args.at(-1) ?? ''], {
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH ?? ''}`,
        A08_LOGDIR: join(scratch, 'logs'),
        A08_JOURNAL: join(scratch, 'journal.ndjson'),
      },
    });
    return {
      code: proc.exitCode ?? 1,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
      timedOut: false,
    };
  };
}

function cannedRunner(stdout: string): SshRunner {
  return async (args) => (args[0] === '-G' ? ok(SSH_G) : ok(args.includes('-O') ? '' : stdout));
}

async function drive(
  group: string,
  name: string,
  args: Record<string, string>,
  runner: SshRunner = localRunner(),
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(
    op,
    { alias: 'edge-box', args },
    { transport: { runner }, auditLogPath: join(scratch, 'audit.jsonl') },
  );
}

interface Logs {
  lines: { ts: string | null; text: string }[];
  next_since: string | null;
  truncated: boolean;
}
const logsOf = (envelope: Envelope<unknown>): Logs => envelope.data as Logs;
const bodyRaw = (envelope: Envelope<unknown>): number =>
  BODY.filter((line) => JSON.stringify(envelope).includes(line.slice(0, 24))).length;

describe('audit08 P08 LEAK — a window or --grep that drops both PEM markers returns the key body raw', () => {
  test('logs docker --since/--until between BEGIN and END: no body line in the envelope', async () => {
    const envelope = await drive('logs', 'docker', {
      container: 'keysvc',
      since: ts(3),
      until: ts(6),
    });
    expect(logsOf(envelope).lines.length).toBe(4);
    expect(bodyRaw(envelope)).toBe(0);
  });

  test('logs docker --grep that matches only base64 body lines: no body line in the envelope', async () => {
    const envelope = await drive('logs', 'docker', {
      container: 'keysvc',
      grep: '[A-Za-z0-9+/]{48}',
    });
    expect(logsOf(envelope).lines.length).toBe(4);
    expect(bodyRaw(envelope)).toBe(0);
  });
});

describe('audit08 P08 BUG — next_since paging', () => {
  test('paging from next_since never returns the last line again', async () => {
    const first = logsOf(await drive('logs', 'docker', { container: 'ticker' }));
    expect(first.lines.at(-1)?.text).toBe('tick 600');
    const second = logsOf(
      await drive('logs', 'docker', { container: 'ticker', since: first.next_since ?? '' }),
    );
    expect(second.lines.map((line) => line.text)).toEqual([]);
  });

  test('paging forward from --since with --max-lines reaches every line, none skipped', async () => {
    const seen = new Set<string>();
    let since = ts(1);
    for (let page = 0; page < 12; page += 1) {
      const result = logsOf(
        await drive('logs', 'docker', { container: 'ticker', since, 'max-lines': '100' }),
      );
      for (const line of result.lines) {
        seen.add(line.text);
      }
      if (result.next_since === null || result.next_since === since) {
        break;
      }
      since = result.next_since;
    }
    expect(seen.size).toBe(600);
  });

  test('--until alone returns the lines before it, not an empty untruncated page', async () => {
    const result = logsOf(await drive('logs', 'docker', { container: 'ticker', until: ts(300) }));
    expect(result.lines.length).toBeGreaterThan(0);
    expect(result.lines.at(-1)?.text).toBe('tick 300');
  });
});

describe('audit08 P08 BUG — the grep -E journal fallback matches JSON metadata, not the message', () => {
  test('logs service nginx --grep nginx returns only the entry whose message says nginx', async () => {
    const envelope = await drive('logs', 'service', { unit: 'nginx', grep: 'nginx' });
    expect(logsOf(envelope).lines.map((line) => line.text)).toEqual([
      'nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address in use)',
    ]);
  });
});

describe('audit08 P08 BUG — with --grep a failing source loses its own error text', () => {
  test('logs docker <missing> --grep: the daemon error reaches the envelope', async () => {
    const envelope = await drive('logs', 'docker', { container: 'nosuch', grep: 'boom' });
    expect(envelope.ok).toBe(false);
    expect(JSON.stringify(envelope)).toContain('No such container');
  });
});

const OVERVIEW_FREE_MISSING_DISK_FULL = [
  '__NPROC__',
  '4',
  '__NPROC_RC__',
  '0',
  '__FREE__',
  '__FREE_RC__',
  '127',
  '__DF__',
  'Filesystem     1B-blocks       Used   Available Capacity Mounted on',
  '/dev/sda1    21467271168 20500000000   967271168       95% /',
  '__DF_RC__',
  '0',
  '__UPTIME__',
  '14:32:05 up 10 days,  3:14,  2 users,  load average: 0.15, 0.22, 0.18',
  '__UPTIME_RC__',
  '0',
  '__PSI__',
].join('\n');

describe('audit08 P08 BUG — a degraded section still reports readings', () => {
  test('check overview with free missing: mem carries no zero readings', async () => {
    const envelope = await drive(
      'check',
      'overview',
      {},
      cannedRunner(OVERVIEW_FREE_MISSING_DISK_FULL),
    );
    const data = envelope.data as { degraded: string[]; mem: { mem: unknown } | null };
    expect(data.degraded).toEqual(['mem']);
    expect(data.mem === null || data.mem.mem === null).toBe(true);
  });
});

describe('audit08 P08 DEVIATION (needs a ruling) — a known risk is reported as unknown', () => {
  test('check overview: disk 95% with free missing is still a dead end (true OR unknown = true)', async () => {
    const envelope = await drive(
      'check',
      'overview',
      {},
      cannedRunner(OVERVIEW_FREE_MISSING_DISK_FULL),
    );
    expect((envelope.data as { dead_end_risk: boolean | null }).dead_end_risk).toBe(true);
  });
});

describe('audit08 P08 DEVIATION (needs a ruling) — --diagnose cannot see a hung ControlMaster', () => {
  let server: Server;
  let port = 0;
  beforeAll(async () => {
    server = createServer((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    port = typeof address === 'object' && address !== null ? address.port : 0;
  });
  afterAll(() => {
    server.close();
  });

  test('a master whose -O check hangs is named in the diagnosis', async () => {
    const runner: SshRunner = async (args) => {
      if (args[0] === '-G') {
        return ok(`hostname 127.0.0.1\nuser opsuser\nport ${port}\n`);
      }
      if (args.includes('-O')) {
        return { code: -1, stdout: '', stderr: '', timedOut: true };
      }
      return ok('sshepherd-ok\n');
    };
    const result = await diagnoseHost('edge-box', { runner });
    expect(JSON.stringify(result)).toMatch(/master/i);
  });
});

const ident = (user: string, hostname: string) => ({
  identity: { user, hostname, port: '2222' },
  maskAddresses: true,
});

describe('audit08 FIX-5 LEAK — the alias port in docker and ss listener forms', () => {
  test.each([
    '0.0.0.0:2222->22/tcp, :::2222->22/tcp',
    'LISTEN 0      128          *:2222            *:*',
  ])('%s', (line) => {
    expect(scrubText(line, ident('opsuser', 'srv-01.example.net')).value).not.toContain('2222');
  });
});

describe('audit08 FIX-5 LEAK — a common user in `user X` at the end of a sentence', () => {
  test.each([
    'systemd-logind[512]: New session 4 of user deploy.',
    'systemd[1]: Started Session 9 of User deploy.',
  ])('%s', (line) => {
    expect(scrubText(line, ident('deploy', 'srv-01.example.net')).value).toContain('<user>');
  });
});

describe('audit08 FIX-5 LEAK — a short hostname where it names the host', () => {
  test.each([
    'Nov 27 10:00:00 web1 sshd[812]: Accepted publickey for opsuser from 192.0.2.4 port 50122 ssh2',
    "Warning: Permanently added '[web1]:2222' (ED25519) to the list of known hosts.",
    'ssh -l opsuser web1',
  ])('%s', (line) => {
    expect(scrubText(line, ident('opsuser', 'web1')).value).not.toMatch(/(?<![\w.-])web1(?![\w-])/);
  });
});

describe('audit08 FIX-5 OVER-MASK — a common user before a package spec is not a login', () => {
  test.each([
    'npm install app@latest',
    'npm i app@next',
    'npm warn app@beta is deprecated',
    'yarn add app@workspace:*',
    'pnpm add app@npm:app-core',
    'added app@v2.1.0',
  ])('%s', (line) => {
    expect(scrubText(line, ident('app', 'srv-01.example.net')).value).toBe(line);
  });
});

describe('audit08 FIX-5 LEAK — a lone END under a log prefix whose line above is another writer', () => {
  const END = '-----END RSA PRIVATE KEY-----';
  test('compose: another service logged right above END', () => {
    const out = maskPemLines([
      ...BODY.slice(0, 3).map((line) => `web-1     | ${line}`),
      'worker-1  | processed job 12',
      `web-1     | ${END}`,
    ]);
    expect(out.slice(0, 3)).toEqual(['***', '***', '***']);
  });
  test('stderr warning interleaved right above END', () => {
    const out = maskPemLines([
      ...BODY.slice(0, 3).map((line) => `INFO ${line}`),
      'WARN slow disk',
      `INFO ${END}`,
    ]);
    expect(out.slice(0, 3)).toEqual(['***', '***', '***']);
  });
  test('Go RFC3339Nano timestamps (trailing zeros trimmed, so the prefix length varies)', () => {
    const out = maskPemLines([
      `time=2026-11-27T10:00:01.123456Z level=info msg=${BODY[0]}`,
      `time=2026-11-27T10:00:01.12346Z level=info msg=${BODY[1]}`,
      `time=2026-11-27T10:00:01.1235Z level=info msg=${BODY[2]}`,
      `time=2026-11-27T10:00:01.2Z level=info msg=${END}`,
    ]);
    expect(out.slice(0, 3)).toEqual(['***', '***', '***']);
  });
});

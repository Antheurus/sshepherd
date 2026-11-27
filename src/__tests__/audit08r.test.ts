import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import { scrubText } from '../scrub.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

// Re-audit of Block 8 part a fix A (4c33cbf). Red tests here are findings; report-only probes log.

const SSH_G = 'hostname srv-01.example.net\nuser opsuser\nport 2222\n';
const BODY = [
  'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2',
  'd3h5ejAxMjM0NTY3ODkrL0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVm',
  'Z2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky9BQkNERUZHSElKS0xNTk9Q',
  'UVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsv',
];
const ts = (second: number): string =>
  `2026-11-27T10:${String(Math.floor(second / 60)).padStart(2, '0')}:${String(second % 60).padStart(2, '0')}.000000000Z`;

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

let scratch = '';
let bin = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit08r-'));
  bin = join(scratch, 'bin');
  Bun.spawnSync(['mkdir', '-p', bin]);
  const entries = [
    { i: 1, msg: 'starting worker' },
    { i: 2, msg: 'nginx: configuration ok' },
    { i: 3, msg: 'reload done' },
  ];
  // systemd before its JSON output moved to the JsonVariant writer printed `"KEY" : "value"`.
  const spaced = entries.map(
    ({ i, msg }) =>
      `{ "__CURSOR" : "s=1;i=${i}", "__REALTIME_TIMESTAMP" : "${1_795_600_000_000_000 + i * 1_000_000}", "_SYSTEMD_UNIT" : "nginx.service", "PRIORITY" : "6", "MESSAGE" : "${msg}" }`,
  );
  writeFileSync(join(scratch, 'spaced.ndjson'), `${spaced.join('\n')}\n`);
  writeFileSync(
    join(bin, 'journalctl'),
    `#!/bin/sh\nfor a in "$@"; do case "$a" in --grep=*|--case-sensitive=*) exit 1;; esac; done\ncat "${join(scratch, 'spaced.ndjson')}"\n`,
  );
  chmodSync(join(bin, 'journalctl'), 0o755);
});
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

function localRunner(): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok(SSH_G);
    }
    if (args.includes('-O')) {
      return ok('');
    }
    const proc = Bun.spawnSync(['sh', '-c', args.at(-1) ?? ''], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}` },
    });
    return {
      code: proc.exitCode ?? 1,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
      timedOut: false,
    };
  };
}

async function drive(
  group: string,
  name: string,
  args: Record<string, string>,
  runner: SshRunner,
  extra: { fields?: string[][]; limit?: number } = {},
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(
    op,
    { alias: 'edge-box', args },
    { transport: { runner }, auditLogPath: join(scratch, 'audit.jsonl'), ...extra },
  );
}

const ident = (user: string, hostname: string) => ({
  identity: { user, hostname, port: '2222' },
  maskAddresses: true,
});

describe('audit08r N-c — --fields without kept turns a cut --since page into a newest page', () => {
  test('paging forward with --limit 4 --fields lines,next_since,truncated reaches every line', async () => {
    const all = Array.from({ length: 30 }, (_, i) => `${ts(i + 1)} tick ${i + 1}`);
    const seen: string[] = [];
    let since = ts(1);
    for (let page = 0; page < 40; page++) {
      const from = all.findIndex((line) => (line.split(' ')[0] ?? '') >= since);
      const window = from === -1 ? [] : all.slice(from, from + 11);
      const runner: SshRunner = async (args) =>
        args[0] === '-G' ? ok(SSH_G) : ok(args.includes('-O') ? '' : `${window.join('\n')}\n`);
      const env = await drive(
        'logs',
        'docker',
        { container: 'c', since, 'max-lines': '10' },
        runner,
        { limit: 4, fields: [['lines'], ['next_since'], ['truncated']] },
      );
      const data = env.data as {
        lines: { text: string }[];
        next_since: string;
        truncated: boolean;
      };
      seen.push(...data.lines.map((line) => line.text));
      if (!data.truncated || !data.next_since) {
        break;
      }
      since = data.next_since;
    }
    expect(seen.length).toBe(30);
  });
});

describe('audit08r N1 — the journald --grep fallback misses `"MESSAGE" : "…"` JSON', () => {
  test('logs service nginx --grep nginx returns the one entry whose message says nginx', async () => {
    const env = await drive('logs', 'service', { unit: 'nginx', grep: 'nginx' }, localRunner());
    const lines = (env.data as { lines: { text: string }[] }).lines.map((line) => line.text);
    expect(lines).toEqual(['nginx: configuration ok']);
  });
});

describe('audit08r (a) — a timed-out logs window keeps key body lines raw in partial_stdout', () => {
  test.each([
    ['markers dropped by the window', BODY.map((line, i) => `${ts(i + 3)} ${line}`)],
    [
      'markers present under the docker prefix',
      [
        `${ts(2)} -----BEGIN RSA PRIVATE KEY-----`,
        ...BODY.map((line, i) => `${ts(i + 3)} ${line}`),
        `${ts(7)} -----END RSA PRIVATE KEY-----`,
      ],
    ],
  ])('%s', async (_label, lines) => {
    const runner: SshRunner = async (args) => {
      if (args[0] === '-G') {
        return ok(SSH_G);
      }
      if (args.includes('-O')) {
        return ok('');
      }
      return { code: 124, stdout: `${lines.join('\n')}\n`, stderr: '', timedOut: true };
    };
    const env = await drive('logs', 'docker', { container: 'c', since: ts(1) }, runner);
    const raw = BODY.filter((line) => JSON.stringify(env).includes(line.slice(0, 24))).length;
    expect({ code: env.error?.code, raw }).toEqual({ code: 'COMMAND_TIMEOUT', raw: 0 });
  });
});

describe('audit08r verifiers — real hashes masked under any name (part b #3 ruling)', () => {
  // Real hashes: openssl passwd -1/-5/-6, libxcrypt crypt() and chpasswd on the fixture's debian.
  const fromFiles = [
    '$1$abcdefgh$IQtUouv7y7Q9dRWkQEPCc.',
    '$5$abcdefghijklmnop$gu.71QnGu.GrGbdJF.mj20x/mWJF1VliZRmeYNpAtDB',
    '$6$abcdefghijklmnop$GRSTFj3H0pZ9BY1uhdqITG.qORbXkTk40qgaa1roNICfs/axSgdNnbKEYghuyLnrmnFXvSE09GdxJbCDOnxdc1',
    '$6$IcEn/B9UBs7EBFRA$XAwqspnCKmkl/.11F7.qTFpZdtZzQogmmS.kE0N7HjbRY4A2QQQk.TDWRzzPyKms4IwgJnkJ1l2yUOxhfoHSb0',
    '$6$rounds=5000$saltsalt$pauPrmdmG4BTE9h2HPmywiw152IFch6BJCEsaY6D.PLTfpV8sqvXwWdyfsgVgozkYH9B80bAip/08R2BPH2xk/',
    '$y$j9T$abcdefghijklmnop$wRwvHNqzMkHLG74uLLCRVTwaZ.a1aIothEUeYGf9oED',
    '$y$jFT$F5Jx5fExrKuPp53xLKQ..1$h5lfPlyx3zc33M.topyXmTycfT3TAuGIenlsBDA21V1',
    '$y$j9T$WkckXDy7Zbk3cRo9DGOZL1$QrlkPidTxy0pEKXzxZsXgkDe30/8UOi9F/VYdikSru8',
  ];
  const real = [
    'SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2FsdA==$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g=:c2VydmVyc2VydmVyc2VydmVyc2VydmVyc2VydmVyc2U=',
    'md5c6b5b1f3c95b4c3e1b6b9c1c2f0c8d4a',
    ...fromFiles,
  ];
  const contexts = (h: string): string[] => [
    `root:${h}:19000:0:99999:7:::`,
    `{"h":"${h}"}`,
    ` fixture_app | ${h}`,
    `NOTE=${h}`,
    `${h},${h}`,
    `{${h},${h}}`,
  ];
  test('every listed shape in every context', async () => {
    const bcrypt = await Bun.password.hash('pw', { algorithm: 'bcrypt', cost: 4 });
    const argon = await Bun.password.hash('pw', { algorithm: 'argon2id' });
    const argonI = await Bun.password.hash('pw', { algorithm: 'argon2i' });
    const argonD = await Bun.password.hash('pw', { algorithm: 'argon2d' });
    const leaks: string[] = [];
    for (const h of [...real, bcrypt, argon, argonI, argonD]) {
      for (const line of contexts(h)) {
        if (scrubText(line).value.includes(h.slice(-20))) {
          leaks.push(line);
        }
      }
    }
    expect(leaks).toEqual([]);
  });
});

describe('audit08r N3 — a verifier at the end of a sentence (trailing period) stays raw', () => {
  test.each([
    'SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2FsdA==$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g=:c2VydmVyc2VydmVyc2VydmVyc2VydmVyc2VydmVyc2U=',
    'md5c6b5b1f3c95b4c3e1b6b9c1c2f0c8d4a',
    '$argon2id$v=19$m=65536,t=2,p=1$xnRRApYS1VdXvixvu029zYSEvReVF/g0TTHnEOBpKfY$z0TQTvCCvrCLLh3pSOs/0CyBo/kC7+3U1m5/GVW0yt4',
  ])('stored verifier set to %s.', (h) => {
    expect(scrubText(`stored verifier set to ${h}.`).value).not.toContain(h.slice(-20));
  });
});

describe('audit08r scrubber variants beyond the receipt strings (report-only)', () => {
  test('log what each variant prints', () => {
    const cases: [string, string, string][] = [
      ['opsuser', 'srv-01.example.net', 'LISTEN 0 4096 [::]:2222 [::]:*'],
      ['opsuser', 'srv-01.example.net', 'tcp6 0 0 :::2222 :::* LISTEN'],
      ['opsuser', 'web1', 'Nov  7 10:00:00 web1 sshd[812]: Accepted publickey'],
      ['opsuser', 'web1', '2026-11-27T10:00:00.123456+07:00 web1 sshd[812]: Accepted'],
      ['opsuser', 'web1', '<34>1 2026-11-27T10:00:00Z web1 sshd 812 - - Accepted'],
      ['opsuser', 'web1', 'ssh -i /k -p 2222 -o BatchMode=yes web1 uptime'],
      ['opsuser', 'web1', 'scp app.tar web1:/tmp/'],
      ['deploy', 'srv-01.example.net', 'Removed session 4 of user deploy.'],
      ['deploy', 'srv-01.example.net', 'pam_unix(sshd:session): session closed for user deploy'],
      ['app', 'srv-01.example.net', 'npm i app@git+https://github.com/x/app'],
      ['app', 'srv-01.example.net', 'npm i app@^1.2.0'],
      ['app', 'srv-01.example.net', 'ssh app@web2'],
    ];
    for (const [user, host, line] of cases) {
      console.log(
        `VARIANT ${JSON.stringify(line)} -> ${JSON.stringify(scrubText(line, ident(user, host)).value)}`,
      );
    }
    expect(true).toBe(true);
  });
});

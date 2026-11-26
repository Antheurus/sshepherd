import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as limits from '../limits.ts';
import { selectFields } from '../output.ts';
import { executeOp, getOp } from '../registry.ts';
import { buildSetupResult } from '../setup-types.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

const ALIAS = 'audit06-host';
let scratch = '';
let savedAllowlist: string | undefined;

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit06-'));
  writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 192.0.2.10\n`);
  writeFileSync(
    join(scratch, 'files-allowlist.toml'),
    `[${ALIAS}]\npaths = ["/srv/app/release.tar", "/srv/app/deploy.pem"]\n`,
  );
  savedAllowlist = process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
  process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
});

afterAll(() => {
  if (savedAllowlist === undefined) {
    delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
  } else {
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = savedAllowlist;
  }
  rmSync(scratch, { recursive: true, force: true });
});

function scripted(last: SpawnOutcome): SshRunner {
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: 'hostname 192.0.2.10\n', stderr: '', timedOut: false },
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
  return executeOp(
    op,
    { alias: ALIAS, args },
    {
      transport: { runner: scripted(last) },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
      yes: true,
    },
  );
}

describe('audit06 PHASE-06 F1 — files download never writes a transport-truncated file', () => {
  test('a base64 payload cut at MAX_STDOUT_BYTES is not written as if complete', async () => {
    const size = 1_600_000;
    const full = `__OK__:${size}\n${Buffer.alloc(size, 7).toString('base64')}`;
    const cut = full.slice(0, limits.MAX_STDOUT_BYTES);
    const localPath = join(scratch, 'release.tar');
    const envelope = await drive(
      'files',
      'download',
      { path: '/srv/app/release.tar', local_path: localPath },
      { code: 143, stdout: cut, stderr: '', timedOut: false, stdoutTruncated: true },
    );
    const data = envelope.data as { written?: boolean } | null;
    const wrote = existsSync(localPath);
    expect({
      writtenFlag: data?.written === true,
      bytesOnDisk: wrote ? statSync(localPath).size : null,
    }).toEqual(
      wrote ? { writtenFlag: true, bytesOnDisk: size } : { writtenFlag: false, bytesOnDisk: null },
    );
  });
});

describe('audit06 PHASE-06 F2 — a capped log keeps the newest lines and stays self-consistent', () => {
  test('logs docker --tail N cut by --max-bytes returns the newest lines; counters match', async () => {
    const lines = Array.from(
      { length: 3_000 },
      (_, i) =>
        `2026-01-01T00:${String(Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}.000000000Z ${'log line body '.repeat(10)}${i}`,
    );
    const newestTs = '2026-01-01T00:49:59.000000000Z';
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web', tail: '3000' },
      { code: 0, stdout: `${lines.join('\n')}\n`, stderr: '', timedOut: false },
    );
    const data = envelope.data as {
      lines: { ts: string }[];
      lines_returned: number;
      next_since: string | null;
    };
    expect(envelope.output_truncated).toBe(true);
    expect({
      lastReturnedTs: data.lines.at(-1)?.ts,
      linesReturnedMatches: data.lines_returned === data.lines.length,
      nextSinceIsLastReturned: data.next_since === data.lines.at(-1)?.ts,
    }).toEqual({
      lastReturnedTs: newestTs,
      linesReturnedMatches: true,
      nextSinceIsLastReturned: true,
    });
  });
});

describe('audit06 PHASE-06 F3 — --fields does not match inherited properties', () => {
  test('toString / constructor / __proto__ on a plain object are reported unmatched', () => {
    const result = selectFields({ a: 1 }, [['toString'], ['constructor'], ['__proto__']]);
    expect(result).toEqual({
      data: {},
      unmatched: ['data.toString', 'data.constructor', 'data.__proto__'],
    });
  });
});

describe('audit06 PHASE-06 F4 — --fields leaves an error envelope data null', () => {
  test('selectFields over null data returns null data', () => {
    expect(selectFields(null, [['rows']]).data).toBeNull();
  });
});

describe('audit06 PHASE-06 F5 — per-line 4 KiB cap (roadmap P1.5)', () => {
  test('a 10 KiB log line comes back at most 4,096 bytes', async () => {
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web', tail: '5' },
      {
        code: 0,
        stdout: `2026-01-01T00:00:00.000000000Z ${'z'.repeat(10_240)}\n`,
        stderr: '',
        timedOut: false,
      },
    );
    const data = envelope.data as { lines: { text: string }[] };
    expect(Math.max(...data.lines.map((line) => Buffer.byteLength(line.text)))).toBeLessThanOrEqual(
      4_096,
    );
  });
});

describe('audit06 PHASE-06 F7 — setup JSON carries schema_version 1', () => {
  test('buildSetupResult output has schema_version 1', () => {
    const result = buildSetupResult({ command: 'setup files-allowlist scaffold', data: {} });
    expect((result as unknown as { schema_version?: number }).schema_version).toBe(1);
  });
});

describe('audit06 PHASE-06 F8 — the session_id cap is a named limit (G7)', () => {
  test('limits.ts names the session id ceiling and audit.ts has no literal 128', () => {
    const named = Object.keys(limits).some((key) => key.includes('SESSION'));
    const literal = /slice\(0,\s*128\)/.test(
      readFileSync(join(import.meta.dir, '..', 'audit.ts'), 'utf8'),
    );
    expect({ named, literal }).toEqual({ named: true, literal: false });
  });
});

describe('audit06 PHASE-05 F9 — PEM line masking counts toward scrubbed', () => {
  test('files tail of a PEM tail (BEGIN cut off) masks the body and reports scrubbed >= 1', async () => {
    const body = ['TUlJRWZha2Vib2R5bGluZW9uZQ', 'TUlJRWZha2Vib2R5bGluZXR3bw'];
    const end = `-----END ${'RSA PRIVATE'} KEY-----`;
    const envelope = await drive(
      'files',
      'tail',
      { path: '/srv/app/deploy.pem', n: '3' },
      { code: 0, stdout: `${body.join('\n')}\n${end}\n`, stderr: '', timedOut: false },
    );
    const printed = JSON.stringify(envelope);
    expect({
      leaked: body.some((line) => printed.includes(line)),
      scrubbedAtLeastOne: envelope.scrubbed >= 1,
    }).toEqual({ leaked: false, scrubbedAtLeastOne: true });
  });
});

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditMutating } from '../audit.ts';
import { defaultRevealAllowlistPath } from '../ops/config.ts';
import {
  capEnvelope,
  limitItems,
  parseFieldPaths,
  selectFields,
  serializeJson,
} from '../output.ts';
import { executeOp, getOp } from '../registry.ts';
import {
  type RunnerOptions,
  readCapped,
  run,
  type SpawnOutcome,
  type SshRunner,
} from '../transport.ts';
import type { Envelope } from '../types.ts';

const ALIAS = 'cap-host';
let scratch = '';
let savedRecipePath: string | undefined;

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-caps-'));
  writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 192.0.2.1\n`);
  writeFileSync(
    join(scratch, 'recipe.toml'),
    `name = "shop-api"\nalias = "${ALIAS}"\nworkdir = "/srv/shop"\n\n[[step]]\nname = "pull"\nkind = "shell"\nrun = "true"\nmutates = false\n\n[rollback]\nstrategy = "compose-file"\nfile = "docker-compose.yml"\n`,
  );
  savedRecipePath = process.env.SSHEPHERD_RECIPE_PATH;
  process.env.SSHEPHERD_RECIPE_PATH = join(scratch, 'recipe.toml');
});

afterAll(() => {
  if (savedRecipePath === undefined) {
    delete process.env.SSHEPHERD_RECIPE_PATH;
  } else {
    process.env.SSHEPHERD_RECIPE_PATH = savedRecipePath;
  }
  rmSync(scratch, { recursive: true, force: true });
});

const bytesOf = (envelope: unknown): number => Buffer.byteLength(serializeJson(envelope));

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(new TextEncoder().encode(chunk));
      }
      controller.close();
    },
  });
}

/** `-G`, master check, then the command: the same three calls `run` makes. */
function scripted(last: SpawnOutcome, seen: RunnerOptions[] = []): SshRunner {
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: 'hostname 192.0.2.1\n', stderr: '', timedOut: false },
    { code: 0, stdout: '', stderr: '', timedOut: false },
    last,
  ];
  let index = 0;
  return async (_args, _timeout, options = {}) => {
    seen.push(options);
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
  deps: Parameters<typeof executeOp>[2] = {},
  seen: RunnerOptions[] = [],
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(
    op,
    { alias: ALIAS, args },
    {
      transport: { runner: scripted(last, seen) },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
      yes: true,
      ...deps,
    },
  );
}

describe('readCapped', () => {
  test('head: keeps the first cap bytes, stops at the cap and reports it', async () => {
    let capped = 0;
    const result = await readCapped(streamOf('abcd', 'efgh', 'ijkl'), 6, 'head', () => {
      capped += 1;
    });
    expect(result).toEqual({ text: 'abcdef', truncated: true });
    expect(capped).toBe(1);
  });

  test('head: output exactly at the cap is not truncated', async () => {
    expect(await readCapped(streamOf('abc', 'def'), 6, 'head', () => {})).toEqual({
      text: 'abcdef',
      truncated: false,
    });
  });

  test('tail: reads everything, keeps the last cap bytes, never calls onCap', async () => {
    let capped = 0;
    const result = await readCapped(streamOf('abcd', 'efgh', 'ijkl'), 6, 'tail', () => {
      capped += 1;
    });
    expect(result).toEqual({ text: 'ghijkl', truncated: true });
    expect(capped).toBe(0);
  });
});

describe('transport run — stdout cap', () => {
  test('a kill-head cut is a clean call that returned a prefix, not a failed command', async () => {
    const outcome = { code: 143, stdout: 'x', stderr: '', timedOut: false, stdoutTruncated: true };
    const result = await run(ALIAS, 'cmd', 5, {
      runner: scripted(outcome),
      sshConfigPath: join(scratch, 'ssh_config'),
    });
    expect(result.error).toBeNull();
    expect(result.raw).toMatchObject({ code: 0, outputTruncated: true });
  });

  test('a drain-tail cut keeps the remote exit code', async () => {
    const outcome = {
      code: 3,
      stdout: 'x',
      stderr: 'boom',
      timedOut: false,
      stdoutTruncated: true,
    };
    const result = await run(
      ALIAS,
      'cmd',
      5,
      { runner: scripted(outcome), sshConfigPath: join(scratch, 'ssh_config') },
      { stdoutCap: 'drain-tail' },
    );
    expect(result.error?.code).toBe('COMMAND_FAILED');
    expect(result.raw.outputTruncated).toBe(true);
  });
});

describe('executeOp — byte cap, applied after the scrubber', () => {
  const bigLog = `${'2026-01-01T00:00:00Z '.concat('line of log output '.repeat(50))}\n`.repeat(
    2_000,
  );

  test('a log read that printed more than the cap returns output_truncated and at most 65,536 bytes', async () => {
    const seen: RunnerOptions[] = [];
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web' },
      { code: 0, stdout: bigLog, stderr: '', timedOut: false, stdoutTruncated: true },
      {},
      seen,
    );
    expect(envelope.ok).toBe(true);
    expect(envelope.output_truncated).toBe(true);
    expect(bytesOf(envelope)).toBeLessThanOrEqual(65_536);
    expect(seen.at(-1)).toEqual({ stdoutCap: 'drain-tail' });
  });

  test('a read op whose head matters is killed at the cap and keeps its first bytes', async () => {
    const seen: RunnerOptions[] = [];
    await drive(
      'check',
      'ports',
      {},
      {
        code: 143,
        stdout: 'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*\n',
        stderr: '',
        timedOut: false,
        stdoutTruncated: true,
      },
      {},
      seen,
    );
    expect(seen.at(-1)).toEqual({ stdoutCap: 'kill-head' });
  });

  test('a log stream cut at the transport ceiling keeps its newest lines, not its oldest, and drops the fragment at its start', async () => {
    const seen: RunnerOptions[] = [];
    const stream = [
      'ldest line cut in half by the ceiling',
      '2026-01-01T00:00:01Z middle',
      '2026-01-01T00:00:02Z newest',
    ].join('\n');
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web' },
      { code: 0, stdout: stream, stderr: '', timedOut: false, stdoutTruncated: true },
      {},
      seen,
    );
    const data = envelope.data as { lines: { text: string }[]; next_since: string };
    expect(seen.at(-1)).toEqual({ stdoutCap: 'drain-tail' });
    expect(data.lines.map((line) => line.text)).toEqual(['middle', 'newest']);
    expect(data.next_since).toBe('2026-01-01T00:00:02Z');
    expect(envelope.output_truncated).toBe(true);
  });

  test('a mutating op is never killed at the cap: it drains and keeps the tail', async () => {
    const seen: RunnerOptions[] = [];
    const envelope = await drive(
      'deploy',
      'rollback',
      { recipe: 'shop-api' },
      { code: 0, stdout: `${bigLog}FINAL-STEP-OK\n`, stderr: '', timedOut: false },
      { auditLogPath: join(scratch, 'audit-deploy.jsonl') },
      seen,
    );
    expect(seen.at(-1)).toEqual({ stdoutCap: 'drain-tail' });
    expect(envelope.output_truncated).toBe(true);
    expect(bytesOf(envelope)).toBeLessThanOrEqual(65_536);
    expect(JSON.stringify(envelope)).toContain('FINAL-STEP-OK');
  });

  test('--max-bytes lowers the cap', async () => {
    const envelope = await drive(
      'logs',
      'docker',
      { container: 'web' },
      { code: 0, stdout: bigLog, stderr: '', timedOut: false },
      { maxBytes: 10_000 },
    );
    expect(bytesOf(envelope)).toBeLessThanOrEqual(10_000);
    expect(envelope.output_truncated).toBe(true);
  });

  test('output that fits is returned untouched, with no output_truncated key', async () => {
    const envelope = await drive(
      'hosts',
      'test',
      {},
      { code: 0, stdout: 'sshepherd-ok\n', stderr: '', timedOut: false },
    );
    expect('output_truncated' in envelope).toBe(false);
    expect(envelope.schema_version).toBe(1);
  });

  test('a cut-short ndjson stream drops its unfinished last line instead of failing to parse', async () => {
    const lines = `${JSON.stringify({ MESSAGE: 'one', __REALTIME_TIMESTAMP: '1' })}\n{"MESSAGE":"cut mid-li`;
    const envelope = await drive(
      'services',
      'compose-ps',
      { file: '/srv/app/docker-compose.yml' },
      { code: 143, stdout: lines, stderr: '', timedOut: false, stdoutTruncated: true },
    );
    expect(envelope.error).toBeNull();
    expect(envelope.output_truncated).toBe(true);
  });

  test('a cut-short native-json payload is OUTPUT_TOO_LARGE, with a way forward', async () => {
    const envelope = await drive(
      'db',
      'tables',
      { target: 'app', db_user: 'u', db_name: 'd', container: 'c' },
      {
        code: 143,
        stdout: '[{"table":"a","si',
        stderr: '',
        timedOut: false,
        stdoutTruncated: true,
      },
    );
    expect(envelope.error?.code).toBe('OUTPUT_TOO_LARGE');
    expect(envelope.error?.hint.length).toBeGreaterThan(0);
  });
});

describe('capEnvelope', () => {
  const base = (data: unknown): Envelope<unknown> => ({
    schema_version: 1,
    ok: true,
    alias: 'a',
    ran_at: '2026-01-01T00:00:00.000Z',
    command: 'x y',
    duration_ms: 1,
    scrubbed: 0,
    data,
    error: null,
  });

  test('a string keeps its head by default and its tail on request', () => {
    const text = `${'a'.repeat(9_000)}${'b'.repeat(9_000)}`;
    const head = capEnvelope(base({ output: text }), 9_000, 'head').data as { output: string };
    const tail = capEnvelope(base({ output: text }), 9_000, 'tail').data as { output: string };
    expect(head.output.startsWith('a')).toBe(true);
    expect(head.output.endsWith('a')).toBe(true);
    expect(tail.output.endsWith('b')).toBe(true);
  });

  test('a list loses trailing items, the error block is never cut', () => {
    const rows = Array.from({ length: 5_000 }, (_, id) => ({ id, note: 'x'.repeat(20) }));
    const envelope: Envelope<unknown> = {
      ...base({ rows }),
      ok: false,
      error: {
        code: 'COMMAND_FAILED',
        message: 'm',
        hint: 'h',
        retryable: false,
        stderr_tail: 'e'.repeat(2_000),
      },
    };
    const capped = capEnvelope(envelope, 20_000);
    expect(bytesOf(capped)).toBeLessThanOrEqual(20_000);
    expect(capped.output_truncated).toBe(true);
    expect(capped.error).toEqual(envelope.error);
    const kept = (capped.data as { rows: { id: number }[] }).rows;
    expect(kept[0]?.id).toBe(0);
  });

  test('multi-byte text still ends up under the cap as printed', () => {
    const capped = capEnvelope(base({ text: '日本語'.repeat(10_000) }), 8_192);
    expect(bytesOf(capped)).toBeLessThanOrEqual(8_192);
  });
});

describe('--fields and --limit', () => {
  const data = {
    rows: [
      { id: 1, name: 'a', secret: 'x' },
      { id: 2, name: 'b', secret: 'y' },
    ],
    total: 2,
    extra: 'z',
  };

  test('keeps only the named paths of data, walking lists per item', () => {
    const paths = parseFieldPaths('data.rows.id,total') ?? [];
    expect(selectFields(data, paths)).toEqual({
      data: { rows: [{ id: 1 }, { id: 2 }], total: 2 },
      unmatched: [],
    });
  });

  test('data.rows keeps only that key under data', () => {
    expect(selectFields(data, parseFieldPaths('data.rows') ?? []).data).toEqual({
      rows: data.rows,
    });
  });

  test('a path that matches nothing is reported, not silently an empty answer', () => {
    expect(selectFields(data, parseFieldPaths('nope') ?? [])).toEqual({
      data: {},
      unmatched: ['data.nope'],
    });
  });

  test('a malformed list is refused', () => {
    expect(parseFieldPaths('a..b')).toBeNull();
    expect(parseFieldPaths('')).toBeNull();
    expect(parseFieldPaths('a,$(x)')).toBeNull();
  });

  test('--limit cuts each list directly under data and says so', () => {
    expect(limitItems(data, 1)).toEqual({
      data: { rows: [data.rows[0]], total: 2, extra: 'z' },
      cut: true,
    });
    expect(limitItems(data, 5).cut).toBe(false);
  });

  test('executeOp applies --fields before the cap and flags unmatched paths', async () => {
    const envelope = await drive(
      'hosts',
      'test',
      {},
      { code: 0, stdout: 'sshepherd-ok\n', stderr: '', timedOut: false },
      { fields: [['reachable'], ['nope']] },
    );
    expect(envelope.data).toEqual({ reachable: true });
    expect(envelope.fields_unmatched).toEqual(['data.nope']);
  });
});

describe('audit rows', () => {
  function rows(path: string): Record<string, unknown>[] {
    return readFileSync(path, 'utf8')
      .split('\n')
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  }

  test('a deploy row names the recipe and carries duration, exit and a sha256 — no raw arg value', async () => {
    const path = join(scratch, 'audit-row.jsonl');
    await drive(
      'deploy',
      'rollback',
      { recipe: 'shop-api' },
      { code: 7, stdout: 'x', stderr: 'fail', timedOut: false },
      { auditLogPath: path },
    );
    const [row] = rows(path);
    expect(row).toMatchObject({
      command: 'deploy rollback',
      recipe: 'shop-api',
      remote_exit: 7,
      error_code: 'COMMAND_FAILED',
      outcome: 'error',
    });
    expect(row?.args_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(typeof row?.args_hash).toBe('string');
    expect(typeof row?.duration_ms).toBe('number');
    expect(typeof row?.bytes).toBe('number');
  });

  test('a content-exposing read op is audited by hash only; hidden db connection args never appear', async () => {
    const path = join(scratch, 'audit-read.jsonl');
    const op = getOp('db', 'query');
    if (!op) {
      throw new Error('db query missing');
    }
    await executeOp(
      op,
      {
        alias: ALIAS,
        args: {
          target: 'app',
          sql: 'SELECT secret_column FROM t',
          container: 'private-container',
          db_user: 'private_user',
          db_name: 'private_db',
        },
      },
      {
        transport: { runner: scripted({ code: 0, stdout: '[]', stderr: '', timedOut: false }) },
        sshConfigPath: join(scratch, 'ssh_config'),
        auditLogPath: path,
      },
    );
    const text = readFileSync(path, 'utf8');
    expect(JSON.parse(text)).toMatchObject({ command: 'db query', target: 'app', remote_exit: 0 });
    for (const forbidden of ['secret_column', 'private-container', 'private_user', 'private_db']) {
      expect(text).not.toContain(forbidden);
    }
  });

  test('the log rotates at the size limit and keeps the active file plus four archives', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-rotate-'));
    try {
      const logPath = join(dir, 'audit.jsonl');
      for (let index = 0; index < 8; index++) {
        auditMutating(
          { alias: `a${index}`, command: 'x y', argsSummary: {}, outcome: 'ok' },
          { logPath, rotateBytes: 100, keepFiles: 5 },
        );
      }
      const names = [logPath, ...[1, 2, 3, 4, 5].map((n) => `${logPath}.${n}`)];
      expect(names.map((name) => existsSync(name))).toEqual([true, true, true, true, true, false]);
      expect(rows(`${logPath}.1`)[0]?.alias).toBe('a6');
      expect(rows(logPath)[0]?.alias).toBe('a7');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('audit tail returns the newest matching rows oldest-first, old crc32-only rows included', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-tail-'));
    const previous = process.env.SSHEPHERD_AUDIT_PATH;
    try {
      const logPath = join(dir, 'audit.jsonl');
      writeFileSync(
        logPath,
        [
          { ts: 't1', alias: 'a', command: 'deploy run', args_hash: 'abc', outcome: 'ok' },
          {
            ts: 't2',
            alias: 'b',
            command: 'files cat',
            args_sha256: 'f'.repeat(64),
            outcome: 'ok',
          },
          {
            ts: 't3',
            alias: 'a',
            command: 'deploy run',
            args_sha256: 'e'.repeat(64),
            outcome: 'ok',
          },
        ]
          .map((row) => JSON.stringify(row))
          .join('\n')
          .concat('\nnot json\n'),
      );
      process.env.SSHEPHERD_AUDIT_PATH = logPath;
      const envelope = await executeOp(
        getOp('audit', 'tail') as NonNullable<ReturnType<typeof getOp>>,
        { alias: '', args: { op: 'deploy run', n: '5' } },
      );
      const data = envelope.data as { rows: Record<string, unknown>[]; row_count: number };
      expect(data.rows.map((row) => row.ts)).toEqual(['t1', 't3']);
      expect(data.rows[0]?.args_hash).toBe('abc');
      expect(data.row_count).toBe(2);
      const bad = await executeOp(getOp('audit', 'tail') as NonNullable<ReturnType<typeof getOp>>, {
        alias: '',
        args: { n: '0' },
      });
      expect(bad.error?.code).toBe('INVALID_ARGS');
    } finally {
      if (previous === undefined) {
        delete process.env.SSHEPHERD_AUDIT_PATH;
      } else {
        process.env.SSHEPHERD_AUDIT_PATH = previous;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('test isolation', () => {
  test('the reveal allowlist path comes from the preload, never the machine home directory', () => {
    const path = defaultRevealAllowlistPath();
    expect(path.startsWith(homedir())).toBe(false);
    expect(path.startsWith(tmpdir())).toBe(true);
    expect(existsSync(path)).toBe(false);
  });
});

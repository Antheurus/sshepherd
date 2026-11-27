import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { journalTime, PAGE_FULL_MARKER } from '../log-command.ts';
import { nextSinceAfter } from '../parsers/logs-shape.ts';
import { type ExecuteDeps, executeOp, getOp } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

// The op's real remote script runs here under sh, against a stand-in `docker` that behaves like the
// real one: --tail first, then an inclusive --since/--until window.
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
f="$PAGING_LOGDIR/$1.log"
if [ ! -f "$f" ]; then echo "Error response from daemon: No such container: $1" >&2; exit 1; fi
if [ "$tail" = all ]; then cat "$f"; else tail -n "$tail" "$f"; fi |
  awk -v s="$since" -v u="$until" '(s == "" || $1 >= s) && (u == "" || $1 <= u)'
`;

const ts = (second: number): string =>
  `2026-11-27T10:${String(Math.floor(second / 60)).padStart(2, '0')}:${String(second % 60).padStart(2, '0')}.000000000Z`;
const TICKS = Array.from({ length: 600 }, (_, i) => `tick ${i + 1}`);

let scratch = '';
let bin = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-paging-'));
  bin = join(scratch, 'bin');
  mkdirSync(bin);
  mkdirSync(join(scratch, 'logs'));
  writeFileSync(join(bin, 'docker'), FAKE_DOCKER);
  chmodSync(join(bin, 'docker'), 0o755);
  const ticker = TICKS.map((text, i) => `${ts(i + 1)} ${text}`);
  writeFileSync(join(scratch, 'logs', 'ticker.log'), `${ticker.join('\n')}\n`);
  const wide = TICKS.map((text, i) => `${ts(i + 1)} ${text} ${'x'.repeat(400)}`);
  writeFileSync(join(scratch, 'logs', 'wide.log'), `${wide.join('\n')}\n`);
  // Lines 100 and 101 share one instant: a page boundary must not split it.
  const shared = TICKS.slice(0, 200).map((text, i) => `${ts(i + 1 === 101 ? 100 : i + 1)} ${text}`);
  writeFileSync(join(scratch, 'logs', 'shared.log'), `${shared.join('\n')}\n`);
});
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

function localRunner(): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok('hostname srv-01.example.net\nuser opsuser\n');
    }
    if (args.includes('-O')) {
      return ok('');
    }
    const proc = Bun.spawnSync(['sh', '-c', args.at(-1) ?? ''], {
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH ?? ''}`,
        PAGING_LOGDIR: join(scratch, 'logs'),
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

interface Page {
  lines: { ts: string | null; text: string }[];
  next_since: string | null;
  truncated: boolean;
  kept: string;
  lines_returned: number;
}

async function drive(
  args: Record<string, string>,
  deps: Partial<ExecuteDeps> = {},
  runner: SshRunner = localRunner(),
): Promise<Envelope<unknown>> {
  const op = getOp('logs', 'docker');
  if (!op) {
    throw new Error('logs docker missing');
  }
  return executeOp(
    op,
    { alias: 'edge-box', args },
    { transport: { runner }, auditLogPath: join(scratch, 'audit.jsonl'), ...deps },
  );
}

/** Pages `container` forward from its first line until a page comes back empty. */
async function pageThrough(
  container: string,
  maxLines: string,
  deps: Partial<ExecuteDeps> = {},
): Promise<{ texts: string[]; pages: Page[] }> {
  const texts: string[] = [];
  const pages: Page[] = [];
  let since = ts(1);
  for (let round = 0; round < 40; round += 1) {
    const page = (await drive({ container, since, 'max-lines': maxLines }, deps)).data as Page;
    pages.push(page);
    texts.push(...page.lines.map((line) => line.text.split(' x')[0] ?? line.text));
    if (page.next_since === null) {
      break;
    }
    since = page.next_since;
  }
  return { texts, pages };
}

describe('logs paging from --since: never repeats, never skips', () => {
  test('a 600-line window paged 100 at a time returns every line exactly once, in order', async () => {
    const { texts, pages } = await pageThrough('ticker', '100');
    expect(texts).toEqual(TICKS);
    expect(pages.map((page) => [page.lines_returned, page.truncated, page.kept])).toEqual([
      [100, true, 'oldest'],
      [100, true, 'oldest'],
      [100, true, 'oldest'],
      [100, true, 'oldest'],
      [100, true, 'oldest'],
      [100, false, 'oldest'],
      [0, false, 'oldest'],
    ]);
    expect(pages[0]?.next_since).toBe('2026-11-27T10:01:40.000000001Z');
  });

  test('--limit cutting each page keeps its oldest lines, so paging still covers the window exactly', async () => {
    const { texts } = await pageThrough('ticker', '100', { limit: 30 });
    expect(texts).toEqual(TICKS);
  });

  test('--max-bytes cutting each page keeps its oldest lines, so paging still covers the window exactly', async () => {
    const { texts, pages } = await pageThrough('wide', '100', { maxBytes: 16_384 });
    expect(texts).toEqual(TICKS);
    expect(pages.length).toBeGreaterThan(7);
  });

  test('a page boundary inside one shared instant moves that instant to the next page', async () => {
    const first = (await drive({ container: 'shared', since: ts(1), 'max-lines': '100' }))
      .data as Page;
    expect(first.lines.at(-1)?.text).toBe('tick 99');
    expect(first.next_since).toBe(ts(100));
    const second = (await drive({ container: 'shared', since: ts(100), 'max-lines': '100' }))
      .data as Page;
    expect(second.lines.slice(0, 2).map((line) => line.text)).toEqual(['tick 100', 'tick 101']);
  });

  test('without --since the newest lines are kept, and next_since follows them exclusively', async () => {
    const page = (await drive({ container: 'ticker', 'max-lines': '50', tail: '50' })).data as Page;
    expect(page.kept).toBe('newest');
    expect(page.lines.at(-1)?.text).toBe('tick 600');
    const after = (await drive({ container: 'ticker', since: page.next_since ?? '' })).data as Page;
    expect(after.lines).toEqual([]);
  });

  test('--until alone reads the newest lines at or before it, not docker --tail applied first', async () => {
    const page = (await drive({ container: 'ticker', until: ts(300), 'max-lines': '20' }))
      .data as Page;
    expect(page.lines.map((line) => line.text)).toEqual(TICKS.slice(280, 300));
  });

  test('--tail with --since is refused: one reads the newest lines, the other reads forward', async () => {
    const envelope = await drive({ container: 'ticker', since: ts(1), tail: '10' });
    expect(envelope.error?.code).toBe('INVALID_ARGS');
  });

  test('a page the byte bound stopped is truncated, and the marker is not a line', async () => {
    const stdout = `${ts(1)} one\n${ts(2)} two\n${PAGE_FULL_MARKER}\n`;
    const runner: SshRunner = async (args) => (args[0] === '-G' ? ok('hostname h\n') : ok(stdout));
    const page = (await drive({ container: 'ticker', since: ts(1) }, {}, runner)).data as Page;
    expect({
      texts: page.lines.map((line) => line.text),
      truncated: page.truncated,
      next: page.next_since,
    }).toEqual({ texts: ['one', 'two'], truncated: true, next: '2026-11-27T10:00:02.000000001Z' });
  });

  test('a filtered read that succeeds prints nothing on stderr; one whose source fails names why', async () => {
    const missing = await drive({ container: 'nosuch', grep: 'tick', since: ts(1) });
    expect(missing.error?.stderr_tail).toContain('No such container: nosuch');
    const found = await drive({ container: 'ticker', grep: 'tick 59', since: ts(1) });
    expect((found.data as Page).lines.map((line) => line.text)).toEqual([
      'tick 59',
      ...TICKS.slice(589, 599).filter((text) => text.startsWith('tick 59')),
    ]);
  });
});

describe('cursor arithmetic', () => {
  test('next_since is one nanosecond past the line, carrying into the second', () => {
    expect(nextSinceAfter('2026-11-27T10:00:01.000000000Z')).toBe('2026-11-27T10:00:01.000000001Z');
    expect(nextSinceAfter('2026-11-27T10:00:59.999999999Z')).toBe('2026-11-27T10:01:00.000000000Z');
    expect(nextSinceAfter('2026-11-27T12:00:01.5+02:00')).toBe('2026-11-27T10:00:01.500000001Z');
    expect(nextSinceAfter(null)).toBeNull();
    expect(nextSinceAfter('not a time')).toBeNull();
  });

  test('journalctl gets an RFC 3339 bound as @epoch.micros, rounded so the same entries match', () => {
    // journald counts microseconds: an entry at .123456 is >= since .123456001 only from .123457.
    expect(journalTime('2026-11-27T10:00:01.123456001Z', 'since')).toBe('@1795773601.123457');
    expect(journalTime('2026-11-27T10:00:01.123456999Z', 'until')).toBe('@1795773601.123456');
    expect(journalTime('2026-11-27T10:00:01.999999500Z', 'since')).toBe('@1795773602.000000');
    expect(journalTime('1h ago', 'since')).toBe('1h ago');
  });
});

describe('the journald --grep fallback matches MESSAGE only, escapes decoded', () => {
  const entries = [
    'upstream ok 1',
    'nginx: [emerg] bind() failed',
    'after 1',
    'say "quoted" here',
    'back\\slash end',
    '{"MESSAGE":"fake"} in text',
  ].map((MESSAGE, i) =>
    JSON.stringify({
      __CURSOR: `s=emerg;i=${i}`,
      __REALTIME_TIMESTAMP: String(1_795_773_601_000_000 + i),
      _SYSTEMD_UNIT: 'nginx.service',
      MESSAGE,
    }),
  );

  function journal(args: Record<string, string>): string[] {
    const dir = join(scratch, 'journal-bin');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(scratch, 'journal.ndjson'), `${entries.join('\n')}\n`);
    writeFileSync(
      join(dir, 'journalctl'),
      `#!/bin/sh\nfor a in "$@"; do case "$a" in --grep*|--case-sensitive*) exit 1 ;; esac; done\ncat "${join(scratch, 'journal.ndjson')}"\n`,
    );
    chmodSync(join(dir, 'journalctl'), 0o755);
    const op = getOp('logs', 'service');
    const remote = op?.buildRemote({ alias: 'edge-box', args: { unit: 'nginx', ...args } }) ?? '';
    const proc = Bun.spawnSync(['sh', '-c', remote], {
      env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ''}` },
    });
    return proc.stdout
      .toString()
      .split('\n')
      .filter((line) => line.startsWith('{'))
      .map((line) => (JSON.parse(line) as { MESSAGE: string }).MESSAGE);
  }

  test('metadata (a cursor holding the word) and a message-shaped value never match', () => {
    expect(journal({ grep: 'emerg' })).toEqual(['nginx: [emerg] bind() failed']);
    expect(journal({ grep: 'fake' })).toEqual(['{"MESSAGE":"fake"} in text']);
  });

  test('an escaped quote and backslash are matched as the message holds them; context surrounds', () => {
    expect(journal({ grep: '"quoted"|back\\\\slash' })).toEqual([
      'say "quoted" here',
      'back\\slash end',
    ]);
    expect(journal({ grep: 'emerg', context: '1' })).toEqual([
      'upstream ok 1',
      'nginx: [emerg] bind() failed',
      'after 1',
    ]);
  });
});

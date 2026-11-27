import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_GREP_PATTERN_CHARS } from '../limits.ts';
import { journalCommand, plainCommand, readLogQuery } from '../log-command.ts';
import { executeOp, getOp, listOps } from '../registry.ts';
import { niced } from '../remote-nice.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import { type OpContext, OpError } from '../types.ts';

const ctxOf = (args: Record<string, string | boolean>): OpContext => ({ alias: 'web', args });

function op(group: string, name: string) {
  const found = getOp(group, name);
  if (!found) {
    throw new Error(`${group} ${name} missing`);
  }
  return found;
}

function remoteOf(group: string, name: string, args: Record<string, string>): string {
  const cmd = op(group, name).buildRemote(ctxOf(args));
  if (cmd === null) {
    throw new Error('no remote command');
  }
  return cmd;
}

let bin = '';
let work = '';

function script(dir: string, name: string, body: string): void {
  writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`);
  chmodSync(join(dir, name), 0o755);
}

const JOURNAL = [
  '{"__REALTIME_TIMESTAMP":"1795658403000000","PRIORITY":"6","MESSAGE":"Connection from peer"}',
  '{"__REALTIME_TIMESTAMP":"1795658404000000","PRIORITY":"6","MESSAGE":"Accepted publickey for ops"}',
  '{"__REALTIME_TIMESTAMP":"1795658405000000","PRIORITY":"6","MESSAGE":"session opened"}',
].join('\n');

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), 'sshepherd-logs-filters-'));
  bin = join(work, 'bin');
  mkdirSync(bin);
  writeFileSync(join(work, 'journal.ndjson'), `${JOURNAL}\n`);
  script(
    bin,
    'docker',
    [
      'echo "$@" >> "$FAKE_LOG"',
      'if [ "$FAKE_MODE" = fail ]; then echo "Error response from daemon: No such container" >&2; exit 1; fi',
      'echo "2026-11-27T10:00:00.000000000Z alpha line"',
      'echo "2026-11-27T10:00:01.000000000Z boom on stderr" >&2',
      'echo "2026-11-27T10:00:02.000000000Z omega line"',
    ].join('\n'),
  );
  // A journalctl whose --grep works (records every call), and one built without pattern matching.
  const withGrep = [
    'echo "$@" >> "$FAKE_LOG"',
    'pattern=; n=1000',
    'while [ $# -gt 0 ]; do',
    '  case "$1" in --grep=*) pattern=$(printf %s "$1" | cut -c8-) ;; -n) shift; n="$1" ;; esac',
    '  shift',
    'done',
    'if [ "$n" = 0 ]; then exit 0; fi',
    `if [ -n "$pattern" ]; then grep -E -e "$pattern" "${join(work, 'journal.ndjson')}"; else cat "${join(work, 'journal.ndjson')}"; fi`,
    'exit 0',
  ].join('\n');
  mkdirSync(join(work, 'bin-grep'));
  script(join(work, 'bin-grep'), 'journalctl', withGrep);
  mkdirSync(join(work, 'bin-nogrep'));
  script(
    join(work, 'bin-nogrep'),
    'journalctl',
    [
      'echo "$@" >> "$FAKE_LOG"',
      'for a in "$@"; do case "$a" in --grep*|--case-sensitive*) echo "Compiled without pattern matching support" >&2; exit 1 ;; esac; done',
      `cat "${join(work, 'journal.ndjson')}"`,
    ].join('\n'),
  );
});

function runLocal(
  remote: string,
  dirs: string[],
  env: Record<string, string> = {},
): { code: number; out: string; err: string; log: string } {
  const logFile = join(work, `calls-${Math.random().toString(36).slice(2)}.log`);
  writeFileSync(logFile, '');
  const proc = Bun.spawnSync(['sh', '-c', remote], {
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      ...process.env,
      PATH: `${dirs.join(':')}:${process.env.PATH}`,
      FAKE_LOG: logFile,
      ...env,
    },
  });
  return {
    code: proc.exitCode ?? -1,
    out: proc.stdout.toString(),
    err: proc.stderr.toString(),
    log: readFileSync(logFile, 'utf8'),
  };
}

describe('logs --grep: the pattern is one argv slot, capped at 512 characters', () => {
  const marker = join(
    tmpdir(),
    `sshepherd-grep-pwn-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  const hostile = [
    "it's",
    'a;b',
    `$(touch ${marker})`,
    `\`touch ${marker}\``,
    `a'; touch ${marker}; '`,
    `a"; touch ${marker}; "`,
    'x'.repeat(MAX_GREP_PATTERN_CHARS),
  ];

  for (const pattern of hostile) {
    test(`logs docker: ${JSON.stringify(pattern.slice(0, 40))} runs nothing and reaches grep intact`, () => {
      const remote = remoteOf('logs', 'docker', { container: 'web', grep: pattern });
      const result = runLocal(remote, [bin]);
      expect({ code: result.code, err: result.err }).toEqual({ code: 0, err: '' });
      expect(existsSync(marker)).toBe(false);
    });
  }

  test('a pattern that is hostile as shell is still searched for as text', () => {
    const remote = remoteOf('logs', 'docker', { container: 'web', grep: 'alpha|omega' });
    expect(runLocal(remote, [bin]).out.trim().split('\n')).toEqual([
      '2026-11-27T10:00:00.000000000Z alpha line',
      '2026-11-27T10:00:02.000000000Z omega line',
    ]);
  });

  const refused: [string, string][] = [
    ['513 characters', 'x'.repeat(MAX_GREP_PATTERN_CHARS + 1)],
    ['a newline', 'a\nb'],
    ['a carriage return', 'a\rb'],
    ['a NUL', 'a\0b'],
  ];
  for (const [what, pattern] of refused) {
    test(`${what} is refused before any command is built`, () => {
      expect(() => readLogQuery(ctxOf({ grep: pattern }))).toThrow(OpError);
      try {
        readLogQuery(ctxOf({ grep: pattern }));
      } catch (err) {
        expect((err as OpError).code).toBe('INVALID_ARGS');
      }
    });
  }

  test('an invalid regular expression fails loud and never starts the source command', () => {
    const remote = remoteOf('logs', 'docker', { container: 'web', grep: '(' });
    const result = runLocal(remote, [bin]);
    expect(result.code).toBe(2);
    expect(result.err).toContain('not a valid extended regular expression');
    expect(result.log).toBe('');
  });

  test('the source command failing stays a failure, not an empty match list', () => {
    const remote = remoteOf('logs', 'docker', { container: 'gone', grep: 'zzz' });
    expect(runLocal(remote, [bin], { FAKE_MODE: 'fail' }).code).toBe(1);
  });

  test('--context needs --grep, and the numbers are bounded', () => {
    expect(() => readLogQuery(ctxOf({ context: '2' }))).toThrow(OpError);
    expect(() => readLogQuery(ctxOf({ grep: 'x', context: '21' }))).toThrow(OpError);
    expect(() => readLogQuery(ctxOf({ 'max-lines': '0' }))).toThrow(OpError);
    expect(readLogQuery(ctxOf({ grep: 'x', context: '20' })).context).toBe(20);
  });
});

describe('logs --max-lines, --since, --until and the stream merge', () => {
  test('docker logs runs with stderr folded into stdout, so a line a service wrote there is returned', () => {
    const result = runLocal(remoteOf('logs', 'docker', { container: 'web' }), [bin]);
    expect(result.out).toContain('boom on stderr');
    expect(result.err).toBe('');
  });

  test('--since and --until become docker flags, each its own argv slot, with no --tail applied before them', () => {
    const remote = remoteOf('logs', 'docker', {
      container: 'web',
      since: '60m',
      until: '2026-11-27T10:00:01',
    });
    expect(runLocal(remote, [bin]).log.trim()).toBe(
      'logs --timestamps --since 60m --until 2026-11-27T10:00:01 web',
    );
  });

  test('--grep scans a wide window by default and keeps the newest --max-lines matches', () => {
    const remote = remoteOf('logs', 'docker', { container: 'web', grep: 'line', 'max-lines': '1' });
    const result = runLocal(remote, [bin]);
    expect(result.log.trim()).toBe('logs --timestamps --tail 200000 web');
    expect(result.out.trim()).toBe('2026-11-27T10:00:02.000000000Z omega line');
  });

  test('--context keeps the lines around a match', () => {
    const remote = remoteOf('logs', 'docker', { container: 'web', grep: 'boom', context: '1' });
    expect(runLocal(remote, [bin]).out.trim().split('\n')).toHaveLength(3);
  });

  test('--max-lines defaults to 500 and an explicit --tail above it raises it', () => {
    expect(readLogQuery(ctxOf({})).maxLines).toBe(500);
    expect(readLogQuery(ctxOf({ tail: '1500' })).maxLines).toBe(1500);
    expect(readLogQuery(ctxOf({ tail: '1500', 'max-lines': '40' })).maxLines).toBe(40);
  });
});

describe('logs service --grep: journalctl --grep where it exists, grep -E where it does not', () => {
  const remote = (args: Record<string, string>) =>
    journalCommand('sshd', readLogQuery(ctxOf(args)));
  const accepted = [
    '{"__REALTIME_TIMESTAMP":"1795658404000000","PRIORITY":"6","MESSAGE":"Accepted publickey for ops"}',
  ];

  test('a journalctl with --grep is asked to filter, case-sensitively', () => {
    const result = runLocal(remote({ grep: 'Accepted' }), [join(work, 'bin-grep')]);
    expect(result.out.trim().split('\n')).toEqual(accepted);
    expect(result.log).toContain('--grep=Accepted');
    expect(result.log).toContain('--case-sensitive=yes');
    expect(result.log).toContain('-u sshd');
  });

  test('a journalctl built without pattern matching falls back to grep -E with the same result', () => {
    const result = runLocal(remote({ grep: 'Accepted' }), [join(work, 'bin-nogrep')]);
    expect(result.code).toBe(0);
    expect(result.out.trim().split('\n')).toEqual(accepted);
    expect(result.log).not.toContain('--grep=Accepted');
  });

  test('--context needs grep -C, so it takes the fallback even where --grep works', () => {
    const result = runLocal(remote({ grep: 'Accepted', context: '1' }), [join(work, 'bin-grep')]);
    expect(result.out.trim().split('\n')).toHaveLength(3);
    expect(result.log).not.toContain('--grep=Accepted');
  });

  test('--max-lines keeps the newest matches on either branch', () => {
    for (const dir of ['bin-grep', 'bin-nogrep']) {
      const result = runLocal(remote({ grep: 'o', 'max-lines': '1' }), [join(work, dir)]);
      expect(result.out.trim().split('\n')).toEqual([
        '{"__REALTIME_TIMESTAMP":"1795658405000000","PRIORITY":"6","MESSAGE":"session opened"}',
      ]);
    }
  });

  test('--since and --until are passed to journalctl', () => {
    const result = runLocal(remote({ grep: 'Accepted', since: '1h ago', until: 'now' }), [
      join(work, 'bin-grep'),
    ]);
    expect(result.log).toContain('--since 1h ago');
    expect(result.log).toContain('--until now');
  });
});

describe('heavy ops run niced', () => {
  const SAMPLE: Record<string, Record<string, string>> = {
    'logs docker': { container: 'web' },
    'logs compose': { project_dir: '/srv/app' },
    'logs service': { unit: 'nginx' },
    'logs docker-daemon': {},
    'logs nginx': { stream: 'error' },
  };

  test('every check and logs op builds its remote command through the nice wrapper', () => {
    const heavy = listOps().filter((entry) => entry.group === 'check' || entry.group === 'logs');
    expect(heavy.length).toBeGreaterThanOrEqual(12);
    for (const entry of heavy) {
      const args = SAMPLE[`${entry.group} ${entry.name}`] ?? {};
      const cmd = entry.buildRemote(ctxOf(args));
      expect(`${entry.group} ${entry.name}: ${cmd}`).toContain('nice -n 10');
    }
  });

  test('a command run through it keeps its output and exit status', () => {
    const ok = runLocal(niced("echo 'hello world'"), []);
    expect({ code: ok.code, out: ok.out }).toEqual({ code: 0, out: 'hello world\n' });
    expect(runLocal(niced('exit 7'), []).code).toBe(7);
  });

  test('the command really runs at a lower priority', () => {
    const niceness = (cmd: string) => Number(runLocal(cmd, []).out.trim());
    const probe = 'ps -o ni= -p $$';
    expect(niceness(niced(probe))).toBe(Math.min(niceness(probe) + 10, 19));
  });

  test('ionice is used where it works, and skipped where it is absent or refuses', () => {
    const ionice = join(work, 'bin-ionice');
    mkdirSync(ionice);
    script(ionice, 'ionice', 'echo ionice "$@" >> "$FAKE_LOG"\nshift\nexec "$@"');
    const used = runLocal(niced('echo done'), [ionice]);
    expect({ out: used.out, log: used.log.includes('ionice -c3') }).toEqual({
      out: 'done\n',
      log: true,
    });

    const refusing = join(work, 'bin-ionice-refuses');
    mkdirSync(refusing);
    script(refusing, 'ionice', 'echo "ioprio_set failed" >&2\nexit 1');
    const skipped = runLocal(niced('echo done'), [refusing]);
    expect({ code: skipped.code, out: skipped.out }).toEqual({ code: 0, out: 'done\n' });
  });

  test('the plain command builder merges stderr only when asked', () => {
    const merged = runLocal(plainCommand(['docker', 'logs', 'web'], true), [bin]);
    const split = runLocal(plainCommand(['docker', 'logs', 'web'], false), [bin]);
    expect(merged.out).toContain('boom on stderr');
    expect(split.out).not.toContain('boom on stderr');
    expect(split.err).toContain('boom on stderr');
  });
});

describe('logs compose', () => {
  // project_dir is a files-allowlist path: this block declares /srv/app for alias web.
  const allowlistBefore = process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
  beforeAll(() => {
    const path = join(work, 'files-allowlist.toml');
    writeFileSync(path, '[web]\npaths = ["/srv/app"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = path;
  });
  afterAll(() => {
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistBefore;
  });

  const stream = [
    'web-1  | 2026-11-27T10:00:02.000000000Z second from web',
    'db-1   | 2026-11-27T10:00:01.000000000Z first from db',
    'db-1   | 2026-11-27T10:00:03.000000000Z third from db',
    'no prefix, compose warning',
  ].join('\n');

  function run(stdout: string, args: Record<string, string>) {
    const outcomes: SpawnOutcome[] = [
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
      { code: 0, stdout: '', stderr: '', timedOut: false },
      { code: 0, stdout, stderr: '', timedOut: false },
    ];
    let index = 0;
    const runner: SshRunner = async () =>
      outcomes[Math.min(index++, outcomes.length - 1)] as SpawnOutcome;
    return executeOp(
      op('logs', 'compose'),
      { alias: 'web', args: { project_dir: '/srv/app', ...args } },
      { transport: { runner } },
    );
  }

  test('the services are merged into time order with their names, the compose warning dropped', async () => {
    const envelope = await run(stream, {});
    const data = envelope.data as {
      source: string;
      lines: { ts: string; text: string; service: string }[];
      next_since: string;
    };
    expect(data.source).toBe('compose:/srv/app');
    expect(data.lines.map((line) => `${line.service}:${line.text}`)).toEqual([
      'db-1:first from db',
      'web-1:second from web',
      'db-1:third from db',
    ]);
    expect(data.next_since).toBe('2026-11-27T10:00:03.000000001Z');
  });

  test('--max-lines keeps the newest lines across services', async () => {
    const envelope = await run(stream, { 'max-lines': '2' });
    const data = envelope.data as { lines: { text: string }[]; truncated: boolean };
    expect(data.lines.map((line) => line.text)).toEqual(['second from web', 'third from db']);
    expect(data.truncated).toBe(true);
  });

  test('the command names the project directory and merges stderr', () => {
    const cmd = remoteOf('logs', 'compose', { project_dir: '/srv/app', since: '10m' });
    expect(cmd).toContain('--project-directory');
    const inner = cmd.slice(cmd.indexOf("'sh' '") + 0);
    expect(inner).toContain('2>&1');
    expect(inner).toContain('--since');
  });

  test('a project directory that starts with a dash is refused as an option', async () => {
    const envelope = await run(stream, { project_dir: '--help' });
    expect(envelope.error?.code).toBe('INVALID_ARGS');
  });
});

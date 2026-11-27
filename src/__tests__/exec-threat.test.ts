import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from 'bun:test';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../cli.ts';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * The threat model of named exec, written before the op exists: every way a caller (or a careless
 * definition) could turn a declared command into a different one is refused, and the refusals that
 * need no host make no ssh call at all. The "host" is this machine: the remote command runs under
 * `sh -c` with stub `docker`, `php` and `argv-echo` first on PATH, so a guard that only looks right
 * on paper (the realpath check, one argv slot per param) is exercised for real.
 */

const ALIAS = 'web-exec';
const SECRET = ['db', 'pw', 'never', 'leaves', '9Kq2'].join('-');
const ENV_KEYS = [
  'SSHEPHERD_EXEC_DIR',
  'SSHEPHERD_TARGETS_PATH',
  'SSHEPHERD_PROFILE',
  'SSHEPHERD_AUDIT_PATH',
] as const;

let scratch = '';
let execDir = '';
let root = '';
let outside = '';
let stubDir = '';
let markerDir = '';
let argvLog = '';
let auditLog = '';
const savedEnv: Record<string, string | undefined> = {};

interface Host {
  runner: SshRunner;
  /** Remote commands the runner was handed (the `timeout`-wrapped call, not the master/-G probes). */
  remotes: string[];
}

/** A runner whose host is this machine; it records every remote command line it ran. */
function localHost(): Host {
  const remotes: string[] = [];
  const runner: SshRunner = async (args) => {
    if (!args.includes('timeout')) {
      return { code: 0, stdout: 'hostname 10.0.0.9\n', stderr: '', timedOut: false };
    }
    const remote = args[args.length - 1] ?? '';
    remotes.push(remote);
    const proc = Bun.spawnSync(['sh', '-c', remote], {
      env: {
        PATH: `${stubDir}:/usr/bin:/bin`,
        ARGV_LOG: argvLog,
        MARKER_DIR: markerDir,
        STUB_SECRET: SECRET,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    return {
      code: proc.exitCode ?? 1,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
      timedOut: false,
    };
  };
  return { runner, remotes };
}

function writeStub(name: string, body: string[]): void {
  const path = join(stubDir, name);
  writeFileSync(path, ['#!/bin/sh', ...body, ''].join('\n'));
  chmodSync(path, 0o755);
}

/** `docker exec <c> cmd...` runs cmd here; `docker restart <c>` leaves a marker; `php artisan
 *  migrate:status` prints a migration table with a leaky debug line; `argv-echo` prints one line
 *  per argument it received, so a value that split into two argv slots shows as two lines. */
function writeStubs(): void {
  mkdirSync(stubDir, { recursive: true });
  writeStub('docker', [
    'printf "docker" >> "$ARGV_LOG"; for a in "$@"; do printf "|%s" "$a" >> "$ARGV_LOG"; done; echo >> "$ARGV_LOG"',
    'case "$1" in',
    '  exec) shift; shift; exec "$@" ;;',
    '  restart) touch "$MARKER_DIR/restarted-$2"; echo "$2" ;;',
    '  *) exit 9 ;;',
    'esac',
  ]);
  writeStub('php', [
    'printf "php" >> "$ARGV_LOG"; for a in "$@"; do printf "|%s" "$a" >> "$ARGV_LOG"; done; echo >> "$ARGV_LOG"',
    'echo "Migration name .............................. Batch / Status"',
    'echo "2024_01_01_000000_create_users_table ........ [1] Ran"',
    'echo "DB_PASSWORD=$STUB_SECRET"',
  ]);
  writeStub('argv-echo', [
    'i=0',
    'for a in "$@"; do i=$((i + 1)); printf "%s:%s\\n" "$i" "$a"; done',
  ]);
  for (const name of ['docker', 'php', 'argv-echo']) {
    Bun.spawnSync([join(stubDir, name)], {
      env: { ARGV_LOG: '/dev/null', MARKER_DIR: markerDir },
      stdin: 'ignore',
      stdout: 'ignore',
      stderr: 'ignore',
    });
  }
}

/** The good definitions every case starts from: an enum param run in a declared container, a path
 *  param under one root, a permissive regex param handed to the `argv-echo` stub (a program not on
 *  the data-only list, so its def opts in with allow_shell and only the universal gates refuse), an int
 *  param with a default, and a mutating def taking a container param. */
function goodDefs(): string {
  return [
    '[app-artisan]',
    'summary = "Read-only artisan commands in the app container"',
    'argv = ["php", "artisan", "{cmd}"]',
    'mutating = false',
    'container = "app"',
    '[app-artisan.params.cmd]',
    'type = "enum"',
    'values = ["migrate:status", "route:list"]',
    '',
    '[show-file]',
    'argv = ["cat", "{file}"]',
    'mutating = false',
    '[show-file.params.file]',
    'type = "path"',
    `under = "${root}"`,
    '',
    '[echo-word]',
    'argv = ["argv-echo", "{word}", "fixed"]',
    'mutating = false',
    'allow_shell = true',
    '[echo-word.params.word]',
    'type = "regex"',
    "pattern = '[\\s\\S]*'",
    '',
    '[tail-log]',
    `argv = ["tail", "-n", "{n}", "${join(root, 'app.log')}"]`,
    'mutating = false',
    '[tail-log.params.n]',
    'type = "int"',
    'min = 1',
    'max = 500',
    'default = 2',
    '',
    '[restart-worker]',
    'argv = ["docker", "restart", "{c}"]',
    'mutating = true',
    '[restart-worker.params.c]',
    'type = "container"',
    '',
  ].join('\n');
}

function writeDefs(alias: string, text: string, mode = 0o600): string {
  const path = join(execDir, `${alias}.toml`);
  rmSync(path, { force: true });
  writeFileSync(path, text);
  chmodSync(path, mode);
  return path;
}

function op(name: string): OpSpec {
  const found = getOp('exec', name);
  if (found === undefined) {
    throw new Error(`exec ${name} is not registered`);
  }
  return found;
}

async function drive(
  opName: string,
  name: string,
  params: string[] | null,
  options: { alias?: string; yes?: boolean; host?: Host } = {},
): Promise<{ envelope: Envelope<unknown>; host: Host }> {
  const host = options.host ?? localHost();
  const args: Record<string, string | boolean> = { name };
  if (params !== null) {
    args.param = JSON.stringify(params);
  }
  const envelope = await executeOp(
    op(opName),
    { alias: options.alias ?? ALIAS, args },
    {
      transport: { runner: host.runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      yes: options.yes ?? false,
      auditLogPath: auditLog,
    },
  );
  return { envelope, host };
}

function linesOf(envelope: Envelope<unknown>): string[] {
  const data = envelope.data as { lines?: string[] } | null;
  return data?.lines ?? [];
}

beforeAll(() => {
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
  }
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-exec-threat-'));
  execDir = join(scratch, 'exec');
  root = join(scratch, 'srv', 'app');
  outside = join(scratch, 'outside');
  stubDir = join(scratch, 'bin');
  markerDir = join(scratch, 'markers');
  argvLog = join(scratch, 'argv.log');
  auditLog = join(scratch, 'audit.jsonl');
  mkdirSync(execDir, { recursive: true, mode: 0o700 });
  mkdirSync(root, { recursive: true });
  mkdirSync(outside, { recursive: true });
  mkdirSync(markerDir, { recursive: true });
  writeFileSync(join(root, 'notes.txt'), 'inside the root\n');
  writeFileSync(join(root, 'app.log'), 'line one\nline two\nline three\n');
  writeFileSync(join(outside, 'secret.txt'), `OUTSIDE ${SECRET}\n`);
  symlinkSync(outside, join(root, 'link'));
  writeFileSync(
    join(scratch, 'ssh_config'),
    ['web-exec', 'shell-host', 'shell-ok', 'rogue-host', 'many-params', 'loose-mode']
      .map((alias) => `Host ${alias}\n  HostName 10.0.0.9\n`)
      .join(''),
  );
  writeFileSync(
    join(scratch, 'targets.toml'),
    `[web-db]\nalias = "${ALIAS}"\ncontainer = "db"\nuser = "ro"\ndatabase = "app"\ncontainers = ["app", "worker"]\n`,
  );
  process.env.SSHEPHERD_EXEC_DIR = execDir;
  process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
  process.env.SSHEPHERD_AUDIT_PATH = auditLog;
  delete process.env.SSHEPHERD_PROFILE;
  writeStubs();
}, 60_000);

afterAll(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = savedEnv[key];
    }
  }
  rmSync(scratch, { recursive: true, force: true });
});

beforeEach(() => {
  writeDefs(ALIAS, goodDefs());
  writeFileSync(argvLog, '');
  rmSync(auditLog, { force: true });
  delete process.env.SSHEPHERD_PROFILE;
});

describe('exec — the declared command runs, its output scrubbed, one argv slot per param', () => {
  test('app-artisan cmd=migrate:status runs `docker exec app php artisan migrate:status`, secret masked', async () => {
    const { envelope, host } = await drive('run', 'app-artisan', ['cmd=migrate:status']);
    expect(envelope.error).toBeNull();
    expect(host.remotes.length).toBe(1);
    expect(readFileSync(argvLog, 'utf8')).toContain(
      'docker|exec|app|php|artisan|migrate:status\nphp|artisan|migrate:status\n',
    );
    const text = JSON.stringify(envelope);
    expect(text).not.toContain(SECRET);
    expect(linesOf(envelope)).toContain('2024_01_01_000000_create_users_table ........ [1] Ran');
    expect(envelope.scrubbed).toBeGreaterThan(0);
  });

  test('a value with spaces stays ONE argv slot', async () => {
    const { envelope } = await drive('run', 'echo-word', ['word=two words here']);
    expect(envelope.error).toBeNull();
    expect(linesOf(envelope)).toEqual(['1:two words here', '2:fixed']);
  });

  test('an int param with a default runs without --param; out of range is refused', async () => {
    const { envelope } = await drive('run', 'tail-log', []);
    expect(envelope.error).toBeNull();
    expect(linesOf(envelope)).toEqual(['line two', 'line three']);
    const { envelope: over, host } = await drive('run', 'tail-log', ['n=501']);
    expect(over.error?.code).toBe('INVALID_ARGS');
    expect(host.remotes.length).toBe(0);
  });

  test('an enum value outside the list, an unknown param and a duplicate are refused with no ssh call', async () => {
    for (const params of [
      ['cmd=migrate'],
      ['cmd=route:list', 'extra=1'],
      ['cmd=route:list', 'cmd=route:list'],
    ]) {
      const { envelope, host } = await drive('run', 'app-artisan', params);
      expect({ params, code: envelope.error?.code, runs: host.remotes.length }).toEqual({
        params,
        code: 'INVALID_ARGS',
        runs: 0,
      });
    }
  });

  test('an undeclared def name is refused with the declared names to choose from', async () => {
    const { envelope, host } = await drive('run', 'app-artisn', ['cmd=route:list']);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.did_you_mean).toContain('app-artisan');
    expect(host.remotes.length).toBe(0);
  });

  test('exec list names every def, its params and whether it mutates — never runs anything', async () => {
    const { envelope, host } = await drive('list', '', null);
    expect(envelope.error).toBeNull();
    expect(host.remotes.length).toBe(0);
    const defs = (envelope.data as { defs: Array<{ name: string; mutating: boolean }> }).defs;
    expect(defs.map((def) => [def.name, def.mutating])).toEqual([
      ['app-artisan', false],
      ['echo-word', false],
      ['restart-worker', true],
      ['show-file', false],
      ['tail-log', false],
    ]);
  });
});

describe('exec threat model — the caller cannot change what runs', () => {
  test('leading `-` in a value is refused (it would be read as an option)', async () => {
    for (const value of ['-rf', '--help', '-']) {
      const { envelope, host } = await drive('run', 'echo-word', [`word=${value}`]);
      expect({ value, code: envelope.error?.code, runs: host.remotes.length }).toEqual({
        value,
        code: 'INVALID_ARGS',
        runs: 0,
      });
    }
  });

  test('shell metacharacters are refused before quoting is even relied on', async () => {
    const marker = join(markerDir, 'pwned');
    for (const value of [
      `a; touch ${marker}`,
      `$(touch ${marker})`,
      `\`touch ${marker}\``,
      'a | b',
      'a && b',
      'a > b',
      "it's",
      'say "hi"',
      'back\\slash',
      ['$', '{HOME}'].join(''),
      '*',
    ]) {
      const { envelope, host } = await drive('run', 'echo-word', [`word=${value}`]);
      expect({ value, code: envelope.error?.code, runs: host.remotes.length }).toEqual({
        value,
        code: 'INVALID_ARGS',
        runs: 0,
      });
    }
    expect(existsSync(marker)).toBe(false);
  });

  test('NUL, newline, carriage return and other control characters are refused', async () => {
    for (const value of ['a\0b', 'a\nb', 'a\rb', 'a\tb', 'a\u001bb']) {
      const { envelope, host } = await drive('run', 'echo-word', [`word=${value}`]);
      expect({ value, code: envelope.error?.code, runs: host.remotes.length }).toEqual({
        value,
        code: 'INVALID_ARGS',
        runs: 0,
      });
    }
  });

  test('path traversal and a path outside `under` are refused locally, no ssh call', async () => {
    for (const value of [
      join(root, '..', '..', 'outside', 'secret.txt'),
      `${root}/../app/notes.txt`,
      join(outside, 'secret.txt'),
      `${root}-sibling/notes.txt`,
      'notes.txt',
    ]) {
      const { envelope, host } = await drive('run', 'show-file', [`file=${value}`]);
      expect({ value, code: envelope.error?.code, runs: host.remotes.length }).toEqual({
        value,
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
    }
  });

  test('a symlink hop out of `under` is refused by the remote realpath check, the command never reads it', async () => {
    const { envelope, host } = await drive('run', 'show-file', [
      `file=${join(root, 'link', 'secret.txt')}`,
    ]);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.message).toContain('outside');
    expect(host.remotes.length).toBe(1);
    expect(host.remotes[0]).toContain('realpath');
    expect(JSON.stringify(envelope)).not.toContain('OUTSIDE');
    const { envelope: inside } = await drive('run', 'show-file', [
      `file=${join(root, 'notes.txt')}`,
    ]);
    expect(inside.error).toBeNull();
    expect(linesOf(inside)).toEqual(['inside the root']);
  });

  test('a container not declared for the alias is refused: as a param value and as a def field', async () => {
    const { envelope, host } = await drive('change', 'restart-worker', ['c=rogue'], { yes: true });
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(host.remotes.length).toBe(0);
    expect(existsSync(join(markerDir, 'restarted-rogue'))).toBe(false);

    writeDefs('rogue-host', '[peek]\nargv = ["env"]\nmutating = false\ncontainer = "rogue"\n');
    const { envelope: def, host: defHost } = await drive('run', 'peek', [], {
      alias: 'rogue-host',
    });
    expect(def.error?.code).toBe('VALIDATION_ERROR');
    expect(defHost.remotes.length).toBe(0);
  });

  test('a shell interpreter in argv needs allow_shell = true', async () => {
    for (const argv of [
      '["sh", "-c", "id"]',
      '["/bin/bash", "-c", "id"]',
      '["env", "sh", "-c", "id"]',
    ]) {
      writeDefs('shell-host', `[whoami]\nargv = ${argv}\nmutating = false\n`);
      const { envelope, host } = await drive('run', 'whoami', [], { alias: 'shell-host' });
      expect({ argv, code: envelope.error?.code, runs: host.remotes.length }).toEqual({
        argv,
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
    }
    writeDefs(
      'shell-ok',
      '[whoami]\nargv = ["sh", "-c", "echo shell-ran"]\nmutating = false\nallow_shell = true\n',
    );
    const { envelope } = await drive('run', 'whoami', [], { alias: 'shell-ok' });
    expect(envelope.error).toBeNull();
    expect(linesOf(envelope)).toEqual(['shell-ran']);
  });

  test('more than 16 params on a call, or declared on a def, is refused', async () => {
    const params = Array.from({ length: 17 }, (_, index) => `p${index}=x`);
    const { envelope, host } = await drive('run', 'echo-word', params);
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(envelope.error?.message).toContain('16');
    expect(host.remotes.length).toBe(0);

    const declared = Array.from(
      { length: 17 },
      (_, index) => `[many.params.p${index}]\ntype = "int"\nmin = 0\nmax = 9\n`,
    ).join('');
    const slots = Array.from({ length: 17 }, (_, index) => `"{p${index}}"`).join(', ');
    writeDefs(
      'many-params',
      `[many]\nargv = ["argv-echo", ${slots}]\nmutating = false\n${declared}`,
    );
    const { envelope: def, host: defHost } = await drive('run', 'many', [], {
      alias: 'many-params',
    });
    expect(def.error?.code).toBe('CONFIG_PARSE_ERROR');
    expect(defHost.remotes.length).toBe(0);
  });

  test('a value over 512 bytes is refused; exactly 512 runs', async () => {
    const { envelope, host } = await drive('run', 'echo-word', [`word=${'a'.repeat(513)}`]);
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(envelope.error?.message).toContain('512');
    expect(host.remotes.length).toBe(0);
    const { envelope: fits } = await drive('run', 'echo-word', [`word=${'a'.repeat(512)}`]);
    expect(fits.error).toBeNull();
    const multibyte = 'é'.repeat(257);
    const { envelope: wide } = await drive('run', 'echo-word', [`word=${multibyte}`]);
    expect(wide.error?.code).toBe('INVALID_ARGS');
  });

  test('a def file readable by group/other, a symlinked def file, or one owned by another user is refused', async () => {
    for (const mode of [0o644, 0o640, 0o604, 0o660]) {
      writeDefs('loose-mode', '[peek]\nargv = ["argv-echo", "x"]\nmutating = false\n', mode);
      const { envelope, host } = await drive('run', 'peek', [], { alias: 'loose-mode' });
      expect({
        mode: mode.toString(8),
        code: envelope.error?.code,
        runs: host.remotes.length,
      }).toEqual({
        mode: mode.toString(8),
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
      expect(envelope.error?.hint).toContain('chmod 600');
    }

    const real = join(scratch, 'elsewhere.toml');
    writeFileSync(real, '[peek]\nargv = ["argv-echo", "x"]\nmutating = false\n');
    chmodSync(real, 0o600);
    rmSync(join(execDir, 'loose-mode.toml'), { force: true });
    symlinkSync(real, join(execDir, 'loose-mode.toml'));
    const { envelope: linked, host: linkedHost } = await drive('run', 'peek', [], {
      alias: 'loose-mode',
    });
    expect(linked.error?.code).toBe('VALIDATION_ERROR');
    expect(linkedHost.remotes.length).toBe(0);

    const uid = process.getuid?.() ?? 0;
    const spy = spyOn(process, 'getuid').mockImplementation(() => uid + 1);
    try {
      const { envelope: foreign, host: foreignHost } = await drive('run', 'app-artisan', [
        'cmd=route:list',
      ]);
      expect(foreign.error?.code).toBe('VALIDATION_ERROR');
      expect(foreign.error?.message).toContain('owned');
      expect(foreignHost.remotes.length).toBe(0);
    } finally {
      spy.mockRestore();
    }
  });

  test('a param slot spliced inside a larger argv element is a definition error', async () => {
    writeDefs(
      'shell-host',
      '[bad]\nargv = ["argv-echo", "--file={f}"]\nmutating = false\n[bad.params.f]\ntype = "int"\nmin = 0\nmax = 9\n',
    );
    const { envelope, host } = await drive('run', 'bad', ['f=1'], { alias: 'shell-host' });
    expect(envelope.error?.code).toBe('CONFIG_PARSE_ERROR');
    expect(host.remotes.length).toBe(0);
  });

  test('the definition is re-read on every call', async () => {
    const { envelope: before } = await drive('run', 'app-artisan', ['cmd=about']);
    expect(before.error?.code).toBe('INVALID_ARGS');
    writeDefs(ALIAS, goodDefs().replace('"route:list"]', '"route:list", "about"]'));
    const { envelope: after } = await drive('run', 'app-artisan', ['cmd=about']);
    expect(after.error).toBeNull();
  });
});

describe('exec — mutating defs: --yes, profile and audit', () => {
  test('a mutating def without --yes -> CONFIRMATION_REQUIRED, nothing ran, the refusal is audited', async () => {
    const { envelope, host } = await drive('change', 'restart-worker', ['c=worker']);
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(host.remotes.length).toBe(0);
    expect(existsSync(join(markerDir, 'restarted-worker'))).toBe(false);
    const rows = readFileSync(auditLog, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(rows.map((row) => [row.command, row.outcome])).toEqual([['exec change', 'refused']]);
  });

  test('with --yes it runs once and writes one ok audit row without the param values', async () => {
    const { envelope, host } = await drive('change', 'restart-worker', ['c=worker'], { yes: true });
    expect(envelope.error).toBeNull();
    expect(host.remotes.length).toBe(1);
    expect(existsSync(join(markerDir, 'restarted-worker'))).toBe(true);
    const text = readFileSync(auditLog, 'utf8');
    const rows = text
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(rows.map((row) => [row.command, row.outcome])).toEqual([['exec change', 'ok']]);
    expect(rows[0].exec_def).toBe('restart-worker');
    expect(text.replaceAll('restart-worker', '')).not.toContain('worker');
  });

  test('SSHEPHERD_PROFILE=read refuses a mutating def (PROFILE_DENIED) and still runs a read-only one', async () => {
    process.env.SSHEPHERD_PROFILE = 'read';
    const { envelope, host } = await drive('change', 'restart-worker', ['c=worker'], { yes: true });
    expect(envelope.error?.code).toBe('PROFILE_DENIED');
    expect(host.remotes.length).toBe(0);
    const { envelope: reads } = await drive('run', 'app-artisan', ['cmd=route:list']);
    expect(reads.error).toBeNull();
  });

  test('`exec run` refuses a mutating def outright, pointing at `exec change --yes`', async () => {
    const { envelope, host } = await drive('run', 'restart-worker', ['c=worker'], { yes: true });
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.next).toContain('exec change');
    expect(host.remotes.length).toBe(0);
  });
});

describe('exec — the CLI shorthand `exec <alias> <name>` picks run or change from the definition', () => {
  const written: string[] = [];
  const realWrite = process.stdout.write.bind(process.stdout);
  let savedExitCode: typeof process.exitCode;

  beforeEach(() => {
    written.length = 0;
    savedExitCode = process.exitCode;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
  });

  afterEach(() => {
    process.stdout.write = realWrite;
    process.exitCode = savedExitCode;
  });

  async function cli(
    argv: string[],
  ): Promise<{ envelope: Envelope<unknown>; host: Host; exit: unknown }> {
    const host = localHost();
    written.length = 0;
    await run(argv, {
      transport: { runner: host.runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: auditLog,
    });
    return { envelope: JSON.parse(written.join('')), host, exit: process.exitCode };
  }

  test('`exec web-exec app-artisan --param cmd=migrate:status` runs without --yes, output scrubbed', async () => {
    const { envelope } = await cli(['exec', ALIAS, 'app-artisan', '--param', 'cmd=migrate:status']);
    expect(envelope.command).toBe('exec run');
    expect(envelope.error).toBeNull();
    expect(JSON.stringify(envelope)).not.toContain(SECRET);
  });

  test('two --param flags both arrive', async () => {
    writeDefs(
      'shell-host',
      '[two]\nargv = ["argv-echo", "{a}", "{b}"]\nmutating = false\nallow_shell = true\n[two.params.a]\ntype = "int"\nmin = 0\nmax = 9\n[two.params.b]\ntype = "enum"\nvalues = ["x", "y"]\n',
    );
    const { envelope } = await cli([
      'exec',
      'shell-host',
      'two',
      '--param',
      'a=3',
      '--param',
      'b=y',
    ]);
    expect(envelope.error).toBeNull();
    expect(linesOf(envelope)).toEqual(['1:3', '2:y']);
  });

  test('a mutating def through the shorthand without --yes -> CONFIRMATION_REQUIRED, exit 2', async () => {
    const { envelope, host, exit } = await cli([
      'exec',
      ALIAS,
      'restart-worker',
      '--param',
      'c=worker',
    ]);
    expect(envelope.command).toBe('exec change');
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(host.remotes.length).toBe(0);
    expect(exit).toBe(2);
  });

  test('SSHEPHERD_PROFILE=read through the shorthand -> PROFILE_DENIED for the mutating def', async () => {
    process.env.SSHEPHERD_PROFILE = 'read';
    const { envelope, host } = await cli([
      'exec',
      ALIAS,
      'restart-worker',
      '--param',
      'c=worker',
      '--yes',
    ]);
    expect(envelope.error?.code).toBe('PROFILE_DENIED');
    expect(host.remotes.length).toBe(0);
  });
});

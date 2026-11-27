import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../cli.ts';
import { localUrl } from '../ops/http.ts';
import { parseCondition } from '../ops/wait.ts';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

const ALIAS = 'web-test';
const KEY_CONTAINER = 'app-key';
const KEY_VALUE = ['kv', 'never', 'leaves', 'the', 'host', '7Q2w9'].join('-');
const COOKIE_VALUE = ['ck', 'header', 'value', '4r8T'].join('-');
const ENV_KEYS = [
  'SSHEPHERD_TARGETS_PATH',
  'SSHEPHERD_FILES_ALLOWLIST_PATH',
  'SSHEPHERD_PROFILE',
] as const;
const STUBBED = ['awk', 'head', 'tail', 'od', 'tr', 'wc', 'cat', 'mktemp', 'rm', 'base64', 'sleep'];

let scratch = '';
let stubDir = '';
let argvLog = '';
let configLog = '';
let envFile = '';
let repo = '';
const savedEnv: Record<string, string | undefined> = {};

function op(group: string, name: string): OpSpec {
  const found = getOp(group, name);
  if (found === undefined) {
    throw new Error(`no op ${group} ${name}`);
  }
  return found;
}

/** Every external command the remote script runs logs its argv here first; `docker` and `curl` are
 *  fakes that hand out the credential (from the environment, as a container would) and record
 *  curl's stdin, so the test sees exactly what a `ps` on the host could see and what curl sent. */
function writeStubs(): void {
  mkdirSync(stubDir, { recursive: true });
  for (const name of STUBBED) {
    const real = Bun.which(name);
    if (real === null) {
      throw new Error(`${name} not on PATH`);
    }
    const path = join(stubDir, name);
    writeFileSync(
      path,
      `#!/bin/sh\nprintf '%s\\n' "${name} $*" >> "$ARGV_LOG"\nexec ${real} "$@"\n`,
    );
    chmodSync(path, 0o755);
  }
  writeFileSync(
    join(stubDir, 'docker'),
    [
      '#!/bin/sh',
      'printf \'%s\\n\' "docker $*" >> "$ARGV_LOG"',
      'case "$*" in',
      '  *State.Health*)',
      '    n=$(cat "$HEALTH_COUNTER" 2>/dev/null || echo 0); echo $((n + 1)) > "$HEALTH_COUNTER"',
      '    if [ "$HEALTH_MODE" = none ]; then echo none; elif [ "$n" -ge 1 ]; then echo healthy; else echo starting; fi ;;',
      '  *Config.Env*) printf \'PATH=/usr/bin\\nAPI_KEY=%s\\nOTHER=x\\n\' "$STUB_KEY" ;;',
      'esac',
    ].join('\n'),
  );
  writeFileSync(
    join(stubDir, 'curl'),
    [
      '#!/bin/sh',
      'printf \'%s\\n\' "curl $*" >> "$ARGV_LOG"',
      'body=; head=; cfg=',
      'while [ $# -gt 0 ]; do',
      '  case "$1" in',
      '    -o) body="$2"; shift ;;',
      '    -D) head="$2"; shift ;;',
      '    -K) cfg="$2"; shift ;;',
      '  esac',
      '  shift',
      'done',
      'if [ "$cfg" = - ]; then cat >> "$CONFIG_LOG"; fi',
      'if [ -n "$head" ]; then printf \'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nSet-Cookie: s=%s\\r\\n\\r\\n\' "$STUB_COOKIE" > "$head"; fi',
      'if [ "$STUB_ECHO" = 1 ]; then printf \'{"echo":"%s"}\' "$STUB_KEY" > "$body"; else printf \'{"ok":true}\\n\' > "$body"; fi',
      'printf \'200 0.012 %s\' "$(wc -c < "$body" | tr -d \' \')"',
    ].join('\n'),
  );
  chmodSync(join(stubDir, 'docker'), 0o755);
  chmodSync(join(stubDir, 'curl'), 0o755);
  // The first exec of a new executable can stall for seconds while the OS scans it; pay it here.
  for (const name of [...STUBBED, 'docker', 'curl']) {
    Bun.spawnSync([join(stubDir, name)], {
      env: { ARGV_LOG: '/dev/null', CONFIG_LOG: '/dev/null' },
      stdin: 'ignore',
      stdout: 'ignore',
      stderr: 'ignore',
    });
  }
}

/** A runner whose "host" is this machine: the remote command runs under `sh -c` with the stubs
 *  first on PATH. Every ssh argv it was handed is kept. */
function localHost(env: Record<string, string> = {}): { runner: SshRunner; sshArgs: string[][] } {
  const sshArgs: string[][] = [];
  const runner: SshRunner = async (args) => {
    sshArgs.push(args);
    if (!args.includes('timeout')) {
      return { code: 0, stdout: 'hostname 10.0.0.9\n', stderr: '', timedOut: false };
    }
    const remote = args[args.length - 1] ?? '';
    const proc = Bun.spawnSync(['sh', '-c', remote], {
      env: {
        PATH: `${stubDir}:/usr/bin:/bin`,
        ARGV_LOG: argvLog,
        CONFIG_LOG: configLog,
        HEALTH_COUNTER: join(scratch, 'health-counter'),
        STUB_KEY: KEY_VALUE,
        STUB_COOKIE: COOKIE_VALUE,
        ...env,
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
  return { runner, sshArgs };
}

function scripted(stdout: string, code: number): { runner: SshRunner; calls: number } {
  const state = { runner: (async () => ({}) as never) as SshRunner, calls: 0 };
  state.runner = async (args) => {
    if (args.includes('timeout')) {
      state.calls += 1;
      return { code, stdout, stderr: '', timedOut: false };
    }
    return { code: 0, stdout: 'hostname 10.0.0.9\n', stderr: '', timedOut: false };
  };
  return state;
}

async function drive(
  group: string,
  name: string,
  args: Record<string, string | boolean>,
  runner: SshRunner,
  yes = false,
): Promise<Envelope<unknown>> {
  return executeOp(
    op(group, name),
    { alias: ALIAS, args },
    {
      transport: { runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      yes,
      auditLogPath: join(scratch, 'audit.jsonl'),
    },
  );
}

beforeAll(() => {
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
  }
  delete process.env.SSHEPHERD_PROFILE;
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-http-wait-git-'));
  stubDir = join(scratch, 'bin');
  argvLog = join(scratch, 'argv.log');
  configLog = join(scratch, 'curl-config.log');
  envFile = join(scratch, 'app.env');
  repo = join(scratch, 'repo');
  writeFileSync(envFile, `APP=1\nexport API_KEY="${KEY_VALUE}"\n`);
  writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
  writeFileSync(
    join(scratch, 'targets.toml'),
    `[web-db]\nalias = "${ALIAS}"\ncontainer = "db"\nuser = "ro"\ndatabase = "app"\ncontainers = ["${KEY_CONTAINER}", "app"]\n`,
  );
  writeFileSync(
    join(scratch, 'files-allowlist.toml'),
    `[${ALIAS}]\npaths = ["${envFile}", "${repo}"]\n`,
  );
  process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
  process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
  writeStubs();

  mkdirSync(repo);
  const git = (...args: string[]): void => {
    const proc = Bun.spawnSync(['git', '-C', repo, ...args], { stdout: 'pipe', stderr: 'pipe' });
    if (proc.exitCode !== 0) {
      throw new Error(`git ${args.join(' ')}: ${proc.stderr.toString()}`);
    }
  };
  git('init', '-q');
  writeFileSync(join(repo, 'app.txt'), 'one\ntwo\n');
  git('add', 'app.txt');
  git(
    '-c',
    'user.name=Fixture',
    '-c',
    'user.email=fixture@example.invalid',
    'commit',
    '-qm',
    'first commit',
  );
  git('remote', 'add', 'origin', `https://deploy:${KEY_VALUE}@example.invalid/team/app.git`);
  writeFileSync(join(repo, 'app.txt'), 'one\ntwo\nthree\n');
  writeFileSync(join(repo, 'untracked.txt'), 'new\n');
}, 120_000);

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
  writeFileSync(argvLog, '');
  writeFileSync(configLog, '');
  rmSync(join(scratch, 'health-counter'), { force: true });
});

describe('localUrl — only the host loopback, as curl will read it', () => {
  test('127.0.0.1, 127.x, ::1 and localhost pass; the WHATWG serialisation is what curl gets', () => {
    expect(localUrl('http://127.0.0.1:80/', 'http get')).toBe('http://127.0.0.1/');
    expect(localUrl('http://127.8.0.2:9000/x?y=1', 'http get')).toBe('http://127.8.0.2:9000/x?y=1');
    expect(localUrl('https://[::1]:8443/h', 'http get')).toBe('https://[::1]:8443/h');
    expect(localUrl('http://localhost:3000/health', 'http get')).toBe(
      'http://localhost:3000/health',
    );
    expect(localUrl('http://127.0.0.1\\@evil.example/', 'http get')).toBe(
      'http://127.0.0.1/@evil.example/',
    );
  });

  for (const bad of [
    'http://example.com/',
    'http://10.0.0.5/',
    'http://127.0.0.1.example.com/',
    'http://user:pw@127.0.0.1/',
    'ftp://127.0.0.1/',
    'file:///etc/passwd',
    'not a url',
  ]) {
    test(`${bad} -> INVALID_ARGS`, () => {
      expect(() => localUrl(bad, 'http get')).toThrow();
    });
  }
});

describe('http get / send — refused locally before any ssh call', () => {
  test('non-localhost URL: INVALID_ARGS, 0 command runs', async () => {
    const fake = scripted('', 0);
    const envelope = await drive('http', 'get', { url: 'http://203.0.113.9/' }, fake.runner);
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(fake.calls).toBe(0);
  });

  test('non-GET without --yes: CONFIRMATION_REQUIRED, 0 command runs', async () => {
    const fake = scripted('', 0);
    const envelope = await drive(
      'http',
      'send',
      { method: 'POST', url: 'http://127.0.0.1/' },
      fake.runner,
    );
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(fake.calls).toBe(0);
  });

  test('--auth on an undeclared container: VALIDATION_ERROR naming targets.toml, 0 command runs', async () => {
    const fake = scripted('', 0);
    const envelope = await drive(
      'http',
      'get',
      { url: 'http://127.0.0.1/', auth: 'env:API_KEY@container=other' },
      fake.runner,
    );
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.message).toContain('targets.toml');
    expect(fake.calls).toBe(0);
  });

  test('--auth on a file not on the files allowlist: VALIDATION_ERROR, 0 command runs', async () => {
    const fake = scripted('', 0);
    const envelope = await drive(
      'http',
      'get',
      { url: 'http://127.0.0.1/', auth: 'env:API_KEY@file=/etc/app.env' },
      fake.runner,
    );
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(fake.calls).toBe(0);
  });

  test('a malformed --auth: INVALID_ARGS', async () => {
    const fake = scripted('', 0);
    const envelope = await drive(
      'http',
      'get',
      { url: 'http://127.0.0.1/', auth: 'API_KEY' },
      fake.runner,
    );
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(fake.calls).toBe(0);
  });
});

describe('http --auth resolves the key on the host only', () => {
  for (const kind of ['container', 'file']) {
    test(`${kind}: the value is in no argv, curl got it on stdin, the envelope has none of it`, async () => {
      const auth = `env:API_KEY@${kind}=${kind === 'container' ? KEY_CONTAINER : envFile}`;
      const host = localHost();
      const envelope = await drive(
        'http',
        'get',
        { url: 'http://127.0.0.1:80/', auth },
        host.runner,
      );
      const data = envelope.data as { status: number; headers_names: string[]; body: string };
      expect(envelope.error).toBeNull();
      expect(data.status).toBe(200);
      expect(data.headers_names).toEqual(['Content-Type', 'Set-Cookie']);
      expect(data.body).toBe('{"ok":true}\n');

      const argv = readFileSync(argvLog, 'utf8');
      expect(argv).toContain('curl ');
      expect(argv).toContain('awk ');
      expect(argv.includes(KEY_VALUE)).toBe(false);
      expect(JSON.stringify(host.sshArgs).includes(KEY_VALUE)).toBe(false);
      expect(readFileSync(configLog, 'utf8')).toBe(
        `header = "Authorization: Bearer ${KEY_VALUE}"\n`,
      );
      const printed = JSON.stringify(envelope);
      expect(printed.includes(KEY_VALUE)).toBe(false);
      expect(printed.includes(COOKIE_VALUE)).toBe(false);
      const audit = readFileSync(join(scratch, 'audit.jsonl'), 'utf8');
      expect(audit.includes(KEY_VALUE)).toBe(false);
    });
  }

  test('--auth-header X-Api-Key sends the bare value under that name', async () => {
    const host = localHost();
    await drive(
      'http',
      'get',
      {
        url: 'http://127.0.0.1/',
        auth: `env:API_KEY@container=${KEY_CONTAINER}`,
        'auth-header': 'X-Api-Key',
      },
      host.runner,
    );
    expect(readFileSync(configLog, 'utf8')).toBe(`header = "X-Api-Key: ${KEY_VALUE}"\n`);
  });

  test('a response echoing the credential back comes back masked on the host, and counted', async () => {
    const host = localHost({ STUB_ECHO: '1' });
    const envelope = await drive(
      'http',
      'get',
      { url: 'http://127.0.0.1/', auth: `env:API_KEY@container=${KEY_CONTAINER}` },
      host.runner,
    );
    expect((envelope.data as { body: string }).body).toBe('{"echo":"***"}');
    expect(envelope.scrubbed).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(envelope).includes(KEY_VALUE)).toBe(false);
  });

  test('a key the container does not define: VALIDATION_ERROR, nothing sent', async () => {
    const host = localHost({ STUB_KEY: '' });
    const envelope = await drive(
      'http',
      'get',
      { url: 'http://127.0.0.1/', auth: `env:API_KEY@container=${KEY_CONTAINER}` },
      host.runner,
    );
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(readFileSync(argvLog, 'utf8')).not.toContain('curl ');
  });

  test('http send POST --json with --yes: body sent from a temp file, same result shape', async () => {
    const host = localHost();
    const envelope = await drive(
      'http',
      'send',
      { method: 'post', url: 'http://127.0.0.1/api', json: '{"name":"x"}' },
      host.runner,
      true,
    );
    expect(envelope.error).toBeNull();
    expect((envelope.data as { status: number }).status).toBe(200);
    expect(readFileSync(argvLog, 'utf8')).toContain('-X POST');
  });

  test('curl exit 7 (nothing listening): COMMAND_FAILED with a next step', async () => {
    const fake = scripted('', 7);
    const envelope = await drive('http', 'get', { url: 'http://127.0.0.1:81/' }, fake.runner);
    expect(envelope.error?.code).toBe('COMMAND_FAILED');
    expect(envelope.error?.next).toBe(`sshepherd check ports ${ALIAS}`);
  });
});

describe('wait for', () => {
  test('conditions parse; a regex keeps its own @ and the url its own port', () => {
    expect(parseCondition('healthy@container=app')).toEqual({ kind: 'healthy', container: 'app' });
    expect(parseCondition('log-contains:ready@v2|up@container=web')).toEqual({
      kind: 'log-contains',
      pattern: 'ready@v2|up',
      container: 'web',
    });
    expect(parseCondition('port-open:5432')).toEqual({ kind: 'port-open', port: 5432 });
    expect(parseCondition('url:http://127.0.0.1:8080/health:status=204')).toEqual({
      kind: 'url',
      url: 'http://127.0.0.1:8080/health',
      status: '204',
    });
    expect(parseCondition('url:http://localhost:3000/')).toEqual({
      kind: 'url',
      url: 'http://localhost:3000/',
      status: '200',
    });
  });

  for (const bad of [
    'healthy',
    'port-open:0',
    'port-open:70000',
    'url:http://example.com/',
    'sleep:5',
  ]) {
    test(`--until ${bad} -> INVALID_ARGS, 0 command runs`, async () => {
      const fake = scripted('', 0);
      const envelope = await drive('wait', 'for', { until: bad }, fake.runner);
      expect(envelope.error?.code).toBe('INVALID_ARGS');
      expect(fake.calls).toBe(0);
    });
  }

  for (const timeout of ['4000', '5']) {
    test(`--timeout ${timeout} -> INVALID_ARGS (10-3600), 0 command runs`, async () => {
      const fake = scripted('', 0);
      const envelope = await drive('wait', 'for', { until: 'port-open:22', timeout }, fake.runner);
      expect(envelope.error?.code).toBe('INVALID_ARGS');
      expect(fake.calls).toBe(0);
    });
  }

  test('healthy@container: starting, then healthy -> ok, 2 attempts, elapsed_ms measured', async () => {
    const host = localHost();
    const envelope = await drive(
      'wait',
      'for',
      { until: 'healthy@container=app', timeout: '60' },
      host.runner,
    );
    expect(envelope.error).toBeNull();
    const data = envelope.data as { met: boolean; attempts: number; elapsed_ms: number };
    expect(data.met).toBe(true);
    expect(data.attempts).toBe(2);
    expect(data.elapsed_ms).toBeGreaterThanOrEqual(1000);
    expect(readFileSync(argvLog, 'utf8')).toContain('sleep 2');
  });

  test('a container without a HEALTHCHECK: VALIDATION_ERROR on the first check', async () => {
    const host = localHost({ HEALTH_MODE: 'none' });
    const envelope = await drive('wait', 'for', { until: 'healthy@container=app' }, host.runner);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.message).toContain('HEALTHCHECK');
  });

  test('not met by the deadline: COMMAND_TIMEOUT, data keeps attempts, elapsed_ms and the last state', async () => {
    const fake = scripted('__WAIT__ timeout 28 55012 unhealthy\n', 3);
    const envelope = await drive(
      'wait',
      'for',
      { until: 'healthy@container=app', timeout: '60' },
      fake.runner,
    );
    expect(envelope.error?.code).toBe('COMMAND_TIMEOUT');
    expect(envelope.error?.message).toContain('within 55 s');
    expect(envelope.data).toEqual({
      until: 'healthy@container=app',
      met: false,
      attempts: 28,
      elapsed_ms: 55012,
      last_state: 'unhealthy',
    });
  });
});

describe('git head / log / diff-stat on an allowlisted repository root', () => {
  test('head: branch, commit, dirty, and the remote URL with its credential removed on the host', async () => {
    const host = localHost();
    const envelope = await drive('git', 'head', { path: repo }, host.runner);
    expect(envelope.error).toBeNull();
    const data = envelope.data as {
      subject: string;
      dirty: boolean;
      commit: string;
      remotes: { name: string; url: string }[];
    };
    expect(data.subject).toBe('first commit');
    expect(data.dirty).toBe(true);
    expect(data.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(data.remotes).toEqual([{ name: 'origin', url: 'https://example.invalid/team/app.git' }]);
    expect(JSON.stringify(envelope).includes(KEY_VALUE)).toBe(false);
  });

  test('log: the commit, author and subject', async () => {
    const host = localHost();
    const envelope = await drive('git', 'log', { path: repo, n: '5' }, host.runner);
    const data = envelope.data as {
      commits: { author: string; subject: string }[];
      truncated: boolean;
    };
    expect(data.commits.map((commit) => [commit.author, commit.subject])).toEqual([
      ['Fixture', 'first commit'],
    ]);
    expect(data.truncated).toBe(false);
  });

  test('diff-stat: per-file counts and the untracked count, never the diff text', async () => {
    const host = localHost();
    const envelope = await drive('git', 'diff-stat', { path: repo }, host.runner);
    expect(envelope.data).toEqual({
      files: [{ path: 'app.txt', added: 1, deleted: 0 }],
      files_changed: 1,
      insertions: 1,
      deletions: 0,
      untracked: 1,
      truncated: false,
    });
  });

  test('a path inside the repository but not its root: VALIDATION_ERROR', async () => {
    const sub = join(repo, 'sub');
    mkdirSync(sub, { recursive: true });
    writeFileSync(
      join(scratch, 'files-allowlist.toml'),
      `[${ALIAS}]\npaths = ["${envFile}", "${repo}", "${sub}"]\n`,
    );
    const host = localHost();
    const envelope = await drive('git', 'log', { path: sub }, host.runner);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.message).toContain('root');
  });

  test('a path off the files allowlist: VALIDATION_ERROR, 0 command runs', async () => {
    const fake = scripted('', 0);
    const envelope = await drive('git', 'head', { path: '/opt/other' }, fake.runner);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(fake.calls).toBe(0);
  });
});

describe('CLI alias-first shorthands', () => {
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

  test('`http <alias> GET <non-localhost>` is http get and refuses with INVALID_ARGS', async () => {
    const fake = scripted('', 0);
    await run(['http', ALIAS, 'GET', 'http://example.com/'], {
      transport: { runner: fake.runner },
    });
    const envelope = JSON.parse(written.join(''));
    expect([envelope.command, envelope.error.code, fake.calls]).toEqual([
      'http get',
      'INVALID_ARGS',
      0,
    ]);
  });

  test('`http <alias> POST <url>` without --yes is http send and needs confirmation', async () => {
    const fake = scripted('', 0);
    await run(['http', ALIAS, 'POST', 'http://127.0.0.1/'], { transport: { runner: fake.runner } });
    const envelope = JSON.parse(written.join(''));
    expect([envelope.command, envelope.error.code, fake.calls]).toEqual([
      'http send',
      'CONFIRMATION_REQUIRED',
      0,
    ]);
  });

  test('`wait <alias> --until ... --timeout 4000` is wait for and refuses with INVALID_ARGS', async () => {
    const fake = scripted('', 0);
    await run(['wait', ALIAS, '--until', 'healthy@container=app', '--timeout', '4000'], {
      transport: { runner: fake.runner },
    });
    const envelope = JSON.parse(written.join(''));
    expect([envelope.command, envelope.error.code, fake.calls]).toEqual([
      'wait for',
      'INVALID_ARGS',
      0,
    ]);
  });
});

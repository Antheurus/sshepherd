import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Block 10 audit (phase 12): each test pins one receipt finding and is red at 80f7409. The cases
 * drive executeOp with a runner that records remote commands and never runs one.
 */

const ALIAS = 'web-a10';
let scratch = '';
let execDir = '';
let auditLog = '';
const saved: Record<string, string | undefined> = {};

function recorder(): { runner: SshRunner; remotes: string[]; budgets: string[] } {
  const remotes: string[] = [];
  const budgets: string[] = [];
  const runner: SshRunner = async (args) => {
    if (args.includes('timeout')) {
      remotes.push(args[args.length - 1] ?? '');
      budgets.push(args[args.length - 2] ?? '');
    }
    return {
      code: 0,
      stdout: args.includes('timeout') ? 'ran\n' : 'hostname 10.0.0.9\n',
      stderr: '',
      timedOut: false,
    };
  };
  return { runner, remotes, budgets };
}

function writeDefs(text: string): void {
  const path = join(execDir, `${ALIAS}.toml`);
  rmSync(path, { force: true });
  writeFileSync(path, text);
  chmodSync(path, 0o600);
}

async function drive(
  opName: 'run' | 'change',
  name: string,
  params: string[],
  yes = false,
  timeoutSec?: number,
): Promise<{ envelope: Envelope<unknown>; remotes: string[]; budgets: string[] }> {
  const op = getOp('exec', opName) as OpSpec;
  const host = recorder();
  const envelope = await executeOp(
    op,
    { alias: ALIAS, args: { name, param: JSON.stringify(params) } },
    {
      transport: { runner: host.runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      yes,
      auditLogPath: auditLog,
      ...(timeoutSec === undefined ? {} : { timeoutSec }),
    },
  );
  return { envelope, remotes: host.remotes, budgets: host.budgets };
}

describe('Phase 12 findings', () => {
  beforeAll(() => {
    for (const key of [
      'SSHEPHERD_EXEC_DIR',
      'SSHEPHERD_AUDIT_PATH',
      'SSHEPHERD_PROFILE',
      'SSHEPHERD_TARGETS_PATH',
    ]) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-a10-'));
    execDir = join(scratch, 'exec');
    auditLog = join(scratch, 'audit.jsonl');
    mkdirSync(execDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
    process.env.SSHEPHERD_EXEC_DIR = execDir;
    process.env.SSHEPHERD_AUDIT_PATH = auditLog;
    writeFileSync(
      join(scratch, 'targets.toml'),
      `[box]\nalias = "${ALIAS}"\ncontainers = ["app"]\n`,
    );
    process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
    delete process.env.SSHEPHERD_PROFILE;
  });
  afterAll(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    rmSync(scratch, { recursive: true, force: true });
  });

  test('P12-F2: a code-taking interpreter (perl -e) needs allow_shell like a shell does', async () => {
    writeDefs(
      '[perl-e]\nargv = ["perl", "-e", "{code}"]\nmutating = false\n[perl-e.params.code]\ntype = "regex"\npattern = \'.*\'\n',
    );
    const { envelope, remotes } = await drive('run', 'perl-e', ['code=system id']);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(remotes.length).toBe(0);
  });

  test('P12-F4: the audit row of exec change names the definition', async () => {
    writeDefs('[restart-it]\nargv = ["touch", "/tmp/x"]\nmutating = true\n');
    rmSync(auditLog, { force: true });
    await drive('change', 'restart-it', [], true);
    expect(readFileSync(auditLog, 'utf8')).toContain('restart-it');
  });

  test('P12-F5: a definition may carry its own timeout (roadmap P3.1)', async () => {
    writeDefs('[slow]\nargv = ["hostname"]\nmutating = false\ntimeout = 5\n');
    const { envelope } = await drive('run', 'slow', []);
    expect(envelope.error).toBeNull();
  });

  test('P12-F6: a regex param is matched whole even when the pattern has a top-level |', async () => {
    writeDefs(
      '[digits]\nargv = ["echo", "{v}"]\nmutating = false\n[digits.params.v]\ntype = "regex"\npattern = \'[0-9]+)|(x\'\n',
    );
    const { envelope, remotes } = await drive('run', 'digits', ['v=12zz']);
    const refusedAtLoadOrValue = envelope.error !== null && remotes.length === 0;
    expect(refusedAtLoadOrValue).toBe(true);
  });
  test('P12-F2: every code-taking program, bare, versioned or behind a wrapper, needs allow_shell', async () => {
    const refused = [
      '["python", "-c", "{v}"]',
      '["python3.11", "-c", "{v}"]',
      '["/usr/bin/python3", "-c", "{v}"]',
      '["node", "-e", "{v}"]',
      '["nodejs", "-e", "{v}"]',
      '["deno", "eval", "{v}"]',
      '["bun", "-e", "{v}"]',
      '["ruby", "-e", "{v}"]',
      '["lua5.4", "-e", "{v}"]',
      '["tclsh", "{v}"]',
      '["awk", "BEGIN{system(\\"id\\")}"]',
      '["gawk", "{v}"]',
      '["mawk", "{v}"]',
      '["busybox", "awk", "{v}"]',
      '["find", "/srv", "-exec", "id", ";"]',
      '["find", "/srv", "-execdir", "id", ";"]',
      '["find", "/srv", "-ok", "id", ";"]',
      '["find", "/srv", "-delete"]',
      '["env", "perl", "-e", "{v}"]',
      '["env", "-i", "FOO=1", "perl", "-e", "{v}"]',
      '["env", "-S", "{v}"]',
      '["nice", "-n", "5", "ruby", "-e", "{v}"]',
      '["timeout", "-k", "5", "10", "python3", "-c", "{v}"]',
      '["stdbuf", "-o", "L", "node", "-e", "{v}"]',
      '["nohup", "perl", "-e", "{v}"]',
      '["xargs", "-n", "1", "perl", "-e", "{v}"]',
      '["setsid", "-f", "php", "-r", "{v}"]',
      '["sudo", "-u", "app", "python3", "-c", "{v}"]',
      '["sudo", "-s"]',
      '["doas", "-u", "app", "lua", "-e", "{v}"]',
      '["su", "app"]',
      '["chroot", "/srv/jail"]',
      '["chroot", "/srv/jail", "perl", "-e", "{v}"]',
      '["php", "-r", "{v}"]',
      '["php8.2", "-r", "{v}"]',
      '["sed", "1e id", "/etc/hostname"]',
      '["sed", "-n", "s/x/id/ep", "/etc/hostname"]',
      '["sed", "{v}", "/etc/hostname"]',
      '["sed", "-e", "{v}", "/etc/hostname"]',
      '["git", "-c", "core.pager=id", "log"]',
      '["git", "--exec-path=/tmp", "log"]',
      '["git", "config", "core.sshCommand", "{v}"]',
      '["tar", "--to-command=id", "-xf", "/srv/a.tar"]',
      '["tar", "--use-compress-program", "id", "-xf", "/srv/a.tar"]',
      '["tar", "-I", "id", "-xf", "/srv/a.tar"]',
      '["tar", "-xIf", "id", "/srv/a.tar"]',
      '["rsync", "-e", "id", "/srv/a", "b:/c"]',
      '["rsync", "--rsh=id", "/srv/a", "b:/c"]',
      '["scp", "-S", "id", "/srv/a", "b:/c"]',
      '["ssh", "box", "{v}"]',
      '["nice", "{v}", "-e", "x"]',
      '["env", "{v}"]',
      '["docker", "exec", "app", "perl", "-e", "{v}"]',
    ];
    for (const argv of refused) {
      const declares = argv.includes('{v}')
        ? `[run-it.params.v]\ntype = "regex"\npattern = '.*'\n`
        : '';
      writeDefs(`[run-it]\nargv = ${argv}\nmutating = false\n${declares}`);
      const params = argv.includes('{v}') ? ['v=x'] : [];
      const { envelope, remotes } = await drive('run', 'run-it', params);
      expect({ argv, code: envelope.error?.code, runs: remotes.length }).toEqual({
        argv,
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
    }
  });

  test('P12-F2: a plain command, artisan through php, and allow_shell still run', async () => {
    for (const [argv, extra] of [
      ['["php", "artisan", "migrate:status"]', ''],
      ['["find", "/srv", "-name", "x"]', ''],
      ['["sed", "-n", "1,5p", "/etc/hostname"]', ''],
      ['["sed", "s/hello/x/g", "/etc/hostname"]', ''],
      ['["git", "log", "-n", "1"]', ''],
      ['["git", "log", "-c", "-n", "1"]', ''],
      ['["php", "artisan", "route:list", "-r"]', ''],
      ['["sudo", "-u", "admins", "du", "-sh", "/srv"]', ''],
      ['["sed", "-n", "# keep\\n1p", "/etc/hostname"]', ''],
      ['["tar", "-tzf", "/srv/a.tar"]', ''],
      ['["nice", "-n", "5", "du", "-sh", "/srv"]', ''],
      ['["env"]', ''],
      ['["constructor", "toString"]', ''],
      ['["perl", "-e", "print 1"]', 'allow_shell = true\n'],
    ]) {
      writeDefs(`[run-it]\nargv = ${argv}\nmutating = false\n${extra}`);
      const { envelope, remotes } = await drive('run', 'run-it', []);
      expect({ argv, error: envelope.error, runs: remotes.length }).toEqual({
        argv,
        error: null,
        runs: 1,
      });
    }
  });

  test('P12-F2: a value naming an interpreter is refused like one naming a shell', async () => {
    writeDefs(
      '[pick]\nargv = ["echo", "{v}"]\nmutating = false\n[pick.params.v]\ntype = "regex"\npattern = \'.*\'\n',
    );
    for (const value of ['perl', '/usr/bin/python3.11', 'node']) {
      const { envelope, remotes } = await drive('run', 'pick', [`v=${value}`]);
      expect({ value, code: envelope.error?.code, runs: remotes.length }).toEqual({
        value,
        code: 'INVALID_ARGS',
        runs: 0,
      });
    }
  });

  test('P12-F1/F3: a path param in a container is resolved and run in ONE invocation, no realpath --', async () => {
    writeDefs(
      '[cat-under]\nargv = ["cat", "{file}"]\nmutating = false\ncontainer = "app"\n[cat-under.params.file]\ntype = "path"\nunder = "/etc"\n',
    );
    const { envelope, remotes } = await drive('run', 'cat-under', ['file=/etc/hostname']);
    expect(envelope.error).toBeNull();
    expect(remotes.length).toBe(1);
    const remote = remotes[0] ?? '';
    expect(remote.startsWith("'docker' 'exec' 'app' 'sh' '-c' ")).toBe(true);
    expect(remote.split("'docker'").length).toBe(2);
    expect(remote).not.toContain('realpath --');
    expect(remote).toContain('realpath');
    expect(remote).toContain('command exec 3<"$d0"');
    expect(remote).toContain('readlink /proc/self/fd/3');
    expect(remote.endsWith(`\nexec '\\''cat'\\'' "$a0"'`)).toBe(true);
  });

  test('P12-F4: the audit row of exec run names the definition too', async () => {
    writeDefs('[peek-it]\nargv = ["hostname"]\nmutating = false\n');
    rmSync(auditLog, { force: true });
    await drive('run', 'peek-it', []);
    const row = JSON.parse(readFileSync(auditLog, 'utf8').trim()) as Record<string, unknown>;
    expect(row.exec_def).toBe('peek-it');
  });

  test('P12-F5: the def timeout is the budget; --timeout overrides it; out of bounds is refused', async () => {
    writeDefs('[slow]\nargv = ["hostname"]\nmutating = false\ntimeout = 5\n');
    expect((await drive('run', 'slow', [])).budgets).toEqual(['5']);
    expect((await drive('run', 'slow', [], false, 900)).budgets).toEqual(['900']);
    writeDefs('[quick]\nargv = ["hostname"]\nmutating = false\n');
    expect((await drive('run', 'quick', [])).budgets).toEqual(['120']);
    for (const bad of ['0', '1801', '2.5', '"10"']) {
      writeDefs(`[slow]\nargv = ["hostname"]\nmutating = false\ntimeout = ${bad}\n`);
      const { envelope, remotes } = await drive('run', 'slow', []);
      expect({ bad, code: envelope.error?.code, runs: remotes.length }).toEqual({
        bad,
        code: 'CONFIG_PARSE_ERROR',
        runs: 0,
      });
    }
  });

  test('P12-F6: a pattern that is not one balanced group on its own is refused at load', async () => {
    for (const pattern of ['a)|(.*', '(a', '[0-9', 'a\\']) {
      writeDefs(
        `[digits]\nargv = ["echo", "{v}"]\nmutating = false\n[digits.params.v]\ntype = "regex"\npattern = '${pattern}'\n`,
      );
      const { envelope, remotes } = await drive('run', 'digits', ['v=a']);
      expect({ pattern, code: envelope.error?.code, runs: remotes.length }).toEqual({
        pattern,
        code: 'CONFIG_PARSE_ERROR',
        runs: 0,
      });
    }
    writeDefs(
      '[digits]\nargv = ["echo", "{v}"]\nmutating = false\n[digits.params.v]\ntype = "regex"\npattern = \'[0-9]+|x\'\n',
    );
    expect((await drive('run', 'digits', ['v=12zz'])).envelope.error?.code).toBe('INVALID_ARGS');
    expect((await drive('run', 'digits', ['v=12'])).envelope.error).toBeNull();
  });
});

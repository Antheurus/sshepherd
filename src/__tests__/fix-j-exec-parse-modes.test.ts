import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readDataArgv } from '../ops/exec.ts';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Fix J (receipt AI): a param def's split into options, code and operands must come out the same
 * whether the program permutes options (GNU getopt) or stops at the first operand
 * (POSIXLY_CORRECT, busybox, BSD). `env` is a wrapper like any other, and `date` and `hostname`
 * left the data-only list (given an operand, each tries to set the clock or the host name).
 */

const ALIAS = 'web-fj';
let scratch = '';
let execDir = '';
const saved: Record<string, string | undefined> = {};

async function drive(
  argv: string[],
  params: string[],
): Promise<{ code: string; runs: number; message: string }> {
  const path = join(execDir, `${ALIAS}.toml`);
  rmSync(path, { force: true });
  const declared = params
    .map((value) => value.split('=')[0] ?? '')
    .map((name) => `[w.params.${name}]\ntype = "regex"\npattern = '.+'\n`)
    .join('');
  writeFileSync(path, `[w]\nargv = ${JSON.stringify(argv)}\nmutating = false\n${declared}`);
  chmodSync(path, 0o600);
  const remotes: string[] = [];
  const runner: SshRunner = async (args) => {
    if (args.includes('timeout')) {
      remotes.push(args[args.length - 1] ?? '');
    }
    return {
      code: 0,
      stdout: args.includes('timeout') ? 'ran\n' : 'hostname 10.0.0.9\n',
      stderr: '',
      timedOut: false,
    };
  };
  const envelope: Envelope<unknown> = await executeOp(
    getOp('exec', 'run') as OpSpec,
    { alias: ALIAS, args: { name: 'w', param: JSON.stringify(params) } },
    {
      transport: { runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
    },
  );
  return {
    code: envelope.error?.code ?? 'OK',
    runs: remotes.length,
    message: envelope.error?.message ?? '',
  };
}

/** One allowed param def per getopt-parsed data-only program (find and php parse by their own
 *  grammar, not getopt), with the split both modes must agree on. */
const ALLOWED: [string[], string[], { operands: string[]; code: string[] }][] = [
  [['cat', '-n', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['tac', '-s', ',', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['head', '-n', '5', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['tail', '-n', '{n}', '/var/log/syslog'], ['n=20'], { operands: ['/var/log/syslog'], code: [] }],
  [['ls', '-la', '{p}'], ['p=/srv'], { operands: ['{p}'], code: [] }],
  [['du', '--max-depth=1', '-sh', '{p}'], ['p=/srv'], { operands: ['{p}'], code: [] }],
  [['df', '-h', '{p}'], ['p=/srv'], { operands: ['{p}'], code: [] }],
  [['stat', '-c', '%s', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['wc', '-l', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['grep', '-r', '-e', 'x', '{p}'], ['p=/srv'], { operands: ['{p}'], code: [] }],
  [['grep', '-f', '{s}', '{p}'], ['s=/etc/hosts', 'p=/srv'], { operands: ['{p}'], code: [] }],
  [['egrep', '-i', 'x', '{p}'], ['p=/srv'], { operands: ['x', '{p}'], code: [] }],
  [['fgrep', 'x', '{p}'], ['p=/srv'], { operands: ['x', '{p}'], code: [] }],
  [['zcat', '-f', '{p}'], ['p=/var/log/a.gz'], { operands: ['{p}'], code: [] }],
  [['md5sum', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['sha1sum', '-b', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['sha256sum', '--tag', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['readlink', '-f', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['realpath', '-e', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: [] }],
  [['echo', '-n', '{q}'], ['q=hello'], { operands: ['{q}'], code: [] }],
  [['id', '-u', '{q}'], ['q=root'], { operands: ['{q}'], code: [] }],
  [['uname', '-s', '{q}'], ['q=x'], { operands: ['{q}'], code: [] }],
  [['uptime', '-p', '{q}'], ['q=x'], { operands: ['{q}'], code: [] }],
  [['free', '-s', '{n}', '-c', '1'], ['n=2'], { operands: [], code: [] }],
  [['ps', '-o', 'pid', '-p', '{n}'], ['n=1'], { operands: [], code: [] }],
  [['touch', '-c', '{p}'], ['p=/srv/x'], { operands: ['{p}'], code: [] }],
  [['mkdir', '-p', '{p}'], ['p=/srv/x'], { operands: ['{p}'], code: [] }],
  [['rmdir', '{p}'], ['p=/srv/x'], { operands: ['{p}'], code: [] }],
  [['rm', '-f', '{p}'], ['p=/srv/x'], { operands: ['{p}'], code: [] }],
  [['cp', '-a', '{p}', '/srv/b'], ['p=/srv/x'], { operands: ['{p}', '/srv/b'], code: [] }],
  [['mv', '-n', '{p}', '/srv/b'], ['p=/srv/x'], { operands: ['{p}', '/srv/b'], code: [] }],
  [['ln', '-s', '{p}', '/srv/b'], ['p=/srv/x'], { operands: ['{p}', '/srv/b'], code: [] }],
  [['chmod', '-R', 'a-w', '{p}'], ['p=/srv/x'], { operands: ['a-w', '{p}'], code: [] }],
  [['chown', '-R', 'www', '{p}'], ['p=/srv/x'], { operands: ['www', '{p}'], code: [] }],
  [['journalctl', '-u', '{q}', '-n', '50', '--no-pager'], ['q=cron'], { operands: [], code: [] }],
  [['sed', '-n', '1p', '{p}'], ['p=/etc/hostname'], { operands: ['1p', '{p}'], code: [] }],
  [['sed', '-n', '-e', 'p', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: ['p'] }],
  [['sed', '-nEe', 'p', '{p}'], ['p=/etc/hostname'], { operands: ['{p}'], code: ['p'] }],
  [['sed', '-i.bak', 's/a/b/', '{p}'], ['p=/srv/x'], { operands: ['s/a/b/', '{p}'], code: [] }],
  [
    ['docker', 'logs', '--since', '{s}', '{q}'],
    ['s=10m', 'q=app'],
    { operands: ['{q}'], code: [] },
  ],
  [['docker', 'restart', '{q}'], ['q=app'], { operands: ['{q}'], code: [] }],
  [['systemctl', 'status', '--no-pager', '{q}'], ['q=cron'], { operands: ['{q}'], code: [] }],
];

/** Defs with an option after the first operand: GNU and stop-at-operand read them differently.
 *  Where the stop-at-operand reading makes a param sed's script, the literal sed walk refuses the
 *  def before rule A7 is reached, so that row names the sed message. */
const SED_CODE = 'runs sed with an option that executes code';
const MOVED: [string[], string[], string, string?][] = [
  [['cat', '{p}', '-n'], ['p=/etc/hostname'], '-n'],
  [['head', '{p}', '-n', '5'], ['p=/etc/hostname'], '-n'],
  [['grep', 'x', '{p}', '-r'], ['p=/srv'], '-r'],
  [['sed', '-n', '{s}', '{p}', '-e', 'p'], ['s=1e id', 'p=/etc/hostname'], '-e', SED_CODE],
  [['sed', '{p}', '-e', 'p'], ['p=/etc/hostname'], '-e', SED_CODE],
  [['sed', '1p', '{p}', '-i'], ['p=/srv/x'], '-i'],
  [['cp', '{p}', '-t', '/srv'], ['p=/srv/x'], '-t'],
  [['cat', '{p}', '--', '/etc/hosts'], ['p=/etc/hostname'], '--'],
  [['docker', 'logs', '{q}', '--tail', '5'], ['q=app'], '--tail'],
  [['systemctl', 'status', '{q}', '--no-pager'], ['q=cron'], '--no-pager'],
];

describe('fix J: one parse under every argument-parsing mode', () => {
  beforeAll(() => {
    for (const key of ['SSHEPHERD_EXEC_DIR', 'SSHEPHERD_PROFILE', 'SSHEPHERD_TARGETS_PATH']) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-fj-'));
    execDir = join(scratch, 'exec');
    mkdirSync(execDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
    writeFileSync(join(scratch, 'targets.toml'), `[box]\nalias = "${ALIAS}"\n`);
    process.env.SSHEPHERD_EXEC_DIR = execDir;
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

  for (const [argv, params, split] of ALLOWED) {
    test(`same split both ways, and runs: ${argv.join(' ')}`, async () => {
      const permuted = readDataArgv(argv, 'permute');
      const stopped = readDataArgv(argv, 'stop');
      expect(permuted).toEqual({ problem: null, ...split });
      expect(stopped).toEqual({ problem: null, ...split });
      expect(await drive(argv, params)).toEqual({ code: 'OK', runs: 1, message: '' });
    });
  }

  for (const [argv, params, moved, message] of MOVED) {
    test(`option after the first operand refused: ${argv.join(' ')}`, async () => {
      const permuted = readDataArgv(argv, 'permute');
      const stopped = readDataArgv(argv, 'stop');
      expect(permuted.problem).toBeNull();
      expect(stopped.operands).not.toEqual(permuted.operands);
      expect(stopped.operands).toContain(moved);
      const result = await drive(argv, params);
      expect({ code: result.code, runs: result.runs }).toEqual({
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
      expect(result.message).toContain(message ?? `puts ${moved} after the first operand`);
      expect(result.message).toContain('allow_shell');
    });
  }

  for (const [argv, params] of [
    [['env', 'A=1', 'cat', '{p}'], ['p=/etc/hostname']],
    [['env', 'POSIXLY_CORRECT=1', 'sed', '-n', '1p', '{p}'], ['p=/etc/hostname']],
    [['date', '{fmt}'], ['fmt=010100002030']],
    [['hostname', '{n}'], ['n=pwned']],
  ] as [string[], string[]][]) {
    test(`not a data-only argv[0], needs allow_shell: ${argv.join(' ')}`, async () => {
      const result = await drive(argv, params);
      expect({ code: result.code, runs: result.runs }).toEqual({
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
      expect(result.message).toContain(`hands a param to ${argv[0]}`);
      expect(result.message).toContain('allow_shell');
    });
  }

  for (const argv of [
    ['sed', '-n', '1e id', '/etc/hostname', '-e', 'p'],
    ['env', 'POSIXLY_CORRECT=1', 'sed', '-n', '1e id', '/etc/hostname', '-e', 'p'],
    ['env', 'LC_ALL=C', 'sed', '1e id', '/etc/hostname', '--expression=p'],
  ]) {
    test(`literal sed script that runs code under stop-at-operand refused: ${argv.join(' ')}`, async () => {
      const result = await drive(argv, []);
      expect({ code: result.code, runs: result.runs }).toEqual({
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
      expect(result.message).toContain('sed with an option that executes code');
    });
  }

  for (const argv of [
    ['date', '+%F'],
    ['hostname'],
    ['sed', '-n', '1p', '/etc/hostname'],
    ['sed', '-n', '1p', '/etc/hostname', '-e', 'p'],
    ['env', 'LC_ALL=C', 'sed', '-n', '1p', '/etc/hostname'],
  ]) {
    test(`literal def still runs: ${argv.join(' ')}`, async () => {
      expect(await drive(argv, [])).toEqual({ code: 'OK', runs: 1, message: '' });
    });
  }
});

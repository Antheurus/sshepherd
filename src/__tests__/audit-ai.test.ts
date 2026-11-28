import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Re-audit of fix I (rule A7): a parser that disagrees with the real program. Each row states the
 * secure outcome; a red row is a bypass. AI-1: env's NAME=value exception lets a literal
 * POSIXLY_CORRECT=1 switch GNU getopt to stop at the first operand, so a param sshepherd reads as
 * a sed input file becomes sed's script. AI-2: the same parse on a host whose login environment
 * already sets POSIXLY_CORRECT, with no env prefix at all.
 */

const ALIAS = 'web-ai';
let scratch = '';
let execDir = '';
const saved: Record<string, string | undefined> = {};

function recorder(): { runner: SshRunner; remotes: string[] } {
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
  return { runner, remotes };
}

async function drive(argv: string, params: string[]): Promise<{ code: string; runs: number }> {
  const path = join(execDir, `${ALIAS}.toml`);
  rmSync(path, { force: true });
  const declared = ['p', 'q', 's', 'f']
    .filter((name) => argv.includes(`"{${name}}"`))
    .map((name) => `[w.params.${name}]\ntype = "regex"\npattern = '.+'\n`)
    .join('');
  writeFileSync(path, `[w]\nargv = [${argv}]\nmutating = false\n${declared}`);
  chmodSync(path, 0o600);
  const host = recorder();
  const envelope: Envelope<unknown> = await executeOp(
    getOp('exec', 'run') as OpSpec,
    { alias: ALIAS, args: { name: 'w', param: JSON.stringify(params) } },
    {
      transport: { runner: host.runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
    },
  );
  return { code: envelope.error?.code ?? 'OK', runs: host.remotes.length };
}

const F = 'f=/etc/hostname';

const REFUSED: [string, string, string[]][] = [
  [
    'AI-1 env POSIXLY_CORRECT=1 sed -n {s} {f} -e p (param becomes the script)',
    '"env", "POSIXLY_CORRECT=1", "sed", "-n", "{s}", "{f}", "-e", "p"',
    ['s=1e id', F],
  ],
  [
    'AI-1 env POSIXLY_CORRECT=1 sed -n <literal e script> {f} -e p',
    '"env", "POSIXLY_CORRECT=1", "sed", "-n", "1e id", "{f}", "-e", "p"',
    [F],
  ],
  [
    'AI-1 literal def (no param): env POSIXLY_CORRECT=1 sed -n <literal e script> file -e p',
    '"env", "POSIXLY_CORRECT=1", "sed", "-n", "1e id", "/etc/hostname", "-e", "p"',
    [],
  ],
  [
    'AI-2 sed -n {s} {f} -e p (option after the operands; a POSIXLY_CORRECT host reads {s} as the script)',
    '"sed", "-n", "{s}", "{f}", "-e", "p"',
    ['s=1e id', F],
  ],
  [
    'sed {f} -e p (fix J rule 2: an option after the first operand; stop-at-operand reads {f} as the script)',
    '"sed", "{f}", "-e", "p"',
    [F],
  ],
  [
    'env A=1 sed -n 1p {f} (fix J rule 1: env is a wrapper)',
    '"env", "A=1", "sed", "-n", "1p", "{f}"',
    [F],
  ],
  ['env -S', '"env", "-S", "cat", "{f}"', [F]],
  ['env --split-string=cat', '"env", "--split-string=cat", "{f}"', [F]],
  ['env -u X', '"env", "-u", "X", "cat", "{f}"', [F]],
  ['env -0', '"env", "-0", "cat", "{f}"', [F]],
  ['env --', '"env", "--", "cat", "{f}"', [F]],
  ['env A=1 --', '"env", "A=1", "--", "cat", "{f}"', [F]],
  ['env -=x (dash name as assignment)', '"env", "-=x", "cat", "{f}"', [F]],
  ['env {s} cat', '"env", "{s}", "cat", "/etc/hostname"', ['s=A=1']],
  ['env A=1 env -S', '"env", "A=1", "env", "-S", "cat", "{f}"', [F]],
  ['env A=1 xargs', '"env", "A=1", "xargs", "cat", "{f}"', [F]],
  ['env A=1 nice', '"env", "A=1", "nice", "cat", "{f}"', [F]],
  ['env A=1 {s}', '"env", "A=1", "{s}", "/etc/hostname"', ['s=cat']],
  ['cat {f} --help (option after operand, unknown)', '"cat", "{f}", "--help"', [F]],
  ['sed {f} -e <literal e>', '"sed", "{f}", "-e", "1e id"', [F]],
  ['sed -n -- {s} {f}', '"sed", "-n", "--", "{s}", "{f}"', ['s=1e id', F]],
  ['sed -nf {s}', '"sed", "-nf", "{s}", "{f}"', ['s=/tmp/s.sed', F]],
  ['sed -n -f {s}', '"sed", "-n", "-f", "{s}", "{f}"', ['s=/tmp/s.sed', F]],
  ['sed -i {s} {f}', '"sed", "-i", "{s}", "{f}"', ['s=1e id', F]],
  ['sed --in-place {s} {f}', '"sed", "--in-place", "{s}", "{f}"', ['s=1e id', F]],
  ['sed -l 5 {s}', '"sed", "-l", "5", "{s}", "{f}"', ['s=1e id', F]],
  ['sed --quie prefix', '"sed", "--quie", "1p", "{f}"', [F]],
  ['sed -s e via --expression=', '"sed", "--expression=1e id", "{f}"', [F]],
  ['sort --compress-program', '"sort", "--compress-program=sh", "{f}"', [F]],
  ['sort {f}', '"sort", "{f}"', [F]],
  ['tar --to-command', '"tar", "--to-command=id", "-xf", "{f}"', [F]],
  ['tar -I', '"tar", "-I", "id", "-xf", "{f}"', [F]],
  ['tar --use-compress-program', '"tar", "--use-compress-program=id", "-xf", "{f}"', [F]],
  ['less {f}', '"less", "{f}"', [F]],
  ['more {f}', '"more", "{f}"', [F]],
  ['man {f}', '"man", "{f}"', [F]],
  ['awk {s} {f}', '"awk", "{s}", "{f}"', ['s=BEGIN', F]],
  ['grep with a --pre (not a GNU grep option)', '"grep", "--pre=id", "x", "{f}"', [F]],
  ['find -fprintf', '"find", "{f}", "-fprintf", "/tmp/x", "%p"', [F]],
  ['find -fprint0', '"find", "{f}", "-fprint0", "/tmp/x"', [F]],
  ['find -fls', '"find", "{f}", "-fls", "/tmp/x"', [F]],
  ['find -execdir', '"find", "{f}", "-execdir", "id", ";"', [F]],
  ['find -okdir', '"find", "{f}", "-okdir", "id", ";"', [F]],
  ['find -D leading', '"find", "-D", "exec", "{f}"', [F]],
  ['docker {s} logs', '"docker", "{s}", "app"', ['s=logs']],
  ['docker exec', '"docker", "exec", "app", "cat", "{f}"', [F]],
  ['docker -H', '"docker", "-H", "x", "logs", "{s}"', ['s=app']],
  ['systemctl {s}', '"systemctl", "{s}", "cron"', ['s=status']],
  ['systemctl status --host=x', '"systemctl", "status", "--host=x", "{s}"', ['s=cron']],
  ['systemctl status -M x', '"systemctl", "status", "-M", "x", "{s}"', ['s=cron']],
  ['php -r', '"php", "-r", "{s}"', ['s=x']],
  ['php {s}', '"php", "{s}"', ['s=/srv/a.php']],
  ['php -f literal', '"php", "-f", "/srv/a.php", "{s}"', ['s=x']],
];

/** A value refused before anything runs: option injection through the value, empty, control
 *  characters. */
const BAD_VALUES: [string, string, string[]][] = [
  ['value --expression=1e id', '"sed", "-n", "1p", "{f}"', ['f=--expression=1e id']],
  ['value -e1e id', '"sed", "-n", "1p", "{f}"', ['f=-e1e id']],
  ['value --help', '"cat", "{f}"', ['f=--help']],
  ['value empty', '"cat", "{f}"', ['f=']],
  ['value with newline', '"cat", "{f}"', ['f=/etc/hostname\nid']],
  ['value with NUL', '"cat", "{f}"', ['f=/etc/hostname\u0000x']],
  ['value naming a shell', '"cat", "{f}"', ['f=/bin/sh']],
];

const ALLOWED: [string, string, string[]][] = [
  ['grep -f {s} {f}', '"grep", "-f", "{s}", "{f}"', ['s=/etc/hosts', F]],
  ['find {f} -files0-from', '"find", "-files0-from", "{f}", "-print"', [F]],
  ['find {f} -newer {s}', '"find", "{f}", "-newer", "{s}", "-print"', [F, 's=/etc/hosts']],
  ['sed -nEe p {f}', '"sed", "-nEe", "p", "{f}"', [F]],
  ['docker logs --since {s} {q}', '"docker", "logs", "--since", "{s}", "{q}"', ['s=10m', 'q=app']],
];

describe('audit AI: fix I re-audit, parser vs program', () => {
  beforeAll(() => {
    for (const key of ['SSHEPHERD_EXEC_DIR', 'SSHEPHERD_PROFILE', 'SSHEPHERD_TARGETS_PATH']) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-ai-'));
    execDir = join(scratch, 'exec');
    mkdirSync(execDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
    writeFileSync(
      join(scratch, 'targets.toml'),
      `[box]\nalias = "${ALIAS}"\ncontainers = ["app"]\n`,
    );
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

  for (const [label, argv, params] of REFUSED) {
    test(`refused without allow_shell: ${label}`, async () => {
      expect(await drive(argv, params)).toEqual({ code: 'VALIDATION_ERROR', runs: 0 });
    });
  }
  for (const [label, argv, params] of BAD_VALUES) {
    test(`value refused before running: ${label}`, async () => {
      const result = await drive(argv, params);
      expect(result.runs).toBe(0);
      expect(result.code).not.toBe('OK');
    });
  }
  for (const [label, argv, params] of ALLOWED) {
    test(`runs: ${label}`, async () => {
      expect(await drive(argv, params)).toEqual({ code: 'OK', runs: 1 });
    });
  }
});

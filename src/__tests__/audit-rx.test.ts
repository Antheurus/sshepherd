import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import { scrub } from '../scrub.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Consolidated re-audit (fixes 3, E, F, G1, G2 at 1498944): each test pins one NEW finding and is
 * red at 1498944. Exec cases drive executeOp with a runner that records remote commands and never
 * runs one; live proof of each (uid=0(root) on the fixture) is in the receipt.
 */

const ALIAS = 'web-arx';
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

function writeDefs(text: string): void {
  const path = join(execDir, `${ALIAS}.toml`);
  rmSync(path, { force: true });
  writeFileSync(path, text);
  chmodSync(path, 0o600);
}

async function drive(
  name: string,
  params: string[],
): Promise<{ envelope: Envelope<unknown>; remotes: string[] }> {
  const op = getOp('exec', 'run') as OpSpec;
  const host = recorder();
  const envelope = await executeOp(
    op,
    { alias: ALIAS, args: { name, param: JSON.stringify(params) } },
    {
      transport: { runner: host.runner },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
    },
  );
  return { envelope, remotes: host.remotes };
}

const PROG_PARAMS = (name: string) =>
  `[${name}.params.prog]\ntype = "regex"\npattern = '[a-z0-9]+'\n` +
  `[${name}.params.script]\ntype = "regex"\npattern = '[0-9a-z ]+'\n` +
  `[${name}.params.file]\ntype = "enum"\nvalues = ["/etc/hostname"]\n`;

describe('consolidated re-audit NEW findings', () => {
  beforeAll(() => {
    for (const key of ['SSHEPHERD_EXEC_DIR', 'SSHEPHERD_PROFILE', 'SSHEPHERD_TARGETS_PATH']) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-arx-'));
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

  // Live on the fixture (debian): prog=sed script='1e id' -> uid=0(root) for ionice, taskset, chrt,
  // flock, runuser, setpriv; the rest were accepted and failed only on the environment.
  for (const [name, argv] of [
    ['ionice', '"ionice", "-c3", "{prog}", "{script}", "{file}"'],
    ['taskset', '"taskset", "1", "{prog}", "{script}", "{file}"'],
    ['chrt', '"chrt", "-o", "0", "{prog}", "{script}", "{file}"'],
    ['flock', '"flock", "/tmp/l", "{prog}", "{script}", "{file}"'],
    ['unshare', '"unshare", "{prog}", "{script}", "{file}"'],
    ['nsenter', '"nsenter", "-t", "1", "-u", "{prog}", "{script}", "{file}"'],
    ['runuser', '"runuser", "-u", "root", "--", "{prog}", "{script}", "{file}"'],
    ['setpriv', '"setpriv", "--nnp", "{prog}", "{script}", "{file}"'],
    ['time', '"time", "{prog}", "{script}", "{file}"'],
    ['watch', '"watch", "-n", "1", "-g", "{prog}", "{script}", "{file}"'],
    ['docker-exec', '"docker", "exec", "app", "{prog}", "{script}", "{file}"'],
  ] as const) {
    test(`NEW-G2-a: a param in program position behind ${name} needs allow_shell`, async () => {
      writeDefs(`[w]\nargv = [${argv}]\nmutating = false\n${PROG_PARAMS('w')}`);
      const { envelope, remotes } = await drive('w', [
        'prog=sed',
        'script=1e id',
        'file=/etc/hostname',
      ]);
      expect([envelope.error?.code, remotes.length]).toEqual(['VALIDATION_ERROR', 0]);
    });
  }

  for (const [name, argv] of [
    ['script -c', '"script", "-q", "-c", "{code}", "/dev/null"'],
    ['pwsh', '"pwsh", "-c", "{code}"'],
    ['Rscript', '"Rscript", "-e", "{code}"'],
    ['expect', '"expect", "-c", "{code}"'],
    ['irb', '"irb", "-e", "{code}"'],
    ['pypy3', '"pypy3", "-c", "{code}"'],
  ] as const) {
    test(`NEW-G2-b: ${name} runs the code it is handed and needs allow_shell`, async () => {
      writeDefs(
        `[c]\nargv = [${argv}]\nmutating = false\n[c.params.code]\ntype = "regex"\npattern = '[a-z ]+'\n`,
      );
      const { envelope, remotes } = await drive('c', ['code=id']);
      expect([envelope.error?.code, remotes.length]).toEqual(['VALIDATION_ERROR', 0]);
    });
  }

  test('NEW-scrub: a JSON-in-string secret whose quotes are written \\u0022 is masked', () => {
    const value = ['Kq9', 'escaped', 'zz71'].join('-');
    const text = `{"msg":"{\\u0022password\\u0022:\\u0022${value}\\u0022}"}`;
    expect(scrub(text).value).not.toContain(value);
  });
});

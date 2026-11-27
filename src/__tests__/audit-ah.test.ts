import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Re-audit of fix H (08e2e0e): the default-deny param rule. Each probe is a def a human might
 * write WITHOUT allow_shell; `refuse: true` marks the ones where a param ends up as executed code
 * on GNU tools, so the def must answer VALIDATION_ERROR before any remote command is sent.
 */

const ALIAS = 'web-ah';
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

const PARAM_TEXT: Record<string, string> = {
  prog: `[w.params.prog]\ntype = "regex"\npattern = '[a-z0-9./_-]+'\n`,
  script: `[w.params.script]\ntype = "regex"\npattern = '[0-9a-z ./_=:-]+'\n`,
  file: `[w.params.file]\ntype = "regex"\npattern = '[0-9a-z ./_=:-]+'\n`,
};
const paramsFor = (argv: string): string =>
  Object.entries(PARAM_TEXT)
    .filter(([name]) => argv.includes(`"{${name}}"`))
    .map(([, text]) => text)
    .join('');

type Probe = { label: string; argv: string; values: string[]; refuse: boolean };

const PROBES: Probe[] = [
  {
    label: 'sed -f {file}',
    argv: '"sed", "-f", "{file}", "/etc/hostname"',
    values: ['file=/tmp/s.sed'],
    refuse: true,
  },
  {
    label: 'sed --file {file}',
    argv: '"sed", "--file", "{file}", "/etc/hostname"',
    values: ['file=/tmp/s.sed'],
    refuse: true,
  },
  {
    label: 'sed {script} (operand)',
    argv: '"sed", "{script}", "/etc/hostname"',
    values: ['script=1e id'],
    refuse: true,
  },
  {
    label: 'sed -n -e p -e {script}',
    argv: '"sed", "-n", "-e", "p", "-e", "{script}", "/etc/hostname"',
    values: ['script=1e id'],
    refuse: true,
  },
  {
    label: 'sed -e p --expr {script} (abbrev)',
    argv: '"sed", "-e", "p", "--expr", "{script}", "/etc/hostname"',
    values: ['script=1e id'],
    refuse: true,
  },
  {
    label: 'sed -e p --fi {file} (abbrev)',
    argv: '"sed", "-e", "p", "--fi", "{file}", "/etc/hostname"',
    values: ['file=/tmp/s.sed'],
    refuse: true,
  },
  {
    label: 'sed -e p {file} (data)',
    argv: '"sed", "-e", "p", "{file}"',
    values: ['file=/etc/hostname'],
    refuse: false,
  },
  {
    label: 'find {file} -exec cat',
    argv: '"find", "{file}", "-exec", "cat", "{}", ";"',
    values: ['file=/etc'],
    refuse: true,
  },
  {
    label: 'find {file} -name {script}',
    argv: '"find", "{file}", "-name", "{script}"',
    values: ['file=/etc', 'script=hostname'],
    refuse: false,
  },
  {
    label: 'du --files0-from {file}',
    argv: '"du", "--files0-from", "{file}"',
    values: ['file=/etc/hostname'],
    refuse: false,
  },
  {
    label: 'cat -v {file}',
    argv: '"cat", "-v", "{file}"',
    values: ['file=/etc/hostname'],
    refuse: false,
  },
  { label: 'php {script}', argv: '"php", "{script}"', values: ['script=/tmp/x.php'], refuse: true },
  {
    label: 'php -d x=1 {script}',
    argv: '"php", "-d", "x=1", "{script}"',
    values: ['script=/tmp/x.php'],
    refuse: true,
  },
  {
    label: 'php -- {script}',
    argv: '"php", "--", "{script}"',
    values: ['script=/tmp/x.php'],
    refuse: true,
  },
  {
    label: 'php /srv/a.php {file}',
    argv: '"php", "/srv/a.php", "{file}"',
    values: ['file=x'],
    refuse: false,
  },
  {
    label: 'docker run {prog}',
    argv: '"docker", "run", "--rm", "{prog}"',
    values: ['prog=alpine'],
    refuse: true,
  },
  {
    label: 'docker exec app {prog}',
    argv: '"docker", "exec", "app", "{prog}"',
    values: ['prog=id'],
    refuse: true,
  },
  {
    label: 'docker {prog} (subcommand param)',
    argv: '"docker", "{prog}", "app"',
    values: ['prog=logs'],
    refuse: true,
  },
  {
    label: 'docker -H {file} logs',
    argv: '"docker", "-H", "{file}", "logs", "app"',
    values: ['file=unix:/x'],
    refuse: true,
  },
  {
    label: 'docker logs {prog}',
    argv: '"docker", "logs", "{prog}"',
    values: ['prog=app'],
    refuse: false,
  },
  {
    label: 'systemctl --user link {file}',
    argv: '"systemctl", "--user", "link", "{file}"',
    values: ['file=/tmp/x.service'],
    refuse: true,
  },
  {
    label: 'systemctl link {file}',
    argv: '"systemctl", "link", "{file}"',
    values: ['file=/tmp/x.service'],
    refuse: true,
  },
  {
    label: 'systemctl edit {prog}',
    argv: '"systemctl", "edit", "{prog}"',
    values: ['prog=x'],
    refuse: true,
  },
  {
    label: 'systemctl status {prog}',
    argv: '"systemctl", "status", "{prog}"',
    values: ['prog=cron'],
    refuse: false,
  },
  {
    label: 'systemd-run {prog}',
    argv: '"systemd-run", "{prog}"',
    values: ['prog=id'],
    refuse: true,
  },
  {
    label: 'timeout {script} cat',
    argv: '"timeout", "{script}", "cat", "/etc/hostname"',
    values: ['script=5'],
    refuse: true,
  },
  {
    label: 'nice -n {script} cat',
    argv: '"nice", "-n", "{script}", "cat", "/etc/hostname"',
    values: ['script=5'],
    refuse: true,
  },
  {
    label: 'env {script} cat',
    argv: '"env", "{script}", "cat", "/etc/hostname"',
    values: ['script=a=1'],
    refuse: true,
  },
  {
    label: 'env A=1 cat {file}',
    argv: '"env", "A=1", "cat", "{file}"',
    values: ['file=/etc/hostname'],
    refuse: false,
  },
  {
    label: 'sudo -u {prog} cat',
    argv: '"sudo", "-u", "{prog}", "cat", "/etc/hostname"',
    values: ['prog=root'],
    refuse: true,
  },
  {
    label: 'xargs -a {file} cat',
    argv: '"xargs", "-a", "{file}", "cat"',
    values: ['file=/etc/hostname'],
    refuse: true,
  },
  {
    label: 'ionice -c3 cat {file} (unlisted wrapper)',
    argv: '"ionice", "-c3", "cat", "{file}"',
    values: ['file=/etc/hostname'],
    refuse: true,
  },
  {
    label: 'nice {prog} (program param)',
    argv: '"nice", "{prog}"',
    values: ['prog=id'],
    refuse: true,
  },
  {
    label: 'timeout 5 docker exec app {prog}',
    argv: '"timeout", "5", "docker", "exec", "app", "{prog}"',
    values: ['prog=id'],
    refuse: true,
  },
  {
    label: 'xargs --max-lines flock cat {prog} {script} {file}',
    argv: '"xargs", "--max-lines", "flock", "cat", "{prog}", "{script}", "{file}"',
    values: ['prog=sed', 'script=1e id', 'file=/etc/hostname'],
    refuse: true,
  },
  {
    label: 'xargs --eof flock cat {prog} {script} {file}',
    argv: '"xargs", "--eof", "flock", "cat", "{prog}", "{script}", "{file}"',
    values: ['prog=sed', 'script=1e id', 'file=/etc/hostname'],
    refuse: true,
  },
  {
    label: 'env -a cat flock x {prog} {script} {file}',
    argv: '"env", "-a", "cat", "flock", "x", "{prog}", "{script}", "{file}"',
    values: ['prog=sed', 'script=1e id', 'file=/etc/hostname'],
    refuse: true,
  },
  {
    label: 'script -q -c {script}',
    argv: '"script", "-q", "-c", "{script}", "/dev/null"',
    values: ['script=id'],
    refuse: true,
  },
  { label: 'watch -g {prog}', argv: '"watch", "-g", "{prog}"', values: ['prog=id'], refuse: true },
];

describe('fix H re-audit: default-deny param probes', () => {
  beforeAll(() => {
    for (const key of ['SSHEPHERD_EXEC_DIR', 'SSHEPHERD_PROFILE', 'SSHEPHERD_TARGETS_PATH']) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-ah-'));
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

  for (const probe of PROBES) {
    test(`AH-probe: ${probe.label} -> ${probe.refuse ? 'refused' : 'allowed'}`, async () => {
      writeDefs(`[w]\nargv = [${probe.argv}]\nmutating = false\n${paramsFor(probe.argv)}`);
      const { envelope, remotes } = await drive('w', probe.values);
      const got = envelope.error?.code ?? 'OK';
      if (process.env.AH_TABLE === '1') {
        console.log(
          `AHROW\t${probe.label}\t${got}\tremotes=${remotes.length}\t${envelope.error?.message ?? ''}`,
        );
      }
      if (probe.refuse) {
        expect([got, remotes.length]).toEqual(['VALIDATION_ERROR', 0]);
      } else {
        expect(got).not.toBe('VALIDATION_ERROR');
      }
    });
  }
});

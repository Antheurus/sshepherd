import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Fix I, rule A7: a param may appear only behind a data-only argv[0], every literal option of that
 * program spelled exactly as one it has. Plus the literal-def walk: sed's long-option prefixes,
 * xargs's optional-value long options and `env -a`.
 */

const ALIAS = 'web-a7';
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
  const declared = ['p', 'q']
    .filter((name) => argv.includes(`"{${name}}"`))
    .map((name) => `[w.params.${name}]\ntype = "regex"\npattern = '[0-9a-z ./_=:-]+'\n`)
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

const REFUSED: [string, string, string[]][] = [
  ['sed --exp prefix', '"sed", "-e", "p", "--exp", "{p}", "/etc/hostname"', ['p=1e id']],
  ['sed --f prefix', '"sed", "-e", "p", "--f", "{p}", "/etc/hostname"', ['p=/tmp/s.sed']],
  ['sed --expr literal before a param file', '"sed", "--expr", "p", "{p}"', ['p=/etc/hostname']],
  ['sed --expr=p glued prefix', '"sed", "--expr=p", "{p}"', ['p=/etc/hostname']],
  ['sed -ne {p}', '"sed", "-ne", "{p}", "/etc/hostname"', ['p=1e id']],
  ['sed literal w script', '"sed", "-n", "w /tmp/x", "{p}"', ['p=/etc/hostname']],
  ['sed literal s///w script', '"sed", "s/a/b/w /tmp/x", "{p}"', ['p=/etc/hostname']],
  ['sed literal r script', '"sed", "-e", "r /etc/shadow", "{p}"', ['p=/etc/hostname']],
  ['xargs --max-lines=1', '"xargs", "--max-lines=1", "cat", "{p}"', ['p=/etc/hostname']],
  ['xargs -L1', '"xargs", "-L1", "cat", "{p}"', ['p=/etc/hostname']],
  ['xargs --eof=x', '"xargs", "--eof=x", "cat", "{p}"', ['p=/etc/hostname']],
  ['env -a', '"env", "-a", "x", "cat", "{p}"', ['p=/etc/hostname']],
  ['env -i', '"env", "-i", "cat", "{p}"', ['p=/etc/hostname']],
  [
    'env A=1 B=2 cat {p} (fix J: env is a wrapper)',
    '"env", "A=1", "B=2", "cat", "{p}"',
    ['p=/etc/hostname'],
  ],
  ['env then a non-data program', '"env", "A=1", "flock", "x", "{p}"', ['p=/etc/hostname']],
  ['cat --show prefix', '"cat", "--show", "{p}"', ['p=/etc/hostname']],
  ['du --files0 prefix', '"du", "--files0", "{p}"', ['p=/etc/hostname']],
  ['cat unknown short option', '"cat", "-W", "{p}"', ['p=/etc/hostname']],
  ['find -fprint', '"find", "{p}", "-fprint", "/tmp/x"', ['p=/etc']],
  ['find -delete', '"find", "{p}", "-name", "x", "-delete"', ['p=/etc']],
  ['find param in expression', '"find", "/etc", "-name", "x", "{p}"', ['p=hostname']],
  ['php option before the script', '"php", "-n", "/srv/a.php", "{p}"', ['p=x']],
  ['git log with a param', '"git", "log", "{p}"', ['p=main']],
  ['git -C with a param', '"git", "-C", "{p}", "log"', ['p=/srv/app']],
  ['nice before a data program', '"nice", "cat", "{p}"', ['p=/etc/hostname']],
  ['sudo before a data program', '"sudo", "-n", "cat", "{p}"', ['p=/etc/hostname']],
  ['timeout before a data program', '"timeout", "5", "cat", "{p}"', ['p=/etc/hostname']],
  ['docker global option', '"docker", "--context", "x", "logs", "{p}"', ['p=app']],
  ['docker logs unknown option', '"docker", "logs", "--tai", "5", "{p}"', ['p=app']],
  ['systemctl option before the verb', '"systemctl", "--user", "status", "{p}"', ['p=cron']],
  ['systemctl -H', '"systemctl", "status", "-H", "x", "{p}"', ['p=cron']],
];

const ALLOWED: [string, string, string[]][] = [
  ['cat {p}', '"cat", "{p}"', ['p=/etc/hostname']],
  ['du -sh {p}', '"du", "-sh", "{p}"', ['p=/srv/app']],
  ['du --max-depth=1 {p}', '"du", "--max-depth=1", "{p}"', ['p=/srv/app']],
  ['sed -n 1,5p {p}', '"sed", "-n", "1,5p", "{p}"', ['p=/etc/hostname']],
  ['sed --expression=p {p}', '"sed", "-n", "--expression=p", "{p}"', ['p=/etc/hostname']],
  ['sed -i.bak s/a/b/ {p}', '"sed", "-i.bak", "s/a/b/", "{p}"', ['p=/srv/app/x']],
  ['tail -n {p} file', '"tail", "-n", "{p}", "/var/log/syslog"', ['p=20']],
  ['grep -e x -r {p}', '"grep", "-e", "x", "-r", "{p}"', ['p=/srv/app']],
  ['find {p} -name {q} -print', '"find", "{p}", "-name", "{q}", "-print"', ['p=/etc', 'q=host']],
  ['docker logs --tail 5 {p}', '"docker", "logs", "--tail", "5", "{p}"', ['p=app']],
  ['docker restart {p}', '"docker", "restart", "{p}"', ['p=app']],
  ['systemctl status --no-pager {p}', '"systemctl", "status", "--no-pager", "{p}"', ['p=cron']],
  ['php artisan {p}', '"php", "artisan", "{p}"', ['p=migrate:status']],
  ['php /srv/a.php {p}', '"php", "/srv/a.php", "{p}"', ['p=x']],
  ['journalctl -u {p} -n 50', '"journalctl", "-u", "{p}", "-n", "50", "--no-pager"', ['p=cron']],
];

const LITERAL_REFUSED: [string, string][] = [
  ['sed --expr literal e script', '"sed", "--expr", "1e id", "/etc/hostname"'],
  ['sed --e literal e script', '"sed", "--e", "1e id", "/etc/hostname"'],
  ['sed --exp=<script> literal e script', '"sed", "-n", "--exp=1e id", "/etc/hostname"'],
  ['xargs --max-lines before sudo -s', '"xargs", "--max-lines", "sudo", "-s"'],
  ['xargs --replace before sudo -i', '"xargs", "--replace", "sudo", "-i"'],
  ['env -a before sudo -s', '"env", "-a", "x", "sudo", "-s"'],
  ['env --argv0 before chroot', '"env", "--argv0", "x", "chroot", "/jail"'],
];

describe('fix I: rule A7', () => {
  beforeAll(() => {
    for (const key of ['SSHEPHERD_EXEC_DIR', 'SSHEPHERD_PROFILE', 'SSHEPHERD_TARGETS_PATH']) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-a7-'));
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
    test(`A7 refuses without allow_shell: ${label}`, async () => {
      expect(await drive(argv, params)).toEqual({ code: 'VALIDATION_ERROR', runs: 0 });
    });
  }
  for (const [label, argv, params] of ALLOWED) {
    test(`A7 runs: ${label}`, async () => {
      expect(await drive(argv, params)).toEqual({ code: 'OK', runs: 1 });
    });
  }
  for (const [label, argv] of LITERAL_REFUSED) {
    test(`literal def refused without allow_shell: ${label}`, async () => {
      expect(await drive(argv, [])).toEqual({ code: 'VALIDATION_ERROR', runs: 0 });
    });
  }
});

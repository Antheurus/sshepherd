import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildDbExecCommand,
  type DbConnection,
  EXEC_DONE_MARKER,
  EXEC_ROWS_MARKER,
  EXEC_TXN_ENDED_MARKER,
} from '../db.ts';
import { executeOp, getOp } from '../registry.ts';
import { scrub, scrubText } from '../scrub.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Fix H (consolidated re-audit at 1498944). Exec: the default-deny rule must keep every plain def
 * running while refusing a param behind any program not known to take data only. db exec: the
 * relay and watchdog are driven for real through a stub `docker` that plays psql, so the xid
 * compare and the cancel path run as the remote shell would run them.
 */

const ALIAS = 'web-fixh';
let scratch = '';
let execDir = '';
let stubDir = '';
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

/** Plays `docker exec -i <c> psql ... -c <buffer>...`: prints the BEGIN and END marker lines psql
 *  would, the `\echo` lines with ROW_COUNT 1, sleeps on `pg_sleep`, and with no `-c` (the
 *  watchdog's second connection) appends the SQL it was fed to STUB_LOG and answers 0. */
const STUB_DOCKER = [
  '#!/bin/sh',
  'n=0',
  'while [ $# -gt 0 ]; do',
  '  if [ "$1" = -c ]; then',
  '    n=$((n + 1)); b=$2; shift 2',
  '    case "$b" in',
  `      "SELECT '__SSHEPHERD_EXEC_BEGIN__"*) echo "__SSHEPHERD_EXEC_BEGIN__ 100 4242 1764300000.5" ;;`,
  `      "SELECT '__SSHEPHERD_EXEC_END__"*) echo "__SSHEPHERD_EXEC_END__ \${STUB_END_XID:-100}" ;;`,
  "      '\\echo '*) printf '%s\\n' \"$b\" | sed -e 's/^.echo //' -e 's/:ROW_COUNT/1/' ;;",
  '      "SELECT pg_sleep("*) sleep "$STUB_SLEEP" ;;',
  '      FAIL) exit 3 ;;',
  '    esac',
  '  else',
  '    shift',
  '  fi',
  'done',
  '[ "$n" -gt 0 ] || { cat >> "$STUB_LOG"; echo 0; }',
].join('\n');

const CONN: DbConnection = {
  kind: 'container',
  composeFile: '',
  service: '',
  container: 'db',
  user: 'writer',
  database: 'app',
};

async function runRemote(
  command: string,
  env: Record<string, string>,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['sh', '-c', command], {
    env: { ...process.env, PATH: `${stubDir}:${process.env.PATH ?? ''}`, ...env },
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: 'ignore',
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stdout, stderr };
}

describe('fix H', () => {
  beforeAll(() => {
    for (const key of ['SSHEPHERD_EXEC_DIR', 'SSHEPHERD_PROFILE', 'SSHEPHERD_TARGETS_PATH']) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-fixh-'));
    execDir = join(scratch, 'exec');
    stubDir = join(scratch, 'bin');
    mkdirSync(execDir, { recursive: true, mode: 0o700 });
    mkdirSync(stubDir, { recursive: true });
    writeFileSync(join(stubDir, 'docker'), STUB_DOCKER);
    chmodSync(join(stubDir, 'docker'), 0o755);
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

  test('NEW-1: the plain defs a param may follow still run', async () => {
    const pathParam = '[run-it.params.p]\ntype = "path"\nunder = "/srv"\n';
    const fileParam = '[run-it.params.p]\ntype = "enum"\nvalues = ["/etc/hostname"]\n';
    const cmdParam = '[run-it.params.p]\ntype = "enum"\nvalues = ["migrate:status"]\n';
    const unitParam = '[run-it.params.p]\ntype = "enum"\nvalues = ["nginx"]\n';
    const cParam = '[run-it.params.p]\ntype = "container"\n';
    for (const [argv, params, value] of [
      ['["php", "artisan", "{p}"]', cmdParam, 'migrate:status'],
      ['["cat", "{p}"]', fileParam, '/etc/hostname'],
      ['["du", "-sh", "{p}"]', pathParam, '/srv/app'],
      ['["sed", "-n", "1,5p", "{p}"]', fileParam, '/etc/hostname'],
      ['["docker", "restart", "{p}"]', cParam, 'app'],
      ['["systemctl", "status", "{p}"]', unitParam, 'nginx'],
      ['["git", "log", "-n", "1"]', '', ''],
    ] as const) {
      writeDefs(`[run-it]\nargv = ${argv}\nmutating = false\n${params}`);
      const { envelope, remotes } = await drive('run-it', value === '' ? [] : [`p=${value}`]);
      expect({ argv, error: envelope.error, runs: remotes.length }).toEqual({
        argv,
        error: null,
        runs: 1,
      });
    }
  });

  test('NEW-1: a param behind an unknown program, a wrapper option or a non-data subcommand needs allow_shell', async () => {
    const v = '[run-it.params.v]\ntype = "regex"\npattern = \'[a-z0-9:]+\'\n';
    for (const argv of [
      '["/opt/app/bin/report", "{v}"]',
      '["git", "log", "{v}"]',
      '["docker", "exec", "app", "cat", "{v}"]',
      '["docker", "{v}", "app"]',
      '["systemctl", "link", "{v}"]',
      '["php", "{v}"]',
      '["php", "-d", "x=1", "artisan", "{v}"]',
      '["sudo", "-u", "{v}", "du", "/srv"]',
      '["xargs", "-a", "{v}", "du"]',
      '["timeout", "{v}", "du", "/srv"]',
      '["sed", "{v}", "/etc/hostname"]',
      '["nice", "du", "{v}"]',
      '["nice", "-n", "5", "du", "-sh", "{v}"]',
      '["sudo", "-u", "admins", "du", "-sh", "{v}"]',
    ]) {
      writeDefs(`[run-it]\nargv = ${argv}\nmutating = false\n${v}`);
      const { envelope, remotes } = await drive('run-it', ['v=x']);
      expect({ argv, code: envelope.error?.code, runs: remotes.length }).toEqual({
        argv,
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
    }
    writeDefs(
      `[run-it]\nargv = ["/opt/app/bin/report", "{v}"]\nmutating = false\nallow_shell = true\n${v}`,
    );
    expect((await drive('run-it', ['v=x'])).envelope.error).toBeNull();
  });

  test('NEW-2: busybox applets that execute are refused, literal or with a param', async () => {
    for (const argv of [
      '["busybox", "sh", "-c", "id"]',
      '["busybox", "ash", "-c", "id"]',
      '["busybox", "awk", "BEGIN{}"]',
      '["busybox", "sed", "1e id", "/etc/hostname"]',
      '["watch", "-n", "1", "id"]',
      '["script", "-q", "-c", "id", "/dev/null"]',
    ]) {
      writeDefs(`[run-it]\nargv = ${argv}\nmutating = false\n`);
      const { envelope, remotes } = await drive('run-it', []);
      expect({ argv, code: envelope.error?.code, runs: remotes.length }).toEqual({
        argv,
        code: 'VALIDATION_ERROR',
        runs: 0,
      });
    }
  });

  test('NEW-5: JSON-in-string secrets three and four levels deep, and cut off unterminated, are masked', () => {
    const value = ['Kq9', 'nested', 'zz71'].join('-');
    const nested = (levels: number): string => {
      let text = `{"password":"${value}"}`;
      for (let level = 0; level < levels; level += 1) {
        text = JSON.stringify(text);
      }
      return `{"msg":${text}}`;
    };
    for (const text of [
      nested(3),
      nested(4),
      `{"msg":"{\\"password\\":\\"${value}`,
      `{"password":"${value}`,
    ]) {
      expect(scrub(text).value).not.toContain(value);
    }
    expect(scrub(nested(1)).value).toContain('password');
  });

  test('NEW-6: a pair inside a URL percent-encoded twice or three times is masked', () => {
    const value = ['sv', 'enc', '42'].join('');
    for (const text of [
      `next=https%253A%252F%252Fa.example%252Fcb%253Ftoken%253D${value}`,
      `next=https%25253A%25252F%25252Fa.example%25252Fcb%25253Ftoken%25253D${value}&x=1`,
    ]) {
      const out = scrubText(text, {}).value;
      expect(out).not.toContain(value);
      expect(out).toContain('a.example');
    }
  });

  test('NEW-3: every statement is preceded by the timer pin, the idle timeout is set for the session', () => {
    const command = buildDbExecCommand(CONN, 5, ['UPDATE t SET n = 1', 'UPDATE t SET n = 2'], true);
    expect(command.split('SET statement_timeout=3000;SET lock_timeout=2000').length - 1).toBe(2);
    expect(command).toContain('SET idle_in_transaction_session_timeout=3000');
    expect(command).toContain(
      "pg_settings WHERE name OPERATOR(pg_catalog.=) '\\''transaction_timeout'\\''",
    );
  });

  test("AH-2: sshepherd's own lines name every operator and function with pg_catalog, and pin search_path before the end checks", () => {
    const command = buildDbExecCommand(CONN, 5, ['UPDATE t SET n = 1'], false);
    const own = command.slice(command.indexOf('__SSHEPHERD_EXEC_BEGIN__'));
    const tail = command.slice(command.lastIndexOf(`${EXEC_ROWS_MARKER} 1 :ROW_COUNT`));
    expect(own).not.toMatch(/[^(.]\|\|/);
    expect(tail).toContain('SET search_path=pg_catalog');
    expect(tail.indexOf('SET search_path=pg_catalog')).toBeLessThan(
      tail.indexOf('sshepherd.exec_xid'),
    );
    expect(tail).toContain(
      "SELECT '\\''__SSHEPHERD_EXEC_END__ '\\'' OPERATOR(pg_catalog.||) pg_catalog.txid_current()",
    );
    expect(tail).not.toMatch(/[^.]txid_current|[^.]current_setting|::text|::int[^4]/);
  });

  test('NEW-4: the relay passes the rows through and exits 0 when the xid at the end is the BEGIN one', async () => {
    const log = join(scratch, 'signal-ok.log');
    const command = buildDbExecCommand(CONN, 2, ['UPDATE t SET n = 1'], false);
    const run = await runRemote(command, { STUB_LOG: log, STUB_SLEEP: '0' });
    expect(run.code).toBe(0);
    expect(run.stdout).toBe(`${EXEC_ROWS_MARKER} 1 1\n${EXEC_DONE_MARKER} rolled_back\n`);
    expect(run.stderr).not.toContain(EXEC_TXN_ENDED_MARKER);
    await Bun.sleep(2500);
    expect(() => readFileSync(log, 'utf8')).toThrow();
  });

  test('NEW-4: a forged transaction (END xid differs from BEGIN) fails with EXEC_TXN_ENDED_MARKER', async () => {
    const command = buildDbExecCommand(CONN, 2, ['COMMIT', 'BEGIN'], false);
    const forged = await runRemote(command, {
      STUB_LOG: join(scratch, 'signal-forged.log'),
      STUB_SLEEP: '0',
      STUB_END_XID: '101',
    });
    expect(forged.code).toBe(3);
    expect(forged.stderr).toContain(`${EXEC_TXN_ENDED_MARKER}: the transaction at the end (101)`);
    const failed = await runRemote(buildDbExecCommand(CONN, 2, ['FAIL'], false), {
      STUB_LOG: join(scratch, 'signal-failed.log'),
      STUB_SLEEP: '0',
    });
    expect([failed.code, failed.stderr.includes(EXEC_TXN_ENDED_MARKER)]).toEqual([3, false]);
  });

  test('NEW-3: past the budget the watchdog cancels then terminates that backend, matched by pid and start', async () => {
    const log = join(scratch, 'signal-late.log');
    const command = buildDbExecCommand(CONN, 1, ['SELECT pg_sleep(3)'], true);
    const run = await runRemote(command, { STUB_LOG: log, STUB_SLEEP: '3' });
    expect(run.code).toBe(0);
    await Bun.sleep(1500);
    const sent = readFileSync(log, 'utf8');
    const match =
      'FROM pg_catalog.pg_stat_activity WHERE pid OPERATOR(pg_catalog.=) 4242 AND extract(epoch FROM backend_start) OPERATOR(pg_catalog.=) 1764300000.5;';
    expect(sent).toContain(`SELECT pg_catalog.pg_cancel_backend(pid) ${match}`);
    expect(sent).toContain(`SELECT pg_catalog.pg_terminate_backend(pid) ${match}`);
    expect(sent.indexOf('pg_cancel_backend')).toBeLessThan(sent.indexOf('pg_terminate_backend'));
  });
});

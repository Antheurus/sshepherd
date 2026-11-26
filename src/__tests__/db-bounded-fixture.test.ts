import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DB_LOCK_TIMEOUT_SEC, DB_QUERY_ROW_LIMIT } from '../limits.ts';
import { executeOp, getOp } from '../registry.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

/**
 * The bounded db reads against the smoke fixture's real postgres: the row limit, the
 * `statement_timeout` cancel (proved with a lowered budget, so it is Postgres and not the ssh
 * timeout that ends the statement), the `lock_timeout` cancel, and the `host` target kind (psql in
 * the sshd container itself). Smoke-only: skipped without the fixture.
 */

const REPO = join(import.meta.dir, '..', '..');

function fixtureNames(): { prefix: string; state: string } {
  const proc = Bun.spawnSync(
    [
      'bash',
      '-c',
      '. "$1"; printf "%s\\n%s" "$SMOKE_PREFIX" "$SMOKE_STATE"',
      'bash',
      join(REPO, 'scripts', 'sshd-fixture', 'project.sh'),
    ],
    { stdout: 'pipe', stderr: 'pipe' },
  );
  const [prefix = '', state = ''] = proc.stdout.toString().split('\n');
  return { prefix, state };
}

const { prefix: PREFIX, state: STATE } = fixtureNames();
const POSTGRES = `${PREFIX}-postgres`;
const SSH_CONFIG = join(STATE, 'ssh_config');
const ALIASES = ['smoke-debian', 'smoke-alpine'];

function fixtureUp(): boolean {
  if (!existsSync(SSH_CONFIG)) {
    return false;
  }
  const proc = Bun.spawnSync(['docker', 'inspect', '-f', '{{.State.Running}}', POSTGRES], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const SAVED = ['SSHEPHERD_TARGETS_PATH', 'XDG_RUNTIME_DIR', 'SSHEPHERD_SSH_CONFIG_PATH'] as const;
const saved: Record<string, string | undefined> = {};
let scratch = '';

async function run(
  name: string,
  target: string,
  args: Record<string, string>,
  timeoutSec?: number,
): Promise<Envelope<unknown>> {
  const op = getOp('db', name);
  if (op === undefined) {
    throw new Error(`db ${name} missing`);
  }
  return executeOp(op, buildDbOpContext(target, args), {
    transport: { runner: defaultRunner, sshConfigPath: SSH_CONFIG },
    sshConfigPath: SSH_CONFIG,
    auditLogPath: join(scratch, 'audit.jsonl'),
    ...(timeoutSec === undefined ? {} : { timeoutSec }),
  });
}

describe.skipIf(!fixtureUp())('bounded db reads (smoke fixture)', () => {
  beforeAll(() => {
    for (const key of SAVED) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-db-bounded-'));
    writeFileSync(
      join(scratch, 'targets.toml'),
      [
        `[prod]\nalias = "smoke-debian"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
        ...ALIASES.map(
          (alias) =>
            `[${alias}-host]\nalias = "${alias}"\nkind = "host"\npg_host = "postgres"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
        ),
      ].join('\n'),
    );
    process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
    process.env.SSHEPHERD_SSH_CONFIG_PATH = SSH_CONFIG;
    process.env.XDG_RUNTIME_DIR = join(STATE, 'run');
  });

  afterAll(async () => {
    for (const alias of ALIASES) {
      await closeMaster(alias);
    }
    for (const key of SAVED) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    }
    rmSync(scratch, { recursive: true, force: true });
  });

  test(`row limit: ${DB_QUERY_ROW_LIMIT} of 1200 rows with truncated: true; --max-rows 1200 returns them all`, async () => {
    const capped = await run('query', 'prod', { sql: 'SELECT id FROM big ORDER BY id' });
    const data = capped.data as { rows: { id: number }[]; row_count: number; truncated: boolean };
    expect({
      row_count: data.row_count,
      truncated: data.truncated,
      last: data.rows.at(-1),
    }).toEqual({
      row_count: DB_QUERY_ROW_LIMIT,
      truncated: true,
      last: { id: DB_QUERY_ROW_LIMIT },
    });
    const all = await run('query', 'prod', { sql: 'SELECT id FROM big', 'max-rows': '1200' });
    expect(all.data).toMatchObject({ row_count: 1200, truncated: false });
  }, 60_000);

  test('a lowered budget (6 s) is cancelled by statement_timeout (3 s), not by the ssh timeout', async () => {
    const started = Date.now();
    const envelope = await run('query', 'prod', { sql: 'SELECT pg_sleep(20)', timeout: '6' }, 6);
    const elapsed = Date.now() - started;
    expect({
      code: envelope.error?.code,
      timeout_sec: envelope.error?.timeout_sec,
      remote_exit: envelope.error?.remote_exit,
      sql_error: (envelope.error?.data?.sql_error as { message?: string } | undefined)?.message,
    }).toEqual({
      code: 'COMMAND_TIMEOUT',
      timeout_sec: 3,
      remote_exit: 1,
      sql_error: 'canceling statement due to statement timeout',
    });
    expect(elapsed).toBeLessThan(6_000);
  }, 60_000);

  test(`a read queued behind another session's lock gives up at lock_timeout (${DB_LOCK_TIMEOUT_SEC} s)`, async () => {
    const holder = Bun.spawn(
      [
        'docker',
        'exec',
        POSTGRES,
        'psql',
        '-U',
        'postgres',
        '-d',
        'fixture',
        '-c',
        'BEGIN; LOCK TABLE orgs IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(5); ROLLBACK;',
      ],
      { stdout: 'ignore', stderr: 'ignore' },
    );
    try {
      await Bun.sleep(1_500);
      const envelope = await run('count', 'prod', { table: 'orgs' });
      expect({ code: envelope.error?.code, timeout_sec: envelope.error?.timeout_sec }).toEqual({
        code: 'COMMAND_TIMEOUT',
        timeout_sec: DB_LOCK_TIMEOUT_SEC,
      });
      expect(envelope.error?.message).toContain('lock_timeout');
    } finally {
      await holder.exited;
    }
  }, 60_000);

  for (const alias of ALIASES) {
    test(`${alias}: a host target runs psql on the host itself`, async () => {
      const envelope = await run('query', `${alias}-host`, {
        sql: 'SELECT current_user AS u, count(*)::int AS n FROM users',
      });
      expect(envelope.data).toEqual({
        rows: [{ u: 'sshepherd_ro', n: 2 }],
        row_count: 1,
        truncated: false,
        masked_columns: [],
      });
      const count = await run('count', `${alias}-host`, { table: 'users', 'where-eq': 'id=1' });
      expect(count.data).toEqual({ count: 1 });
    }, 60_000);
  }
});

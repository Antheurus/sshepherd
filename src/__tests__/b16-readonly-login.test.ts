import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

/**
 * Gotcha B16: `SET ROLE` never sandboxes untrusted SQL — `RESET ROLE` or `set_config('role', ...)`
 * inside the statement returns it to the LOGIN role. So the fixture's `db query` target logs in AS
 * the read-only role (`sshepherd_ro`, created by the fixture's own postgres init), and this test
 * proves the escape fails twice: through sshepherd, and with every sshepherd parser bypassed (psql
 * straight into the container). A superuser login running the same escape is the control: it
 * gets out, which is why the login role is the boundary. Smoke-only: skipped without the fixture.
 */

const REPO = join(import.meta.dir, '..', '..');
const ALIAS = 'smoke-debian';

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

/** psql straight into the fixture postgres: no sshepherd guard, wrapper or parser in the way. */
function psqlDirect(user: string, script: string): { stdout: string; stderr: string } {
  const proc = Bun.spawnSync(
    ['docker', 'exec', '-i', POSTGRES, 'psql', '-X', '-U', user, '-d', 'fixture', '-At'],
    { stdin: Buffer.from(script), stdout: 'pipe', stderr: 'pipe' },
  );
  return { stdout: proc.stdout.toString(), stderr: proc.stderr.toString() };
}

const markerRows = (marker: string): string =>
  psqlDirect(
    'postgres',
    `SELECT count(*) FROM smoke_fixture WHERE note = '${marker}';`,
  ).stdout.trim();

const SAVED = ['SSHEPHERD_TARGETS_PATH', 'XDG_RUNTIME_DIR', 'SSHEPHERD_SSH_CONFIG_PATH'] as const;
const saved: Record<string, string | undefined> = {};
let scratch = '';

describe.skipIf(!fixtureUp())(
  'B16: the read-only LOGIN role is the boundary (smoke fixture)',
  () => {
    beforeAll(() => {
      for (const key of SAVED) {
        saved[key] = process.env[key];
      }
      scratch = mkdtempSync(join(tmpdir(), 'sshepherd-b16-'));
      writeFileSync(
        join(scratch, 'targets.toml'),
        `[prod]\nalias = "${ALIAS}"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
      );
      process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
      process.env.SSHEPHERD_SSH_CONFIG_PATH = SSH_CONFIG;
      process.env.XDG_RUNTIME_DIR = join(STATE, 'run');
    });

    afterAll(async () => {
      await closeMaster(ALIAS);
      for (const key of SAVED) {
        if (saved[key] === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = saved[key];
        }
      }
      rmSync(scratch, { recursive: true, force: true });
    });

    async function dbQuery(sql: string): Promise<Envelope<unknown>> {
      const op = getOp('db', 'query');
      if (op === undefined) {
        throw new Error('db query op missing');
      }
      return executeOp(op, buildDbOpContext('prod', { sql }), {
        transport: { runner: defaultRunner, sshConfigPath: SSH_CONFIG },
        sshConfigPath: SSH_CONFIG,
        auditLogPath: join(scratch, 'audit.jsonl'),
      });
    }

    const sqlError = (envelope: Envelope<unknown>): unknown =>
      (envelope.error?.data?.sql_error as { message?: string } | undefined)?.message;

    test('through sshepherd: RESET ROLE is refused, set_config(role) is denied, and a write after it fails', async () => {
      const reset = await dbQuery('RESET ROLE; SELECT 1');
      expect(reset.error?.code).toBe('VALIDATION_ERROR');

      const roleEscape = await dbQuery("SELECT set_config('role', 'postgres', false)");
      expect(sqlError(roleEscape)).toBe('permission denied to set role "postgres"');

      const marker = `b16-cte-${Date.now()}`;
      const write = await dbQuery(
        `WITH w AS (INSERT INTO smoke_fixture (note) VALUES ('${marker}') RETURNING id) SELECT set_config('default_transaction_read_only', 'off', false), (SELECT count(*) FROM w)`,
      );
      expect(write.ok).toBe(false);
      expect(String(sqlError(write))).toMatch(
        /read-only transaction|permission denied|data-modifying statement must be at the top level/,
      );
      expect(markerRows(marker)).toBe('0');

      const still = await dbQuery('SELECT current_user AS u');
      expect((still.data as { rows: unknown[] }).rows).toEqual([{ u: 'sshepherd_ro' }]);
    }, 60_000);

    test('parsers bypassed (psql as sshepherd_ro): every escape is denied and no write lands', () => {
      const marker = `b16-direct-${Date.now()}`;
      const { stdout, stderr } = psqlDirect(
        'sshepherd_ro',
        [
          'RESET ROLE;',
          "SELECT set_config('role', 'postgres', false);",
          'SET default_transaction_read_only = off;',
          'BEGIN READ WRITE;',
          `INSERT INTO smoke_fixture (note) VALUES ('${marker}');`,
          'COMMIT;',
          'SELECT current_user;',
          '',
        ].join('\n'),
      );
      expect(stderr).toContain('permission denied to set role "postgres"');
      expect(stderr).toContain('permission denied for table smoke_fixture');
      expect(stdout.trim().split('\n').at(-1)).toBe('sshepherd_ro');
      expect(markerRows(marker)).toBe('0');
    });

    test('control: a superuser login that only SET ROLEs to sshepherd_ro gets out with RESET ROLE', () => {
      const marker = `b16-control-${Date.now()}`;
      const { stdout } = psqlDirect(
        'postgres',
        [
          'BEGIN;',
          'SET LOCAL ROLE sshepherd_ro;',
          'RESET ROLE;',
          'SELECT current_user;',
          `INSERT INTO smoke_fixture (note) VALUES ('${marker}') RETURNING 'inserted';`,
          'ROLLBACK;',
          '',
        ].join('\n'),
      );
      expect(stdout).toContain('postgres');
      expect(stdout).toContain('inserted');
      expect(markerRows(marker)).toBe('0');
    });
  },
);

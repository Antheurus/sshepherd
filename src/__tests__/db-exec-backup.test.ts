import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifySqlStatement, splitSqlStatements } from '../db.ts';
import { executeOp, getOp } from '../registry.ts';
import { buildDbOpContext, loadTargets } from '../targets.ts';
import { closeMaster, type SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Phase 13: `db exec` (one transaction as the target's write_role, per-statement row counts,
 * `--dry-run` rolls back, DDL refused without `--allow-ddl`, sha256 + tables in the audit row and
 * the scrubbed text only in a 0600 side file), `db backup` and `db backup-verify`.
 *
 * Gotcha B2: a restore is verified by real per-table COUNT(*) on both sides, never by a hash or an
 * exit code — the live test changes the source after the dump and expects the mismatch to show.
 * Gotcha B10: no shared fixture table is mutated to reproduce anything; every write lands in a
 * schema and a write role this file creates and drops, and the throwaway restore databases are
 * counted at the end (0 left).
 */

const REPO = join(import.meta.dir, '..', '..');

function op(group: string, name: string): OpSpec {
  const found = getOp(group, name);
  if (found === undefined) {
    throw new Error(`${group} ${name} op missing`);
  }
  return found;
}

const classify = (sql: string) => splitSqlStatements(sql).map(classifySqlStatement);

describe('db exec statement splitting', () => {
  test('splits at ; outside strings, quoted names, dollar quotes and comments', () => {
    const sql = [
      "INSERT INTO t (a) VALUES ('x;y');",
      'UPDATE "we;ird" SET a = 1; -- trailing ; comment',
      'DO $body$ BEGIN PERFORM 1; END $body$;',
      "SELECT E'it\\'s;';",
      '/* a ; block /* nested ; */ */ DELETE FROM t',
      ';;',
    ].join('\n');
    expect(splitSqlStatements(sql).map((statement) => statement.text)).toEqual([
      "INSERT INTO t (a) VALUES ('x;y')",
      'UPDATE "we;ird" SET a = 1',
      '-- trailing ; comment\nDO $body$ BEGIN PERFORM 1; END $body$',
      "SELECT E'it\\'s;'",
      '/* a ; block /* nested ; */ */ DELETE FROM t',
    ]);
  });

  test('an unclosed string or comment is refused, never split by guess', () => {
    expect(() => splitSqlStatements("UPDATE t SET a = 'open; DELETE FROM t")).toThrow(
      'leaves a string open',
    );
    expect(() => splitSqlStatements('DELETE FROM t /* open')).toThrow('inside a /* comment');
    expect(() => splitSqlStatements('DO $x$ BEGIN')).toThrow('dollar-quoted');
  });
});

describe('db exec statement classification', () => {
  test('DDL verbs, EXPLAIN ANALYZE around one, and SELECT ... INTO are DDL; DML is not', () => {
    const ddl = (sql: string) => classify(sql).map((info) => [info.command, info.ddl]);
    expect(ddl('DROP TABLE exec_demo')).toEqual([['DROP', true]]);
    expect(ddl('truncate orders')).toEqual([['TRUNCATE', true]]);
    expect(ddl('ALTER ROLE app PASSWORD NULL')).toEqual([['ALTER', true]]);
    expect(ddl("DO $$ BEGIN RAISE NOTICE 'x'; END $$")).toEqual([['DO', true]]);
    expect(ddl('CALL refresh_all()')).toEqual([['CALL', true]]);
    expect(ddl('GRANT SELECT ON t TO r')).toEqual([['GRANT', true]]);
    expect(ddl('SELECT * INTO copy_of_t FROM t')).toEqual([['SELECT', true]]);
    expect(ddl('EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1')).toEqual([['CREATE', true]]);
    expect(ddl('EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t')).toEqual([['DELETE', false]]);
    expect(ddl("INSERT INTO t (a) VALUES ('drop table x')")).toEqual([['INSERT', false]]);
    expect(
      ddl('WITH gone AS (DELETE FROM t RETURNING id) INSERT INTO log SELECT id FROM gone'),
    ).toEqual([['WITH', false]]);
    expect(ddl('MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE')).toEqual([
      ['MERGE', false],
    ]);
  });

  test('transaction control, psql meta-commands, role/timer changes and COPY PROGRAM are refused outright', () => {
    const refused = (sql: string) => classify(sql)[0]?.refused ?? null;
    for (const sql of [
      'BEGIN',
      'COMMIT',
      'end',
      'ROLLBACK',
      'SAVEPOINT s',
      'PREPARE TRANSACTION $$x$$',
    ]) {
      expect({ sql, refused: refused(sql) }).toEqual({
        sql,
        refused: expect.stringContaining('transaction'),
      });
    }
    expect(refused('\\! rm -rf /')).toContain('psql meta-command');
    expect(refused('SET ROLE postgres')).toContain('login role');
    expect(refused('SET SESSION AUTHORIZATION postgres')).toContain('login role');
    expect(refused('set local statement_timeout = 0')).toContain('timer');
    expect(refused('RESET ALL')).toContain('timer');
    expect(refused("SELECT set_config('role', 'postgres', false)")).toContain('set_config');
    expect(refused("COPY t TO PROGRAM 'curl example.invalid'")).toContain('shell command');
    expect(refused('CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1')).toContain(
      'BEGIN ATOMIC',
    );
    expect(refused('SET search_path = app')).toBeNull();
    expect(refused('UPDATE t SET a = 1')).toBeNull();
  });

  test('table names are read off FROM/JOIN/INTO/UPDATE/TABLE/TRUNCATE/USING, never function calls', () => {
    const tables = (sql: string) => classify(sql)[0]?.tables;
    expect(
      tables('UPDATE App.Orders o SET total = 0 FROM "Line Items" li WHERE li.id = o.id'),
    ).toEqual(['app.orders', '"Line Items"']);
    expect(tables('DROP TABLE IF EXISTS a, b CASCADE')).toEqual(['a', 'b']);
    expect(tables('INSERT INTO audit_log (id) SELECT id FROM generate_series(1, 3) id')).toEqual([
      'audit_log',
    ]);
    expect(tables('DELETE FROM ONLY sessions USING users u WHERE u.id = 1')).toEqual([
      'sessions',
      'users',
    ]);
  });
});

describe('targets.toml write_role and retention', () => {
  let dir = '';
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'sshepherd-p13-targets-'));
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const load = (body: string) => {
    const path = join(dir, `t-${Math.random().toString(36).slice(2)}.toml`);
    writeFileSync(
      path,
      `[prod]\nalias = "box"\ncontainer = "db"\nuser = "ro"\ndatabase = "app"\n${body}`,
    );
    return loadTargets(path).prod;
  };

  test('declared fields are read; absent ones leave the target exactly as before', () => {
    expect(
      load(
        'write_role = "app_rw"\nbackup_dir = "/srv/dumps"\nbackup_keep = 3\nbackup_max_bytes = 1000\n',
      ),
    ).toMatchObject({
      writeRole: 'app_rw',
      backupDir: '/srv/dumps',
      backupKeep: 3,
      backupMaxBytes: 1000,
    });
    const plain = load('') as unknown as Record<string, unknown>;
    expect(
      ['writeRole', 'backupDir', 'backupKeep', 'backupMaxBytes'].filter((key) => key in plain),
    ).toEqual([]);
  });

  test('a malformed write_role, keep or size is a CONFIG_PARSE_ERROR naming the field', () => {
    expect(() => load('write_role = "app; DROP"\n')).toThrow('write_role');
    expect(() => load('backup_keep = 0\n')).toThrow('backup_keep');
    expect(() => load('backup_keep = 101\n')).toThrow('backup_keep');
    expect(() => load('backup_max_bytes = "5G"\n')).toThrow('backup_max_bytes');
  });
});

describe('db exec gates before any ssh call (scripted runner)', () => {
  let dir = '';
  let calls = 0;
  const runner: SshRunner = async () => {
    calls += 1;
    return { code: 0, stdout: '', stderr: '', timedOut: false };
  };
  const saved = process.env.SSHEPHERD_TARGETS_PATH;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'sshepherd-p13-gates-'));
    writeFileSync(
      join(dir, 'targets.toml'),
      [
        '[norole]\nalias = "box"\ncontainer = "db"\nuser = "ro"\ndatabase = "app"\n',
        '[same]\nalias = "box"\ncontainer = "db"\nuser = "ro"\ndatabase = "app"\nwrite_role = "ro"\n',
        '[prod]\nalias = "box"\ncontainer = "db"\nuser = "ro"\ndatabase = "app"\nwrite_role = "app_rw"\n',
        '[url]\nalias = "box"\nkind = "container-env"\ncontainer = "app"\nwrite_role = "app_rw"\n',
      ].join('\n'),
    );
    writeFileSync(
      join(dir, 'drop.sql'),
      "-- clean up\nDROP TABLE orders;\nUPDATE users SET pw = 'x';\n",
    );
    writeFileSync(join(dir, 'ok.sql'), "UPDATE users SET nickname = 'a';\n");
    writeFileSync(join(dir, 'ssh_config'), 'Host box\n  HostName 10.0.0.9\n');
    process.env.SSHEPHERD_TARGETS_PATH = join(dir, 'targets.toml');
  });
  afterAll(() => {
    if (saved === undefined) {
      delete process.env.SSHEPHERD_TARGETS_PATH;
    } else {
      process.env.SSHEPHERD_TARGETS_PATH = saved;
    }
    rmSync(dir, { recursive: true, force: true });
  });

  async function exec(
    target: string,
    args: Record<string, string | boolean>,
    auditLogPath: string,
  ) {
    calls = 0;
    const envelope = await executeOp(op('db', 'exec'), buildDbOpContext(target, args), {
      transport: { runner, sshConfigPath: join(dir, 'ssh_config') },
      sshConfigPath: join(dir, 'ssh_config'),
      yes: true,
      auditLogPath,
    });
    return { envelope, calls };
  }

  test('no write_role, write_role equal to user, or a container-env target: VALIDATION_ERROR naming why, 0 ssh calls', async () => {
    const file = join(dir, 'ok.sql');
    const norole = await exec('norole', { file }, join(dir, 'a1.jsonl'));
    expect([norole.envelope.error?.code, norole.calls]).toEqual(['VALIDATION_ERROR', 0]);
    expect(norole.envelope.error?.message).toContain('declares no write_role');
    const same = await exec('same', { file }, join(dir, 'a2.jsonl'));
    expect(same.envelope.error?.message).toContain('write_role equal to user');
    const url = await exec('url', { file }, join(dir, 'a3.jsonl'));
    expect(url.envelope.error?.message).toContain('container-env');
  });

  test('DROP TABLE without --allow-ddl: DDL_REFUSED, 0 ssh calls; the audit row holds sql_sha256 + tables, the text only in a 0600 side file', async () => {
    const stateDir = join(dir, 'state');
    const auditLogPath = join(stateDir, 'audit.jsonl');
    const { envelope, calls: made } = await exec(
      'prod',
      { file: join(dir, 'drop.sql') },
      auditLogPath,
    );
    expect([envelope.error?.code, made]).toEqual(['DDL_REFUSED', 0]);
    expect(envelope.error?.message).toContain('statement 1 (DROP)');

    const sql = readFileSync(join(dir, 'drop.sql'), 'utf8');
    const sha = new Bun.CryptoHasher('sha256').update(sql).digest('hex');
    const rowText = readFileSync(auditLogPath, 'utf8');
    const row = JSON.parse(rowText.trim()) as Record<string, unknown>;
    expect(row).toMatchObject({
      command: 'db exec',
      outcome: 'error',
      error_code: 'DDL_REFUSED',
      sql_sha256: sha,
      tables: ['orders', 'users'],
    });
    expect(rowText).not.toContain('DROP TABLE');
    expect(rowText).not.toContain('app_rw');

    const side = join(stateDir, 'sql', `${sha}.sql`);
    expect(statSync(side).mode & 0o777).toBe(0o600);
    expect(statSync(join(stateDir, 'sql')).mode & 0o777).toBe(0o700);
    expect(readFileSync(side, 'utf8')).toContain('DROP TABLE orders;');
  });

  test('--dry-run runs for real then rolls back: no confirm gate, but the deploy profile and an audit row with dry_run; --allow-ddl lets the plan through to ssh', async () => {
    const savedProfile = process.env.SSHEPHERD_PROFILE;
    try {
      process.env.SSHEPHERD_PROFILE = 'read';
      const readLog = join(dir, 'dry-read.jsonl');
      const denied = await exec('prod', { file: join(dir, 'ok.sql'), 'dry-run': true }, readLog);
      expect([denied.envelope.error?.code, denied.calls]).toEqual(['PROFILE_DENIED', 0]);

      process.env.SSHEPHERD_PROFILE = 'deploy';
      const auditLogPath = join(dir, 'dry.jsonl');
      const dry = await exec(
        'prod',
        { file: join(dir, 'drop.sql'), 'dry-run': true, 'allow-ddl': true },
        auditLogPath,
      );
      expect(dry.calls).toBe(1);
      const sha = new Bun.CryptoHasher('sha256')
        .update(readFileSync(join(dir, 'drop.sql'), 'utf8'))
        .digest('hex');
      expect(JSON.parse(readFileSync(auditLogPath, 'utf8').trim())).toMatchObject({
        command: 'db exec',
        dry_run: true,
        sql_sha256: sha,
        tables: ['orders', 'users'],
      });
    } finally {
      if (savedProfile === undefined) {
        delete process.env.SSHEPHERD_PROFILE;
      } else {
        process.env.SSHEPHERD_PROFILE = savedProfile;
      }
    }
  });

  test('side files: one older than 90 days is deleted, and the oldest go first past 200 MB', async () => {
    const stateDir = join(dir, 'retention');
    const sqlDir = join(stateDir, 'sql');
    mkdirSync(sqlDir, { recursive: true });
    const stale = join(sqlDir, `${'a'.repeat(64)}.sql`);
    const big = join(sqlDir, `${'b'.repeat(64)}.sql`);
    const recent = join(sqlDir, `${'c'.repeat(64)}.sql`);
    const unrelated = join(sqlDir, 'notes.txt');
    writeFileSync(stale, 'old');
    writeFileSync(big, Buffer.alloc(150 * 1_024 * 1_024));
    writeFileSync(recent, Buffer.alloc(60 * 1_024 * 1_024));
    writeFileSync(unrelated, 'kept');
    const day = 86_400;
    const now = Date.now() / 1_000;
    utimesSync(stale, now - 91 * day, now - 91 * day);
    utimesSync(big, now - 2 * day, now - 2 * day);
    utimesSync(recent, now - day, now - day);
    await exec('prod', { file: join(dir, 'drop.sql') }, join(stateDir, 'audit.jsonl'));
    const left = readdirSync(sqlDir).sort();
    expect(left).toContain(`${'c'.repeat(64)}.sql`);
    expect(left).toContain('notes.txt');
    expect(left).not.toContain(`${'a'.repeat(64)}.sql`);
    expect(left).not.toContain(`${'b'.repeat(64)}.sql`);
    expect(left.length).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// live fixture
// ---------------------------------------------------------------------------

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
const SSHD = `${PREFIX}-sshd-debian`;
const SSH_CONFIG = join(STATE, 'ssh_config');
const ALIAS = 'smoke-debian';

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

function psqlDirect(database: string, script: string): string {
  const proc = Bun.spawnSync(
    [
      'docker',
      'exec',
      '-i',
      POSTGRES,
      'psql',
      '-X',
      '-q',
      '-v',
      'ON_ERROR_STOP=1',
      '-U',
      'postgres',
      '-d',
      database,
      '-At',
    ],
    { stdin: Buffer.from(script), stdout: 'pipe', stderr: 'pipe' },
  );
  if (proc.exitCode !== 0) {
    throw new Error(`psql failed: ${proc.stderr.toString()}`);
  }
  return proc.stdout.toString().trim();
}

describe.skipIf(!fixtureUp())('db exec / backup / backup-verify (smoke fixture)', () => {
  const tag = `p13_${Math.random().toString(36).slice(2, 10)}`;
  const schema = tag;
  const role = `${tag}_rw`;
  const backupDir = `/tmp/sshepherd-${tag}-dumps`;
  let scratch = '';
  let runtimeDir = '';
  let env: Record<string, string> = {};

  const demoCount = (): number =>
    Number(psqlDirect('fixture', `SELECT count(*) FROM ${schema}.exec_demo;`));

  function cli(...args: string[]): {
    envelope: Envelope<Record<string, unknown>>;
    exitCode: number;
  } {
    const proc = Bun.spawnSync(['bun', join(REPO, 'src', 'cli.ts'), ...args], {
      cwd: REPO,
      env: { ...process.env, ...env },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    return {
      envelope: JSON.parse(proc.stdout.toString()) as Envelope<Record<string, unknown>>,
      exitCode: proc.exitCode ?? -1,
    };
  }

  const auditRows = (): Record<string, unknown>[] => {
    const path = join(scratch, 'state', 'audit.jsonl');
    return existsSync(path)
      ? readFileSync(path, 'utf8')
          .split('\n')
          .filter((line) => line.length > 0)
          .map((line) => JSON.parse(line) as Record<string, unknown>)
      : [];
  };

  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-p13-live-'));
    runtimeDir = mkdtempSync('/tmp/sshepherd-p13-run-');
    psqlDirect(
      'fixture',
      [
        `CREATE SCHEMA ${schema};`,
        `CREATE TABLE ${schema}.exec_demo (id serial PRIMARY KEY, note text NOT NULL);`,
        `CREATE ROLE ${role} LOGIN CREATEDB;`,
        `GRANT USAGE, CREATE ON SCHEMA ${schema} TO ${role};`,
        `GRANT SELECT, INSERT, UPDATE, DELETE ON ${schema}.exec_demo TO ${role};`,
        `GRANT USAGE ON SEQUENCE ${schema}.exec_demo_id_seq TO ${role};`,
        `ALTER ROLE ${role} SET search_path = ${schema};`,
      ].join('\n'),
    );
    writeFileSync(
      join(scratch, 'targets.toml'),
      `[prod]\nalias = "${ALIAS}"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\nwrite_role = "${role}"\nbackup_dir = "${backupDir}"\n`,
    );
    writeFileSync(join(scratch, 'drop.sql'), 'DROP TABLE exec_demo;\n');
    writeFileSync(join(scratch, 'create.sql'), 'CREATE TABLE ddl_probe (id int);\n');
    writeFileSync(
      join(scratch, 'half.sql'),
      "INSERT INTO exec_demo (note) VALUES ('lands first');\nINSERT INTO exec_demo (id, note) VALUES (NULL, 'violates not-null');\n",
    );
    writeFileSync(
      join(scratch, 'commit.sql'),
      "INSERT INTO exec_demo (note) VALUES ('x');\nCOMMIT;\n",
    );
    env = {
      SSHEPHERD_TARGETS_PATH: join(scratch, 'targets.toml'),
      SSHEPHERD_SSH_CONFIG_PATH: SSH_CONFIG,
      SSHEPHERD_STATE_DIR: join(scratch, 'state'),
      XDG_RUNTIME_DIR: runtimeDir,
    };
  }, 60_000);

  afterAll(async () => {
    const saved = process.env.XDG_RUNTIME_DIR;
    process.env.XDG_RUNTIME_DIR = runtimeDir;
    await closeMaster(ALIAS);
    process.env.XDG_RUNTIME_DIR = saved;
    psqlDirect('fixture', `DROP SCHEMA IF EXISTS ${schema} CASCADE;\nDROP ROLE IF EXISTS ${role};`);
    Bun.spawnSync(['docker', 'exec', SSHD, 'rm', '-rf', '--', backupDir]);
    rmSync(scratch, { recursive: true, force: true });
    rmSync(runtimeDir, { recursive: true, force: true });
  }, 60_000);

  test('--dry-run reports per-statement row counts and changes nothing; --yes commits the same change', () => {
    expect(demoCount()).toBe(0);
    const dry = cli('db', 'exec', 'prod', '--file', './fixtures/change.sql', '--dry-run');
    expect(dry.exitCode).toBe(0);
    expect(dry.envelope.data).toMatchObject({
      dry_run: true,
      committed: false,
      tables: ['exec_demo'],
      statements: [
        { index: 1, command: 'INSERT', row_count: 2 },
        { index: 2, command: 'UPDATE', row_count: 1 },
        { index: 3, command: 'DELETE', row_count: 1 },
      ],
    });
    expect(demoCount()).toBe(0);
    expect(auditRows()).toEqual([
      expect.objectContaining({ command: 'db exec', dry_run: true, tables: ['exec_demo'] }),
    ]);

    const real = cli('db', 'exec', 'prod', '--file', './fixtures/change.sql', '--yes');
    expect(real.envelope.data).toMatchObject({ dry_run: false, committed: true });
    expect(demoCount()).toBe(1);
    expect(psqlDirect('fixture', `SELECT note FROM ${schema}.exec_demo;`)).toBe('first, edited');
    const sha = new Bun.CryptoHasher('sha256')
      .update(readFileSync(join(REPO, 'fixtures', 'change.sql')))
      .digest('hex');
    expect(auditRows().at(-1)).toMatchObject({
      command: 'db exec',
      outcome: 'ok',
      sql_sha256: sha,
      tables: ['exec_demo'],
    });
  }, 60_000);

  test('without --yes the real run is CONFIRMATION_REQUIRED and nothing changes', () => {
    const before = demoCount();
    const refused = cli('db', 'exec', 'prod', '--file', './fixtures/change.sql');
    expect([refused.envelope.error?.code, refused.exitCode]).toEqual(['CONFIRMATION_REQUIRED', 2]);
    expect(demoCount()).toBe(before);
  }, 60_000);

  test('DROP TABLE without --allow-ddl is DDL_REFUSED (exit 2) and the table stands; the audit row has sql_sha256 + tables, the text only in the 0600 side file', () => {
    const refused = cli('db', 'exec', 'prod', '--file', join(scratch, 'drop.sql'), '--yes');
    expect([refused.envelope.error?.code, refused.exitCode]).toEqual(['DDL_REFUSED', 2]);
    expect(psqlDirect('fixture', `SELECT to_regclass('${schema}.exec_demo') IS NOT NULL;`)).toBe(
      't',
    );
    const row = auditRows().at(-1) ?? {};
    const sha = new Bun.CryptoHasher('sha256').update('DROP TABLE exec_demo;\n').digest('hex');
    expect(row).toMatchObject({
      error_code: 'DDL_REFUSED',
      sql_sha256: sha,
      tables: ['exec_demo'],
    });
    expect(JSON.stringify(auditRows())).not.toContain('DROP TABLE');
    const side = join(scratch, 'state', 'sql', `${sha}.sql`);
    expect(statSync(side).mode & 0o777).toBe(0o600);
    expect(readFileSync(side, 'utf8')).toBe('DROP TABLE exec_demo;\n');

    // Past the guard, the write role itself is the boundary: it does not own exec_demo.
    const notOwner = cli(
      'db',
      'exec',
      'prod',
      '--file',
      join(scratch, 'drop.sql'),
      '--allow-ddl',
      '--yes',
    );
    expect(notOwner.envelope.error?.code).toBe('COMMAND_FAILED');
    expect(JSON.stringify(notOwner.envelope.error?.data)).toContain(
      'must be owner of table exec_demo',
    );
    expect(psqlDirect('fixture', `SELECT to_regclass('${schema}.exec_demo') IS NOT NULL;`)).toBe(
      't',
    );

    const ddlDry = cli(
      'db',
      'exec',
      'prod',
      '--file',
      join(scratch, 'create.sql'),
      '--allow-ddl',
      '--dry-run',
    );
    expect(ddlDry.envelope.data).toMatchObject({
      dry_run: true,
      committed: false,
      statements: [{ command: 'CREATE' }],
    });
    expect(psqlDirect('fixture', `SELECT to_regclass('${schema}.ddl_probe') IS NULL;`)).toBe('t');
  }, 60_000);

  test('a statement failing mid-file leaves nothing committed; a COMMIT in the file is refused before anything runs', () => {
    const before = demoCount();
    const half = cli('db', 'exec', 'prod', '--file', join(scratch, 'half.sql'), '--yes');
    expect(half.envelope.error?.code).toBe('COMMAND_FAILED');
    expect(half.envelope.data).toEqual({ committed: false, statements_ok: 1 });
    expect(demoCount()).toBe(before);
    const commit = cli('db', 'exec', 'prod', '--file', join(scratch, 'commit.sql'), '--yes');
    expect(commit.envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(commit.envelope.error?.message).toContain('statement 2 (COMMIT)');
    expect(demoCount()).toBe(before);
  }, 60_000);

  test('backup --keep 7 then backup-verify: every table COUNT(*) equal between source and the throwaway restore, which is dropped', () => {
    const backup = cli('db', 'backup', 'prod', '--keep', '7', '--yes');
    expect(backup.exitCode).toBe(0);
    const data = backup.envelope.data ?? {};
    expect(data.path).toBe(`${backupDir}/${String(data.name)}`);
    expect(Number(data.bytes)).toBeGreaterThan(0);
    expect(String(data.sha256)).toMatch(/^[0-9a-f]{64}$/);
    expect(Number(data.table_data_entries)).toBeGreaterThan(0);
    const remoteSha = Bun.spawnSync(['docker', 'exec', SSHD, 'sha256sum', String(data.path)], {
      stdout: 'pipe',
    })
      .stdout.toString()
      .split(' ')[0];
    expect(remoteSha).toBe(String(data.sha256));

    const verify = cli('db', 'backup-verify', 'prod');
    expect(verify.exitCode).toBe(0);
    const result = verify.envelope.data ?? {};
    expect(result).toMatchObject({
      dump: data.name,
      verified: true,
      restore_errors: 0,
      mismatched: [],
      throwaway_dropped: true,
    });
    const tables = result.tables as { table: string; source: number; restored: number }[];
    expect(tables.length).toBeGreaterThan(3);
    expect(tables.every((pair) => pair.source === pair.restored)).toBe(true);
    expect(tables.find((pair) => pair.table === 'public.big')).toEqual({
      table: 'public.big',
      source: 1200,
      restored: 1200,
    });
    expect(tables.find((pair) => pair.table === `${schema}.exec_demo`)?.restored).toBe(demoCount());
  }, 120_000);

  test('B2: a row added to the source after the dump shows as a mismatch, so the comparison is real', () => {
    psqlDirect('fixture', `INSERT INTO ${schema}.exec_demo (note) VALUES ('after the dump');`);
    const verify = cli('db', 'backup-verify', 'prod');
    expect(verify.envelope.data).toMatchObject({
      verified: false,
      mismatched: [`${schema}.exec_demo`],
    });
  }, 120_000);

  test("--keep prunes this target's oldest dumps only, never another file in the directory", () => {
    Bun.spawnSync([
      'docker',
      'exec',
      SSHD,
      'sh',
      '-c',
      `touch ${backupDir}/notes.txt ${backupDir}/other-20200101T000000Z.dump`,
    ]);
    const names: string[] = [];
    for (let run = 0; run < 3; run += 1) {
      Bun.sleepSync(1_100);
      const backup = cli('db', 'backup', 'prod', '--keep', '2', '--yes');
      expect(backup.exitCode).toBe(0);
      names.push(String(backup.envelope.data?.name));
      expect(Number(backup.envelope.data?.kept)).toBeLessThanOrEqual(2);
    }
    const listing = Bun.spawnSync(['docker', 'exec', SSHD, 'ls', '-1', backupDir], {
      stdout: 'pipe',
    })
      .stdout.toString()
      .split('\n')
      .filter((name) => name.length > 0)
      .sort();
    expect(listing).toEqual(['notes.txt', 'other-20200101T000000Z.dump', ...names.slice(1)].sort());
  }, 120_000);

  test('no throwaway restore database is left behind', () => {
    expect(
      psqlDirect(
        'fixture',
        "SELECT count(*) FROM pg_database WHERE datname LIKE 'sshepherd_verify_%';",
      ),
    ).toBe('0');
  });
});

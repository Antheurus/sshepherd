import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildPsqlCommand,
  countRowsSql,
  envUrlPsqlScript,
  quoteIdentifier,
  statementTimeoutFor,
} from '../db.ts';
import { DB_QUERY_ROW_LIMIT } from '../limits.ts';
import { pendingMigrations } from '../ops/db.ts';
import { executeOp, getOp } from '../registry.ts';
import { parseDiscover, roRole } from '../setup-db-target.ts';
import { loadTargets } from '../targets.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

const ALIAS = 'db-host';
let scratch = '';

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-db-hardening-'));
  writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 192.0.2.10\n`);
});

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

/** `-G`, master check, then the command; `commands` collects the remote command lines. */
function scripted(last: SpawnOutcome, commands: string[] = []): SshRunner {
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: 'hostname 192.0.2.10\n', stderr: '', timedOut: false },
    { code: 0, stdout: '', stderr: '', timedOut: false },
    last,
  ];
  let index = 0;
  return async (args) => {
    commands.push(args.join(' '));
    const outcome = outcomes[Math.min(index, outcomes.length - 1)] as SpawnOutcome;
    index += 1;
    return outcome;
  };
}

const CONN_ARGS = { target: 'prod', container: 'shop-db', db_user: 'shop_ro', db_name: 'shop' };

/** The remote command line with shellJoin's quoting undone, so SQL reads as written. */
const unquote = (line: string | undefined): string => (line ?? '').replaceAll("'\\''", "'");

async function drive(
  name: string,
  args: Record<string, string>,
  last: SpawnOutcome,
  deps: Parameters<typeof executeOp>[2] = {},
  commands: string[] = [],
): Promise<Envelope<unknown>> {
  const op = getOp('db', name);
  if (op === undefined) {
    throw new Error(`db ${name} missing`);
  }
  return executeOp(
    op,
    { alias: ALIAS, args: { ...CONN_ARGS, ...args } },
    {
      transport: { runner: scripted(last, commands) },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
      ...deps,
    },
  );
}

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });
const psqlFailed = (stderr: string): SpawnOutcome => ({
  code: 1,
  stdout: '',
  stderr,
  timedOut: false,
});

describe('db query: bounded, with the {rows, row_count, truncated} shape', () => {
  test(`asks for one row past the limit, sets the timeouts, and reports truncated`, async () => {
    const commands: string[] = [];
    const rows = JSON.stringify([{ n: 1 }, { n: 2 }, { n: 3 }]);
    const envelope = await drive(
      'query',
      { sql: 'SELECT n FROM t', 'max-rows': '2' },
      ok(rows),
      {},
      commands,
    );
    expect(envelope.data).toEqual({
      rows: [{ n: 1 }, { n: 2 }],
      row_count: 2,
      truncated: true,
      masked_columns: [],
    });
    const remote = unquote(commands.at(-1));
    expect(remote).toContain('LIMIT 3');
    expect(remote).toContain("SET statement_timeout = '60s'; SET lock_timeout = '2s'");
    expect(remote).toContain('BEGIN TRANSACTION READ ONLY');
  });

  test(`no --max-rows: the limit is ${DB_QUERY_ROW_LIMIT}`, async () => {
    const commands: string[] = [];
    const envelope = await drive('query', { sql: 'SELECT 1 AS a' }, ok('[{"a":1}]'), {}, commands);
    expect(envelope.data).toEqual({
      rows: [{ a: 1 }],
      row_count: 1,
      truncated: false,
      masked_columns: [],
    });
    expect(commands.at(-1)).toContain(`LIMIT ${DB_QUERY_ROW_LIMIT + 1}`);
  });

  test('zero rows (json_agg NULL) is an empty rows list', async () => {
    const envelope = await drive('query', { sql: 'SELECT 1 WHERE false' }, ok(''));
    expect(envelope.data).toEqual({ rows: [], row_count: 0, truncated: false, masked_columns: [] });
  });

  test('--max-rows outside 1..10000 is INVALID_ARGS before any ssh call', async () => {
    const commands: string[] = [];
    for (const bad of ['0', '10001', 'ten']) {
      const envelope = await drive(
        'query',
        { sql: 'SELECT 1', 'max-rows': bad },
        ok('[]'),
        {},
        commands,
      );
      expect(envelope.error?.code).toBe('INVALID_ARGS');
    }
    expect(commands.filter((line) => line.includes('psql'))).toEqual([]);
  });

  test('--limit cuts rows and recounts row_count; --fields data.rows keeps only rows', async () => {
    const rows = JSON.stringify([{ n: 1 }, { n: 2 }, { n: 3 }]);
    const limited = await drive('query', { sql: 'SELECT n FROM t' }, ok(rows), { limit: 1 });
    expect(limited.data).toEqual({
      rows: [{ n: 1 }],
      row_count: 1,
      truncated: true,
      masked_columns: [],
    });
    expect(limited.output_truncated).toBe(true);
    const fields = await drive('query', { sql: 'SELECT n FROM t' }, ok(rows), {
      fields: [['rows']],
    });
    expect(fields.data).toEqual({ rows: [{ n: 1 }, { n: 2 }, { n: 3 }] });
  });

  test("psql's statement_timeout cancel is COMMAND_TIMEOUT naming the limit, which follows --timeout", async () => {
    const stderr = 'psql:<stdin>:1: ERROR:  canceling statement due to statement timeout\n';
    const fallback = await drive('query', { sql: 'SELECT pg_sleep(90)' }, psqlFailed(stderr));
    expect(fallback.error).toMatchObject({
      code: 'COMMAND_TIMEOUT',
      message: 'Postgres cancelled the statement at statement_timeout (60 s)',
      timeout_sec: 60,
      remote_exit: 1,
      phase: 'command',
    });
    expect(fallback.error?.data?.sql_error).toEqual({
      message: 'canceling statement due to statement timeout',
    });
    const commands: string[] = [];
    const lowered = await drive(
      'query',
      { sql: 'SELECT pg_sleep(90)', timeout: '20' },
      psqlFailed(stderr),
      { timeoutSec: 20 },
      commands,
    );
    expect(lowered.error?.timeout_sec).toBe(10);
    expect(unquote(commands.at(-1))).toContain("SET statement_timeout = '10s'");
  });

  test('a lock_timeout cancel is COMMAND_TIMEOUT pointing at db activity', async () => {
    const envelope = await drive(
      'count',
      { table: 'users' },
      psqlFailed('ERROR:  canceling statement due to lock timeout\n'),
    );
    expect(envelope.error).toMatchObject({
      code: 'COMMAND_TIMEOUT',
      timeout_sec: 2,
      next: 'sshepherd db activity prod',
    });
  });

  test('any other psql error stays COMMAND_FAILED', async () => {
    const envelope = await drive(
      'query',
      { sql: 'SELECT nope' },
      psqlFailed('ERROR:  column "nope" does not exist\n'),
    );
    expect(envelope.error?.code).toBe('COMMAND_FAILED');
  });
});

describe('statementTimeoutFor', () => {
  test('the budget less 15 s, or half of a short budget, never below 1 s', () => {
    expect([75, 60, 20, 10, 2, 1].map(statementTimeoutFor)).toEqual([60, 45, 10, 5, 1, 1]);
  });
});

describe('db describe / count / migrations', () => {
  test('describe shapes the catalog JSON; an unknown table names db tables', async () => {
    const catalog = {
      found: true,
      schema: 'public',
      table: 'users',
      columns: [{ name: 'id', type: 'integer', nullable: false, default: "nextval('s')" }],
      indexes: [{ name: 'users_pkey', unique: true, primary: true, definition: 'CREATE ...' }],
      foreign_keys: [
        {
          name: 'users_org_fkey',
          columns: ['org_id'],
          references_table: 'orgs',
          references_columns: ['id'],
          definition: 'FOREIGN KEY ...',
        },
      ],
    };
    const commands: string[] = [];
    const found = await drive(
      'describe',
      { table: 'Users' },
      ok(JSON.stringify(catalog)),
      {},
      commands,
    );
    const { found: _found, ...shape } = catalog;
    expect(found.data).toEqual(shape);
    expect(commands.at(-1)).toContain('to_regclass(');
    const missing = await drive('describe', { table: 'nope' }, ok('{"found":false}'));
    expect(missing.error).toMatchObject({
      code: 'VALIDATION_ERROR',
      next: 'sshepherd db tables prod',
    });
  });

  test('count returns {count}; --where-eq quotes the column and the value', async () => {
    const commands: string[] = [];
    const envelope = await drive(
      'count',
      { table: 'users', 'where-eq': "email=o'neil@example.com" },
      ok('{"count":1}'),
      {},
      commands,
    );
    expect(envelope.data).toEqual({ count: 1 });
    expect(countRowsSql('"users"', { column: '"email"', value: "o'neil" })).toBe(
      `SELECT json_build_object('count', count(*)) FROM "users" WHERE "email" = 'o''neil'`,
    );
    const bad = await drive('count', { table: 'users', 'where-eq': 'novalue' }, ok('{}'));
    expect(bad.error?.code).toBe('INVALID_ARGS');
  });

  test('migrations shapes one entry per present table', async () => {
    const stdout = JSON.stringify([
      {
        framework: 'prisma',
        table: '_prisma_migrations',
        migrations: [{ name: '20261001_init', applied_at: '2026-10-01T00:00:00+00:00' }],
      },
      {
        framework: 'rails',
        table: 'schema_migrations',
        migrations: [{ name: '1', applied_at: null }],
      },
    ]);
    const envelope = await drive('migrations', {}, ok(stdout));
    expect(envelope.data).toEqual({
      tables: [
        { ...JSON.parse(stdout)[0], current: '20261001_init', pending: null },
        { ...JSON.parse(stdout)[1], current: '1', pending: null },
      ],
    });
    const none = await drive('migrations', {}, ok('[]'));
    expect(none.data).toEqual({ tables: [] });
  });

  test('migrations --table reads one known table, schema-qualified; anything else is refused', async () => {
    const commands: string[] = [];
    const stdout = JSON.stringify([
      {
        framework: 'rails',
        table: 'app.schema_migrations',
        migrations: [{ name: '20261015000000', applied_at: null }],
      },
    ]);
    const envelope = await drive(
      'migrations',
      { table: 'app.schema_migrations' },
      ok(stdout),
      {},
      commands,
    );
    expect((envelope.data as { tables: { current: string }[] }).tables[0]?.current).toBe(
      '20261015000000',
    );
    const remote = unquote(commands.at(-1));
    expect(remote).toContain('FROM "app"."schema_migrations"');
    expect(remote).not.toContain('_prisma_migrations');
    for (const bad of ['users', 'x;drop', 'a.b.schema_migrations']) {
      const refused = await drive('migrations', { table: bad }, ok('[]'));
      expect(refused.error?.code).toBe('INVALID_ARGS');
    }
    const absent = await drive('migrations', { table: 'schema_migrations' }, ok('[]'));
    expect(absent.error?.code).toBe('VALIDATION_ERROR');
  });

  test('migrations --dir is allowlist-gated and lists the entries no applied name accounts for', async () => {
    const allowlist = join(scratch, 'files-allowlist.toml');
    writeFileSync(
      allowlist,
      `[${ALIAS}]\npaths = ["/opt/app/prisma/migrations", "/opt/app/db/migrate"]\n`,
    );
    const saved = process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlist;
    try {
      const commands: string[] = [];
      const off = await drive('migrations', { dir: '/etc' }, ok('[]'), {}, commands);
      expect(off.error?.code).toBe('VALIDATION_ERROR');
      expect(commands.filter((line) => line.includes('psql'))).toEqual([]);

      const tables = JSON.stringify([
        {
          framework: 'prisma',
          table: '_prisma_migrations',
          migrations: [
            { name: '20261102103000_add_nickname', applied_at: '2026-11-02T10:30:00+00:00' },
          ],
          names: ['20261102103000_add_nickname', '20261001090000_init'],
        },
      ]);
      const listing = [
        '20261001090000_init',
        '20261102103000_add_nickname',
        '20261120080000_add_orgs',
        'migration_lock.toml',
      ];
      const envelope = await drive(
        'migrations',
        { dir: '/opt/app/prisma/migrations' },
        ok(`${tables}\n__DIR__\n${listing.join('\n')}\n`),
        {},
        commands,
      );
      expect((envelope.data as { tables: unknown[] }).tables).toEqual([
        {
          framework: 'prisma',
          table: '_prisma_migrations',
          current: '20261102103000_add_nickname',
          migrations: [
            { name: '20261102103000_add_nickname', applied_at: '2026-11-02T10:30:00+00:00' },
          ],
          pending: ['20261120080000_add_orgs'],
        },
      ]);
      expect(unquote(commands.at(-1))).toContain("'names'");

      const missing = await drive(
        'migrations',
        { dir: '/opt/app/db/migrate' },
        ok('[]\n__DIR__\n__NO_DIR__\n'),
      );
      expect(missing.error?.code).toBe('VALIDATION_ERROR');
    } finally {
      if (saved === undefined) {
        delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
      } else {
        process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = saved;
      }
    }
  });

  test('pendingMigrations: rails versions, typeorm class names, knex and laravel file names', () => {
    expect(
      pendingMigrations(
        [
          '20260901000000_create_users.rb',
          '20261015000000_add_orgs.rb',
          '20261120000000_x.rb',
          'schema.rb',
        ],
        ['20260901000000', '20261015000000'],
      ),
    ).toEqual(['20261120000000_x.rb']);
    expect(
      pendingMigrations(
        ['1700000000000-Init.ts', '1700000000001-AddUsers.ts'],
        ['Init1700000000000'],
      ),
    ).toEqual(['1700000000001-AddUsers.ts']);
    expect(
      pendingMigrations(['20261001_init.js', '20261001_users.js'], ['20261001_init.js']),
    ).toEqual(['20261001_users.js']);
    expect(
      pendingMigrations(
        ['2014_10_12_000000_create_users_table.php', '2026_11_01_000000_add_orgs.php'],
        ['2014_10_12_000000_create_users_table'],
      ),
    ).toEqual(['2026_11_01_000000_add_orgs.php']);
  });
});

describe('quoteIdentifier', () => {
  test('folds unquoted parts, keeps quoted ones, refuses anything else', () => {
    expect(quoteIdentifier('users', 'table')).toBe('"users"');
    expect(quoteIdentifier('Public.Users', 'table')).toBe('"public"."users"');
    expect(quoteIdentifier('app."MixedCase"', 'table')).toBe('"app"."MixedCase"');
    for (const bad of ['a;b', 'a.b.c', '-users', "x'y", '', 'a..b', 'a b']) {
      expect(() => quoteIdentifier(bad, 'table')).toThrow(/table must be/);
    }
    expect(() => quoteIdentifier('s.col', 'column', 1)).toThrow(/column must be/);
  });
});

describe('buildPsqlCommand by target kind', () => {
  const base = { composeFile: '', service: '', container: '', user: '', database: '' };

  test('host: psql on the host, optionally through sudo and to a TCP host', () => {
    expect(
      buildPsqlCommand(
        {
          ...base,
          kind: 'host',
          user: 'ro',
          database: 'app',
          sudoUser: 'postgres',
          pgHost: 'db',
          pgPort: '5433',
        },
        'SELECT 1',
      ),
    ).toBe(
      "'sudo' '-n' '-u' 'postgres' 'psql' '-h' 'db' '-p' '5433' '-U' 'ro' '-d' 'app' '-v' 'ON_ERROR_STOP=1' '-qAt' '-c' 'SELECT 1'",
    );
  });

  test('container-env: no URL anywhere, psql in the container or via printenv into psql_container', () => {
    const same = buildPsqlCommand(
      { ...base, kind: 'container-env', container: 'web', envKey: 'DATABASE_URL' },
      'SELECT 1',
    );
    expect(same.startsWith("'docker' 'exec' '-i' 'web' 'sh' '-c' 'u=$" + '{DATABASE_URL:-}')).toBe(
      true,
    );
    expect(same.endsWith("'sh' '-c' 'SELECT 1'")).toBe(true);
    expect(same).not.toContain('printenv');
    const via = buildPsqlCommand(
      { ...base, kind: 'container-env', container: 'web', envKey: 'DB_URL', psqlContainer: 'pg' },
      'SELECT 1',
    );
    expect(via).toContain('printenv');
    expect(via).toContain('-e SSHEPHERD_PGURL');
    expect(() =>
      buildPsqlCommand(
        { ...base, kind: 'container-env', container: 'web', envKey: 'BAD-KEY' },
        'x',
      ),
    ).toThrow(/container-env/);
  });
});

describe('the env-URL script decodes the URL into PG* and never passes it as argv', () => {
  const STUB_VARS = [
    'PGHOST',
    'PGPORT',
    'PGUSER',
    'PGPASSWORD',
    'PGDATABASE',
    'PGSSLMODE',
    'PGAPPNAME',
  ];

  /** Runs the script with a stub `psql` first on PATH that prints its env and its own argv. */
  function runScript(url: string | undefined): { code: number; stdout: string; stderr: string } {
    const bin = mkdtempSync(join(scratch, 'bin-'));
    const stub = join(bin, 'psql');
    writeFileSync(
      stub,
      [
        '#!/bin/sh',
        ...STUB_VARS.map((name) => `printf '%s=%s\\n' ${name} "\${${name}-<unset>}"`),
        'printf "ARGV=%s\\n" "$*"',
      ].join('\n'),
    );
    chmodSync(stub, 0o755);
    const env: Record<string, string> = { PATH: `${bin}:/usr/bin:/bin`, PGHOST: 'stale-host' };
    if (url !== undefined) {
      env.DATABASE_URL = url;
    }
    const proc = Bun.spawnSync(
      ['sh', '-c', envUrlPsqlScript('DATABASE_URL'), 'sh', '-c', 'SELECT 1'],
      {
        env,
        stdout: 'pipe',
        stderr: 'pipe',
      },
    );
    return {
      code: proc.exitCode ?? -1,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
    };
  }

  const parse = (stdout: string): Record<string, string> =>
    Object.fromEntries(
      stdout
        .trim()
        .split('\n')
        .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]),
    );

  test('percent-decoded user, password and database; host, port and known query params', () => {
    const out = runScript(
      'postgresql://app%40ops:p%40ss%27w%3Ard@db.internal:6543/my%20db?sslmode=require&application_name=web&schema=public',
    );
    expect(out.code).toBe(0);
    expect(parse(out.stdout)).toEqual({
      PGHOST: 'db.internal',
      PGPORT: '6543',
      PGUSER: 'app@ops',
      PGPASSWORD: "p@ss'w:rd",
      PGDATABASE: 'my db',
      PGSSLMODE: 'require',
      PGAPPNAME: 'web',
      ARGV: '-v ON_ERROR_STOP=1 -qAt -c SELECT 1',
    });
  });

  test('multi-host and IPv6 host lists; no password means none is set; a stale PGHOST is dropped', () => {
    expect(parse(runScript('postgres://ro@h1:5433,h2/app').stdout)).toMatchObject({
      PGHOST: 'h1,h2',
      PGPORT: '5433,5432',
      PGUSER: 'ro',
      PGPASSWORD: '<unset>',
    });
    expect(parse(runScript('postgres://ro@[::1]:5432/app').stdout)).toMatchObject({
      PGHOST: '::1',
      PGPORT: '5432',
    });
    expect(parse(runScript('postgres:///app').stdout)).toMatchObject({
      PGHOST: '<unset>',
      PGDATABASE: 'app',
    });
  });

  test("a connect error naming the URL's host and user masks both before it leaves the container, keeping stdout and the exit code", () => {
    const bin = mkdtempSync(join(scratch, 'bin-'));
    writeFileSync(
      join(bin, 'psql'),
      [
        '#!/bin/sh',
        'printf "partial-row\\n"',
        'printf "psql: error: connection to server at \\"%s\\" (192.0.2.10), port 5432 failed: FATAL:  password authentication failed for user \\"%s\\"\\n" "$PGHOST" "$PGUSER" >&2',
        'printf "xdb.ledger.example.net is another host and billing_apps another user\\n" >&2',
        'exit 2',
      ].join('\n'),
    );
    chmodSync(join(bin, 'psql'), 0o755);
    const proc = Bun.spawnSync(
      ['sh', '-c', envUrlPsqlScript('DATABASE_URL'), 'sh', '-c', 'SELECT 1'],
      {
        env: {
          PATH: `${bin}:/usr/bin:/bin`,
          DATABASE_URL: 'postgres://billing_app:pw@db.ledger.example.net:5432/app',
        },
        stdout: 'pipe',
        stderr: 'pipe',
      },
    );
    expect({
      code: proc.exitCode,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
    }).toEqual({
      code: 2,
      stdout: 'partial-row\n',
      stderr:
        'psql: error: connection to server at "<db-host>" (192.0.2.10), port 5432 failed: FATAL:  password authentication failed for user "<db-user>"\nxdb.ledger.example.net is another host and billing_apps another user\n',
    });
  });

  test('a non-postgres or missing URL exits 3 without echoing it', () => {
    const wrong = runScript('mysql://root:topsecretvalue@db/app');
    expect(wrong.code).toBe(3);
    expect(wrong.stderr).toContain('does not hold a postgres:// URL');
    expect(`${wrong.stdout}${wrong.stderr}`).not.toContain('topsecretvalue');
    const missing = runScript(undefined);
    expect(missing.code).toBe(3);
    expect(missing.stderr).toContain('DATABASE_URL is not set');
  });
});

describe('targets.toml kinds', () => {
  function load(body: string): ReturnType<typeof loadTargets> {
    const path = join(mkdtempSync(join(scratch, 'targets-')), 'targets.toml');
    writeFileSync(path, body);
    return loadTargets(path);
  }

  test('container-env defaults env_key to DATABASE_URL and needs no user/database', () => {
    const targets = load('[app]\nalias = "web-1"\nkind = "container-env"\ncontainer = "web"\n');
    expect(targets.app).toMatchObject({
      kind: 'container-env',
      container: 'web',
      envKey: 'DATABASE_URL',
      psqlContainer: null,
      user: '',
    });
  });

  test('host keeps sudo_user/pg_host/pg_port; a bad kind, env_key or pg_port is refused', () => {
    const targets = load(
      '[h]\nalias = "web-1"\nkind = "host"\nsudo_user = "postgres"\npg_port = "5433"\nuser = "ro"\ndatabase = "app"\n',
    );
    expect(targets.h).toMatchObject({ kind: 'host', sudoUser: 'postgres', pgPort: '5433' });
    expect(() => load('[x]\nalias = "a"\nkind = "mysql"\n')).toThrow(/expected one of container/);
    expect(() =>
      load('[x]\nalias = "a"\nkind = "container-env"\ncontainer = "c"\nenv_key = "A-B"\n'),
    ).toThrow(/env_key/);
    expect(() =>
      load('[x]\nalias = "a"\nkind = "host"\nuser = "u"\ndatabase = "d"\npg_port = "abc"\n'),
    ).toThrow(/pg_port/);
    expect(() => load('[x]\nalias = "a"\nkind = "host"\n')).toThrow(/missing 'user' or 'database'/);
  });
});

describe('setup db-target ro-role and discover', () => {
  function targetsFile(): string {
    const path = join(mkdtempSync(join(scratch, 'ro-')), 'targets.toml');
    writeFileSync(
      path,
      '[prod]\nalias = "web-1"\ncontainer = "db"\nuser = "app"\ndatabase = "app"\n',
    );
    return path;
  }

  test('--print-sql gives the LOGIN role SQL and its checks; nothing else is accepted', () => {
    const path = targetsFile();
    const outcome = roRole('prod', { printSql: true }, path);
    if (!('sql' in outcome)) {
      throw new Error('expected SQL');
    }
    expect(outcome.sql).toContain(
      'CREATE ROLE sshepherd_ro WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;',
    );
    expect(outcome.sql).toContain('GRANT SELECT ON ALL TABLES IN SCHEMA public TO sshepherd_ro;');
    expect(outcome.sql).not.toContain('GRANT pg_read_all_data');
    expect(outcome.sql).toContain("SET temp_file_limit = '256MB'");
    expect(roRole('prod', { printSql: false }, path)).toMatchObject({
      error: { code: 'INVALID_ARGS' },
    });
    expect(roRole('prodd', { printSql: true }, path)).toMatchObject({
      error: { code: 'VALIDATION_ERROR', did_you_mean: ['prod'] },
    });
    expect(roRole('prod', { printSql: true, role: 'Bad-Role' }, path)).toMatchObject({
      error: { code: 'INVALID_ARGS' },
    });
  });

  test('discover keeps postgres containers and compose project names only', () => {
    const stdout = [
      'shop-db-1\tpostgres:16\tshop\tdb',
      'shop-web-1\tnode:22\tshop\tweb',
      'geo\tpostgis/postgis:16-3.4\t\t',
      '',
    ].join('\n');
    expect(parseDiscover('web-1', stdout)).toEqual({
      alias: 'web-1',
      postgres_containers: [
        {
          container: 'geo',
          image: 'postgis/postgis:16-3.4',
          compose_project: null,
          compose_service: null,
        },
        {
          container: 'shop-db-1',
          image: 'postgres:16',
          compose_project: 'shop',
          compose_service: 'db',
        },
      ],
      compose_projects: ['shop'],
    });
  });
});

describe('db query: deny_columns masking', () => {
  test('values of denied columns are masked after the fetch and named in masked_columns', async () => {
    const rows = JSON.stringify([
      {
        id: 1,
        email: 'rina@example.com',
        password_hash: 'x1',
        api_key: null,
        rolpassword: 'SCRAM-SHA-256$4096:aa',
      },
      { id: 2, email: 'budi@example.com', password_hash: 'x2', api_key: 'k2', rolpassword: null },
    ]);
    const envelope = await drive('query', { sql: 'SELECT * FROM users' }, ok(rows));
    expect(envelope.data).toEqual({
      rows: [
        {
          id: 1,
          email: 'rina@example.com',
          password_hash: '***',
          api_key: null,
          rolpassword: '***',
        },
        {
          id: 2,
          email: 'budi@example.com',
          password_hash: '***',
          api_key: '***',
          rolpassword: null,
        },
      ],
      row_count: 2,
      truncated: false,
      masked_columns: ['api_key', 'password_hash', 'rolpassword'],
    });
    expect(JSON.stringify(envelope)).not.toContain('SCRAM-SHA-256$4096:aa');
  });

  test("a target's own deny_columns replaces the default list", async () => {
    const rows = JSON.stringify([{ ssn: '123', password: 'p' }]);
    const envelope = await drive('query', { sql: 'SELECT 1', deny_columns: '["^ssn$"]' }, ok(rows));
    const data = envelope.data as { rows: Record<string, unknown>[]; masked_columns: string[] };
    expect(data.rows[0]?.ssn).toBe('***');
    expect(data.masked_columns).toEqual(['ssn']);
  });
});

describe('db query: the caller SQL cannot leave the row-limit wrapper', () => {
  const refused = [
    "SELECT id, repeat('x', 5000) AS pad FROM big) sshepherd_q) t --",
    'SELECT * FROM big) a) t, (SELECT * FROM (SELECT 1',
    'SELECT 1 --\r) a) t, (SELECT (SELECT 1',
    'SELECT 1 /* open',
    'SELECT 1 /* /* nested */ still open',
    '/* x */ ) x --',
    "SELECT 'open",
    'SELECT "open',
    'SELECT $q$ open',
    'SELECT (1',
  ];
  for (const sql of refused) {
    test(`refused before ssh: ${JSON.stringify(sql)}`, async () => {
      const commands: string[] = [];
      const envelope = await drive('query', { sql }, ok('[]'), {}, commands);
      expect(envelope.error?.code).toBe('VALIDATION_ERROR');
      expect(commands.filter((line) => line.includes('psql'))).toEqual([]);
    });
  }

  const accepted = [
    'SELECT id FROM big -- a trailing comment',
    "SELECT '--' AS dashes, '/*' AS opener, ')' AS paren",
    "SELECT 'it''s' AS quote",
    "SELECT E'a\\'b)' AS e",
    "SELECT E'\\' ) x) t --' AS one_string",
    "SELECT '\\' AS backslash, ')' AS p",
    'SELECT $$ ) $$ AS d, $tag$ ( $tag$ AS t',
    'SELECT "odd)name" FROM t /* ( */ WHERE (a = 1)',
    'SELECT 1 /* nested /* ) */ */',
    'SELECT a$b FROM t WHERE x = $1',
  ];
  for (const sql of accepted) {
    test(`accepted and wrapped on its own lines: ${JSON.stringify(sql)}`, async () => {
      const commands: string[] = [];
      const envelope = await drive('query', { sql, 'max-rows': '1' }, ok('[]'), {}, commands);
      expect(envelope.error?.code).toBeUndefined();
      const remote = unquote(commands.at(-1));
      expect(remote).toContain(`(\n${sql}\n) sshepherd_q LIMIT 2\n) t`);
      expect(remote).toContain('SET standard_conforming_strings = on');
    });
  }
});

describe('setup db-target ro-role: tables only by default, --all-data opt-in', () => {
  test('grants only app tables by default (--tables-only is the same SQL); --all-data names the pg_authid exposure', () => {
    const path = join(scratch, 'ro-role-targets.toml');
    writeFileSync(
      path,
      '[prod]\nalias = "web-1"\ncontainer = "db"\nuser = "app"\ndatabase = "app"\n[envonly]\nalias = "web-1"\ncontainers = ["app_1"]\n',
    );
    const full = roRole('prod', { printSql: true, allData: true }, path);
    const tables = roRole('prod', { printSql: true }, path);
    const alias = roRole('prod', { printSql: true, tablesOnly: true }, path);
    if (!('sql' in full) || !('sql' in tables) || !('sql' in alias)) {
      throw new Error('expected SQL');
    }
    expect(alias.sql).toBe(tables.sql);
    expect(full.sql).toContain('pg_authid');
    expect(full.sql).toContain('GRANT pg_read_all_data TO sshepherd_ro;');
    expect(full.sql).toContain('substr, encode, replace of rolpassword) comes back NOT masked');
    expect(full.sql).toContain(
      "has_table_privilege('sshepherd_ro', 'pg_authid', 'SELECT'); -- expect: t",
    );
    expect(roRole('prod', { printSql: true, allData: true, tablesOnly: true }, path)).toMatchObject(
      { error: { code: 'INVALID_ARGS' } },
    );
    expect(roRole('envonly', { printSql: true }, path)).toMatchObject({
      error: { code: 'VALIDATION_ERROR' },
    });
    expect(tables.sql).not.toContain('GRANT pg_read_all_data');
    expect(tables.sql).toContain('GRANT USAGE ON SCHEMA public TO sshepherd_ro;');
    expect(tables.sql).toContain('GRANT SELECT ON ALL TABLES IN SCHEMA public TO sshepherd_ro;');
    expect(tables.sql).toContain(
      'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO sshepherd_ro;',
    );
    expect(tables.sql).toContain(
      "has_table_privilege('sshepherd_ro', 'pg_authid', 'SELECT'); -- expect: f",
    );
  });
});

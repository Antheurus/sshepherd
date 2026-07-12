import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertSelectOnly,
  buildDbSlowCommand,
  buildPsqlCommand,
  type DbConnection,
  wrapAsJsonAgg,
  wrapReadOnlyTxn,
} from '../db.ts';

const COMPOSE_CONN: DbConnection = {
  composeFile: '/opt/lms/docker-compose.yml',
  service: 'db',
  container: '',
  user: 'ro',
  database: 'lms',
};

const CONTAINER_CONN: DbConnection = {
  composeFile: '',
  service: '',
  container: 'staging_postgres_1',
  user: 'ro',
  database: 'app',
};

describe('assertSelectOnly — parser layer (UX guardrail, not the security boundary)', () => {
  test('a plain SELECT passes', () => {
    expect(() => assertSelectOnly('SELECT 1')).not.toThrow();
  });

  test('rejects INSERT with a clear error', () => {
    expect(() => assertSelectOnly('INSERT INTO foo (a) VALUES (1)')).toThrow(
      /refusing statement type 'insert'/,
    );
  });

  test('rejects UPDATE/DELETE/DDL', () => {
    expect(() => assertSelectOnly('UPDATE foo SET a = 1')).toThrow(
      /refusing statement type 'update'/,
    );
    expect(() => assertSelectOnly('DELETE FROM foo')).toThrow(/refusing statement type 'delete'/);
    expect(() => assertSelectOnly('DROP TABLE foo')).toThrow(/refusing statement type 'drop'/);
  });

  test('a writable CTE parses as select and passes the parser layer (txn wrapper is the real gate)', () => {
    expect(() =>
      assertSelectOnly('WITH x AS (INSERT INTO foo (a) VALUES (1) RETURNING *) SELECT * FROM x'),
    ).not.toThrow();
  });

  test('exotic-but-unparseable syntax is let through, never blocked', () => {
    expect(() =>
      assertSelectOnly('SELECT * FROM foo TABLESAMPLE BERNOULLI (10) $$$ garbage'),
    ).not.toThrow();
  });
});

describe('wrapReadOnlyTxn / wrapAsJsonAgg', () => {
  test('wraps in BEGIN TRANSACTION READ ONLY ... ROLLBACK, trimming a trailing semicolon', () => {
    expect(wrapReadOnlyTxn('SELECT 1;')).toBe('BEGIN TRANSACTION READ ONLY; SELECT 1; ROLLBACK;');
  });

  test('wraps arbitrary SQL as a single json_agg subquery', () => {
    expect(wrapAsJsonAgg('SELECT * FROM foo;')).toBe(
      'SELECT json_agg(t) FROM (SELECT * FROM foo) t',
    );
  });
});

describe('buildPsqlCommand — connection method selection', () => {
  test('compose connection produces `docker compose -f <file> exec -T <service> psql ...`', () => {
    const cmd = buildPsqlCommand(COMPOSE_CONN, 'SELECT 1');
    expect(cmd).toContain('docker');
    expect(cmd).toContain('compose');
    expect(cmd).toContain(COMPOSE_CONN.composeFile);
    expect(cmd).toContain(COMPOSE_CONN.service);
    expect(cmd).toContain('psql');
    expect(cmd).toContain('-qAt');
  });

  test('container connection produces `docker exec -i <container> psql ...`', () => {
    const cmd = buildPsqlCommand(CONTAINER_CONN, 'SELECT 1');
    expect(cmd).toContain('exec');
    expect(cmd).toContain(CONTAINER_CONN.container);
    expect(cmd).not.toContain('compose');
  });

  test('throws when a connection has neither compose nor container info', () => {
    const empty: DbConnection = {
      composeFile: '',
      service: '',
      container: '',
      user: 'ro',
      database: 'db',
    };
    expect(() => buildPsqlCommand(empty, 'SELECT 1')).toThrow(/needs either/);
  });
});

function freshMarkerPath(): string {
  return join(tmpdir(), `sshepherd-db-pwn-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('quoting — SQL text and connection fields never break out of their argument boundary', () => {
  test('a SQL string shaped like a shell injection cannot splice in a second command', () => {
    const marker = freshMarkerPath();
    const malicious = `SELECT 1'; touch ${marker}; echo '`;
    const cmd = buildPsqlCommand(CONTAINER_CONN, malicious);
    Bun.spawnSync(['sh', '-c', cmd], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });

  test('buildDbSlowCommand nests two psql invocations inside one sh -c script safely', () => {
    const marker = freshMarkerPath();
    const conn: DbConnection = { ...CONTAINER_CONN, container: `db'; touch ${marker}; echo '` };
    const cmd = buildDbSlowCommand(conn);
    Bun.spawnSync(['sh', '-c', cmd], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });
});

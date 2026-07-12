import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertNoMultiStatementSql,
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

  test("a targets.toml compose_file value containing a literal `'; rm -rf /` cannot execute", () => {
    const marker = freshMarkerPath();
    const conn: DbConnection = {
      ...COMPOSE_CONN,
      composeFile: `/opt/x.yml'; touch ${marker}; rm -rf / #`,
    };
    const cmd = buildPsqlCommand(conn, 'SELECT 1');
    Bun.spawnSync(['sh', '-c', cmd], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });

  test('a targets.toml user/database value shaped as a shell escape cannot execute', () => {
    const marker = freshMarkerPath();
    const conn: DbConnection = {
      ...CONTAINER_CONN,
      user: `ro'; touch ${marker}; echo '`,
      database: `app$(touch ${marker})`,
    };
    const cmd = buildPsqlCommand(conn, 'SELECT 1');
    Bun.spawnSync(['sh', '-c', cmd], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });

  test('a backtick/subshell payload in a connection field cannot execute', () => {
    const marker = freshMarkerPath();
    const conn: DbConnection = { ...CONTAINER_CONN, container: `c1\`touch ${marker}\`` };
    const cmd = buildPsqlCommand(conn, 'SELECT 1');
    Bun.spawnSync(['sh', '-c', cmd], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });
});

describe('multi-statement SQL escape attempt (SELECT 1; COMMIT; DROP TABLE x)', () => {
  const MULTI_STATEMENT_ATTACK = 'SELECT 1; COMMIT; DROP TABLE x';

  test('the parser layer catches it because the second real statement is a DROP', () => {
    expect(() => assertSelectOnly(MULTI_STATEMENT_ATTACK)).toThrow(
      /refusing statement type 'drop'/,
    );
  });

  test('even if the parser layer were bypassed, wrapAsJsonAgg confines every embedded semicolon inside one FROM-subquery — no top-level second statement is reachable', () => {
    const wrapped = wrapReadOnlyTxn(wrapAsJsonAgg(MULTI_STATEMENT_ATTACK));
    // The whole attack string must appear verbatim inside the "FROM (...)" subquery
    // boundary, never as a sibling top-level statement after the wrapper's own
    // semicolons. A subquery cannot contain a bare `;`-separated statement list —
    // Postgres would reject this as a syntax error before anything executes.
    expect(wrapped).toBe(
      `BEGIN TRANSACTION READ ONLY; SELECT json_agg(t) FROM (${MULTI_STATEMENT_ATTACK}) t; ROLLBACK;`,
    );
    const subqueryStart = wrapped.indexOf('FROM (') + 'FROM ('.length;
    const subqueryEnd = wrapped.lastIndexOf(') t;');
    const subquery = wrapped.slice(subqueryStart, subqueryEnd);
    expect(subquery).toBe(MULTI_STATEMENT_ATTACK);
    // No unescaped COMMIT/ROLLBACK/DROP sits outside the subquery boundary.
    expect(wrapped.slice(0, subqueryStart)).not.toMatch(/COMMIT|DROP/i);
    expect(wrapped.slice(subqueryEnd)).not.toMatch(/COMMIT|DROP/i);
  });

  test('a crafted statement cannot execute a second shell/SQL command when run end-to-end through buildPsqlCommand', () => {
    const marker = freshMarkerPath();
    // Even bypassing assertSelectOnly entirely (simulating "parser missed it"), the SQL
    // never reaches a shell — it is one quoted `-c` argument to psql. This proves the
    // shell layer treats the whole crafted SQL as inert argument text, not commands.
    const wrapped = wrapReadOnlyTxn(wrapAsJsonAgg(`SELECT 1; COMMIT; DROP TABLE x -- ${marker}`));
    const cmd = buildPsqlCommand(CONTAINER_CONN, wrapped);
    Bun.spawnSync(['sh', '-c', cmd], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });
});

describe('multi-statement db query is rejected (COMMIT-injection gap closed)', () => {
  // A payload engineered around wrapAsJsonAgg's exact template
  // (`SELECT json_agg(t) FROM (<sql>) t`) can close that paren *itself* via a leading
  // `) t;` and resume with its own fully-formed statements before the template's
  // trailing `) t` is appended — node-sql-parser throws on the malformed fragment and
  // `assertSelectOnly`'s advisory catch-and-pass-through (by design — see its
  // docstring) lets it reach `wrapAsJsonAgg` unblocked, producing a fully SQL-valid
  // multi-statement batch where an injected `COMMIT` ends the READ ONLY transaction
  // before the attacker's own DDL/DML runs. `assertNoMultiStatementSql` closes this by
  // rejecting any bare `;` in the user-supplied `sql` outright, before node-sql-parser
  // or `wrapAsJsonAgg` ever see it — a legitimate ad hoc single SELECT never needs one.
  test('rejects a payload that would close the FROM(...) boundary early and inject a COMMIT', () => {
    const payload = 'SELECT 1) t; COMMIT; DROP TABLE foo; SELECT (SELECT 1';
    expect(() => assertNoMultiStatementSql(payload)).toThrow(
      /db query rejects multi-statement SQL/,
    );
  });

  test('a plain single SELECT with no semicolon passes', () => {
    expect(() => assertNoMultiStatementSql('SELECT * FROM users LIMIT 5')).not.toThrow();
  });

  test('a SELECT with a single trailing semicolon is rejected too', () => {
    expect(() => assertNoMultiStatementSql('SELECT * FROM users LIMIT 5;')).toThrow(
      /db query rejects multi-statement SQL/,
    );
  });
});

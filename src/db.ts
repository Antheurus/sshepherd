import { Parser } from 'node-sql-parser';
import { shellJoin } from './quote.ts';

const parser = new Parser();

/**
 * Statement types `node-sql-parser` reports for a top-level non-SELECT statement.
 * `select` covers plain SELECTs AND writable CTEs (`WITH x AS (INSERT ...) SELECT ...`
 * astifies as `select`) — that gap is intentional, see `assertSelectOnly`.
 */
const WRITE_STATEMENT_TYPES = new Set([
  'insert',
  'update',
  'delete',
  'replace',
  'truncate',
  'create',
  'alter',
  'drop',
  'rename',
  'grant',
  'revoke',
]);

function readStatementType(statement: unknown): string | null {
  if (typeof statement !== 'object' || statement === null) {
    return null;
  }
  const type = (statement as Record<string, unknown>).type;
  return typeof type === 'string' ? type.toLowerCase() : null;
}

/**
 * Security guard for `db query`'s free-text `sql` arg only — NOT part of `assertSelectOnly`
 * and never called for the static, sshepherd-authored SQL (tables/activity/connections/
 * slow/size), which legitimately contains `;`. A payload can close `wrapAsJsonAgg`'s
 * `FROM (<sql>) t` boundary early and append its own statements (e.g. a bare `COMMIT`
 * that ends `wrapReadOnlyTxn`'s read-only transaction before injected DDL/DML runs) —
 * node-sql-parser throws on the malformed fragment and `assertSelectOnly`'s advisory
 * catch-and-pass-through lets it through unblocked. A legitimate ad hoc single SELECT
 * never needs a `;`, so this rejects any bare `;` outright, before node-sql-parser and
 * before `wrapAsJsonAgg` ever see the string.
 */
export function assertNoMultiStatementSql(sql: string): void {
  if (sql.trim().includes(';')) {
    throw new Error("db query rejects multi-statement SQL: a single SELECT statement, no ';'");
  }
}

/**
 * UX guardrail only (research.md §"DB access", layer 3 of 3): a fast, friendly
 * rejection for a statement whose top-level type is unambiguously non-SELECT. This is
 * NOT the security boundary — a writable CTE parses as `select` and passes here on
 * purpose; `wrapReadOnlyTxn` (layer 2) is the real gate, and the read-only DB role
 * (layer 1, documented in targets.example.toml) is the engine-side boundary. A
 * statement the parser can't parse at all (exotic-but-valid Postgres syntax) is let
 * through too — the parser must never block a legitimate SELECT it doesn't understand.
 */
export function assertSelectOnly(sql: string): void {
  let statements: unknown;
  try {
    statements = parser.astify(sql, { database: 'postgresql' });
  } catch {
    return;
  }
  const list = Array.isArray(statements) ? statements : [statements];
  for (const statement of list) {
    const type = readStatementType(statement);
    if (type !== null && WRITE_STATEMENT_TYPES.has(type)) {
      throw new Error(
        `db query: refusing statement type '${type}' — only SELECT is allowed (parser layer)`,
      );
    }
  }
}

/**
 * Wraps SQL in an explicit read-only transaction — the REAL enforced gate (defense in
 * depth on top of the read-only DB role, not a replacement for it: PG docs note a
 * session can revoke read-only on itself). `-v ON_ERROR_STOP=1` (set by the caller)
 * makes psql abort the whole `-c` buffer, including the trailing ROLLBACK, the instant
 * the engine rejects a write inside the transaction.
 */
export function wrapReadOnlyTxn(sql: string): string {
  const trimmed = sql.trim().replace(/;+\s*$/, '');
  return `BEGIN TRANSACTION READ ONLY; ${trimmed}; ROLLBACK;`;
}

/** Wraps arbitrary SQL so psql's `-t -A` output is exactly one JSON value (array), never a raw table. */
export function wrapAsJsonAgg(sql: string): string {
  const trimmed = sql.trim().replace(/;+\s*$/, '');
  return `SELECT json_agg(t) FROM (${trimmed}) t`;
}

export interface DbConnection {
  composeFile: string;
  service: string;
  container: string;
  user: string;
  database: string;
}

function execPrefix(conn: DbConnection): string[] {
  if (conn.composeFile.length > 0 && conn.service.length > 0) {
    return ['docker', 'compose', '-f', conn.composeFile, 'exec', '-T', conn.service];
  }
  if (conn.container.length > 0) {
    return ['docker', 'exec', '-i', conn.container];
  }
  throw new Error('db: connection needs either {compose_file, service} or {container}');
}

/**
 * Builds the full remote command: `docker (compose) exec` into the db container, running
 * psql non-interactively against a single `-c` SQL buffer. `-qAt` = quiet (suppresses the
 * BEGIN/ROLLBACK command-completion tags the txn wrapper adds, leaving only the SELECT's
 * tuple output), unaligned, tuples-only — one JSON value per call, trivial to parse.
 */
export function buildPsqlCommand(conn: DbConnection, sql: string): string {
  return shellJoin([
    ...execPrefix(conn),
    'psql',
    '-U',
    conn.user,
    '-d',
    conn.database,
    '-v',
    'ON_ERROR_STOP=1',
    '-qAt',
    '-c',
    sql,
  ]);
}

/**
 * `db slow` needs two round trips: check whether `pg_stat_statements` is installed
 * before ever referencing it, because Postgres validates catalog references at parse
 * time — a single query with the real SELECT inside an untaken CASE branch still fails
 * to plan when the extension is absent. Both calls run inside the same remote shell
 * script (one ssh round trip), following the same nested shq-quoting pattern as
 * `files cat`/`files download`'s sh -c scripts.
 */
export function buildDbSlowCommand(conn: DbConnection): string {
  const checkSql = wrapReadOnlyTxn(
    "SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'",
  );
  const dataSql = wrapReadOnlyTxn(
    "SELECT json_build_object('available', true, 'queries', coalesce(json_agg(s), '[]'::json)) " +
      'FROM (SELECT query, calls, total_exec_time, mean_exec_time, rows FROM pg_stat_statements ' +
      'ORDER BY mean_exec_time DESC LIMIT 20) s',
  );
  const checkCmd = buildPsqlCommand(conn, checkSql);
  const dataCmd = buildPsqlCommand(conn, dataSql);
  const script = [
    `present=$(${checkCmd})`,
    'if [ -n "$present" ]; then',
    `  ${dataCmd}`,
    'else',
    `  printf '%s' '{"available":false,"reason":"pg_stat_statements not installed"}'`,
    'fi',
  ].join('\n');
  return shellJoin(['sh', '-c', script]);
}

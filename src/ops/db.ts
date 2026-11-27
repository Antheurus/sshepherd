import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { AuditWriteError } from '../audit.ts';
import {
  assertNoMultiStatementSql,
  assertSelectOnly,
  assertSelfContainedSql,
  backupNamePattern,
  boundedSessionSql,
  buildDbBackupScript,
  buildDbBackupVerifyScript,
  buildDbExecCommand,
  buildDbMigrationsCommand,
  buildDbSlowCommand,
  buildPsqlCommand,
  classifySqlStatement,
  countRowsSql,
  type DbConnection,
  describeTableSql,
  EXEC_DONE_MARKER,
  EXEC_ROWS_MARKER,
  EXEC_TXN_ENDED_MARKER,
  limitRows,
  MIGRATION_TABLES,
  MIGRATIONS_DIR_MARKER,
  MIGRATIONS_NO_DIR_MARKER,
  migrationTableRef,
  quoteIdentifier,
  type SqlStatement,
  type StatementInfo,
  splitSqlStatements,
  statementTimeoutFor,
  wrapAsJsonAgg,
  wrapReadOnlyTxn,
} from '../db.ts';
import { describeError } from '../errors.ts';
import {
  DB_BACKUP_KEEP_DEFAULT,
  DB_BACKUP_KEEP_MAX,
  DB_BACKUP_MAX_BYTES_DEFAULT,
  DB_BACKUP_TIMEOUT_SEC,
  DB_BACKUP_VERIFY_MAX_TABLES,
  DB_BACKUP_VERIFY_TIMEOUT_SEC,
  DB_EXEC_MAX_COMMAND_BYTES,
  DB_EXEC_MAX_SQL_BYTES,
  DB_EXEC_MAX_STATEMENTS,
  DB_EXEC_MAX_TABLES,
  DB_EXEC_SQL_DIR_MAX_BYTES,
  DB_EXEC_SQL_KEEP_DAYS,
  DB_EXEC_TIMEOUT_SEC,
  DB_LOCK_TIMEOUT_SEC,
  DB_MIGRATIONS_COMPARE_MAX,
  DB_MIGRATIONS_LIMIT,
  DB_QUERY_MAX_ROWS,
  DB_QUERY_ROW_LIMIT,
  DB_QUERY_TIMEOUT_SEC,
  DB_TIMEOUT_SEC,
  MAX_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, optBool, optStr, optStrOrNull, readRecord, reqStr } from '../op-args.ts';
import { MASK, scrubText } from '../scrub.ts';
import {
  DB_BACKUP_DEFAULT_DIR,
  DEFAULT_DENY_COLUMNS,
  defaultTargetsPath,
  PG_TARGET_KINDS,
  type PgTargetKind,
  pgTargetNames,
} from '../targets.ts';
import { type ErrorInfo, type OpContext, OpError, type OpSpec, Premasked } from '../types.ts';

// ---------------------------------------------------------------------------
// db
// ---------------------------------------------------------------------------

function targetKind(ctx: OpContext): PgTargetKind {
  const kind = optStr(ctx, 'db_kind', 'container');
  return (PG_TARGET_KINDS as readonly string[]).includes(kind)
    ? (kind as PgTargetKind)
    : 'container';
}

function dbConnectionFromCtx(ctx: OpContext): DbConnection {
  const kind = targetKind(ctx);
  const fromUrl = kind === 'container-env';
  return {
    kind,
    composeFile: optStr(ctx, 'compose_file', ''),
    service: optStr(ctx, 'service', ''),
    container: optStr(ctx, 'container', ''),
    user: fromUrl ? optStr(ctx, 'db_user', '') : reqStr(ctx, 'db_user'),
    database: fromUrl ? optStr(ctx, 'db_name', '') : reqStr(ctx, 'db_name'),
    envKey: optStr(ctx, 'env_key', ''),
    psqlContainer: optStr(ctx, 'psql_container', ''),
    sudoUser: optStr(ctx, 'sudo_user', ''),
    pgHost: optStr(ctx, 'pg_host', ''),
    pgPort: optStr(ctx, 'pg_port', ''),
  };
}

/** The target's connection fields `buildDbOpContext` resolves from targets.toml. */
const DB_CONNECTION_ARGS = [
  'db_user',
  'db_name',
  'container',
  'compose_file',
  'service',
  'psql_container',
  'sudo_user',
  'pg_host',
];

/** Declared on the bounded ops so the CLI's global `--timeout` also reaches `buildRemote`, where it
 *  sets `statement_timeout` (the budget less its grace). */
const TIMEOUT_ARG = arg(
  'timeout',
  'flag',
  false,
  'Seconds for the whole call; Postgres cancels the statement itself 15 s (or half the budget) before it.',
);

/** The ssh budget the call runs with: `--timeout` when given (the CLI has already bounded it). */
function budgetSec(ctx: OpContext, fallback: number): number {
  const raw = ctx.args.timeout;
  const value = typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  return Number.isInteger(value) && value >= 1 && value <= MAX_TIMEOUT_SEC ? value : fallback;
}

function boundedSql(ctx: OpContext, fallbackBudgetSec: number): string {
  return boundedSessionSql(statementTimeoutFor(budgetSec(ctx, fallbackBudgetSec)));
}

const STATEMENT_TIMEOUT_TEXT = 'canceling statement due to statement timeout';
const LOCK_TIMEOUT_TEXT = 'canceling statement due to lock timeout';

/** psql's own cancel is a `COMMAND_TIMEOUT` with its cause, not a generic `COMMAND_FAILED`. */
function refinePsqlTimeout(fallbackBudgetSec: number) {
  return (commandStderr: string, error: ErrorInfo, ctx: OpContext): ErrorInfo | undefined => {
    const target = String(ctx.args.target ?? '');
    const base = { remote_exit: error.remote_exit, phase: 'command' as const };
    if (commandStderr.includes(STATEMENT_TIMEOUT_TEXT)) {
      const limit = statementTimeoutFor(budgetSec(ctx, fallbackBudgetSec));
      return {
        ...describeError(
          'COMMAND_TIMEOUT',
          `Postgres cancelled the statement at statement_timeout (${limit} s)`,
          {
            hint: 'Narrow the query (a WHERE on an indexed column, a smaller range) or give it more time with --timeout <sec>; statement_timeout follows that budget.',
          },
        ),
        ...base,
        timeout_sec: limit,
      };
    }
    if (commandStderr.includes(LOCK_TIMEOUT_TEXT)) {
      return {
        ...describeError(
          'COMMAND_TIMEOUT',
          `the statement waited past lock_timeout (${DB_LOCK_TIMEOUT_SEC} s) for a lock another session holds`,
          {
            hint: 'A migration or long write holds a lock on that table; see blocked_by in db activity, then retry once it finishes.',
            next: `sshepherd db activity ${target}`,
          },
        ),
        ...base,
        timeout_sec: DB_LOCK_TIMEOUT_SEC,
      };
    }
    return undefined;
  };
}

const PSQL_FIELD = /^(?:psql:\S*\s+)?(ERROR|DETAIL|HINT):\s+(.*)$/gm;

/** psql's own `ERROR:`/`DETAIL:`/`HINT:` lines, first of each, as `error.data.sql_error`. No
 *  `position`: psql's caret points into the wrapped statement (read-only transaction + json_agg),
 *  so a column number would not match the SQL the caller wrote. */
function psqlErrorData(commandStderr: string): Record<string, unknown> | undefined {
  const fields = new Map<string, string>();
  for (const match of commandStderr.matchAll(PSQL_FIELD)) {
    const name = match[1]?.toLowerCase();
    const text = match[2]?.trim();
    if (name !== undefined && text !== undefined && !fields.has(name)) {
      fields.set(name, text);
    }
  }
  const message = fields.get('error');
  if (message === undefined) {
    return undefined;
  }
  const sqlError: Record<string, string> = { message };
  for (const name of ['detail', 'hint']) {
    const text = fields.get(name);
    if (text !== undefined) {
      sqlError[name] = text;
    }
  }
  return { sql_error: sqlError };
}

/** `wrapAsJsonAgg` turns zero rows into SQL NULL, which psql -qAt prints as an empty string. */
function parseJsonArray(parsed: unknown): unknown[] {
  if (parsed === null) {
    return [];
  }
  return Array.isArray(parsed) ? parsed : [parsed];
}

interface DbListResult {
  targets: string[];
}

const dbList: OpSpec<DbListResult> = {
  group: 'db',
  name: 'list',
  summary: 'List declared pg-target names from targets.toml (names only — never host/user/db).',
  args: [],
  mutating: false,
  exposes: 'none',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as DbListResult,
  runLocal: () => ({ targets: pgTargetNames(defaultTargetsPath()) }),
};

interface DbTableEntry {
  schema: string;
  table: string;
  size_bytes: number;
}

const DB_TABLES_SQL =
  'SELECT schemaname AS schema, tablename AS table, ' +
  "pg_total_relation_size(format('%I.%I', schemaname, tablename)) AS size_bytes " +
  "FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') " +
  'ORDER BY size_bytes DESC';

const dbTables: OpSpec<DbTableEntry[]> = {
  group: 'db',
  name: 'tables',
  summary: 'All user tables with total size in bytes (indexes + toast included).',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(wrapAsJsonAgg(DB_TABLES_SQL))),
  shape: (parsed) =>
    parseJsonArray(parsed).map((raw) => {
      const record = readRecord(raw);
      return {
        schema: typeof record.schema === 'string' ? record.schema : '',
        table: typeof record.table === 'string' ? record.table : '',
        size_bytes: typeof record.size_bytes === 'number' ? record.size_bytes : 0,
      };
    }),
};

interface DbActivityBackend {
  pid: number;
  usename: string | null;
  application_name: string | null;
  state: string | null;
  query_start: string | null;
  query_seconds: number | null;
  wait_event: string | null;
  blocked_by: number[];
}

interface DbActivityResult {
  backends_total: number;
  max_connections: number;
  backends: DbActivityBackend[];
}

const DB_ACTIVITY_SQL =
  'SELECT json_build_object(' +
  "'backends_total', (SELECT count(*) FROM pg_stat_activity), " +
  "'max_connections', (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'), " +
  "'backends', (SELECT coalesce(json_agg(b), '[]'::json) FROM (" +
  'SELECT pid, usename, application_name, state, query_start, ' +
  'extract(epoch FROM (now() - query_start)) AS query_seconds, wait_event, ' +
  'pg_blocking_pids(pid) AS blocked_by FROM pg_stat_activity WHERE pid <> pg_backend_pid()' +
  ') b))';

const dbActivity: OpSpec<DbActivityResult> = {
  group: 'db',
  name: 'activity',
  summary:
    'pg_stat_activity per backend (query_seconds, blocked_by) + backends_total vs max_connections.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(DB_ACTIVITY_SQL)),
  shape: (parsed) => {
    const record = readRecord(parsed);
    const backends = Array.isArray(record.backends) ? record.backends : [];
    return {
      backends_total: typeof record.backends_total === 'number' ? record.backends_total : 0,
      max_connections: typeof record.max_connections === 'number' ? record.max_connections : 0,
      backends: backends.map((raw) => {
        const b = readRecord(raw);
        return {
          pid: typeof b.pid === 'number' ? b.pid : 0,
          usename: typeof b.usename === 'string' ? b.usename : null,
          application_name: typeof b.application_name === 'string' ? b.application_name : null,
          state: typeof b.state === 'string' ? b.state : null,
          query_start: typeof b.query_start === 'string' ? b.query_start : null,
          query_seconds: typeof b.query_seconds === 'number' ? b.query_seconds : null,
          wait_event: typeof b.wait_event === 'string' ? b.wait_event : null,
          blocked_by: Array.isArray(b.blocked_by)
            ? b.blocked_by.filter((pid): pid is number => typeof pid === 'number')
            : [],
        };
      }),
    };
  },
};

interface DbConnectionsResult {
  backends_total: number;
  max_connections: number;
  by_state: Record<string, number>;
}

const DB_CONNECTIONS_SQL =
  'SELECT json_build_object(' +
  "'backends_total', (SELECT count(*) FROM pg_stat_activity), " +
  "'max_connections', (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'), " +
  "'by_state', (SELECT coalesce(json_object_agg(coalesce(state, 'unknown'), cnt), '{}'::json) FROM (" +
  'SELECT state, count(*) AS cnt FROM pg_stat_activity GROUP BY state' +
  ') s))';

const dbConnections: OpSpec<DbConnectionsResult> = {
  group: 'db',
  name: 'connections',
  summary: 'Backend count by state vs max_connections.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(DB_CONNECTIONS_SQL)),
  shape: (parsed) => {
    const record = readRecord(parsed);
    const byStateRaw = readRecord(record.by_state);
    const byState: Record<string, number> = {};
    for (const [key, value] of Object.entries(byStateRaw)) {
      if (typeof value === 'number') {
        byState[key] = value;
      }
    }
    return {
      backends_total: typeof record.backends_total === 'number' ? record.backends_total : 0,
      max_connections: typeof record.max_connections === 'number' ? record.max_connections : 0,
      by_state: byState,
    };
  },
};

interface DbSlowQueryEntry {
  query: string;
  calls: number;
  total_exec_time: number;
  mean_exec_time: number;
  rows: number;
}

interface DbSlowResult {
  available: boolean;
  reason: string | null;
  queries: DbSlowQueryEntry[];
}

const dbSlow: OpSpec<DbSlowResult> = {
  group: 'db',
  name: 'slow',
  summary: 'Top queries by mean exec time from pg_stat_statements — degrades cleanly when absent.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  exposes: 'content',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) => buildDbSlowCommand(dbConnectionFromCtx(ctx)),
  shape: (parsed) => {
    const record = readRecord(parsed);
    if (record.available !== true) {
      return {
        available: false,
        reason: typeof record.reason === 'string' ? record.reason : null,
        queries: [],
      };
    }
    const rawQueries = Array.isArray(record.queries) ? record.queries : [];
    return {
      available: true,
      reason: null,
      queries: rawQueries.map((raw) => {
        const q = readRecord(raw);
        return {
          query: typeof q.query === 'string' ? q.query : '',
          calls: typeof q.calls === 'number' ? q.calls : 0,
          total_exec_time: typeof q.total_exec_time === 'number' ? q.total_exec_time : 0,
          mean_exec_time: typeof q.mean_exec_time === 'number' ? q.mean_exec_time : 0,
          rows: typeof q.rows === 'number' ? q.rows : 0,
        };
      }),
    };
  },
};

interface DbSizeEntry {
  datname: string;
  size_bytes: number;
}

const DB_SIZE_SQL =
  'SELECT datname, pg_database_size(datname) AS size_bytes ' +
  'FROM pg_database WHERE datistemplate = false ORDER BY size_bytes DESC';

const dbSize: OpSpec<{ databases: DbSizeEntry[] }> = {
  group: 'db',
  name: 'size',
  summary: 'Every non-template database on the server, sized in bytes.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(wrapAsJsonAgg(DB_SIZE_SQL))),
  shape: (parsed) => ({
    databases: parseJsonArray(parsed).map((raw) => {
      const record = readRecord(raw);
      return {
        datname: typeof record.datname === 'string' ? record.datname : '',
        size_bytes: typeof record.size_bytes === 'number' ? record.size_bytes : 0,
      };
    }),
  }),
};

interface DbQueryResult {
  rows: unknown[];
  row_count: number;
  truncated: boolean;
  /** Columns whose values were masked because their name matched the target's `deny_columns`. */
  masked_columns: string[];
}

/** The target's `deny_columns` as `buildDbOpContext` passed them (a JSON list), else the default:
 *  a context that carries none, or an unreadable one, masks as much as the default does. */
function denyColumnPatterns(ctx: OpContext): RegExp[] {
  const raw = ctx.args.deny_columns;
  let list: unknown = DEFAULT_DENY_COLUMNS;
  if (typeof raw === 'string' && raw.length > 0) {
    try {
      list = JSON.parse(raw);
    } catch {
      list = DEFAULT_DENY_COLUMNS;
    }
  }
  const patterns =
    Array.isArray(list) && list.length > 0 && list.every((item) => typeof item === 'string')
      ? (list as string[])
      : DEFAULT_DENY_COLUMNS;
  return patterns.map((pattern) => new RegExp(pattern, 'i'));
}

/** Masks, by column name, every non-null value of a denied column in the fetched rows. */
function maskDeniedColumns(
  rows: unknown[],
  patterns: RegExp[],
): { rows: unknown[]; maskedColumns: string[]; cells: number } {
  const maskedColumns = new Set<string>();
  let cells = 0;
  const masked = rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      return row;
    }
    const out: Record<string, unknown> = {};
    for (const [column, value] of Object.entries(row)) {
      if (patterns.some((pattern) => pattern.test(column))) {
        maskedColumns.add(column);
        if (value !== null) {
          cells += 1;
          out[column] = MASK;
          continue;
        }
      }
      out[column] = value;
    }
    return out;
  });
  return { rows: masked, maskedColumns: [...maskedColumns].sort(), cells };
}

/** `--max-rows`, else `DB_QUERY_ROW_LIMIT`; anything outside 1..`DB_QUERY_MAX_ROWS` is refused. */
function rowLimit(ctx: OpContext): number {
  const raw = ctx.args['max-rows'];
  if (raw === undefined) {
    return DB_QUERY_ROW_LIMIT;
  }
  const value = typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(value) || value < 1 || value > DB_QUERY_MAX_ROWS) {
    throw new OpError(
      'INVALID_ARGS',
      `--max-rows must be a whole number of rows from 1 to ${DB_QUERY_MAX_ROWS}`,
    );
  }
  return value;
}

const dbQuery: OpSpec<DbQueryResult> = {
  group: 'db',
  name: 'query',
  summary:
    'Ad hoc read-only SQL against a pg-target — SELECT only, a read-only transaction with statement and lock timeouts, at most --max-rows rows.',
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    arg('sql', 'positional', true, 'SELECT statement to run.'),
    arg(
      'max-rows',
      'flag',
      false,
      `Rows to return, 1-${DB_QUERY_MAX_ROWS} (default ${DB_QUERY_ROW_LIMIT}); a query with more sets truncated: true.`,
    ),
    TIMEOUT_ARG,
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: DB_QUERY_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  refineError: refinePsqlTimeout(DB_QUERY_TIMEOUT_SEC),
  hiddenArgs: DB_CONNECTION_ARGS,
  echoArgs: ['sql'],
  buildRemote: (ctx) => {
    const sql = reqStr(ctx, 'sql');
    assertNoMultiStatementSql(sql);
    assertSelfContainedSql(sql);
    assertSelectOnly(sql);
    const limit = rowLimit(ctx);
    return buildPsqlCommand(
      dbConnectionFromCtx(ctx),
      boundedSql(ctx, DB_QUERY_TIMEOUT_SEC),
      wrapReadOnlyTxn(wrapAsJsonAgg(limitRows(sql, limit))),
    );
  },
  shape: (parsed, ctx) => {
    const all = parseJsonArray(parsed);
    const limit = rowLimit(ctx);
    const { rows, maskedColumns, cells } = maskDeniedColumns(
      all.slice(0, limit),
      denyColumnPatterns(ctx),
    );
    return new Premasked(
      {
        rows,
        row_count: rows.length,
        truncated: all.length > limit,
        masked_columns: maskedColumns,
      },
      cells,
    );
  },
  recount: (_before, after) => {
    const data = readRecord(after);
    if (!Array.isArray(data.rows)) {
      return after;
    }
    const recounted: Record<string, unknown> = { ...data };
    if ('row_count' in data) {
      recounted.row_count = data.rows.length;
    }
    if ('truncated' in data) {
      recounted.truncated = true;
    }
    return recounted;
  },
};

interface DbColumn {
  name: string;
  type: string;
  nullable: boolean;
  default: string | null;
}

interface DbIndex {
  name: string;
  unique: boolean;
  primary: boolean;
  definition: string;
}

interface DbForeignKey {
  name: string;
  columns: string[];
  references_table: string;
  references_columns: string[];
  definition: string;
}

interface DbDescribeResult {
  schema: string;
  table: string;
  columns: DbColumn[];
  indexes: DbIndex[];
  foreign_keys: DbForeignKey[];
}

const strOr = (value: unknown, fallback: string): string =>
  typeof value === 'string' ? value : fallback;
const strList = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
const listOf = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

const TABLE_ARG = arg(
  'table',
  'positional',
  true,
  'Table as name or schema.name (unquoted parts fold to lower case; "Quoted" parts are exact).',
);

const dbDescribe: OpSpec<DbDescribeResult> = {
  group: 'db',
  name: 'describe',
  summary:
    'One table: columns (type, nullable, default), indexes and foreign keys, from the catalog.',
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    TABLE_ARG,
    TIMEOUT_ARG,
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  refineError: refinePsqlTimeout(DB_TIMEOUT_SEC),
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildPsqlCommand(
      dbConnectionFromCtx(ctx),
      boundedSql(ctx, DB_TIMEOUT_SEC),
      wrapReadOnlyTxn(describeTableSql(quoteIdentifier(reqStr(ctx, 'table'), 'table'))),
    ),
  shape: (parsed, ctx) => {
    const record = readRecord(parsed);
    if (record.found !== true) {
      const target = String(ctx.args.target ?? '');
      throw new OpError(
        'VALIDATION_ERROR',
        `table '${String(ctx.args.table)}' does not exist on pg-target '${target}', or its role cannot see it`,
        { next: `sshepherd db tables ${target}` },
      );
    }
    return {
      schema: strOr(record.schema, ''),
      table: strOr(record.table, ''),
      columns: listOf(record.columns).map((raw) => {
        const c = readRecord(raw);
        return {
          name: strOr(c.name, ''),
          type: strOr(c.type, ''),
          nullable: c.nullable === true,
          default: typeof c.default === 'string' ? c.default : null,
        };
      }),
      indexes: listOf(record.indexes).map((raw) => {
        const i = readRecord(raw);
        return {
          name: strOr(i.name, ''),
          unique: i.unique === true,
          primary: i.primary === true,
          definition: strOr(i.definition, ''),
        };
      }),
      foreign_keys: listOf(record.foreign_keys).map((raw) => {
        const f = readRecord(raw);
        return {
          name: strOr(f.name, ''),
          columns: strList(f.columns),
          references_table: strOr(f.references_table, ''),
          references_columns: strList(f.references_columns),
          definition: strOr(f.definition, ''),
        };
      }),
    };
  },
};

/** `--where-eq col=value`: the column becomes a quoted identifier, the value a literal. */
function whereEqOf(ctx: OpContext): { column: string; value: string } | null {
  const raw = ctx.args['where-eq'];
  if (raw === undefined) {
    return null;
  }
  const text = String(raw);
  const eq = text.indexOf('=');
  if (eq <= 0) {
    throw new OpError(
      'INVALID_ARGS',
      `--where-eq must be column=value, got ${JSON.stringify(text)}`,
    );
  }
  return {
    column: quoteIdentifier(text.slice(0, eq), '--where-eq column', 1),
    value: text.slice(eq + 1),
  };
}

const dbCount: OpSpec<{ count: number }> = {
  group: 'db',
  name: 'count',
  summary: 'count(*) of one table, optionally only rows where one column equals a value.',
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    TABLE_ARG,
    arg(
      'where-eq',
      'flag',
      false,
      'column=value: count only the rows where that column equals the value.',
    ),
    TIMEOUT_ARG,
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  errorData: psqlErrorData,
  refineError: refinePsqlTimeout(DB_TIMEOUT_SEC),
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildPsqlCommand(
      dbConnectionFromCtx(ctx),
      boundedSql(ctx, DB_TIMEOUT_SEC),
      wrapReadOnlyTxn(countRowsSql(quoteIdentifier(reqStr(ctx, 'table'), 'table'), whereEqOf(ctx))),
    ),
  shape: (parsed) => {
    const count = readRecord(parsed).count;
    return { count: typeof count === 'number' ? count : 0 };
  },
};

interface DbMigration {
  name: string;
  applied_at: string | null;
}

interface DbMigrationsTable {
  framework: string;
  table: string;
  /** The newest applied migration's name; null when the table is empty. */
  current: string | null;
  migrations: DbMigration[];
  /** With `--dir`: entries of that directory no applied migration accounts for; else null. */
  pending: string[] | null;
}

interface DbMigrationsResult {
  tables: DbMigrationsTable[];
}

/** `--table`: a known migrations table, by name or schema.name. */
function migrationsTableOf(ctx: OpContext) {
  const raw = optStrOrNull(ctx, 'table');
  if (raw === null) {
    return null;
  }
  const ref = migrationTableRef(quoteIdentifier(raw, '--table'));
  if (ref === null) {
    throw new OpError(
      'INVALID_ARGS',
      `--table must name one of the migrations tables sshepherd reads (${MIGRATION_TABLES.join(', ')}), optionally schema-qualified; got ${JSON.stringify(raw)}`,
    );
  }
  return ref;
}

function migrationsDirOf(ctx: OpContext): string | null {
  const dir = optStrOrNull(ctx, 'dir');
  if (dir !== null && /[\0\r\n]/.test(dir)) {
    throw new OpError(
      'INVALID_ARGS',
      `--dir contains a NUL or line-break character (got ${JSON.stringify(dir)})`,
    );
  }
  return dir;
}

/** The trailing digits a framework keeps as the version: all of a rails `version`, the timestamp
 *  a typeorm class name ends with (`Init1700000000000`). Eight digits is the shortest date. */
const VERSION_NAME = /^(?:\d{8,}|[A-Za-z_][A-Za-z0-9_]*?(\d{8,}))$/;

/** Entries of a migrations directory that no applied name accounts for. An entry counts when it
 *  starts with a digit (every framework names migrations by date or sequence, so a lock file or
 *  README is not one) and is applied when the name, the name less its extension, or its leading
 *  version (`20260901000000_create_users.rb` for rails, `1700000000000-Init.ts` for typeorm)
 *  matches an applied migration. */
export function pendingMigrations(entries: string[], applied: string[]): string[] {
  const names = new Set(applied);
  const versions = new Set<string>();
  for (const name of applied) {
    const match = VERSION_NAME.exec(name);
    if (match !== null) {
      versions.add(match[1] ?? name);
    }
  }
  return entries
    .filter((entry) => /^\d/.test(entry))
    .filter((entry) => {
      const stem = entry.replace(/\.[A-Za-z0-9]+$/, '');
      const version = /^\d{8,}/.exec(stem)?.[0];
      return !(
        names.has(entry) ||
        names.has(stem) ||
        (version !== undefined && versions.has(version))
      );
    })
    .sort();
}

/** The JSON array of tables, then with `--dir` the marker line and the directory's entries. */
function parseMigrationsOutput(stdout: string): { tables: unknown; entries: string[] | null } {
  const marker = stdout.indexOf(`\n${MIGRATIONS_DIR_MARKER}\n`);
  const json = (marker === -1 ? stdout : stdout.slice(0, marker)).trim();
  const tables: unknown = json.length === 0 ? [] : JSON.parse(json);
  if (marker === -1) {
    return { tables, entries: null };
  }
  const listing = stdout.slice(marker + MIGRATIONS_DIR_MARKER.length + 2);
  const lines = listing.split('\n').filter((line) => line.length > 0);
  return { tables, entries: lines };
}

const dbMigrations: OpSpec<DbMigrationsResult> = {
  group: 'db',
  name: 'migrations',
  summary: `Applied migrations (current, then name and applied_at, newest ${DB_MIGRATIONS_LIMIT} per table) from whichever of the prisma, knex, typeorm, rails and laravel tables exist; --dir adds the pending ones.`,
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    arg(
      'table',
      'flag',
      false,
      `Read only this migrations table (${MIGRATION_TABLES.join(', ')}), as name or schema.name.`,
    ),
    arg(
      'dir',
      'flag',
      false,
      `Remote migrations directory — must be on files-allowlist.toml; its entries no applied migration accounts for come back as pending (at most ${DB_MIGRATIONS_COMPARE_MAX} compared).`,
    ),
    TIMEOUT_ARG,
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_TIMEOUT_SEC,
  output: { parse: parseMigrationsOutput },
  allowlist: [{ kind: 'path', scope: 'files', argName: 'dir', optional: true }],
  errorData: psqlErrorData,
  refineError: refinePsqlTimeout(DB_TIMEOUT_SEC),
  hiddenArgs: DB_CONNECTION_ARGS,
  buildRemote: (ctx) =>
    buildDbMigrationsCommand(
      dbConnectionFromCtx(ctx),
      boundedSql(ctx, DB_TIMEOUT_SEC),
      wrapReadOnlyTxn,
      DB_MIGRATIONS_LIMIT,
      {
        table: migrationsTableOf(ctx),
        dir: migrationsDirOf(ctx),
        compareMax: DB_MIGRATIONS_COMPARE_MAX,
      },
    ),
  shape: (parsed, ctx) => {
    const { tables, entries } = parsed as ReturnType<typeof parseMigrationsOutput>;
    const dir = optStrOrNull(ctx, 'dir');
    if (entries !== null && entries[0] === MIGRATIONS_NO_DIR_MARKER) {
      throw new OpError(
        'VALIDATION_ERROR',
        `db migrations: '${dir ?? ''}' is not a directory on the host`,
        {
          hint: 'Pass the directory the migration files live in, e.g. prisma/migrations or db/migrate under the app root.',
        },
      );
    }
    const shaped = parseJsonArray(tables).map((raw): DbMigrationsTable => {
      const record = readRecord(raw);
      const migrations = listOf(record.migrations).map((entry) => {
        const m = readRecord(entry);
        return {
          name: typeof m.name === 'string' ? m.name : String(m.name ?? ''),
          applied_at: typeof m.applied_at === 'string' ? m.applied_at : null,
        };
      });
      const names = strList(record.names);
      if (
        entries !== null &&
        (names.length > DB_MIGRATIONS_COMPARE_MAX || entries.length > DB_MIGRATIONS_COMPARE_MAX)
      ) {
        throw new OpError(
          'OUTPUT_TOO_LARGE',
          `db migrations --dir: more than ${DB_MIGRATIONS_COMPARE_MAX} applied migrations or directory entries, so pending cannot be told completely`,
          {
            hint: 'Run db migrations without --dir for the current version and the newest applied ones.',
          },
        );
      }
      return {
        framework: strOr(record.framework, ''),
        table: strOr(record.table, ''),
        current: migrations[0]?.name ?? null,
        migrations,
        pending: entries === null ? null : pendingMigrations(entries, names),
      };
    });
    if (shaped.length === 0 && optStrOrNull(ctx, 'table') !== null) {
      const target = String(ctx.args.target ?? '');
      throw new OpError(
        'VALIDATION_ERROR',
        `table '${String(ctx.args.table)}' does not exist on pg-target '${target}', or its role cannot see it`,
        { next: `sshepherd db migrations ${target}` },
      );
    }
    return { tables: shaped };
  },
};

// ---------------------------------------------------------------------------
// governed writes and backups: db exec, db backup, db backup-verify
// ---------------------------------------------------------------------------

/** Connection args of the write ops: the read set plus the write login, masked in errors the same way. */
const DB_WRITE_ARGS = [...DB_CONNECTION_ARGS, 'write_role'];

function targetName(ctx: OpContext): string {
  return String(ctx.args.target ?? '');
}

/** The write ops reach Postgres as a login the target names; a container-env URL carries its own. */
function refuseUrlTarget(ctx: OpContext, conn: DbConnection, op: string): void {
  if (conn.kind === 'container-env') {
    throw new OpError(
      'VALIDATION_ERROR',
      `${op}: pg-target '${targetName(ctx)}' is kind container-env, whose URL names its own login; ${op} runs only on container and host targets`,
      {
        hint: 'Declare a container or host pg-target for the same database with user and write_role.',
      },
    );
  }
}

/** The connection as the target's `write_role`: declared, and never the read login `user`. */
function writeConnection(ctx: OpContext, op: string): DbConnection {
  const conn = dbConnectionFromCtx(ctx);
  refuseUrlTarget(ctx, conn, op);
  const role = optStr(ctx, 'write_role', '');
  if (role.length === 0) {
    throw new OpError(
      'VALIDATION_ERROR',
      `${op}: pg-target '${targetName(ctx)}' declares no write_role in targets.toml, and ${op} never connects as the read-only login`,
      {
        hint: 'A human adds write_role = "<login>" to that target: a login allowed to write the tables the change touches (and CREATEDB for backup-verify).',
      },
    );
  }
  if (role === conn.user) {
    throw new OpError(
      'VALIDATION_ERROR',
      `${op}: pg-target '${targetName(ctx)}' has write_role equal to user; write_role must be a different login than the read-only one db query uses`,
      { hint: 'Point write_role at the separate write login in targets.toml.' },
    );
  }
  return { ...conn, user: role };
}

/** The SQL `--file` held when `buildRemote` read it, kept for the same call's `shape` and audit row
 *  so all three see the very text that ran, even if the file changes meanwhile. */
const execSqlByCall = new WeakMap<OpContext, string>();

function readExecSql(ctx: OpContext): string {
  const cached = execSqlByCall.get(ctx);
  if (cached !== undefined) {
    return cached;
  }
  const path = reqStr(ctx, 'file');
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch {
    throw new OpError('VALIDATION_ERROR', `db exec: local file '${path}' not found or unreadable`, {
      hint: '--file names a LOCAL .sql file, e.g. ./migrations/fix-orders.sql.',
    });
  }
  if (bytes.length > DB_EXEC_MAX_SQL_BYTES) {
    throw new OpError(
      'VALIDATION_ERROR',
      `db exec: '${path}' is ${bytes.length} bytes; one call takes at most ${DB_EXEC_MAX_SQL_BYTES}`,
      { hint: 'Split the change into smaller files and run them one after the other.' },
    );
  }
  const sql = bytes.toString('utf8');
  if (sql.includes('\0')) {
    throw new OpError(
      'VALIDATION_ERROR',
      `db exec: '${path}' contains a NUL byte; it is not a SQL text file`,
    );
  }
  execSqlByCall.set(ctx, sql);
  return sql;
}

const sha256Hex = (text: string): string => createHash('sha256').update(text).digest('hex');

function tablesOfStatements(infos: StatementInfo[]): string[] {
  return [...new Set(infos.flatMap((info) => info.tables))].sort().slice(0, DB_EXEC_MAX_TABLES);
}

interface ExecPlan {
  statements: SqlStatement[];
  infos: StatementInfo[];
}

/** The file split and classified; a refused statement or (without `--allow-ddl`) a DDL one stops
 *  the call before anything is sent. */
function execPlan(ctx: OpContext): ExecPlan {
  const statements = splitSqlStatements(readExecSql(ctx));
  if (statements.length === 0) {
    throw new OpError('VALIDATION_ERROR', 'db exec: the file holds no SQL statement');
  }
  if (statements.length > DB_EXEC_MAX_STATEMENTS) {
    throw new OpError(
      'VALIDATION_ERROR',
      `db exec: the file holds ${statements.length} statements; one call runs at most ${DB_EXEC_MAX_STATEMENTS}`,
      { hint: 'Split the change into smaller files.' },
    );
  }
  const infos = statements.map(classifySqlStatement);
  const refused = infos.findIndex((info) => info.refused !== null);
  if (refused !== -1) {
    throw new OpError(
      'VALIDATION_ERROR',
      `db exec: statement ${refused + 1} (${infos[refused]?.command || 'unknown'}) is refused: ${infos[refused]?.refused}`,
      { hint: 'Remove that statement; nothing in the file ran.' },
    );
  }
  if (!optBool(ctx, 'allow-ddl', false)) {
    const ddl = infos.findIndex((info) => info.ddl);
    if (ddl !== -1) {
      throw new OpError(
        'DDL_REFUSED',
        `db exec: statement ${ddl + 1} (${infos[ddl]?.command}) changes the schema or privileges (or runs opaque code), and --allow-ddl was not given; nothing ran`,
      );
    }
  }
  return { statements, infos };
}

/** Writes the scrubbed SQL as `<stateDir>/sql/<sha256>.sql` (0600, dir 0700), then deletes side
 *  files older than `DB_EXEC_SQL_KEEP_DAYS` and, oldest first, any past `DB_EXEC_SQL_DIR_MAX_BYTES`
 *  — never the one just written. */
function writeSqlSideFile(stateDir: string, sha: string, sql: string): void {
  const dir = join(stateDir, 'sql');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const masked = scrubText(sql, { maskAddresses: true }).value.replace(
    /(\bPASSWORD\s+)'(?:[^']|'')*'/gi,
    `$1'${MASK}'`,
  );
  const file = join(dir, `${sha}.sql`);
  writeFileSync(file, masked, { mode: 0o600 });
  chmodSync(file, 0o600);
  const oldest = Date.now() - DB_EXEC_SQL_KEEP_DAYS * 86_400_000;
  const entries = readdirSync(dir)
    .filter((name) => /^[0-9a-f]{64}\.sql$/.test(name))
    .map((name) => ({ path: join(dir, name), ...statSync(join(dir, name)) }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  let total = 0;
  for (const entry of entries) {
    if (entry.path === file) {
      total += entry.size;
    } else if (entry.mtimeMs < oldest || total + entry.size > DB_EXEC_SQL_DIR_MAX_BYTES) {
      rmSync(entry.path, { force: true });
    } else {
      total += entry.size;
    }
  }
}

interface DbExecStatement {
  index: number;
  command: string;
  row_count: number | null;
}

interface DbExecResult {
  dry_run: boolean;
  committed: boolean;
  sql_sha256: string;
  tables: string[];
  statements: DbExecStatement[];
}

/** `db exec`'s own errors before psql's timeouts: the transaction it opened was ended by something
 *  in the file the splitter did not see, so the envelope cannot say what was committed. */
function refineExecError(
  commandStderr: string,
  error: ErrorInfo,
  ctx: OpContext,
): ErrorInfo | undefined {
  if (commandStderr.includes(EXEC_TXN_ENDED_MARKER)) {
    return {
      ...describeError(
        'COMMAND_FAILED',
        'db exec: the transaction db exec opened was ended inside the file (a COMMIT or ROLLBACK db exec did not see), so statements before it may already be committed, dry run or not',
        {
          hint: 'Check the touched tables by hand before running anything again, and report the file: its statements were split differently by Postgres than by db exec.',
        },
      ),
      remote_exit: error.remote_exit,
      phase: 'command' as const,
    };
  }
  return refinePsqlTimeout(DB_EXEC_TIMEOUT_SEC)(commandStderr, error, ctx);
}

/** The `ROW_COUNT` echo of every statement that finished, and how the transaction ended. */
function parseExecOutput(stdout: string): { rows: Map<number, number>; done: string | null } {
  const rows = new Map<number, number>();
  let done: string | null = null;
  for (const line of stdout.split('\n')) {
    const parts = line.trim().split(' ');
    if (parts[0] === EXEC_ROWS_MARKER && parts.length === 3) {
      rows.set(Number(parts[1]), Number(parts[2]));
    } else if (parts[0] === EXEC_DONE_MARKER && parts.length === 2) {
      done = parts[1] ?? null;
    }
  }
  return { rows, done };
}

const dbExec: OpSpec<DbExecResult> = {
  group: 'db',
  name: 'exec',
  summary:
    "Governed SQL writes from a local file: one transaction as the target's write_role, per-statement row counts; --dry-run rolls back; DDL needs --allow-ddl.",
  args: [
    arg(
      'target',
      'positional',
      true,
      'pg-target name declared in targets.toml (needs write_role).',
    ),
    arg(
      'file',
      'flag',
      true,
      `Local .sql file, at most ${DB_EXEC_MAX_SQL_BYTES} bytes and ${DB_EXEC_MAX_STATEMENTS} statements; no BEGIN/COMMIT, no psql meta-commands.`,
    ),
    arg(
      'dry-run',
      'flag',
      false,
      'Runs every statement for real, reports the row counts, then ROLLBACK: not a simulation (sequences advance, rows lock, triggers fire). Needs the deploy profile and writes an audit row.',
    ),
    arg(
      'allow-ddl',
      'flag',
      false,
      'Allow CREATE/ALTER/DROP/TRUNCATE/GRANT/REVOKE/DO/CALL and SELECT ... INTO; without it they are DDL_REFUSED.',
    ),
    TIMEOUT_ARG,
  ],
  mutating: true,
  exposes: 'metadata',
  timeoutSec: DB_EXEC_TIMEOUT_SEC,
  output: { parse: parseExecOutput },
  errorData: psqlErrorData,
  refineError: refineExecError,
  hiddenArgs: DB_WRITE_ARGS,
  buildRemote: (ctx) => {
    const conn = writeConnection(ctx, 'db exec');
    const { statements } = execPlan(ctx);
    const command = buildDbExecCommand(
      conn,
      budgetSec(ctx, DB_EXEC_TIMEOUT_SEC),
      statements.map((statement) => statement.text),
      !optBool(ctx, 'dry-run', false),
    );
    const bytes = Buffer.byteLength(command, 'utf8');
    if (bytes > DB_EXEC_MAX_COMMAND_BYTES) {
      throw new OpError(
        'VALIDATION_ERROR',
        `db exec: the file's ${statements.length} statements make a ${bytes}-byte remote command once quoted; one call carries at most ${DB_EXEC_MAX_COMMAND_BYTES}; nothing ran`,
        {
          hint: 'Split the change into smaller files and run them one after the other; many statements and many quotes are what fill it.',
        },
      );
    }
    return command;
  },
  shapeError: (raw) => ({
    committed: raw.commandStderr.includes(EXEC_TXN_ENDED_MARKER) ? null : false,
    statements_ok: parseExecOutput(raw.stdout).rows.size,
  }),
  shape: (parsed, ctx) => {
    const { rows, done } = parsed as ReturnType<typeof parseExecOutput>;
    if (done === null) {
      throw new OpError(
        'PARSE_ERROR',
        'db exec: psql exited 0 but never reported the end of the transaction',
      );
    }
    const { infos } = execPlan(ctx);
    return {
      dry_run: optBool(ctx, 'dry-run', false),
      committed: done === 'committed',
      sql_sha256: sha256Hex(readExecSql(ctx)),
      tables: tablesOfStatements(infos),
      statements: infos.map((info, index) => ({
        index: index + 1,
        command: info.command,
        row_count: rows.get(index + 1) ?? null,
      })),
    };
  },
  auditFields: (ctx, stateDir) => {
    let sql: string;
    try {
      sql = readExecSql(ctx);
    } catch {
      return undefined;
    }
    let tables: string[];
    try {
      tables = tablesOfStatements(splitSqlStatements(sql).map(classifySqlStatement));
    } catch {
      tables = [];
    }
    const sha = sha256Hex(sql);
    try {
      writeSqlSideFile(stateDir, sha, sql);
    } catch (err) {
      const code = err instanceof Error && 'code' in err ? err.code : undefined;
      throw new AuditWriteError('state_dir', typeof code === 'string' ? code : undefined);
    }
    return { sqlSha256: sha, tables };
  },
};

/** This target's dump directory and the file-name prefix its dumps share. */
function backupLocation(ctx: OpContext): { dir: string; prefix: string } {
  const safe = targetName(ctx).replace(/[^A-Za-z0-9_-]/g, '_');
  return { dir: optStr(ctx, 'backup_dir', DB_BACKUP_DEFAULT_DIR), prefix: `sshepherd-${safe}-` };
}

function wholeNumber(raw: unknown): number {
  return typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
}

/** `--keep`, else the target's `backup_keep`; 1 to `DB_BACKUP_KEEP_MAX`. */
function keepCount(ctx: OpContext): number {
  const flag = ctx.args.keep;
  const value = wholeNumber(flag ?? ctx.args.backup_keep ?? String(DB_BACKUP_KEEP_DEFAULT));
  if (!Number.isInteger(value) || value < 1 || value > DB_BACKUP_KEEP_MAX) {
    throw new OpError(
      'INVALID_ARGS',
      `--keep must be a whole number of dumps from 1 to ${DB_BACKUP_KEEP_MAX}, got ${JSON.stringify(flag)}`,
    );
  }
  return value;
}

/** Marker lines `KEY rest` of the backup scripts, the last value per key and every `__PRUNED__`. */
function parseMarkerLines(stdout: string): { values: Map<string, string>; pruned: string[] } {
  const values = new Map<string, string>();
  const pruned: string[] = [];
  for (const line of stdout.split('\n')) {
    const match = /^(__[A-Z_]+__)(?: (.*))?$/.exec(line.trimEnd());
    if (match === null) {
      continue;
    }
    const [, key = '', rest = ''] = match;
    if (key === '__PRUNED__') {
      pruned.push(rest);
    } else {
      values.set(key, rest);
    }
  }
  return { values, pruned };
}

interface DbBackupResult {
  path: string;
  name: string;
  bytes: number;
  sha256: string;
  table_data_entries: number;
  kept: number;
  kept_bytes: number;
  pruned: string[];
}

const dbBackup: OpSpec<DbBackupResult> = {
  group: 'db',
  name: 'backup',
  summary:
    "pg_dump -Fc into the target's backup directory on the host; returns path, bytes, sha256 and TABLE DATA entries, then prunes this target's oldest dumps past --keep / backup_max_bytes.",
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    arg(
      'keep',
      'flag',
      false,
      `Dumps of this target to keep, 1-${DB_BACKUP_KEEP_MAX} (default backup_keep, else 7); older ones in the directory are deleted.`,
    ),
  ],
  mutating: true,
  exposes: 'metadata',
  timeoutSec: DB_BACKUP_TIMEOUT_SEC,
  output: { parse: parseMarkerLines },
  hiddenArgs: DB_WRITE_ARGS,
  buildRemote: (ctx) => {
    const conn = dbConnectionFromCtx(ctx);
    refuseUrlTarget(ctx, conn, 'db backup');
    const { dir, prefix } = backupLocation(ctx);
    const stamp = new Date()
      .toISOString()
      .replace(/[-:]/g, '')
      .replace(/\.\d+Z$/, 'Z');
    return buildDbBackupScript(conn, {
      dir,
      prefix,
      name: `${prefix}${stamp}.dump`,
      keep: keepCount(ctx),
      maxBytes: wholeNumber(ctx.args.backup_max_bytes ?? String(DB_BACKUP_MAX_BYTES_DEFAULT)),
    });
  },
  shape: (parsed, ctx) => {
    const { values, pruned } = parsed as ReturnType<typeof parseMarkerLines>;
    const fields = (values.get('__BACKUP__') ?? '').split(' ');
    if (fields.length !== 6) {
      throw new OpError('PARSE_ERROR', 'db backup: the host never reported the finished dump');
    }
    const [name = '', bytes, sha256 = '', entries, kept, keptBytes] = fields;
    return {
      path: `${backupLocation(ctx).dir}/${name}`,
      name,
      bytes: Number(bytes),
      sha256,
      table_data_entries: Number(entries),
      kept: Number(kept),
      kept_bytes: Number(keptBytes),
      pruned,
    };
  },
};

interface DbTableCountPair {
  table: string;
  source: number | null;
  restored: number | null;
}

interface DbBackupVerifyResult {
  dump: string;
  verified: boolean;
  restore_errors: number;
  tables_compared: number;
  mismatched: string[];
  throwaway_dropped: boolean;
  tables: DbTableCountPair[];
}

function readCounts(raw: string | undefined, side: string): Map<string, number> {
  const list = parseJsonArray(JSON.parse(raw === undefined || raw.length === 0 ? 'null' : raw));
  if (list.length > DB_BACKUP_VERIFY_MAX_TABLES) {
    throw new OpError(
      'OUTPUT_TOO_LARGE',
      `db backup-verify: the ${side} has more than ${DB_BACKUP_VERIFY_MAX_TABLES} tables, so it cannot be verified table by table`,
    );
  }
  const counts = new Map<string, number>();
  for (const item of list) {
    const record = readRecord(item);
    if (typeof record.table === 'string' && typeof record.count === 'number') {
      counts.set(record.table, record.count);
    }
  }
  return counts;
}

const dbBackupVerify: OpSpec<DbBackupVerifyResult> = {
  group: 'db',
  name: 'backup-verify',
  summary:
    "Restores a dump (default: this target's newest) into a throwaway database as write_role, compares every table's COUNT(*) with the source, then drops it.",
  args: [
    arg(
      'target',
      'positional',
      true,
      'pg-target name declared in targets.toml (needs write_role with CREATEDB).',
    ),
    arg(
      'dump',
      'flag',
      false,
      'Dump file name from db backup (default: the newest one of this target).',
    ),
    TIMEOUT_ARG,
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DB_BACKUP_VERIFY_TIMEOUT_SEC,
  output: { parse: parseMarkerLines },
  errorData: psqlErrorData,
  refineError: refinePsqlTimeout(DB_BACKUP_VERIFY_TIMEOUT_SEC),
  hiddenArgs: DB_WRITE_ARGS,
  buildRemote: (ctx) => {
    const conn = dbConnectionFromCtx(ctx);
    const writer = writeConnection(ctx, 'db backup-verify');
    const { dir, prefix } = backupLocation(ctx);
    const dump = optStrOrNull(ctx, 'dump');
    if (dump !== null && !new RegExp(backupNamePattern(prefix)).test(dump)) {
      throw new OpError(
        'INVALID_ARGS',
        `--dump must be a dump name db backup wrote for this target (${prefix}<YYYYMMDDTHHMMSSZ>.dump), got ${JSON.stringify(dump)}`,
      );
    }
    return buildDbBackupVerifyScript(conn, {
      dir,
      prefix,
      dump,
      throwaway: `sshepherd_verify_${Math.floor(Date.now() / 1_000)}_${randomBytes(8).toString('hex')}`,
      writeRole: writer.user,
      sessionSql: boundedSql(ctx, DB_BACKUP_VERIFY_TIMEOUT_SEC),
      maxTables: DB_BACKUP_VERIFY_MAX_TABLES,
    });
  },
  shape: (parsed, ctx) => {
    const { values } = parsed as ReturnType<typeof parseMarkerLines>;
    if (values.has('__NO_DUMP__')) {
      throw new OpError(
        'VALIDATION_ERROR',
        `db backup-verify: no dump of pg-target '${targetName(ctx)}' in its backup directory${optStrOrNull(ctx, 'dump') === null ? '' : ' under that name'}`,
        { next: `sshepherd db backup ${targetName(ctx)} --yes` },
      );
    }
    if (!values.has('__LEFTOVER__')) {
      throw new OpError('PARSE_ERROR', 'db backup-verify: the host never reported the comparison');
    }
    const source = readCounts(values.get('__SOURCE__'), 'source database');
    const restored = readCounts(values.get('__RESTORED__'), 'restored copy');
    const names = [...new Set([...source.keys(), ...restored.keys()])].sort();
    const tables = names.map((table) => ({
      table,
      source: source.get(table) ?? null,
      restored: restored.get(table) ?? null,
    }));
    const mismatched = tables
      .filter((pair) => pair.source !== pair.restored)
      .map((pair) => pair.table);
    const restoreErrors = Number(values.get('__RESTORE_ERRORS__') ?? 'NaN');
    return {
      dump: values.get('__DUMP__') ?? '',
      verified: restoreErrors === 0 && mismatched.length === 0,
      restore_errors: restoreErrors,
      tables_compared: tables.length,
      mismatched,
      throwaway_dropped: values.get('__LEFTOVER__') === '0',
      tables,
    };
  },
};

export const dbOps = [
  dbList,
  dbTables,
  dbActivity,
  dbConnections,
  dbSlow,
  dbSize,
  dbQuery,
  dbDescribe,
  dbCount,
  dbMigrations,
  dbExec,
  dbBackup,
  dbBackupVerify,
] as OpSpec[];

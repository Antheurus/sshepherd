import {
  assertNoMultiStatementSql,
  assertSelectOnly,
  assertSelfContainedSql,
  boundedSessionSql,
  buildDbMigrationsCommand,
  buildDbSlowCommand,
  buildPsqlCommand,
  countRowsSql,
  type DbConnection,
  describeTableSql,
  limitRows,
  MIGRATION_TABLES,
  MIGRATIONS_DIR_MARKER,
  MIGRATIONS_NO_DIR_MARKER,
  migrationTableRef,
  quoteIdentifier,
  statementTimeoutFor,
  wrapAsJsonAgg,
  wrapReadOnlyTxn,
} from '../db.ts';
import { describeError } from '../errors.ts';
import {
  DB_LOCK_TIMEOUT_SEC,
  DB_MIGRATIONS_COMPARE_MAX,
  DB_MIGRATIONS_LIMIT,
  DB_QUERY_MAX_ROWS,
  DB_QUERY_ROW_LIMIT,
  DB_QUERY_TIMEOUT_SEC,
  DB_TIMEOUT_SEC,
  MAX_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, optStr, optStrOrNull, readRecord, reqStr } from '../op-args.ts';
import { MASK } from '../scrub.ts';
import {
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
] as OpSpec[];

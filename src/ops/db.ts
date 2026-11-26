import {
  assertNoMultiStatementSql,
  assertSelectOnly,
  buildDbSlowCommand,
  buildPsqlCommand,
  type DbConnection,
  wrapAsJsonAgg,
  wrapReadOnlyTxn,
} from '../db.ts';
import { arg, optStr, readRecord, reqStr } from '../op-args.ts';
import { defaultTargetsPath, loadTargets } from '../targets.ts';
import type { OpContext, OpSpec } from '../types.ts';

const DB_TIMEOUT_SEC = 20;

// ---------------------------------------------------------------------------
// db
// ---------------------------------------------------------------------------

function dbConnectionFromCtx(ctx: OpContext): DbConnection {
  return {
    composeFile: optStr(ctx, 'compose_file', ''),
    service: optStr(ctx, 'service', ''),
    container: optStr(ctx, 'container', ''),
    user: reqStr(ctx, 'db_user'),
    database: reqStr(ctx, 'db_name'),
  };
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
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as DbListResult,
  runLocal: () => ({ targets: Object.keys(loadTargets(defaultTargetsPath())) }),
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
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
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
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
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
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
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
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
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
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
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

const dbQuery: OpSpec<unknown[]> = {
  group: 'db',
  name: 'query',
  summary:
    'Ad hoc read-only SQL against a pg-target — SELECT only, enforced by parser rejection + a read-only transaction wrapper.',
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    arg('sql', 'positional', true, 'SELECT statement to run.'),
  ],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) => {
    const sql = reqStr(ctx, 'sql');
    assertNoMultiStatementSql(sql);
    assertSelectOnly(sql);
    return buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(wrapAsJsonAgg(sql)));
  },
  shape: (parsed) => parseJsonArray(parsed),
};

export const dbOps = [
  dbList,
  dbTables,
  dbActivity,
  dbConnections,
  dbSlow,
  dbSize,
  dbQuery,
] as OpSpec[];

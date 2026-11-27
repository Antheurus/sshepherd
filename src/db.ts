import { Parser } from 'node-sql-parser';
import {
  DB_BACKUP_VERIFY_STALE_SEC,
  DB_LOCK_TIMEOUT_SEC,
  DB_STATEMENT_GRACE_SEC,
  DB_VERIFY_DROP_TRIES,
} from './limits.ts';
import { shellJoin, shq } from './quote.ts';
import { OpError } from './types.ts';

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
    throw new OpError(
      'VALIDATION_ERROR',
      "db query rejects multi-statement SQL: a single SELECT statement, no ';'",
    );
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
      throw new OpError(
        'VALIDATION_ERROR',
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
  return `BEGIN TRANSACTION READ ONLY;\n${trimmed}\n;\nROLLBACK;`;
}

/** Wraps arbitrary SQL so psql's `-t -A` output is exactly one JSON value (array), never a raw table.
 *  The SQL sits on its own lines, so a trailing `--` comment in it ends at the newline after it. */
export function wrapAsJsonAgg(sql: string): string {
  const trimmed = sql.trim().replace(/;+\s*$/, '');
  return `SELECT json_agg(t) FROM (\n${trimmed}\n) t`;
}

const IDENT_START = /[A-Za-z_\u0080-\uffff]/;
const IDENT_CONT = /[A-Za-z0-9_$\u0080-\uffff]/;
const DOLLAR_TAG = /^\$(?:[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*)?\$/;

/** Index just past the quote that closes a string or quoted identifier opened before `from`;
 *  -1 when it never closes. A doubled quote is one quote; `backslash` (E'' strings) also lets a
 *  backslash escape the next character. */
function closingQuote(sql: string, from: number, quote: string, backslash: boolean): number {
  for (let i = from; i < sql.length; i += 1) {
    const c = sql[i];
    if (backslash && c === '\\') {
      i += 1;
    } else if (c === quote) {
      if (sql[i + 1] !== quote) {
        return i + 1;
      }
      i += 1;
    }
  }
  return -1;
}

/** Index of the quote that continues a string constant ending just before `from`, or -1. This is
 *  Postgres's `quotecontinue`: whitespace holding at least one newline (`\n` or `\r`), where a `--`
 *  comment counts as whitespace up to its newline, and then a quote. A block comment does not. */
function continuationQuote(sql: string, from: number): number {
  let newline = false;
  let i = from;
  while (i < sql.length) {
    const c = sql[i];
    if (c === '\n' || c === '\r') {
      newline = true;
      i += 1;
    } else if (c === ' ' || c === '\t' || c === '\f' || c === '\v') {
      i += 1;
    } else if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n' && sql[i] !== '\r') {
        i += 1;
      }
    } else {
      break;
    }
  }
  return newline && sql[i] === "'" ? i : -1;
}

/** Index just past an E'' string opened before `from`, or -1 when it never closes. A segment that
 *  continues it on a later line is still an E'' segment to Postgres, backslash escapes included. */
function closingEString(sql: string, from: number): number {
  let end = closingQuote(sql, from, "'", true);
  while (end !== -1) {
    const next = continuationQuote(sql, end);
    if (next === -1) {
      return end;
    }
    end = closingQuote(sql, next + 1, "'", true);
  }
  return -1;
}

/** Index just past the `*\/` that closes the block comment opened at `from`; -1 when it never
 *  closes. Postgres nests block comments. */
function closingComment(sql: string, from: number): number {
  let level = 1;
  let i = from + 2;
  while (i < sql.length) {
    if (sql.startsWith('/*', i)) {
      level += 1;
      i += 2;
    } else if (sql.startsWith('*/', i)) {
      level -= 1;
      i += 2;
      if (level === 0) {
        return i;
      }
    } else {
      i += 1;
    }
  }
  return -1;
}

function unwrappableSql(why: string): OpError {
  return new OpError(
    'VALIDATION_ERROR',
    `db query: ${why}, so it cannot run inside the row limit`,
    {
      hint: 'Pass one complete SELECT: every ( closed inside it, and no string, quoted name or /* comment left open.',
    },
  );
}

/**
 * Security guard for `db query`'s free-text `sql` arg: it runs inside sshepherd's wrapper
 * (`FROM (\n<sql>\n) sshepherd_q LIMIT n`), so it must not be able to close that wrapper's
 * parenthesis itself (`... FROM big) sshepherd_q) t, (SELECT (SELECT 1` aggregates every row past
 * the limit) or leave a string or comment open for the wrapper's tail to fall into. Scanned with
 * Postgres's lexical rules (standard strings, E'' escapes carried into the segments that continue
 * an E'' string on later lines, dollar quotes, quoted identifiers, `--` comments ending at \n or
 * \r, nested block comments), every parenthesis outside them must
 * close inside the caller's text. `boundedSessionSql` pins `standard_conforming_strings` on, so a
 * backslash in a plain '' string is a character to the server exactly as it is here.
 */
export function assertSelfContainedSql(sql: string): void {
  let depth = 0;
  let i = 0;
  while (i < sql.length) {
    const c = sql[i] as string;
    if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n' && sql[i] !== '\r') {
        i += 1;
      }
    } else if (c === '/' && sql[i + 1] === '*') {
      i = closingComment(sql, i);
      if (i === -1) {
        throw unwrappableSql('the SQL ends inside a /* comment');
      }
    } else if (c === "'" || c === '"') {
      i = closingQuote(sql, i + 1, c, false);
      if (i === -1) {
        throw unwrappableSql(`the SQL leaves a ${c === '"' ? 'quoted name' : 'string'} open`);
      }
    } else if (IDENT_START.test(c)) {
      const start = i;
      while (i < sql.length && IDENT_CONT.test(sql[i] as string)) {
        i += 1;
      }
      if (i - start === 1 && (c === 'e' || c === 'E') && sql[i] === "'") {
        i = closingEString(sql, i + 1);
        if (i === -1) {
          throw unwrappableSql('the SQL leaves a string open');
        }
      }
    } else if (c === '$') {
      const tag = DOLLAR_TAG.exec(sql.slice(i))?.[0];
      if (tag === undefined) {
        i += 1;
      } else {
        const end = sql.indexOf(tag, i + tag.length);
        if (end === -1) {
          throw unwrappableSql('the SQL leaves a dollar-quoted string open');
        }
        i = end + tag.length;
      }
    } else {
      if (c === '(') {
        depth += 1;
      } else if (c === ')') {
        depth -= 1;
        if (depth < 0) {
          throw unwrappableSql('the SQL closes a parenthesis it never opened');
        }
      }
      i += 1;
    }
  }
  if (depth !== 0) {
    throw unwrappableSql('the SQL leaves a parenthesis open');
  }
}

export interface DbConnection {
  /** `container` when empty: the kind targets.toml defaulted to before kinds existed. */
  kind?: 'container' | 'container-env' | 'host' | '';
  composeFile: string;
  service: string;
  container: string;
  user: string;
  database: string;
  envKey?: string;
  psqlContainer?: string;
  sudoUser?: string;
  pgHost?: string;
  pgPort?: string;
}

function execPrefix(conn: DbConnection): string[] {
  if (conn.composeFile.length > 0 && conn.service.length > 0) {
    return ['docker', 'compose', '-f', conn.composeFile, 'exec', '-T', conn.service];
  }
  if (conn.container.length > 0) {
    return ['docker', 'exec', '-i', conn.container];
  }
  throw new OpError(
    'VALIDATION_ERROR',
    'db: connection needs either {compose_file, service} or {container}',
  );
}

const PSQL_FLAGS = ['-v', 'ON_ERROR_STOP=1', '-qAt'];

/** Each SQL buffer is its own `-c`, so psql sends it as its own simple-Query message: a `SET`
 *  in one buffer is in force for the timer of the next on every Postgres version. */
function commandArgs(sql: string[]): string[] {
  return sql.flatMap((buffer) => ['-c', buffer]);
}

/**
 * Turns a `postgres://` / `postgresql://` URL on stdin into `PG*` assignments a shell `eval`s, so
 * libpq reads the connection from its environment and the URL is never an argv entry (`ps` shows
 * argv). Userinfo, database and query values are percent-decoded; every value is single-quoted.
 * The URL is never echoed, not even on a parse failure.
 */
const URL_TO_PG_ENV_AWK = String.raw`
function hex(c) { return index("0123456789abcdef", tolower(c)) - 1 }
function dec(s,   out, i, c, a, b) {
  out = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "%" && i + 2 <= length(s)) {
      a = hex(substr(s, i + 1, 1)); b = hex(substr(s, i + 2, 1))
      if (a >= 0 && b >= 0) { out = out sprintf("%c", a * 16 + b); i += 2; continue }
    }
    out = out c
  }
  return out
}
function q(s,   out, i, c) {
  out = "\047"
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\047") out = out "\047\134\047\047"; else out = out c
  }
  return out "\047"
}
function put(name, value) { printf "%s=%s; export %s\n", name, q(value), name }
{ url = url $0 }
END {
  if (url !~ /^postgres(ql)?:\/\//) {
    print "sshepherd: the env var does not hold a postgres:// URL" > "/dev/stderr"
    exit 3
  }
  sub(/^postgres(ql)?:\/\//, "", url)
  query = ""
  p = index(url, "?")
  if (p > 0) { query = substr(url, p + 1); url = substr(url, 1, p - 1) }
  at = 0
  for (i = length(url); i > 0; i--) if (substr(url, i, 1) == "@") { at = i; break }
  if (at > 0) {
    auth = substr(url, 1, at - 1); url = substr(url, at + 1)
    p = index(auth, ":")
    if (p > 0) { put("PGUSER", dec(substr(auth, 1, p - 1))); put("PGPASSWORD", dec(substr(auth, p + 1))) }
    else if (auth != "") put("PGUSER", dec(auth))
  }
  p = index(url, "/")
  if (p > 0) { db = substr(url, p + 1); url = substr(url, 1, p - 1); if (db != "") put("PGDATABASE", dec(db)) }
  n = split(url, specs, ","); hosts = ""; ports = ""; anyport = 0
  for (i = 1; i <= n; i++) {
    h = specs[i]; port = ""
    if (substr(h, 1, 1) == "[") {
      e = index(h, "]"); rest = substr(h, e + 1); h = substr(h, 2, e - 2)
      if (substr(rest, 1, 1) == ":") port = substr(rest, 2)
    } else {
      c = 0
      for (j = length(h); j > 0; j--) if (substr(h, j, 1) == ":") { c = j; break }
      if (c > 0) { port = substr(h, c + 1); h = substr(h, 1, c - 1) }
    }
    if (port != "") anyport = 1; else port = "5432"
    hosts = hosts (i > 1 ? "," : "") dec(h); ports = ports (i > 1 ? "," : "") port
  }
  if (hosts !~ /^,*$/) put("PGHOST", hosts)
  if (anyport) put("PGPORT", ports)
  env["host"] = "PGHOST"; env["port"] = "PGPORT"; env["user"] = "PGUSER"
  env["password"] = "PGPASSWORD"; env["dbname"] = "PGDATABASE"; env["sslmode"] = "PGSSLMODE"
  env["sslrootcert"] = "PGSSLROOTCERT"; env["sslcert"] = "PGSSLCERT"; env["sslkey"] = "PGSSLKEY"
  env["application_name"] = "PGAPPNAME"; env["connect_timeout"] = "PGCONNECT_TIMEOUT"
  env["options"] = "PGOPTIONS"; env["target_session_attrs"] = "PGTARGETSESSIONATTRS"
  env["channel_binding"] = "PGCHANNELBINDING"; env["gssencmode"] = "PGGSSENCMODE"
  n = split(query, pairs, "&")
  for (i = 1; i <= n; i++) {
    p = index(pairs[i], "=")
    if (p > 0) { k = dec(substr(pairs[i], 1, p - 1)); if (k in env) put(env[k], dec(substr(pairs[i], p + 1))) }
  }
}
`;

/** Masks the URL's own host(s) and user in psql's stderr as `<db-host>`/`<db-user>`, read from the
 *  decoded `PG*` environment (never argv): a connect error names both (`connection to server at
 *  "<host>"`, `for user "<user>"`), and they are known only inside the container — the local scrubber
 *  could never mask what it was never told. A match counts only as a whole name. */
const MASK_PG_IDENTITY_AWK = `
function word(c) { return c ~ /[A-Za-z0-9_.-]/ }
function lit(s, v, m,   out, i, n) {
  if (v == "") return s
  out = ""; n = length(v)
  while ((i = index(s, v)) > 0) {
    if ((i == 1 || !word(substr(s, i - 1, 1))) && !word(substr(s, i + n, 1))) out = out substr(s, 1, i - 1) m
    else out = out substr(s, 1, i - 1 + n)
    s = substr(s, i + n)
  }
  return out s
}
{
  line = $0
  n = split(ENVIRON["PGHOST"], hosts, ",")
  for (k = 1; k <= n; k++) line = lit(line, hosts[k], "<db-host>")
  print lit(line, ENVIRON["PGUSER"], "<db-user>")
}
`;

/** The shell that runs psql from a URL held in `$<varName>`: decode it into `PG*`, drop every
 *  copy of the URL, then run psql with the SQL buffers from its own argv (`"$@"`), its stdout
 *  straight through and its stderr held back until `MASK_PG_IDENTITY_AWK` has masked it. */
export function envUrlPsqlScript(varName: string): string {
  return [
    `u=\${${varName}:-}`,
    `[ -n "$u" ] || { echo "sshepherd: ${varName} is not set in the container" >&2; exit 3; }`,
    'unset PGHOST PGHOSTADDR PGPORT PGUSER PGPASSWORD PGDATABASE PGSERVICE PGSSLMODE PGOPTIONS',
    `pg_env=$(printf '%s' "$u" | awk '${URL_TO_PG_ENV_AWK}') || exit 3`,
    `unset u ${varName === 'SSHEPHERD_PGURL' ? 'SSHEPHERD_PGURL' : ''}`.trimEnd(),
    'eval "$pg_env"',
    'unset pg_env',
    'exec 3>&1',
    `err=$(psql ${PSQL_FLAGS.join(' ')} "$@" 2>&1 1>&3)`,
    'rc=$?',
    'exec 3>&-',
    `[ -z "$err" ] || printf '%s\\n' "$err" | awk '${MASK_PG_IDENTITY_AWK}' >&2`,
    'exit $rc',
  ].join('\n');
}

/** `container-env` with a separate `psql_container`: the URL is read out of the app container into
 *  a shell variable on the host and handed to the psql container through `docker exec -e NAME`
 *  (the value comes from the environment, never from argv). */
const ENV_URL_VIA_SCRIPT = [
  'c=$1 k=$2 v=$3 script=$4',
  'shift 4',
  'SSHEPHERD_PGURL=$(docker exec "$c" printenv "$k") || { echo "sshepherd: $k is not set in the env container" >&2; exit 3; }',
  'export SSHEPHERD_PGURL',
  'exec docker exec -i -e SSHEPHERD_PGURL "$v" sh -c "$script" sh "$@"',
].join('\n');

function envUrlCommand(conn: DbConnection, sql: string[]): string {
  const envKey = conn.envKey && conn.envKey.length > 0 ? conn.envKey : 'DATABASE_URL';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envKey) || conn.container.length === 0) {
    throw new OpError('VALIDATION_ERROR', 'db: a container-env target needs container and env_key');
  }
  const via = conn.psqlContainer ?? '';
  if (via.length === 0 || via === conn.container) {
    return shellJoin([
      'docker',
      'exec',
      '-i',
      conn.container,
      'sh',
      '-c',
      envUrlPsqlScript(envKey),
      'sh',
      ...commandArgs(sql),
    ]);
  }
  return shellJoin([
    'sh',
    '-c',
    ENV_URL_VIA_SCRIPT,
    'sh',
    conn.container,
    envKey,
    via,
    envUrlPsqlScript('SSHEPHERD_PGURL'),
    ...commandArgs(sql),
  ]);
}

function hostCommand(conn: DbConnection, sql: string[]): string {
  const sudo = conn.sudoUser && conn.sudoUser.length > 0 ? ['sudo', '-n', '-u', conn.sudoUser] : [];
  const host = conn.pgHost && conn.pgHost.length > 0 ? ['-h', conn.pgHost] : [];
  const port = conn.pgPort && conn.pgPort.length > 0 ? ['-p', conn.pgPort] : [];
  return shellJoin([
    ...sudo,
    'psql',
    ...host,
    ...port,
    '-U',
    conn.user,
    '-d',
    conn.database,
    ...PSQL_FLAGS,
    ...commandArgs(sql),
  ]);
}

/**
 * Builds the full remote command that runs psql non-interactively over one or more `-c` SQL
 * buffers, reached per the target's kind (see targets.ts): `docker (compose) exec` into the db
 * container (the default), psql on the host, or psql fed from a container's env URL. `-qAt` =
 * quiet (suppresses the BEGIN/SET/ROLLBACK command-completion tags the wrappers add, leaving only
 * the SELECT's tuple output), unaligned, tuples-only — one JSON value per call, trivial to parse.
 */
export function buildPsqlCommand(conn: DbConnection, ...sql: string[]): string {
  if (conn.kind === 'container-env') {
    return envUrlCommand(conn, sql);
  }
  if (conn.kind === 'host') {
    return hostCommand(conn, sql);
  }
  return shellJoin([
    ...execPrefix(conn),
    'psql',
    '-U',
    conn.user,
    '-d',
    conn.database,
    ...PSQL_FLAGS,
    ...commandArgs(sql),
  ]);
}

/** The `statement_timeout` for an ssh budget: the budget less `DB_STATEMENT_GRACE_SEC`, or half of
 *  a budget too short for the full grace, so the database's own cancel always fires first. */
export function statementTimeoutFor(budgetSec: number): number {
  return Math.max(1, budgetSec - Math.min(DB_STATEMENT_GRACE_SEC, Math.floor(budgetSec / 2)));
}

/** The first psql buffer of every bounded read: session limits set in their own message, so the
 *  next buffer's statement runs under them. A statement cannot lift its own timer — Postgres arms
 *  it when the statement starts. */
export function boundedSessionSql(statementTimeoutSec: number): string {
  return `SET statement_timeout = '${statementTimeoutSec}s'; SET lock_timeout = '${DB_LOCK_TIMEOUT_SEC}s'; SET standard_conforming_strings = on`;
}

/** At most `limit + 1` rows of the caller's SELECT: the extra row is how `truncated` is known
 *  without a second count query. */
export function limitRows(sql: string, limit: number): string {
  const trimmed = sql.trim().replace(/;+\s*$/, '');
  return `SELECT * FROM (\n${trimmed}\n) sshepherd_q LIMIT ${limit + 1}`;
}

const IDENT_PART = /^(?:[A-Za-z_][A-Za-z0-9_$]*|"[^"]+")$/;

/** A `table` / `schema.table` / column argument as a quoted SQL identifier: an unquoted part folds
 *  to lower case as Postgres would, a `"Quoted"` part is kept exactly. Anything else is refused, so
 *  the name never needs escaping inside the SQL sshepherd builds. */
export function quoteIdentifier(raw: string, what: string, maxParts = 2): string {
  const parts = raw.match(/"[^"]*"|[^.]+/g) ?? [];
  const valid =
    parts.length > 0 &&
    parts.length <= maxParts &&
    parts.join('.') === raw &&
    parts.every((part) => IDENT_PART.test(part));
  if (!valid) {
    throw new OpError(
      'INVALID_ARGS',
      `${what} must be a name or schema.name of letters, digits, _ and $ (or a "Quoted" part), got ${JSON.stringify(raw)}`,
    );
  }
  return parts.map((part) => (part.startsWith('"') ? part : `"${part.toLowerCase()}"`)).join('.');
}

/** A value as a SQL string literal: `standard_conforming_strings` (on since 9.1) makes doubling
 *  `'` a complete escape; Postgres coerces the literal to the column's type. */
export function quoteLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

export function describeTableSql(table: string): string {
  const rel = `to_regclass(${quoteLiteral(table)})`;
  return (
    'SELECT json_build_object(' +
    `'found', ${rel} IS NOT NULL, ` +
    `'schema', (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = ${rel}), ` +
    `'table', (SELECT c.relname FROM pg_class c WHERE c.oid = ${rel}), ` +
    "'columns', (SELECT coalesce(json_agg(json_build_object('name', a.attname, " +
    "'type', format_type(a.atttypid, a.atttypmod), 'nullable', NOT a.attnotnull, " +
    "'default', pg_get_expr(d.adbin, d.adrelid)) ORDER BY a.attnum), '[]'::json) " +
    'FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum ' +
    `WHERE a.attrelid = ${rel} AND a.attnum > 0 AND NOT a.attisdropped), ` +
    "'indexes', (SELECT coalesce(json_agg(json_build_object('name', ic.relname, " +
    "'unique', i.indisunique, 'primary', i.indisprimary, 'definition', pg_get_indexdef(i.indexrelid)) " +
    "ORDER BY ic.relname), '[]'::json) FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid " +
    `WHERE i.indrelid = ${rel}), ` +
    "'foreign_keys', (SELECT coalesce(json_agg(json_build_object('name', con.conname, " +
    "'columns', (SELECT json_agg(a.attname ORDER BY k.ord) FROM unnest(con.conkey) WITH ORDINALITY k(attnum, ord) " +
    'JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum), ' +
    "'references_table', con.confrelid::regclass::text, " +
    "'references_columns', (SELECT json_agg(a.attname ORDER BY k.ord) FROM unnest(con.confkey) WITH ORDINALITY k(attnum, ord) " +
    'JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum), ' +
    "'definition', pg_get_constraintdef(con.oid)) ORDER BY con.conname), '[]'::json) " +
    `FROM pg_constraint con WHERE con.conrelid = ${rel} AND con.contype = 'f'))`
  );
}

export function countRowsSql(
  table: string,
  whereEq: { column: string; value: string } | null,
): string {
  const where = whereEq === null ? '' : ` WHERE ${whereEq.column} = ${quoteLiteral(whereEq.value)}`;
  return `SELECT json_build_object('count', count(*)) FROM ${table}${where}`;
}

interface MigrationSource {
  framework: string;
  table: string;
  /** Columns yielding `name` and `applied_at` (null when the table keeps no time). */
  columns: string;
  order: string;
}

/** The migrations tables of the common frameworks, the columns each keeps for a name and a time. */
const MIGRATION_SOURCES: MigrationSource[] = [
  {
    framework: 'prisma',
    table: '_prisma_migrations',
    columns: 'migration_name AS name, finished_at AS applied_at',
    order: 'started_at DESC',
  },
  {
    framework: 'knex',
    table: 'knex_migrations',
    columns: 'name, migration_time AS applied_at',
    order: 'id DESC',
  },
  {
    framework: 'typeorm',
    table: 'migrations_typeorm',
    columns: 'name, to_timestamp("timestamp" / 1000.0) AS applied_at',
    order: 'id DESC',
  },
  {
    framework: 'rails',
    table: 'schema_migrations',
    columns: 'version::text AS name, NULL::timestamptz AS applied_at',
    order: 'version DESC',
  },
  {
    framework: 'laravel',
    table: 'migrations',
    columns: 'migration AS name, NULL::timestamptz AS applied_at',
    order: 'id DESC',
  },
];

export const MIGRATION_FRAMEWORKS = MIGRATION_SOURCES.map((source) => source.framework);
export const MIGRATION_TABLES = MIGRATION_SOURCES.map((source) => source.table);

/** Which framework's table to read, and as which quoted relation. */
export interface MigrationTableRef {
  framework: string;
  relation: string;
}

/** `--table <name>` (validated by `quoteIdentifier`): the framework whose table it is, matched by
 *  its last part, so `app.schema_migrations` reads a rails table outside the search path. */
export function migrationTableRef(quoted: string): MigrationTableRef | null {
  const last = quoted.slice(quoted.lastIndexOf('"', quoted.length - 2) + 1, -1);
  const source = MIGRATION_SOURCES.find((entry) => entry.table === last);
  return source === undefined ? null : { framework: source.framework, relation: quoted };
}

function sourceFor(framework: string): MigrationSource {
  const source = MIGRATION_SOURCES.find((entry) => entry.framework === framework);
  if (source === undefined) {
    throw new OpError('INTERNAL_ERROR', `db migrations: no source for '${framework}'`);
  }
  return source;
}

function defaultRefs(): MigrationTableRef[] {
  return MIGRATION_SOURCES.map((source) => ({
    framework: source.framework,
    relation: `"${source.table}"`,
  }));
}

/** Which candidate tables exist, as space-separated framework names (`to_regclass` is NULL for a
 *  missing one, so nothing here references a table that may be absent). */
export function migrationTablesPresentSql(refs: MigrationTableRef[] = defaultRefs()): string {
  const values = refs
    .map((ref) => `(${quoteLiteral(ref.framework)}, ${quoteLiteral(ref.relation)})`)
    .join(', ');
  return `SELECT coalesce(string_agg(f, ' '), '') FROM (VALUES ${values}) v(f, t) WHERE to_regclass(t) IS NOT NULL`;
}

/** One framework's applied migrations, newest first, as one JSON object; with `namesLimit`, also
 *  every applied name up to that many plus one, for the `--dir` comparison. */
export function migrationsSql(
  framework: string,
  limit: number,
  relation = `"${sourceFor(framework).table}"`,
  namesLimit: number | null = null,
): string {
  const source = sourceFor(framework);
  const ordered = `SELECT ${source.columns} FROM ${relation} ORDER BY ${source.order}`;
  const names =
    namesLimit === null
      ? ''
      : `, 'names', (SELECT coalesce(json_agg(a.name), '[]'::json) FROM (SELECT name FROM (${ordered}) s LIMIT ${namesLimit + 1}) a)`;
  return (
    `SELECT json_build_object('framework', ${quoteLiteral(source.framework)}, 'table', ${quoteLiteral(relation.replaceAll('"', ''))}, ` +
    "'migrations', coalesce(json_agg(json_build_object('name', m.name, 'applied_at', m.applied_at)), '[]'::json)" +
    `${names}) FROM (SELECT name, applied_at FROM (${ordered}) s LIMIT ${limit}) m`
  );
}

export const MIGRATIONS_DIR_MARKER = '__DIR__';
export const MIGRATIONS_NO_DIR_MARKER = '__NO_DIR__';

export interface MigrationsCommandOptions {
  /** `--table`: read only this one. */
  table: MigrationTableRef | null;
  /** `--dir`: list this remote directory after the tables, for the pending comparison. */
  dir: string | null;
  /** Names and entries read for the comparison (one more says it was cut). */
  compareMax: number;
}

/**
 * `db migrations`: one remote shell — the first psql call lists which migrations tables exist,
 * then one bounded call per present table, joined into a JSON array; with `--dir`, a marker line
 * and the directory's entry names follow. Each psql call is built by `buildPsqlCommand`, so every
 * target kind works the same way.
 */
export function buildDbMigrationsCommand(
  conn: DbConnection,
  sessionSql: string,
  wrap: (sql: string) => string,
  limit: number,
  options: MigrationsCommandOptions = { table: null, dir: null, compareMax: 0 },
): string {
  const refs = options.table === null ? defaultRefs() : [options.table];
  const namesLimit = options.dir === null ? null : options.compareMax;
  const lines = [
    `present=$(${buildPsqlCommand(conn, sessionSql, wrap(migrationTablesPresentSql(refs)))}) || exit $?`,
    "printf '['",
    "sep=''",
    'for framework in $present; do',
    '  case "$framework" in',
  ];
  for (const ref of refs) {
    const sql = migrationsSql(ref.framework, limit, ref.relation, namesLimit);
    lines.push(
      `    ${ref.framework}) out=$(${buildPsqlCommand(conn, sessionSql, wrap(sql))}) || exit $? ;;`,
    );
  }
  lines.push(
    '    *) continue ;;',
    '  esac',
    `  printf '%s%s' "$sep" "$out"`,
    "  sep=','",
    'done',
    "printf ']'",
  );
  if (options.dir !== null) {
    lines.push(
      `d=${shq(options.dir)}`,
      `printf '\\n%s\\n' ${MIGRATIONS_DIR_MARKER}`,
      `if [ -d "$d" ]; then ls -1A -- "$d" | head -n ${options.compareMax + 1}; else echo ${MIGRATIONS_NO_DIR_MARKER}; fi`,
    );
  }
  return shellJoin(['sh', '-c', lines.join('\n')]);
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

/** One lexical token of a `db exec` statement: a word (unquoted name or keyword, upper-cased in
 *  `upper`), a "quoted" name, a string or dollar-quoted constant, a number, or one punctuation
 *  character. Comments and whitespace are not tokens. `depth` is the parenthesis depth it sits at. */
interface SqlToken {
  kind: 'word' | 'ident' | 'string' | 'number' | 'punct';
  text: string;
  upper: string;
  start: number;
  depth: number;
}

function unscannableSql(why: string): OpError {
  return new OpError('VALIDATION_ERROR', `db exec: ${why}, so it cannot be split into statements`, {
    hint: 'Close every string, quoted name, dollar quote and /* comment in the file.',
  });
}

/** Postgres's lexical rules as `assertSelfContainedSql` reads them (standard strings, E'' escapes
 *  with their continuation lines, dollar quotes, quoted names, `--` and nested block comments),
 *  emitting tokens instead of only tracking depth. */
function scanSql(sql: string): SqlToken[] {
  const tokens: SqlToken[] = [];
  let depth = 0;
  let i = 0;
  const push = (kind: SqlToken['kind'], start: number, end: number): void => {
    const text = sql.slice(start, end);
    tokens.push({ kind, text, upper: text.toUpperCase(), start, depth });
  };
  while (i < sql.length) {
    const c = sql[i] as string;
    const start = i;
    if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n' && sql[i] !== '\r') {
        i += 1;
      }
    } else if (c === '/' && sql[i + 1] === '*') {
      i = closingComment(sql, i);
      if (i === -1) {
        throw unscannableSql('the SQL ends inside a /* comment');
      }
    } else if (c === "'" || c === '"') {
      i = closingQuote(sql, i + 1, c, false);
      if (i === -1) {
        throw unscannableSql(`the SQL leaves a ${c === '"' ? 'quoted name' : 'string'} open`);
      }
      push(c === '"' ? 'ident' : 'string', start, i);
    } else if (IDENT_START.test(c)) {
      while (i < sql.length && IDENT_CONT.test(sql[i] as string)) {
        i += 1;
      }
      if (i - start === 1 && (c === 'e' || c === 'E') && sql[i] === "'") {
        i = closingEString(sql, i + 1);
        if (i === -1) {
          throw unscannableSql('the SQL leaves a string open');
        }
        push('string', start, i);
      } else if (i - start === 1 && (c === 'u' || c === 'U') && sql.startsWith('&"', i)) {
        i = closingQuote(sql, i + 2, '"', false);
        if (i === -1) {
          throw unscannableSql('the SQL leaves a quoted name open');
        }
        push('ident', start, i);
      } else {
        push('word', start, i);
      }
    } else if (c === '$' && DOLLAR_TAG.test(sql.slice(i))) {
      const tag = DOLLAR_TAG.exec(sql.slice(i))?.[0] ?? '$$';
      const end = sql.indexOf(tag, i + tag.length);
      if (end === -1) {
        throw unscannableSql('the SQL leaves a dollar-quoted string open');
      }
      i = end + tag.length;
      push('string', start, i);
    } else if (/[0-9]/.test(c)) {
      while (i < sql.length && /[0-9.]/.test(sql[i] as string)) {
        i += 1;
      }
      push('number', start, i);
    } else if (/\s/.test(c)) {
      i += 1;
    } else {
      if (c === ')') {
        depth = Math.max(0, depth - 1);
      }
      push('punct', start, i + 1);
      if (c === '(') {
        depth += 1;
      }
      i += 1;
    }
  }
  return tokens;
}

/** One statement of a `db exec` file: its text exactly as written (trimmed), and its tokens. */
export interface SqlStatement {
  text: string;
  tokens: SqlToken[];
}

/** Splits a change file at every `;` outside strings, quoted names, dollar quotes and comments.
 *  A piece holding only comments or whitespace is not a statement. */
export function splitSqlStatements(sql: string): SqlStatement[] {
  const statements: SqlStatement[] = [];
  let pieceStart = 0;
  let pieceTokens: SqlToken[] = [];
  const close = (end: number): void => {
    if (pieceTokens.length > 0) {
      statements.push({ text: sql.slice(pieceStart, end).trim(), tokens: pieceTokens });
    }
    pieceTokens = [];
  };
  for (const token of scanSql(sql)) {
    if (token.kind === 'punct' && token.text === ';') {
      close(token.start);
      pieceStart = token.start + 1;
    } else {
      pieceTokens.push(token);
    }
  }
  close(sql.length);
  return statements;
}

/** Statements that change the schema, privileges or run opaque code, refused without --allow-ddl. */
const DDL_VERBS = new Set([
  'CREATE',
  'ALTER',
  'DROP',
  'TRUNCATE',
  'DO',
  'CALL',
  'GRANT',
  'REVOKE',
  'COMMENT',
  'SECURITY',
  'REINDEX',
  'CLUSTER',
  'REFRESH',
  'IMPORT',
  'LOAD',
  'REASSIGN',
]);

/** Transaction control: `db exec` owns the one transaction, so a file never opens, ends or splits it. */
const TRANSACTION_VERBS = new Set([
  'BEGIN',
  'START',
  'COMMIT',
  'END',
  'ROLLBACK',
  'ABORT',
  'SAVEPOINT',
  'RELEASE',
]);

/** Session settings the file must not change: the login role, and the timers sshepherd set. */
const GUARDED_SETTINGS = new Set([
  'role',
  'session',
  'all',
  'statement_timeout',
  'lock_timeout',
  'idle_in_transaction_session_timeout',
  'transaction_timeout',
]);

/** Settings that decide how Postgres reads the bytes of a statement, i.e. where it ends:
 *  `standard_conforming_strings` (whether `\` escapes inside '' strings), `client_encoding` (bytes
 *  are converted before lexing, so a multibyte character in SJIS/BIG5/GBK can swallow a following
 *  backslash; `SET NAMES` is its alias), and `backslash_quote` / `escape_string_warning` (read by
 *  the lexer on every `\'`). `splitSqlStatements` lexes with all four at the values
 *  `EXEC_SESSION_PIN_SQL` pins, so no statement may change them, in any spelling. */
const SCANNER_SETTINGS = new Set([
  'standard_conforming_strings',
  'client_encoding',
  'names',
  'backslash_quote',
  'escape_string_warning',
]);

const TABLE_KEYWORDS = new Set(['FROM', 'JOIN', 'INTO', 'UPDATE', 'TABLE', 'TRUNCATE', 'USING']);
const LIST_KEYWORDS = new Set(['FROM', 'TABLE', 'TRUNCATE']);
const SKIP_BEFORE_NAME = new Set(['ONLY', 'IF', 'NOT', 'EXISTS', 'TABLE', 'LATERAL']);
const NOT_A_TABLE = new Set(['SELECT', 'VALUES', 'LATERAL', 'WITH', 'TABLE', 'ROWS', 'ALL', 'SET']);

/** What `classifySqlStatement` reads off one statement. */
export interface StatementInfo {
  /** The statement's verb (`INSERT`, `UPDATE`, `DROP`, ...), after any `EXPLAIN [options]`. */
  command: string;
  /** Changes the schema or privileges, or runs opaque code: needs `--allow-ddl`. */
  ddl: boolean;
  /** Why `db exec` refuses it outright, whatever the flags; null when it may run. */
  refused: string | null;
  /** Tables it names, as `schema.table` or `table` (unquoted parts lower-cased). */
  tables: string[];
}

const nameText = (token: SqlToken): string =>
  token.kind === 'ident' ? token.text : token.text.toLowerCase();

/** Index just past the `)` closing the `(` at `open`, read off the tokens' depth. */
function afterParens(tokens: SqlToken[], open: number): number {
  const depth = tokens[open]?.depth ?? 0;
  for (let k = open + 1; k < tokens.length; k += 1) {
    if (tokens[k]?.text === ')' && tokens[k]?.depth === depth) {
      return k + 1;
    }
  }
  return tokens.length;
}

/** Names a `WITH` clause defines (`name [(cols)] AS [NOT] [MATERIALIZED] (...)`), at any depth:
 *  inside that statement they are not tables. */
function cteNames(tokens: SqlToken[]): Set<string> {
  const names = new Set<string>();
  tokens.forEach((token, i) => {
    if (token.kind !== 'word' || token.upper !== 'WITH') {
      return;
    }
    let j = tokens[i + 1]?.upper === 'RECURSIVE' ? i + 2 : i + 1;
    for (;;) {
      const name = tokens[j];
      if (name === undefined || (name.kind !== 'word' && name.kind !== 'ident')) {
        return;
      }
      j += 1;
      if (tokens[j]?.text === '(') {
        j = afterParens(tokens, j);
      }
      if (tokens[j]?.kind !== 'word' || tokens[j]?.upper !== 'AS') {
        return;
      }
      j += 1;
      while (['NOT', 'MATERIALIZED'].includes(tokens[j]?.upper ?? '')) {
        j += 1;
      }
      if (tokens[j]?.text !== '(') {
        return;
      }
      names.add(nameText(name));
      j = afterParens(tokens, j);
      if (tokens[j]?.text !== ',') {
        return;
      }
      j += 1;
    }
  });
  return names;
}

/** The table names after FROM/JOIN/INTO/UPDATE/TABLE/TRUNCATE/USING (and a comma list after
 *  FROM/TABLE/TRUNCATE, read past aliases, column lists, subqueries and function calls); a name
 *  followed by `(` after FROM/JOIN/USING is a function, not a table, and a CTE name is not one. */
function tablesOf(tokens: SqlToken[]): string[] {
  const tables: string[] = [];
  const isName = (token: SqlToken | undefined): token is SqlToken =>
    token !== undefined &&
    (token.kind === 'ident' || (token.kind === 'word' && !NOT_A_TABLE.has(token.upper)));
  for (let i = 0; i < tokens.length; i += 1) {
    const keyword = tokens[i] as SqlToken;
    if (keyword.kind !== 'word' || !TABLE_KEYWORDS.has(keyword.upper)) {
      continue;
    }
    let j = i + 1;
    for (;;) {
      while (tokens[j]?.kind === 'word' && SKIP_BEFORE_NAME.has(tokens[j]?.upper ?? '')) {
        j += 1;
      }
      const first = tokens[j];
      if (first?.text === '(' && LIST_KEYWORDS.has(keyword.upper)) {
        j = afterParens(tokens, j);
      } else if (isName(first)) {
        const parts = [nameText(first)];
        j += 1;
        while (tokens[j]?.text === '.' && isName(tokens[j + 1])) {
          parts.push(nameText(tokens[j + 1] as SqlToken));
          j += 2;
        }
        const functionCall =
          tokens[j]?.text === '(' && !['INTO', 'UPDATE', 'TABLE'].includes(keyword.upper);
        if (functionCall) {
          j = afterParens(tokens, j);
        } else {
          tables.push(parts.join('.'));
        }
      } else {
        break;
      }
      if (!LIST_KEYWORDS.has(keyword.upper)) {
        break;
      }
      const next = tokens[j + 1]?.text;
      if (tokens[j]?.upper === 'AS') {
        j += 2;
      } else if (
        (tokens[j]?.kind === 'word' || tokens[j]?.kind === 'ident') &&
        (next === ',' || next === '(')
      ) {
        j += 1;
      }
      if (tokens[j]?.text === '(') {
        j = afterParens(tokens, j);
      }
      if (tokens[j]?.text !== ',') {
        break;
      }
      j += 1;
    }
  }
  const ctes = cteNames(tokens);
  return tables.filter((table) => !ctes.has(table));
}

const asciiLower = (text: string): string =>
  text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());

/** A U&"..." body with its escapes decoded the way Postgres does: `<esc>XXXX`, `<esc>+XXXXXX`, and a
 *  doubled escape for the escape character itself. An escape Postgres would reject is kept as is. */
function decodeUnicodeName(body: string, escapeChar: string): string {
  let out = '';
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i] as string;
    if (c !== escapeChar) {
      out += c;
    } else if (body[i + 1] === escapeChar) {
      out += escapeChar;
      i += 1;
    } else {
      const long = body[i + 1] === '+';
      const hex = (long ? /^[0-9A-Fa-f]{6}/ : /^[0-9A-Fa-f]{4}/).exec(
        body.slice(i + (long ? 2 : 1)),
      )?.[0];
      const point = hex === undefined ? Number.NaN : Number.parseInt(hex, 16);
      if (Number.isNaN(point) || point > 0x10ffff) {
        out += c;
      } else {
        out += String.fromCodePoint(point);
        i += (long ? 1 : 0) + (hex?.length ?? 0);
      }
    }
  }
  return out;
}

/** The name Postgres resolves the word or quoted name at `index` to: an unquoted word folds ASCII
 *  letters to lower case (as Postgres does), a "quoted" name is exact with `""` as one `"`, and a
 *  U&"..." name is decoded (escape character from a following `UESCAPE 'c'`). Null for any other
 *  token. */
function sqlName(tokens: SqlToken[], index: number): string | null {
  const token = tokens[index];
  if (token?.kind === 'word') {
    return asciiLower(token.text);
  }
  if (token?.kind !== 'ident') {
    return null;
  }
  const unicode = /^[uU]&/.test(token.text);
  const body = token.text.slice(unicode ? 3 : 1, -1).replaceAll('""', '"');
  if (!unicode) {
    return body;
  }
  const escapeText = tokens[index + 1]?.upper === 'UESCAPE' ? tokens[index + 2]?.text : undefined;
  const escapeChar = escapeText !== undefined && /^'.'$/.test(escapeText) ? escapeText[1] : '\\';
  return decodeUnicodeName(body, escapeChar ?? '\\');
}

/** The setting a `SET`/`RESET` at `index` names, after `SESSION`/`LOCAL` (kept when it is `SET
 *  SESSION AUTHORIZATION`), case-folded: Postgres looks settings up case-insensitively, quoted or
 *  not. `NAMES` is `client_encoding`'s alias only as the unquoted keyword. */
function settingAt(tokens: SqlToken[], index: number): string {
  let s = index + 1;
  while (
    tokens[s]?.kind === 'word' &&
    ['SESSION', 'LOCAL'].includes(tokens[s]?.upper ?? '') &&
    tokens[s + 1]?.upper !== 'AUTHORIZATION'
  ) {
    s += 1;
  }
  const name = sqlName(tokens, s);
  return name === null ? '' : asciiLower(name);
}

/**
 * The verb, the DDL flag, a refusal and the table names of one `db exec` statement, read lexically
 * (the parser cannot be trusted with a statement it does not understand). DDL is a DDL verb, an
 * `EXPLAIN [ANALYZE]` around one, or `SELECT ... INTO new_table`. Refused outright: a psql
 * meta-command (a buffer starting with a backslash would run as one), transaction control, a
 * `SET`/`RESET` of the role, a timer or a setting the splitter's lexing depends on (also inside
 * `ALTER ROLE|DATABASE|SYSTEM|FUNCTION ... SET` and `CREATE FUNCTION ... SET`), `set_config()`, `COPY
 * ... PROGRAM`, and an SQL-standard `BEGIN ATOMIC` body (its inner `;` cannot be split on). Names
 * are compared as Postgres resolves them: quoted, U&-escaped and schema-qualified spellings alike.
 */
export function classifySqlStatement(statement: SqlStatement): StatementInfo {
  const { text, tokens } = statement;
  const words = tokens.filter((token) => token.kind === 'word');
  let v = 0;
  while (words[v]?.upper === 'EXPLAIN') {
    v += 1;
    while (['ANALYZE', 'ANALYSE', 'VERBOSE'].includes(words[v]?.upper ?? '')) {
      v += 1;
    }
  }
  let verbToken = words[v];
  if (v > 0 && verbToken !== undefined) {
    const firstAfterOptions = tokens.findIndex(
      (token) =>
        token.depth === 0 && token.start > (words[v - 1]?.start ?? 0) && token.kind !== 'punct',
    );
    verbToken = tokens[firstAfterOptions]?.kind === 'word' ? tokens[firstAfterOptions] : verbToken;
  }
  const command = verbToken?.upper ?? '';
  const topWords = words.filter((token) => token.depth === 0);
  const refuse = (why: string): StatementInfo => ({
    command,
    ddl: false,
    refused: why,
    tables: tablesOf(tokens),
  });

  if (text.startsWith('\\')) {
    return refuse('a psql meta-command (\\...) is not SQL');
  }
  if (TRANSACTION_VERBS.has(command)) {
    return refuse(
      `${command} is transaction control; db exec runs the whole file in its own one transaction`,
    );
  }
  if (command === 'PREPARE' && words[v + 1]?.upper === 'TRANSACTION') {
    return refuse('PREPARE TRANSACTION is transaction control');
  }
  if (command === 'SET' || command === 'RESET') {
    const setting = settingAt(tokens, tokens.indexOf(verbToken as SqlToken));
    if (GUARDED_SETTINGS.has(setting)) {
      return refuse(`${command} ${setting} would change the login role or a timer db exec set`);
    }
  }
  if (command === 'SET' || command === 'RESET' || command === 'ALTER' || command === 'CREATE') {
    const changed = tokens
      .map((token, index) =>
        token.kind === 'word' && (token.upper === 'SET' || token.upper === 'RESET')
          ? settingAt(tokens, index)
          : '',
      )
      .find((setting) => SCANNER_SETTINGS.has(setting));
    if (changed !== undefined) {
      return refuse(
        `changing ${changed === 'names' ? 'client_encoding (SET NAMES)' : changed} would make Postgres split the file differently than db exec did`,
      );
    }
  }
  const setConfig = tokens.findIndex(
    (_token, index) =>
      sqlName(tokens, index) === 'set_config' &&
      tokens[tokens[index + 1]?.upper === 'UESCAPE' ? index + 3 : index + 1]?.text === '(',
  );
  if (setConfig !== -1) {
    return refuse('set_config() could change the login role, a timer or how statements are split');
  }
  if (command === 'COPY' && topWords.some((token) => token.upper === 'PROGRAM')) {
    return refuse('COPY ... PROGRAM runs a shell command on the database server');
  }
  if (
    topWords.some(
      (token, index) => token.upper === 'BEGIN' && topWords[index + 1]?.upper === 'ATOMIC',
    )
  ) {
    return refuse(
      'a BEGIN ATOMIC function body is not supported; write the body dollar-quoted ($$ ... $$)',
    );
  }
  const selectInto = topWords.some(
    (token, index) =>
      token.upper === 'INTO' && !['INSERT', 'MERGE'].includes(topWords[index - 1]?.upper ?? ''),
  );
  return {
    command,
    ddl: DDL_VERBS.has(command) || selectInto,
    refused: null,
    tables: tablesOf(tokens),
  };
}

export const EXEC_ROWS_MARKER = '__SSHEPHERD_ROWS__';
export const EXEC_DONE_MARKER = '__SSHEPHERD_DONE__';

/** The settings `splitSqlStatements` lexes with, pinned for the whole `db exec` session. */
export const EXEC_SESSION_PIN_SQL =
  'SET standard_conforming_strings = on; SET client_encoding = UTF8; SET backslash_quote = safe_encoding; SET escape_string_warning = on';
/** The two that move a statement's end, set again in their own buffer before every statement: a
 *  setting changed where the classifier cannot see it (inside a function, through
 *  `query_to_xml`) is back to the scanner's value before the server lexes the next buffer, which
 *  it does whole before running any of it. Written short (`SET NAMES` is `client_encoding`): it is
 *  repeated before each of up to 500 statements, and the whole remote command must stay one
 *  argument under Linux's 128 KiB `MAX_ARG_STRLEN`. */
export const EXEC_PARSER_PIN_SQL = "SET standard_conforming_strings=on;SET NAMES 'UTF8'";
/** In the error psql prints when the transaction `db exec` opened is no longer the open one at the
 *  end (a COMMIT or ROLLBACK the splitter did not see): what ran may already be committed. */
export const EXEC_TXN_ENDED_MARKER = 'sshepherd-exec-transaction-ended';

/**
 * `db exec`: one psql session as the write login (`conn.user`), output of the statements
 * themselves sent to /dev/null (`\o`; `\echo` still reaches stdout), the session limits and
 * `EXEC_SESSION_PIN_SQL`, `BEGIN` and the transaction's xid noted in a transaction-local setting,
 * then per statement `EXEC_PARSER_PIN_SQL`, the statement as its own buffer and an echo of psql's
 * `ROW_COUNT`; then a check that the open transaction still has that xid (an error carrying
 * `EXEC_TXN_ENDED_MARKER` otherwise), and `COMMIT` or (a dry run) `ROLLBACK`. `ON_ERROR_STOP`
 * ends psql at the first failing statement and the server rolls the open transaction back when
 * the connection closes.
 */
export function buildDbExecCommand(
  conn: DbConnection,
  sessionSql: string,
  statements: string[],
  commit: boolean,
): string {
  const buffers = [
    '\\o /dev/null',
    sessionSql,
    EXEC_SESSION_PIN_SQL,
    'BEGIN',
    "SELECT set_config('sshepherd.exec_xid', txid_current()::text, true)",
  ];
  statements.forEach((statement, index) => {
    buffers.push(
      EXEC_PARSER_PIN_SQL,
      statement,
      `\\echo ${EXEC_ROWS_MARKER} ${index + 1} :ROW_COUNT`,
    );
  });
  buffers.push(
    `SELECT CASE WHEN current_setting('sshepherd.exec_xid', true) = txid_current()::text THEN 1 ELSE ('${EXEC_TXN_ENDED_MARKER} ' || txid_current()::text)::int END`,
    commit ? 'COMMIT' : 'ROLLBACK',
    `\\echo ${EXEC_DONE_MARKER} ${commit ? 'committed' : 'rolled_back'}`,
  );
  return buildPsqlCommand(conn, ...buffers);
}

/** A Postgres client tool (`pg_dump`, `pg_restore`) run the way the target reaches psql: in the db
 *  container, or on the host (as `sudo_user`, at `pg_host`/`pg_port`). `connect` adds `-U`/`-d`. */
export function pgToolCommand(
  conn: DbConnection,
  tool: 'pg_dump' | 'pg_restore',
  toolArgs: string[],
  connect: { user: string; database: string } | null,
): string {
  const login = connect === null ? [] : ['-U', connect.user, '-d', connect.database];
  if (conn.kind === 'host') {
    const sudo =
      conn.sudoUser && conn.sudoUser.length > 0 ? ['sudo', '-n', '-u', conn.sudoUser] : [];
    const host =
      connect !== null && conn.pgHost && conn.pgHost.length > 0 ? ['-h', conn.pgHost] : [];
    const port =
      connect !== null && conn.pgPort && conn.pgPort.length > 0 ? ['-p', conn.pgPort] : [];
    return shellJoin([...sudo, tool, ...host, ...port, ...login, ...toolArgs]);
  }
  return shellJoin([...execPrefix(conn), tool, ...login, ...toolArgs]);
}

/** Dump file names `db backup` writes and prunes, for one target: anything else in the directory is
 *  never touched. */
export function backupNamePattern(prefix: string): string {
  return `^${prefix}[0-9]{8}T[0-9]{6}Z\\.dump$`;
}

export interface BackupPlan {
  dir: string;
  prefix: string;
  name: string;
  keep: number;
  maxBytes: number;
}

/**
 * `db backup`: `pg_dump -Fc` into `<dir>/.<name>.<pid>.partial` (0600 under a 0700 umask, its own
 * file even when two backups start in the same second), hard-linked to its name only when the dump
 * exited 0 (`ln` fails when the name exists, so the second of two same-second backups never
 * overwrites the first: it reports the name taken and leaves it alone); then its size, sha256 and `TABLE DATA` entry count (from
 * `pg_restore -l`), then the prune: this target's dumps newest first, each kept while fewer than
 * `keep` are kept and the total stays within `maxBytes`, the new dump always kept. Only names
 * matching `backupNamePattern` inside `dir` are ever deleted.
 */
export function buildDbBackupScript(conn: DbConnection, plan: BackupPlan): string {
  const dump = pgToolCommand(conn, 'pg_dump', ['-Fc'], {
    user: conn.user,
    database: conn.database,
  });
  const list = pgToolCommand(conn, 'pg_restore', ['-l'], null);
  const lines = [
    'umask 077',
    `d=${shq(plan.dir)}`,
    `n=${shq(plan.name)}`,
    `keep=${plan.keep}`,
    `max=${plan.maxBytes}`,
    'mkdir -p -- "$d" || exit 3',
    'if [ -e "$d/$n" ]; then echo "sshepherd: $n already exists; run db backup again in a second" >&2; exit 3; fi',
    't="$d/.$n.$$.partial"',
    `${dump} > "$t" || { rc=$?; rm -f -- "$t"; exit $rc; }`,
    'if ! ln -- "$t" "$d/$n" 2>/dev/null; then',
    '  rm -f -- "$t"',
    '  if [ -e "$d/$n" ]; then echo "sshepherd: $n already exists; run db backup again in a second" >&2; else echo "sshepherd: could not link the finished dump into $d" >&2; fi',
    '  exit 3',
    'fi',
    'rm -f -- "$t"',
    'f="$d/$n"',
    'bytes=$(wc -c < "$f" | tr -d \' \')',
    'sha=$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f") | cut -d \' \' -f 1)',
    `listing=$(${list} < "$f") || { echo "sshepherd: pg_restore -l could not read the new dump" >&2; exit 4; }`,
    "entries=$(printf '%s\\n' \"$listing\" | grep -c ' TABLE DATA ' || true)",
    'kept=0',
    'total=0',
    `for x in $(ls -1 -- "$d" | grep -E ${shq(backupNamePattern(plan.prefix))} | sort -r); do`,
    '  sz=$(wc -c < "$d/$x" | tr -d \' \')',
    '  if [ "$x" != "$n" ] && { [ "$kept" -ge "$keep" ] || [ $((total + sz)) -gt "$max" ]; }; then',
    '    rm -f -- "$d/$x" && echo "__PRUNED__ $x"',
    '  else',
    '    kept=$((kept + 1)); total=$((total + sz))',
    '  fi',
    'done',
    'echo "__BACKUP__ $n $bytes $sha $entries $kept $total"',
  ];
  return shellJoin(['sh', '-c', lines.join('\n')]);
}

/** Every user table with its exact `count(*)`, as one JSON array sorted by name, at most `limit + 1`
 *  tables (one more says the database has too many). `query_to_xml` runs each count inside this
 *  one SELECT, so it stays a read in a read-only transaction. */
export function tableCountsSql(limit: number): string {
  return (
    "SELECT coalesce(json_agg(json_build_object('table', c.name, 'count', c.n) ORDER BY c.name), '[]'::json) FROM (" +
    "SELECT format('%I.%I', schemaname, tablename) AS name, " +
    "(xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', schemaname, tablename), false, true, '')))[1]::text::bigint AS n " +
    "FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') " +
    `ORDER BY 1 LIMIT ${limit + 1}) c`
  );
}

export interface VerifyPlan {
  dir: string;
  prefix: string;
  /** A dump name to verify; null = the newest of this target's dumps. */
  dump: string | null;
  /** The throwaway database name (`sshepherd_verify_<unix seconds>_<16 hex>`). */
  throwaway: string;
  writeRole: string;
  sessionSql: string;
  maxTables: number;
}

/** Throwaway database names `db backup-verify` creates: the creation time in Unix seconds, so a
 *  later run can tell a leftover from a verify still running, and 16 random hex digits. */
export const VERIFY_DB_PATTERN = '^sshepherd_verify_[0-9]{10}_[0-9a-f]{16}$';

/** `drop_db NAME`: ends every session on that throwaway database (a restore whose ssh session died
 *  keeps its own connection open inside the container) and drops it, retried `DB_VERIFY_DROP_TRIES`
 *  times 1 s apart. The name is checked against the throwaway shape before it reaches SQL, and the
 *  SQL goes to psql on stdin, so it is never built into an argv. */
function dropThrowawayFunction(writer: DbConnection): string {
  const psql = buildPsqlCommand(writer);
  return [
    'drop_db() {',
    '  case "$1" in *[!a-z0-9_]*) return 1 ;; sshepherd_verify_*) ;; *) return 1 ;; esac',
    '  i=0',
    `  while [ "$i" -lt ${DB_VERIFY_DROP_TRIES} ]; do`,
    `    printf '%s\\n' "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$1' AND pid <> pg_backend_pid();" "DROP DATABASE IF EXISTS \\"$1\\";" | ${psql} >/dev/null 2>&1 && return 0`,
    '    i=$((i + 1))',
    '    sleep 1',
    '  done',
    '  return 1',
    '}',
  ].join('\n');
}

/**
 * `db backup-verify`: drop this write login's throwaway databases older than
 * `DB_BACKUP_VERIFY_STALE_SEC` (leftovers of a run that was killed), create the throwaway as the
 * write login, `pg_restore` the dump into it in the background (`--no-owner --no-privileges`;
 * non-fatal errors counted from "errors ignored on restore: N", their text never printed, kept in a
 * 0600 file the cleanup removes) while a blank heartbeat line a second tells the script when the
 * ssh session is gone, count every table on the source (as the read login) and in the throwaway,
 * then drop it and report whether it is gone. Cleanup does not depend on this process living: the
 * EXIT trap drops it on every exit a signal allows, and a watchdog in its own session (`setsid`,
 * else `nohup`) drops it once this script's pid is gone for any reason, SIGKILL included. Marker
 * lines carry each part back.
 */
export function buildDbBackupVerifyScript(conn: DbConnection, plan: VerifyPlan): string {
  const writer: DbConnection = { ...conn, user: plan.writeRole };
  const quotedDb = `"${plan.throwaway}"`;
  const onTarget = (sql: string): string => buildPsqlCommand(writer, sql);
  const counts = wrapReadOnlyTxn(tableCountsSql(plan.maxTables));
  const restore = pgToolCommand(conn, 'pg_restore', ['--no-owner', '--no-privileges'], {
    user: plan.writeRole,
    database: plan.throwaway,
  });
  const dropFn = dropThrowawayFunction(writer);
  const staleSql =
    `SELECT datname FROM pg_database WHERE datname ~ ${quoteLiteral(VERIFY_DB_PATTERN)} ` +
    `AND substr(datname, 18, 10)::bigint < extract(epoch FROM now())::bigint - ${DB_BACKUP_VERIFY_STALE_SEC}`;
  const watchdog = [
    "trap '' HUP INT TERM PIPE",
    dropFn,
    'i=0',
    `while [ "$i" -lt ${DB_BACKUP_VERIFY_STALE_SEC} ] && kill -0 "$1" 2>/dev/null; do i=$((i + 1)); sleep 1; done`,
    'drop_db "$2"',
    'rm -f -- "$3"',
  ].join('\n');
  const pick =
    plan.dump === null
      ? `f=$(ls -1 -- "$d" 2>/dev/null | grep -E ${shq(backupNamePattern(plan.prefix))} | sort | tail -n 1)`
      : `f=${shq(plan.dump)}`;
  const lines = [
    'umask 077',
    `d=${shq(plan.dir)}`,
    `db=${shq(plan.throwaway)}`,
    dropFn,
    `for x in $(${onTarget(staleSql)} 2>/dev/null); do drop_db "$x" || true; done`,
    pick,
    'if [ -z "$f" ] || [ ! -f "$d/$f" ]; then echo __NO_DUMP__; exit 0; fi',
    'e="$d/.$db.err"',
    `w=${shq(watchdog)}`,
    'if command -v setsid >/dev/null 2>&1; then setsid sh -c "$w" sh "$$" "$db" "$e" </dev/null >/dev/null 2>&1 &',
    'else nohup sh -c "$w" sh "$$" "$db" "$e" </dev/null >/dev/null 2>&1 &',
    'fi',
    'cleanup() { drop_db "$db"; rm -f -- "$e"; }',
    'trap cleanup EXIT',
    "trap 'exit 129' HUP",
    "trap 'exit 130' INT",
    "trap 'exit 141' PIPE",
    "trap 'exit 143' TERM",
    `${onTarget(`CREATE DATABASE ${quotedDb}`)} >/dev/null || exit $?`,
    `${restore} < "$d/$f" 2> "$e" &`,
    'rp=$!',
    'while kill -0 "$rp" 2>/dev/null; do printf \'\\n\' || exit 141; sleep 1; done',
    'wait "$rp"',
    'rrc=$?',
    'nerr=$(sed -n \'s/.*errors ignored on restore: \\([0-9][0-9]*\\).*/\\1/p\' "$e" | tail -n 1)',
    'if [ "$rrc" -ne 0 ] && [ -z "$nerr" ]; then echo "sshepherd: pg_restore failed before restoring anything (exit $rrc)" >&2; exit "$rrc"; fi',
    '[ -n "$nerr" ] || nerr=0',
    'echo "__DUMP__ $f"',
    'echo "__RESTORE_ERRORS__ $nerr"',
    `src=$(${buildPsqlCommand(conn, plan.sessionSql, counts)}) || exit $?`,
    'printf \'__SOURCE__ %s\\n\' "$src"',
    `dst=$(${buildPsqlCommand({ ...writer, database: plan.throwaway }, plan.sessionSql, counts)}) || exit $?`,
    'printf \'__RESTORED__ %s\\n\' "$dst"',
    'cleanup',
    'trap - EXIT',
    `left=$(${onTarget(`SELECT count(*) FROM pg_database WHERE datname = ${quoteLiteral(plan.throwaway)}`)}) || exit $?`,
    'echo "__LEFTOVER__ $left"',
  ];
  return shellJoin(['sh', '-c', lines.join('\n')]);
}

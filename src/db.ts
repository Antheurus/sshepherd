import { Parser } from 'node-sql-parser';
import { DB_LOCK_TIMEOUT_SEC, DB_STATEMENT_GRACE_SEC } from './limits.ts';
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

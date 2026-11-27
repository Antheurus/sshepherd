import { auditSetupMutating as auditMutating, confirmGate } from './audit.ts';
import {
  DB_LOCK_TIMEOUT_SEC,
  DB_RO_ROLE_TEMP_FILE_LIMIT_MB,
  DB_STATEMENT_TIMEOUT_SEC,
  DEFAULT_TIMEOUT_SEC,
} from './limits.ts';
import { shellJoin } from './quote.ts';
import { appendBlock, readTextOrEmpty, writeTextSecure } from './setup-file-io.ts';
import { buildSetupResult, type SetupResult } from './setup-types.ts';
import { didYouMean } from './suggest.ts';
import { defaultTargetsPath, loadTargets, pgTargetNames } from './targets.ts';
import { tomlQuote } from './toml-quote.ts';
import { run, type TransportDeps } from './transport.ts';

export interface ScaffoldOptions {
  alias: string;
  user: string;
  database: string;
  composeFile?: string;
  service?: string;
  container?: string;
  yes: boolean;
}

export interface ScaffoldData {
  name: string;
  alias: string;
  user: string;
  database: string;
  composeFile: string | null;
  service: string | null;
  container: string | null;
}

type ContainerRef =
  | { kind: 'compose'; composeFile: string; service: string }
  | { kind: 'container'; container: string }
  | { kind: 'invalid'; message: string };

/**
 * Mirrors `readTarget`'s own validation (`src/targets.ts:32-66`): exactly one of
 * `{compose_file, service}` or `{container}` — never both, never neither, never a partial
 * compose pair (compose_file without service, or vice versa).
 */
function resolveContainerRef(options: ScaffoldOptions): ContainerRef {
  const hasComposeFile = options.composeFile !== undefined;
  const hasService = options.service !== undefined;
  const hasContainer = options.container !== undefined;
  const hasCompose = hasComposeFile && hasService;

  if (hasCompose && hasContainer) {
    return {
      kind: 'invalid',
      message: 'declares both --compose-file/--service and --container — pick one',
    };
  }
  if (hasCompose) {
    return {
      kind: 'compose',
      composeFile: options.composeFile as string,
      service: options.service as string,
    };
  }
  if (hasContainer) {
    return { kind: 'container', container: options.container as string };
  }
  if (hasComposeFile !== hasService) {
    return { kind: 'invalid', message: '--compose-file and --service must be provided together' };
  }
  return { kind: 'invalid', message: 'needs either --compose-file/--service or --container' };
}

/** Field order/quoting matches targets.example.toml's per-field style. */
function buildTargetTableLines(
  name: string,
  options: ScaffoldOptions,
  ref: ContainerRef,
): string[] {
  const lines = [`[${name}]`, `alias = ${tomlQuote(options.alias)}`];
  if (ref.kind === 'compose') {
    lines.push(
      `compose_file = ${tomlQuote(ref.composeFile)}`,
      `service = ${tomlQuote(ref.service)}`,
    );
  } else if (ref.kind === 'container') {
    lines.push(`container = ${tomlQuote(ref.container)}`);
  }
  lines.push(`user = ${tomlQuote(options.user)}`, `database = ${tomlQuote(options.database)}`);
  return lines;
}

/**
 * Appends a `[<name>]` table to `targets.toml`. Refuses with `VALIDATION_ERROR` if the
 * container reference isn't exactly one of `{compose_file, service}` or `{container}` —
 * checked before the `--yes` gate and before any file write, since it's a structural
 * argument error rather than a mutation the human might reasonably want to confirm. Refuses
 * with `TARGET_EXISTS` if `<name>` is already declared, leaving the existing file untouched.
 */
export function scaffold(
  name: string,
  options: ScaffoldOptions,
  path: string = defaultTargetsPath(),
): SetupResult<ScaffoldData> {
  const command = 'setup db-target scaffold';
  const argsSummary = {
    name,
    alias: options.alias,
    user: options.user,
    database: options.database,
    composeFile: options.composeFile ?? '',
    service: options.service ?? '',
    container: options.container ?? '',
  };

  const ref = resolveContainerRef(options);
  if (ref.kind === 'invalid') {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: { code: 'VALIDATION_ERROR', message: `target '${name}' ${ref.message}` },
    });
  }

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'scaffold requires --yes' },
    });
  }

  const existingTargets = loadTargets(path);
  if (name in existingTargets) {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: { code: 'TARGET_EXISTS', message: `target '${name}' already exists in ${path}` },
    });
  }

  const tableLines = buildTargetTableLines(name, options, ref);
  const newText = appendBlock(readTextOrEmpty(path), tableLines.join('\n'));
  writeTextSecure(path, newText);

  auditMutating({ alias: options.alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: {
      name,
      alias: options.alias,
      user: options.user,
      database: options.database,
      composeFile: ref.kind === 'compose' ? ref.composeFile : null,
      service: ref.kind === 'compose' ? ref.service : null,
      container: ref.kind === 'container' ? ref.container : null,
    },
  });
}

export interface RoRoleOptions {
  printSql: boolean;
  role?: string;
  /** `--all-data`: `pg_read_all_data` (every table, pg_authid included) instead of the default
   *  SELECT on the app's tables. */
  allData?: boolean;
  /** `--tables-only`: the default shape, still accepted so older calls keep working. */
  tablesOnly?: boolean;
}

const RO_ROLE_DEFAULT = 'sshepherd_ro';
const ROLE_NAME_PATTERN = /^[a-z_][a-z0-9_]{0,62}$/;

/**
 * The SQL a human applies to give a pg-target a read-only LOGIN role, plus the checks that prove
 * it. sshepherd never runs it (it would need a privileged login on the user's database): the
 * login role is the only boundary untrusted SQL cannot leave, because `RESET ROLE` and
 * `set_config('role', ...)` inside a query return to it.
 */
export function roRoleSql(target: string, role: string, allData = false): string {
  const tablesOnly = !allData;
  const grants = tablesOnly
    ? [
        '-- SELECT on the tables of schema public and nothing else (no system catalog such as',
        '-- pg_authid). Repeat the three lines below for every other schema the app uses. The',
        '-- DEFAULT PRIVILEGES line covers tables created later by the role that runs it; run it as the',
        '-- role that owns the app tables, or add FOR ROLE <owner>.',
        `GRANT USAGE ON SCHEMA public TO ${role};`,
        `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role};`,
        `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ${role};`,
      ]
    : [
        '-- --all-data: pg_read_all_data reads every table, the system catalogs included: pg_authid',
        "-- holds every role's password verifier, and this role can SELECT it. sshepherd db query masks",
        '-- the rolpassword and passwd columns by name (deny_columns in targets.toml), but a value read',
        '-- through a function (substr, encode, replace of rolpassword) comes back NOT masked, and the',
        '-- role itself can always read them. Without --all-data this prints a grant of the app tables only.',
        `GRANT pg_read_all_data TO ${role};`,
      ];
  return [
    `-- Read-only login role for sshepherd pg-target '${target}'.`,
    '-- sshepherd never runs this. Apply it yourself as a superuser (or a CREATEROLE role allowed to',
    tablesOnly
      ? '-- grant on the app schema) on the target database.'
      : '-- grant pg_read_all_data) on the target database; pg_read_all_data needs Postgres 14 or later.',
    '-- Why a LOGIN role: SET ROLE does not sandbox SQL, because RESET ROLE or',
    "-- set_config('role', ...) inside a query returns to the login role. The login role itself must",
    '-- be the restricted one, and a member of no role it could switch to.',
    'BEGIN;',
    `CREATE ROLE ${role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
    ...grants,
    `ALTER ROLE ${role} SET default_transaction_read_only = on;`,
    `ALTER ROLE ${role} SET statement_timeout = '${DB_STATEMENT_TIMEOUT_SEC}s';`,
    `ALTER ROLE ${role} SET lock_timeout = '${DB_LOCK_TIMEOUT_SEC}s';`,
    `ALTER ROLE ${role} SET temp_file_limit = '${DB_RO_ROLE_TEMP_FILE_LIMIT_MB}MB'; -- superuser-only: the role cannot lift it`,
    'COMMIT;',
    `-- A password is only needed over TCP (a container-env URL, or a host target with pg_host):`,
    `-- set it in psql with \\password ${role}, never in a file.`,
    `-- Then point the target at it: user = "${role}" in targets.toml (container-env: the URL's user).`,
    '',
    '-- Checks. Run each and compare with the expected result in its comment.',
    `SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = '${role}'; -- expect: f | f | f | f | f`,
    `SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid WHERE m.member = '${role}'::regrole AND r.rolname <> 'pg_read_all_data'; -- expect: 0`,
    `SELECT pg_has_role('${role}', 'pg_write_all_data', 'USAGE'); -- expect: f`,
    `SELECT has_table_privilege('${role}', 'pg_authid', 'SELECT'); -- expect: ${tablesOnly ? 'f' : 't (pg_read_all_data; see above)'}`,
    `-- Connected as ${role}: SELECT set_config('role', 'postgres', false); -- expect: ERROR: permission denied to set role "postgres"`,
    `-- Connected as ${role}: CREATE TEMP TABLE sshepherd_check (x int); -- expect: ERROR: cannot execute CREATE TABLE in a read-only transaction`,
    '',
  ].join('\n');
}

/** `setup db-target ro-role <target> --print-sql [--all-data]`: the SQL text, or a setup error when the call
 *  is incomplete. Reads targets.toml only to refuse a target that is not declared. */
export function roRole(
  target: string,
  options: RoRoleOptions,
  path: string = defaultTargetsPath(),
): { sql: string } | SetupResult<null> {
  const command = 'setup db-target ro-role';
  if (!options.printSql) {
    return buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: pass --print-sql; sshepherd only prints this SQL, a human applies it`,
        next: `sshepherd setup db-target ro-role ${target} --print-sql`,
      },
    });
  }
  const role = options.role ?? RO_ROLE_DEFAULT;
  if (!ROLE_NAME_PATTERN.test(role)) {
    return buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: --role must be a lower-case Postgres name (letters, digits, _), got ${JSON.stringify(role)}`,
      },
    });
  }
  if (options.allData === true && options.tablesOnly === true) {
    return buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: --all-data and --tables-only ask for two different grants; pass one (the default is tables only)`,
      },
    });
  }
  const targets = loadTargets(path);
  const names = pgTargetNames(path);
  if (!names.includes(target)) {
    return buildSetupResult({
      command,
      error: {
        code: 'VALIDATION_ERROR',
        message:
          target in targets
            ? `targets.toml entry '${target}' declares only containers; a read-only role needs a pg-target with user and database`
            : `pg-target '${target}' is not declared in targets.toml`,
        next: 'sshepherd db list',
        did_you_mean: didYouMean(target, names),
      },
    });
  }
  return { sql: roRoleSql(target, role, options.allData === true) };
}

export interface DiscoveredPostgres {
  container: string;
  image: string;
  compose_project: string | null;
  compose_service: string | null;
}

export interface DiscoverData {
  alias: string;
  postgres_containers: DiscoveredPostgres[];
  compose_projects: string[];
}

const DISCOVER_FORMAT =
  '{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}';
const POSTGRES_IMAGE = /postgres|postgis|timescale/i;

/** `docker ps` lines -> the running postgres containers and every compose project, names only. */
export function parseDiscover(alias: string, stdout: string): DiscoverData {
  const postgres: DiscoveredPostgres[] = [];
  const projects = new Set<string>();
  for (const line of stdout.split('\n')) {
    const [container = '', image = '', project = '', service = ''] = line.split('\t');
    if (container.length === 0) {
      continue;
    }
    if (project.length > 0) {
      projects.add(project);
    }
    if (POSTGRES_IMAGE.test(image)) {
      postgres.push({
        container,
        image,
        compose_project: project.length > 0 ? project : null,
        compose_service: service.length > 0 ? service : null,
      });
    }
  }
  return {
    alias,
    postgres_containers: postgres.sort((a, b) => a.container.localeCompare(b.container)),
    compose_projects: [...projects].sort(),
  };
}

/** `setup db-target discover <alias>`: what `setup db-target scaffold` could point at on that
 *  host, read with one `docker ps`; it writes nothing. */
export async function discover(
  alias: string,
  deps?: TransportDeps,
): Promise<SetupResult<DiscoverData>> {
  const command = 'setup db-target discover';
  const result = await run(
    alias,
    shellJoin(['docker', 'ps', '--format', DISCOVER_FORMAT]),
    DEFAULT_TIMEOUT_SEC,
    deps,
  );
  if (result.error !== null) {
    return buildSetupResult({
      command,
      error: {
        code: 'REMOTE_FAILED',
        message: `${command}: ${result.error.code}: ${result.error.message}`,
        hint: result.error.hint,
      },
    });
  }
  return buildSetupResult({ command, data: parseDiscover(alias, result.raw.stdout) });
}

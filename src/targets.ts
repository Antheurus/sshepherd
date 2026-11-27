import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { DB_BACKUP_KEEP_MAX } from './limits.ts';
import { isProfile, PROFILES, type Profile } from './profiles.ts';
import { didYouMean } from './suggest.ts';
import { parseTomlFile } from './toml-parse.ts';
import { type OpContext, OpError } from './types.ts';

/**
 * A named Postgres access target — the `db` group's equivalent of an SSH alias (see
 * research.md §"DB access": "`<pg-target>` mirrors the SSH-alias no-credentials model").
 * Declares HOW to reach psql on the host the alias points at, by `kind`:
 * - `container` (the default): `docker exec`/`docker compose exec` into the database container,
 *   psql with the declared `user`/`database`. Auth is container peer/trust or the remote
 *   `~/.pgpass`.
 * - `container-env`: the connection URL lives in an env var (`env_key`, default `DATABASE_URL`) of
 *   `container`; it is read and handed to psql inside one remote shell (in `psql_container` when
 *   the app image has no psql), so the URL and its password never transit sshepherd.
 * - `host`: psql installed on the host itself, optionally run as `sudo_user` (peer auth) and
 *   pointed at `pg_host`/`pg_port`.
 * Never a password in targets.toml.
 */
export type PgTargetKind = 'container' | 'container-env' | 'host';

export const PG_TARGET_KINDS: readonly PgTargetKind[] = ['container', 'container-env', 'host'];

export interface PgTarget {
  alias: string;
  kind: PgTargetKind;
  composeFile: string | null;
  service: string | null;
  container: string | null;
  /** Empty for `container-env`: the URL names its own user and database. */
  user: string;
  database: string;
  /** `container-env` only: the env var holding the URL. */
  envKey: string | null;
  /** `container-env` only: the container psql runs in, when not `container` itself. */
  psqlContainer: string | null;
  /** `host` only. */
  sudoUser: string | null;
  pgHost: string | null;
  pgPort: string | null;
  /** Highest `SSHEPHERD_PROFILE` a db op on this target runs with; null = no cap. */
  maxProfile: Profile | null;
  /** Column-name regexes whose values `db query` masks (case-insensitive); the default list unless
   *  the target declares its own `deny_columns`, which replaces it. */
  denyColumns: string[];
  /** Containers on this target's alias whose env key names `env keys --container` may read. */
  containers: string[];
  /** A table with only `alias` and `containers`: it gates `env keys --container` and `services
   *  inspect`'s env, and is no pg-target — a db op naming it is refused. */
  containersOnly?: boolean;
  /** The login `db exec` and `db backup-verify` connect as — never `user`, the read login; absent
   *  when the target declares none, which refuses both. */
  writeRole?: string;
  /** Directory on the host `db backup` writes dumps into; absent = `DB_BACKUP_DEFAULT_DIR`. */
  backupDir?: string;
  /** Dumps kept per target (`backup_keep`, absent = `DB_BACKUP_KEEP_DEFAULT`) and their total size
   *  cap in bytes (`backup_max_bytes`, absent = `DB_BACKUP_MAX_BYTES_DEFAULT`); db ops apply both. */
  backupKeep?: number;
  backupMaxBytes?: number;
}

/** Where `db backup` writes dumps when the target declares no `backup_dir`: relative to the ssh
 *  login's home directory, the directory every remote command starts in. */
export const DB_BACKUP_DEFAULT_DIR = '.sshepherd/backups';

/** The fields a containers-only table holds; any other field makes it a pg-target again. */
const CONTAINERS_ONLY_FIELDS = new Set(['alias', 'containers']);

/** `db query` masks a column whose name matches one of these, unless the target declares its own
 *  `deny_columns`: secrets by name, plus Postgres's own `rolpassword` (pg_authid, readable through
 *  pg_read_all_data) and `passwd` (pg_shadow). */
export const DEFAULT_DENY_COLUMNS = [
  'pass(word)?|secret|token|api_?key|private_?key|credential|salt|hash',
  'rolpassword|passwd',
];

/** Overridable via `SSHEPHERD_TARGETS_PATH` for tests — mirrors transport.ts's XDG_RUNTIME_DIR override. */
export function defaultTargetsPath(): string {
  const override = process.env.SSHEPHERD_TARGETS_PATH;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.config', 'sshepherd', 'targets.toml');
}

const TARGETS_HINT =
  'Fix that entry in targets.toml (SSHEPHERD_TARGETS_PATH, else ~/.config/sshepherd/targets.toml); targets.example.toml shows every field.';

function targetsError(message: string): OpError {
  return new OpError('CONFIG_PARSE_ERROR', message, { hint: TARGETS_HINT });
}

function readMaxProfile(name: string, raw: unknown): Profile | null {
  if (raw === undefined) {
    return null;
  }
  if (typeof raw !== 'string' || !isProfile(raw)) {
    throw targetsError(
      `targets.toml: target '${name}' has max_profile ${JSON.stringify(raw)}; expected one of ${PROFILES.join(', ')}`,
    );
  }
  return raw;
}

const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CONTAINER_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

function readStringList(name: string, field: string, raw: unknown): string[] | null {
  if (raw === undefined) {
    return null;
  }
  if (!Array.isArray(raw) || raw.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw targetsError(
      `targets.toml: target '${name}' has ${field} ${JSON.stringify(raw)}; expected a list of non-empty strings`,
    );
  }
  return raw as string[];
}

function readDenyColumns(name: string, raw: unknown): string[] {
  const list = readStringList(name, 'deny_columns', raw);
  if (list === null) {
    return DEFAULT_DENY_COLUMNS;
  }
  if (list.length === 0) {
    throw targetsError(
      `targets.toml: target '${name}' has an empty deny_columns; leave it out for the default list`,
    );
  }
  for (const pattern of list) {
    try {
      new RegExp(pattern, 'i');
    } catch {
      throw targetsError(
        `targets.toml: target '${name}' has deny_columns entry ${JSON.stringify(pattern)}, which is not a valid regex`,
      );
    }
  }
  return list;
}

function readContainers(name: string, raw: unknown): string[] {
  const list = readStringList(name, 'containers', raw) ?? [];
  const bad = list.find((container) => !CONTAINER_NAME_PATTERN.test(container));
  if (bad !== undefined) {
    throw targetsError(
      `targets.toml: target '${name}' has containers entry ${JSON.stringify(bad)}; expected a container name`,
    );
  }
  return list;
}
const PORT_PATTERN = /^[0-9]{1,5}$/;
const ROLE_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/;

function readWriteRole(name: string, raw: unknown): string | undefined {
  if (raw === undefined) {
    return undefined;
  }
  if (typeof raw !== 'string' || !ROLE_NAME_PATTERN.test(raw)) {
    throw targetsError(
      `targets.toml: target '${name}' has write_role ${JSON.stringify(raw)}; expected a Postgres role name (letters, digits, _ and $)`,
    );
  }
  return raw;
}

function readBackupDir(name: string, raw: unknown): string | undefined {
  if (raw === undefined) {
    return undefined;
  }
  if (typeof raw !== 'string' || raw.length === 0 || /[\0\r\n]/.test(raw)) {
    throw targetsError(
      `targets.toml: target '${name}' has backup_dir ${JSON.stringify(raw)}; expected a directory path on one line`,
    );
  }
  return raw;
}

function readPositiveInt(
  name: string,
  field: string,
  raw: unknown,
  max: number,
): number | undefined {
  if (raw === undefined) {
    return undefined;
  }
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 1 || raw > max) {
    throw targetsError(
      `targets.toml: target '${name}' has ${field} ${JSON.stringify(raw)}; expected a whole number from 1 to ${max}`,
    );
  }
  return raw;
}

function readKind(name: string, raw: unknown): PgTargetKind {
  if (raw === undefined) {
    return 'container';
  }
  if (typeof raw !== 'string' || !(PG_TARGET_KINDS as readonly string[]).includes(raw)) {
    throw targetsError(
      `targets.toml: target '${name}' has kind ${JSON.stringify(raw)}; expected one of ${PG_TARGET_KINDS.join(', ')}`,
    );
  }
  return raw as PgTargetKind;
}

const str = (record: Record<string, unknown>, key: string): string | null =>
  typeof record[key] === 'string' ? (record[key] as string) : null;

function readTarget(name: string, raw: unknown): PgTarget {
  if (typeof raw !== 'object' || raw === null) {
    throw targetsError(`targets.toml: target '${name}' is not a table`);
  }
  const record = raw as Record<string, unknown>;
  const alias = str(record, 'alias') ?? '';
  const kind = readKind(name, record.kind);
  const composeFile = str(record, 'compose_file');
  const service = str(record, 'service');
  const container = str(record, 'container');
  const user = str(record, 'user') ?? '';
  const database = str(record, 'database') ?? '';
  const maxProfile = readMaxProfile(name, record.max_profile);
  const denyColumns = readDenyColumns(name, record.deny_columns);
  const containers = readContainers(name, record.containers);
  const writeFields = {
    writeRole: readWriteRole(name, record.write_role),
    backupDir: readBackupDir(name, record.backup_dir),
    backupKeep: readPositiveInt(name, 'backup_keep', record.backup_keep, DB_BACKUP_KEEP_MAX),
    backupMaxBytes: readPositiveInt(
      name,
      'backup_max_bytes',
      record.backup_max_bytes,
      Number.MAX_SAFE_INTEGER,
    ),
  };
  const base: PgTarget = {
    alias,
    kind,
    composeFile: null,
    service: null,
    container: null,
    user,
    database,
    envKey: null,
    psqlContainer: null,
    sudoUser: null,
    pgHost: null,
    pgPort: null,
    maxProfile,
    denyColumns,
    containers,
    ...Object.fromEntries(Object.entries(writeFields).filter(([, value]) => value !== undefined)),
  };

  if (alias.length === 0) {
    throw targetsError(`targets.toml: target '${name}' is missing 'alias'`);
  }

  if (
    containers.length > 0 &&
    Object.keys(record).every((key) => CONTAINERS_ONLY_FIELDS.has(key))
  ) {
    return { ...base, containersOnly: true };
  }

  if (kind === 'container-env') {
    const envKey = str(record, 'env_key') ?? 'DATABASE_URL';
    if (container === null) {
      throw targetsError(`targets.toml: target '${name}' (kind container-env) needs 'container'`);
    }
    if (!ENV_KEY_PATTERN.test(envKey)) {
      throw targetsError(
        `targets.toml: target '${name}' has env_key ${JSON.stringify(envKey)}; expected an env var name`,
      );
    }
    return { ...base, container, envKey, psqlContainer: str(record, 'psql_container') };
  }

  if (user.length === 0 || database.length === 0) {
    throw targetsError(`targets.toml: target '${name}' is missing 'user' or 'database'`);
  }

  if (kind === 'host') {
    const pgPort = str(record, 'pg_port');
    if (pgPort !== null && !PORT_PATTERN.test(pgPort)) {
      throw targetsError(
        `targets.toml: target '${name}' has pg_port ${JSON.stringify(pgPort)}; expected digits as a string`,
      );
    }
    return {
      ...base,
      sudoUser: str(record, 'sudo_user'),
      pgHost: str(record, 'pg_host'),
      pgPort,
    };
  }

  const hasCompose = composeFile !== null && service !== null;
  if (hasCompose && container !== null) {
    throw targetsError(
      `targets.toml: target '${name}' declares both compose_file/service and container — pick one`,
    );
  }
  if (hasCompose) {
    return { ...base, composeFile, service };
  }
  if (container !== null) {
    return { ...base, container };
  }
  throw targetsError(
    `targets.toml: target '${name}' needs either {compose_file, service} or {container}`,
  );
}

/** Missing file yields an empty map (mirrors `listHostAliases`'s missing-config behavior). */
export function loadTargets(path: string = defaultTargetsPath()): Record<string, PgTarget> {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return {};
  }
  const parsed = parseTomlFile(text, 'targets.toml', TARGETS_HINT);
  const targets: Record<string, PgTarget> = {};
  for (const [name, raw] of Object.entries(parsed)) {
    targets[name] = readTarget(name, raw);
  }
  return targets;
}

/** Containers `env keys --container` may read on `alias`: every `containers` entry of every target
 *  riding on that alias. */
export function declaredContainers(alias: string, path?: string): string[] {
  const declared = new Set<string>();
  for (const target of Object.values(loadTargets(path))) {
    if (target.alias === alias) {
      for (const container of target.containers) {
        declared.add(container);
      }
    }
  }
  return [...declared].sort();
}

/** Target names a db op may use: every table except a containers-only one. */
export function pgTargetNames(path?: string): string[] {
  return Object.entries(loadTargets(path))
    .filter(([, target]) => target.containersOnly !== true)
    .map(([name]) => name);
}

export function resolveTarget(name: string, path?: string): PgTarget {
  const targets = loadTargets(path);
  const target = targets[name];
  if (!target) {
    throw new OpError('VALIDATION_ERROR', `pg-target '${name}' is not declared in targets.toml`, {
      hint: 'Use a declared target name, or add this one with setup db-target scaffold.',
      next: 'sshepherd db list',
      did_you_mean: didYouMean(name, pgTargetNames(path)),
    });
  }
  if (target.containersOnly === true) {
    throw new OpError(
      'VALIDATION_ERROR',
      `targets.toml entry '${name}' declares only containers (for env keys --container and services inspect); a db op needs 'user', 'database' and how to reach psql (container, or compose_file + service, or kind)`,
      {
        hint: 'Pick a pg-target from db list, or have a human add the connection fields to this entry.',
        next: 'sshepherd db list',
      },
    );
  }
  return target;
}

/**
 * Resolves a pg-target name into the `OpContext` a `db` op's `buildRemote` reads —
 * `ctx.alias` becomes the target's ssh alias, and the connection fields are flattened
 * into `ctx.args` so `buildRemote` stays a pure function of `ctx`, same as every other
 * op in the registry. The CLI (future phase) and tests both compose `db` op contexts
 * through this one function.
 */
export function buildDbOpContext(
  targetName: string,
  extraArgs: Record<string, string | boolean>,
  path?: string,
): OpContext {
  const target = resolveTarget(targetName, path);
  return {
    alias: target.alias,
    args: {
      ...extraArgs,
      target: targetName,
      compose_file: target.composeFile ?? '',
      service: target.service ?? '',
      container: target.container ?? '',
      db_user: target.user,
      db_name: target.database,
      db_kind: target.kind,
      env_key: target.envKey ?? '',
      psql_container: target.psqlContainer ?? '',
      sudo_user: target.sudoUser ?? '',
      pg_host: target.pgHost ?? '',
      pg_port: target.pgPort ?? '',
      max_profile: target.maxProfile ?? '',
      deny_columns: JSON.stringify(target.denyColumns),
      ...(target.writeRole === undefined ? {} : { write_role: target.writeRole }),
      ...(target.backupDir === undefined ? {} : { backup_dir: target.backupDir }),
      ...(target.backupKeep === undefined ? {} : { backup_keep: String(target.backupKeep) }),
      ...(target.backupMaxBytes === undefined
        ? {}
        : { backup_max_bytes: String(target.backupMaxBytes) }),
    },
  };
}

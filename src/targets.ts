import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { OpContext } from './types.ts';

/**
 * A named Postgres access target — the `db` group's equivalent of an SSH alias (see
 * research.md §"DB access": "`<pg-target>` mirrors the SSH-alias no-credentials model").
 * Declares HOW to reach psql on the host the alias points at (a compose file + service,
 * or a plain container name) and which db/user to pass to psql. Never a password: on
 * `docker exec`/`docker compose exec` the database's own auth is container peer/trust
 * or the remote's `~/.pgpass` — the password itself never transits sshepherd.
 */
export interface PgTarget {
  alias: string;
  composeFile: string | null;
  service: string | null;
  container: string | null;
  user: string;
  database: string;
}

/** Overridable via `SSHEPHERD_TARGETS_PATH` for tests — mirrors transport.ts's XDG_RUNTIME_DIR override. */
export function defaultTargetsPath(): string {
  const override = process.env.SSHEPHERD_TARGETS_PATH;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.config', 'sshepherd', 'targets.toml');
}

function readTarget(name: string, raw: unknown): PgTarget {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error(`targets.toml: target '${name}' is not a table`);
  }
  const record = raw as Record<string, unknown>;
  const alias = typeof record.alias === 'string' ? record.alias : '';
  const composeFile = typeof record.compose_file === 'string' ? record.compose_file : null;
  const service = typeof record.service === 'string' ? record.service : null;
  const container = typeof record.container === 'string' ? record.container : null;
  const user = typeof record.user === 'string' ? record.user : '';
  const database = typeof record.database === 'string' ? record.database : '';

  if (alias.length === 0) {
    throw new Error(`targets.toml: target '${name}' is missing 'alias'`);
  }
  if (user.length === 0 || database.length === 0) {
    throw new Error(`targets.toml: target '${name}' is missing 'user' or 'database'`);
  }

  const hasCompose = composeFile !== null && service !== null;
  if (hasCompose && container !== null) {
    throw new Error(
      `targets.toml: target '${name}' declares both compose_file/service and container — pick one`,
    );
  }
  if (hasCompose) {
    return { alias, composeFile, service, container: null, user, database };
  }
  if (container !== null) {
    return { alias, composeFile: null, service: null, container, user, database };
  }
  throw new Error(
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
  const parsed = Bun.TOML.parse(text) as Record<string, unknown>;
  const targets: Record<string, PgTarget> = {};
  for (const [name, raw] of Object.entries(parsed)) {
    targets[name] = readTarget(name, raw);
  }
  return targets;
}

export function resolveTarget(name: string, path?: string): PgTarget {
  const targets = loadTargets(path);
  const target = targets[name];
  if (!target) {
    throw new Error(`pg-target '${name}' is not declared in targets.toml`);
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
    },
  };
}

import type { PortMapping } from './parsers/docker-ports.ts';
import { type ArgSpec, type OpContext, OpError } from './types.ts';

export { DEFAULT_TIMEOUT_SEC, FILE_TIMEOUT_SEC, LOG_TIMEOUT_SEC } from './limits.ts';
export const DEFAULT_LOG_TAIL = 200;
export const FILE_CAT_MAX_BYTES = 1_048_576; // 1 MiB

// ---------------------------------------------------------------------------
// Arg helpers — every buildRemote/shape reads args through these so a missing
// required arg fails the same way everywhere.
// ---------------------------------------------------------------------------

export function reqStr(ctx: OpContext, key: string): string {
  const value = ctx.args[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new OpError('INVALID_ARGS', `missing required arg '${key}'`);
  }
  return value;
}

export function optStr(ctx: OpContext, key: string, fallback: string): string {
  const value = ctx.args[key];
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

export function optStrOrNull(ctx: OpContext, key: string): string | null {
  const value = ctx.args[key];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

export function optBool(ctx: OpContext, key: string, fallback: boolean): boolean {
  const value = ctx.args[key];
  return typeof value === 'boolean' ? value : fallback;
}

/** Names an ssh alias, container, unit, service, stream, tunnel id, recipe or pg-target. */
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.@:+~-]*$/;
/** A local or remote file path: `shellJoin` quotes every other character, so only a NUL or a
 *  line break — which no quoting carries through a remote command line intact — is refused. */
const PATH_FORBIDDEN = /[\0\r\n]/;

/** Positional values that name something (as opposed to free text such as `sql`), by arg name. */
const NAME_ARGS = new Set([
  'alias',
  'container',
  'unit',
  'service',
  'stream',
  'id',
  'recipe',
  'target',
]);
const PATH_ARGS = new Set(['path', 'local_path', 'remote_path', 'file', 'project_dir']);

/**
 * A positional that starts with `-` would be read by ssh/docker/systemctl/ls as an option
 * (`logs docker web -f`, `files cat host --x`), so a name or path argument is refused before
 * any command is built or any ssh runner is called.
 */
export function assertPositional(name: string, value: string): void {
  if (value.startsWith('-')) {
    throw new OpError(
      'INVALID_ARGS',
      `argument '${name}' must not start with '-' (got '${value}'): it would be read as an option`,
      {
        hint: PATH_ARGS.has(name)
          ? `Pass the path itself; a relative path that starts with '-' needs ./ in front, as ./${value}.`
          : `Pass the real ${name}; none of these names starts with '-'.`,
      },
    );
  }
  if (PATH_ARGS.has(name)) {
    if (PATH_FORBIDDEN.test(value)) {
      throw new OpError(
        'INVALID_ARGS',
        `argument '${name}' contains a NUL or line-break character (got ${JSON.stringify(value)})`,
        { hint: 'Pass the path on one line; a path with a NUL or line break cannot be sent.' },
      );
    }
    return;
  }
  if (NAME_ARGS.has(name) && !NAME_PATTERN.test(value)) {
    throw new OpError(
      'INVALID_ARGS',
      `argument '${name}' has characters outside the allowed set (got '${value}')`,
      { hint: 'Use letters, digits and . _ - @ : + ~ only.' },
    );
  }
}

/** Runs `assertPositional` over the op's alias and every positional the op declares. */
export function assertOpPositionals(op: { args: ArgSpec[] }, ctx: OpContext): void {
  if (ctx.alias.length > 0) {
    assertPositional('alias', ctx.alias);
  }
  for (const spec of op.args) {
    const value = ctx.args[spec.name];
    const isNameOrPath = NAME_ARGS.has(spec.name) || PATH_ARGS.has(spec.name);
    if (spec.kind === 'positional' && isNameOrPath && typeof value === 'string') {
      assertPositional(spec.name, value);
    }
  }
}

export function arg(
  name: string,
  kind: ArgSpec['kind'],
  required: boolean,
  description: string,
): ArgSpec {
  return { name, kind, required, description };
}

export function readRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

export interface ComposePsEntry {
  id: string;
  name: string;
  service: string;
  image: string;
  state: string;
  health: string | null;
  exit_code: number | null;
  ports: PortMapping[];
}

export function shapeComposePsEntry(raw: unknown): ComposePsEntry | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const publishers = Array.isArray(record.Publishers) ? (record.Publishers as unknown[]) : [];
  const ports: PortMapping[] = publishers
    .map((publisher): PortMapping | null => {
      const p = readRecord(publisher);
      const containerPort = typeof p.TargetPort === 'number' ? p.TargetPort : null;
      if (containerPort === null) {
        return null;
      }
      return {
        host_ip: typeof p.URL === 'string' && p.URL.length > 0 ? p.URL : null,
        host_port: typeof p.PublishedPort === 'number' ? p.PublishedPort : null,
        container_port: containerPort,
        proto: typeof p.Protocol === 'string' ? p.Protocol : 'tcp',
      };
    })
    .filter((mapping): mapping is PortMapping => mapping !== null);

  return {
    id: typeof record.ID === 'string' ? record.ID.slice(0, 12) : '',
    name: typeof record.Name === 'string' ? record.Name : '',
    service: typeof record.Service === 'string' ? record.Service : '',
    image: typeof record.Image === 'string' ? record.Image : '',
    state: typeof record.State === 'string' ? record.State : 'unknown',
    health: typeof record.Health === 'string' && record.Health.length > 0 ? record.Health : null,
    exit_code: typeof record.ExitCode === 'number' ? record.ExitCode : null,
    ports,
  };
}

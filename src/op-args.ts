import type { PortMapping } from './parsers/docker-ports.ts';
import type { ArgSpec, OpContext } from './types.ts';

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
    throw new Error(`missing required arg '${key}'`);
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

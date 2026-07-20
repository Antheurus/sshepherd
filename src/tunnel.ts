import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { writeTextSecure } from './setup-file-io.ts';
import { OpRunLocalError } from './types.ts';

export type TunnelKind = 'local' | 'remote' | 'dynamic';

export interface TunnelRecord {
  id: string;
  alias: string;
  kind: TunnelKind;
  /** Auto-assigned local port for kind=local/dynamic; null for kind=remote. */
  localPort: number | null;
  /** kind=local: the "host:port" being forwarded to. kind=remote: the bind spec on the
   *  alias's side. null for kind=dynamic (a SOCKS proxy has no single target). */
  remoteTarget: string | null;
  /** kind=remote only: "host:port" on the operator's machine being exposed. null otherwise. */
  localTarget: string | null;
  /** PID of the detached supervisor process (the process-GROUP leader) — NOT ssh's own PID. */
  pid: number;
  openedAt: string;
  expiresAt: string;
}

/** Overridable via `SSHEPHERD_TUNNEL_STATE_DIR` for tests — mirrors `targets.ts`'s
 *  `SSHEPHERD_TARGETS_PATH` override. */
export function defaultTunnelStateDir(): string {
  const override = process.env.SSHEPHERD_TUNNEL_STATE_DIR;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.local', 'state', 'sshepherd', 'tunnels');
}

export function tunnelRecordPath(dir: string, id: string): string {
  return join(dir, `${id}.json`);
}

/** Writes a tunnel state file via `writeTextSecure` (0600 file, 0700 parent) — the same
 *  extracted primitive `setup`'s config writers use, so the secure-write behavior stays in one
 *  place instead of being hand-copied here. */
export function writeTunnelRecord(path: string, record: TunnelRecord): void {
  writeTextSecure(path, JSON.stringify(record));
}

/** Binds an ephemeral local TCP listener, reads back the OS-assigned port, releases it
 *  immediately. There is a small window between release and ssh's own bind where another
 *  process could take the port — `openTunnel` (a later task) surfaces `TUNNEL_PORT_TAKEN` if
 *  that happens, rather than pretending this race can be closed entirely on localhost. */
export function findFreePort(): number {
  const listener = Bun.listen({
    hostname: '127.0.0.1',
    port: 0,
    // Bun.listen requires at least a `data` or `drain` handler at runtime (ERR_INVALID_ARG_TYPE)
    // even though the types mark them optional. No connection is ever accepted here, so it no-ops.
    socket: { data() {} },
  });
  const port = listener.port;
  listener.stop(true);
  return port;
}

export const DEFAULT_DURATION_SEC = 3600;
export const MIN_DURATION_SEC = 30;
export const MAX_DURATION_SEC = 86_400;

export interface OpenTunnelParams {
  alias: string;
  kind: TunnelKind;
  remote?: string;
  local?: string;
  durationSec: number;
}

export function validateOpenParams(params: OpenTunnelParams): void {
  if (params.kind !== 'local' && params.kind !== 'remote' && params.kind !== 'dynamic') {
    throw new OpRunLocalError(
      'VALIDATION_ERROR',
      `kind must be 'local', 'remote', or 'dynamic', got '${params.kind}'`,
    );
  }
  if ((params.kind === 'local' || params.kind === 'remote') && !params.remote) {
    throw new OpRunLocalError('VALIDATION_ERROR', `--remote is required for kind '${params.kind}'`);
  }
  if (params.kind === 'remote' && !params.local) {
    throw new OpRunLocalError('VALIDATION_ERROR', "--local is required for kind 'remote'");
  }
  if ((params.kind === 'local' || params.kind === 'dynamic') && params.local) {
    throw new OpRunLocalError('VALIDATION_ERROR', `--local is not valid for kind '${params.kind}'`);
  }
  if (params.durationSec < MIN_DURATION_SEC || params.durationSec > MAX_DURATION_SEC) {
    throw new OpRunLocalError(
      'VALIDATION_ERROR',
      `--duration must be between ${MIN_DURATION_SEC} and ${MAX_DURATION_SEC} seconds`,
    );
  }
}

/** `localPort` is the auto-assigned port from `findFreePort()` for kind=local/dynamic, `null`
 *  for kind=remote (the local side there is `params.local`, an agent-supplied string, not a
 *  port sshepherd allocates). */
export function buildSshArgs(params: OpenTunnelParams, localPort: number | null): string[] {
  if (params.kind === 'local') {
    return ['-N', '-L', `${localPort}:${params.remote}`, params.alias];
  }
  if (params.kind === 'dynamic') {
    return ['-N', '-D', String(localPort), params.alias];
  }
  return ['-N', '-R', `${params.remote}:${params.local}`, params.alias];
}

/** Returns `null` for a missing or malformed state file — a tunnel state dir behaves like
 *  `targets.ts`'s "missing file yields empty" tolerance, never throws on a bad read. */
export function readTunnelRecordFile(path: string): TunnelRecord | null {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(text) as TunnelRecord;
  } catch {
    return null;
  }
}

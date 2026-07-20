import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { writeTextSecure } from './setup-file-io.ts';

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

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { listHostAliases } from './parsers/ssh-config.ts';
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

/** Dev mode (`bun src/cli.ts ...`) needs `[bun, /path/to/cli.ts]` to re-invoke correctly —
 *  `process.execPath` alone would just be the `bun` binary, which can't be run with no script
 *  argument the way this needs. A compiled standalone binary (`dist/sshepherd`, the real
 *  distribution artifact) has no separate script path in `process.argv[1]`, so `process.execPath`
 *  alone IS the correct full re-invocation. */
export function resolveSelfInvocation(): string[] {
  const scriptArg = process.argv[1];
  if (scriptArg && scriptArg.endsWith('cli.ts')) {
    return [process.execPath, scriptArg];
  }
  return [process.execPath];
}

export interface RunSupervisorParams {
  command: string;
  args: string[];
  durationSec: number;
}

/** Runs as the hidden `sshepherd tunnel __supervise` entrypoint (wired in a later task's
 *  `cli.ts` change). Spawns the real command (ssh) as its OWN child — inheriting this process's
 *  group, which `openTunnel` (a later task) makes a NEW group via `detached: true` when it
 *  spawns the supervisor itself — holds a JS timer for `durationSec`, and kills the child
 *  directly (no process-group trick needed here; this process has a direct handle to its own
 *  child) if the timer fires first. */
export async function runSupervisor(params: RunSupervisorParams): Promise<number> {
  const proc = Bun.spawn([params.command, ...params.args], {
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  const timer = setTimeout(() => {
    proc.kill('SIGKILL');
  }, params.durationSec * 1000);
  const exitCode = await proc.exited;
  clearTimeout(timer);
  return exitCode;
}

export interface SpawnSupervisorResult {
  pid: number;
}

export interface OpenTunnelDeps {
  spawnSupervisor?: (id: string, durationSec: number, sshArgs: string[]) => SpawnSupervisorResult;
}

/** The real (production) spawn path — a detached re-invocation of this same binary in
 *  `tunnel __supervise` mode. `detached: true` makes the supervisor the leader of a NEW process
 *  group; the ssh child it spawns from inside `runSupervisor` inherits that same group (default
 *  POSIX fork/exec behavior for a non-detached child), which is what lets `closeTunnel` (Task 8)
 *  kill both with one negative-PID signal. */
function defaultSpawnSupervisor(
  id: string,
  durationSec: number,
  sshArgs: string[],
): SpawnSupervisorResult {
  const selfInvocation = resolveSelfInvocation();
  const proc = Bun.spawn(
    [...selfInvocation, 'tunnel', '__supervise', id, String(durationSec), 'ssh', ...sshArgs],
    {
      stdio: ['ignore', 'ignore', 'ignore'],
      detached: true,
    },
  );
  proc.unref();
  return { pid: proc.pid };
}

/** Ties validation, alias-authorization, port-finding, and the detached supervisor spawn into one
 *  callable open. The alias is checked against the aliases ACTUALLY declared in `~/.ssh/config`
 *  before any argv is built or process spawned: the tunnel path spawns ssh directly (never through
 *  `transport.ts`, which guards aliases via `ssh -G`), so without this check a leading-dash alias
 *  like `-oProxyCommand=<cmd>` would reach ssh as an option, not a hostname — local command
 *  execution. */
export function openTunnel(
  params: OpenTunnelParams,
  sshConfigPath: string,
  deps: OpenTunnelDeps = {},
): TunnelRecord {
  validateOpenParams(params);

  const declaredAliases = listHostAliases(sshConfigPath);
  if (!declaredAliases.includes(params.alias)) {
    throw new OpRunLocalError(
      'UNKNOWN_ALIAS',
      `alias '${params.alias}' is not declared in the ssh config`,
    );
  }

  const id = `t-${randomUUID()}`;
  const localPort = params.kind === 'local' || params.kind === 'dynamic' ? findFreePort() : null;
  const sshArgs = buildSshArgs(params, localPort);

  const spawn = deps.spawnSupervisor ?? defaultSpawnSupervisor;
  const { pid } = spawn(id, params.durationSec, sshArgs);

  const now = Date.now();
  const record: TunnelRecord = {
    id,
    alias: params.alias,
    kind: params.kind,
    localPort,
    remoteTarget: params.kind === 'dynamic' ? null : (params.remote ?? null),
    localTarget: params.kind === 'remote' ? (params.local ?? null) : null,
    pid,
    openedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + params.durationSec * 1000).toISOString(),
  };

  writeTunnelRecord(tunnelRecordPath(defaultTunnelStateDir(), id), record);
  return record;
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

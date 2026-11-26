import { mkdirSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeError, errorInfo } from './errors.ts';
import { CONNECT_TIMEOUT_SEC, CONTROL_PERSIST_SEC, KILL_AFTER_SEC } from './limits.ts';
import { listHostAliases } from './parsers/ssh-config.ts';
import { didYouMean } from './suggest.ts';
import type { ErrorInfo, RawResult } from './types.ts';

/** macOS caps a Unix-domain socket path at ~104 bytes (Linux at 108) — stay under 100. */
const MAX_SOCKET_PATH_LENGTH = 100;

/** Hex chars of the alias sha256 kept in the socket name: 64 bits, collision-free for any
 *  realistic alias count, and short enough to keep the path under the socket limit. */
const SOCKET_NAME_HEX_CHARS = 16;
/** `-O exit` needs a host argument syntactically; with an explicit ControlPath it is never resolved. */
const DISCONNECT_PLACEHOLDER_HOST = 'sshepherd-disconnect';
/** Exit codes the remote `timeout` wrapper uses: 124 = TERM after the budget, 137 = KILL after `-k`. */
const REMOTE_TIMEOUT_EXIT_CODES = [124, 137];
const CONTROL_COMMAND_TIMEOUT_MS = 5_000;
const VALIDATE_TIMEOUT_MS = 5_000;
const MASTER_OPEN_TIMEOUT_MS = (CONNECT_TIMEOUT_SEC + 5) * 1_000;
const LOCAL_TIMEOUT_BUFFER_MS = 2_000;
/** A long-running remote command (a slow SQL DELETE, a big docker build) that produces no
 *  stdout/stderr for minutes leaves the TCP session looking idle. Idle-timeout middleboxes
 *  (cloud NAT/LB/stateful firewalls — commonly 120-150s) silently drop it; ssh then exits
 *  255 with no useful stderr, misclassified as a generic SSH_TRANSPORT_ERROR at a suspicious
 *  ~140s clustering that has nothing to do with any timeout sshepherd itself sets. Sending a
 *  keepalive on the ControlMaster every 15s (x4 missed = 60s tolerance) keeps the session
 *  looking active so it survives genuinely long, quiet remote commands. */
const KEEPALIVE_INTERVAL_S = 15;
const KEEPALIVE_COUNT_MAX = 4;

/** What a single `ssh` invocation returns — captured stdout/stderr as one opaque stream. */
export interface SpawnOutcome {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

/**
 * Injected in tests with a fake implementation so transport/classification tests never
 * touch a real network or a real `ssh` binary.
 */
export type SshRunner = (args: string[], timeoutMs: number) => Promise<SpawnOutcome>;

export interface TransportDeps {
  runner: SshRunner;
  /** ssh client config used to tell a declared alias from a bare hostname; defaults to `~/.ssh/config`. */
  sshConfigPath?: string;
}

export interface TransportResult {
  raw: RawResult;
  error: ErrorInfo | null;
}

export { errorInfo };

export interface ClassifyContext {
  /** The `--timeout` budget the command ran under; lets a timeout error carry it. */
  timeoutSec?: number;
  /** Wall time of the phase being classified. */
  elapsedMs?: number;
}

function connectTimeoutInfo(elapsedMs?: number): ErrorInfo {
  const info = errorInfo('CONNECT_TIMEOUT');
  info.phase = 'connect';
  info.timeout_sec = CONNECT_TIMEOUT_SEC;
  if (elapsedMs !== undefined) {
    info.elapsed_ms = elapsedMs;
  }
  return info;
}

function commandTimeoutInfo(ctx: ClassifyContext): ErrorInfo {
  const info = errorInfo('COMMAND_TIMEOUT');
  info.phase = 'command';
  if (ctx.timeoutSec !== undefined) {
    info.timeout_sec = ctx.timeoutSec;
    info.budget_sec = ctx.timeoutSec;
  }
  if (ctx.elapsedMs !== undefined) {
    info.elapsed_ms = ctx.elapsedMs;
  }
  return info;
}

/**
 * Reads `raw.transportStderr` only to decide the code, never to build the message —
 * the stderr text is discarded after this function returns. No redaction allowlist:
 * OpenSSH stderr phrasing varies by version/locale, so discard-entirely is the only
 * shape that can't eventually leak an IP or hostname.
 */
export function classify(raw: RawResult, ctx: ClassifyContext = {}): ErrorInfo | null {
  if (raw.timedOut || REMOTE_TIMEOUT_EXIT_CODES.includes(raw.code)) {
    return commandTimeoutInfo(ctx);
  }
  if (raw.code === 255) {
    const text = raw.transportStderr;
    if (/connection timed out|operation timed out/i.test(text)) {
      return connectTimeoutInfo(ctx.elapsedMs);
    }
    if (/permission denied|too many authentication failures/i.test(text)) {
      return errorInfo('AUTH_FAILED');
    }
    if (/remote host identification has changed/i.test(text)) {
      return errorInfo('HOST_KEY_MISMATCH');
    }
    return errorInfo('SSH_TRANSPORT_ERROR');
  }
  if (raw.code !== 0) {
    return errorInfo('COMMAND_FAILED', raw.code);
  }
  return null;
}

function socketDir(): string {
  const xdgRuntimeDir = process.env.XDG_RUNTIME_DIR;
  const base = xdgRuntimeDir && xdgRuntimeDir.length > 0 ? xdgRuntimeDir : tmpdir();
  return join(base, 'sshepherd');
}

/** Opaque, short, deterministic per alias — never `%h`/`%r`/`%p` (those leak host/user/port).
 *  sha256 prefix, not crc32: two aliases sharing a 32-bit checksum would share a master and
 *  silently run one alias's commands on the other's host. */
function socketPath(alias: string): string {
  const dir = socketDir();
  const name = new Bun.CryptoHasher('sha256')
    .update(alias)
    .digest('hex')
    .slice(0, SOCKET_NAME_HEX_CHARS);
  const full = join(dir, `${name}.sock`);
  if (full.length >= MAX_SOCKET_PATH_LENGTH) {
    throw new Error(
      `ControlPath socket path is ${full.length} chars, must stay under ${MAX_SOCKET_PATH_LENGTH}`,
    );
  }
  return full;
}

/** `ssh -G <anything>` exits 0 even for a name no config declares — it just echoes the name back
 *  as the hostname. So an alias is unknown when `-G` fails, or when it resolved to itself AND no
 *  `Host` stanza declares it. The hostname is compared and dropped, never kept or returned. */
async function unknownAliasError(alias: string, deps: TransportDeps): Promise<ErrorInfo | null> {
  const result = await deps.runner(['-G', alias], VALIDATE_TIMEOUT_MS);
  const resolved = result.code === 0 && result.stdout.trim().length > 0;
  const resolvedHost = /^hostname\s+(\S+)/im.exec(result.stdout)?.[1];
  const echoed = resolvedHost !== undefined && resolvedHost.toLowerCase() === alias.toLowerCase();
  if (resolved && !echoed) {
    return null;
  }
  const declared = listHostAliases(deps.sshConfigPath ?? join(homedir(), '.ssh', 'config'));
  if (resolved && declared.includes(alias)) {
    return null;
  }
  return describeError('UNKNOWN_ALIAS', `ssh alias '${alias}' is not defined in ssh config`, {
    did_you_mean: didYouMean(alias, declared),
  });
}

type MasterOutcome = { sock: string; failure: null } | { sock: string; failure: TransportResult };

/** Reuses a live master (`-O check`); otherwise opens one that persists `CONTROL_PERSIST_SEC`
 *  past the last use, so the next sshepherd invocation finds it. The open's outcome decides
 *  the result: a failed open is classified here instead of surfacing as a confusing second
 *  failure from the command that follows. */
async function ensureMaster(alias: string, runner: SshRunner): Promise<MasterOutcome> {
  mkdirSync(socketDir(), { recursive: true, mode: 0o700 });
  const sock = socketPath(alias);

  const check = await runner(
    ['-o', `ControlPath=${sock}`, '-O', 'check', alias],
    CONTROL_COMMAND_TIMEOUT_MS,
  );
  if (check.code === 0) {
    return { sock, failure: null };
  }

  // A socket file whose master died answers "Connection refused"; a missing socket does not
  // need clearing, so `-O exit` runs only for the stale case.
  if (/connection refused/i.test(check.stderr)) {
    await runner(['-o', `ControlPath=${sock}`, '-O', 'exit', alias], CONTROL_COMMAND_TIMEOUT_MS);
  }

  const openedAtMs = Date.now();
  const open = await runner(
    [
      '-o',
      'BatchMode=yes',
      '-o',
      `ConnectTimeout=${CONNECT_TIMEOUT_SEC}`,
      '-o',
      'LogLevel=ERROR',
      '-o',
      `ServerAliveInterval=${KEEPALIVE_INTERVAL_S}`,
      '-o',
      `ServerAliveCountMax=${KEEPALIVE_COUNT_MAX}`,
      '-o',
      'ControlMaster=auto',
      '-o',
      `ControlPath=${sock}`,
      '-o',
      `ControlPersist=${CONTROL_PERSIST_SEC}`,
      '-M',
      '-N',
      '-f',
      alias,
    ],
    MASTER_OPEN_TIMEOUT_MS,
  );
  if (open.code === 0 && !open.timedOut) {
    return { sock, failure: null };
  }

  const elapsedMs = Date.now() - openedAtMs;
  const raw: RawResult = {
    code: 255,
    stdout: '',
    transportStderr: open.stderr,
    commandStderr: '',
    timedOut: false,
  };
  const error = open.timedOut ? connectTimeoutInfo(elapsedMs) : classify(raw, { elapsedMs });
  return { sock, failure: { raw, error } };
}

/**
 * Connects via ControlMaster (opening or reusing it), runs `remoteCmd` wrapped in a
 * remote `timeout <timeoutSec>` (kills a hung remote process, not just local
 * abandonment), and classifies the result. `deps.runner` defaults to a real
 * `Bun.spawn`-backed `ssh` shell-out; tests inject a fake runner so this whole path
 * runs with no network and no real `ssh` binary.
 */
export async function run(
  alias: string,
  remoteCmd: string,
  timeoutSec: number,
  deps: TransportDeps = { runner: defaultRunner },
): Promise<TransportResult> {
  const unknownAlias = await unknownAliasError(alias, deps);
  if (unknownAlias) {
    return {
      raw: { code: -1, stdout: '', transportStderr: '', commandStderr: '', timedOut: false },
      error: unknownAlias,
    };
  }

  const master = await ensureMaster(alias, deps.runner);
  if (master.failure) {
    return master.failure;
  }

  const startedAtMs = Date.now();
  const outcome = await deps.runner(
    [
      '-o',
      'BatchMode=yes',
      '-o',
      `ConnectTimeout=${CONNECT_TIMEOUT_SEC}`,
      '-o',
      'LogLevel=ERROR',
      '-o',
      `ServerAliveInterval=${KEEPALIVE_INTERVAL_S}`,
      '-o',
      `ServerAliveCountMax=${KEEPALIVE_COUNT_MAX}`,
      '-o',
      `ControlPath=${master.sock}`,
      alias,
      '--',
      'timeout',
      // `-k <sec>` (not `--kill-after=`): busybox `timeout` has only the short form, GNU
      // accepts both. Without escalation a single SIGTERM to the direct child is all it
      // sends, and a `sh -c` wrapper (or a `docker exec` whose signal never reaches the
      // process inside the container) can survive that indefinitely. KILL 10 s later makes
      // sure the remote process tree actually goes away, though it still cannot reach a
      // process already inside a container — see recipes.md for that caveat (set a
      // statement_timeout / equivalent server-side, don't rely on this).
      '-k',
      String(KILL_AFTER_SEC),
      String(timeoutSec),
      remoteCmd,
    ],
    timeoutSec * 1_000 + LOCAL_TIMEOUT_BUFFER_MS,
  );

  // ssh exits 255 for its own transport failures; any other code is the remote command's.
  const raw: RawResult = {
    code: outcome.code,
    stdout: outcome.stdout,
    transportStderr: outcome.code === 255 ? outcome.stderr : '',
    commandStderr: outcome.code === 255 ? '' : outcome.stderr,
    timedOut: outcome.timedOut,
  };

  return { raw, error: classify(raw, { timeoutSec, elapsedMs: Date.now() - startedAtMs }) };
}

/** Tears down one alias's ControlMaster (`hosts disconnect <alias>`); true when one was up. */
export async function closeMaster(
  alias: string,
  deps: TransportDeps = { runner: defaultRunner },
): Promise<boolean> {
  const sock = socketPath(alias);
  const result = await deps.runner(
    ['-o', `ControlPath=${sock}`, '-O', 'exit', alias],
    CONTROL_COMMAND_TIMEOUT_MS,
  );
  return result.code === 0;
}

/** Tears down every sshepherd ControlMaster (`hosts disconnect --all`); returns how many
 *  were up. Sockets are named by alias hash, so this walks the socket directory instead. */
export async function closeAllMasters(
  deps: TransportDeps = { runner: defaultRunner },
): Promise<number> {
  const dir = socketDir();
  let names: string[];
  try {
    names = readdirSync(dir).filter((name) => name.endsWith('.sock'));
  } catch {
    return 0;
  }
  let closed = 0;
  for (const name of names) {
    const result = await deps.runner(
      ['-o', `ControlPath=${join(dir, name)}`, '-O', 'exit', DISCONNECT_PLACEHOLDER_HOST],
      CONTROL_COMMAND_TIMEOUT_MS,
    );
    if (result.code === 0) {
      closed += 1;
    }
  }
  return closed;
}

async function defaultRunner(args: string[], timeoutMs: number): Promise<SpawnOutcome> {
  const proc = Bun.spawn(['ssh', ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: 'ignore',
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill();
  }, timeoutMs);

  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  clearTimeout(timer);

  return { code, stdout, stderr, timedOut };
}

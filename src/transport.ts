import { mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ErrorInfo, RawResult, SshErrorCode } from './types.ts';

/** macOS caps a Unix-domain socket path at ~104 bytes (Linux at 108) — stay under 100. */
const MAX_SOCKET_PATH_LENGTH = 100;

const CONNECT_TIMEOUT_S = 10;
const CONTROL_PERSIST_S = 60;
const CONTROL_COMMAND_TIMEOUT_MS = 5_000;
const VALIDATE_TIMEOUT_MS = 5_000;
const MASTER_OPEN_TIMEOUT_MS = (CONNECT_TIMEOUT_S + 5) * 1_000;
const LOCAL_TIMEOUT_BUFFER_MS = 2_000;

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
}

export interface TransportResult {
  raw: RawResult;
  error: ErrorInfo | null;
}

const ERROR_MESSAGES: Record<SshErrorCode, string> = {
  UNKNOWN_ALIAS: 'SSH alias is not defined in ssh config',
  CONNECT_TIMEOUT: 'Connection to the remote host timed out',
  AUTH_FAILED: 'SSH authentication failed for this alias',
  HOST_KEY_MISMATCH: 'Remote host key does not match the known host entry',
  SSH_TRANSPORT_ERROR: 'SSH transport failed before the command could run',
  COMMAND_FAILED: 'Remote command exited with a non-zero status',
  COMMAND_TIMEOUT: 'Remote command timed out',
};

function errorInfo(code: SshErrorCode, remoteExit?: number): ErrorInfo {
  const info: ErrorInfo = { code, message: ERROR_MESSAGES[code] };
  if (remoteExit !== undefined) {
    info.remote_exit = remoteExit;
  }
  return info;
}

/**
 * Reads `raw.transportStderr` only to decide the code, never to build the message —
 * the stderr text is discarded after this function returns. No redaction allowlist:
 * OpenSSH stderr phrasing varies by version/locale, so discard-entirely is the only
 * shape that can't eventually leak an IP or hostname.
 */
export function classify(raw: RawResult): ErrorInfo | null {
  if (raw.timedOut) {
    return errorInfo('COMMAND_TIMEOUT');
  }
  if (raw.code === 255) {
    const text = raw.transportStderr;
    if (/connection timed out|operation timed out/i.test(text)) {
      return errorInfo('CONNECT_TIMEOUT');
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

/** Opaque, short, deterministic per alias — never `%h`/`%r`/`%p` (those leak host/user/port). */
function socketPath(alias: string): string {
  const dir = socketDir();
  const name = Bun.hash.crc32(alias).toString(36);
  const full = join(dir, `${name}.sock`);
  if (full.length >= MAX_SOCKET_PATH_LENGTH) {
    throw new Error(
      `ControlPath socket path is ${full.length} chars, must stay under ${MAX_SOCKET_PATH_LENGTH}`,
    );
  }
  return full;
}

/** Never parse `-G` output into a variable that escapes this function — presence only. */
async function validateAlias(alias: string, runner: SshRunner): Promise<boolean> {
  const result = await runner(['-G', alias], VALIDATE_TIMEOUT_MS);
  return result.code === 0 && result.stdout.trim().length > 0;
}

async function ensureMaster(alias: string, runner: SshRunner): Promise<string> {
  mkdirSync(socketDir(), { recursive: true, mode: 0o700 });
  const sock = socketPath(alias);

  const check = await runner(
    ['-o', `ControlPath=${sock}`, '-O', 'check', alias],
    CONTROL_COMMAND_TIMEOUT_MS,
  );
  if (check.code === 0) {
    return sock;
  }

  // Defensively clear a stale socket left behind by a crashed prior run.
  await runner(['-o', `ControlPath=${sock}`, '-O', 'exit', alias], CONTROL_COMMAND_TIMEOUT_MS);

  await runner(
    [
      '-o',
      'BatchMode=yes',
      '-o',
      `ConnectTimeout=${CONNECT_TIMEOUT_S}`,
      '-o',
      'LogLevel=ERROR',
      '-o',
      'ControlMaster=auto',
      '-o',
      `ControlPath=${sock}`,
      '-o',
      `ControlPersist=${CONTROL_PERSIST_S}`,
      '-M',
      '-N',
      '-f',
      alias,
    ],
    MASTER_OPEN_TIMEOUT_MS,
  );

  return sock;
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
  const aliasOk = await validateAlias(alias, deps.runner);
  if (!aliasOk) {
    return {
      raw: { code: -1, stdout: '', transportStderr: '', commandStderr: '', timedOut: false },
      error: errorInfo('UNKNOWN_ALIAS'),
    };
  }

  const sock = await ensureMaster(alias, deps.runner);

  const outcome = await deps.runner(
    [
      '-o',
      'BatchMode=yes',
      '-o',
      'LogLevel=ERROR',
      '-o',
      `ControlPath=${sock}`,
      alias,
      '--',
      'timeout',
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

  return { raw, error: classify(raw) };
}

/** CLI calls this at shutdown to tear down the ControlMaster for an alias. */
export async function closeMaster(
  alias: string,
  deps: TransportDeps = { runner: defaultRunner },
): Promise<void> {
  const sock = socketPath(alias);
  await deps.runner(['-o', `ControlPath=${sock}`, '-O', 'exit', alias], CONTROL_COMMAND_TIMEOUT_MS);
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

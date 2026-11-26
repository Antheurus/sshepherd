import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeError, errorInfo } from './errors.ts';
import {
  CONNECT_TIMEOUT_SEC,
  CONTROL_PERSIST_SEC,
  KILL_AFTER_SEC,
  MAX_STDOUT_BYTES,
} from './limits.ts';
import { configMayDeclare, readSshConfigNames } from './parsers/ssh-config.ts';
import type { ConnectionIdentity } from './scrub.ts';
import { defaultSshConfigPath } from './setup-ssh-alias.ts';
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
/** On every connection sshepherd opens: a key known_hosts lacks or contradicts is refused, never
 *  accepted on first use, whatever the user's ssh config says (`-o` beats the config file). */
export const STRICT_HOST_KEY_ARGS = ['-o', 'StrictHostKeyChecking=yes'];

/** What a single `ssh` invocation returns — captured stdout/stderr as one opaque stream. */
export interface SpawnOutcome {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** stdout reached `MAX_STDOUT_BYTES`; `stdout` holds the kept part, `code` is then the kill's. */
  stdoutTruncated?: boolean;
}

/** What to do when stdout reaches `MAX_STDOUT_BYTES`. `kill-head` stops the ssh client and keeps
 *  the first bytes (a read op: the rest is not wanted). `drain-tail` keeps reading, keeps the last
 *  bytes and never kills: a mutating op must run to its end, and its last lines say how it ended. */
export type StdoutCapPolicy = 'kill-head' | 'drain-tail';

export interface RunnerOptions {
  stdoutCap?: StdoutCapPolicy;
  /** Read ceiling in place of `MAX_STDOUT_BYTES` (an op's `maxStdoutBytes`). */
  stdoutMaxBytes?: number;
}

/**
 * Injected in tests with a fake implementation so transport/classification tests never
 * touch a real network or a real `ssh` binary.
 */
export type SshRunner = (
  args: string[],
  timeoutMs: number,
  options?: RunnerOptions,
) => Promise<SpawnOutcome>;

export interface TransportDeps {
  runner: SshRunner;
  /** ssh client config used to tell a declared alias from a bare hostname; defaults to `~/.ssh/config`. */
  sshConfigPath?: string;
}

export interface TransportResult {
  raw: RawResult;
  error: ErrorInfo | null;
  /** What `ssh -G` resolved the alias to — handed to the scrubber to mask, never put in an envelope. */
  identity?: ConnectionIdentity;
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

/** busybox `timeout` hands back the child's own status (143 after TERM, or whatever a `docker exec`
 *  client exits with) instead of GNU's 124, so exit codes alone miss a timeout there. A non-zero
 *  exit that took the whole budget is one: the remote clock starts after the local one, so a real
 *  timeout always measures at least `timeoutSec` locally. ssh's own 255 is a transport failure. */
function ranOutOfBudget(raw: RawResult, ctx: ClassifyContext): boolean {
  if (raw.code === 0 || raw.code === 255 || ctx.timeoutSec === undefined) {
    return false;
  }
  return ctx.elapsedMs !== undefined && ctx.elapsedMs >= ctx.timeoutSec * 1_000;
}

/**
 * Reads `raw.transportStderr` only to decide the code, never to build the message —
 * the stderr text is discarded after this function returns. No redaction allowlist:
 * OpenSSH stderr phrasing varies by version/locale, so discard-entirely is the only
 * shape that can't eventually leak an IP or hostname.
 */
export function classify(raw: RawResult, ctx: ClassifyContext = {}): ErrorInfo | null {
  if (raw.timedOut || REMOTE_TIMEOUT_EXIT_CODES.includes(raw.code) || ranOutOfBudget(raw, ctx)) {
    return commandTimeoutInfo(ctx);
  }
  if (raw.code === 255) {
    const text = raw.transportStderr;
    if (/connection timed out|operation timed out/i.test(text)) {
      return connectTimeoutInfo(ctx.elapsedMs);
    }
    // The changed-key banner also ends in "Host key verification failed", so it is tested first.
    if (/remote host identification has changed|host key for .* has changed/i.test(text)) {
      return errorInfo('HOST_KEY_CHANGED');
    }
    if (/host key verification failed|no \S+ host key is known for/i.test(text)) {
      return errorInfo('HOST_KEY_UNKNOWN');
    }
    if (/permission denied|too many authentication failures/i.test(text)) {
      return errorInfo('AUTH_FAILED');
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

/** The hostname (unless it is the alias itself), user and non-22 port `ssh -G` printed. */
function identityOf(sshG: string, alias: string): ConnectionIdentity {
  const field = (name: string): string | undefined =>
    new RegExp(`^${name}\\s+(\\S+)`, 'im').exec(sshG)?.[1];
  const hostname = field('hostname');
  const user = field('user');
  const port = field('port');
  return {
    ...(hostname !== undefined && hostname.toLowerCase() !== alias.toLowerCase()
      ? { hostname }
      : {}),
    ...(user !== undefined ? { user } : {}),
    ...(port !== undefined && port !== '22' ? { port } : {}),
  };
}

/** `ssh -G <anything>` exits 0 even for a name no config declares — it just echoes the name back
 *  as the hostname. So an alias is unknown when `-G` fails, or when it resolved to itself AND
 *  nothing in the config (followed through `Include`) can apply to it: no literal `Host` entry,
 *  no matching wildcard `Host` line, no `Match` block. A known alias's hostname, user and port are
 *  kept only as the scrubber's `identity`, never returned in an error or a result. */
export async function resolveAlias(
  alias: string,
  deps: TransportDeps,
): Promise<{ error: ErrorInfo | null; identity: ConnectionIdentity }> {
  const result = await deps.runner(['-G', alias], VALIDATE_TIMEOUT_MS);
  const resolved = result.code === 0 && result.stdout.trim().length > 0;
  const resolvedHost = /^hostname\s+(\S+)/im.exec(result.stdout)?.[1];
  const echoed = resolvedHost !== undefined && resolvedHost.toLowerCase() === alias.toLowerCase();
  const identity = resolved ? identityOf(result.stdout, alias) : {};
  if (resolved && !echoed) {
    return { error: null, identity };
  }
  const names = readSshConfigNames(deps.sshConfigPath ?? defaultSshConfigPath());
  if (resolved && configMayDeclare(names, alias)) {
    return { error: null, identity };
  }
  return {
    error: describeError('UNKNOWN_ALIAS', `ssh alias '${alias}' is not defined in ssh config`, {
      did_you_mean: didYouMean(alias, names.aliases),
    }),
    identity: {},
  };
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
      ...STRICT_HOST_KEY_ARGS,
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
  options: RunnerOptions = {},
): Promise<TransportResult> {
  const { error: unknownAlias, identity } = await resolveAlias(alias, deps);
  if (unknownAlias) {
    return {
      raw: { code: -1, stdout: '', transportStderr: '', commandStderr: '', timedOut: false },
      error: unknownAlias,
    };
  }

  const master = await ensureMaster(alias, deps.runner);
  if (master.failure) {
    return { ...master.failure, identity };
  }

  const startedAtMs = Date.now();
  const outcome = await deps.runner(
    [
      ...STRICT_HOST_KEY_ARGS,
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
    options,
  );

  // A kill-head cut is ours, not the remote command's: its exit code says nothing, so the
  // call counts as a clean one that returned a prefix.
  const killedAtCap = outcome.stdoutTruncated === true && options.stdoutCap !== 'drain-tail';
  // ssh exits 255 for its own transport failures; any other code is the remote command's.
  const raw: RawResult = {
    code: killedAtCap ? 0 : outcome.code,
    stdout: outcome.stdout,
    transportStderr: raw255(outcome, killedAtCap) ? outcome.stderr : '',
    commandStderr: raw255(outcome, killedAtCap) ? '' : outcome.stderr,
    timedOut: outcome.timedOut,
    ...(outcome.stdoutTruncated ? { outputTruncated: true } : {}),
  };

  return {
    raw,
    error: classify(raw, { timeoutSec, elapsedMs: Date.now() - startedAtMs }),
    identity,
  };
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

export interface ScannedHostKey {
  /** The known_hosts name ssh itself wrote for the alias (`host`, or `[host]:port`) — local use
   *  only, never returned in an envelope. */
  name: string;
  type: string;
  /** Base64 public key blob. */
  key: string;
}

export type HostKeyScan =
  | { keys: ScannedHostKey[]; knownHostsFile: string; hashNames: boolean; error: null }
  | { error: ErrorInfo };

/** ssh's own expanded config for the alias: the first `UserKnownHostsFile` (where a trusted key
 *  is recorded) and whether names there are hashed. */
async function knownHostsConfig(
  alias: string,
  deps: TransportDeps,
): Promise<{ knownHostsFile: string; hashNames: boolean } | null> {
  const result = await deps.runner(['-G', alias], VALIDATE_TIMEOUT_MS);
  const file = /^userknownhostsfile\s+(\S+)/im.exec(result.stdout)?.[1];
  if (result.code !== 0 || file === undefined) {
    return null;
  }
  const knownHostsFile = file.startsWith('~/') ? join(homedir(), file.slice(2)) : file;
  return { knownHostsFile, hashNames: /^hashknownhosts\s+yes/im.test(result.stdout) };
}

/** The key the host presents, fetched the way ssh itself would see it (same `-F` config, so the
 *  same HostName/Port/HostKeyAlias): one connection that may record the key only into a
 *  throwaway known_hosts, offers no authentication method so nothing runs on the unverified host,
 *  and bypasses any ControlMaster so a real key exchange happens. The caller decides whether the
 *  key is trusted; the real known_hosts is never touched here. */
export async function scanHostKeys(
  alias: string,
  deps: TransportDeps = { runner: defaultRunner },
): Promise<HostKeyScan> {
  const { error: unknownAlias } = await resolveAlias(alias, deps);
  if (unknownAlias) {
    return { error: unknownAlias };
  }
  const config = await knownHostsConfig(alias, deps);
  if (config === null) {
    return { error: errorInfo('SSH_TRANSPORT_ERROR') };
  }
  const scratch = mkdtempSync(join(tmpdir(), 'sshepherd-hostkey-'));
  const scratchFile = join(scratch, 'known_hosts');
  try {
    const startedAtMs = Date.now();
    const outcome = await deps.runner(
      [
        '-T',
        '-o',
        'BatchMode=yes',
        '-o',
        `ConnectTimeout=${CONNECT_TIMEOUT_SEC}`,
        '-o',
        'LogLevel=ERROR',
        '-o',
        'ControlMaster=no',
        '-o',
        'ControlPath=none',
        '-o',
        'StrictHostKeyChecking=accept-new',
        '-o',
        `UserKnownHostsFile=${scratchFile}`,
        '-o',
        'GlobalKnownHostsFile=/dev/null',
        '-o',
        'HashKnownHosts=no',
        '-o',
        'UpdateHostKeys=no',
        '-o',
        'PreferredAuthentications=none',
        alias,
        'true',
      ],
      MASTER_OPEN_TIMEOUT_MS,
    );
    let text = '';
    try {
      text = readFileSync(scratchFile, 'utf8');
    } catch {
      // no file: ssh never got as far as the key exchange
    }
    const keys = text
      .split('\n')
      .map((line) => line.trim().split(/\s+/))
      .filter((fields): fields is [string, string, string] => fields.length >= 3)
      .map(([name, type, key]) => ({ name, type, key }));
    if (keys.length > 0) {
      return { keys, ...config, error: null };
    }
    const elapsedMs = Date.now() - startedAtMs;
    if (outcome.timedOut) {
      return { error: connectTimeoutInfo(elapsedMs) };
    }
    const raw: RawResult = {
      code: 255,
      stdout: '',
      transportStderr: outcome.stderr,
      commandStderr: '',
      timedOut: false,
    };
    return { error: classify(raw, { elapsedMs }) ?? errorInfo('SSH_TRANSPORT_ERROR') };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** `-F <path>` when `SSHEPHERD_SSH_CONFIG_PATH` is set (the smoke fixture's own config), so a
 *  run never needs a stanza in the real `~/.ssh/config`; empty when unset. */
export function sshConfigArgs(): string[] {
  const override = process.env.SSHEPHERD_SSH_CONFIG_PATH;
  return override && override.length > 0 ? ['-F', override] : [];
}

/** A killed client exits non-zero with whatever stderr it had; that is not an ssh failure. */
function raw255(outcome: SpawnOutcome, killedAtCap: boolean): boolean {
  return outcome.code === 255 && !killedAtCap;
}

interface CappedRead {
  text: string;
  truncated: boolean;
}

/** Reads `stream` keeping at most `cap` bytes: the first ones (`head`, stops reading and calls
 *  `onCap` at the cap) or the last ones (`tail`, reads to the end). */
export async function readCapped(
  stream: ReadableStream<Uint8Array>,
  cap: number,
  keep: 'head' | 'tail',
  onCap: () => void,
): Promise<CappedRead> {
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let kept = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    const chunk = Buffer.from(value);
    if (keep === 'head') {
      const room = cap - kept;
      if (chunk.length <= room) {
        chunks.push(chunk);
        kept += chunk.length;
        continue;
      }
      chunks.push(chunk.subarray(0, room));
      truncated = true;
      onCap();
      await reader.cancel();
      break;
    }
    chunks.push(chunk);
    kept += chunk.length;
    while (chunks.length > 1 && kept - (chunks[0]?.length ?? 0) >= cap) {
      kept -= chunks.shift()?.length ?? 0;
      truncated = true;
    }
  }
  let all = Buffer.concat(chunks);
  if (all.length > cap) {
    truncated = true;
    all = keep === 'head' ? all.subarray(0, cap) : all.subarray(all.length - cap);
  }
  return { text: all.toString('utf8'), truncated };
}

export async function defaultRunner(
  args: string[],
  timeoutMs: number,
  options: RunnerOptions = {},
): Promise<SpawnOutcome> {
  const proc = Bun.spawn(['ssh', ...sshConfigArgs(), ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: 'ignore',
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill();
  }, timeoutMs);

  const keep = options.stdoutCap === 'drain-tail' ? 'tail' : 'head';
  const [stdout, stderr, code] = await Promise.all([
    readCapped(proc.stdout, options.stdoutMaxBytes ?? MAX_STDOUT_BYTES, keep, () => proc.kill()),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  clearTimeout(timer);

  return { code, stdout: stdout.text, stderr, timedOut, stdoutTruncated: stdout.truncated };
}

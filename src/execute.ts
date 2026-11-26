import { type AuditOutcome, auditMutating, confirmGate } from './audit.ts';
import { describeError, errorInfo, fillNext } from './errors.ts';
import { MAX_PARTIAL_STDOUT_CHARS, MAX_TIMEOUT_SEC } from './limits.ts';
import { assertOpPositionals, optBool } from './op-args.ts';
import { enforceAllowlist, loadScrubExtraPatterns, revealKeysOf } from './ops/config.ts';
import { buildEnvelope, splitNdjson } from './output.ts';
import { type ScrubOptions, scrub } from './scrub.ts';
import { defaultSshConfigPath } from './setup-ssh-alias.ts';
import { run, type TransportDeps } from './transport.ts';
import {
  type Envelope,
  type ErrorInfo,
  type OpContext,
  OpError,
  type OpSpec,
  type OutputMode,
} from './types.ts';

/** `op.timeoutSec` is the per-op default; the CLI's global `--timeout` arrives as
 *  `deps.timeoutSec` and applies to every op, bounded by the shared ceiling. */
function effectiveTimeoutSec(op: OpSpec, deps: ExecuteDeps): number {
  return Math.min(deps.timeoutSec ?? op.timeoutSec, MAX_TIMEOUT_SEC);
}

/** A timed-out command's stdout so far is still the legitimate payload — return it
 *  (capped) so a "almost done" step is visible instead of lost. */
function partialStdout(error: ErrorInfo, stdout: string): Record<string, unknown> | undefined {
  if (error.code !== 'COMMAND_TIMEOUT' || stdout.length === 0) {
    return undefined;
  }
  return { partial_stdout: stdout.slice(0, MAX_PARTIAL_STDOUT_CHARS) };
}

/** `error.stderr_tail` is the last 20 lines of a failed command's stderr, then at most its last
 *  2 KiB: enough for the error and its context lines, never a dump of a chatty command. */
const STDERR_TAIL_MAX_LINES = 20;
const STDERR_TAIL_MAX_BYTES = 2_048;

/** Cut after scrubbing, so a cut can never split a `KEY=value` pair into an unrecognised one. */
function stderrTail(scrubbedStderr: string): string {
  const lines = scrubbedStderr.trimEnd().split('\n');
  const tail = lines.slice(-STDERR_TAIL_MAX_LINES).join('\n');
  const bytes = Buffer.from(tail, 'utf8');
  if (bytes.length <= STDERR_TAIL_MAX_BYTES) {
    return tail;
  }
  return bytes.subarray(bytes.length - STDERR_TAIL_MAX_BYTES).toString('utf8');
}

/** Keys a `--reveal` named (already cleared by `enforceAllowlist`) plus the alias's own extra
 *  patterns. Loaded before the op runs, so a malformed reveal-allowlist.toml fails the op up front. */
function scrubOptionsFor(op: OpSpec, ctx: OpContext): ScrubOptions {
  const reveal = op.allowlist?.find((policy) => policy.kind === 'reveal-keys');
  return {
    revealKeys: reveal ? revealKeysOf(ctx, reveal.argName) : new Set(),
    extraPatterns: loadScrubExtraPatterns(ctx.alias),
  };
}

function hiddenValues(op: OpSpec, ctx: OpContext): string[] {
  return (op.hiddenArgs ?? [])
    .map((name) => ctx.args[name])
    .filter((value): value is string => typeof value === 'string' && value.length > 0);
}

/**
 * The one scrub pass over an envelope: the shaped data when the op exposes anything, every
 * error (message, `data`, partial stdout on the error path) and the command's stderr, which then
 * becomes `stderr_tail`. Revealed keys are honoured only on success — an error never unmasks —
 * and an op's `hiddenArgs` values are masked only in errors, where they would be echoed.
 */
function scrubEnvelope(
  op: OpSpec,
  ctx: OpContext,
  envelope: Envelope<unknown>,
  commandStderr: string,
  options: ScrubOptions,
): Envelope<unknown> {
  const scrubData = envelope.error !== null || op.exposes !== 'none';
  const effective =
    envelope.error === null
      ? options
      : { ...options, revealKeys: new Set<string>(), literals: hiddenValues(op, ctx) };
  const { value, count } = scrub(
    { data: scrubData ? envelope.data : null, error: envelope.error, stderr: commandStderr },
    effective,
  );
  const tail = stderrTail(value.stderr);
  const error =
    value.error !== null && tail.length > 0 ? { ...value.error, stderr_tail: tail } : value.error;
  return { ...envelope, data: scrubData ? value.data : envelope.data, error, scrubbed: count };
}

export interface ExecuteDeps {
  transport?: TransportDeps;
  sshConfigPath?: string;
  /** Confirms a mutating op — the CLI (Phase 6) sets this after `--yes` or an interactive prompt. */
  yes?: boolean;
  /** The CLI's `--timeout <sec>`: replaces the op's default budget. */
  timeoutSec?: number;
  /** Overrides `auditMutating`'s log path — tests point this at a temp file. */
  auditLogPath?: string;
}

function parseByMode(mode: OutputMode, stdout: string): unknown {
  if (mode === 'native-json') {
    return stdout.trim().length > 0 ? JSON.parse(stdout) : null;
  }
  if (mode === 'ndjson') {
    return splitNdjson(stdout);
  }
  if (mode === 'raw') {
    return stdout;
  }
  return mode.parse(stdout);
}

function auditFor(
  deps: ExecuteDeps,
  alias: string,
  command: string,
  ctx: OpContext,
  outcome: AuditOutcome,
): void {
  auditMutating(
    { alias, command, argsSummary: ctx.args, outcome },
    deps.auditLogPath ? { logPath: deps.auditLogPath } : undefined,
  );
}

/** Every `OpError` the op raises, on its way into an envelope. */
function opErrorInfo(err: OpError): ErrorInfo {
  return describeError(err.code, err.message, err.extras);
}

/** Anything else that escapes an op: the message is withheld (a JSON.parse error quotes the
 *  remote output, which can carry file contents) — only the error class names what broke. */
export function internalErrorInfo(command: string, err: unknown): ErrorInfo {
  const kind = err instanceof Error ? err.name : typeof err;
  return describeError('INTERNAL_ERROR', `'${command}' failed inside sshepherd (${kind})`);
}

interface OpResult {
  envelope: Envelope<unknown>;
  outcome: AuditOutcome;
  /** A failed command's stderr (non-255 exits only — the transport blanks it for 255). */
  commandStderr?: string;
}

/**
 * The one place an `OpSpec` is turned into an `Envelope`: gate mutating ops through
 * `confirmGate`/`auditMutating` (the ONE mutating path, no per-op bespoke gating), resolve
 * the remote command (or run the host-local fallback), execute it through `transport.run`
 * (the single execution path), parse per `output`, then `shape` into the final payload.
 * `deploy run --dry-run` executes nothing and mutates nothing, so it is exempt from the
 * gate/audit — every other mutating op requires `--yes` (or an interactive confirm the CLI
 * resolves into `deps.yes`) and always writes exactly one audit line once the op has ended,
 * whether it succeeded, failed, was refused, or threw. Nothing escapes as an exception: a throw
 * becomes an `INVALID_ARGS`/`VALIDATION_ERROR` envelope (the caller's input) or an
 * `INTERNAL_ERROR` one (ours), and an audit line that cannot be written becomes
 * `AUDIT_WRITE_FAILED` carrying the op's own result. The CLI is the only intended caller in production; tests call
 * this directly with a scripted transport so no real ssh/network is ever touched.
 */
export async function executeOp(
  op: OpSpec,
  ctx: OpContext,
  deps: ExecuteDeps = {},
): Promise<Envelope<unknown>> {
  const startedAtMs = Date.now();
  const command = `${op.group} ${op.name}`;
  const requiresConfirm = op.mutating && !optBool(ctx, 'dry-run', false);
  let outcome: AuditOutcome = 'error';
  let envelope: Envelope<unknown>;
  let commandStderr = '';
  let scrubOptions: ScrubOptions = {};
  try {
    scrubOptions = scrubOptionsFor(op, ctx);
    ({
      envelope,
      outcome,
      commandStderr = '',
    } = await runOp(op, ctx, deps, command, requiresConfirm, startedAtMs));
  } catch (err) {
    const error = err instanceof OpError ? opErrorInfo(err) : internalErrorInfo(command, err);
    envelope = buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data: null,
      error: fillNext(error, ctx.alias),
    });
  }
  envelope = scrubEnvelope(op, ctx, envelope, commandStderr, scrubOptions);
  if (!requiresConfirm) {
    return envelope;
  }
  try {
    auditFor(deps, ctx.alias, command, ctx, outcome);
  } catch {
    return unauditedEnvelope(envelope, command, outcome);
  }
  return envelope;
}

/** The op has already run (or been refused) by the time its audit line fails, so its result is
 *  kept and flagged instead of discarded. The fs error is withheld: it quotes the log path. */
function unauditedEnvelope(
  envelope: Envelope<unknown>,
  command: string,
  outcome: AuditOutcome,
): Envelope<unknown> {
  const error: ErrorInfo = {
    ...describeError(
      'AUDIT_WRITE_FAILED',
      `'${command}' finished with outcome '${outcome}' but its audit line could not be written to the audit log`,
    ),
    op_outcome: outcome,
  };
  if (envelope.error !== null) {
    error.op_error = envelope.error;
  }
  return { ...envelope, ok: false, error };
}

async function runOp(
  op: OpSpec,
  ctx: OpContext,
  deps: ExecuteDeps,
  command: string,
  requiresConfirm: boolean,
  startedAtMs: number,
): Promise<OpResult> {
  const finish = (data: unknown, error: ErrorInfo | null, outcome: AuditOutcome): OpResult => ({
    envelope: buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data,
      error: error === null ? null : fillNext(error, ctx.alias),
    }),
    outcome,
  });

  if (!confirmGate({ mutating: requiresConfirm, yes: deps.yes ?? false })) {
    return finish(null, errorInfo('CONFIRMATION_REQUIRED'), 'refused');
  }

  assertOpPositionals(op, ctx);
  enforceAllowlist(op.allowlist, ctx);
  const remoteCmd = op.buildRemote(ctx);

  if (remoteCmd === null) {
    if (!op.runLocal) {
      throw new Error(
        `registry: op '${command}' has no buildRemote output and no runLocal fallback`,
      );
    }
    const sshConfigPath = deps.sshConfigPath ?? defaultSshConfigPath();
    try {
      const data = await op.runLocal(ctx, sshConfigPath, deps.transport);
      return finish(data, null, 'ok');
    } catch (err) {
      if (err instanceof OpError) {
        return finish(null, opErrorInfo(err), 'error');
      }
      throw err;
    }
  }

  const result = await run(
    ctx.alias,
    remoteCmd,
    effectiveTimeoutSec(op, deps),
    withConfigPath(deps),
  );
  if (result.error) {
    const data =
      op.shapeError?.(result.raw, ctx) ?? partialStdout(result.error, result.raw.stdout) ?? null;
    const errorData = op.errorData?.(result.raw.commandStderr);
    const error = errorData ? { ...result.error, data: errorData } : result.error;
    return {
      ...finish(data, error, 'error'),
      commandStderr: op.exposeStderr === false ? '' : result.raw.commandStderr,
    };
  }

  const parsed = parseByMode(op.output, result.raw.stdout);
  return finish(op.shape(parsed, ctx), null, 'ok');
}

/** The transport validates an alias against the same ssh config `hosts list` reads. */
function withConfigPath(deps: ExecuteDeps): TransportDeps | undefined {
  if (deps.sshConfigPath === undefined) {
    return deps.transport;
  }
  return deps.transport && { ...deps.transport, sshConfigPath: deps.sshConfigPath };
}

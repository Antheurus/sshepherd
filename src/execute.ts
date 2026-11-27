import {
  AUDIT_IDENTIFIER_ARGS,
  type AuditIdentifier,
  type AuditOutcome,
  AuditWriteError,
  auditMutating,
  confirmGate,
} from './audit.ts';
import { auditUnwritableWarning, describeError, errorInfo, fillNext } from './errors.ts';
import {
  DEFAULT_MAX_BYTES,
  MAX_PARTIAL_STDOUT_CHARS,
  MAX_STDOUT_BYTES,
  MAX_TIMEOUT_SEC,
} from './limits.ts';
import { assertOpPositionals, optBool } from './op-args.ts';
import {
  enforceAllowlist,
  loadRevealAddresses,
  loadScrubExtraPatterns,
  revealKeysOf,
} from './ops/config.ts';
import {
  buildEnvelope,
  capEnvelope,
  limitItems,
  selectFields,
  serializeJson,
  splitNdjson,
} from './output.ts';
import { profileDenial } from './profiles.ts';
import {
  type ConnectionIdentity,
  isEnvFile,
  maskEnvContent,
  maskPemBodyChunks,
  maskPemLines,
  type ScrubOptions,
  scrub,
} from './scrub.ts';
import { defaultSshConfigPath } from './setup-ssh-alias.ts';
import { run, type TransportDeps } from './transport.ts';
import {
  type Envelope,
  type ErrorInfo,
  type OpContext,
  OpError,
  type OpSpec,
  type OutputMode,
  Premasked,
} from './types.ts';

/** `op.timeoutSec` is the per-op default; the CLI's global `--timeout` arrives as
 *  `deps.timeoutSec` and applies to every op, bounded by the shared ceiling. */
function effectiveTimeoutSec(op: OpSpec, deps: ExecuteDeps): number {
  return Math.min(deps.timeoutSec ?? op.timeoutSec, MAX_TIMEOUT_SEC);
}

/** A timed-out command's stdout so far is still the legitimate payload — return it so a "almost
 *  done" step is visible instead of lost. An op reading an env-shaped allowlisted path gets the
 *  same whole-file masking its `shape` would have applied, and every op gets the line-array
 *  key-body pass `logs *` runs on its lines. It is capped by `capPartialStdout` only after the
 *  envelope is scrubbed, so a cut can never leave a quoted value unclosed or an env block too
 *  short for the env-block pass. */
function partialStdout(
  op: OpSpec,
  ctx: OpContext,
  error: ErrorInfo,
  stdout: string,
): Record<string, unknown> | undefined {
  if (error.code !== 'COMMAND_TIMEOUT' || stdout.length === 0) {
    return undefined;
  }
  const pathPolicy = op.allowlist?.find((policy) => policy.kind === 'path');
  const path = pathPolicy ? ctx.args[pathPolicy.argName] : undefined;
  const text =
    typeof path === 'string' && isEnvFile(path) ? maskEnvContent(stdout, new Set()) : stdout;
  const lines = maskPemBodyChunks(maskPemLines(text.split('\n'))).join('\n');
  return { partial_stdout: lines };
}

/** Cuts a scrubbed envelope's `data.partial_stdout` to `MAX_PARTIAL_STDOUT_CHARS`. */
function capPartialStdout(envelope: Envelope<unknown>): Envelope<unknown> {
  const data = envelope.data;
  if (typeof data !== 'object' || data === null || !('partial_stdout' in data)) {
    return envelope;
  }
  const stdout = data.partial_stdout;
  if (typeof stdout !== 'string' || stdout.length <= MAX_PARTIAL_STDOUT_CHARS) {
    return envelope;
  }
  return {
    ...envelope,
    data: { ...data, partial_stdout: stdout.slice(0, MAX_PARTIAL_STDOUT_CHARS) },
  };
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

/** Keys a `--reveal` named (already cleared by `enforceAllowlist`), the alias's own extra
 *  patterns and its `reveal_addresses` opt-out. Loaded before the op runs, so a malformed
 *  reveal-allowlist.toml fails the op up front. */
function scrubOptionsFor(op: OpSpec, ctx: OpContext): ScrubOptions {
  const reveal = op.allowlist?.find((policy) => policy.kind === 'reveal-keys');
  return {
    revealKeys: reveal ? revealKeysOf(ctx, reveal.argName) : new Set(),
    extraPatterns: loadScrubExtraPatterns(ctx.alias),
    maskAddresses: !loadRevealAddresses(ctx.alias),
    maskEnvBlocks: op.maskEnvBlocks === true,
  };
}

function argValues(names: string[] | undefined, ctx: OpContext): string[] {
  return (names ?? [])
    .map((name) => ctx.args[name])
    .filter((value): value is string => typeof value === 'string' && value.length > 0);
}

/**
 * The one scrub pass over an envelope: the shaped data, whatever the op's `exposes` label says (a
 * label is a claim about the op, never a switch on the scrubber), every error (message, `data`,
 * partial stdout on the error path) and the command's stderr, which then
 * becomes `stderr_tail`. Revealed keys are honoured only on success — an error never unmasks —
 * and an op's `hiddenArgs` values are masked only in errors, where they would be echoed. The
 * alias's identity is always masked, and IP literals are too unless the alias opted out (also
 * when the options never loaded, e.g. a reveal-allowlist.toml that failed to parse).
 */
function scrubEnvelope(
  op: OpSpec,
  ctx: OpContext,
  envelope: Envelope<unknown>,
  commandStderr: string,
  options: ScrubOptions,
): Envelope<unknown> {
  const withAddresses = { ...options, maskAddresses: options.maskAddresses ?? true };
  const effective =
    envelope.error === null
      ? withAddresses
      : {
          ...withAddresses,
          revealKeys: new Set<string>(),
          literals: argValues(op.hiddenArgs, ctx),
          echoText: argValues(op.echoArgs, ctx).join('\n'),
        };
  const { value, count } = scrub(
    { data: envelope.data, error: envelope.error, stderr: commandStderr },
    effective,
  );
  const tail = stderrTail(value.stderr);
  const error =
    value.error !== null && tail.length > 0 ? { ...value.error, stderr_tail: tail } : value.error;
  return { ...envelope, data: value.data, error, scrubbed: count };
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
  /** The CLI's `--max-bytes`: the printed envelope never exceeds it (default `DEFAULT_MAX_BYTES`). */
  maxBytes?: number;
  /** The CLI's `--fields`, parsed: dot paths of `data` to keep. */
  fields?: string[][];
  /** The CLI's `--limit`: items kept per list in `data`. */
  limit?: number;
}

/** An op whose newest output matters (`logs *`, `files tail`) reads a too-long stream to its end and
 *  keeps the last bytes, instead of stopping at the first ones. */
function keepsTail(op: OpSpec): boolean {
  return op.truncateKeeps === 'tail';
}

/** A stream cut from the front starts mid-line; that fragment is not a line of the output. */
function dropPartialFirstLine(stdout: string): string {
  return stdout.slice(stdout.indexOf('\n') + 1);
}

function parseByMode(mode: OutputMode, stdout: string, cutShort: boolean): unknown {
  if (mode === 'native-json') {
    return stdout.trim().length > 0 ? JSON.parse(stdout) : null;
  }
  if (mode === 'ndjson') {
    // A cut-short stream ends mid-line; the unfinished line is not JSON and is dropped.
    return splitNdjson(cutShort ? stdout.slice(0, stdout.lastIndexOf('\n') + 1) : stdout);
  }
  if (mode === 'raw') {
    return stdout;
  }
  return mode.parse(stdout);
}

/** The names (recipe, target, container, unit) that say what an audited op ran on. Anything the op
 *  resolved from local config and hides from its envelope (`hiddenArgs`) stays out of the log too. */
function auditIdentifiers(op: OpSpec, ctx: OpContext): Partial<Record<AuditIdentifier, string>> {
  const identifiers: Partial<Record<AuditIdentifier, string>> = {};
  for (const name of AUDIT_IDENTIFIER_ARGS) {
    const value = ctx.args[name];
    if (typeof value === 'string' && value.length > 0 && !op.hiddenArgs?.includes(name)) {
      identifiers[name] = value;
    }
  }
  return identifiers;
}

function auditFor(
  deps: ExecuteDeps,
  op: OpSpec,
  alias: string,
  command: string,
  ctx: OpContext,
  outcome: AuditOutcome,
  envelope: Envelope<unknown>,
): void {
  const ran = outcome !== 'refused';
  auditMutating(
    {
      alias,
      command,
      argsSummary: ctx.args,
      outcome,
      identifiers: auditIdentifiers(op, ctx),
      durationMs: envelope.duration_ms,
      remoteExit: ran
        ? (envelope.error?.remote_exit ?? (envelope.error === null ? 0 : undefined))
        : undefined,
      errorCode: envelope.error?.code,
      bytes: Buffer.byteLength(serializeJson(envelope)),
    },
    deps.auditLogPath ? { logPath: deps.auditLogPath } : undefined,
  );
}

/** Rounds of cap-then-recount: a recount moves the size by a few bytes, so a re-cap settles it in
 *  a round or two; the bound only stops a pathological value from looping. */
const RECOUNT_MAX_ROUNDS = 4;

/** The line cap, `--fields`, `--limit`, then `--max-bytes`, in that order, on the scrubbed
 *  envelope: the cap measures what the caller selected, and runs last so it cannot cut ahead of
 *  the scrubber. After a cut, the op's `recount` makes `data`'s own counters match what is left. */
function shapeOutput(
  op: OpSpec,
  envelope: Envelope<unknown>,
  deps: ExecuteDeps,
  cutAtTransport: boolean,
): Envelope<unknown> {
  let shaped = envelope;
  let cut = cutAtTransport;
  if (op.capLines !== undefined) {
    const capped = op.capLines(shaped.data);
    shaped = { ...shaped, data: capped.data };
    cut = cut || capped.cut;
  }
  const unselected = shaped.data;
  if (deps.fields !== undefined) {
    const { data, unmatched } = selectFields(shaped.data, deps.fields);
    shaped = { ...shaped, data, ...(unmatched.length > 0 ? { fields_unmatched: unmatched } : {}) };
  }
  const selected = shaped.data;
  if (deps.limit !== undefined) {
    const limited = limitItems(shaped.data, deps.limit, op.limitKeeps);
    shaped = { ...shaped, data: limited.data };
    cut = cut || limited.cut;
  }
  if (cut) {
    shaped = { ...shaped, output_truncated: true };
  }
  const maxBytes = deps.maxBytes ?? DEFAULT_MAX_BYTES;
  const keep = op.truncateKeeps ?? 'head';
  let capped = capEnvelope(shaped, maxBytes, keep);
  for (
    let round = 0;
    op.recount && capped.output_truncated && round < RECOUNT_MAX_ROUNDS;
    round++
  ) {
    const recounted = {
      ...capped,
      data: op.recount(selected, capped.data, cutAtTransport, unselected),
    };
    if (Buffer.byteLength(serializeJson(recounted)) <= maxBytes) {
      return recounted;
    }
    capped = capEnvelope(recounted, maxBytes, keep);
  }
  return capped;
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
  /** The transport stopped reading at `MAX_STDOUT_BYTES`. */
  outputTruncated?: boolean;
  /** Values the op's `shape` masked itself (`Premasked`), added to the scrubber's count. */
  premasked?: number;
  /** The alias's resolved hostname/user/port, for the scrubber only. */
  identity?: ConnectionIdentity;
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
 * `INTERNAL_ERROR` one (ours). An audit line that cannot be written leaves a mutating op's own
 * envelope standing with an `AUDIT_UNWRITABLE` warning (the op already ran), and turns a content
 * read into `AUDIT_WRITE_FAILED` carrying its result. The CLI is the only intended caller in production; tests call
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
  const audited = requiresConfirm || (!op.mutating && op.exposes === 'content');
  let outcome: AuditOutcome = 'error';
  let envelope: Envelope<unknown>;
  let commandStderr = '';
  let cutAtTransport = false;
  let premasked = 0;
  let scrubOptions: ScrubOptions = {};
  try {
    scrubOptions = scrubOptionsFor(op, ctx);
    ({
      envelope,
      outcome,
      commandStderr = '',
      outputTruncated: cutAtTransport = false,
      premasked = 0,
      identity: scrubOptions.identity,
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
  envelope = capPartialStdout(scrubEnvelope(op, ctx, envelope, commandStderr, scrubOptions));
  envelope = { ...envelope, scrubbed: envelope.scrubbed + premasked };
  envelope = shapeOutput(op, envelope, deps, cutAtTransport);
  if (!audited) {
    return envelope;
  }
  try {
    auditFor(deps, op, ctx.alias, command, ctx, outcome, envelope);
  } catch (err) {
    if (!requiresConfirm) {
      return unauditedEnvelope(envelope, command, outcome);
    }
    const { role, errno } =
      err instanceof AuditWriteError ? err : { role: 'audit_file' as const, errno: undefined };
    const warned = {
      ...envelope,
      warnings: [...(envelope.warnings ?? []), auditUnwritableWarning(role, errno)],
    };
    return capEnvelope(warned, deps.maxBytes ?? DEFAULT_MAX_BYTES, op.truncateKeeps ?? 'head');
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

  const denied = profileDenial(op, ctx);
  if (denied !== null) {
    return finish(null, denied, 'refused');
  }

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
    {
      stdoutCap: op.mutating || keepsTail(op) ? 'drain-tail' : 'kill-head',
      ...(op.maxStdoutBytes !== undefined ? { stdoutMaxBytes: op.maxStdoutBytes } : {}),
    },
  );
  const outputTruncated = result.raw.outputTruncated === true;
  const { identity } = result;
  if (result.error) {
    const data =
      op.shapeError?.(result.raw, ctx) ??
      partialStdout(op, ctx, result.error, result.raw.stdout) ??
      null;
    const refined = op.refineError?.(result.raw.commandStderr, result.error, ctx) ?? result.error;
    const errorData = op.errorData?.(result.raw.commandStderr);
    const error = errorData ? { ...refined, data: errorData } : refined;
    return {
      ...finish(data, error, 'error'),
      commandStderr: op.exposeStderr === false ? '' : result.raw.commandStderr,
      outputTruncated,
      identity,
    };
  }

  try {
    const tailCut = outputTruncated && keepsTail(op) && !op.mutating;
    const parsed = parseByMode(
      op.output,
      tailCut ? dropPartialFirstLine(result.raw.stdout) : result.raw.stdout,
      outputTruncated && !tailCut,
    );
    const shaped = op.shape(parsed, ctx);
    if (shaped instanceof Premasked) {
      return {
        ...finish(shaped.data, null, 'ok'),
        outputTruncated,
        premasked: shaped.count,
        identity,
      };
    }
    return { ...finish(shaped, null, 'ok'), outputTruncated, identity };
  } catch (err) {
    // An op's own error (files download refusing a short payload) says more than the generic one.
    if (!outputTruncated || err instanceof OpError) {
      throw err;
    }
    throw new OpError(
      'OUTPUT_TOO_LARGE',
      `'${command}' printed more than ${op.maxStdoutBytes ?? MAX_STDOUT_BYTES} bytes, so its output was cut before it could be parsed`,
    );
  }
}

/** The transport validates an alias against the same ssh config `hosts list` reads. */
function withConfigPath(deps: ExecuteDeps): TransportDeps | undefined {
  if (deps.sshConfigPath === undefined) {
    return deps.transport;
  }
  return deps.transport && { ...deps.transport, sshConfigPath: deps.sshConfigPath };
}

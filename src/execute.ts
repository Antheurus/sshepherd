import { homedir } from 'node:os';
import { join } from 'node:path';
import { auditMutating, confirmGate } from './audit.ts';
import { MAX_PARTIAL_STDOUT_CHARS, MAX_TIMEOUT_SEC } from './limits.ts';
import { optBool } from './op-args.ts';
import { enforceAllowlist } from './ops/config.ts';
import { buildEnvelope, splitNdjson } from './output.ts';
import { errorInfo, run, type TransportDeps } from './transport.ts';
import {
  type Envelope,
  type ErrorInfo,
  type OpContext,
  OpRunLocalError,
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
  outcome: 'ok' | 'error' | 'refused',
): void {
  auditMutating(
    { alias, command, argsSummary: ctx.args, outcome },
    deps.auditLogPath ? { logPath: deps.auditLogPath } : undefined,
  );
}

/**
 * The one place an `OpSpec` is turned into an `Envelope`: gate mutating ops through
 * `confirmGate`/`auditMutating` (the ONE mutating path, no per-op bespoke gating), resolve
 * the remote command (or run the host-local fallback), execute it through `transport.run`
 * (the single execution path), parse per `output`, then `shape` into the final payload.
 * `deploy run --dry-run` executes nothing and mutates nothing, so it is exempt from the
 * gate/audit — every other mutating op requires `--yes` (or an interactive confirm the CLI
 * resolves into `deps.yes`) and always writes an audit line, success or failure. The CLI
 * (Phase 6) is the only intended caller in production; tests call this directly with a
 * scripted transport so no real ssh/network is ever touched.
 */
export async function executeOp(
  op: OpSpec,
  ctx: OpContext,
  deps: ExecuteDeps = {},
): Promise<Envelope<unknown>> {
  const startedAtMs = Date.now();
  const command = `${op.group} ${op.name}`;
  const isDryRun = optBool(ctx, 'dry-run', false);
  const requiresConfirm = op.mutating && !isDryRun;

  if (!confirmGate({ mutating: requiresConfirm, yes: deps.yes ?? false })) {
    auditFor(deps, ctx.alias, command, ctx, 'refused');
    return buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data: null,
      error: errorInfo('CONFIRMATION_REQUIRED'),
    });
  }

  enforceAllowlist(op.allowlist, ctx);
  const remoteCmd = op.buildRemote(ctx);

  if (remoteCmd === null) {
    if (!op.runLocal) {
      throw new Error(
        `registry: op '${command}' has no buildRemote output and no runLocal fallback`,
      );
    }
    const sshConfigPath = deps.sshConfigPath ?? join(homedir(), '.ssh', 'config');
    let data: unknown;
    try {
      data = await op.runLocal(ctx, sshConfigPath, deps.transport);
    } catch (err) {
      if (err instanceof OpRunLocalError) {
        if (requiresConfirm) {
          auditFor(deps, ctx.alias, command, ctx, 'error');
        }
        return buildEnvelope({
          alias: ctx.alias,
          command,
          startedAtMs,
          data: null,
          error: { code: err.code, message: err.message },
        });
      }
      throw err;
    }
    const envelope = buildEnvelope({ alias: ctx.alias, command, startedAtMs, data, error: null });
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'ok');
    }
    return envelope;
  }

  const result = await run(ctx.alias, remoteCmd, effectiveTimeoutSec(op, deps), deps.transport);
  if (result.error) {
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'error');
    }
    return buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data:
        op.shapeError?.(result.raw, ctx) ?? partialStdout(result.error, result.raw.stdout) ?? null,
      error: result.error,
    });
  }

  const parsed = parseByMode(op.output, result.raw.stdout);
  const data = op.shape(parsed, ctx);
  if (requiresConfirm) {
    auditFor(deps, ctx.alias, command, ctx, 'ok');
  }
  return buildEnvelope({ alias: ctx.alias, command, startedAtMs, data, error: null });
}

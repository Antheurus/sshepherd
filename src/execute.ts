import { homedir } from 'node:os';
import { join } from 'node:path';
import { auditMutating, confirmGate } from './audit.ts';
import { optBool } from './op-args.ts';
import { enforceAllowlist } from './ops/config.ts';
import { buildEnvelope, splitNdjson } from './output.ts';
import { errorInfo, run, type TransportDeps } from './transport.ts';
import {
  type Envelope,
  type OpContext,
  OpRunLocalError,
  type OpSpec,
  type OutputMode,
} from './types.ts';

/** Ceiling for any `--timeout` override — generous enough for a genuinely slow one-off
 *  migration/build, low enough that a typo (`--timeout 9999999999`) can't wedge a
 *  session open indefinitely. */
const MAX_TIMEOUT_OVERRIDE_SEC = 3_600;

/** `op.timeoutSec` is the static per-op default; ops that declare a `timeout` ArgSpec
 *  (currently `deploy run`/`deploy migrate`) let the caller raise it for a known-slow
 *  step instead of retrying blind against the same fixed budget every time. */
function effectiveTimeoutSec(op: OpSpec, ctx: OpContext): number {
  const raw = ctx.args.timeout;
  if (typeof raw !== 'string') {
    return op.timeoutSec;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return op.timeoutSec;
  }
  return Math.min(parsed, MAX_TIMEOUT_OVERRIDE_SEC);
}

export interface ExecuteDeps {
  transport?: TransportDeps;
  sshConfigPath?: string;
  /** Confirms a mutating op — the CLI (Phase 6) sets this after `--yes` or an interactive prompt. */
  yes?: boolean;
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
      data = op.runLocal(ctx, sshConfigPath);
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

  const result = await run(ctx.alias, remoteCmd, effectiveTimeoutSec(op, ctx), deps.transport);
  if (result.error) {
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'error');
    }
    return buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data: op.shapeError?.(result.raw, ctx) ?? null,
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

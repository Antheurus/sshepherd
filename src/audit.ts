import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export type AuditOutcome = 'ok' | 'error' | 'refused';

export interface AuditEntryInput {
  alias: string;
  command: string;
  /** Arg values, not logged raw — they could contain sensitive paths — only their hash is written. */
  argsSummary: Record<string, string | boolean>;
  outcome: AuditOutcome;
}

export interface AuditDeps {
  logPath: string;
}

/** Read on every call, never at import: a compiled binary must not freeze the build machine's
 *  environment, and tests redirect it through `SSHEPHERD_STATE_DIR` (`SSHEPHERD_AUDIT_PATH`
 *  names the file itself). */
export function auditLogPath(): string {
  const file = process.env.SSHEPHERD_AUDIT_PATH;
  if (file && file.length > 0) {
    return file;
  }
  const dir = process.env.SSHEPHERD_STATE_DIR;
  if (dir && dir.length > 0) {
    return join(dir, 'audit.jsonl');
  }
  return join(homedir(), '.local', 'state', 'sshepherd', 'audit.jsonl');
}

function hashArgs(argsSummary: Record<string, string | boolean>): string {
  const sortedKeys = Object.keys(argsSummary).sort();
  const canonical = JSON.stringify(argsSummary, sortedKeys);
  return Bun.hash.crc32(canonical).toString(36);
}

/** Appends one JSON line per mutating op to the audit log, creating a private 0700 dir if missing. */
export function auditMutating(
  input: AuditEntryInput,
  deps: AuditDeps = { logPath: auditLogPath() },
): void {
  mkdirSync(dirname(deps.logPath), { recursive: true, mode: 0o700 });
  const entry = {
    ts: new Date().toISOString(),
    alias: input.alias,
    command: input.command,
    args_hash: hashArgs(input.argsSummary),
    outcome: input.outcome,
  };
  appendFileSync(deps.logPath, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
}

/** Pure gate: a mutating op needs `--yes` before it runs; the CLI wires the actual prompt. */
export function confirmGate(input: { mutating: boolean; yes: boolean }): boolean {
  return !input.mutating || input.yes;
}

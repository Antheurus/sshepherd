import { appendFileSync, existsSync, mkdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { AUDIT_KEEP_FILES, AUDIT_ROTATE_BYTES, MAX_SESSION_ID_CHARS } from './limits.ts';
import type { AuditExtra, AuditPathRole } from './types.ts';

export type AuditOutcome = 'ok' | 'error' | 'refused';

export interface AuditEntryInput {
  alias: string;
  command: string;
  /** Arg values, not logged raw — they could contain sensitive paths — only their hash is written. */
  argsSummary: Record<string, string | boolean>;
  outcome: AuditOutcome;
  /** Names that identify what ran (recipe, target, container, unit) — never arg values. */
  identifiers?: Partial<Record<AuditIdentifier, string>>;
  durationMs?: number;
  /** Exit status of the remote command; absent when it never ran. */
  remoteExit?: number;
  errorCode?: string;
  /** Size of the envelope as printed. */
  bytes?: number;
  /** Op-specific fields (`db exec`: `sql_sha256`, `tables`). */
  extra?: AuditExtra;
}

/** The arg names whose values are safe to log: they name a thing, they are not its contents. */
export const AUDIT_IDENTIFIER_ARGS = ['recipe', 'target', 'container', 'unit'] as const;
export type AuditIdentifier = (typeof AUDIT_IDENTIFIER_ARGS)[number];

export interface AuditDeps {
  logPath: string;
  /** Tests shrink these; production uses the limits.ts values. */
  rotateBytes?: number;
  keepFiles?: number;
}

const PROFILES = new Set(['read', 'deploy', 'admin']);

/** `exec run|change` rows name the definition that ran, as deploy rows name the recipe: a declared
 *  name is an identifier, and anything not shaped like one stays only in the args hash. */
function execDefName(input: AuditEntryInput): string | undefined {
  const name = input.argsSummary.name;
  return input.command.startsWith('exec ') &&
    typeof name === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)
    ? name
    : undefined;
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

/** Full sha256 of the args: two different `deploy run` calls never share a hash, and the raw
 *  values are not recoverable from it. `args_hash` (crc32) stays on new rows for readers of old ones. */
function sha256Args(argsSummary: Record<string, string | boolean>): string {
  const sortedKeys = Object.keys(argsSummary).sort();
  return new Bun.CryptoHasher('sha256')
    .update(JSON.stringify(argsSummary, sortedKeys))
    .digest('hex');
}

/** `audit.jsonl` -> `audit.jsonl.1` -> ... : the newest archive is `.1`, the oldest falls off. */
export function auditArchivePaths(logPath: string, keepFiles: number = AUDIT_KEEP_FILES): string[] {
  return Array.from({ length: keepFiles - 1 }, (_, index) => `${logPath}.${index + 1}`);
}

function rotateIfFull(logPath: string, rotateBytes: number, keepFiles: number): void {
  if (!existsSync(logPath) || statSync(logPath).size < rotateBytes) {
    return;
  }
  const archives = auditArchivePaths(logPath, keepFiles);
  const oldest = archives[archives.length - 1];
  if (oldest !== undefined) {
    rmSync(oldest, { force: true });
  }
  for (let index = archives.length - 1; index > 0; index--) {
    const from = archives[index - 1];
    const to = archives[index];
    if (from !== undefined && to !== undefined && existsSync(from)) {
      renameSync(from, to);
    }
  }
  const newest = archives[0];
  if (newest === undefined) {
    rmSync(logPath, { force: true });
    return;
  }
  renameSync(logPath, newest);
}

/** What `auditMutating` throws when the log cannot be written: which part refused and the
 *  filesystem's error code, never the fs message (it quotes the path). */
export class AuditWriteError extends Error {
  constructor(
    public readonly role: AuditPathRole,
    public readonly errno: string | undefined,
  ) {
    super(`the audit log ${role} could not be written${errno === undefined ? '' : ` (${errno})`}`);
    this.name = 'AuditWriteError';
  }
}

function errnoOf(err: unknown): string | undefined {
  return err instanceof Error && 'code' in err && typeof err.code === 'string'
    ? err.code
    : undefined;
}

function writeStep(role: AuditPathRole, write: () => void): void {
  try {
    write();
  } catch (err) {
    throw new AuditWriteError(role, errnoOf(err));
  }
}

/** Appends one JSON line per audited op (mutating, or exposing content) to the audit log,
 *  creating a private 0700 dir if missing and rotating the file at `AUDIT_ROTATE_BYTES`. */
export function auditMutating(
  input: AuditEntryInput,
  deps: AuditDeps = { logPath: auditLogPath() },
): void {
  writeStep('state_dir', () => {
    mkdirSync(dirname(deps.logPath), { recursive: true, mode: 0o700 });
  });
  writeStep('audit_archive', () =>
    rotateIfFull(
      deps.logPath,
      deps.rotateBytes ?? AUDIT_ROTATE_BYTES,
      deps.keepFiles ?? AUDIT_KEEP_FILES,
    ),
  );
  const profile = process.env.SSHEPHERD_PROFILE;
  const sessionId = process.env.SSHEPHERD_SESSION_ID;
  const entry = {
    ts: new Date().toISOString(),
    alias: input.alias,
    command: input.command,
    ...input.identifiers,
    exec_def: execDefName(input),
    args_hash: hashArgs(input.argsSummary),
    args_sha256: sha256Args(input.argsSummary),
    outcome: input.outcome,
    duration_ms: input.durationMs,
    remote_exit: input.remoteExit,
    error_code: input.errorCode,
    bytes: input.bytes,
    sql_sha256: input.extra?.sqlSha256,
    tables: input.extra?.tables,
    profile: profile !== undefined && PROFILES.has(profile) ? profile : undefined,
    session_id:
      sessionId !== undefined && sessionId.length > 0
        ? sessionId.slice(0, MAX_SESSION_ID_CHARS)
        : undefined,
  };
  writeStep('audit_file', () =>
    appendFileSync(deps.logPath, `${JSON.stringify(entry)}\n`, { mode: 0o600 }),
  );
}

const setupAuditFailures: AuditWriteError[] = [];

/** `auditMutating` for a `setup` action, which reports through `buildSetupResult` rather than an
 *  envelope: an unwritable log is held for that result's `AUDIT_UNWRITABLE` warning instead of
 *  failing an action that already ran (the user chose run-and-warn over fail-closed). */
export function auditSetupMutating(input: AuditEntryInput): void {
  try {
    auditMutating(input);
  } catch (err) {
    if (!(err instanceof AuditWriteError)) {
      throw err;
    }
    setupAuditFailures.push(err);
  }
}

/** The audit failures `auditSetupMutating` held since the last call, emptied as they are taken. */
export function takeSetupAuditFailures(): AuditWriteError[] {
  return setupAuditFailures.splice(0);
}

/** Pure gate: a mutating op needs `--yes` before it runs; the CLI wires the actual prompt. */
export function confirmGate(input: { mutating: boolean; yes: boolean }): boolean {
  return !input.mutating || input.yes;
}

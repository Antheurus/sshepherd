import { existsSync, readFileSync } from 'node:fs';
import { auditArchivePaths, auditLogPath } from '../audit.ts';
import { DEFAULT_AUDIT_TAIL, MAX_AUDIT_TAIL } from '../limits.ts';
import { arg, DEFAULT_TIMEOUT_SEC, optStr, optStrOrNull } from '../op-args.ts';
import { type OpContext, OpError, type OpSpec } from '../types.ts';

interface AuditTailResult {
  rows: Record<string, unknown>[];
  row_count: number;
}

function parseRowCount(ctx: OpContext): number {
  const raw = optStr(ctx, 'n', String(DEFAULT_AUDIT_TAIL));
  const count = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(count) || count < 1 || count > MAX_AUDIT_TAIL) {
    throw new OpError(
      'INVALID_ARGS',
      `--n must be a whole number of rows from 1 to ${MAX_AUDIT_TAIL}`,
      {
        next: 'sshepherd audit tail --help',
      },
    );
  }
  return count;
}

function parseRow(line: string): Record<string, unknown> | null {
  try {
    const row: unknown = JSON.parse(line);
    return typeof row === 'object' && row !== null && !Array.isArray(row)
      ? (row as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** The newest `count` rows matching the filters, oldest first, reading the active log and then
 *  its archives until enough are found. Rows written before `args_sha256` keep their `args_hash`. */
function tailAuditLog(
  count: number,
  filters: { alias: string | null; command: string | null },
): Record<string, unknown>[] {
  const active = auditLogPath();
  const found: Record<string, unknown>[] = [];
  for (const path of [active, ...auditArchivePaths(active)]) {
    if (!existsSync(path)) {
      continue;
    }
    const lines = readFileSync(path, 'utf8').split('\n');
    for (let index = lines.length - 1; index >= 0 && found.length < count; index--) {
      const row = parseRow(lines[index] ?? '');
      if (
        row !== null &&
        (filters.alias === null || row.alias === filters.alias) &&
        (filters.command === null || row.command === filters.command)
      ) {
        found.push(row);
      }
    }
    if (found.length >= count) {
      break;
    }
  }
  return found.reverse();
}

const auditTail: OpSpec<AuditTailResult> = {
  group: 'audit',
  name: 'tail',
  summary:
    'The newest rows of the local audit log: what ran, how long, its exit, a sha256 of its args — never the args.',
  args: [
    arg(
      'n',
      'flag',
      false,
      `Rows to return (default ${DEFAULT_AUDIT_TAIL}, max ${MAX_AUDIT_TAIL}).`,
    ),
    arg('alias', 'flag', false, 'Only rows for this ssh alias.'),
    arg('op', 'flag', false, 'Only rows for this op, as "<group> <action>" (e.g. "deploy run").'),
  ],
  mutating: false,
  exposes: 'none',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as AuditTailResult,
  runLocal: (ctx) => {
    const rows = tailAuditLog(parseRowCount(ctx), {
      alias: optStrOrNull(ctx, 'alias'),
      command: optStrOrNull(ctx, 'op'),
    });
    return { rows, row_count: rows.length };
  },
};

export const auditOps = [auditTail] as OpSpec[];

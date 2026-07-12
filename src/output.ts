import type { Envelope, ErrorInfo } from './types.ts';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringifyCell(value: unknown): string {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function renderTable(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) {
    return '(no rows)';
  }
  const columns: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!columns.includes(key)) {
        columns.push(key);
      }
    }
  }
  const cells = rows.map((row) => columns.map((column) => stringifyCell(row[column])));
  const widths = columns.map((column, index) =>
    Math.max(column.length, ...cells.map((row) => row[index]?.length ?? 0)),
  );
  const formatRow = (values: string[]) =>
    values.map((value, index) => value.padEnd(widths[index] ?? 0)).join('  ');
  const separator = widths.map((width) => '-'.repeat(width));
  return [formatRow(columns), formatRow(separator), ...cells.map(formatRow)].join('\n');
}

function renderKeyValue(entries: Record<string, unknown>): string {
  const keys = Object.keys(entries);
  const width = Math.max(0, ...keys.map((key) => key.length));
  return keys.map((key) => `${key.padEnd(width)}  ${stringifyCell(entries[key])}`).join('\n');
}

function renderValue(value: unknown): string {
  if (Array.isArray(value)) {
    return renderTable(value.filter(isPlainObject));
  }
  if (isPlainObject(value)) {
    return renderKeyValue(value);
  }
  return stringifyCell(value);
}

export interface BuildEnvelopeInput<T> {
  alias: string;
  command: string;
  startedAtMs: number;
  data: T | null;
  error: ErrorInfo | null;
}

/**
 * The only place an Envelope is constructed. `Envelope` has no host/user/port/ip
 * field to begin with (see types.ts), so this is structurally safe — it echoes back
 * only the alias it was given.
 */
export function buildEnvelope<T>(input: BuildEnvelopeInput<T>): Envelope<T> {
  return {
    ok: input.error === null,
    alias: input.alias,
    ran_at: new Date().toISOString(),
    command: input.command,
    duration_ms: Date.now() - input.startedAtMs,
    data: input.data,
    error: input.error,
  };
}

/** docker/journalctl emit NDJSON, not a JSON array — split on newlines before parsing each line. */
export function splitNdjson(stdout: string): unknown[] {
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as unknown);
}

export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function printError(message: string): void {
  process.stderr.write(`${message}\n`);
}

/**
 * Human-readable rendering of an `Envelope` for terminal use (`--pretty`): header fields
 * as key/value lines, then `error` (if set) and `data` rendered as a table (array of
 * objects), key/value lines (object), or the raw scalar — never raw JSON.
 */
export function printPretty(envelope: Envelope<unknown>): void {
  const header: Record<string, unknown> = {
    ok: envelope.ok,
    alias: envelope.alias,
    command: envelope.command,
    ran_at: envelope.ran_at,
    duration_ms: envelope.duration_ms,
  };
  process.stdout.write(`${renderKeyValue(header)}\n`);
  if (envelope.error !== null) {
    process.stdout.write(
      `\nerror:\n${renderKeyValue(envelope.error as unknown as Record<string, unknown>)}\n`,
    );
  }
  if (envelope.data !== null && envelope.data !== undefined) {
    process.stdout.write(`\ndata:\n${renderValue(envelope.data)}\n`);
  }
}

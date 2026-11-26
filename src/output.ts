import type { Envelope, ErrorInfo } from './types.ts';

const byteLength = (value: unknown): number => Buffer.byteLength(serializeJson(value));

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
  /** Set by `executeOp` after its scrub pass; the CLI sets it on the envelopes it scrubs itself. */
  scrubbed?: number;
}

/**
 * The only place an Envelope is constructed. `Envelope` has no host/user/port/ip
 * field to begin with (see types.ts), so this is structurally safe — it echoes back
 * only the alias it was given.
 */
export function buildEnvelope<T>(input: BuildEnvelopeInput<T>): Envelope<T> {
  return {
    schema_version: 1,
    ok: input.error === null,
    alias: input.alias,
    ran_at: new Date().toISOString(),
    command: input.command,
    duration_ms: Date.now() - input.startedAtMs,
    scrubbed: input.scrubbed ?? 0,
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

/** The exact text `printJson` writes, so a byte cap measures what the caller will receive. */
export function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function printJson(value: unknown): void {
  process.stdout.write(serializeJson(value));
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

// -- --fields / --limit / --max-bytes ---------------------------------------------------------

/** Parses `--fields a,b.c` into dot paths relative to `data`; a leading `data.` is accepted
 *  because that is how the envelope shows them. Returns null for an empty or malformed list. */
export function parseFieldPaths(raw: string): string[][] | null {
  const parts = raw.split(',').map((part) => part.trim().replace(/^data\./, ''));
  if (parts.some((part) => !/^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.test(part))) {
    return null;
  }
  return parts.map((part) => (part === 'data' ? [] : part.split('.')));
}

/** What `path` selects out of `value`, keeping the nesting that leads to it; arrays are walked
 *  element by element (so `rows.id` picks `id` from every row, empty objects keep the indexes
 *  aligned). `undefined` when nothing on the path exists. */
function pick(value: unknown, path: string[]): unknown {
  if (path.length === 0) {
    return value;
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => pick(item, path) ?? {});
    return items.some((item) => !(isPlainObject(item) && Object.keys(item).length === 0))
      ? items
      : undefined;
  }
  const [head, ...rest] = path;
  if (!isPlainObject(value) || head === undefined || !Object.hasOwn(value, head)) {
    return undefined;
  }
  const inner = pick(value[head], rest);
  return inner === undefined ? undefined : { [head]: inner };
}

function mergePicked(target: unknown, source: unknown): unknown {
  if (Array.isArray(target) && Array.isArray(source)) {
    return target.map((item, index) => mergePicked(item, source[index]));
  }
  if (isPlainObject(target) && isPlainObject(source)) {
    const merged: Record<string, unknown> = { ...target };
    for (const [key, value] of Object.entries(source)) {
      merged[key] = Object.hasOwn(merged, key) ? mergePicked(merged[key], value) : value;
    }
    return merged;
  }
  return source;
}

/** `--fields`: keeps only the named paths of `data`, so an agent pays for what it asked for.
 *  Paths that matched nothing come back in `unmatched` instead of silently emptying the answer. */
export function selectFields(
  data: unknown,
  paths: string[][],
): { data: unknown; unmatched: string[] } {
  let selected: unknown;
  const unmatched: string[] = [];
  for (const path of paths) {
    const picked = pick(data, path);
    if (picked === undefined) {
      unmatched.push(path.length === 0 ? 'data' : `data.${path.join('.')}`);
      continue;
    }
    selected = selected === undefined ? picked : mergePicked(selected, picked);
  }
  if (selected !== undefined) {
    return { data: selected, unmatched };
  }
  return { data: data === null ? null : Array.isArray(data) ? [] : {}, unmatched };
}

/** `--limit N`: the first N items of `data` when it is a list, or of each list directly under it —
 *  the last N when `keep` is `tail`. */
export function limitItems(
  data: unknown,
  limit: number,
  keep: 'head' | 'tail' = 'head',
): { data: unknown; cut: boolean } {
  const take = (list: unknown[]): unknown[] =>
    keep === 'head' ? list.slice(0, limit) : list.slice(Math.max(0, list.length - limit));
  if (Array.isArray(data)) {
    return { data: take(data), cut: data.length > limit };
  }
  if (!isPlainObject(data)) {
    return { data, cut: false };
  }
  let cut = false;
  const limited: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value) && value.length > limit) {
      limited[key] = take(value);
      cut = true;
    } else {
      limited[key] = value;
    }
  }
  return { data: limited, cut };
}

/** Largest `n` in 0..max for which `fits(n)` holds, given that `fits` is monotone (true, then false). */
function largestFitting(max: number, fits: (n: number) => boolean): number {
  let low = 0;
  let high = max;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (fits(mid)) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }
  return low;
}

/** Printed size of `value` when it sits `depth` levels down inside the envelope: every line after
 *  its first carries `2 * depth` more bytes of indentation than it would on its own. */
function sizeAt(value: unknown, depth: number): number {
  const text = JSON.stringify(value, null, 2) ?? 'null';
  const lines = text.split('\n').length - 1;
  return Buffer.byteLength(text) + lines * 2 * depth;
}

/** Cuts `value` until its printed form, at `depth`, is at most `target` bytes: strings and lists
 *  keep their head or tail, objects shrink their largest member first. Best effort — a target too
 *  small for even the keys gives back an emptied value. */
function trimTo(value: unknown, target: number, keep: 'head' | 'tail', depth: number): unknown {
  if (sizeAt(value, depth) <= target) {
    return value;
  }
  if (typeof value === 'string') {
    const slice = (n: number) =>
      keep === 'head' ? value.slice(0, n) : value.slice(value.length - n);
    return slice(largestFitting(value.length, (n) => sizeAt(slice(n), depth) <= target));
  }
  if (Array.isArray(value)) {
    const slice = (n: number) =>
      keep === 'head' ? value.slice(0, n) : value.slice(value.length - n);
    const count = largestFitting(value.length, (n) => sizeAt(slice(n), depth) <= target);
    if (count > 0 || value.length === 0) {
      return slice(count);
    }
    const only = keep === 'head' ? value[0] : value[value.length - 1];
    return [trimTo(only, Math.max(0, target - 8), keep, depth + 1)];
  }
  if (isPlainObject(value)) {
    const trimmed: Record<string, unknown> = { ...value };
    for (let round = 0; round < 64 && sizeAt(trimmed, depth) > target; round++) {
      const sizes = Object.entries(trimmed).map(
        ([key, member]) => [key, sizeAt(member, depth + 1)] as const,
      );
      const [largest, size] = sizes.reduce((best, entry) => (entry[1] > best[1] ? entry : best));
      const excess = sizeAt(trimmed, depth) - target;
      const next = trimTo(trimmed[largest], Math.max(0, size - excess), keep, depth + 1);
      if (sizeAt(next, depth + 1) >= size) {
        delete trimmed[largest];
      } else {
        trimmed[largest] = next;
      }
      if (Object.keys(trimmed).length === 0) {
        break;
      }
    }
    return trimmed;
  }
  return value;
}

/**
 * `--max-bytes`: the printed envelope never exceeds `maxBytes`. `data` is trimmed (and
 * `output_truncated` set) until it fits; the error block is never cut. Runs after the scrubber, on
 * values that are already masked, so a cut cannot expose half of a secret's mask boundary.
 */
export function capEnvelope(
  envelope: Envelope<unknown>,
  maxBytes: number,
  keep: 'head' | 'tail' = 'head',
): Envelope<unknown> {
  if (byteLength(envelope) <= maxBytes) {
    return envelope;
  }
  const flagged: Envelope<unknown> = { ...envelope, output_truncated: true };
  // `data: null` prints as 4 bytes that the real value replaces.
  let target = maxBytes - byteLength({ ...flagged, data: null }) + 4;
  for (let round = 0; round < 8; round++) {
    const candidate = { ...flagged, data: trimTo(envelope.data, Math.max(0, target), keep, 1) };
    const excess = byteLength(candidate) - maxBytes;
    if (excess <= 0) {
      return candidate;
    }
    target -= excess + 1;
  }
  return { ...flagged, data: null };
}

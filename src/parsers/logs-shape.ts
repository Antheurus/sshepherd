import { MAX_LINE_BYTES } from '../limits.ts';
import type { LogLine } from './journal.ts';

/** Which end of the window a `logs *` page keeps when more lines exist than it returns: `oldest`
 *  when `--since` is set (the page starts at `--since` and pages forward), `newest` otherwise. */
export type LogsKept = 'oldest' | 'newest';

/** Shared response shape for every `logs *` op — see research.md §response envelope. */
export interface LogsResult {
  source: string;
  lines_returned: number;
  truncated: boolean;
  kept: LogsKept;
  lines: LogLine[];
  /** Exclusive cursor: the last returned line's instant plus 1 ns, so `--since <next_since>` never
   *  returns that line again; null when no line carries a timestamp. */
  next_since: string | null;
}

/** One page of log lines as the remote command returned it. With `kept: 'oldest'` the remote asked
 *  for one line past `limit` (`lines[limit]`, the next page's first line) and `full` says it stopped
 *  early at the page byte bound. */
export interface LogsPage {
  lines: LogLine[];
  limit: number;
  kept: LogsKept;
  full?: boolean;
}

const INSTANT = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/;

/** An RFC 3339 timestamp as whole Unix seconds plus nanoseconds, or null when `ts` is not one. */
export function instantOf(ts: string): { seconds: number; nanos: number } | null {
  const match = INSTANT.exec(ts);
  if (!match) {
    return null;
  }
  const [, base = '', fraction = '', zone = ''] = match;
  const ms = Date.parse(`${base}${zone}`);
  if (Number.isNaN(ms)) {
    return null;
  }
  return { seconds: ms / 1_000, nanos: Number(fraction.padEnd(9, '0')) };
}

/** `ts` plus one nanosecond, as a UTC RFC 3339 timestamp with nine fraction digits; null when `ts`
 *  is null or not a timestamp. */
export function nextSinceAfter(ts: string | null | undefined): string | null {
  const instant = typeof ts === 'string' ? instantOf(ts) : null;
  if (instant === null) {
    return null;
  }
  let { seconds, nanos } = instant;
  nanos += 1;
  if (nanos === 1_000_000_000) {
    nanos = 0;
    seconds += 1;
  }
  const base = new Date(seconds * 1_000).toISOString().slice(0, 19);
  return `${base}.${String(nanos).padStart(9, '0')}Z`;
}

function lastTs(lines: readonly unknown[]): string | null {
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i];
    if (isRecord(line) && typeof line.ts === 'string') {
      return line.ts;
    }
  }
  return null;
}

/** A page read forward from `--since`: the first `limit` lines, `truncated` when a next line exists
 *  or the byte bound stopped the read. When that next line shares the last kept line's instant, the
 *  kept lines of that instant move to the next page and `next_since` is the instant itself (the
 *  cursor is inclusive there), so a page boundary never splits one instant and skips half of it. */
function oldestPage(page: LogsPage): { lines: LogLine[]; truncated: boolean; next: string | null } {
  let lines = page.lines.slice(0, page.limit);
  const following = page.lines[page.limit];
  const truncated = page.full === true || following !== undefined;
  const shared = following?.ts ?? null;
  if (shared !== null && lines.at(-1)?.ts === shared) {
    const before = lines.filter((line) => line.ts !== shared);
    if (before.length > 0 && before.length === lines.findIndex((line) => line.ts === shared)) {
      lines = before;
      return { lines, truncated, next: shared };
    }
  }
  return { lines, truncated, next: nextSinceAfter(lastTs(lines)) };
}

/** `truncated` is true when more lines may exist than were returned: newest-kept, when the line
 *  count hit the requested limit; oldest-kept, when the remote had a line past it. */
export function buildLogsResult(source: string, page: LogsPage): LogsResult {
  if (page.kept === 'oldest') {
    const { lines, truncated, next } = oldestPage(page);
    return {
      source,
      lines_returned: lines.length,
      truncated,
      kept: 'oldest',
      lines,
      next_since: next,
    };
  }
  return {
    source,
    lines_returned: page.lines.length,
    truncated: page.lines.length >= page.limit,
    kept: 'newest',
    lines: page.lines,
    next_since: nextSinceAfter(lastTs(page.lines)),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The first `MAX_LINE_BYTES` of `text`, never splitting a UTF-8 character. */
function capLineText(text: string): string {
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= MAX_LINE_BYTES) {
    return text;
  }
  let end = MAX_LINE_BYTES;
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) {
    end -= 1;
  }
  return bytes.subarray(0, end).toString('utf8');
}

/** `OpSpec.capLines` for `{lines}` output, whether each line is a string (`files tail`) or a
 *  `{text}` object (`logs *`): every line keeps its head, at most `MAX_LINE_BYTES`. */
export function capLines(data: unknown): { data: unknown; cut: boolean } {
  if (!isRecord(data) || !Array.isArray(data.lines)) {
    return { data, cut: false };
  }
  let cut = false;
  const lines = data.lines.map((line: unknown) => {
    if (typeof line === 'string') {
      const capped = capLineText(line);
      cut = cut || capped !== line;
      return capped;
    }
    if (isRecord(line) && typeof line.text === 'string') {
      const capped = capLineText(line.text);
      cut = cut || capped !== line.text;
      return capped === line.text ? line : { ...line, text: capped };
    }
    return line;
  });
  return { data: cut ? { ...data, lines } : data, cut };
}

/** `OpSpec.recount` for `{lines}` output: once a cap dropped lines, `lines_returned` counts what is
 *  left, `truncated` turns true (more lines exist than were returned) and `next_since` is the last
 *  returned line's instant plus 1 ns, so paging from it repeats nothing. A `kept: 'oldest'` page was
 *  cut from its front by `--limit`/`--max-bytes` (both keep the tail of a log op); the same number
 *  of lines is taken from its start instead, so paging forward from `next_since` skips nothing. Only
 *  fields still present (after `--fields`) are rewritten. */
export function recountLines(before: unknown, after: unknown, sourceCut: boolean): unknown {
  if (!isRecord(after) || !Array.isArray(after.lines)) {
    return after;
  }
  const beforeLines: unknown[] =
    isRecord(before) && Array.isArray(before.lines) ? before.lines : [];
  const kept = after.kept ?? (isRecord(before) ? before.kept : undefined);
  const lines: unknown[] =
    kept === 'oldest' && beforeLines.length > after.lines.length
      ? beforeLines.slice(0, after.lines.length)
      : after.lines;
  const recounted: Record<string, unknown> = { ...after, lines };
  if (Object.hasOwn(recounted, 'lines_returned')) {
    recounted.lines_returned = lines.length;
  }
  if (Object.hasOwn(recounted, 'truncated') && (sourceCut || lines.length < beforeLines.length)) {
    recounted.truncated = true;
  }
  if (Object.hasOwn(recounted, 'next_since')) {
    const last = lines.at(-1);
    if (last === undefined) {
      recounted.next_since = null;
    } else if (isRecord(last) && Object.hasOwn(last, 'ts')) {
      recounted.next_since = nextSinceAfter(lastTs(lines));
    }
  }
  return recounted;
}

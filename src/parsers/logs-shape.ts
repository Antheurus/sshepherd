import { MAX_LINE_BYTES } from '../limits.ts';
import type { LogLine } from './journal.ts';

/** Shared response shape for every `logs *` op — see research.md §response envelope. */
export interface LogsResult {
  source: string;
  lines_returned: number;
  truncated: boolean;
  lines: LogLine[];
  next_since: string | null;
}

/** `truncated` is true when the line count hit the requested limit — more may exist. */
export function buildLogsResult(
  source: string,
  lines: LogLine[],
  requestedLimit: number,
): LogsResult {
  const lastLine = lines[lines.length - 1];
  return {
    source,
    lines_returned: lines.length,
    truncated: lines.length >= requestedLimit,
    lines,
    next_since: lastLine ? lastLine.ts : null,
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
 *  returned line's timestamp, so paging from it skips nothing. Only fields still present (after
 *  `--fields`) are rewritten. */
export function recountLines(before: unknown, after: unknown, sourceCut: boolean): unknown {
  if (!isRecord(after) || !Array.isArray(after.lines)) {
    return after;
  }
  const lines: unknown[] = after.lines;
  const beforeCount = isRecord(before) && Array.isArray(before.lines) ? before.lines.length : 0;
  const recounted: Record<string, unknown> = { ...after };
  if (Object.hasOwn(recounted, 'lines_returned')) {
    recounted.lines_returned = lines.length;
  }
  if (Object.hasOwn(recounted, 'truncated') && (sourceCut || lines.length < beforeCount)) {
    recounted.truncated = true;
  }
  const last = lines.at(-1);
  if (Object.hasOwn(recounted, 'next_since')) {
    if (last === undefined) {
      recounted.next_since = null;
    } else if (isRecord(last) && Object.hasOwn(last, 'ts')) {
      recounted.next_since = last.ts;
    }
  }
  return recounted;
}

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

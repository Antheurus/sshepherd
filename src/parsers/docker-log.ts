/**
 * Parses `docker logs --timestamps` plain-text lines into the shared
 * `{ ts, stream, text }` log-line shape. Each line is `<RFC3339-nano timestamp> <text>`.
 *
 * KNOWN LIMITATION: the `docker logs` CLI merges stdout and stderr into one text stream
 * with no per-line stream tag (that tagging only exists in the json-file log driver's
 * on-disk format, which isn't guaranteed — Docker 20.10+ defaults to the binary `local`
 * driver). Every line is reported as `stdout`; flagged in the phase report for audit.
 */
import type { LogLine } from './journal.ts';

const TIMESTAMP_PATTERN = /^(\S+)\s(.*)$/;

export function parseDockerLogLine(line: string): LogLine | null {
  const match = TIMESTAMP_PATTERN.exec(line);
  if (!match) {
    return null;
  }
  const [, ts, text] = match;
  if (ts === undefined || text === undefined) {
    return null;
  }
  return { ts, stream: 'stdout', text };
}

export function parseDockerLogLines(stdout: string): LogLine[] {
  return stdout
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0)
    .map(parseDockerLogLine)
    .filter((line): line is LogLine => line !== null);
}

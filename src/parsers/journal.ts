/**
 * Shapes one `journalctl -o json` NDJSON entry (native JSON, per research.md §output
 * shaping — split with `splitNdjson` before calling this) into the shared
 * `{ ts, stream, text }` log-line shape.
 *
 * `stream` is a heuristic: journald has no first-class stdout/stderr field for arbitrary
 * units, so this maps syslog `PRIORITY <= 3` (err/crit/alert/emerg) to `stderr` and
 * everything else to `stdout`. Flagged in the phase report as an assumption to audit
 * against a real journald instance.
 */
export interface LogLine {
  /** `null` when the source has no reliable per-line timestamp (e.g. nginx access log). */
  ts: string | null;
  stream: 'stdout' | 'stderr';
  text: string;
}

const STDERR_PRIORITY_THRESHOLD = 3;

function readString(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === 'string' ? value : null;
}

export function shapeJournalEntry(entry: unknown): LogLine | null {
  if (typeof entry !== 'object' || entry === null) {
    return null;
  }
  const record = entry as Record<string, unknown>;

  const realtimeMicros = readString(record, '__REALTIME_TIMESTAMP');
  const message = readString(record, 'MESSAGE');
  const priority = readString(record, 'PRIORITY');
  if (realtimeMicros === null || message === null) {
    return null;
  }

  const micros = Number.parseInt(realtimeMicros, 10);
  const ts = Number.isNaN(micros)
    ? new Date(0).toISOString()
    : new Date(micros / 1000).toISOString();
  const priorityNum = priority !== null ? Number.parseInt(priority, 10) : Number.NaN;
  const stream: LogLine['stream'] =
    !Number.isNaN(priorityNum) && priorityNum <= STDERR_PRIORITY_THRESHOLD ? 'stderr' : 'stdout';

  return { ts, stream, text: message };
}

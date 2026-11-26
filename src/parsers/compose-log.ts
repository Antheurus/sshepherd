/**
 * Parses `docker compose logs --no-color --timestamps` into the shared log-line shape. Each line is
 * `<service>-<n>  | <RFC3339-nano timestamp> <text>`; compose prints stdout and stderr of every
 * container through one stream with no per-line tag, so every line is reported as `stdout`.
 */
import type { LogLine } from './journal.ts';

const COMPOSE_LOG_PATTERN = /^(\S+)\s+\|\s(\S+)\s(.*)$/;

export function parseComposeLogLines(stdout: string): LogLine[] {
  const lines: LogLine[] = [];
  for (const raw of stdout.split('\n')) {
    const match = COMPOSE_LOG_PATTERN.exec(raw.trimEnd());
    const [, service, ts, text] = match ?? [];
    if (service === undefined || ts === undefined || text === undefined) {
      continue;
    }
    lines.push({ ts, stream: 'stdout', text, service });
  }
  return lines;
}

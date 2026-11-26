import {
  arg,
  DEFAULT_LOG_TAIL,
  LOG_TIMEOUT_SEC,
  optStr,
  optStrOrNull,
  reqStr,
} from '../op-args.ts';
import { parseDockerLogLines } from '../parsers/docker-log.ts';
import { type LogLine, shapeJournalEntry } from '../parsers/journal.ts';
import { buildLogsResult, capLines, type LogsResult, recountLines } from '../parsers/logs-shape.ts';
import { shellJoin } from '../quote.ts';
import { maskPemLines } from '../scrub.ts';
import { didYouMeanOrAll } from '../suggest.ts';
import { type OpContext, OpError, type OpSpec, Premasked } from '../types.ts';

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

/** Every log op splits output per line or journald entry, so no single string holds a whole PEM
 *  block for `scrubText` to see: the line-array pass masks its body first. `masked` counts the
 *  lines it changed, for the envelope's `scrubbed`. */
function maskPemLogLines<T extends LogLine>(lines: T[]): { lines: T[]; masked: number } {
  const texts = maskPemLines(lines.map((line) => line.text));
  let masked = 0;
  const out = lines.map((line, index) => {
    const text = texts[index] ?? line.text;
    if (text !== line.text) {
      masked += 1;
    }
    return { ...line, text };
  });
  return { lines: out, masked };
}

/** What every `logs *` op shares past its own parsing: the PEM pass, the result shape, and the
 *  count of what the PEM pass masked. */
function shapeLogs(source: string, raw: LogLine[], ctx: OpContext): Premasked<LogsResult> {
  const { lines, masked } = maskPemLogLines(raw);
  const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
  return new Premasked(
    buildLogsResult(source, lines, Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit),
    masked,
  );
}

/** A capped or `--limit`ed log keeps its newest lines, and its counters follow what was kept. */
const LOG_CAPS = {
  truncateKeeps: 'tail',
  limitKeeps: 'tail',
  capLines,
  recount: recountLines,
} as const satisfies Pick<OpSpec, 'truncateKeeps' | 'limitKeeps' | 'capLines' | 'recount'>;

function buildLogsDocker(ctx: OpContext): string {
  const container = reqStr(ctx, 'container');
  const tail = optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL));
  const since = optStrOrNull(ctx, 'since');
  const parts = ['docker', 'logs', '--timestamps', '--tail', tail];
  if (since !== null) {
    parts.push('--since', since);
  }
  parts.push(container);
  return shellJoin(parts);
}

const logsDocker: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker',
  summary: 'Tail a container log as {ts, stream, text} line objects + next_since.',
  args: [
    arg('container', 'positional', true, 'Container name or ID.'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
    arg('since', 'flag', false, 'Only lines newer than this timestamp/duration.'),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: buildLogsDocker,
  ...LOG_CAPS,
  shape: (parsed, ctx) =>
    shapeLogs(`docker:${reqStr(ctx, 'container')}`, parseDockerLogLines(parsed as string), ctx),
};

function buildJournalCommand(unit: string, tail: string): string {
  return shellJoin(['journalctl', '-u', unit, '-n', tail, '-o', 'json', '--no-pager']);
}

function shapeJournalLines(parsed: unknown): ReturnType<typeof shapeJournalEntry>[] {
  const entries = parsed as unknown[];
  return entries.map(shapeJournalEntry).filter((line) => line !== null);
}

const logsService: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'service',
  summary: 'Tail a systemd unit journal as {ts, stream, text} line objects + next_since.',
  args: [
    arg('unit', 'positional', true, 'systemd unit name.'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) =>
    buildJournalCommand(reqStr(ctx, 'unit'), optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL))),
  ...LOG_CAPS,
  shape: (parsed, ctx) =>
    shapeLogs(
      `service:${reqStr(ctx, 'unit')}`,
      shapeJournalLines(parsed).filter((line): line is NonNullable<typeof line> => line !== null),
      ctx,
    ),
};

const logsDockerDaemon: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker-daemon',
  summary: 'Tail the docker daemon journal (feeds the exit-137 differential).',
  args: [arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`)],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) =>
    buildJournalCommand('docker', optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL))),
  ...LOG_CAPS,
  shape: (parsed, ctx) =>
    shapeLogs(
      'docker-daemon',
      shapeJournalLines(parsed).filter((line): line is NonNullable<typeof line> => line !== null),
      ctx,
    ),
};

const NGINX_LOG_PATHS: Record<string, string> = {
  error: '/var/log/nginx/error.log',
  access: '/var/log/nginx/access.log',
};

const logsNginx: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'nginx',
  summary: 'Tail the nginx error or access log.',
  args: [
    arg('stream', 'positional', true, '"error" or "access".'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const stream = reqStr(ctx, 'stream');
    const path = NGINX_LOG_PATHS[stream];
    if (path === undefined) {
      throw new OpError(
        'VALIDATION_ERROR',
        `unknown nginx log stream '${stream}' — expected "error" or "access"`,
        { did_you_mean: didYouMeanOrAll(stream, Object.keys(NGINX_LOG_PATHS)) },
      );
    }
    return shellJoin(['tail', '-n', optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), path]);
  },
  ...LOG_CAPS,
  shape: (parsed, ctx) =>
    shapeLogs(
      `nginx:${reqStr(ctx, 'stream')}`,
      (parsed as string)
        .split('\n')
        .map((line) => line.trimEnd())
        .filter((line) => line.length > 0)
        .map((text): LogLine => ({ ts: null, stream: 'stdout', text })),
      ctx,
    ),
};

export const logsOps = [logsDocker, logsService, logsDockerDaemon, logsNginx] as OpSpec[];

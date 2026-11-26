import { MAX_TAIL_LINES } from '../limits.ts';
import {
  grepCommand,
  journalCommand,
  type LogQuery,
  lineLimit,
  plainCommand,
  readLogQuery,
} from '../log-command.ts';
import { arg, DEFAULT_LOG_TAIL, LOG_TIMEOUT_SEC, reqStr } from '../op-args.ts';
import { parseComposeLogLines } from '../parsers/compose-log.ts';
import { parseDockerLogLines } from '../parsers/docker-log.ts';
import { type LogLine, parseJournalLines, shapeJournalEntry } from '../parsers/journal.ts';
import { buildLogsResult, capLines, type LogsResult, recountLines } from '../parsers/logs-shape.ts';
import { maskPemLines } from '../scrub.ts';
import { didYouMeanOrAll } from '../suggest.ts';
import { type OpContext, OpError, type OpSpec, Premasked, type RawResult } from '../types.ts';

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
  const query = readLogQuery(ctx);
  const { lines, masked } = maskPemLogLines(raw);
  return new Premasked(buildLogsResult(source, lines, lineLimit(query)), masked);
}

/** A capped or `--limit`ed log keeps its newest lines, and its counters follow what was kept;
 *  `truncateKeeps` also makes a stream past the transport read ceiling keep its newest bytes. */
const LOG_CAPS = {
  truncateKeeps: 'tail',
  limitKeeps: 'tail',
  capLines,
  recount: recountLines,
} as const satisfies Pick<OpSpec, 'truncateKeeps' | 'limitKeeps' | 'capLines' | 'recount'>;

const LOG_FILTER_ARGS = [
  arg('tail', 'flag', false, `Lines to read from the source (default ${DEFAULT_LOG_TAIL}).`),
  arg(
    'grep',
    'flag',
    false,
    'Only lines matching this extended regular expression (512 chars max).',
  ),
  arg('context', 'flag', false, 'With --grep: lines kept around each match (0-20).'),
  arg('max-lines', 'flag', false, 'Most lines returned, newest kept (default 500).'),
];
const LOG_WINDOW_ARGS = [
  arg('since', 'flag', false, 'Only lines newer than this timestamp or duration.'),
  arg('until', 'flag', false, 'Only lines older than this timestamp or duration.'),
];

const FAILURE_TAIL_LINES = 5;
const FAILURE_TAIL_LINE_CHARS = 512;

/** A log reader that folds stderr into stdout leaves a failed command's own message there (`docker
 *  logs` on a missing container); this hands its last lines back with the error. */
function shapeLogsError(raw: RawResult): Record<string, unknown> | undefined {
  if (raw.timedOut || (raw.code !== 1 && raw.code !== 2)) {
    return undefined;
  }
  const lines = raw.stdout
    .split('\n')
    .map((line) => line.trimEnd().slice(0, FAILURE_TAIL_LINE_CHARS))
    .filter((line) => line.length > 0);
  return lines.length === 0 ? undefined : { output_tail: lines.slice(-FAILURE_TAIL_LINES) };
}

/** The remote command of a source with no pipeline of its own: filtered by `grep -E` when asked. */
function filteredCommand(producer: string[], query: LogQuery, merge: boolean): string {
  return query.grep === null
    ? plainCommand(producer, merge)
    : grepCommand(producer, query, merge, query.maxLines);
}

function buildLogsDocker(ctx: OpContext): string {
  const query = readLogQuery(ctx);
  const parts = ['docker', 'logs', '--timestamps', '--tail', String(query.scanLines)];
  if (query.since !== null) {
    parts.push('--since', query.since);
  }
  if (query.until !== null) {
    parts.push('--until', query.until);
  }
  parts.push(reqStr(ctx, 'container'));
  return filteredCommand(parts, query, true);
}

const logsDocker: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker',
  summary:
    'Tail a container log (stdout and stderr merged) as {ts, stream, text} line objects + next_since.',
  args: [
    arg('container', 'positional', true, 'Container name or ID.'),
    ...LOG_FILTER_ARGS,
    ...LOG_WINDOW_ARGS,
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: buildLogsDocker,
  shapeError: shapeLogsError,
  ...LOG_CAPS,
  shape: (parsed, ctx) =>
    shapeLogs(`docker:${reqStr(ctx, 'container')}`, parseDockerLogLines(parsed as string), ctx),
};

function buildLogsCompose(ctx: OpContext): string {
  const query = readLogQuery(ctx);
  const parts = [
    'docker',
    'compose',
    '--project-directory',
    reqStr(ctx, 'project_dir'),
    'logs',
    '--no-color',
    '--timestamps',
    '--tail',
    String(query.scanLines),
  ];
  if (query.since !== null) {
    parts.push('--since', query.since);
  }
  if (query.until !== null) {
    parts.push('--until', query.until);
  }
  return query.grep === null
    ? plainCommand(parts, true)
    : grepCommand(parts, query, true, MAX_TAIL_LINES);
}

/** Compose prints one container after another, so the lines are put in time order before the
 *  newest `limit` are kept. */
function shapeComposeLogs(parsed: unknown, ctx: OpContext): Premasked<LogsResult> {
  const query = readLogQuery(ctx);
  const ordered = parseComposeLogLines(parsed as string)
    .map((line, index) => ({ line, index }))
    .sort((a, b) => (a.line.ts ?? '').localeCompare(b.line.ts ?? '') || a.index - b.index)
    .map(({ line }) => line)
    .slice(-query.maxLines);
  return shapeLogs(`compose:${reqStr(ctx, 'project_dir')}`, ordered, ctx);
}

const logsCompose: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'compose',
  summary:
    'Tail every service of a compose project (stdout and stderr merged) as {ts, stream, text, service} line objects + next_since.',
  args: [
    arg('project_dir', 'positional', true, 'Compose project directory on the remote.'),
    arg('tail', 'flag', false, `Lines to read from each container (default ${DEFAULT_LOG_TAIL}).`),
    ...LOG_FILTER_ARGS.slice(1),
    ...LOG_WINDOW_ARGS,
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: buildLogsCompose,
  shapeError: shapeLogsError,
  ...LOG_CAPS,
  shape: shapeComposeLogs,
};

function shapeJournalLines(parsed: unknown): LogLine[] {
  return (parsed as unknown[]).map(shapeJournalEntry).filter((line) => line !== null);
}

const logsService: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'service',
  summary: 'Tail a systemd unit journal as {ts, stream, text} line objects + next_since.',
  args: [
    arg('unit', 'positional', true, 'systemd unit name.'),
    ...LOG_FILTER_ARGS,
    ...LOG_WINDOW_ARGS,
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: { parse: parseJournalLines },
  buildRemote: (ctx) => journalCommand(reqStr(ctx, 'unit'), readLogQuery(ctx)),
  ...LOG_CAPS,
  shape: (parsed, ctx) =>
    shapeLogs(`service:${reqStr(ctx, 'unit')}`, shapeJournalLines(parsed), ctx),
};

const logsDockerDaemon: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker-daemon',
  summary: 'Tail the docker daemon journal (feeds the exit-137 differential).',
  args: [...LOG_FILTER_ARGS, ...LOG_WINDOW_ARGS],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: { parse: parseJournalLines },
  buildRemote: (ctx) => journalCommand('docker', readLogQuery(ctx)),
  ...LOG_CAPS,
  shape: (parsed, ctx) => shapeLogs('docker-daemon', shapeJournalLines(parsed), ctx),
};

const NGINX_LOG_PATHS: Record<string, string> = {
  error: '/var/log/nginx/error.log',
  access: '/var/log/nginx/access.log',
};

const logsNginx: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'nginx',
  summary: 'Tail the nginx error or access log.',
  args: [arg('stream', 'positional', true, '"error" or "access".'), ...LOG_FILTER_ARGS],
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
    const query = readLogQuery(ctx);
    return filteredCommand(['tail', '-n', String(query.scanLines), path], query, false);
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

export const logsOps = [
  logsDocker,
  logsCompose,
  logsService,
  logsDockerDaemon,
  logsNginx,
] as OpSpec[];

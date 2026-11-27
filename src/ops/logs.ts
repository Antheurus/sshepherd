import { MAX_TAIL_LINES } from '../limits.ts';
import {
  filteredCommand,
  journalCommand,
  type LogQuery,
  lineLimit,
  logPipelineCommand,
  PAGE_FULL_MARKER,
  plainCommand,
  readLogQuery,
} from '../log-command.ts';
import { arg, DEFAULT_LOG_TAIL, LOG_TIMEOUT_SEC, reqStr } from '../op-args.ts';
import { parseComposeLogLines } from '../parsers/compose-log.ts';
import { parseDockerLogLines } from '../parsers/docker-log.ts';
import { type LogLine, parseJournalLines, shapeJournalEntry } from '../parsers/journal.ts';
import { buildLogsResult, capLines, type LogsResult, recountLines } from '../parsers/logs-shape.ts';
import { maskPemBodyChunks, maskPemLines } from '../scrub.ts';
import { didYouMeanOrAll } from '../suggest.ts';
import { type OpContext, OpError, type OpSpec, Premasked, type RawResult } from '../types.ts';

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

/** Every log op splits output per line or journald entry, so no single string holds a whole PEM
 *  block for `scrubText` to see: the line-array pass masks its body first. A window or `--grep` can
 *  keep body lines and drop both markers, so a bare full-width body chunk is masked as well
 *  (`maskPemBodyChunks`). `masked` counts the lines it changed, for the envelope's `scrubbed`. */
function maskPemLogLines<T extends LogLine>(lines: T[]): { lines: T[]; masked: number } {
  const texts = maskPemBodyChunks(maskPemLines(lines.map((line) => line.text)));
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

/** What every `logs *` op shares past its own parsing: the PEM pass (over every line read, the
 *  one past a page included), the result shape, and the count of what the PEM pass masked. */
function shapeLogs(
  source: string,
  raw: LogLine[],
  ctx: OpContext,
  full = false,
): Premasked<LogsResult> {
  const query = readLogQuery(ctx);
  const { lines, masked } = maskPemLogLines(raw);
  return new Premasked(
    buildLogsResult(source, { lines, limit: lineLimit(query), kept: query.kept, full }),
    masked,
  );
}

/** Raw page output with the page reader's `PAGE_FULL_MARKER` line taken off; `full` says it was there. */
function pageText(parsed: unknown): { text: string; full: boolean } {
  const text = parsed as string;
  const lines = text.split('\n');
  const at = lines.lastIndexOf(PAGE_FULL_MARKER);
  if (at === -1) {
    return { text, full: false };
  }
  return { text: lines.slice(0, at).join('\n'), full: true };
}

/** A capped or `--limit`ed log keeps its newest lines, and its counters follow what was kept (a
 *  `--since` page takes its oldest instead, in `recountLines`); `truncateKeeps` also makes a stream
 *  past the transport read ceiling keep its newest bytes, which a `--since` page never reaches: its
 *  reader stops at `LOG_PAGE_MAX_BYTES`. */
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
  arg(
    'max-lines',
    'flag',
    false,
    'Most lines returned (default 500): the newest, or with --since the oldest from that moment.',
  ),
];
const LOG_WINDOW_ARGS = [
  arg(
    'since',
    'flag',
    false,
    'Read forward from this timestamp or duration (a page; pass next_since as the next --since). Not with --tail.',
  ),
  arg('until', 'flag', false, 'Only lines at or before this timestamp or duration.'),
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

/** `--since`/`--until` as docker flags. docker applies `--tail` before either, so a windowed read
 *  never passes it one: `--tail 200 --until <t>` is the newest 200 lines filtered to `<t>`, empty
 *  whenever those are all newer. */
function windowFlags(query: LogQuery): string[] {
  return [
    ...(query.since === null ? [] : ['--since', query.since]),
    ...(query.until === null ? [] : ['--until', query.until]),
  ];
}

const isWindowed = (query: LogQuery): boolean => query.since !== null || query.until !== null;

function buildLogsDocker(ctx: OpContext): string {
  const query = readLogQuery(ctx);
  const container = reqStr(ctx, 'container');
  if (!isWindowed(query)) {
    return filteredCommand(
      ['docker', 'logs', '--timestamps', '--tail', String(query.scanLines), container],
      query,
      true,
    );
  }
  return logPipelineCommand(query, {
    producer: ['docker', 'logs', '--timestamps', ...windowFlags(query), container],
    merge: true,
    filter: 'text',
    scan: query.kept === 'newest' ? query.scanLines : 0,
  });
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
  shape: (parsed, ctx) => {
    const { text, full } = pageText(parsed);
    return shapeLogs(`docker:${reqStr(ctx, 'container')}`, parseDockerLogLines(text), ctx, full);
  },
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
  ];
  if (!isWindowed(query)) {
    parts.push('--tail', String(query.scanLines));
    return query.grep === null
      ? plainCommand(parts, true)
      : logPipelineCommand(query, {
          producer: parts,
          merge: true,
          filter: 'text',
          newestMax: MAX_TAIL_LINES,
        });
  }
  return logPipelineCommand(query, {
    producer: [...parts, ...windowFlags(query)],
    merge: true,
    filter: 'text',
    order: true,
    newestMax: query.grep === null ? query.scanLines : query.maxLines,
  });
}

/** Compose prints one container after another, so the lines are put in time order before the
 *  newest `limit` are kept (a `--since` page was ordered and cut on the host). */
function shapeComposeLogs(parsed: unknown, ctx: OpContext): Premasked<LogsResult> {
  const query = readLogQuery(ctx);
  const { text, full } = pageText(parsed);
  const ordered = parseComposeLogLines(text)
    .map((line, index) => ({ line, index }))
    .sort((a, b) => (a.line.ts ?? '').localeCompare(b.line.ts ?? '') || a.index - b.index)
    .map(({ line }) => line);
  const page = query.kept === 'oldest' ? ordered : ordered.slice(-query.maxLines);
  return shapeLogs(`compose:${reqStr(ctx, 'project_dir')}`, page, ctx, full);
}

const logsCompose: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'compose',
  summary:
    'Tail every service of a compose project (stdout and stderr merged) as {ts, stream, text, service} line objects + next_since.',
  args: [
    arg(
      'project_dir',
      'positional',
      true,
      'Compose project directory on the remote — must be on, or under, a files-allowlist.toml entry.',
    ),
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
  allowlist: [{ kind: 'path', scope: 'files', argName: 'project_dir', within: true }],
};

function shapeJournalLogs(source: string, parsed: unknown, ctx: OpContext): Premasked<LogsResult> {
  const { text, full } = pageText(parsed);
  const lines = parseJournalLines(text)
    .map(shapeJournalEntry)
    .filter((line) => line !== null);
  return shapeLogs(source, lines, ctx, full);
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
  output: 'raw',
  buildRemote: (ctx) => journalCommand(reqStr(ctx, 'unit'), readLogQuery(ctx)),
  ...LOG_CAPS,
  shape: (parsed, ctx) => shapeJournalLogs(`service:${reqStr(ctx, 'unit')}`, parsed, ctx),
};

const logsDockerDaemon: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker-daemon',
  summary: 'Tail the docker daemon journal (feeds the exit-137 differential).',
  args: [...LOG_FILTER_ARGS, ...LOG_WINDOW_ARGS],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => journalCommand('docker', readLogQuery(ctx)),
  ...LOG_CAPS,
  shape: (parsed, ctx) => shapeJournalLogs('docker-daemon', parsed, ctx),
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

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
import { buildLogsResult } from '../parsers/logs-shape.ts';
import { shellJoin } from '../quote.ts';
import { maskPemLines } from '../scrub.ts';
import { didYouMeanOrAll } from '../suggest.ts';
import { type OpContext, OpError, type OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

/** Every log op splits output per line or journald entry, so no single string holds a whole PEM
 *  block for `scrubText` to see: the line-array pass masks its body first. */
function maskPemLogLines<T extends LogLine>(lines: T[]): T[] {
  const texts = maskPemLines(lines.map((line) => line.text));
  return lines.map((line, index) => ({ ...line, text: texts[index] ?? line.text }));
}

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
  shape: (parsed, ctx) => {
    const lines = maskPemLogLines(parseDockerLogLines(parsed as string));
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult(
      `docker:${reqStr(ctx, 'container')}`,
      lines,
      Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit,
    );
  },
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
  shape: (parsed, ctx) => {
    const lines = maskPemLogLines(
      shapeJournalLines(parsed).filter((line): line is NonNullable<typeof line> => line !== null),
    );
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult(
      `service:${reqStr(ctx, 'unit')}`,
      lines,
      Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit,
    );
  },
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
  shape: (parsed, ctx) => {
    const lines = maskPemLogLines(
      shapeJournalLines(parsed).filter((line): line is NonNullable<typeof line> => line !== null),
    );
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult('docker-daemon', lines, Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit);
  },
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
  shape: (parsed, ctx) => {
    const stream = reqStr(ctx, 'stream');
    const lines = maskPemLogLines(
      (parsed as string)
        .split('\n')
        .map((line) => line.trimEnd())
        .filter((line) => line.length > 0)
        .map((text): LogLine => ({ ts: null, stream: 'stdout', text })),
    );
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult(
      `nginx:${stream}`,
      lines,
      Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit,
    );
  },
};

export const logsOps = [logsDocker, logsService, logsDockerDaemon, logsNginx] as OpSpec[];

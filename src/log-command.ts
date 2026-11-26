import {
  DEFAULT_LOG_MAX_LINES,
  LOG_GREP_SCAN_LINES,
  MAX_GREP_PATTERN_CHARS,
  MAX_LOG_CONTEXT_LINES,
  MAX_TAIL_LINES,
} from './limits.ts';
import { DEFAULT_LOG_TAIL, optStrOrNull } from './op-args.ts';
import { shellJoin } from './quote.ts';
import { niced } from './remote-nice.ts';
import { type OpContext, OpError } from './types.ts';

/** What a `logs *` caller asked for, validated. `grep` is null when absent. */
export interface LogQuery {
  grep: string | null;
  context: number;
  /** Most lines the op returns, newest kept. */
  maxLines: number;
  /** Lines the source is asked for: `--tail`, else 200 (or the grep scan window when grepping). */
  scanLines: number;
  since: string | null;
  until: string | null;
}

function parseBounded(ctx: OpContext, key: string, min: number, max: number): number | null {
  const raw = optStrOrNull(ctx, key);
  if (raw === null) {
    return null;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new OpError(
      'INVALID_ARGS',
      `--${key} must be a whole number from ${min} to ${max} (got '${raw}')`,
    );
  }
  return value;
}

function assertGrepPattern(pattern: string): void {
  if (pattern.length > MAX_GREP_PATTERN_CHARS) {
    throw new OpError(
      'INVALID_ARGS',
      `--grep is ${pattern.length} characters; the limit is ${MAX_GREP_PATTERN_CHARS}`,
      { hint: 'Search for a shorter, more specific fragment.' },
    );
  }
  if (/[\0\r\n]/.test(pattern)) {
    throw new OpError(
      'INVALID_ARGS',
      '--grep must be one line: a NUL or line break cannot be sent, and grep would read a line break as a second pattern',
      { hint: 'Pass one pattern on one line; join alternatives with |.' },
    );
  }
}

/** Reads `--grep`, `--context`, `--max-lines`, `--tail`, `--since` and `--until` of a `logs *` op. */
export function readLogQuery(ctx: OpContext): LogQuery {
  const grep = optStrOrNull(ctx, 'grep');
  if (grep !== null) {
    assertGrepPattern(grep);
  }
  const context = parseBounded(ctx, 'context', 0, MAX_LOG_CONTEXT_LINES) ?? 0;
  if (context > 0 && grep === null) {
    throw new OpError('INVALID_ARGS', '--context needs --grep: it is the lines around each match', {
      next: 'Add --grep <pattern>, or drop --context.',
    });
  }
  const tail = parseBounded(ctx, 'tail', 1, MAX_TAIL_LINES);
  const explicitMax = parseBounded(ctx, 'max-lines', 1, MAX_TAIL_LINES);
  const maxLines = explicitMax ?? Math.max(DEFAULT_LOG_MAX_LINES, tail ?? 0);
  const sourceLines = tail ?? (grep === null ? DEFAULT_LOG_TAIL : LOG_GREP_SCAN_LINES);
  return {
    grep,
    context,
    maxLines,
    scanLines: grep === null ? Math.min(sourceLines, maxLines) : sourceLines,
    since: optStrOrNull(ctx, 'since'),
    until: optStrOrNull(ctx, 'until'),
  };
}

/** The line count past which a result is `truncated`: more lines may exist than were returned. */
export function lineLimit(query: LogQuery): number {
  return query.grep === null ? query.scanLines : query.maxLines;
}

/** Shared tail of the grep scripts. `merge` (1) folds the producer's stderr into the stream: a
 *  log reader that drops stderr hides every line a service wrote there. The producer's own exit
 *  status is carried out of the pipeline through fd 4 (a POSIX sh has no pipefail), so a missing
 *  container still fails the command instead of reading as "no matches". */
const PIPE_TAIL = [
  'run() { if [ "$merge" = 1 ]; then "$@" 2>&1; else "$@"; fi; }',
  'filter() { if [ "$native" = 1 ]; then cat; else grep -a -E $ctxflag -e "$pattern"; fi; }',
  'exec 3>&1',
  'rc=$( { { run "$@"; echo $? >&4; } | filter | tail -n "$max" >&3; } 4>&1 )',
  'if [ -z "$rc" ]; then rc=1; fi',
  'exit "$rc"',
];

/** Refuses a pattern grep -E cannot compile before the pipeline starts: its exit 2 would otherwise
 *  be swallowed by the pipeline, reading as "no matches". */
const PATTERN_CHECK = [
  'grep -a -E -e "$pattern" </dev/null',
  'if [ $? -eq 2 ]; then echo "--grep is not a valid extended regular expression" >&2; exit 2; fi',
];

const GREP_SCRIPT = [
  'pattern=$1; context=$2; max=$3; merge=$4; native=0; ctxflag=; shift 4',
  '[ "$context" -gt 0 ] && ctxflag="-C $context"',
  ...PATTERN_CHECK,
  ...PIPE_TAIL,
].join('\n');

const JOURNAL_SCRIPT = [
  'pattern=$1; context=$2; max=$3; scan=$4; unit=$5; since=$6; upto=$7; merge=0; native=0; ctxflag=; shift 7',
  'set -- journalctl -o json --no-pager -n "$scan"',
  '[ -n "$unit" ] && set -- "$@" -u "$unit"',
  '[ -n "$since" ] && set -- "$@" --since "$since"',
  '[ -n "$upto" ] && set -- "$@" --until "$upto"',
  '[ "$context" -gt 0 ] && ctxflag="-C $context"',
  // journalctl --grep is PCRE2 and absent from some builds; `--case-sensitive` matches grep -E.
  // Context needs grep's -C, so it always takes the grep -E branch.
  'if [ "$context" -eq 0 ] && journalctl --case-sensitive=yes --grep=x -n 0 --no-pager >/dev/null 2>&1; then',
  '  native=1; set -- "$@" --case-sensitive=yes --grep="$pattern"',
  'else',
  ...PATTERN_CHECK.map((line) => `  ${line}`),
  'fi',
  ...PIPE_TAIL,
].join('\n');

/** `producer` as written, its stderr folded into stdout when `merge`. No pipeline, so the exit
 *  status is the producer's. */
export function plainCommand(producer: string[], merge: boolean): string {
  return niced(`${shellJoin(producer)}${merge ? ' 2>&1' : ''}`);
}

/** `producer | grep -E | tail -n maxLines`, exit status the producer's. The pattern is one argv slot
 *  of a `sh -c` script, never part of its text. */
export function grepCommand(
  producer: string[],
  query: LogQuery,
  merge: boolean,
  maxLines: number,
): string {
  return niced(
    shellJoin([
      'sh',
      '-c',
      GREP_SCRIPT,
      'sh',
      query.grep ?? '',
      String(query.context),
      String(maxLines),
      merge ? '1' : '0',
      ...producer,
    ]),
  );
}

/** The journal of `unit` as JSON lines, filtered by `--grep` natively where journalctl supports
 *  it, by `grep -E` otherwise. */
export function journalCommand(unit: string, query: LogQuery): string {
  if (query.grep === null) {
    const parts = [
      'journalctl',
      '-o',
      'json',
      '--no-pager',
      '-n',
      String(query.scanLines),
      '-u',
      unit,
    ];
    if (query.since !== null) {
      parts.push('--since', query.since);
    }
    if (query.until !== null) {
      parts.push('--until', query.until);
    }
    return plainCommand(parts, false);
  }
  return niced(
    shellJoin([
      'sh',
      '-c',
      JOURNAL_SCRIPT,
      'sh',
      query.grep,
      String(query.context),
      String(query.maxLines),
      String(query.scanLines),
      unit,
      query.since ?? '',
      query.until ?? '',
    ]),
  );
}

import {
  DEFAULT_LOG_MAX_LINES,
  LOG_GREP_SCAN_LINES,
  LOG_PAGE_MAX_BYTES,
  MAX_GREP_PATTERN_CHARS,
  MAX_LOG_CONTEXT_LINES,
  MAX_TAIL_LINES,
} from './limits.ts';
import { DEFAULT_LOG_TAIL, optStrOrNull } from './op-args.ts';
import { instantOf, type LogsKept } from './parsers/logs-shape.ts';
import { shellJoin } from './quote.ts';
import { niced } from './remote-nice.ts';
import { type OpContext, OpError } from './types.ts';

/** What a `logs *` caller asked for, validated. `grep` is null when absent. */
export interface LogQuery {
  grep: string | null;
  context: number;
  /** Most lines the op returns. */
  maxLines: number;
  /** Lines the source is asked for: `--tail`, else 200 (or the grep scan window when grepping). */
  scanLines: number;
  since: string | null;
  until: string | null;
  /** `oldest` when `--since` is set: the page starts at `--since` and the next one follows it. */
  kept: LogsKept;
}

/** Printed by the page reader after the last whole line that fit `LOG_PAGE_MAX_BYTES`: more lines
 *  exist than the page holds. No source line can equal it (docker and compose lines start with a
 *  timestamp or a service name, journald lines with `{`). */
export const PAGE_FULL_MARKER = '__SSHEPHERD_PAGE_FULL__';

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
  const since = optStrOrNull(ctx, 'since');
  const tail = parseBounded(ctx, 'tail', 1, MAX_TAIL_LINES);
  if (since !== null && tail !== null) {
    throw new OpError(
      'INVALID_ARGS',
      '--tail reads the newest lines, while --since reads forward from that moment: they cannot both bound one page',
      { hint: 'Size a --since page with --max-lines, and page on with next_since.' },
    );
  }
  const explicitMax = parseBounded(ctx, 'max-lines', 1, MAX_TAIL_LINES);
  const maxLines = explicitMax ?? Math.max(DEFAULT_LOG_MAX_LINES, tail ?? 0);
  const sourceLines = tail ?? (grep === null ? DEFAULT_LOG_TAIL : LOG_GREP_SCAN_LINES);
  return {
    grep,
    context,
    maxLines,
    scanLines: grep === null ? Math.min(sourceLines, maxLines) : sourceLines,
    since,
    until: optStrOrNull(ctx, 'until'),
    kept: since === null ? 'newest' : 'oldest',
  };
}

/** The line count a page is measured against: past it, a result is `truncated`. */
export function lineLimit(query: LogQuery): number {
  return query.grep === null && query.kept === 'newest' ? query.scanLines : query.maxLines;
}

/** Keeps a journald entry whose MESSAGE matches `$P` (an extended regular expression, read from the
 *  environment so awk applies no escape processing to it), with `c` entries of context either side
 *  as `grep -C` would: matching the raw JSON line instead matched `_SYSTEMD_UNIT`, `__CURSOR` and
 *  every other field. The value is cut out with `index`/`substr` only: mawk and busybox awk read a
 *  backslash inside a bracket expression as an escape, so a `match()` regex for a JSON string never
 *  matched there. The key may have blanks around its colon (`"MESSAGE" : "..."`, what systemd
 *  printed before its JsonVariant writer), and a `"MESSAGE"` with no colon after it is a value,
 *  not the key. A MESSAGE journald stores as a byte array (not UTF-8) never matches. */
const JOURNAL_MESSAGE_AWK = String.raw`
function unescape(s,   out, i, ch, nx) {
  out = ""
  for (i = 1; i <= length(s); i++) {
    ch = substr(s, i, 1)
    if (ch != "\\" || i == length(s)) { out = out ch; continue }
    i++; nx = substr(s, i, 1)
    if (nx == "n") out = out "\n"; else if (nx == "t") out = out "\t"; else out = out nx
  }
  return out
}
function skipblanks(s) {
  while (substr(s, 1, 1) == " " || substr(s, 1, 1) == "\t") s = substr(s, 2)
  return s
}
function message(line,   at, s, out, q, k) {
  s = line
  while ((at = index(s, "\"MESSAGE\"")) > 0) {
    s = skipblanks(substr(s, at + 9))
    if (substr(s, 1, 1) != ":") continue
    s = skipblanks(substr(s, 2))
    if (substr(s, 1, 1) == "\"") break
  }
  if (at == 0) return ""
  s = substr(s, 2); out = ""
  while ((q = index(s, "\"")) > 0) {
    k = q - 1
    while (k > 0 && substr(s, k, 1) == "\\") k--
    if ((q - 1 - k) % 2 == 0) {
      out = out substr(s, 1, q - 1)
      return index(out, "\\") ? unescape(out) : out
    }
    out = out substr(s, 1, q); s = substr(s, q + 1)
  }
  return ""
}
BEGIN { c = c + 0; pat = ENVIRON["P"]; last = 0; after = 0 }
{
  if (message($0) ~ pat) {
    start = NR - c; if (start <= last) start = last + 1
    for (i = start; i < NR; i++) print held[i % (c + 1)]
    print; last = NR; after = c
  } else if (after > 0) { print; last = NR; after-- }
  if (c > 0) held[NR % (c + 1)] = $0
}`;

/** The first `max` lines whose bytes fit `budget`, then `PAGE_FULL_MARKER` if the budget stopped
 *  it. A first line larger than the whole budget is cut to it, so a page always moves forward. */
const PAGE_AWK = `
{ b += length($0) + 1
  if (b > budget) { if (NR == 1) print substr($0, 1, budget); print "${PAGE_FULL_MARKER}"; exit }
  print
  if (NR >= max) exit }`;

/** Every filtered or windowed `logs *` read. `"$@"` is the producer; its stages, in order:
 *  - `scan` (> 0): its newest `scan` lines, for a source that cannot bound itself under `--until`;
 *  - `save` (when filtering): keeps the last 5 unfiltered lines (512 bytes each) beside the exit
 *    status on fd 4; only when the producer failed are they printed on stderr, so a missing
 *    container's own message, folded into the stream and filtered out, still reaches
 *    `error.stderr_tail`, and a run that succeeded prints nothing there;
 *  - `filter`: `text` = `grep -E`, `json` = `JOURNAL_MESSAGE_AWK`, `journal` = journalctl's own
 *    `--grep` where it has one and no context is asked, else `json`;
 *  - `order` (1): compose lines into time order (`<service> | <ts> <text>`, field 3);
 *  - `limit`: `newest` = `tail -n max`; `oldest` = `PAGE_AWK` (the caller asks one line past the
 *    page, so the page knows a next one exists).
 *  `merge` (1) folds the producer's stderr into the stream: a log reader that drops stderr hides every
 *  line a service wrote there. The producer's own exit status is carried out of the pipeline through
 *  fd 4 (a POSIX sh has no pipefail), so a missing container still fails the command instead of
 *  reading as "no matches"; a page reader that stopped early kills the producer with SIGPIPE (141),
 *  which is its success. The pattern is one argv slot, never part of the script text. */
const LOG_SCRIPT = [
  'pattern=$1; context=$2; max=$3; merge=$4; scan=$5; order=$6; keep=$7; filter=$8; budget=$9; shift 9',
  'ctxflag=; [ "$context" -gt 0 ] && ctxflag="-C $context"',
  // journalctl --grep is PCRE2 and absent from some builds; `--case-sensitive` matches grep -E.
  // Context needs grep's -C, so it always takes the awk branch.
  'if [ "$filter" = journal ]; then',
  '  filter=json',
  '  if [ "$context" -eq 0 ] && journalctl --case-sensitive=yes --grep=x -n 0 --no-pager >/dev/null 2>&1; then',
  '    filter=none; set -- "$@" --case-sensitive=yes --grep="$pattern"',
  '  fi',
  'fi',
  // Refuses a pattern grep -E cannot compile before the pipeline starts: its exit 2 would otherwise
  // be swallowed by the pipeline, reading as "no matches".
  'if [ "$filter" != none ]; then',
  '  grep -a -E -e "$pattern" </dev/null',
  '  if [ $? -eq 2 ]; then echo "--grep is not a valid extended regular expression" >&2; exit 2; fi',
  'fi',
  'run() { if [ "$merge" = 1 ]; then "$@" 2>&1; else "$@"; fi; }',
  'scancut() { if [ "$scan" -gt 0 ]; then tail -n "$scan"; else cat; fi; }',
  `save() { if [ "$filter" = none ]; then cat; else awk '{ print; t[NR % 5] = substr($0, 1, 512) } END { for (i = NR - 4; i <= NR; i++) if (i > 0) print "tail:" t[i % 5] > "/dev/fd/4" }'; fi; }`,
  'filter() { case "$filter" in',
  '  text) grep -a -E $ctxflag -e "$pattern" ;;',
  `  json) P="$pattern" awk -v c="$context" '${JOURNAL_MESSAGE_AWK.replaceAll("'", "'\\''")}' ;;`,
  '  *) cat ;;',
  'esac; }',
  'order() { if [ "$order" = 1 ]; then sort -s -b -k3,3; else cat; fi; }',
  `limit() { if [ "$keep" = oldest ]; then LC_ALL=C awk -v max="$max" -v budget="$budget" '${PAGE_AWK}'; else tail -n "$max"; fi; }`,
  'exec 3>&1',
  'cap=$( { { run "$@"; echo "rc:$?" >&4; } | scancut | save | filter | order | limit >&3; } 4>&1 )',
  `rc=$(printf '%s\\n' "$cap" | sed -n 's/^rc://p' | tail -n 1)`,
  'if [ -z "$rc" ]; then rc=1; fi',
  'if [ "$rc" -eq 141 ] && [ "$keep" = oldest ]; then rc=0; fi',
  `if [ "$rc" -ne 0 ]; then printf '%s\\n' "$cap" | sed -n 's/^tail://p' >&2; fi`,
  'exit "$rc"',
].join('\n');

export type LogFilter = 'text' | 'journal';

export interface LogPipeline {
  /** The source command, with every flag it applies itself. */
  producer: string[];
  /** Fold the producer's stderr into the stream. */
  merge: boolean;
  /** `filter` applies when `query.grep` is set: `grep -E` over lines, or journald's MESSAGE. */
  filter: LogFilter;
  /** Lines kept from the producer's end before filtering (0: none). */
  scan?: number;
  /** Compose output: sort by the timestamp in field 3 before the page is cut. */
  order?: boolean;
  /** Newest-kept page size (default `query.maxLines`). */
  newestMax?: number;
}

/** `producer` as written, its stderr folded into stdout when `merge`. No pipeline, so the exit
 *  status is the producer's. */
export function plainCommand(producer: string[], merge: boolean): string {
  return niced(`${shellJoin(producer)}${merge ? ' 2>&1' : ''}`);
}

/** `pipeline.producer` through `LOG_SCRIPT`: filtered by `--grep` when asked, then cut to the page
 *  `query.kept` names. */
export function logPipelineCommand(query: LogQuery, pipeline: LogPipeline): string {
  const oldest = query.kept === 'oldest';
  return niced(
    shellJoin([
      'sh',
      '-c',
      LOG_SCRIPT,
      'sh',
      query.grep ?? '',
      String(query.context),
      String(oldest ? query.maxLines + 1 : (pipeline.newestMax ?? query.maxLines)),
      pipeline.merge ? '1' : '0',
      String(pipeline.scan ?? 0),
      pipeline.order ? '1' : '0',
      query.kept,
      query.grep === null ? 'none' : pipeline.filter,
      String(LOG_PAGE_MAX_BYTES),
      ...pipeline.producer,
    ]),
  );
}

/** A `--since`/`--until` value as journalctl reads it. An RFC 3339 timestamp (what `next_since`
 *  hands back) becomes `@<epoch>.<microseconds>`, the form every journalctl parses: older builds
 *  read no `T`/`Z` form. journald counts microseconds, so an inclusive `--since` rounds up and an
 *  inclusive `--until` rounds down, and the same entries match. Anything else (`1h ago`, `today`)
 *  passes through. */
export function journalTime(value: string, edge: 'since' | 'until'): string {
  const instant = instantOf(value);
  if (instant === null) {
    return value;
  }
  let seconds = instant.seconds;
  let micros =
    edge === 'since' ? Math.ceil(instant.nanos / 1_000) : Math.floor(instant.nanos / 1_000);
  if (micros === 1_000_000) {
    micros = 0;
    seconds += 1;
  }
  return `@${seconds}.${String(micros).padStart(6, '0')}`;
}

/** The journal of `unit` as JSON lines. `-n` bounds a newest-kept read (journalctl applies it after
 *  `--until`); a `--since` page has no `-n`, the page reader bounds it. */
export function journalCommand(unit: string, query: LogQuery): string {
  const parts = ['journalctl', '-o', 'json', '--no-pager'];
  if (query.kept === 'newest') {
    parts.push('-n', String(query.scanLines));
  }
  parts.push('-u', unit);
  if (query.since !== null) {
    parts.push('--since', journalTime(query.since, 'since'));
  }
  if (query.until !== null) {
    parts.push('--until', journalTime(query.until, 'until'));
  }
  if (query.grep === null && query.kept === 'newest') {
    return plainCommand(parts, false);
  }
  return logPipelineCommand(query, { producer: parts, merge: false, filter: 'journal' });
}

/** A text source whose own flags hold no window (`tail` of an nginx log, docker with `--tail`). */
export function filteredCommand(producer: string[], query: LogQuery, merge: boolean): string {
  return query.grep === null
    ? plainCommand(producer, merge)
    : logPipelineCommand(query, { producer, merge, filter: 'text' });
}

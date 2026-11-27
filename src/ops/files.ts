import { readFileSync, writeFileSync } from 'node:fs';
import {
  DEFAULT_HEAD_LINES,
  DOWNLOAD_MAX_BYTES,
  DOWNLOAD_MAX_STDOUT_BYTES,
  MAX_FILES_GREP_PATTERN_CHARS,
  MAX_FILES_LINE_SPAN,
  MAX_FIND_NAME_CHARS,
  MAX_FIND_RESULTS,
  MAX_GREP_CONTEXT_LINES,
  MAX_GREP_MATCH_LINES,
  MAX_HEAD_LINES,
  MAX_PEM_SECRET_RANGES,
} from '../limits.ts';
import {
  arg,
  DEFAULT_LOG_TAIL,
  FILE_CAT_MAX_BYTES,
  FILE_TIMEOUT_SEC,
  optStr,
  optStrOrNull,
  reqStr,
} from '../op-args.ts';
import { parseDu } from '../parsers/du.ts';
import { capLines, recountLines } from '../parsers/logs-shape.ts';
import { parseLs } from '../parsers/ls.ts';
import { shellJoin, shq } from '../quote.ts';
import { niced } from '../remote-nice.ts';
import { isEnvFile, MASK, maskEnvContent, scrubText } from '../scrub.ts';
import { type OpContext, OpError, type OpSpec, Premasked } from '../types.ts';
import { loadFilesAllowlist, loadScrubExtraPatterns, revealKeysOf } from './config.ts';

const DOWNLOAD_TIMEOUT_SEC = 30;
/** The size header's number is canonical: no sign, padding or leading zero. */
const DOWNLOAD_HEADER_OK = /^__OK__:(0|[1-9]\d*)$/;
const DOWNLOAD_HEADER_TOO_LARGE = /^__TOO_LARGE__:(0|[1-9]\d*)$/;

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

const filesLs: OpSpec<ReturnType<typeof parseLs>> = {
  group: 'files',
  name: 'ls',
  summary: 'Directory listing (structured, byte sizes).',
  args: [
    arg('path', 'positional', true, 'Remote directory path — must be on files-allowlist.toml.'),
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  buildRemote: (ctx) =>
    shellJoin(['ls', '-la', '--time-style=long-iso', '--', reqStr(ctx, 'path')]),
  shape: (parsed) => parseLs(parsed as string),
};

/** `--lines A:B`: lines A to B of the file, 1-based and inclusive, at most `MAX_FILES_LINE_SPAN`. */
interface LineRange {
  start: number;
  end: number;
}

const LINES_ARG = arg(
  'lines',
  'flag',
  false,
  `A:B — only lines A to B of the file (1-based, inclusive, at most ${MAX_FILES_LINE_SPAN} lines); not combined with --n.`,
);

function lineRangeOf(ctx: OpContext): LineRange | null {
  const raw = optStrOrNull(ctx, 'lines');
  if (raw === null) {
    return null;
  }
  if (optStrOrNull(ctx, 'n') !== null) {
    throw new OpError('INVALID_ARGS', '--lines and --n pick lines two ways; pass one of them');
  }
  const match = /^(\d{1,9}):(\d{1,9})$/.exec(raw);
  const start = Number(match?.[1] ?? 0);
  const end = Number(match?.[2] ?? 0);
  if (start < 1 || end < start || end - start + 1 > MAX_FILES_LINE_SPAN) {
    throw new OpError(
      'INVALID_ARGS',
      `--lines must be A:B with 1 <= A <= B and at most ${MAX_FILES_LINE_SPAN} lines (got '${raw}')`,
      { hint: 'For example --lines 120:180.' },
    );
  }
  return { start, end };
}

const ENV_ENTRY = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*)$/;
const ENV_SKIPPED = /^\s*(?:#.*)?$/;

/** Index of the first `quote` in `text` no backslash escapes, or -1. */
function unescapedQuote(text: string, quote: string): number {
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === '\\') {
      i += 1;
    } else if (text[i] === quote) {
      return i;
    }
  }
  return -1;
}

/** The lines of an env-shaped file read from line 1, masked line for line (so line numbers still
 *  hold): each `KEY=value` as `files cat` masks it, and every line of a quoted value that runs on
 *  past its own line masked whole, as is any other line that is neither an entry nor a comment. */
function maskEnvLines(lines: readonly string[], revealKeys: ReadonlySet<string>): string[] {
  let open = '';
  return lines.map((line) => {
    if (open !== '') {
      if (unescapedQuote(line, open) !== -1) {
        open = '';
      }
      return MASK;
    }
    if (ENV_SKIPPED.test(line)) {
      return line;
    }
    const value = ENV_ENTRY.exec(line)?.[4];
    if (value === undefined) {
      return MASK;
    }
    const quote = value[0];
    if ((quote === '"' || quote === "'") && unescapedQuote(value.slice(1), quote) === -1) {
      open = quote;
    }
    return maskEnvContent(line, revealKeys);
  });
}

/** Per-line PEM membership of one whole file, decided on the host in one pass: every marker of every
 *  line (`-----BEGIN|END <label>-----`, any number per line, joined to its neighbours or not) is read
 *  in order; a private-key BEGIN opens a block, its END closes it, an unterminated one runs to EOF,
 *  and a certificate's markers change nothing. A line is secret when any part of it inside a block
 *  holds base64 text, so marker lines stay visible. NULs become spaces first and both tools run in
 *  the C locale, so no binary byte or invalid UTF-8 hides a marker. Prints one line: the secret
 *  ranges and the line count read (`3-4 9-12 =57`), or `x =57` past `MAX_PEM_SECRET_RANGES`. */
const PEM_MEMBERSHIP_AWK = String.raw`function content(s,  t) { t = s; gsub(/\\n/, "", t); return t ~ /[A-Za-z0-9+=\/]/ }
function flush() { if (first > 0) { if (++count > cap) over = 1; else ranges = ranges first "-" last " " } first = 0 }
{ secret = 0
  if (index($0, "-----") == 0) { secret = inside && content($0) }
  else { k = split($0, part, /-----+/)
    for (i = 1; i <= k; i++) {
      if (i > 1 && i < k && part[i] ~ /^(BEGIN|END) [A-Z0-9 ]+$/) {
        if (part[i] ~ /^BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?$/) inside = 1
        else if (part[i] ~ /^END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?$/) inside = 0
      } else if (inside && content(part[i])) secret = 1 } }
  if (secret) { if (first > 0 && last == NR - 1) last = NR; else { flush(); first = NR; last = NR } } }
END { flush(); if (over) printf "x =%d\n", NR; else printf "%s=%d\n", ranges, NR }`;

/** Shell text printing the PEM membership of the file `fileRef` names. */
function pemMembershipScript(fileRef: string): string {
  return `{ LC_ALL=C tr '\\000' ' ' < ${fileRef}; } 2>/dev/null | LC_ALL=C awk -v cap=${MAX_PEM_SECRET_RANGES} ${shq(PEM_MEMBERSHIP_AWK)}`;
}

interface PemMembership {
  /** Lines the pass read; null when it failed, was cut off or passed the cap. */
  total: number | null;
  /** Whether line `n` of the file is masked: a secret line, any line past `total`, every line when
   *  the pass gave no usable answer. */
  isSecret: (n: number) => boolean;
}

const PEM_MEMBERSHIP = /^((?:\d+-\d+ )*)=(\d+)$/;

function parsePemMembership(text: string | null): PemMembership {
  const match = PEM_MEMBERSHIP.exec(text?.trim() ?? '');
  const ranges = (match?.[1] ?? '')
    .split(' ')
    .filter((range) => range !== '')
    .map((range) => range.split('-').map(Number));
  if (match === null || ranges.length > MAX_PEM_SECRET_RANGES) {
    return { total: null, isSecret: () => true };
  }
  const total = Number(match[2]);
  return {
    total,
    isSecret: (n) =>
      n < 1 || n > total || ranges.some(([start = 0, end = 0]) => n >= start && n <= end),
  };
}

/** Which side of the NUL the membership sits on: the side a too-long stream keeps (`tail` keeps
 *  its end, `head` and `cat` their start), so a cut can drop read lines but never the membership. */
type MembershipSide = 'first' | 'last';

/** The last line a tail read prints: the membership's line count, or `--lines`' B when that is
 *  lower or the count is unknown. The shell computes the same `e` before it reads. */
function tailReadEnd(range: LineRange | null, total: number | null): number {
  const t = total ?? 0;
  if (range === null) {
    return t;
  }
  return t > 0 && t < range.end ? t : range.end;
}

/** The remote read for head/tail: the whole file's PEM membership, taken first, then the lines, a
 *  NUL between them. A tail read stops at the membership's last line (`tailReadEnd`), so its lines
 *  are numbered back from that line even after the transport cut its front; an env-shaped `--lines`
 *  read starts at line 1 (its masking needs every value from its start). A range is cut with
 *  `head | tail -n +A`, never `sed`: busybox sed counts a NUL as a line break, so its line numbers
 *  would drift from the membership's. With no usable count, tail runs as asked and every line it
 *  prints is masked. The exit status is the read's. */
function textReadCommand(
  path: string,
  range: LineRange | null,
  count: string,
  side: MembershipSide,
): string {
  let read: string;
  if (range === null) {
    read =
      side === 'first'
        ? `head -n ${shq(count)} -- "$p"`
        : `t=\${m##*=}; case $t in ''|0|*[!0-9]*) tail -n ${shq(count)} -- "$p" ;; *) head -n "$t" -- "$p" | tail -n ${shq(count)} ;; esac`;
  } else {
    const end = side === 'first' ? String(range.end) : '"$e"';
    const lines = isEnvFile(path)
      ? `head -n ${end} -- "$p"`
      : `if [ -f "$p" ]; then head -n ${end} -- "$p" | tail -n +${range.start}; else head -n 1 -- "$p"; exit 1; fi`;
    read =
      side === 'first'
        ? lines
        : `t=\${m##*=}; e=${range.end}; case $t in ''|0|*[!0-9]*) ;; *) [ "$t" -lt "$e" ] && e=$t ;; esac; ${lines}`;
  }
  const membership = `m=$(${pemMembershipScript('"$p"')})`;
  const script =
    side === 'first'
      ? [`p=${shq(path)}`, membership, `printf '%s\\0' "$m"`, read].join('; ')
      : [`p=${shq(path)}`, membership, read, 'rc=$?', `printf '\\0%s' "$m"`, 'exit $rc'].join('; ');
  return shellJoin(['sh', '-c', script]);
}

/** Output of a read split into the lines and the membership (null when the NUL was cut off). */
function splitMembership(
  text: string,
  side: MembershipSide,
): { body: string; membership: string | null } {
  const at = side === 'first' ? text.indexOf('\0') : text.lastIndexOf('\0');
  if (at === -1) {
    return { body: text, membership: null };
  }
  return side === 'first'
    ? { body: text.slice(at + 1), membership: text.slice(0, at) }
    : { body: text.slice(0, at), membership: text.slice(at + 1) };
}

/** A read's text as lines, without the empty string a final newline leaves. */
function readLines(body: string): string[] {
  const lines = body.split('\n');
  if (lines.at(-1) === '') {
    lines.pop();
  }
  return lines;
}

interface FilesCatResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  masked: boolean;
  content: string | null;
}

/** `files cat`'s `truncated` also covers a `content` that `--max-bytes` (or the transport) cut. */
function recountCat(before: unknown, after: unknown, sourceCut: boolean): unknown {
  if (typeof after !== 'object' || after === null || !Object.hasOwn(after, 'truncated')) {
    return after;
  }
  const content = (after as { content?: unknown }).content;
  const original = (before as { content?: unknown } | null)?.content;
  return sourceCut || content !== original ? { ...after, truncated: true } : after;
}

const filesCat: OpSpec<FilesCatResult> = {
  group: 'files',
  name: 'cat',
  summary: `Read a file (size-guarded at ${FILE_CAT_MAX_BYTES} bytes); .env-shaped files are masked unless --reveal names the key.`,
  args: [
    arg('path', 'positional', true, 'Remote file path — must be on files-allowlist.toml.'),
    arg(
      'reveal',
      'flag',
      false,
      'Comma-separated key names to unmask (env files only) — each must clear the hardcoded secret-pattern denylist and be on reveal-allowlist.toml.',
    ),
    LINES_ARG,
  ],
  mutating: false,
  exposes: 'content',
  exposeStderr: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [
    { kind: 'path', scope: 'files', argName: 'path' },
    { kind: 'reveal-keys', argName: 'reveal' },
  ],
  recount: recountCat,
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    const read =
      lineRangeOf(ctx) === null
        ? 'cat "$p"'
        : `m=$(${pemMembershipScript('"$p"')}); printf '%s\\0' "$m"; cat "$p"`;
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${FILE_CAT_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else ${read}; fi`,
    ].join('; ');
    return shellJoin(['sh', '-c', script]);
  },
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const trimmed = text.trim();
    if (trimmed === '__NOT_FOUND__') {
      return { found: false, truncated: false, size_bytes: null, masked: false, content: null };
    }
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(trimmed);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        masked: false,
        content: null,
      };
    }
    const path = reqStr(ctx, 'path');
    const shouldMask = isEnvFile(path);
    const range = lineRangeOf(ctx);
    if (range !== null) {
      const split = splitMembership(text, 'first');
      const membership = parsePemMembership(split.membership);
      const lines = readLines(split.body);
      const shown = shouldMask ? maskEnvLines(lines, revealKeysOf(ctx, 'reveal')) : lines;
      const content = shown
        .slice(range.start - 1, range.end)
        .map((line, index) => (membership.isSecret(range.start + index) ? MASK : line))
        .join('\n');
      return {
        found: true,
        truncated: false,
        size_bytes: Buffer.byteLength(content, 'utf8'),
        masked: shouldMask,
        content,
      };
    }
    return {
      found: true,
      truncated: false,
      size_bytes: Buffer.byteLength(text, 'utf8'),
      masked: shouldMask,
      content: shouldMask ? maskEnvContent(text, revealKeysOf(ctx, 'reveal')) : text,
    };
  },
};

interface FilesTailResult {
  lines: string[];
  lines_returned: number;
}

/** The lines of a file read by `tail`/`head`, numbered as in the file: from line 1 (head, and any
 *  env-shaped `--lines` read), from A (a plain file's `--lines` on head), or back from the last line
 *  the read printed (tail, which the host stopped at `tailReadEnd`). Env-shaped files are masked
 *  as their whole file masks them (every line, should a front cut have taken their line 1), then
 *  every line the file's PEM membership calls secret. */
function shapeTextLines(
  text: string,
  path: string,
  range: LineRange | null,
  side: MembershipSide,
): Premasked<FilesTailResult> {
  const split = splitMembership(text, side);
  const membership = parsePemMembership(split.membership);
  const raw = readLines(split.body);
  const env = isEnvFile(path);
  const shown = !env
    ? raw
    : range === null
      ? readLines(maskEnvContent(split.body, new Set()))
      : maskEnvLines(raw, new Set());
  const first =
    side === 'last'
      ? tailReadEnd(range, membership.total) - raw.length + 1
      : range !== null && !env
        ? range.start
        : 1;
  const lostStart = env && range !== null && first !== 1;
  const lines: string[] = [];
  let masked = 0;
  shown.forEach((line, index) => {
    const n = first + index;
    const trimmed = line.trimEnd();
    if (trimmed.length === 0 || (range !== null && (n < range.start || n > range.end))) {
      return;
    }
    const out = lostStart || membership.isSecret(n) ? MASK : trimmed;
    masked += out === trimmed ? 0 : 1;
    lines.push(out);
  });
  return new Premasked({ lines, lines_returned: lines.length }, masked);
}

const filesTail: OpSpec<FilesTailResult> = {
  group: 'files',
  name: 'tail',
  summary: 'Tail N lines of a file.',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be on files-allowlist.toml.'),
    arg('n', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
    LINES_ARG,
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  truncateKeeps: 'tail',
  capLines,
  recount: recountLines,
  buildRemote: (ctx) => {
    const range = lineRangeOf(ctx);
    const count = range === null ? optStr(ctx, 'n', String(DEFAULT_LOG_TAIL)) : '';
    return textReadCommand(reqStr(ctx, 'path'), range, count, 'last');
  },
  shape: (parsed, ctx) =>
    shapeTextLines(parsed as string, reqStr(ctx, 'path'), lineRangeOf(ctx), 'last'),
};

function boundedLineCount(ctx: OpContext, name: string, fallback: number, max: number): number {
  const raw = optStrOrNull(ctx, name);
  if (raw === null) {
    return fallback;
  }
  const value = /^\d+$/.test(raw) ? Number.parseInt(raw, 10) : 0;
  if (value < 1 || value > max) {
    throw new OpError(
      'INVALID_ARGS',
      `--${name} must be a whole number from 1 to ${max} (got '${raw}')`,
    );
  }
  return value;
}

const filesHead: OpSpec<FilesTailResult> = {
  group: 'files',
  name: 'head',
  summary: `First N lines of a file (default ${DEFAULT_HEAD_LINES}, at most ${MAX_HEAD_LINES}); .env-shaped files are masked like files tail.`,
  args: [
    arg('path', 'positional', true, 'Remote file path — must be on files-allowlist.toml.'),
    arg('n', 'flag', false, `Number of lines (default ${DEFAULT_HEAD_LINES}).`),
    LINES_ARG,
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  capLines,
  recount: recountLines,
  buildRemote: (ctx) => {
    const range = lineRangeOf(ctx);
    const count =
      range === null ? String(boundedLineCount(ctx, 'n', DEFAULT_HEAD_LINES, MAX_HEAD_LINES)) : '';
    return textReadCommand(reqStr(ctx, 'path'), range, count, 'first');
  },
  shape: (parsed, ctx) =>
    shapeTextLines(parsed as string, reqStr(ctx, 'path'), lineRangeOf(ctx), 'first'),
};

/** Private-key-shaped file names `files grep` never reads, however the pattern matches. */
const GREP_SKIPPED_NAMES = [
  '*.pem',
  '*.key',
  '*.p12',
  '*.pfx',
  'id_rsa*',
  'id_ed25519*',
  'id_ecdsa*',
];

const NOT_FOUND_MARKER = '__NOT_FOUND__';
const ESCAPE_MARKER = '__ESCAPE__';

/** A pattern or glob rides one quoted argv slot, so only what no quoting can carry is refused:
 *  NUL, and a line break (grep reads each line of a pattern as another pattern). */
function assertSearchText(op: string, flag: string, value: string, maxChars: number): void {
  if (/[\0\r\n]/.test(value)) {
    throw new OpError(
      'INVALID_ARGS',
      `${op}: ${flag} contains a NUL or line-break character (got ${JSON.stringify(value)})`,
      { hint: `Pass ${flag} on one line.` },
    );
  }
  if (value.length > maxChars) {
    throw new OpError(
      'INVALID_ARGS',
      `${op}: ${flag} is ${value.length} characters; the limit is ${maxChars}`,
      {
        hint: `Shorten ${flag} to at most ${maxChars} characters.`,
      },
    );
  }
}

/** Resolves the root on the host and refuses it unless it still lies under an allowlisted entry
 *  there: a symlink (the root itself or a parent) cannot lead a search out of the allowlist. The
 *  search then runs on the resolved path, and `find` never follows a link below it. */
function searchRootScript(path: string, alias: string): string {
  const entries = (loadFilesAllowlist()[alias] ?? []).filter((entry) => entry !== '/');
  return [
    `p=${shq(path)}`,
    `if [ ! -e "$p" ]; then echo ${NOT_FOUND_MARKER}; exit 0; fi`,
    `r=$(realpath -- "$p") || { echo ${NOT_FOUND_MARKER}; exit 0; }`,
    'ok=0',
    `for a in ${entries.map(shq).join(' ') || "''"}; do ra=$(realpath -- "$a" 2>/dev/null) || continue; case "$r" in "$ra"|"$ra"/*) ok=1;; esac; done`,
    `if [ "$ok" != 1 ]; then echo ${ESCAPE_MARKER}; exit 0; fi`,
  ].join('; ');
}

interface FilesGrepResult {
  found: boolean;
  lines: string[];
  lines_returned: number;
  truncated: boolean;
}

/** Env-shaped basenames, the shell twin of `isEnvFile` (matched on the lower-cased basename). */
const ENV_FILE_CASE = '*.env*|*.vars|*.secrets|credentials*|*.pem|id_*';

/** Run per file, so every block of grep output arrives behind the path it came from (`path NUL
 *  lines NUL whole NUL membership NUL`) and nothing has to split a path out of a line: `$1` is the
 *  pattern, the rest are files. `whole` is empty except for an env-shaped file, where it is the file
 *  itself (its first `FILE_CAT_MAX_BYTES`, base64 on one line): a matched line inside a multi-line
 *  value can only be masked knowing every line above it. `membership` is the whole file's PEM
 *  membership (`pemMembershipScript`), so a matched key body line is masked whether or not its BEGIN
 *  matched too. A file holding a NUL is skipped as binary, as GNU grep's -I already does: busybox
 *  grep reads past -I and counts a NUL as a line break, so its line numbers would drift from the
 *  membership's. A NUL never occurs in a path or in a text line. */
function grepPerFileScript(flags: string[]): string {
  return [
    'p=$1',
    'shift',
    [
      `for f do out=$(grep ${shellJoin(flags)} -e "$p" -- "$f" | head -n ${MAX_GREP_MATCH_LINES + 1})`,
      '[ -n "$out" ] || continue',
      `case $(tr -dc '\\000' < "$f" | wc -c) in *[1-9]*) continue ;; esac`,
      `case "$(printf '%s' "\${f##*/}" | tr 'A-Z' 'a-z')" in ${ENV_FILE_CASE}) whole=$(head -c ${FILE_CAT_MAX_BYTES} -- "$f" | base64 | tr -d '\\n') ;; *) whole='' ;; esac`,
      `pem=$(${pemMembershipScript('"$f"')})`,
      `printf '%s\\0%s\\n\\0%s\\0%s\\n\\0' "$f" "$out" "$whole" "$pem"`,
      'done',
    ].join('; '),
  ].join('; ');
}

/** `12:text` (a match), `12-text` (context) or `--` (between context groups) of one file. */
const GREP_FILE_LINE = /^(\d+)([:-])(.*)$/s;

/** One file's grep lines, parsed (null for a `--` separator). */
function grepBlockLines(block: string): (RegExpExecArray | null)[] {
  return block
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => GREP_FILE_LINE.exec(line));
}

/** One file's lines back in `path:12:text` form, masked: an env-shaped file line by line as
 *  `maskEnvLines` masks the whole file (a line past what arrived of it is masked whole), then every
 *  line that file's own PEM membership calls secret. */
function maskGrepGroup(path: string, block: string, whole: string, membership: string): string[] {
  const parsed = grepBlockLines(block);
  const envLines = isEnvFile(path)
    ? maskEnvLines(Buffer.from(whole, 'base64').toString('utf8').split('\n'), new Set())
    : null;
  const texts = parsed.map((match) => {
    const text = match?.[3] ?? '';
    if (envLines === null || match === null) {
      return text;
    }
    return envLines[Number(match[1]) - 1] ?? MASK;
  });
  const pem = parsePemMembership(membership);
  return parsed.map((match, index) => {
    if (match === null) {
      return '--';
    }
    const text = pem.isSecret(Number(match[1])) ? MASK : texts[index];
    return `${path}${match[2]}${match[1]}${match[2]}${text}`;
  });
}

/** The whole answer as grep's own `path:12:text` lines, each file's block masked as one group, and
 *  the same lines unmasked (to count what masking changed). */
function grepLines(text: string): { lines: string[]; unmasked: string[] } {
  const parts = text.split('\0');
  const lines: string[] = [];
  const unmasked: string[] = [];
  for (let i = 0; i + 1 < parts.length; i += 4) {
    const path = parts[i] ?? '';
    const block = parts[i + 1] ?? '';
    lines.push(...maskGrepGroup(path, block, parts[i + 2] ?? '', parts[i + 3] ?? ''));
    unmasked.push(
      ...grepBlockLines(block).map((match) =>
        match === null ? '--' : `${path}${match[2]}${match[1]}${match[2]}${match[3]}`,
      ),
    );
  }
  return { lines, unmasked };
}

function refusedSearchRoot(op: string, ctx: OpContext): OpError {
  return new OpError(
    'VALIDATION_ERROR',
    `${op}: '${reqStr(ctx, 'path')}' resolves outside every files-allowlist.toml root for alias '${ctx.alias}' (a symlink leads out of it), so nothing was read`,
    {
      hint: 'Search the real directory, and have a human declare it with setup files-allowlist scaffold if it is meant to be searchable.',
    },
  );
}

const filesGrep: OpSpec<FilesGrepResult> = {
  group: 'files',
  name: 'grep',
  summary: `Search text files under an allowlisted root for an extended regex (at most ${MAX_GREP_MATCH_LINES} lines; binary and private-key files skipped); env-file lines are masked.`,
  args: [
    arg(
      'path',
      'positional',
      true,
      'Remote directory or file — must be on, or under, a files-allowlist.toml entry.',
    ),
    arg(
      'pattern',
      'positional',
      true,
      `Extended regex, at most ${MAX_FILES_GREP_PATTERN_CHARS} characters, one line.`,
    ),
    arg(
      'context',
      'flag',
      false,
      `Lines of context either side of a match (0 to ${MAX_GREP_CONTEXT_LINES}).`,
    ),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path', within: true }],
  capLines,
  recount: recountLines,
  buildRemote: (ctx) => {
    const pattern = reqStr(ctx, 'pattern');
    assertSearchText('files grep', 'pattern', pattern, MAX_FILES_GREP_PATTERN_CHARS);
    const rawContext = optStrOrNull(ctx, 'context');
    const context = rawContext === null ? 0 : Number(rawContext);
    if (!Number.isInteger(context) || context < 0 || context > MAX_GREP_CONTEXT_LINES) {
      throw new OpError(
        'INVALID_ARGS',
        `--context must be a whole number from 0 to ${MAX_GREP_CONTEXT_LINES} (got '${rawContext}')`,
      );
    }
    const skipped = GREP_SKIPPED_NAMES.flatMap((name) => ['!', '-name', name]);
    const grepFlags = context > 0 ? ['-InE', '-C', String(context)] : ['-InE'];
    const search = `find "$r" -type f ${shellJoin(skipped)} -exec sh -c ${shq(grepPerFileScript(grepFlags))} sh ${shq(pattern)} {} +`;
    return niced(
      shellJoin([
        'sh',
        '-c',
        [
          searchRootScript(reqStr(ctx, 'path'), ctx.alias),
          `${search} | head -n ${MAX_GREP_MATCH_LINES + 1}`,
        ].join('; '),
      ]),
    );
  },
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const marker = text.trim();
    if (marker === NOT_FOUND_MARKER) {
      return { found: false, lines: [], lines_returned: 0, truncated: false };
    }
    if (marker === ESCAPE_MARKER) {
      throw refusedSearchRoot('files grep', ctx);
    }
    const all = grepLines(text);
    const lines = all.lines.slice(0, MAX_GREP_MATCH_LINES);
    return new Premasked(
      {
        found: true,
        lines,
        lines_returned: lines.length,
        truncated: all.lines.length > MAX_GREP_MATCH_LINES,
      },
      lines.filter((line, index) => line !== all.unmasked[index]).length,
    );
  },
};

interface FilesFindResult {
  found: boolean;
  paths: string[];
  paths_returned: number;
  truncated: boolean;
}

const filesFind: OpSpec<FilesFindResult> = {
  group: 'files',
  name: 'find',
  summary: `List paths under an allowlisted root, optionally only those whose name matches a glob (at most ${MAX_FIND_RESULTS} paths; symlinks are not followed).`,
  args: [
    arg(
      'path',
      'positional',
      true,
      'Remote directory — must be on, or under, a files-allowlist.toml entry.',
    ),
    arg(
      'name',
      'flag',
      false,
      `Glob for the file name, at most ${MAX_FIND_NAME_CHARS} characters, one line.`,
    ),
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path', within: true }],
  buildRemote: (ctx) => {
    const name = optStrOrNull(ctx, 'name');
    if (name !== null) {
      assertSearchText('files find', '--name', name, MAX_FIND_NAME_CHARS);
    }
    const nameTest = name === null ? '' : ` -name ${shq(name)}`;
    return niced(
      shellJoin([
        'sh',
        '-c',
        [
          searchRootScript(reqStr(ctx, 'path'), ctx.alias),
          `find "$r"${nameTest} | head -n ${MAX_FIND_RESULTS + 1}`,
        ].join('; '),
      ]),
    );
  },
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const marker = text.trim();
    if (marker === NOT_FOUND_MARKER) {
      return { found: false, paths: [], paths_returned: 0, truncated: false };
    }
    if (marker === ESCAPE_MARKER) {
      throw refusedSearchRoot('files find', ctx);
    }
    const all = text.split('\n').filter((line) => line.length > 0);
    const paths = all.slice(0, MAX_FIND_RESULTS);
    return {
      found: true,
      paths,
      paths_returned: paths.length,
      truncated: all.length > MAX_FIND_RESULTS,
    };
  },
};

interface FilesDownloadResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  written: boolean;
  masked: boolean;
  local_path: string | null;
}

const UTF8 = new TextDecoder('utf-8', { fatal: true });

function decodeText(bytes: Buffer): string | null {
  try {
    const text = UTF8.decode(bytes);
    return text.includes('\u0000') ? null : text;
  } catch {
    return null;
  }
}

/** What `files download` writes: a text file gets the same masking `files cat` shows (whole-file
 *  for env-shaped paths, then the scrubber), with `--reveal` keys left as they are; a binary file
 *  (invalid UTF-8 or a NUL byte) is written byte for byte, since rewriting it would corrupt it —
 *  except on an env-shaped path, where its `KEY=` lines are masked on the bytes (read as latin1,
 *  one char per byte, so every other byte is written back unchanged). */
function downloadBytes(
  raw: Buffer,
  path: string,
  alias: string,
  revealKeys: Set<string>,
): { bytes: Buffer; masked: boolean } {
  const text = decodeText(raw);
  if (text === null) {
    if (!isEnvFile(path)) {
      return { bytes: raw, masked: false };
    }
    const latin1 = raw.toString('latin1');
    const envMasked = maskEnvContent(latin1, revealKeys);
    return { bytes: Buffer.from(envMasked, 'latin1'), masked: envMasked !== latin1 };
  }
  const envMasked = isEnvFile(path) ? maskEnvContent(text, revealKeys) : text;
  const scrubbed = scrubText(envMasked, {
    revealKeys,
    extraPatterns: loadScrubExtraPatterns(alias),
  }).value;
  return { bytes: Buffer.from(scrubbed, 'utf8'), masked: scrubbed !== text };
}

/** Writes the decoded bytes straight to local disk and never returns them — this is the
 *  zero-knowledge boundary for `files download`. Earlier versions inlined the whole file
 *  as `content_base64` in the JSON envelope (the caller's tool-result/context), which
 *  defeated `files cat`'s masking for any file downloaded this way, `.env`-shaped or not
 *  (see SKILL.md Gotchas #10). Base64 still transits the ssh channel and briefly lives in
 *  this process's memory to decode — that's the same local-process exposure `files cat`
 *  already has before masking runs, not a new one; the fix is that raw content never
 *  crosses back into the envelope that reaches the agent. */
function writeDownloadedFile(localPath: string, bytes: Buffer): void {
  try {
    writeFileSync(localPath, bytes);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new OpError(
      'VALIDATION_ERROR',
      `files download: could not write local file '${localPath}': ${reason}`,
    );
  }
}

const filesDownload: OpSpec<FilesDownloadResult> = {
  group: 'files',
  name: 'download',
  summary: `Read a file as base64 over the existing ssh channel (size-guarded at ${DOWNLOAD_MAX_BYTES} bytes) and write it straight to a local path — no separate scp/sftp process, and the raw content never enters the JSON envelope.`,
  args: [
    arg('path', 'positional', true, 'Remote file path — must be on files-allowlist.toml.'),
    arg('local_path', 'positional', true, 'Local destination path to write the file to.'),
    arg(
      'reveal',
      'flag',
      false,
      'Comma-separated key names written unmasked — same denylist + reveal-allowlist.toml gate as files cat.',
    ),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: DOWNLOAD_TIMEOUT_SEC,
  maxStdoutBytes: DOWNLOAD_MAX_STDOUT_BYTES,
  output: 'raw',
  allowlist: [
    { kind: 'path', scope: 'files', argName: 'path' },
    { kind: 'reveal-keys', argName: 'reveal' },
  ],
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${DOWNLOAD_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else echo "__OK__:$sz"; base64 "$p" | tr -d '\\n'; fi`,
    ].join('; ');
    return shellJoin(['sh', '-c', script]);
  },
  shapeError: (raw) =>
    raw.stdout.length === 0
      ? undefined
      : { written: false, bytes_received: Buffer.byteLength(raw.stdout, 'utf8') },
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const localPath = reqStr(ctx, 'local_path');
    const newlineIndex = text.indexOf('\n');
    const firstLine = newlineIndex === -1 ? text : text.slice(0, newlineIndex);

    if (firstLine === '__NOT_FOUND__') {
      return {
        found: false,
        truncated: false,
        size_bytes: null,
        written: false,
        masked: false,
        local_path: null,
      };
    }
    const tooLarge = DOWNLOAD_HEADER_TOO_LARGE.exec(firstLine);
    if (tooLarge) {
      return {
        found: true,
        truncated: true,
        size_bytes: Number.parseInt(tooLarge[1] ?? '', 10),
        written: false,
        masked: false,
        local_path: null,
      };
    }
    const ok = DOWNLOAD_HEADER_OK.exec(firstLine);
    if (ok?.[1] === undefined) {
      throw new OpError(
        'PARSE_ERROR',
        `files download: the answer for '${reqStr(ctx, 'path')}' does not open with a canonical size header, so nothing was written to '${localPath}'`,
        {
          hint: 'The header must be exactly __OK__:<bytes> with no padding or leading zeros; run it again, and use files tail if the host keeps answering this way.',
        },
      );
    }
    const size = Number.parseInt(ok[1], 10);
    const contentBase64 = newlineIndex === -1 ? '' : text.slice(newlineIndex + 1).trim();
    const raw = Buffer.from(contentBase64, 'base64');
    if (raw.length !== size) {
      throw new OpError(
        'OUTPUT_TOO_LARGE',
        `files download: the host reported ${size} bytes for '${reqStr(ctx, 'path')}' but ${raw.length} arrived, so nothing was written to '${localPath}'`,
        {
          hint: `The read stopped before the whole file arrived (the ceiling is ${DOWNLOAD_MAX_STDOUT_BYTES} bytes of base64, enough for a ${DOWNLOAD_MAX_BYTES}-byte file), or the file changed while it was read; run it again, and use files tail for a file that is still being written.`,
        },
      );
    }
    const { bytes, masked } = downloadBytes(
      raw,
      reqStr(ctx, 'path'),
      ctx.alias,
      revealKeysOf(ctx, 'reveal'),
    );
    writeDownloadedFile(localPath, bytes);
    return {
      found: true,
      truncated: false,
      size_bytes: size,
      written: true,
      masked,
      local_path: localPath,
    };
  },
};

interface FilesDiskUsageResult {
  path: string;
  size_bytes: number | null;
}

const filesDiskUsage: OpSpec<FilesDiskUsageResult> = {
  group: 'files',
  name: 'disk-usage',
  summary: 'Total size in bytes of a remote path (du -sb).',
  args: [arg('path', 'positional', true, 'Remote path — must be on files-allowlist.toml.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  buildRemote: (ctx) => niced(shellJoin(['du', '-sb', '--', reqStr(ctx, 'path')])),
  shape: (parsed, ctx) => {
    const entries = parseDu(parsed as string);
    const first = entries[0];
    return { path: reqStr(ctx, 'path'), size_bytes: first ? first.size_bytes : null };
  },
};

// files (mutating)

/** No `.bak` (this is a general upload, not an in-place config overwrite — unlike `config put`). */
function buildFilesUploadScript(remotePath: string, contentBase64: string): string {
  const script = [
    `p=${shq(remotePath)}`,
    `printf '%s' ${shq(contentBase64)} | base64 -d > "$p"`,
  ].join('; ');
  return shellJoin(['sh', '-c', script]);
}

interface FilesUploadResult {
  written: boolean;
  remote_path: string;
}

const filesUpload: OpSpec<FilesUploadResult> = {
  group: 'files',
  name: 'upload',
  summary:
    'Upload a local file to a remote path over the existing ssh channel (base64, no scp/sftp) — destination must be on files-allowlist.toml, no backup, gated by --yes like every other mutating op.',
  args: [
    arg('local_path', 'positional', true, 'Local file path to read and upload.'),
    arg(
      'remote_path',
      'positional',
      true,
      'Destination path on the remote — must be on files-allowlist.toml.',
    ),
  ],
  mutating: true,
  exposes: 'none',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'remote_path' }],
  buildRemote: (ctx) => {
    const localPath = reqStr(ctx, 'local_path');
    const remotePath = reqStr(ctx, 'remote_path');
    let contentBase64: string;
    try {
      contentBase64 = readFileSync(localPath).toString('base64');
    } catch {
      throw new OpError(
        'VALIDATION_ERROR',
        `files upload: local file '${localPath}' not found or unreadable`,
      );
    }
    return buildFilesUploadScript(remotePath, contentBase64);
  },
  shape: (_parsed, ctx) => ({ written: true, remote_path: reqStr(ctx, 'remote_path') }),
};

export const filesOps = [
  filesLs,
  filesCat,
  filesTail,
  filesHead,
  filesGrep,
  filesFind,
  filesDownload,
  filesDiskUsage,
  filesUpload,
] as OpSpec[];

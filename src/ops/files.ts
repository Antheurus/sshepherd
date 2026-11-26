import { readFileSync, writeFileSync } from 'node:fs';
import {
  DEFAULT_HEAD_LINES,
  DOWNLOAD_MAX_BYTES,
  DOWNLOAD_MAX_STDOUT_BYTES,
  MAX_FILES_GREP_PATTERN_CHARS,
  MAX_FIND_NAME_CHARS,
  MAX_FIND_RESULTS,
  MAX_GREP_CONTEXT_LINES,
  MAX_GREP_MATCH_LINES,
  MAX_HEAD_LINES,
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
import { isEnvFile, maskEnvContent, maskPemLines, scrubText } from '../scrub.ts';
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
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${FILE_CAT_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else cat "$p"; fi`,
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
    const shouldMask = isEnvFile(reqStr(ctx, 'path'));
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

/** The lines of a file read by `tail`/`head`: env-shaped files masked whole, then PEM lines. */
function shapeTextLines(text: string, path: string): Premasked<FilesTailResult> {
  const unmasked = (isEnvFile(path) ? maskEnvContent(text, new Set()) : text)
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0);
  const lines = maskPemLines(unmasked);
  const masked = lines.filter((line, index) => line !== unmasked[index]).length;
  return new Premasked({ lines, lines_returned: lines.length }, masked);
}

const filesTail: OpSpec<FilesTailResult> = {
  group: 'files',
  name: 'tail',
  summary: 'Tail N lines of a file.',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be on files-allowlist.toml.'),
    arg('n', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  truncateKeeps: 'tail',
  capLines,
  recount: recountLines,
  buildRemote: (ctx) =>
    shellJoin([
      'tail',
      '-n',
      optStr(ctx, 'n', String(DEFAULT_LOG_TAIL)),
      '--',
      reqStr(ctx, 'path'),
    ]),
  shape: (parsed, ctx) => shapeTextLines(parsed as string, reqStr(ctx, 'path')),
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
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  capLines,
  recount: recountLines,
  buildRemote: (ctx) =>
    shellJoin([
      'head',
      '-n',
      String(boundedLineCount(ctx, 'n', DEFAULT_HEAD_LINES, MAX_HEAD_LINES)),
      '--',
      reqStr(ctx, 'path'),
    ]),
  shape: (parsed, ctx) => shapeTextLines(parsed as string, reqStr(ctx, 'path')),
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

/** `path:12:text` (a match) or `path-12-text` (context): the path part, for the env-file check. */
const GREP_LINE_PREFIX = /^(.*?)([:-])(\d+)\2/;

function maskGrepLine(line: string): string {
  const match = GREP_LINE_PREFIX.exec(line);
  const path = match?.[1];
  if (match === null || path === undefined || !isEnvFile(path)) {
    return line;
  }
  return match[0] + maskEnvContent(line.slice(match[0].length), new Set());
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
    const grepFlags = context > 0 ? ['-InHE', '-C', String(context)] : ['-InHE'];
    const search = `find "$r" -type f ${shellJoin(skipped)} -exec grep ${shellJoin(grepFlags)} -e ${shq(pattern)} -- {} +`;
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
    const all = text.split('\n').filter((line) => line.length > 0);
    const kept = all.slice(0, MAX_GREP_MATCH_LINES);
    const lines = kept.map(maskGrepLine);
    return new Premasked(
      {
        found: true,
        lines,
        lines_returned: lines.length,
        truncated: all.length > MAX_GREP_MATCH_LINES,
      },
      lines.filter((line, index) => line !== kept[index]).length,
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

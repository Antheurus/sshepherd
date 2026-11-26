import { readFileSync, writeFileSync } from 'node:fs';
import {
  arg,
  DEFAULT_LOG_TAIL,
  FILE_CAT_MAX_BYTES,
  FILE_TIMEOUT_SEC,
  optStr,
  reqStr,
} from '../op-args.ts';
import { parseDu } from '../parsers/du.ts';
import { parseLs } from '../parsers/ls.ts';
import { shellJoin, shq } from '../quote.ts';
import { isEnvFile, maskEnvContent, maskPemLines, scrubText } from '../scrub.ts';
import { OpError, type OpSpec } from '../types.ts';
import { loadScrubExtraPatterns, revealKeysOf } from './config.ts';

const DOWNLOAD_TIMEOUT_SEC = 30;
const DOWNLOAD_MAX_BYTES = 10_485_760; // 10 MiB

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
  buildRemote: (ctx) =>
    shellJoin([
      'tail',
      '-n',
      optStr(ctx, 'n', String(DEFAULT_LOG_TAIL)),
      '--',
      reqStr(ctx, 'path'),
    ]),
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const lines = maskPemLines(
      (isEnvFile(reqStr(ctx, 'path')) ? maskEnvContent(text, new Set()) : text)
        .split('\n')
        .map((line) => line.trimEnd())
        .filter((line) => line.length > 0),
    );
    return { lines, lines_returned: lines.length };
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
  contentBase64: string,
  path: string,
  alias: string,
  revealKeys: Set<string>,
): { bytes: Buffer; masked: boolean } {
  const raw = Buffer.from(contentBase64, 'base64');
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
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const localPath = reqStr(ctx, 'local_path');
    const newlineIndex = text.indexOf('\n');
    const firstLine = (newlineIndex === -1 ? text : text.slice(0, newlineIndex)).trim();

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
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(firstLine);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        written: false,
        masked: false,
        local_path: null,
      };
    }
    const ok = /^__OK__:(\d+)/.exec(firstLine);
    const size = ok?.[1];
    const contentBase64 = newlineIndex === -1 ? '' : text.slice(newlineIndex + 1).trim();
    const { bytes, masked } = downloadBytes(
      contentBase64,
      reqStr(ctx, 'path'),
      ctx.alias,
      revealKeysOf(ctx, 'reveal'),
    );
    writeDownloadedFile(localPath, bytes);
    return {
      found: true,
      truncated: false,
      size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
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
  buildRemote: (ctx) => shellJoin(['du', '-sb', '--', reqStr(ctx, 'path')]),
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
  filesDownload,
  filesDiskUsage,
  filesUpload,
] as OpSpec[];

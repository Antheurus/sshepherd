import { readFileSync } from 'node:fs';
import { ENV_LENGTH_BUCKET_BOUNDS } from '../limits.ts';
import { arg, assertPositional, FILE_TIMEOUT_SEC, optStrOrNull, reqStr } from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import { didYouMean } from '../suggest.ts';
import { declaredContainers } from '../targets.ts';
import { OpError, type OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// env — key names only. The value of a variable never leaves the host: one remote command reads
// the env (a container's, or a file's) and prints `KEY<TAB>state<TAB>bucket` per variable, so
// the local process has no value to filter, mask or leak. The scrubber is the second line.
// ---------------------------------------------------------------------------

const [BUCKET_SMALL, BUCKET_MEDIUM] = ENV_LENGTH_BUCKET_BOUNDS;
export const ENV_BUCKET_LABELS = [
  '0',
  `1-${BUCKET_SMALL}`,
  `${BUCKET_SMALL + 1}-${BUCKET_MEDIUM}`,
  `${BUCKET_MEDIUM + 1}+`,
];

const BUCKET_EXPR = (len: string): string =>
  `(${len} == 0) ? "${ENV_BUCKET_LABELS[0]}" : (${len} <= ${BUCKET_SMALL}) ? "${ENV_BUCKET_LABELS[1]}" : (${len} <= ${BUCKET_MEDIUM}) ? "${ENV_BUCKET_LABELS[2]}" : "${ENV_BUCKET_LABELS[3]}"`;

/** Reads `docker inspect`'s Env on stdin, one JSON string per line (a newline inside a value is
 *  already escaped there). Prints only the key, whether the value is empty, and the length bucket. */
const JSON_ENV_AWK = [
  '{ line = $0',
  'line = substr(line, 2, length(line) - 2)',
  'eq = index(line, "="); if (eq < 2) next',
  'key = substr(line, 1, eq - 1); if (key !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next',
  'val = substr(line, eq + 1); sub(/^[ \\t]+/, "", val); sub(/[ \\t\\r]+$/, "", val)',
  'n = length(val)',
  `b = ${BUCKET_EXPR('n')}`,
  'print key "\\t" ((n == 0) ? "empty" : "set") "\\t" b }',
].join('; ');

/** Reads a `.env` file the way dotenv loaders do: `[export ]KEY = value`, `#` comments, CRLF, and a
 *  single- or double-quoted value that runs over several lines (a PEM key, JSON, wrapped base64)
 *  until its closing quote, a backslash escaping the next character. A key is only ever read from
 *  the start of an entry, never from a line inside a quoted value. Prints the same three columns
 *  as `JSON_ENV_AWK`; the value's length counts the newlines inside it. */
export const DOTENV_AWK = String.raw`
function emit(k, n) { print k "\t" ((n == 0) ? "empty" : "set") "\t" (${BUCKET_EXPR('n')}) }
function closing(s, q,   i, c) {
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\\") { i++; continue }
    if (c == q) return i
  }
  return 0
}
{
  line = $0
  sub(/\r$/, "", line)
  if (open != "") {
    p = closing(line, open)
    if (p == 0) { len += length(line) + 1; next }
    emit(key, len + p - 1); open = ""; next
  }
  sub(/^[ \t]+/, "", line)
  if (line == "" || substr(line, 1, 1) == "#") next
  sub(/^export[ \t]+/, "", line)
  eq = index(line, "="); if (eq < 2) next
  key = substr(line, 1, eq - 1); sub(/[ \t]+$/, "", key)
  if (key !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next
  val = substr(line, eq + 1); sub(/^[ \t]+/, "", val)
  q = substr(val, 1, 1)
  if (q == "\"" || q == "'") {
    rest = substr(val, 2)
    p = closing(rest, q)
    if (p > 0) { emit(key, p - 1); next }
    open = q; len = length(rest) + 1; next
  }
  sub(/[ \t]+#.*$/, "", val); sub(/[ \t]+$/, "", val)
  emit(key, length(val))
}
END { if (open != "") emit(key, len) }
`;

export interface EnvKeyEntry {
  key: string;
  state: 'set' | 'empty';
  length_bucket: string;
}

const KEY_LINE = /^([A-Za-z_][A-Za-z0-9_]*)\t(set|empty)\t(0|\d+-\d+|\d+\+)$/;

/** Only a line of exactly the shape the remote awk prints is an entry; anything else is dropped,
 *  so a stray line can never carry text into the envelope. A repeated key keeps its last state,
 *  as a dotenv loader does. */
export function parseEnvKeyLines(text: string): EnvKeyEntry[] {
  const byKey = new Map<string, EnvKeyEntry>();
  for (const line of text.split('\n')) {
    const match = KEY_LINE.exec(line.replace(/\r$/, ''));
    const [, key, state, bucket] = match ?? [];
    if (key !== undefined && (state === 'set' || state === 'empty') && bucket !== undefined) {
      byKey.set(key, { key, state, length_bucket: bucket });
    }
  }
  return [...byKey.values()];
}

const NOT_FOUND = '__NOT_FOUND__';

function envFileScript(path: string): string {
  return [
    `p=${shq(path)}`,
    `if [ ! -f "$p" ]; then echo ${NOT_FOUND}; exit 0; fi`,
    `awk ${shq(DOTENV_AWK)} "$p"`,
  ].join('; ');
}

/** The remote half of "which variables does this container define": `containerRef` is the shell
 *  text naming the container (`"$c"`), and the Go template emits one JSON string per variable. */
export function containerEnvSummaryScript(containerRef: string): string {
  return [
    `out=$(docker inspect --type container --format '{{range .Config.Env}}{{json .}}{{"\\n"}}{{end}}' -- ${containerRef}) || exit $?`,
    `printf '%s\\n' "$out" | awk ${shq(JSON_ENV_AWK)}`,
  ].join('; ');
}

function containerEnvScript(container: string): string {
  return [
    `c=${shq(container)}`,
    'command -v docker >/dev/null 2>&1 || exit 127',
    containerEnvSummaryScript('"$c"'),
  ].join('; ');
}

function envSource(ctx: Parameters<OpSpec['buildRemote']>[0]): string {
  const container = optStrOrNull(ctx, 'container');
  const path = optStrOrNull(ctx, 'path');
  if ((container === null) === (path === null)) {
    throw new OpError('INVALID_ARGS', 'env keys needs exactly one of --container or --path', {
      hint: 'Pass --container NAME for a running container, or --path FILE for an allowlisted env file.',
    });
  }
  if (container !== null) {
    assertPositional('container', container);
    const declared = declaredContainers(ctx.alias);
    if (!declared.includes(container)) {
      throw new OpError(
        'VALIDATION_ERROR',
        `env keys: container '${container}' is not declared for alias '${ctx.alias}' in targets.toml`,
        {
          hint: 'A human lists it in containers = [...] on a targets.toml entry whose alias is this one; the agent never widens its own list.',
          did_you_mean: didYouMean(container, declared),
        },
      );
    }
    return shellJoin(['sh', '-c', containerEnvScript(container)]);
  }
  assertPositional('path', path as string);
  return shellJoin(['sh', '-c', envFileScript(path as string)]);
}

const envKeys: OpSpec<EnvKeyEntry[]> = {
  group: 'env',
  name: 'keys',
  summary:
    'Key names of a container environment or an env file, each with set/empty and a coarse length bucket — values never leave the host.',
  args: [
    arg(
      'container',
      'flag',
      false,
      'Container name — must be in containers = [...] of a targets.toml entry on this alias (not combined with --path).',
    ),
    arg(
      'path',
      'flag',
      false,
      'Remote env file — must be on files-allowlist.toml (not combined with --container).',
    ),
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path', optional: true }],
  buildRemote: (ctx) => envSource(ctx),
  shape: (parsed, ctx) => {
    const text = parsed as string;
    if (text.trim() === NOT_FOUND) {
      throw new OpError(
        'VALIDATION_ERROR',
        `env keys: '${optStrOrNull(ctx, 'path') ?? ''}' is not a file on the host`,
        { hint: 'Check the path with files ls on its parent directory.' },
      );
    }
    return parseEnvKeyLines(text);
  },
};

/** Key names a local `.env.example`-style file defines, read by the same `DOTENV_AWK` the host runs
 *  on the remote file (multi-line quoted values, escaped quotes, `export`, CRLF, comments,
 *  `KEY = value`), so both sides of the diff agree on what a key is. Only the key column is kept. */
export function readAgainstKeys(localPath: string): Set<string> {
  let text: Buffer;
  try {
    text = readFileSync(localPath);
  } catch {
    throw new OpError(
      'VALIDATION_ERROR',
      `env diff: local file '${localPath}' not found or unreadable`,
      { hint: '--against names a LOCAL file such as ./.env.example.' },
    );
  }
  const awk = Bun.spawnSync(['awk', DOTENV_AWK], { stdin: text, stdout: 'pipe', stderr: 'pipe' });
  if (awk.exitCode !== 0) {
    throw new OpError(
      'COMMAND_FAILED',
      `env diff: reading the key names of local file '${localPath}' with awk failed (exit ${awk.exitCode})`,
      {
        hint: 'env diff needs a POSIX awk on PATH locally, the same one the host uses for the remote file.',
      },
    );
  }
  return new Set(parseEnvKeyLines(awk.stdout.toString()).map((entry) => entry.key));
}

interface EnvDiffResult {
  missing: string[];
  extra: string[];
  empty: string[];
}

const envDiff: OpSpec<EnvDiffResult> = {
  group: 'env',
  name: 'diff',
  summary:
    'Compare an allowlisted remote env file with a LOCAL reference file by key name: missing (only in --against), extra (only on the host), empty (set to nothing on the host).',
  args: [
    arg('path', 'flag', true, 'Remote env file — must be on files-allowlist.toml.'),
    arg(
      'against',
      'flag',
      true,
      'LOCAL reference file (such as ./.env.example); only its key names are read.',
    ),
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  buildRemote: (ctx) => {
    readAgainstKeys(reqStr(ctx, 'against'));
    assertPositional('path', reqStr(ctx, 'path'));
    return shellJoin(['sh', '-c', envFileScript(reqStr(ctx, 'path'))]);
  },
  shape: (parsed, ctx) => {
    const text = parsed as string;
    if (text.trim() === NOT_FOUND) {
      throw new OpError(
        'VALIDATION_ERROR',
        `env diff: '${reqStr(ctx, 'path')}' is not a file on the host`,
        {
          hint: 'Check the path with files ls on its parent directory.',
        },
      );
    }
    const remote = parseEnvKeyLines(text);
    const reference = readAgainstKeys(reqStr(ctx, 'against'));
    const present = new Set(remote.map((entry) => entry.key));
    return {
      missing: [...reference].filter((key) => !present.has(key)),
      extra: remote.filter((entry) => !reference.has(entry.key)).map((entry) => entry.key),
      empty: remote.filter((entry) => entry.state === 'empty').map((entry) => entry.key),
    };
  },
};

export const envOps = [envKeys, envDiff] as OpSpec[];

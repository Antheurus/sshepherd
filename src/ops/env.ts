import { readFileSync } from 'node:fs';
import { ENV_LENGTH_BUCKET_BOUNDS } from '../limits.ts';
import { arg, assertPositional, FILE_TIMEOUT_SEC, optStrOrNull, reqStr } from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
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

/** Reads env lines on stdin: `json` mode is one JSON string per line (`docker inspect`'s Env, where
 *  a newline inside a value is already escaped), `dotenv` mode is a `.env` file. Prints only the
 *  key, whether the value is empty, and the length bucket. */
function awkProgram(mode: 'json' | 'dotenv'): string {
  const unwrap =
    mode === 'json'
      ? 'line = substr(line, 2, length(line) - 2)'
      : 'sub(/^[ \\t]+/, "", line); sub(/^export[ \\t]+/, "", line)';
  const unquote =
    mode === 'json'
      ? ''
      : 'if (length(val) >= 2 && (substr(val, 1, 1) == "\\"" || substr(val, 1, 1) == sprintf("%c", 39)) && substr(val, length(val), 1) == substr(val, 1, 1)) val = substr(val, 2, length(val) - 2)';
  return [
    '{ line = $0',
    unwrap,
    'eq = index(line, "="); if (eq < 2) next',
    'key = substr(line, 1, eq - 1); if (key !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next',
    'val = substr(line, eq + 1); sub(/^[ \\t]+/, "", val); sub(/[ \\t\\r]+$/, "", val)',
    unquote,
    'n = length(val)',
    `b = (n == 0) ? "${ENV_BUCKET_LABELS[0]}" : (n <= ${BUCKET_SMALL}) ? "${ENV_BUCKET_LABELS[1]}" : (n <= ${BUCKET_MEDIUM}) ? "${ENV_BUCKET_LABELS[2]}" : "${ENV_BUCKET_LABELS[3]}"`,
    'print key "\\t" ((n == 0) ? "empty" : "set") "\\t" b }',
  ]
    .filter((part) => part.length > 0)
    .join('; ');
}

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
    `awk ${shq(awkProgram('dotenv'))} "$p"`,
  ].join('; ');
}

/** The remote half of "which variables does this container define": `containerRef` is the shell
 *  text naming the container (`"$c"`), and the Go template emits one JSON string per variable. */
export function containerEnvSummaryScript(containerRef: string): string {
  return [
    `out=$(docker inspect --type container --format '{{range .Config.Env}}{{json .}}{{"\\n"}}{{end}}' -- ${containerRef}) || exit $?`,
    `printf '%s\\n' "$out" | awk ${shq(awkProgram('json'))}`,
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
    arg('container', 'flag', false, 'Container name or ID (not combined with --path).'),
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

/** Key names a local `.env.example`-style file defines: the part before `=` on a `KEY=...` line.
 *  The value half of every line is dropped here, never held past this function. */
export function readAgainstKeys(localPath: string): Set<string> {
  let text: string;
  try {
    text = readFileSync(localPath, 'utf8');
  } catch {
    throw new OpError(
      'VALIDATION_ERROR',
      `env diff: local file '${localPath}' not found or unreadable`,
      { hint: '--against names a LOCAL file such as ./.env.example.' },
    );
  }
  const keys = new Set<string>();
  for (const line of text.split('\n')) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match?.[1] !== undefined) {
      keys.add(match[1]);
    }
  }
  return keys;
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

import {
  GIT_DIFF_STAT_MAX_FILES,
  GIT_LOG_DEFAULT_COMMITS,
  GIT_LOG_MAX_COMMITS,
  GIT_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, optStrOrNull, reqStr } from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import { type OpContext, OpError, type OpSpec } from '../types.ts';

const NOT_FOUND = '__NOT_FOUND__';
const NOT_A_REPO = '__NOT_A_REPO__';
const NOT_REPO_ROOT = '__NOT_REPO_ROOT__';
const UNSAFE_OWNER = '__UNSAFE_OWNER__';
const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

/** Every git call runs read-only: no optional index lock (`git status` would otherwise rewrite the
 *  index), and no hook or fsmonitor command a repository's own config could start. The path must be
 *  the repository's root, so an allowlisted directory never reads a repository above it. */
function gitPrelude(path: string): string[] {
  return [
    `p=${shq(path)}`,
    `[ -d "$p" ] || { echo ${NOT_FOUND}; exit 0; }`,
    'command -v git >/dev/null 2>&1 || exit 127',
    'export GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat',
    'g() { git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "$p" "$@"; }',
    `top=$(g rev-parse --show-toplevel 2>&1) || { case "$top" in *"dubious ownership"*) echo ${UNSAFE_OWNER} ;; *) echo ${NOT_A_REPO} ;; esac; exit 0; }`,
    `[ "$top" = "$(cd "$p" && pwd -P)" ] || { echo ${NOT_REPO_ROOT}; exit 0; }`,
  ];
}

/** A remote's fetch URL with any `user:password@` removed on the host, so the credential never
 *  crosses the wire; `name<TAB>url` per remote. */
const REMOTES_AWK = String.raw`$3 == "(fetch)" { u = $2; sub(/:\/\/[^\/]*@/, "://", u); print "remote\t" $1 "\t" u }`;

function gitCommand(path: string, body: string[]): string {
  return shellJoin(['sh', '-c', [...gitPrelude(path), ...body].join('\n')]);
}

function refuseMarker(text: string, ctx: OpContext): void {
  const path = reqStr(ctx, 'path');
  const marker = text.trim();
  const messages: Record<string, [string, string]> = {
    [NOT_FOUND]: [
      `'${path}' is not a directory on the host`,
      'Check the path with files ls on its parent directory.',
    ],
    [NOT_A_REPO]: [
      `'${path}' is not a git repository`,
      "Pass the directory that holds the repository's .git.",
    ],
    [NOT_REPO_ROOT]: [
      `'${path}' is inside a git repository whose root is another directory`,
      'Pass the repository root itself; a human allowlists that exact path.',
    ],
    [UNSAFE_OWNER]: [
      `git refuses '${path}': the repository is owned by another user than the ssh login`,
      'A human adds it to safe.directory for the login user on the host, or logs in as its owner.',
    ],
  };
  const refusal = messages[marker];
  if (refusal !== undefined) {
    throw new OpError('VALIDATION_ERROR', `git: ${refusal[0]}`, { hint: refusal[1] });
  }
}

export interface GitRemote {
  name: string;
  url: string;
}

function readRemotes(lines: string[]): GitRemote[] {
  return lines
    .filter((line) => line.startsWith('remote\t'))
    .map((line) => {
      const [, name = '', url = ''] = line.split('\t');
      return { name, url };
    });
}

export interface GitHead {
  branch: string | null;
  commit: string | null;
  subject: string | null;
  committed_at: string | null;
  author: string | null;
  dirty: boolean;
  upstream: string | null;
  ahead: number | null;
  behind: number | null;
  remotes: GitRemote[];
}

function field(lines: string[], key: string): string | null {
  const line = lines.find((entry) => entry.startsWith(`${key}=`));
  const value = line?.slice(key.length + 1) ?? '';
  return value.length > 0 ? value : null;
}

const PATH_ARGS = [
  arg('path', 'positional', true, 'Repository root on the host — must be on files-allowlist.toml.'),
];

const gitHead: OpSpec<GitHead> = {
  group: 'git',
  name: 'head',
  summary:
    'Where a repository on the host stands: branch, HEAD commit and subject, dirty, upstream ahead/behind, and remote URLs with any credential removed on the host.',
  args: PATH_ARGS,
  mutating: false,
  exposes: 'content',
  timeoutSec: GIT_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  buildRemote: (ctx) =>
    gitCommand(reqStr(ctx, 'path'), [
      'echo "branch=$(g symbolic-ref --short -q HEAD)"',
      "g log -1 --format='commit=%H%nsubject=%s%ncommitted_at=%cI%nauthor=%an' 2>/dev/null || true",
      'echo "dirty=$(g status --porcelain --untracked-files=no 2>/dev/null | wc -l)"',
      `u=$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null) && echo "upstream=$u" && echo "ahead_behind=$(g rev-list --left-right --count 'HEAD...@{u}' 2>/dev/null)"`,
      `g remote -v | awk ${shq(REMOTES_AWK)}`,
    ]),
  shape: (parsed, ctx) => {
    const text = parsed as string;
    refuseMarker(text, ctx);
    const lines = text.split('\n');
    const [ahead, behind] = (field(lines, 'ahead_behind') ?? '').trim().split(/\s+/).map(Number);
    return {
      branch: field(lines, 'branch'),
      commit: field(lines, 'commit'),
      subject: field(lines, 'subject'),
      committed_at: field(lines, 'committed_at'),
      author: field(lines, 'author'),
      dirty: Number((field(lines, 'dirty') ?? '0').trim()) > 0,
      upstream: field(lines, 'upstream'),
      ahead: ahead !== undefined && Number.isInteger(ahead) ? ahead : null,
      behind: behind !== undefined && Number.isInteger(behind) ? behind : null,
      remotes: readRemotes(lines),
    };
  },
};

function commitCount(ctx: OpContext): number {
  const raw = optStrOrNull(ctx, 'n');
  if (raw === null) {
    return GIT_LOG_DEFAULT_COMMITS;
  }
  const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(value) || value < 1 || value > GIT_LOG_MAX_COMMITS) {
    throw new OpError(
      'INVALID_ARGS',
      `git log: --n must be a whole number from 1 to ${GIT_LOG_MAX_COMMITS}`,
    );
  }
  return value;
}

export interface GitCommit {
  commit: string;
  committed_at: string;
  author: string;
  subject: string;
}

const gitLog: OpSpec<{ commits: GitCommit[]; truncated: boolean }> = {
  group: 'git',
  name: 'log',
  summary: 'The newest commits of a repository on the host: commit, committed_at, author, subject.',
  args: [
    ...PATH_ARGS,
    arg(
      'n',
      'flag',
      false,
      `Commits to return (1-${GIT_LOG_MAX_COMMITS}, default ${GIT_LOG_DEFAULT_COMMITS}).`,
    ),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: GIT_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  buildRemote: (ctx) =>
    gitCommand(reqStr(ctx, 'path'), [
      `g log -n ${commitCount(ctx) + 1} --format='commit%x09%H%x09%cI%x09%an%x09%s' 2>/dev/null || true`,
    ]),
  shape: (parsed, ctx) => {
    const text = parsed as string;
    refuseMarker(text, ctx);
    const commits = text
      .split('\n')
      .filter((line) => line.startsWith('commit\t'))
      .map((line) => {
        const [, commit = '', committedAt = '', author = '', ...subject] = line.split('\t');
        return { commit, committed_at: committedAt, author, subject: subject.join('\t') };
      });
    const limit = commitCount(ctx);
    return { commits: commits.slice(0, limit), truncated: commits.length > limit };
  },
};

export interface GitFileStat {
  path: string;
  /** Null for a binary file, whose lines git does not count. */
  added: number | null;
  deleted: number | null;
}

interface GitDiffStat {
  files: GitFileStat[];
  files_changed: number;
  insertions: number;
  deletions: number;
  untracked: number;
  truncated: boolean;
}

const gitDiffStat: OpSpec<GitDiffStat> = {
  group: 'git',
  name: 'diff-stat',
  summary:
    'Uncommitted changes in a repository on the host, against HEAD: per file lines added/deleted, totals, and the untracked file count — never the diff text.',
  args: PATH_ARGS,
  mutating: false,
  exposes: 'metadata',
  timeoutSec: GIT_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'files', argName: 'path' }],
  buildRemote: (ctx) =>
    gitCommand(reqStr(ctx, 'path'), [
      `base=$(g rev-parse -q --verify HEAD) || base=${EMPTY_TREE}`,
      `g diff --numstat --no-ext-diff --no-textconv "$base" | head -n ${GIT_DIFF_STAT_MAX_FILES + 1} | awk '{ print "stat\\t" $0 }'`,
      'echo "untracked=$(g status --porcelain --untracked-files=normal | grep -c "^??")"',
    ]),
  shape: (parsed, ctx) => {
    const text = parsed as string;
    refuseMarker(text, ctx);
    const lines = text.split('\n');
    const all = lines
      .filter((line) => line.startsWith('stat\t'))
      .map((line): GitFileStat => {
        const [, added = '-', deleted = '-', ...path] = line.split('\t');
        return {
          path: path.join('\t'),
          added: added === '-' ? null : Number(added),
          deleted: deleted === '-' ? null : Number(deleted),
        };
      });
    const files = all.slice(0, GIT_DIFF_STAT_MAX_FILES);
    return {
      files,
      files_changed: files.length,
      insertions: files.reduce((sum, file) => sum + (file.added ?? 0), 0),
      deletions: files.reduce((sum, file) => sum + (file.deleted ?? 0), 0),
      untracked: Number((field(lines, 'untracked') ?? '0').trim()),
      truncated: all.length > GIT_DIFF_STAT_MAX_FILES,
    };
  },
};

export const gitOps = [gitHead, gitLog, gitDiffStat] as OpSpec[];

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GIT_DIFF_STAT_MAX_FILES } from '../limits.ts';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { Envelope, OpSpec } from '../types.ts';

/**
 * Block 9 audit receipt checks (phases 11 and 19), each one a finding's failing check: the remote
 * script runs on this machine under `sh -c` (the "host" is local), with a fake `curl` first on PATH
 * where the case needs one and the real git otherwise.
 */

const ALIAS = 'audit-host';
const SECRET = ['Qv7', 'straddle', 'secret', 'Zp41xK'].join('-');
const ENV_KEYS = ['SSHEPHERD_TARGETS_PATH', 'SSHEPHERD_FILES_ALLOWLIST_PATH', 'SSHEPHERD_PROFILE'];

let scratch = '';
let stubDir = '';
let filterRepo = '';
let plainRepo = '';
let marker = '';
const saved: Record<string, string | undefined> = {};

function op(group: string, name: string): OpSpec {
  const found = getOp(group, name);
  if (found === undefined) {
    throw new Error(`no op ${group} ${name}`);
  }
  return found;
}

function localHost(env: Record<string, string>): SshRunner {
  return async (args) => {
    if (!args.includes('timeout')) {
      return { code: 0, stdout: 'hostname 10.0.0.9\n', stderr: '', timedOut: false };
    }
    const proc = Bun.spawnSync(['sh', '-c', args[args.length - 1] ?? ''], {
      env: { PATH: `${stubDir}:/usr/bin:/bin:/opt/homebrew/bin`, HOME: scratch, ...env },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    return {
      code: proc.exitCode ?? 1,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
      timedOut: false,
    };
  };
}

async function drive(
  group: string,
  name: string,
  args: Record<string, string | boolean>,
  env: Record<string, string> = {},
  maxBytes?: number,
): Promise<Envelope<unknown>> {
  return executeOp(
    op(group, name),
    { alias: ALIAS, args },
    {
      transport: { runner: localHost(env) },
      sshConfigPath: join(scratch, 'ssh_config'),
      auditLogPath: join(scratch, 'audit.jsonl'),
      ...(maxBytes === undefined ? {} : { maxBytes }),
    },
  );
}

function git(repo: string, ...args: string[]): void {
  const proc = Bun.spawnSync(['git', '-C', repo, ...args], { stdout: 'pipe', stderr: 'pipe' });
  if (proc.exitCode !== 0) {
    throw new Error(`git ${args.join(' ')}: ${proc.stderr.toString()}`);
  }
}

beforeAll(() => {
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
  }
  delete process.env.SSHEPHERD_PROFILE;
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit-a09-'));
  stubDir = join(scratch, 'bin');
  mkdirSync(stubDir);
  marker = join(scratch, 'filter-ran');
  filterRepo = join(scratch, 'filter-repo');
  plainRepo = join(scratch, 'plain-repo');
  writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
  writeFileSync(join(scratch, 'targets.toml'), '');
  writeFileSync(
    join(scratch, 'files-allowlist.toml'),
    `[${ALIAS}]\npaths = ["${filterRepo}", "${plainRepo}"]\n`,
  );
  process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
  process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');

  // A fake curl: STUB_MODE=straddle writes a 64 KiB body whose last bytes open a JSON secret;
  // STUB_MODE=hang sleeps the whole --max-time (5 s, as a hung listener does) and prints 000.
  writeFileSync(
    join(stubDir, 'curl'),
    [
      '#!/bin/sh',
      'body=; head=',
      'while [ $# -gt 0 ]; do case "$1" in -o) body="$2"; shift ;; -D) head="$2"; shift ;; esac; shift; done',
      'if [ "$STUB_MODE" = hang ]; then sleep 5; printf 000; exit 28; fi',
      `printf 'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n' > "$head"`,
      `{ head -c 65511 /dev/zero | tr '\\0' a; printf '"api_token":"%s"}' "${SECRET}"; } > "$body"`,
      `printf '200 0.010 %s' "$(wc -c < "$body" | tr -d ' ')"`,
    ].join('\n'),
  );
  chmodSync(join(stubDir, 'curl'), 0o755);

  for (const repo of [filterRepo, plainRepo]) {
    mkdirSync(repo);
    git(repo, 'init', '-q');
    writeFileSync(join(repo, 'f'), 'a\n');
    git(repo, 'add', 'f');
    git(
      repo,
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'one',
    );
  }
  git(filterRepo, 'config', 'filter.x.clean', `sh -c "touch ${marker}; cat"`);
  writeFileSync(join(filterRepo, '.git', 'info', 'attributes'), '* filter=x\n');
  writeFileSync(join(filterRepo, 'f'), 'a\nb\n');
}, 60_000);

afterAll(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = saved[key];
    }
  }
  rmSync(scratch, { recursive: true, force: true });
});

describe('block 9 audit findings', () => {
  test('http get: a JSON secret cut by the 64 KiB body cap leaves no prefix of its value', async () => {
    const envelope = await drive(
      'http',
      'get',
      { url: 'http://127.0.0.1:8080/' },
      { STUB_MODE: 'straddle' },
      200_000,
    );
    const text = JSON.stringify(envelope);
    expect(envelope.ok).toBe(true);
    expect(text.includes(SECRET.slice(0, 8))).toBe(false);
  });

  test('git diff-stat runs no clean filter a repository config names', async () => {
    rmSync(marker, { force: true });
    const envelope = await drive('git', 'diff-stat', { path: filterRepo });
    expect(envelope.ok).toBe(true);
    expect(existsSync(marker)).toBe(false);
  });

  test('git head without an upstream reports ahead and behind as null, not 0', async () => {
    const envelope = await drive('git', 'head', { path: plainRepo });
    const data = envelope.data as {
      upstream: string | null;
      ahead: number | null;
      behind: number | null;
    };
    expect([data.upstream, data.ahead, data.behind]).toEqual([null, null, null]);
  });

  test('wait for url: a probe that hangs its whole 5 s still reports inside --timeout 11', async () => {
    const envelope = await drive(
      'wait',
      'for',
      { until: 'url:http://127.0.0.1:8098/', timeout: '11' },
      { STUB_MODE: 'hang' },
    );
    const data = envelope.data as { elapsed_ms: number } | null;
    expect(envelope.error?.code).toBe('COMMAND_TIMEOUT');
    expect(data?.elapsed_ms ?? Number.POSITIVE_INFINITY).toBeLessThan(11_000);
  }, 40_000);
});

describe('block 9 fix: git runs no command a repository config names, and counts every file', () => {
  const repos: Record<string, string> = {};
  const markers: Record<string, string> = {};

  function fixtureRepo(name: string): string {
    const repo = join(scratch, name);
    mkdirSync(repo);
    git(repo, 'init', '-q');
    writeFileSync(join(repo, 'f'), 'a\n');
    git(repo, 'add', 'f');
    git(
      repo,
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'one',
    );
    repos[name] = repo;
    markers[name] = join(scratch, `${name}-ran`);
    return repo;
  }

  beforeAll(() => {
    const fsmonitor = fixtureRepo('fsmonitor-repo');
    const hook = join(scratch, 'fsmonitor-hook');
    writeFileSync(hook, `#!/bin/sh\ntouch ${markers['fsmonitor-repo']}\n`);
    chmodSync(hook, 0o755);
    git(fsmonitor, 'config', 'core.fsmonitor', hook);
    writeFileSync(join(fsmonitor, 'f'), 'a\nb\n');

    const textconv = fixtureRepo('textconv-repo');
    git(textconv, 'config', 'diff.x.textconv', `sh -c "touch ${markers['textconv-repo']}; cat"`);
    writeFileSync(join(textconv, '.git', 'info', 'attributes'), '* diff=x\n');
    writeFileSync(join(textconv, 'f'), 'a\nb\n');

    const oddName = fixtureRepo('odd-filter-repo');
    git(oddName, 'config', 'filter.a=b.clean', `sh -c "touch ${markers['odd-filter-repo']}; cat"`);
    writeFileSync(join(oddName, '.git', 'info', 'attributes'), '* filter=a=b\n');
    writeFileSync(join(oddName, 'f'), 'a\nb\n');

    const many = fixtureRepo('many-repo');
    for (let i = 0; i <= GIT_DIFF_STAT_MAX_FILES + 9; i++) {
      writeFileSync(join(many, `n${i}`), 'x\ny\n');
    }
    git(many, 'add', '-A');

    writeFileSync(
      join(scratch, 'files-allowlist.toml'),
      `[${ALIAS}]\npaths = [${[filterRepo, plainRepo, ...Object.values(repos)].map((p) => `"${p}"`).join(', ')}]\n`,
    );
  }, 60_000);

  test('git diff-stat runs no core.fsmonitor command the repository config names', async () => {
    const envelope = await drive('git', 'diff-stat', { path: repos['fsmonitor-repo'] ?? '' });
    expect(envelope.ok).toBe(true);
    expect(existsSync(markers['fsmonitor-repo'] ?? '')).toBe(false);
  });

  test('git diff-stat runs no diff.<driver>.textconv the repository config names', async () => {
    const envelope = await drive('git', 'diff-stat', { path: repos['textconv-repo'] ?? '' });
    expect(envelope.ok).toBe(true);
    expect(existsSync(markers['textconv-repo'] ?? '')).toBe(false);
  });

  test('git head runs no clean filter either, even on a file whose stat changed', async () => {
    rmSync(marker, { force: true });
    writeFileSync(join(filterRepo, 'f'), 'a\nc\n');
    const envelope = await drive('git', 'head', { path: filterRepo });
    expect(envelope.ok).toBe(true);
    expect(existsSync(marker)).toBe(false);
  });

  test('a filter driver no -c override can name is refused, and its command never runs', async () => {
    const envelope = await drive('git', 'diff-stat', { path: repos['odd-filter-repo'] ?? '' });
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(existsSync(markers['odd-filter-repo'] ?? '')).toBe(false);
  });

  test('git diff-stat: files stays capped, files_changed and the line totals count every file', async () => {
    const envelope = await drive('git', 'diff-stat', { path: repos['many-repo'] ?? '' });
    const data = envelope.data as {
      files: unknown[];
      files_changed: number;
      insertions: number;
      truncated: boolean;
    };
    const total = GIT_DIFF_STAT_MAX_FILES + 10;
    expect([data.files.length, data.files_changed, data.insertions, data.truncated]).toEqual([
      GIT_DIFF_STAT_MAX_FILES,
      total,
      total * 2,
      true,
    ]);
  }, 30_000);
});

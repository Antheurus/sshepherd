import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { Envelope } from '../types.ts';

// Block 8 fix C: N4 (compose reads only the allowlisted directory) and the two user decisions —
// env blocks in `deploy run` output are masked whole, and an unwritable audit log warns a mutating
// op instead of failing it.

const SSH_G = 'hostname srv-01.example.net\nuser opsuser\nport 2222\n';
const DEMO_RECIPE_PATH = join(import.meta.dir, 'fixtures', 'deploy.demo.toml');
const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });

let scratch = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-block08c-'));
});
afterAll(() => {
  if (existsSync(join(scratch, 'locked'))) {
    chmodSync(join(scratch, 'locked'), 0o700);
  }
  rmSync(scratch, { recursive: true, force: true });
});

function opOf(group: string, name: string) {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return op;
}

/** Answers `ssh -G` and the master check, and hands `stdout` back for the command itself. */
function scripted(stdout: string): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok(SSH_G);
    }
    return ok(args.includes('-O') ? '' : stdout);
  };
}

/** Runs the remote command in a local `sh` with `bin` first on PATH. */
function localRunner(bin: string): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok(SSH_G);
    }
    if (args.includes('-O')) {
      return ok('');
    }
    const proc = Bun.spawnSync(['sh', '-c', args.at(-1) ?? ''], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}` },
    });
    return {
      code: proc.exitCode ?? 1,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
      timedOut: false,
    };
  };
}

describe('N4 — logs compose never reads a parent directory compose file', () => {
  test('allowlist /srv/app/sub, compose file only in /srv/app -> refused, no parent lines', async () => {
    const root = join(scratch, 'srv', 'app');
    const sub = join(root, 'sub');
    mkdirSync(sub, { recursive: true });
    writeFileSync(join(root, 'compose.yaml'), 'services:\n  web:\n    image: nginx\n');
    // Stands in for docker compose: with no -f it walks from --project-directory up to the first
    // directory holding a compose file, as the real one did on the fixture.
    const bin = join(scratch, 'bin');
    mkdirSync(bin, { recursive: true });
    writeFileSync(
      join(bin, 'docker'),
      [
        '#!/bin/sh',
        'dir=',
        'while [ $# -gt 0 ]; do [ "$1" = --project-directory ] && dir=$2; shift; done',
        'while [ -n "$dir" ] && [ "$dir" != / ]; do',
        '  if [ -f "$dir/compose.yaml" ]; then',
        '    echo "web-1  | 2026-11-27T10:00:01.000000000Z parent project line"; exit 0',
        '  fi',
        '  dir=$(dirname "$dir")',
        'done',
        'echo "no configuration file provided: not found" >&2; exit 1',
      ].join('\n'),
    );
    chmodSync(join(bin, 'docker'), 0o755);
    const allowlist = join(scratch, 'files-allowlist.toml');
    writeFileSync(allowlist, `[edge-box]\npaths = ["${sub}"]\n`);
    const before = process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlist;
    try {
      const env = await executeOp(
        opOf('logs', 'compose'),
        { alias: 'edge-box', args: { project_dir: sub } },
        { transport: { runner: localRunner(bin) }, auditLogPath: join(scratch, 'audit.jsonl') },
      );
      const text = JSON.stringify(env);
      expect({
        parentLine: text.includes('parent project line'),
        refused:
          env.error?.code === 'VALIDATION_ERROR' || text.includes('no configuration file provided'),
      }).toEqual({ parentLine: false, refused: true });
    } finally {
      process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = before;
    }
  });
});

describe('D-env — an env block in deploy run output is masked whatever its keys', () => {
  const canary = ['canary', 'f08c', 'spaced', '4417'].join('-');
  const stdout = [
    'Step 2/4 : print the env file',
    'APP_NAME=shop',
    `SPACED = ${canary}`,
    '# database',
    '',
    'export LOG_LEVEL=debug',
    'building image',
    'BUILD_ID=123',
    'done',
  ].join('\n');

  test('SPACED = <canary> inside a 3+ line block -> 0 hits; a lone BUILD_ID=123 stays readable', async () => {
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const env = await executeOp(
        opOf('deploy', 'run'),
        { alias: 'lms-server', args: { recipe: 'demo' } },
        {
          transport: { runner: scripted(stdout) },
          yes: true,
          auditLogPath: join(scratch, 'deploy-audit.jsonl'),
        },
      );
      const text = JSON.stringify(env);
      const output = (env.data as { output: string }).output;
      expect({
        ok: env.ok,
        hits: text.split(canary).length - 1,
        spacedMasked: output.includes('SPACED = ***MASKED***'),
        nonSecretKeyMasked: output.includes('APP_NAME=***MASKED***'),
        lone: output.includes('BUILD_ID=123'),
      }).toEqual({ ok: true, hits: 0, spacedMasked: true, nonSecretKeyMasked: true, lone: true });
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });
});

describe('D-audit — an unwritable audit log warns a mutating op, read ops unchanged', () => {
  const stateBefore = process.env.SSHEPHERD_STATE_DIR;
  let locked = '';
  beforeAll(() => {
    locked = join(scratch, 'locked');
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    process.env.SSHEPHERD_STATE_DIR = locked;
  });
  afterAll(() => {
    process.env.SSHEPHERD_STATE_DIR = stateBefore;
  });

  test('services restart still runs: ok, data kept, AUDIT_UNWRITABLE warning naming the role', async () => {
    let commands = 0;
    const runner: SshRunner = async (args) => {
      if (args[0] === '-G') {
        return ok(SSH_G);
      }
      if (args.includes('-O')) {
        return ok('');
      }
      commands += 1;
      return ok('web\n');
    };
    const env = (await executeOp(
      opOf('services', 'restart'),
      { alias: 'edge-box', args: { container: 'web' } },
      { transport: { runner }, yes: true },
    )) as Envelope<unknown>;
    const warning = env.warnings?.[0];
    expect({
      commands,
      ok: env.ok,
      error: env.error,
      data: env.data,
      code: warning?.code,
      role: warning?.path_role,
      errno: warning?.errno,
      hintNamesFix: warning?.hint.includes('SSHEPHERD_STATE_DIR') ?? false,
      leaksPath: JSON.stringify(env).includes(scratch),
      logWritten: existsSync(join(locked, 'audit.jsonl')),
    }).toEqual({
      commands: 1,
      ok: true,
      error: null,
      data: { container: 'web', restarted: true },
      code: 'AUDIT_UNWRITABLE',
      role: 'audit_file',
      errno: 'EACCES',
      hintNamesFix: true,
      leaksPath: false,
      logWritten: false,
    });
  });

  test('a content read (logs docker) is unchanged: AUDIT_WRITE_FAILED, no warning', async () => {
    const env = await executeOp(
      opOf('logs', 'docker'),
      { alias: 'edge-box', args: { container: 'web' } },
      { transport: { runner: scripted('2026-11-27T10:00:01.000000000Z hello\n') } },
    );
    expect({ code: env.error?.code, ok: env.ok, warnings: env.warnings }).toEqual({
      code: 'AUDIT_WRITE_FAILED',
      ok: false,
      warnings: undefined,
    });
  });
});

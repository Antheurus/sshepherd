import { describe, expect, spyOn, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { printFailure } from '../cli.ts';
import { buildSetupResult, printSetupResult } from '../setup-types.ts';

/**
 * Every envelope or setup result printed outside `executeOp` passes the shared scrubber: the
 * `doctor` report, the CLI's own argument-error envelope, the catch-all in `main` (an `OpError`
 * and an `INTERNAL_ERROR`), and every setup result, JSON and `--pretty`. Each path gets a planted
 * secret and a documentation-range address, and neither may come out.
 */
const CLI = join(import.meta.dir, '..', 'cli.ts');
const SECRET = 'Zq8vN3kLp0Wt6YbR2mXc';
const ADDRESS = '203.0.113.9';
const PLANTED = `password=${SECRET} ${ADDRESS}`;

function cli(args: string[], env: Record<string, string> = {}): { stdout: string; exit: number } {
  const proc = Bun.spawnSync(['bun', CLI, ...args], {
    env: { ...process.env, ...env },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return { stdout: proc.stdout.toString(), exit: proc.exitCode ?? -1 };
}

function expectClean(out: string): void {
  expect(out.length).toBeGreaterThan(0);
  expect({ secret: out.includes(SECRET), address: out.includes(ADDRESS) }).toEqual({
    secret: false,
    address: false,
  });
}

function captureStdout(fn: () => void): string {
  let out = '';
  const spy = spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    out += String(chunk);
    return true;
  }) as typeof process.stdout.write);
  const exitCode = process.exitCode;
  try {
    fn();
  } finally {
    spy.mockRestore();
    // printFailure sets the exit code of the process it runs in, here the test runner.
    process.exitCode = exitCode ?? 0;
  }
  return out;
}

describe('output printed outside executeOp passes the scrubber', () => {
  test('main catch-all, OpError: an unknown group echoing the planted text', () => {
    const { stdout, exit } = cli([`grp-${ADDRESS}-${PLANTED.replace(' ', '-')}`]);
    expect(exit).toBe(2);
    expect(JSON.parse(stdout).error.code).toBe('UNKNOWN_SUBGROUP');
    expectClean(stdout);
  });

  test('main catch-all, VALIDATION_ERROR: a recipe error quoting the planted text', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-local-scrub-'));
    const recipe = join(dir, 'demo.toml');
    writeFileSync(
      recipe,
      [
        'name = "demo"',
        'alias = "app1"',
        'workdir = "/srv/app"',
        '',
        '[[step]]',
        'name = "build"',
        'kind = "shell"',
        'run = "make"',
        `depends_on = "${PLANTED}"`,
        '',
      ].join('\n'),
    );
    const { stdout, exit } = cli(['deploy', 'status', 'demo'], { SSHEPHERD_RECIPE_PATH: recipe });
    expect(exit).toBe(2);
    expect(JSON.parse(stdout).error.code).toBe('VALIDATION_ERROR');
    expectClean(stdout);
  });

  test('main catch-all, INTERNAL_ERROR: the command words it names', () => {
    const out = captureStdout(() =>
      printFailure([`${ADDRESS}`, `token=${SECRET}`], new TypeError('boom')),
    );
    const envelope = JSON.parse(out);
    expect(envelope.error.code).toBe('INTERNAL_ERROR');
    expect(envelope.scrubbed).toBeGreaterThan(0);
    expectClean(out);
  });

  test('the argument-error envelope: an alias carrying the planted address', () => {
    const { stdout, exit } = cli(['hosts', 'test', `${ADDRESS}`, '--timeout', 'soon']);
    expect(exit).toBe(2);
    expect(JSON.parse(stdout).error.code).toBe('INVALID_ARGS');
    expectClean(stdout);
  });

  test('doctor: a targets file whose target names carry the planted text', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-local-scrub-'));
    const targets = join(dir, 'targets.toml');
    writeFileSync(
      targets,
      `["db-${ADDRESS}"]\nalias = "app1"\nuser = "app"\ndatabase = "app"\ncontainer = "pg"\n\n["token=${SECRET}"]\nalias = "app1"\nuser = "app"\ndatabase = "app"\ncontainer = "pg"\n`,
    );
    const { stdout, exit } = cli(['doctor'], {
      SSHEPHERD_TARGETS_PATH: targets,
      SSHEPHERD_INSTALL_DIR: dir,
      SSHEPHERD_SKILL_PATH: join(dir, 'SKILL.md'),
      SSHEPHERD_DIST_PATH: join(dir, 'sshepherd'),
    });
    expect(exit).toBe(0);
    expect(JSON.parse(stdout).data.pg_targets_without_ro_role).toHaveLength(2);
    expectClean(stdout);
  });

  test('setup: an unknown sub-group echoing the planted text', () => {
    const { stdout, exit } = cli(['setup', `x-${ADDRESS}-token=${SECRET}`]);
    expect(exit).toBe(2);
    expect(JSON.parse(stdout).error.code).toBe('UNKNOWN_SUBGROUP');
    expectClean(stdout);
  });

  test('setup results, JSON and --pretty: data and error both scrubbed', () => {
    const result = buildSetupResult({
      command: 'setup ssh-alias status',
      data: { note: PLANTED },
      error: { code: 'VALIDATION_ERROR', message: `bad value ${PLANTED}` },
    });
    for (const pretty of [false, true]) {
      expectClean(captureStdout(() => printSetupResult(result, pretty)));
    }
  });
});

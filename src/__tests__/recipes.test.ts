import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildDeployOpContext,
  buildMigrateScript,
  buildRollbackCommand,
  buildRunScript,
  loadRecipe,
  planRecipe,
  type RecipeStep,
  resolveStepOrder,
} from '../recipes.ts';

const FIXTURE_PATH = join(import.meta.dir, 'fixtures', 'deploy.demo.toml');

function writeRecipe(lines: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-recipe-test-'));
  const path = join(dir, 'recipe.toml');
  writeFileSync(path, `${lines.join('\n')}\n`);
  return path;
}

describe('buildDeployOpContext — resolves ctx.alias from the recipe (mirrors buildDbOpContext)', () => {
  test('alias comes from the recipe file, not the recipe name, and recipe name is preserved in args', () => {
    const ctx = buildDeployOpContext('demo', { 'dry-run': true }, FIXTURE_PATH);
    expect(ctx.alias).toBe('lms-server');
    expect(ctx.args.recipe).toBe('demo');
    expect(ctx.args['dry-run']).toBe(true);
  });

  test('a missing recipe throws the same clear error loadRecipe throws', () => {
    expect(() =>
      buildDeployOpContext('does-not-exist', {}, join(tmpdir(), 'sshepherd-nope-ctx.toml')),
    ).toThrow(/not found/);
  });
});

describe('loadRecipe — fixture', () => {
  test('parses the demo recipe and resolves migrate after up despite file order', () => {
    const recipe = loadRecipe('demo', FIXTURE_PATH);
    expect(recipe.name).toBe('demo');
    expect(recipe.alias).toBe('lms-server');
    expect(recipe.workdir).toBe('/opt/lms');
    expect(recipe.steps.map((step) => step.name)).toEqual([
      'pull-code',
      'build-image',
      'up',
      'migrate',
      'verify',
    ]);
    expect(recipe.rollback).toEqual({ strategy: 'previous-tag', tag: 'v1.2.2' });
  });
});

describe('loadRecipe — validation', () => {
  test('a missing file throws a clear error', () => {
    expect(() => loadRecipe('does-not-exist', join(tmpdir(), 'sshepherd-nope.toml'))).toThrow(
      /not found/,
    );
  });

  test('a recipe missing alias throws', () => {
    const path = writeRecipe([
      'name = "bad"',
      'workdir = "/opt/app"',
      '[[step]]',
      'name = "a"',
      'kind = "shell"',
      'run = "echo hi"',
    ]);
    expect(() => loadRecipe('bad', path)).toThrow(/missing 'alias'/);
  });

  test('a recipe with no steps throws', () => {
    const path = writeRecipe(['name = "bad"', 'alias = "x"', 'workdir = "/opt/app"']);
    expect(() => loadRecipe('bad', path)).toThrow(/no steps/);
  });

  test('a duplicate step name throws', () => {
    const path = writeRecipe([
      'name = "bad"',
      'alias = "x"',
      'workdir = "/opt/app"',
      '[[step]]',
      'name = "a"',
      'kind = "shell"',
      'run = "echo hi"',
      '[[step]]',
      'name = "a"',
      'kind = "shell"',
      'run = "echo bye"',
    ]);
    expect(() => loadRecipe('bad', path)).toThrow(/duplicate step/);
  });

  test('an unknown step kind throws', () => {
    const path = writeRecipe([
      'name = "bad"',
      'alias = "x"',
      'workdir = "/opt/app"',
      '[[step]]',
      'name = "a"',
      'kind = "nonsense"',
    ]);
    expect(() => loadRecipe('bad', path)).toThrow(/unknown kind/);
  });
});

function step(name: string, dependsOn?: string): RecipeStep {
  return { kind: 'shell', name, run: 'echo hi', mutates: true, depends_on: dependsOn };
}

describe('resolveStepOrder', () => {
  test('a dependency declared out of file order sorts after the step it depends on', () => {
    const ordered = resolveStepOrder([step('migrate', 'up'), step('build'), step('up')]);
    const names = ordered.map((s) => s.name);
    expect(names).toEqual(['up', 'migrate', 'build']);
    expect(names.indexOf('up')).toBeLessThan(names.indexOf('migrate'));
  });

  test('independent steps keep their file order', () => {
    const ordered = resolveStepOrder([step('a'), step('b'), step('c')]);
    expect(ordered.map((s) => s.name)).toEqual(['a', 'b', 'c']);
  });

  test('an unknown depends_on target throws', () => {
    expect(() => resolveStepOrder([step('a', 'ghost')])).toThrow(/unknown step/);
  });

  test('a dependency cycle throws', () => {
    expect(() => resolveStepOrder([step('a', 'b'), step('b', 'a')])).toThrow(/cycle/);
  });
});

describe('planRecipe — dry-run plan', () => {
  test('marks which steps mutate and includes the exact resolved remote command per step', () => {
    const recipe = loadRecipe('demo', FIXTURE_PATH);
    const plan = planRecipe(recipe);

    expect(plan.recipe).toBe('demo');
    expect(plan.alias).toBe('lms-server');
    expect(plan.workdir).toBe('/opt/lms');
    expect(plan.steps.map((s) => s.name)).toEqual([
      'pull-code',
      'build-image',
      'up',
      'migrate',
      'verify',
    ]);

    const byName = new Map(plan.steps.map((s) => [s.name, s]));
    expect(byName.get('pull-code')?.mutates).toBe(true);
    expect(byName.get('build-image')?.mutates).toBe(true);
    expect(byName.get('up')?.mutates).toBe(true);
    expect(byName.get('migrate')?.mutates).toBe(true);
    expect(byName.get('verify')?.mutates).toBe(false);
    expect(byName.get('migrate')?.depends_on).toBe('up');

    for (const planStep of plan.steps) {
      expect(planStep.remote_command).toContain('sh');
    }
  });
});

describe('buildMigrateScript', () => {
  test('runs only the migrate-kind steps', () => {
    const recipe = loadRecipe('demo', FIXTURE_PATH);
    const script = buildMigrateScript(recipe.steps, recipe.workdir);
    expect(script).toContain('artisan migrate --force');
    expect(script).not.toContain('git pull');
    expect(script).not.toContain('docker compose build app');
  });

  test('throws when the recipe has no migrate steps', () => {
    expect(() => buildMigrateScript([step('a')], '/opt/app')).toThrow(/no migrate steps/);
  });
});

describe('buildRollbackCommand', () => {
  test('refuses when the recipe declares no [rollback] block', () => {
    const recipe = { ...loadRecipe('demo', FIXTURE_PATH), rollback: null };
    expect(() => buildRollbackCommand(recipe)).toThrow(/declares no \[rollback\] block/);
  });

  test('previous-tag strategy sets IMAGE_TAG and runs compose up -d', () => {
    const recipe = loadRecipe('demo', FIXTURE_PATH);
    const command = buildRollbackCommand(recipe);
    expect(command).toContain('IMAGE_TAG');
    expect(command).toContain('v1.2.2');
    expect(command).toContain('docker compose up -d');
  });

  test('compose-file strategy runs compose -f <file> up -d', () => {
    const recipe = {
      ...loadRecipe('demo', FIXTURE_PATH),
      rollback: { strategy: 'compose-file' as const, file: 'docker-compose.previous.yml' },
    };
    const command = buildRollbackCommand(recipe);
    expect(command).toContain('docker-compose.previous.yml');
    expect(command).toContain('up -d');
  });
});

/**
 * Real drive, not a string-shape guess: `buildRunScript`'s output is exactly the argv
 * `run()` (transport.ts) hands to `ssh <alias> <command>` — feeding it to a real local
 * `sh -c` reproduces the exact parse the remote login shell would do. Payloads always end
 * in `touch <marker>` so even a genuine quoting failure only creates a harmless temp file.
 */
function freshMarkerPath(): string {
  return join(
    tmpdir(),
    `sshepherd-recipe-pwn-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
}

function assertShellParsesSafely(remoteCmd: string, marker: string): void {
  Bun.spawnSync(['sh', '-c', remoteCmd], { stdout: 'ignore', stderr: 'ignore' });
  expect(existsSync(marker)).toBe(false);
}

describe('quoting — non-shell recipe step fields are injection-safe (real sh -c drive)', () => {
  test('workdir shaped like a shell injection cannot splice a second command via cd', () => {
    const marker = freshMarkerPath();
    const maliciousWorkdir = `/opt/lms'; touch ${marker}; echo '`;
    const steps: RecipeStep[] = [step('noop')];
    const script = buildRunScript(steps, maliciousWorkdir);
    assertShellParsesSafely(script, marker);
  });

  test('healthcheck target shaped like a shell injection cannot splice a second command', () => {
    const marker = freshMarkerPath();
    const maliciousTarget = `app'; touch ${marker}; echo '`;
    const steps: RecipeStep[] = [
      { kind: 'healthcheck', name: 'verify', target: maliciousTarget, timeout: '2s' },
    ];
    const script = buildRunScript(steps, '/opt/lms');
    // healthcheckScript loops until timeout; give the injected marker a chance to fire if unsafe.
    Bun.spawnSync(['sh', '-c', script], { stdout: 'ignore', stderr: 'ignore' });
    expect(existsSync(marker)).toBe(false);
  });

  test('http-probe url shaped like a shell injection cannot splice a second command', () => {
    const marker = freshMarkerPath();
    const maliciousUrl = `http://x'; touch ${marker}; echo '`;
    const steps: RecipeStep[] = [
      {
        kind: 'http-probe',
        name: 'probe',
        url: maliciousUrl,
        expect_status: 200,
        retries: 1,
        interval: 0,
      },
    ];
    const script = buildRunScript(steps, '/opt/lms');
    assertShellParsesSafely(script, marker);
  });
});

describe('buildRollbackCommand — injection safety on rollback fields (real sh -c drive)', () => {
  test('previous-tag: a tag shaped like a shell injection cannot splice a second command', () => {
    const marker = freshMarkerPath();
    const recipe = {
      ...loadRecipe('demo', FIXTURE_PATH),
      rollback: { strategy: 'previous-tag' as const, tag: `v1'; touch ${marker}; echo '` },
    };
    const command = buildRollbackCommand(recipe);
    assertShellParsesSafely(command, marker);
  });

  test('compose-file: a file shaped like a shell injection cannot splice a second command', () => {
    const marker = freshMarkerPath();
    const recipe = {
      ...loadRecipe('demo', FIXTURE_PATH),
      rollback: {
        strategy: 'compose-file' as const,
        file: `docker-compose.yml'; touch ${marker}; echo '`,
      },
    };
    const command = buildRollbackCommand(recipe);
    assertShellParsesSafely(command, marker);
  });
});

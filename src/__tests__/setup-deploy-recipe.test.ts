import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildRollbackCommand, loadRecipe, resolveStepOrder } from '../recipes.ts';
import { scaffold } from '../setup-deploy-recipe.ts';

function tempRecipePath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-deploy-recipe-test-'));
  return join(dir, 'demo.toml');
}

describe('scaffold', () => {
  test('writes name/alias/workdir and one placeholder shell step', () => {
    const path = tempRecipePath();
    const result = scaffold('demo', { alias: 'lms-server', workdir: '/opt/lms', yes: true }, path);

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ name: 'demo', alias: 'lms-server', workdir: '/opt/lms' });

    const text = readFileSync(path, 'utf8');
    expect(text).toContain('name = "demo"');
    expect(text).toContain('alias = "lms-server"');
    expect(text).toContain('workdir = "/opt/lms"');
    expect(text).toContain('[[step]]');
    expect(text).toContain('kind = "shell"');
  });

  test('the generated skeleton round-trips through the real loadRecipe/resolveStepOrder', () => {
    const path = tempRecipePath();
    scaffold('demo', { alias: 'lms-server', workdir: '/opt/lms', yes: true }, path);

    const recipe = loadRecipe('demo', path);
    expect(recipe.alias).toBe('lms-server');
    expect(recipe.workdir).toBe('/opt/lms');
    expect(recipe.rollback).toBeNull();

    const ordered = resolveStepOrder(recipe.steps);
    expect(ordered).toHaveLength(1);
    expect(ordered[0]?.kind).toBe('shell');
  });

  test('the freshly-scaffolded recipe has no [rollback] block, so buildRollbackCommand refuses', () => {
    const path = tempRecipePath();
    scaffold('demo', { alias: 'lms-server', workdir: '/opt/lms', yes: true }, path);

    const recipe = loadRecipe('demo', path);
    expect(() => buildRollbackCommand(recipe)).toThrow(/declares no \[rollback\] block/);
  });

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted, no file touched', () => {
    const path = tempRecipePath();
    const result = scaffold('demo', { alias: 'lms-server', workdir: '/opt/lms', yes: false }, path);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(existsSync(path)).toBe(false);
  });

  test('fails with RECIPE_EXISTS for a duplicate name, existing file untouched byte-for-byte', () => {
    const path = tempRecipePath();
    writeFileSync(
      path,
      ['name = "demo"', 'alias = "other-alias"', 'workdir = "/opt/other"', ''].join('\n'),
    );
    const before = readFileSync(path, 'utf8');

    const result = scaffold('demo', { alias: 'lms-server', workdir: '/opt/lms', yes: true }, path);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('RECIPE_EXISTS');
    expect(readFileSync(path, 'utf8')).toBe(before);
  });
});

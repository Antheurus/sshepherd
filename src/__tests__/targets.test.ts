import { describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildDbOpContext, loadTargets, resolveTarget } from '../targets.ts';

function writeFixtureTargets(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-targets-test-'));
  const path = join(dir, 'targets.toml');
  writeFileSync(
    path,
    [
      '[prod]',
      'alias = "lms-server"',
      'compose_file = "/opt/lms/docker-compose.yml"',
      'service = "db"',
      'user = "sshepherd_ro"',
      'database = "lms"',
      '',
      '[staging]',
      'alias = "staging-1"',
      'container = "staging_postgres_1"',
      'user = "sshepherd_ro"',
      'database = "app"',
      '',
    ].join('\n'),
  );
  return path;
}

describe('loadTargets', () => {
  test('parses compose-style and container-style targets', () => {
    const targets = loadTargets(writeFixtureTargets());
    expect(Object.keys(targets)).toEqual(['prod', 'staging']);
    expect(targets.prod).toEqual({
      alias: 'lms-server',
      composeFile: '/opt/lms/docker-compose.yml',
      service: 'db',
      container: null,
      user: 'sshepherd_ro',
      database: 'lms',
      maxProfile: null,
    });
    expect(targets.staging).toEqual({
      alias: 'staging-1',
      composeFile: null,
      service: null,
      container: 'staging_postgres_1',
      user: 'sshepherd_ro',
      database: 'app',
      maxProfile: null,
    });
  });

  test('a missing file yields an empty map, mirroring listHostAliases', () => {
    expect(loadTargets(join(tmpdir(), 'sshepherd-does-not-exist', 'targets.toml'))).toEqual({});
  });

  test('a target with neither compose_file/service nor container throws', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-targets-test-'));
    const path = join(dir, 'targets.toml');
    writeFileSync(path, ['[bad]', 'alias = "x"', 'user = "ro"', 'database = "db"', ''].join('\n'));
    expect(() => loadTargets(path)).toThrow(/needs either/);
  });

  test('a target declaring both compose and container throws', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-targets-test-'));
    const path = join(dir, 'targets.toml');
    writeFileSync(
      path,
      [
        '[bad]',
        'alias = "x"',
        'compose_file = "/a/b.yml"',
        'service = "db"',
        'container = "c1"',
        'user = "ro"',
        'database = "db"',
        '',
      ].join('\n'),
    );
    expect(() => loadTargets(path)).toThrow(/pick one/);
  });
});

describe('resolveTarget', () => {
  test('throws a clear error for an undeclared pg-target', () => {
    const path = writeFixtureTargets();
    expect(() => resolveTarget('does-not-exist', path)).toThrow(/not declared/);
  });
});

describe('buildDbOpContext', () => {
  test('resolves a pg-target into an OpContext with alias + flattened connection args', () => {
    const path = writeFixtureTargets();
    const ctx = buildDbOpContext('prod', { sql: 'SELECT 1' }, path);
    expect(ctx.alias).toBe('lms-server');
    expect(ctx.args).toEqual({
      sql: 'SELECT 1',
      target: 'prod',
      compose_file: '/opt/lms/docker-compose.yml',
      service: 'db',
      container: '',
      db_user: 'sshepherd_ro',
      db_name: 'lms',
      max_profile: '',
    });
  });

  test('a target max_profile is parsed and flattened as max_profile; an unknown value is refused', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-targets-test-'));
    const path = join(dir, 'targets.toml');
    const target = ['alias = "lms-server"', 'container = "pg"', 'user = "ro"', 'database = "lms"'];
    writeFileSync(path, ['[prod]', ...target, 'max_profile = "read"', ''].join('\n'));
    expect(loadTargets(path).prod?.maxProfile).toBe('read');
    expect(buildDbOpContext('prod', {}, path).args.max_profile).toBe('read');

    writeFileSync(path, ['[prod]', ...target, 'max_profile = "root"', ''].join('\n'));
    expect(() => loadTargets(path)).toThrow(
      /max_profile "root"; expected one of read, deploy, admin/,
    );
  });
});

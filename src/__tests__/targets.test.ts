import { describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildDbOpContext,
  DEFAULT_DENY_COLUMNS,
  declaredContainers,
  loadTargets,
  resolveTarget,
} from '../targets.ts';

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
      kind: 'container',
      envKey: null,
      psqlContainer: null,
      sudoUser: null,
      pgHost: null,
      pgPort: null,
      denyColumns: DEFAULT_DENY_COLUMNS,
      containers: [],
    });
    expect(targets.staging).toEqual({
      alias: 'staging-1',
      composeFile: null,
      service: null,
      container: 'staging_postgres_1',
      user: 'sshepherd_ro',
      database: 'app',
      maxProfile: null,
      kind: 'container',
      envKey: null,
      psqlContainer: null,
      sudoUser: null,
      pgHost: null,
      pgPort: null,
      denyColumns: DEFAULT_DENY_COLUMNS,
      containers: [],
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
      db_kind: 'container',
      env_key: '',
      psql_container: '',
      sudo_user: '',
      pg_host: '',
      pg_port: '',
      max_profile: '',
      deny_columns: JSON.stringify(DEFAULT_DENY_COLUMNS),
    });
  });

  test('deny_columns replaces the default list; an empty, non-list or bad-regex one is refused', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-targets-test-'));
    const path = join(dir, 'targets.toml');
    const target = ['alias = "lms-server"', 'container = "pg"', 'user = "ro"', 'database = "lms"'];
    writeFileSync(path, ['[prod]', ...target, 'deny_columns = ["^ssn$"]', ''].join('\n'));
    expect(loadTargets(path).prod?.denyColumns).toEqual(['^ssn$']);
    expect(buildDbOpContext('prod', {}, path).args.deny_columns).toBe('["^ssn$"]');
    for (const bad of ['[]', '"pass"', '["("]', '[1]']) {
      writeFileSync(path, ['[prod]', ...target, `deny_columns = ${bad}`, ''].join('\n'));
      expect(() => loadTargets(path)).toThrow(/deny_columns/);
    }
  });

  test('containers add up per alias across targets; a non-name entry is refused', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-targets-test-'));
    const path = join(dir, 'targets.toml');
    const target = (name: string, alias: string, containers: string) =>
      [
        `[${name}]`,
        `alias = "${alias}"`,
        'container = "pg"',
        'user = "ro"',
        'database = "d"',
        `containers = ${containers}`,
        '',
      ].join('\n');
    writeFileSync(
      path,
      [
        target('a', 'web-01', '["app", "worker"]'),
        target('b', 'web-01', '["app", "cron"]'),
        target('c', 'db-01', '["other"]'),
      ].join('\n'),
    );
    expect(declaredContainers('web-01', path)).toEqual(['app', 'cron', 'worker']);
    expect(declaredContainers('db-01', path)).toEqual(['other']);
    expect(declaredContainers('nowhere', path)).toEqual([]);
    writeFileSync(path, target('a', 'web-01', '["-v"]'));
    expect(() => loadTargets(path)).toThrow(/containers/);
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

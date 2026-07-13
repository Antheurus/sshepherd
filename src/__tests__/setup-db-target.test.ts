import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scaffold } from '../setup-db-target.ts';
import { loadTargets, resolveTarget } from '../targets.ts';

function tempTargetsPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-db-target-test-'));
  return join(dir, 'targets.toml');
}

describe('scaffold', () => {
  test('compose-hosted target round-trips through the real loadTargets/resolveTarget', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'prod',
      {
        alias: 'lms-server',
        user: 'sshepherd_ro',
        database: 'lms',
        composeFile: '/opt/lms/docker-compose.yml',
        service: 'db',
        yes: true,
      },
      path,
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      name: 'prod',
      alias: 'lms-server',
      user: 'sshepherd_ro',
      database: 'lms',
      composeFile: '/opt/lms/docker-compose.yml',
      service: 'db',
      container: null,
    });

    const expectedTarget = {
      alias: 'lms-server',
      composeFile: '/opt/lms/docker-compose.yml',
      service: 'db',
      container: null,
      user: 'sshepherd_ro',
      database: 'lms',
    };
    const targets = loadTargets(path);
    expect(targets.prod).toEqual(expectedTarget);
    expect(resolveTarget('prod', path)).toEqual(expectedTarget);
  });

  test('plain-container target round-trips through the real loadTargets/resolveTarget', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'staging',
      {
        alias: 'staging-1',
        user: 'sshepherd_ro',
        database: 'app',
        container: 'staging_postgres_1',
        yes: true,
      },
      path,
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      name: 'staging',
      alias: 'staging-1',
      user: 'sshepherd_ro',
      database: 'app',
      composeFile: null,
      service: null,
      container: 'staging_postgres_1',
    });

    const expectedTarget = {
      alias: 'staging-1',
      composeFile: null,
      service: null,
      container: 'staging_postgres_1',
      user: 'sshepherd_ro',
      database: 'app',
    };
    const targets = loadTargets(path);
    expect(targets.staging).toEqual(expectedTarget);
    expect(resolveTarget('staging', path)).toEqual(expectedTarget);
  });

  test('a second scaffold call appends alongside an existing table, both readable', () => {
    const path = tempTargetsPath();
    scaffold(
      'prod',
      { alias: 'lms-server', user: 'ro', database: 'lms', container: 'lms_pg', yes: true },
      path,
    );
    scaffold(
      'staging',
      { alias: 'staging-1', user: 'ro', database: 'app', container: 'staging_pg', yes: true },
      path,
    );

    const targets = loadTargets(path);
    expect(Object.keys(targets).sort()).toEqual(['prod', 'staging']);
  });

  test('fails validation before any file write when both compose and container are given', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'prod',
      {
        alias: 'lms-server',
        user: 'sshepherd_ro',
        database: 'lms',
        composeFile: '/opt/lms/docker-compose.yml',
        service: 'db',
        container: 'lms_pg',
        yes: true,
      },
      path,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('VALIDATION_ERROR');
    expect(existsSync(path)).toBe(false);
  });

  test('fails validation when neither compose nor container is given', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'prod',
      { alias: 'lms-server', user: 'sshepherd_ro', database: 'lms', yes: true },
      path,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('VALIDATION_ERROR');
    expect(existsSync(path)).toBe(false);
  });

  test('fails validation when compose_file is given without service', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'prod',
      {
        alias: 'lms-server',
        user: 'sshepherd_ro',
        database: 'lms',
        composeFile: '/opt/lms/docker-compose.yml',
        yes: true,
      },
      path,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('VALIDATION_ERROR');
    expect(existsSync(path)).toBe(false);
  });

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted, no file touched', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'prod',
      {
        alias: 'lms-server',
        user: 'sshepherd_ro',
        database: 'lms',
        container: 'lms_pg',
        yes: false,
      },
      path,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(existsSync(path)).toBe(false);
  });

  test('a value containing a double quote round-trips through the real loadTargets without throwing (regression for CRITICAL 1)', () => {
    const path = tempTargetsPath();
    const result = scaffold(
      'weird',
      { alias: 'my"alias', user: 'app', database: 'appdb', container: 'c', yes: true },
      path,
    );

    expect(result.ok).toBe(true);
    expect(result.data?.alias).toBe('my"alias');

    expect(() => loadTargets(path)).not.toThrow();
    expect(loadTargets(path).weird?.alias).toBe('my"alias');
  });

  test('fails with TARGET_EXISTS for a duplicate name, existing file untouched byte-for-byte', () => {
    const path = tempTargetsPath();
    writeFileSync(
      path,
      [
        '[prod]',
        'alias = "lms-server"',
        'container = "lms_pg"',
        'user = "ro"',
        'database = "lms"',
        '',
      ].join('\n'),
    );
    const before = readFileSync(path, 'utf8');

    const result = scaffold(
      'prod',
      {
        alias: 'other-alias',
        user: 'other_ro',
        database: 'other_db',
        container: 'other_pg',
        yes: true,
      },
      path,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('TARGET_EXISTS');
    expect(readFileSync(path, 'utf8')).toBe(before);
  });
});

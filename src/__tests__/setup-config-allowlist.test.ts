import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertPathAllowed } from '../registry.ts';
import { scaffold } from '../setup-config-allowlist.ts';
import type { OpContext } from '../types.ts';

function tempAllowlistPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-config-allowlist-test-'));
  return join(dir, 'config-allowlist.toml');
}

function ctxFor(alias: string): OpContext {
  return { alias, args: {} };
}

describe('scaffold', () => {
  test('a new alias round-trips through the real assertPathAllowed for every listed path', () => {
    const path = tempAllowlistPath();
    const result = scaffold(
      'lms-server',
      { paths: ['/etc/nginx/nginx.conf', '/opt/lms/.env'], yes: true },
      path,
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      alias: 'lms-server',
      paths: ['/etc/nginx/nginx.conf', '/opt/lms/.env'],
    });

    const previousEnv = process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = path;
    try {
      expect(() =>
        assertPathAllowed('config', ctxFor('lms-server'), '/etc/nginx/nginx.conf'),
      ).not.toThrow();
      expect(() =>
        assertPathAllowed('config', ctxFor('lms-server'), '/opt/lms/.env'),
      ).not.toThrow();
      expect(() => assertPathAllowed('config', ctxFor('lms-server'), '/etc/shadow')).toThrow();
    } finally {
      if (previousEnv === undefined) {
        delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
      } else {
        process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = previousEnv;
      }
    }
  });

  test('a second scaffold call for the same alias with different paths unions the lists, not duplicates the table', () => {
    const path = tempAllowlistPath();
    scaffold('lms-server', { paths: ['/etc/nginx/nginx.conf'], yes: true }, path);
    const second = scaffold('lms-server', { paths: ['/opt/lms/.env'], yes: true }, path);

    expect(second.ok).toBe(true);
    expect(second.data).toEqual({
      alias: 'lms-server',
      paths: ['/etc/nginx/nginx.conf', '/opt/lms/.env'],
    });

    const text = readFileSync(path, 'utf8');
    expect(text.match(/\[lms-server\]/g)?.length).toBe(1);
  });

  test('re-scaffolding with an already-present path does not duplicate it in the union', () => {
    const path = tempAllowlistPath();
    scaffold('lms-server', { paths: ['/etc/nginx/nginx.conf'], yes: true }, path);
    const second = scaffold(
      'lms-server',
      { paths: ['/etc/nginx/nginx.conf', '/opt/lms/.env'], yes: true },
      path,
    );

    expect(second.data).toEqual({
      alias: 'lms-server',
      paths: ['/etc/nginx/nginx.conf', '/opt/lms/.env'],
    });
  });

  test('a second alias appends alongside an existing table, both readable', () => {
    const path = tempAllowlistPath();
    scaffold('lms-server', { paths: ['/etc/nginx/nginx.conf'], yes: true }, path);
    scaffold('staging-1', { paths: ['/opt/app/.env'], yes: true }, path);

    const text = readFileSync(path, 'utf8');
    expect(text).toContain('[lms-server]');
    expect(text).toContain('[staging-1]');

    const previousEnv = process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = path;
    try {
      expect(() =>
        assertPathAllowed('config', ctxFor('lms-server'), '/etc/nginx/nginx.conf'),
      ).not.toThrow();
      expect(() => assertPathAllowed('config', ctxFor('staging-1'), '/opt/app/.env')).not.toThrow();
    } finally {
      if (previousEnv === undefined) {
        delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
      } else {
        process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = previousEnv;
      }
    }
  });

  test('fails with VALIDATION_ERROR when --paths resolves to an empty list, no file touched', () => {
    const path = tempAllowlistPath();
    const result = scaffold('lms-server', { paths: [], yes: true }, path);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('VALIDATION_ERROR');
    expect(existsSync(path)).toBe(false);
  });

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted, no file touched', () => {
    const path = tempAllowlistPath();
    const result = scaffold('lms-server', { paths: ['/etc/nginx/nginx.conf'], yes: false }, path);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(existsSync(path)).toBe(false);
  });

  test('merging an existing alias preserves an unrelated table untouched byte-for-byte', () => {
    const path = tempAllowlistPath();
    writeFileSync(
      path,
      [
        '[other-alias]',
        'paths = ["/etc/other.conf"]',
        '',
        '[lms-server]',
        'paths = ["/etc/nginx/nginx.conf"]',
        '',
      ].join('\n'),
    );

    const result = scaffold('lms-server', { paths: ['/opt/lms/.env'], yes: true }, path);

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      alias: 'lms-server',
      paths: ['/etc/nginx/nginx.conf', '/opt/lms/.env'],
    });

    const text = readFileSync(path, 'utf8');
    expect(text).toContain('[other-alias]');
    expect(text).toContain('paths = ["/etc/other.conf"]');
    expect(text.match(/\[other-alias\]/g)?.length).toBe(1);
  });
});

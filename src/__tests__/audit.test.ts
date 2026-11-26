import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditLogPath, auditMutating, confirmGate } from '../audit.ts';

describe('confirmGate', () => {
  test('non-mutating ops always pass, regardless of --yes', () => {
    expect(confirmGate({ mutating: false, yes: false })).toBe(true);
    expect(confirmGate({ mutating: false, yes: true })).toBe(true);
  });

  test('a mutating op is refused without --yes', () => {
    expect(confirmGate({ mutating: true, yes: false })).toBe(false);
  });

  test('a mutating op is allowed with --yes', () => {
    expect(confirmGate({ mutating: true, yes: true })).toBe(true);
  });
});

describe('auditMutating', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('appends one JSON line with a hashed args field, never the raw arg values', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit-test-'));
    tempDirs.push(dir);
    const logPath = join(dir, 'audit.jsonl');

    auditMutating(
      {
        alias: 'lms-server',
        command: 'services restart',
        argsSummary: { unit: 'lms-app', secretPath: '/opt/lms/.env.super-secret' },
        outcome: 'ok',
      },
      { logPath },
    );

    expect(existsSync(logPath)).toBe(true);
    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const line = lines[0];
    if (line === undefined) {
      throw new Error('expected an audit log line');
    }
    const entry = JSON.parse(line) as Record<string, unknown>;

    expect(entry.alias).toBe('lms-server');
    expect(entry.command).toBe('services restart');
    expect(entry.outcome).toBe('ok');
    expect(typeof entry.args_hash).toBe('string');
    expect(line).not.toContain('.env.super-secret');
    expect(line).not.toContain('secretPath');
  });

  test('appends a second line on a second call, does not overwrite the first', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit-test-'));
    tempDirs.push(dir);
    const logPath = join(dir, 'audit.jsonl');

    auditMutating(
      { alias: 'a', command: 'deploy run', argsSummary: {}, outcome: 'ok' },
      { logPath },
    );
    auditMutating(
      { alias: 'a', command: 'deploy run', argsSummary: {}, outcome: 'error' },
      { logPath },
    );

    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
  });
});

describe('auditLogPath — the log path is read at call time', () => {
  const saved = {
    dir: process.env.SSHEPHERD_STATE_DIR,
    file: process.env.SSHEPHERD_AUDIT_PATH,
  };

  afterEach(() => {
    for (const [key, value] of [
      ['SSHEPHERD_STATE_DIR', saved.dir],
      ['SSHEPHERD_AUDIT_PATH', saved.file],
    ] as const) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });

  test('the test preload points the default path at a throwaway state dir, never the real log', () => {
    delete process.env.SSHEPHERD_AUDIT_PATH;
    const resolved = auditLogPath();
    expect(resolved.startsWith(tmpdir())).toBe(true);
    expect(resolved).not.toContain(join(homedir(), '.local'));
  });

  test('a default-path call with no deps writes into SSHEPHERD_STATE_DIR', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit-state-'));
    delete process.env.SSHEPHERD_AUDIT_PATH;
    process.env.SSHEPHERD_STATE_DIR = dir;
    try {
      auditMutating({ alias: 'a', command: 'config put', argsSummary: {}, outcome: 'ok' });
      expect(readFileSync(join(dir, 'audit.jsonl'), 'utf8')).toContain('"command":"config put"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('SSHEPHERD_AUDIT_PATH wins over the state dir and is re-read on every call', () => {
    process.env.SSHEPHERD_AUDIT_PATH = '/tmp/one.jsonl';
    expect(auditLogPath()).toBe('/tmp/one.jsonl');
    process.env.SSHEPHERD_AUDIT_PATH = '/tmp/two.jsonl';
    expect(auditLogPath()).toBe('/tmp/two.jsonl');
  });

  test('with neither variable set the default is the user state directory', () => {
    delete process.env.SSHEPHERD_AUDIT_PATH;
    delete process.env.SSHEPHERD_STATE_DIR;
    expect(auditLogPath()).toBe(join(homedir(), '.local', 'state', 'sshepherd', 'audit.jsonl'));
  });
});

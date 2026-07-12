import { describe, expect, test } from 'bun:test';
import { buildEnvelope, splitNdjson } from '../output.ts';

describe('buildEnvelope', () => {
  test('ok is true and error is null on a successful op', () => {
    const startedAtMs = Date.now();
    const envelope = buildEnvelope({
      alias: 'lms-server',
      command: 'check mem',
      startedAtMs,
      data: { free_bytes: 1024 },
      error: null,
    });

    expect(envelope.ok).toBe(true);
    expect(envelope.alias).toBe('lms-server');
    expect(envelope.command).toBe('check mem');
    expect(envelope.error).toBeNull();
    expect(envelope.data).toEqual({ free_bytes: 1024 });
    expect(envelope.duration_ms).toBeGreaterThanOrEqual(0);
    expect(() => new Date(envelope.ran_at).toISOString()).not.toThrow();
  });

  test('ok is false and data stays null when error is set', () => {
    const envelope = buildEnvelope({
      alias: 'lms-server',
      command: 'hosts test',
      startedAtMs: Date.now(),
      data: null,
      error: { code: 'AUTH_FAILED', message: 'SSH authentication failed for this alias' },
    });

    expect(envelope.ok).toBe(false);
    expect(envelope.data).toBeNull();
    expect(envelope.error?.code).toBe('AUTH_FAILED');
  });

  test('the envelope has no host/user/port/ip field — structural half of zero-knowledge', () => {
    const envelope = buildEnvelope({
      alias: 'lms-server',
      command: 'hosts test',
      startedAtMs: Date.now(),
      data: null,
      error: null,
    });

    const keys = Object.keys(envelope);
    expect(keys.sort()).toEqual(
      ['ok', 'alias', 'ran_at', 'command', 'duration_ms', 'data', 'error'].sort(),
    );
  });
});

describe('splitNdjson', () => {
  test('parses one JSON object per non-blank line', () => {
    const stdout = '{"a":1}\n{"b":2}\n\n{"c":3}\n';
    expect(splitNdjson(stdout)).toEqual([{ a: 1 }, { b: 2 }, { c: 3 }]);
  });

  test('returns an empty array for blank input', () => {
    expect(splitNdjson('\n\n')).toEqual([]);
  });
});

import { describe, expect, test } from 'bun:test';
import { listOps } from '../registry.ts';
import { buildSetupResult, type SetupErrorInfo } from '../setup-types.ts';
import { OpRunLocalError } from '../types.ts';

describe('buildSetupResult', () => {
  test('defaults to ok:true, data:null, error:null when neither is supplied', () => {
    const result = buildSetupResult({ command: 'setup ssh-alias register' });

    expect(result.ok).toBe(true);
    expect(result.command).toBe('setup ssh-alias register');
    expect(result.data).toBeNull();
    expect(result.error).toBeNull();
    expect(() => new Date(result.ran_at).toISOString()).not.toThrow();
  });

  test('ok is false and the error is echoed back when an error is supplied', () => {
    const error: SetupErrorInfo = {
      code: 'NOT_IMPLEMENTED',
      message: 'setup db-target scaffold is not implemented yet',
    };
    const result = buildSetupResult({ command: 'setup db-target scaffold', error });

    expect(result.ok).toBe(false);
    expect(result.error).toEqual(error);
    expect(result.data).toBeNull();
  });

  test('carries through typed data on success', () => {
    const result = buildSetupResult({
      command: 'setup config-allowlist scaffold',
      data: { alias: 'lms-server', paths: ['/opt/lms'] },
    });

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ alias: 'lms-server', paths: ['/opt/lms'] });
  });

  test('the shape has no alias/duration_ms field — deliberately not an Envelope', () => {
    const keys = Object.keys(buildSetupResult({ command: 'setup deploy-recipe scaffold' }));
    expect(keys.sort()).toEqual(['command', 'data', 'error', 'ok', 'ran_at']);
  });
});

describe('setup stays off the registry', () => {
  test('GROUPS derived from listOps() does not include "setup"', () => {
    const groups = new Set(listOps().map((op) => op.group));
    expect(groups.has('setup')).toBe(false);
  });
});

describe('OpRunLocalError', () => {
  test('OpRunLocalError carries a code and a dynamic message', () => {
    const err = new OpRunLocalError('VALIDATION_ERROR', "--remote is required for kind 'local'");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('OpRunLocalError');
    expect(err.code).toBe('VALIDATION_ERROR');
    expect(err.message).toBe("--remote is required for kind 'local'");
  });
});

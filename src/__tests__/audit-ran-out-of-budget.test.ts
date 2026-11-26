import { describe, expect, test } from 'bun:test';
import { classify, run, type SshRunner } from '../transport.ts';
import type { RawResult } from '../types.ts';

function failing(code: number): RawResult {
  return { code, stdout: '', transportStderr: '', commandStderr: 'boom', timedOut: false };
}

describe('ranOutOfBudget through classify', () => {
  test('exit 1 after 100 ms of a 30 s budget stays COMMAND_FAILED', () => {
    const info = classify(failing(1), { timeoutSec: 30, elapsedMs: 100 });
    expect(info?.code).toBe('COMMAND_FAILED');
  });

  test('exit 1 just under the budget stays COMMAND_FAILED', () => {
    expect(classify(failing(1), { timeoutSec: 30, elapsedMs: 29_999 })?.code).toBe(
      'COMMAND_FAILED',
    );
  });

  test('exit 143 having used the whole budget is COMMAND_TIMEOUT', () => {
    expect(classify(failing(143), { timeoutSec: 2, elapsedMs: 2_050 })?.code).toBe(
      'COMMAND_TIMEOUT',
    );
  });

  test('exit 255 at the budget is a transport failure, never a timeout', () => {
    const raw: RawResult = {
      code: 255,
      stdout: '',
      transportStderr: 'x',
      commandStderr: '',
      timedOut: false,
    };
    expect(classify(raw, { timeoutSec: 2, elapsedMs: 5_000 })?.code).toBe('SSH_TRANSPORT_ERROR');
  });

  test('without a timeoutSec in context no exit code can become a timeout', () => {
    expect(classify(failing(1), { elapsedMs: 999_999 })?.code).toBe('COMMAND_FAILED');
  });
});

describe('ranOutOfBudget through run() with a scripted runner', () => {
  const fast: SshRunner = async (args) => {
    if (args.includes('-G'))
      return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
    if (args.includes('timeout')) return { code: 1, stdout: '', stderr: 'nope', timedOut: false };
    return { code: 0, stdout: '', stderr: '', timedOut: false };
  };

  test('a command exiting 1 immediately with budget 30 is COMMAND_FAILED', async () => {
    const result = await run('lms-server', 'false', 30, { runner: fast });
    expect(result.error?.code).toBe('COMMAND_FAILED');
  });

  test('a command exiting 1 only after consuming the 1 s budget is COMMAND_TIMEOUT (documents the heuristic)', async () => {
    const slow: SshRunner = async (args) => {
      if (args.includes('timeout')) {
        await Bun.sleep(1_050);
        return { code: 1, stdout: '', stderr: 'x', timedOut: false };
      }
      return fast(args, 0);
    };
    const result = await run('lms-server', 'false', 1, { runner: slow });
    expect(result.error?.code).toBe('COMMAND_TIMEOUT');
  });
});

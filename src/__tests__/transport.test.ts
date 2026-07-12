import { describe, expect, test } from 'bun:test';
import { buildEnvelope } from '../output.ts';
import { classify, run, type SpawnOutcome, type SshRunner } from '../transport.ts';
import type { RawResult } from '../types.ts';

/** Scripted runner: returns queued outcomes in call order, last one repeats if exhausted. */
function scriptedRunner(outcomes: SpawnOutcome[]): SshRunner {
  let index = 0;
  return async () => {
    const outcome = outcomes[Math.min(index, outcomes.length - 1)];
    index += 1;
    if (!outcome) {
      throw new Error('scriptedRunner: no outcome configured');
    }
    return outcome;
  };
}

describe('classify', () => {
  test('exit 255 + Permission denied -> AUTH_FAILED', () => {
    const raw: RawResult = {
      code: 255,
      stdout: '',
      transportStderr: 'Permission denied (publickey).',
      commandStderr: '',
      timedOut: false,
    };
    expect(classify(raw)).toEqual({
      code: 'AUTH_FAILED',
      message: 'SSH authentication failed for this alias',
    });
  });

  test('exit 255 + connection timed out -> CONNECT_TIMEOUT', () => {
    const raw: RawResult = {
      code: 255,
      stdout: '',
      transportStderr: 'ssh: connect to host 10.0.0.5 port 22: Connection timed out',
      commandStderr: '',
      timedOut: false,
    };
    expect(classify(raw)?.code).toBe('CONNECT_TIMEOUT');
  });

  test('exit 255 + host key change phrase -> HOST_KEY_MISMATCH', () => {
    const raw: RawResult = {
      code: 255,
      stdout: '',
      transportStderr: 'REMOTE HOST IDENTIFICATION HAS CHANGED!',
      commandStderr: '',
      timedOut: false,
    };
    expect(classify(raw)?.code).toBe('HOST_KEY_MISMATCH');
  });

  test('exit 255 + unrecognized phrase -> SSH_TRANSPORT_ERROR', () => {
    const raw: RawResult = {
      code: 255,
      stdout: '',
      transportStderr: 'kex_exchange_identification: read: Connection reset by peer',
      commandStderr: '',
      timedOut: false,
    };
    expect(classify(raw)?.code).toBe('SSH_TRANSPORT_ERROR');
  });

  test('non-255 exit -> COMMAND_FAILED, carries the remote exit code', () => {
    const raw: RawResult = {
      code: 7,
      stdout: '',
      transportStderr: '',
      commandStderr: 'systemctl: unit not found',
      timedOut: false,
    };
    expect(classify(raw)).toEqual({
      code: 'COMMAND_FAILED',
      message: 'Remote command exited with a non-zero status',
      remote_exit: 7,
    });
  });

  test('timedOut -> COMMAND_TIMEOUT regardless of exit code', () => {
    const raw: RawResult = {
      code: 0,
      stdout: '',
      transportStderr: '',
      commandStderr: '',
      timedOut: true,
    };
    expect(classify(raw)?.code).toBe('COMMAND_TIMEOUT');
  });

  test('exit 0, not timed out -> no error', () => {
    const raw: RawResult = {
      code: 0,
      stdout: '{"ok":true}',
      transportStderr: '',
      commandStderr: '',
      timedOut: false,
    };
    expect(classify(raw)).toBeNull();
  });
});

describe('run — alias validation', () => {
  test('unknown alias returns UNKNOWN_ALIAS without attempting a connection', async () => {
    let callCount = 0;
    const runner: SshRunner = async () => {
      callCount += 1;
      return { code: 1, stdout: '', stderr: '', timedOut: false };
    };

    const result = await run('nope', 'echo hi', 5, { runner });

    expect(result.error?.code).toBe('UNKNOWN_ALIAS');
    // Only the -G validation call should have run — no master open, no command run.
    expect(callCount).toBe(1);
  });
});

describe('run — end to end with a fake runner', () => {
  test('a successful command produces no error and carries stdout', async () => {
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check (master already up)
      { code: 0, stdout: '{"free_bytes":123}', stderr: '', timedOut: false }, // actual run
    ]);

    const result = await run('lms-server', 'cat /proc/meminfo', 10, { runner });

    expect(result.error).toBeNull();
    expect(result.raw.stdout).toBe('{"free_bytes":123}');
  });

  test('AUTH_FAILED path never leaks its transportStderr text into the raw stdout field', async () => {
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 1, stdout: '', stderr: '', timedOut: false }, // -O check fails (no master yet)
      { code: 1, stdout: '', stderr: '', timedOut: false }, // -O exit (stale cleanup, ignored)
      { code: 255, stdout: '', stderr: '', timedOut: false }, // -M -N -f open fails
      {
        code: 255,
        stdout: '',
        stderr: 'Permission denied (publickey) for 10.0.0.9',
        timedOut: false,
      }, // actual run attempt over the (unopened) master
    ]);

    const result = await run('lms-server', 'echo hi', 10, { runner });

    expect(result.error?.code).toBe('AUTH_FAILED');
    expect(result.raw.stdout).toBe('');
  });
});

describe('hygiene invariant — transport stderr never reaches the envelope', () => {
  test('a simulated ssh transport-stderr line containing an IP never appears in the envelope', async () => {
    const leakyIp = '203.0.113.42';
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 1, stdout: '', stderr: '', timedOut: false }, // -O check fails
      { code: 1, stdout: '', stderr: '', timedOut: false }, // -O exit cleanup
      { code: 255, stdout: '', stderr: '', timedOut: false }, // master open fails
      {
        code: 255,
        stdout: '',
        stderr: `ssh: connect to host ${leakyIp} port 22: Connection timed out`,
        timedOut: false,
      },
    ]);

    const startedAtMs = Date.now();
    const result = await run('lms-server', 'echo hi', 10, { runner });
    const envelope = buildEnvelope({
      alias: 'lms-server',
      command: 'hosts test',
      startedAtMs,
      data: null,
      error: result.error,
    });

    expect(result.error?.code).toBe('CONNECT_TIMEOUT');
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain(leakyIp);
    expect(envelope.error?.message).toBe('Connection to the remote host timed out');
    expect(Object.keys(envelope)).not.toContain('host');
    expect(Object.keys(envelope)).not.toContain('ip');
    expect(Object.keys(envelope)).not.toContain('user');
    expect(Object.keys(envelope)).not.toContain('port');
  });
});

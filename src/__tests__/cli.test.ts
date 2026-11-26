import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { join } from 'node:path';
import { parseArgv, run } from '../cli.ts';
import type { SshRunner } from '../transport.ts';

describe('parseArgv — boolean flags never swallow a positional', () => {
  test('`deploy run --yes r1` keeps r1 as a positional and sets yes', () => {
    const { positionals, flags } = parseArgv(['deploy', 'run', '--yes', 'r1']);

    expect(positionals).toEqual(['deploy', 'run', 'r1']);
    expect(flags.get('yes')).toEqual(['true']);
  });

  for (const flag of ['yes', 'dry-run', 'keep-session', 'pretty', 'help', 'all']) {
    test(`--${flag} before a positional`, () => {
      const { positionals, flags } = parseArgv([`--${flag}`, 'target']);

      expect(positionals).toEqual(['target']);
      expect(flags.get(flag)).toEqual(['true']);
    });
  }

  test('a value flag still takes the next token', () => {
    const { positionals, flags } = parseArgv(['--tail', '50', 'web-01']);

    expect(positionals).toEqual(['web-01']);
    expect(flags.get('tail')).toEqual(['50']);
  });

  test('`--` ends flag parsing: everything after it is a positional, even --yes', () => {
    const { positionals, flags } = parseArgv(['web-01', '--', '--yes', '-x', 'last']);

    expect(positionals).toEqual(['web-01', '--yes', '-x', 'last']);
    expect(flags.has('yes')).toBe(false);
  });
});

describe('run — global --timeout', () => {
  const written: string[] = [];
  const realWrite = process.stdout.write.bind(process.stdout);
  let savedExitCode: typeof process.exitCode;

  beforeEach(() => {
    written.length = 0;
    savedExitCode = process.exitCode;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
  });

  afterEach(() => {
    process.stdout.write = realWrite;
    process.exitCode = savedExitCode;
  });

  function scripted(seenTimeouts: number[]): SshRunner {
    return async (args, timeoutMs) => {
      if (args.includes('timeout')) {
        seenTimeouts.push(timeoutMs);
        return {
          code: 0,
          stdout: 'Filesystem Size Used Avail Use% Mounted\n',
          stderr: '',
          timedOut: false,
        };
      }
      return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
    };
  }

  test('`check disk x --timeout 45` reaches the runner with a 45 s budget', async () => {
    const seen: number[] = [];
    const remoteArgs: string[][] = [];
    const runner: SshRunner = async (args, timeoutMs) => {
      if (args.includes('timeout')) {
        remoteArgs.push(args);
      }
      return scripted(seen)(args, timeoutMs);
    };

    await run(['check', 'disk', 'x', '--timeout', '45'], { transport: { runner } });

    const args = remoteArgs[0] ?? [];
    expect(args[args.indexOf('timeout') + 3]).toBe('45');
    expect(seen[0]).toBe(45 * 1_000 + 2_000);
  });

  test('without --timeout the op default (check: 30 s) applies', async () => {
    const seen: number[] = [];

    await run(['check', 'disk', 'x'], { transport: { runner: scripted(seen) } });

    expect(seen[0]).toBe(30 * 1_000 + 2_000);
  });

  for (const bad of ['9999', '0', '-5', 'abc', '1.5']) {
    test(`--timeout ${bad} -> INVALID_ARGS envelope, ssh never touched`, async () => {
      let calls = 0;
      const runner: SshRunner = async () => {
        calls += 1;
        return { code: 0, stdout: '', stderr: '', timedOut: false };
      };

      await run(['check', 'disk', 'x', '--timeout', bad], { transport: { runner } });

      const envelope = JSON.parse(written.join(''));
      expect(envelope.ok).toBe(false);
      expect(envelope.error.code).toBe('INVALID_ARGS');
      expect(envelope.error.message).toContain('1 to 3600');
      expect(calls).toBe(0);
      expect(process.exitCode).toBe(2);
    });
  }
});

interface CliEnvelope {
  ok: boolean;
  error: {
    code: string;
    message: string;
    hint: string;
    retryable: boolean;
    next?: string;
    did_you_mean?: string[];
  };
}

describe('usage failures are JSON envelopes with guidance and exit code 2', () => {
  async function runBinary(
    args: string[],
  ): Promise<{ envelope: CliEnvelope; code: number; stderr: string }> {
    const proc = Bun.spawn(['bun', join(import.meta.dir, '..', 'cli.ts'), ...args], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env, SSHEPHERD_TARGETS_PATH: '/nonexistent/targets.toml' },
    });
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { envelope: JSON.parse(stdout), code, stderr };
  }

  test('unknown action -> UNKNOWN_SUBGROUP listing the group actions', async () => {
    const { envelope, code } = await runBinary(['check', 'bogus']);
    expect(envelope.ok).toBe(false);
    expect(envelope.error.code).toBe('UNKNOWN_SUBGROUP');
    expect(envelope.error.did_you_mean).toContain('disk');
    expect(envelope.error.next).toBe('sshepherd check --help');
    expect(envelope.error.retryable).toBe(false);
    expect(code).toBe(2);
  });

  test('a misspelt group suggests the real one first', async () => {
    const { envelope, code } = await runBinary(['chek', 'disk']);
    expect(envelope.error.code).toBe('UNKNOWN_SUBGROUP');
    expect(envelope.error.did_you_mean?.[0]).toBe('check');
    expect(code).toBe(2);
  });

  test('an unknown flag -> PARSE_ERROR naming it, with the near flag', async () => {
    const { envelope, code } = await runBinary(['logs', 'docker', 'web', '--tial', '5']);
    expect(envelope.error.code).toBe('PARSE_ERROR');
    expect(envelope.error.message).toContain('--tial');
    expect(envelope.error.did_you_mean).toContain('--tail');
    expect(code).toBe(2);
  });

  test('a missing required positional -> INVALID_ARGS pointing at --help', async () => {
    const { envelope, code } = await runBinary(['logs', 'docker', 'web']);
    expect(envelope.error.code).toBe('INVALID_ARGS');
    expect(envelope.error.next).toBe('sshepherd logs docker --help');
    expect(code).toBe(2);
  });

  test('an option-shaped container -> INVALID_ARGS before ssh', async () => {
    const { envelope, code } = await runBinary(['logs', 'docker', 'web', '-f']);
    expect(envelope.error.code).toBe('INVALID_ARGS');
    expect(code).toBe(2);
  });

  test('an undeclared pg-target -> VALIDATION_ERROR, no stderr text', async () => {
    const { envelope, code, stderr } = await runBinary(['db', 'tables', 'nope']);
    expect(envelope.error.code).toBe('VALIDATION_ERROR');
    expect(envelope.error.next).toBe('sshepherd db list');
    expect(code).toBe(2);
    expect(stderr).toBe('');
  });

  test('setup <sub-group> <action> --help prints help even though required args are missing', async () => {
    const proc = Bun.spawn(
      ['bun', join(import.meta.dir, '..', 'cli.ts'), 'setup', 'db-target', 'scaffold', '--help'],
      { stdout: 'pipe', stderr: 'pipe' },
    );
    const [stdout, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    expect(stdout).toContain('sshepherd setup db-target <action>');
    expect(code).toBe(0);
  });

  test('an unknown setup sub-group carries did_you_mean and exits 2', async () => {
    const { envelope, code } = await runBinary(['setup', 'ssh-alais']);
    expect(envelope.error.code).toBe('UNKNOWN_SUBGROUP');
    expect(envelope.error.did_you_mean?.[0]).toBe('ssh-alias');
    expect(envelope.error.hint.length).toBeGreaterThan(0);
    expect(code).toBe(2);
  });
});

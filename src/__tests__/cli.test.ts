import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
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

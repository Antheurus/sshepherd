import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { errorInfo } from '../errors.ts';
import { buildEnvelope } from '../output.ts';
import { listHostAliases } from '../parsers/ssh-config.ts';
import { executeOp, getOp } from '../registry.ts';
import {
  classify,
  closeAllMasters,
  closeMaster,
  run,
  type SpawnOutcome,
  type SshRunner,
} from '../transport.ts';
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
    expect(classify(raw)).toEqual(errorInfo('AUTH_FAILED'));
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
    expect(classify(raw)).toEqual(errorInfo('COMMAND_FAILED', 7));
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

describe('run — keepalive and kill-escalation (fixes the idle-drop / orphaned-remote-process incident)', () => {
  test('opening a fresh ControlMaster carries ServerAliveInterval/CountMax — a long, quiet remote command must not look idle to a network middlebox', async () => {
    const seenArgs: string[][] = [];
    const runner: SshRunner = async (args) => {
      seenArgs.push(args);
      if (args.includes('-G')) {
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      }
      if (args.includes('check')) {
        return { code: 1, stdout: '', stderr: '', timedOut: false }; // no master yet
      }
      if (args.includes('exit')) {
        return { code: 1, stdout: '', stderr: '', timedOut: false }; // stale cleanup, ignored
      }
      // -M -N -f master open, then the actual command
      return { code: 0, stdout: 'ok', stderr: '', timedOut: false };
    };

    await run('lms-server', 'echo hi', 30, { runner });

    const masterOpenCall = seenArgs.find((a) => a.includes('-M') && a.includes('-N'));
    expect(masterOpenCall).toBeDefined();
    expect(masterOpenCall).toContain('ServerAliveInterval=15');
    expect(masterOpenCall).toContain('ServerAliveCountMax=4');

    const commandCall = seenArgs[seenArgs.length - 1];
    expect(commandCall).toContain('ServerAliveInterval=15');
    expect(commandCall).toContain('ServerAliveCountMax=4');
  });

  test('the remote command is wrapped in `timeout -k 10 <sec>` (the short form busybox also accepts) so a hung wrapper is force-killed', async () => {
    let commandArgs: string[] = [];
    const runner: SshRunner = async (args) => {
      if (args.includes('timeout')) {
        commandArgs = args;
      }
      return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
    };

    await run('lms-server', 'echo hi', 45, { runner });

    const timeoutIndex = commandArgs.indexOf('timeout');
    expect(timeoutIndex).toBeGreaterThanOrEqual(0);
    expect(commandArgs[timeoutIndex + 1]).toBe('-k');
    expect(commandArgs[timeoutIndex + 2]).toBe('10');
    expect(commandArgs[timeoutIndex + 3]).toBe('45');
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
      { code: 255, stdout: '', stderr: 'No such file or directory', timedOut: false }, // -O check: no master yet
      {
        code: 255,
        stdout: '',
        stderr: 'Permission denied (publickey) for 10.0.0.9',
        timedOut: false,
      }, // -M -N -f open fails; the command never runs
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
      { code: 255, stdout: '', stderr: 'No such file or directory', timedOut: false }, // -O check fails
      {
        code: 255,
        stdout: '',
        stderr: `ssh: connect to host ${leakyIp} port 22: Connection timed out`,
        timedOut: false,
      }, // master open fails
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

  test('a remote command that itself prints an IP on stderr with a non-255 exit stays out of the error message, since only remote stdout is legitimate payload', async () => {
    const remoteIp = '198.51.100.7';
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check (master already up)
      {
        code: 1,
        stdout: '',
        // This is the REMOTE COMMAND's own stderr (e.g. `curl` failing and echoing the
        // IP it tried to hit) — not an ssh transport failure. Exit code is non-255, so
        // transport.run must route this to commandStderr, and classify() must never
        // read commandStderr when building the static ErrorInfo.message.
        stderr: `curl: (7) Failed to connect to ${remoteIp} port 443: Connection refused`,
        timedOut: false,
      },
    ]);

    const startedAtMs = Date.now();
    const result = await run('lms-server', 'curl https://internal', 10, { runner });
    const envelope = buildEnvelope({
      alias: 'lms-server',
      command: 'net check',
      startedAtMs,
      data: null,
      error: result.error,
    });

    expect(result.error?.code).toBe('COMMAND_FAILED');
    expect(result.error?.remote_exit).toBe(1);
    // The remote command's own stderr text (and the IP inside it) must never surface —
    // only the static per-code message is allowed into the envelope.
    expect(result.error?.message).toBe('Remote command exited with a non-zero status');
    expect(JSON.stringify(envelope)).not.toContain(remoteIp);
  });

  test('remote command STDOUT is the legitimate payload and is not scrubbed even if it contains an IP — only ssh transport stderr is discarded', async () => {
    const remoteIp = '198.51.100.7';
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check (master already up)
      {
        code: 0,
        // Legitimate op output, e.g. `ip addr` — this is the payload the user asked
        // for, not transport chatter, and must pass through untouched.
        stdout: `{"iface":"eth0","addr":"${remoteIp}"}`,
        stderr: '',
        timedOut: false,
      },
    ]);

    const result = await run('lms-server', 'ip -j addr show eth0', 10, { runner });

    expect(result.error).toBeNull();
    expect(result.raw.stdout).toContain(remoteIp);
  });
});

/** Stateful fake: a master opened once stays up, as a ControlPersist master does across
 *  separate sshepherd invocations. */
function persistentMasterRunner(): { runner: SshRunner; calls: string[][]; opens: () => number } {
  const calls: string[][] = [];
  let masterUp = false;
  let opens = 0;
  const runner: SshRunner = async (args) => {
    calls.push(args);
    if (args.includes('-G')) {
      return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
    }
    if (args.includes('check')) {
      return masterUp
        ? { code: 0, stdout: '', stderr: 'Master running', timedOut: false }
        : { code: 255, stdout: '', stderr: 'No such file or directory', timedOut: false };
    }
    if (args.includes('-M')) {
      masterUp = true;
      opens += 1;
      return { code: 0, stdout: '', stderr: '', timedOut: false };
    }
    return { code: 0, stdout: 'ok', stderr: '', timedOut: false };
  };
  return { runner, calls, opens: () => opens };
}

describe('run — one ControlMaster reused across invocations', () => {
  test('two sequential run() calls open at most one master', async () => {
    const fake = persistentMasterRunner();

    const first = await run('web-a', 'echo one', 10, { runner: fake.runner });
    const second = await run('web-a', 'echo two', 10, { runner: fake.runner });

    expect(first.error).toBeNull();
    expect(second.error).toBeNull();
    expect(fake.opens()).toBe(1);
  });

  test('the master persists 300 s past the last use and the socket name is a 16-char sha256 prefix under 100 chars', async () => {
    const fake = persistentMasterRunner();

    await run('web-a', 'echo one', 10, { runner: fake.runner });

    const open = fake.calls.find((args) => args.includes('-M'));
    expect(open).toContain('ControlPersist=300');
    expect(open).toContain('ConnectTimeout=10');
    const controlPath = (open?.find((arg) => arg.startsWith('ControlPath=')) ?? '').slice(
      'ControlPath='.length,
    );
    expect(controlPath.length).toBeLessThan(100);
    expect(controlPath).toMatch(/\/[0-9a-f]{16}\.sock$/);
  });

  test('the command call carries ConnectTimeout=10 so a lapsed master fails fast, not after the OS default', async () => {
    const fake = persistentMasterRunner();

    await run('web-a', 'echo one', 10, { runner: fake.runner });

    const commandCall = fake.calls[fake.calls.length - 1];
    expect(commandCall).toContain('ConnectTimeout=10');
  });

  test('`-O exit` runs only when `-O check` reports a stale socket (Connection refused)', async () => {
    const calls: string[][] = [];
    const makeRunner = (checkStderr: string): SshRunner => {
      return async (args) => {
        calls.push(args);
        if (args.includes('check')) {
          return { code: 255, stdout: '', stderr: checkStderr, timedOut: false };
        }
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      };
    };

    await run('web-a', 'echo hi', 10, { runner: makeRunner('No such file or directory') });
    expect(calls.some((args) => args.includes('exit'))).toBe(false);

    calls.length = 0;
    await run('web-a', 'echo hi', 10, {
      runner: makeRunner('Control socket connect: Connection refused'),
    });
    expect(calls.some((args) => args.includes('exit'))).toBe(true);
  });
});

describe('run — connect failures and remote timeouts are classified', () => {
  test('master-open 255 "Connection timed out" -> CONNECT_TIMEOUT (phase connect), command never runs', async () => {
    const calls: string[][] = [];
    const runner: SshRunner = async (args) => {
      calls.push(args);
      if (args.includes('-G')) {
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      }
      if (args.includes('check')) {
        return { code: 255, stdout: '', stderr: 'No such file or directory', timedOut: false };
      }
      return {
        code: 255,
        stdout: '',
        stderr: 'ssh: connect to host 10.0.0.9 port 22: Connection timed out',
        timedOut: false,
      };
    };

    const result = await run('web-a', 'echo hi', 10, { runner });

    expect(result.error?.code).toBe('CONNECT_TIMEOUT');
    expect(result.error?.phase).toBe('connect');
    expect(result.error?.timeout_sec).toBe(10);
    expect(typeof result.error?.elapsed_ms).toBe('number');
    expect(calls.some((args) => args.includes('timeout'))).toBe(false);
  });

  test('master-open killed locally (timedOut) -> CONNECT_TIMEOUT, not COMMAND_TIMEOUT', async () => {
    const runner: SshRunner = async (args) => {
      if (args.includes('-G')) {
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      }
      if (args.includes('check')) {
        return { code: 255, stdout: '', stderr: '', timedOut: false };
      }
      return { code: -1, stdout: '', stderr: '', timedOut: true };
    };

    const result = await run('web-a', 'echo hi', 10, { runner });

    expect(result.error?.code).toBe('CONNECT_TIMEOUT');
    expect(result.error?.phase).toBe('connect');
  });

  test('master-open 255 "Permission denied" -> AUTH_FAILED', async () => {
    const runner: SshRunner = async (args) => {
      if (args.includes('-G')) {
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      }
      if (args.includes('check')) {
        return { code: 255, stdout: '', stderr: '', timedOut: false };
      }
      return { code: 255, stdout: '', stderr: 'Permission denied (publickey).', timedOut: false };
    };

    const result = await run('web-a', 'echo hi', 10, { runner });

    expect(result.error?.code).toBe('AUTH_FAILED');
  });

  for (const exitCode of [124, 137]) {
    test(`remote exit ${exitCode} -> COMMAND_TIMEOUT carrying budget_sec, phase and the partial stdout`, async () => {
      const runner: SshRunner = async (args) => {
        if (args.includes('timeout')) {
          return { code: exitCode, stdout: 'half-done\n', stderr: 'Terminated', timedOut: false };
        }
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      };

      const result = await run('web-a', 'slow-thing', 45, { runner });

      expect(result.error?.code).toBe('COMMAND_TIMEOUT');
      expect(result.error?.budget_sec).toBe(45);
      expect(result.error?.timeout_sec).toBe(45);
      expect(result.error?.phase).toBe('command');
      expect(typeof result.error?.elapsed_ms).toBe('number');
      expect(result.raw.stdout).toBe('half-done\n');
    });
  }

  test('local kill of the command (timedOut) -> COMMAND_TIMEOUT with the budget', async () => {
    const runner: SshRunner = async (args) => {
      if (args.includes('timeout')) {
        return { code: -1, stdout: 'so far', stderr: '', timedOut: true };
      }
      return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
    };

    const result = await run('web-a', 'slow-thing', 20, { runner });

    expect(result.error?.code).toBe('COMMAND_TIMEOUT');
    expect(result.error?.budget_sec).toBe(20);
    expect(result.raw.stdout).toBe('so far');
  });
});

describe('hosts disconnect — closing reused masters on demand', () => {
  test('closeMaster reports whether a master was up', async () => {
    const up: SshRunner = async () => ({ code: 0, stdout: '', stderr: '', timedOut: false });
    const down: SshRunner = async () => ({ code: 255, stdout: '', stderr: '', timedOut: false });

    expect(await closeMaster('web-a', { runner: up })).toBe(true);
    expect(await closeMaster('web-a', { runner: down })).toBe(false);
  });

  test('closeAllMasters sends `-O exit` to every *.sock in the socket dir and counts the live ones', async () => {
    const saved = process.env.XDG_RUNTIME_DIR;
    const base = mkdtempSync(join(tmpdir(), 'sshepherd-disconnect-'));
    mkdirSync(join(base, 'sshepherd'));
    for (const name of ['aaaa.sock', 'bbbb.sock', 'notes.txt']) {
      writeFileSync(join(base, 'sshepherd', name), '');
    }
    process.env.XDG_RUNTIME_DIR = base;
    try {
      const paths: string[] = [];
      const runner: SshRunner = async (args) => {
        paths.push(args.find((arg) => arg.startsWith('ControlPath=')) ?? '');
        const live = paths.length === 1;
        return { code: live ? 0 : 255, stdout: '', stderr: '', timedOut: false };
      };

      const closed = await closeAllMasters({ runner });

      expect(closed).toBe(1);
      expect(paths.sort()).toEqual([
        `ControlPath=${join(base, 'sshepherd', 'aaaa.sock')}`,
        `ControlPath=${join(base, 'sshepherd', 'bbbb.sock')}`,
      ]);
    } finally {
      if (saved === undefined) {
        delete process.env.XDG_RUNTIME_DIR;
      } else {
        process.env.XDG_RUNTIME_DIR = saved;
      }
    }
  });

  test('the op needs an alias or --all, never both', async () => {
    const op = getOp('hosts', 'disconnect');
    if (!op) {
      throw new Error('hosts disconnect op missing');
    }
    const runner: SshRunner = async () => ({ code: 0, stdout: '', stderr: '', timedOut: false });

    const neither = await executeOp(op, { alias: '', args: {} }, { transport: { runner } });
    const both = await executeOp(
      op,
      { alias: 'web-a', args: { all: true } },
      { transport: { runner } },
    );
    const one = await executeOp(op, { alias: 'web-a', args: {} }, { transport: { runner } });

    expect(neither.error?.code).toBe('VALIDATION_ERROR');
    expect(both.error?.code).toBe('VALIDATION_ERROR');
    expect(one.data).toEqual({ closed: 1 });
  });
});

describe('executeOp — a timed-out command returns what it printed', () => {
  test('COMMAND_TIMEOUT envelope carries data.partial_stdout and the budget', async () => {
    const op = getOp('check', 'disk');
    if (!op) {
      throw new Error('check disk op missing');
    }
    const runner: SshRunner = async (args) =>
      args.includes('timeout')
        ? { code: 124, stdout: 'Filesystem\n', stderr: '', timedOut: false }
        : { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };

    const envelope = await executeOp(
      op,
      { alias: 'web-a', args: {} },
      { transport: { runner }, timeoutSec: 45 },
    );

    expect(envelope.error?.code).toBe('COMMAND_TIMEOUT');
    expect(envelope.error?.budget_sec).toBe(45);
    expect(envelope.data).toEqual({ partial_stdout: 'Filesystem\n' });
  });
});

describe('run — an alias no ssh config declares is UNKNOWN_ALIAS even though ssh -G exits 0', () => {
  function configWith(text: string): string {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-alias-test-'));
    const path = join(dir, 'config');
    writeFileSync(path, text);
    return path;
  }

  test('-G echoing the name back as hostname + no Host stanza -> UNKNOWN_ALIAS with the nearest declared alias, one runner call', async () => {
    let calls = 0;
    const runner: SshRunner = async (args) => {
      calls += 1;
      return args.includes('-G')
        ? { code: 0, stdout: 'host nonexist\nhostname nonexist\n', stderr: '', timedOut: false }
        : { code: 0, stdout: '', stderr: '', timedOut: false };
    };
    const sshConfigPath = configWith('Host web-prod\n  HostName 10.0.0.9\nHost nonexistent\n');

    const result = await run('nonexist', 'echo hi', 10, { runner, sshConfigPath });

    expect(result.error?.code).toBe('UNKNOWN_ALIAS');
    expect(result.error?.next).toBe('sshepherd hosts list');
    expect(result.error?.did_you_mean).toEqual(['nonexistent']);
    expect(calls).toBe(1);
  });

  test('an alias declared with no HostName (so -G echoes it) is still known', async () => {
    const runner: SshRunner = async (args) =>
      args.includes('-G')
        ? { code: 0, stdout: 'hostname bare-alias\n', stderr: '', timedOut: false }
        : { code: 0, stdout: 'ok', stderr: '', timedOut: false };
    const sshConfigPath = configWith('Host bare-alias\n  User deploy\n');

    const result = await run('bare-alias', 'echo hi', 10, { runner, sshConfigPath });

    expect(result.error).toBeNull();
  });
});

describe('run — Include, wildcard Host and Match blocks are followed like ssh does', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'sshepherd-include-test-'));
  const sshConfigPath = join(tempDir, 'config');
  writeFileSync(join(tempDir, 'extra.conf'), 'Host inc2\n  User u\n');
  writeFileSync(
    sshConfigPath,
    'Include extra.conf\n\nHost *.internal\n  User ops\n\nMatch host m2\n  User x\n',
  );
  const bareConfigPath = join(tempDir, 'bare-config');
  writeFileSync(bareConfigPath, 'Host web-prod\n  HostName 10.0.0.9\n');

  /** `-G` goes to the real ssh, which only parses the temp config; every other call is
   *  answered locally so no connection is ever attempted. */
  function realParseRunner(configPath: string): SshRunner {
    return async (args) => {
      if (!args.includes('-G')) {
        return { code: 255, stdout: '', stderr: 'no network in tests', timedOut: false };
      }
      const proc = Bun.spawn(['ssh', '-F', configPath, ...args], {
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [stdout, stderr, code] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);
      return { code, stdout, stderr, timedOut: false };
    };
  }

  for (const alias of ['inc2', 'x.internal', 'm2']) {
    test(`${alias} is not refused as UNKNOWN_ALIAS`, async () => {
      const result = await run(alias, 'echo hi', 10, {
        runner: realParseRunner(sshConfigPath),
        sshConfigPath,
      });
      expect(result.error?.code).not.toBe('UNKNOWN_ALIAS');
    });
  }

  test('a name no pattern can match is still UNKNOWN_ALIAS', async () => {
    const result = await run('totally-undeclared', 'echo hi', 10, {
      runner: realParseRunner(bareConfigPath),
      sshConfigPath: bareConfigPath,
    });
    expect(result.error?.code).toBe('UNKNOWN_ALIAS');
  });

  test('hosts list names the literal aliases of an Included file, never a wildcard', () => {
    expect(listHostAliases(sshConfigPath)).toEqual(['inc2']);
  });
});

describe('executeOp — an audit line that cannot be written keeps the op result', () => {
  test('scripted success + audit path under a regular file -> AUDIT_WRITE_FAILED envelope, data kept, no throw', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit-fail-'));
    const notADir = join(dir, 'state-file');
    writeFileSync(notADir, '');
    const op = getOp('services', 'restart');
    if (!op) {
      throw new Error('services restart op missing');
    }
    let calls = 0;
    const outcomes: SpawnOutcome[] = [
      { code: 0, stdout: 'hostname 10.0.0.9\n', stderr: '', timedOut: false },
      { code: 0, stdout: '', stderr: '', timedOut: false },
      { code: 0, stdout: 'web\n', stderr: '', timedOut: false },
    ];
    const scripted = scriptedRunner(outcomes);
    const runner: SshRunner = async (args, timeoutMs) => {
      calls += 1;
      return scripted(args, timeoutMs);
    };

    const envelope = await executeOp(
      op,
      { alias: 'web-01', args: { container: 'web' } },
      { transport: { runner }, yes: true, auditLogPath: join(notADir, 'audit.jsonl') },
    );

    expect(calls).toBe(3);
    expect(envelope.ok).toBe(false);
    expect(envelope.alias).toBe('web-01');
    expect(envelope.error?.code).toBe('AUDIT_WRITE_FAILED');
    expect(envelope.error?.op_outcome).toBe('ok');
    expect(envelope.error?.message).not.toContain(dir);
    expect(envelope.data).toEqual({ container: 'web', restarted: true });
  });
});

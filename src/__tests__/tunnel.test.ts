import { describe, expect, test } from 'bun:test';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OpRunLocalError } from '../types.ts';
import {
  buildSshArgs,
  closeTunnel,
  defaultTunnelStateDir,
  DEFAULT_DURATION_SEC,
  findFreePort,
  listTunnels,
  MAX_DURATION_SEC,
  MIN_DURATION_SEC,
  openTunnel,
  readTunnelRecordFile,
  resolveSelfInvocation,
  runSupervisor,
  tunnelRecordPath,
  validateOpenParams,
  writeTunnelRecord,
} from '../tunnel.ts';

function tempStateDir(): string {
  return mkdtempSync(join(tmpdir(), 'sshepherd-tunnel-test-'));
}

function withTempStateDir<T>(fn: () => T): T {
  const dir = tempStateDir();
  const original = process.env.SSHEPHERD_TUNNEL_STATE_DIR;
  process.env.SSHEPHERD_TUNNEL_STATE_DIR = dir;
  try {
    return fn();
  } finally {
    if (original === undefined) {
      delete process.env.SSHEPHERD_TUNNEL_STATE_DIR;
    } else {
      process.env.SSHEPHERD_TUNNEL_STATE_DIR = original;
    }
  }
}

function tempSshConfig(aliases: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-tunnel-sshconfig-'));
  const path = join(dir, 'config');
  const text = aliases.map((a) => `Host ${a}\n    HostName example.invalid\n    User test\n`).join('\n');
  writeFileSync(path, text);
  return path;
}

describe('defaultTunnelStateDir', () => {
  test('honors SSHEPHERD_TUNNEL_STATE_DIR override', () => {
    const original = process.env.SSHEPHERD_TUNNEL_STATE_DIR;
    process.env.SSHEPHERD_TUNNEL_STATE_DIR = '/tmp/example-override';
    expect(defaultTunnelStateDir()).toBe('/tmp/example-override');
    if (original === undefined) {
      delete process.env.SSHEPHERD_TUNNEL_STATE_DIR;
    } else {
      process.env.SSHEPHERD_TUNNEL_STATE_DIR = original;
    }
  });
});

describe('writeTunnelRecord / readTunnelRecordFile', () => {
  test('round-trips a record through disk with 0600 permissions', () => {
    const dir = tempStateDir();
    const record = {
      id: 't-test1',
      alias: 'example-alias',
      kind: 'local' as const,
      localPort: 54321,
      remoteTarget: 'localhost:5432',
      localTarget: null,
      pid: 999999,
      openedAt: '2026-07-20T10:00:00.000Z',
      expiresAt: '2026-07-20T11:00:00.000Z',
    };
    const path = join(dir, `${record.id}.json`);
    writeTunnelRecord(path, record);

    const mode = statSync(path).mode & 0o777;
    expect(mode).toBe(0o600);

    const roundTripped = readTunnelRecordFile(path);
    expect(roundTripped).toEqual(record);
  });

  test('readTunnelRecordFile returns null for a missing file', () => {
    const dir = tempStateDir();
    expect(readTunnelRecordFile(join(dir, 'does-not-exist.json'))).toBeNull();
  });

  test('readTunnelRecordFile returns null for malformed JSON', () => {
    const dir = tempStateDir();
    const path = join(dir, 'broken.json');
    writeFileSync(path, 'not json{{{');
    expect(readTunnelRecordFile(path)).toBeNull();
  });
});

describe('findFreePort', () => {
  test('returns a port that is immediately bindable again', async () => {
    const port = findFreePort();
    expect(port).toBeGreaterThan(0);
    expect(port).toBeLessThan(65536);

    // Prove it's actually free by binding a real listener on it.
    await new Promise<void>((resolve, reject) => {
      const server = createServer();
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => {
        server.close(() => resolve());
      });
    });
  });

  test('two consecutive calls return different ports', () => {
    const a = findFreePort();
    const b = findFreePort();
    expect(a).not.toBe(b);
  });
});

describe('validateOpenParams', () => {
  test('accepts a valid local-kind request', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'local', remote: 'localhost:5432', durationSec: 60 }),
    ).not.toThrow();
  });

  test('rejects an unknown kind', () => {
    expect(() =>
      // @ts-expect-error deliberately invalid kind for the test
      validateOpenParams({ alias: 'a', kind: 'bogus', durationSec: 60 }),
    ).toThrow(OpRunLocalError);
  });

  test('rejects local kind missing --remote', () => {
    expect(() => validateOpenParams({ alias: 'a', kind: 'local', durationSec: 60 })).toThrow(
      OpRunLocalError,
    );
  });

  test('rejects remote kind missing --local', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'remote', remote: '0.0.0.0:8080', durationSec: 60 }),
    ).toThrow(OpRunLocalError);
  });

  test('rejects dynamic kind carrying a --local flag', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'dynamic', local: 'localhost:3000', durationSec: 60 }),
    ).toThrow(OpRunLocalError);
  });

  test('rejects a duration outside [MIN, MAX]', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'dynamic', durationSec: MIN_DURATION_SEC - 1 }),
    ).toThrow(OpRunLocalError);
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'dynamic', durationSec: MAX_DURATION_SEC + 1 }),
    ).toThrow(OpRunLocalError);
  });
});

describe('buildSshArgs', () => {
  test('local kind', () => {
    expect(
      buildSshArgs({ alias: 'web-01', kind: 'local', remote: 'localhost:5432', durationSec: 60 }, 54321),
    ).toEqual(['-N', '-L', '54321:localhost:5432', 'web-01']);
  });

  test('dynamic kind', () => {
    expect(buildSshArgs({ alias: 'web-01', kind: 'dynamic', durationSec: 60 }, 1080)).toEqual([
      '-N',
      '-D',
      '1080',
      'web-01',
    ]);
  });

  test('remote kind', () => {
    expect(
      buildSshArgs(
        { alias: 'web-01', kind: 'remote', remote: '0.0.0.0:8080', local: 'localhost:3000', durationSec: 60 },
        null,
      ),
    ).toEqual(['-N', '-R', '0.0.0.0:8080:localhost:3000', 'web-01']);
  });
});

describe('resolveSelfInvocation', () => {
  test('dev mode (argv[1] ends with cli.ts) re-invokes bun + the script path', () => {
    const original = process.argv;
    const bunPath = original[0] ?? 'bun';
    process.argv = [bunPath, '/repo/src/cli.ts', 'tunnel', 'open'];
    try {
      expect(resolveSelfInvocation()).toEqual([bunPath, '/repo/src/cli.ts']);
    } finally {
      process.argv = original;
    }
  });

  test('compiled-binary mode (argv[1] does not end with cli.ts) re-invokes execPath alone', () => {
    const original = process.argv;
    process.argv = ['/usr/local/bin/sshepherd', 'tunnel', 'open'];
    try {
      expect(resolveSelfInvocation()).toEqual([process.execPath]);
    } finally {
      process.argv = original;
    }
  });
});

describe('runSupervisor', () => {
  test('spawns the given command, kills it once durationSec elapses, and resolves', async () => {
    // Use a real, harmless long-running command (`sleep 5`) standing in for `ssh -N ...` — the
    // supervisor doesn't know or care what it's supervising, only that it must die on schedule.
    const start = Date.now();
    const exitCode = await runSupervisor({
      command: 'sleep',
      args: ['5'],
      durationSec: 1,
    });
    const elapsedMs = Date.now() - start;
    // Killed by the 1s timer, long before `sleep 5` would exit on its own.
    expect(elapsedMs).toBeLessThan(4000);
    expect(exitCode).not.toBe(0);
  });

  test('resolves with the real exit code when the command finishes before the deadline', async () => {
    const exitCode = await runSupervisor({ command: 'true', args: [], durationSec: 10 });
    expect(exitCode).toBe(0);
  });
});

describe('openTunnel', () => {
  test('local kind: assigns a port, spawns via the injected fn, writes a state record', () => {
    withTempStateDir(() => {
      const sshConfigPath = tempSshConfig(['web-01']);
      const record = openTunnel(
        { alias: 'web-01', kind: 'local', remote: 'localhost:5432', durationSec: 120 },
        sshConfigPath,
        { spawnSupervisor: () => ({ pid: 424242 }) },
      );

      expect(record.alias).toBe('web-01');
      expect(record.kind).toBe('local');
      expect(record.localPort).toBeGreaterThan(0);
      expect(record.remoteTarget).toBe('localhost:5432');
      expect(record.localTarget).toBeNull();
      expect(record.pid).toBe(424242);

      const onDisk = readTunnelRecordFile(tunnelRecordPath(defaultTunnelStateDir(), record.id));
      expect(onDisk).toEqual(record);
    });
  });

  test('remote kind: no localPort assigned, records localTarget', () => {
    withTempStateDir(() => {
      const sshConfigPath = tempSshConfig(['web-01']);
      const record = openTunnel(
        { alias: 'web-01', kind: 'remote', remote: '0.0.0.0:8080', local: 'localhost:3000', durationSec: 120 },
        sshConfigPath,
        { spawnSupervisor: () => ({ pid: 424242 }) },
      );
      expect(record.localPort).toBeNull();
      expect(record.remoteTarget).toBe('0.0.0.0:8080');
      expect(record.localTarget).toBe('localhost:3000');
    });
  });

  test('propagates validation errors before ever calling spawnSupervisor', () => {
    withTempStateDir(() => {
      const sshConfigPath = tempSshConfig(['web-01']);
      let spawnCalled = false;
      expect(() =>
        openTunnel(
          { alias: 'web-01', kind: 'local', durationSec: 120 },
          sshConfigPath,
          {
            spawnSupervisor: () => {
              spawnCalled = true;
              return { pid: 1 };
            },
          },
        ),
      ).toThrow(OpRunLocalError);
      expect(spawnCalled).toBe(false);
    });
  });

  test('rejects an alias that is not declared in the ssh config, before spawning', () => {
    withTempStateDir(() => {
      const sshConfigPath = tempSshConfig(['web-01']); // 'evil-alias' is NOT declared
      let spawnCalled = false;
      let caught: unknown;
      try {
        openTunnel(
          { alias: '-oProxyCommand=touch /tmp/pwned', kind: 'dynamic', durationSec: 120 },
          sshConfigPath,
          {
            spawnSupervisor: () => {
              spawnCalled = true;
              return { pid: 1 };
            },
          },
        );
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(OpRunLocalError);
      expect((caught as InstanceType<typeof OpRunLocalError>).code).toBe('UNKNOWN_ALIAS');
      expect(spawnCalled).toBe(false);
    });
  });
});

describe('listTunnels / closeTunnel', () => {
  // A real detached process, its own group leader — stands in for a real supervisor PID without
  // actually re-invoking the sshepherd binary. The subprocess handle is returned (not just the
  // pid) so a test can `await proc.exited` and REAP it: an unreaped Bun child stays a zombie in
  // the runner's process table, and `process.kill(pid, 0)` on a zombie still reports it "alive",
  // which would mask a genuine kill. In production the supervisor is reaped by init, so a
  // separate list/close process sees true liveness — awaiting here reproduces that.
  function spawnRealGroupLeader(): Bun.Subprocess {
    const proc = Bun.spawn(['sleep', '30'], { stdio: ['ignore', 'ignore', 'ignore'], detached: true });
    proc.unref();
    return proc;
  }

  test('listTunnels returns an active, non-expired record with remainingSec', () => {
    withTempStateDir(() => {
      const proc = spawnRealGroupLeader();
      const sshConfigPath = tempSshConfig(['web-01']);
      const record = openTunnel(
        { alias: 'web-01', kind: 'dynamic', durationSec: 120 },
        sshConfigPath,
        { spawnSupervisor: () => ({ pid: proc.pid }) },
      );

      const active = listTunnels();
      expect(active).toHaveLength(1);
      expect(active[0]?.id).toBe(record.id);
      expect(active[0]?.remainingSec).toBeGreaterThan(0);
      expect(active[0]?.remainingSec).toBeLessThanOrEqual(120);

      closeTunnel(record.id); // cleanup: kill the real sleep process
    });
  });

  test('listTunnels prunes a record whose PID is dead', () => {
    withTempStateDir(() => {
      // `spawnSync` runs `true` to completion AND reaps it before returning, so its pid is a
      // genuinely dead (non-zombie) pid the moment we read it — no retry/poll needed.
      const deadPid = Bun.spawnSync(['true'], { stdio: ['ignore', 'ignore', 'ignore'] }).pid;
      const sshConfigPath = tempSshConfig(['web-01']);
      const record = openTunnel(
        { alias: 'web-01', kind: 'dynamic', durationSec: 120 },
        sshConfigPath,
        { spawnSupervisor: () => ({ pid: deadPid }) },
      );

      const path = tunnelRecordPath(defaultTunnelStateDir(), record.id);
      const active = listTunnels();
      expect(active).toHaveLength(0);
      expect(readTunnelRecordFile(path)).toBeNull();
    });
  });

  test('closeTunnel kills a real process group and removes the state file', async () => {
    const proc = spawnRealGroupLeader();
    const record = withTempStateDir(() => {
      const sshConfigPath = tempSshConfig(['web-01']);
      const rec = openTunnel(
        { alias: 'web-01', kind: 'dynamic', durationSec: 120 },
        sshConfigPath,
        { spawnSupervisor: () => ({ pid: proc.pid }) },
      );

      const result = closeTunnel(rec.id);
      expect(result).toEqual({ id: rec.id, closed: true });
      expect(readTunnelRecordFile(tunnelRecordPath(defaultTunnelStateDir(), rec.id))).toBeNull();
      return rec;
    });

    // Reap the SIGKILL'd group leader, then confirm it is genuinely gone — not a zombie the
    // kill(0) check would misread as still alive.
    await proc.exited;
    expect(() => process.kill(proc.pid, 0)).toThrow();
  });

  test('closeTunnel on an unknown id is idempotent (closed: false, no throw)', () => {
    withTempStateDir(() => {
      expect(closeTunnel('t-does-not-exist')).toEqual({ id: 't-does-not-exist', closed: false });
    });
  });
});

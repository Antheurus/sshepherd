import { describe, expect, test } from 'bun:test';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OpRunLocalError } from '../types.ts';
import {
  buildSshArgs,
  defaultTunnelStateDir,
  DEFAULT_DURATION_SEC,
  findFreePort,
  MAX_DURATION_SEC,
  MIN_DURATION_SEC,
  readTunnelRecordFile,
  resolveSelfInvocation,
  runSupervisor,
  validateOpenParams,
  writeTunnelRecord,
} from '../tunnel.ts';

function tempStateDir(): string {
  return mkdtempSync(join(tmpdir(), 'sshepherd-tunnel-test-'));
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

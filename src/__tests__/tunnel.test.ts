import { describe, expect, test } from 'bun:test';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defaultTunnelStateDir, findFreePort, readTunnelRecordFile, writeTunnelRecord } from '../tunnel.ts';

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

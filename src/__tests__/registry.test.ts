import { describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp, listOps } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';

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

/** Every read-only op's happy path: -G validate, -O check (master already up), actual run. */
function connectedRunOutcomes(stdout: string): SpawnOutcome[] {
  return [
    { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
    { code: 0, stdout: '', stderr: '', timedOut: false },
    { code: 0, stdout, stderr: '', timedOut: false },
  ];
}

describe('registry — getOp/listOps', () => {
  test('every read-only op declared in the phase brief is registered', () => {
    const expected: Array<[string, string]> = [
      ['hosts', 'list'],
      ['hosts', 'test'],
      ['hosts', 'info'],
      ['check', 'overview'],
      ['check', 'mem'],
      ['check', 'disk'],
      ['check', 'cpu'],
      ['check', 'ports'],
      ['check', 'oom-history'],
      ['check', 'kernel'],
      ['logs', 'docker'],
      ['logs', 'service'],
      ['logs', 'nginx'],
      ['logs', 'docker-daemon'],
      ['services', 'ps'],
      ['services', 'stats'],
      ['services', 'inspect'],
      ['services', 'compose-ps'],
      ['services', 'healthcheck'],
      ['services', 'systemctl-status'],
      ['files', 'ls'],
      ['files', 'cat'],
      ['files', 'tail'],
      ['files', 'download'],
      ['files', 'disk-usage'],
    ];
    for (const [group, name] of expected) {
      expect(getOp(group, name)).toBeDefined();
    }
    expect(listOps()).toHaveLength(expected.length);
    expect(listOps().every((op) => op.mutating === false)).toBe(true);
  });
});

describe('hosts list — hygiene', () => {
  function writeFixtureConfig(): string {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-test-'));
    const configPath = join(dir, 'config');
    writeFileSync(
      configPath,
      [
        'Host lms-server',
        '    HostName 10.0.0.9',
        '    User deploy',
        '    Port 2222',
        '',
        'Host staging web-1 web-2',
        '    HostName 10.0.0.10',
        '',
        'Host *',
        '    ServerAliveInterval 30',
        '',
      ].join('\n'),
    );
    return configPath;
  }

  test('returns alias names only — never HostName/User/Port, and skips the wildcard stanza', async () => {
    const op = getOp('hosts', 'list');
    if (!op) {
      throw new Error('hosts list op missing');
    }
    const sshConfigPath = writeFixtureConfig();

    const envelope = await executeOp(op, { alias: '', args: {} }, { sshConfigPath });

    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({ aliases: ['lms-server', 'staging', 'web-1', 'web-2'] });

    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain('10.0.0.9');
    expect(serialized).not.toContain('10.0.0.10');
    expect(serialized).not.toContain('deploy');
    expect(serialized).not.toContain('2222');
    expect(serialized).not.toContain('*');
  });
});

describe('check overview — dead_end_risk verdict', () => {
  test('true when disk use exceeds 90%', async () => {
    const op = getOp('check', 'overview');
    if (!op) {
      throw new Error('check overview op missing');
    }
    const stdout = [
      '__NPROC__',
      '4',
      '__FREE__',
      '              total        used        free      shared  buff/cache   available',
      'Mem:     8589934592  1234567890  3456789012   12345678   3987654321   6789012345',
      'Swap:    2147483648           0  2147483648',
      '__DF__',
      'Filesystem     1B-blocks       Used   Available Capacity Mounted on',
      '/dev/sda1    21467271168 20500000000   967271168       95% /',
      '__UPTIME__',
      '14:32:05 up 10 days,  3:14,  2 users,  load average: 0.15, 0.22, 0.18',
      '__PSI__',
      'some avg10=0.00 avg60=0.00 avg300=0.00 total=0',
      'full avg10=0.00 avg60=0.00 avg300=0.00 total=0',
    ].join('\n');

    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(true);
    const data = envelope.data as { dead_end_risk: boolean; disk: Array<{ use_percent: number }> };
    expect(data.disk[0]?.use_percent).toBe(95);
    expect(data.dead_end_risk).toBe(true);
  });

  test('false when disk and memory pressure are both within bounds', async () => {
    const op = getOp('check', 'overview');
    if (!op) {
      throw new Error('check overview op missing');
    }
    const stdout = [
      '__NPROC__',
      '4',
      '__FREE__',
      '              total        used        free      shared  buff/cache   available',
      'Mem:     8589934592  1234567890  3456789012   12345678   3987654321   6789012345',
      'Swap:    2147483648           0  2147483648',
      '__DF__',
      'Filesystem     1B-blocks       Used   Available Capacity Mounted on',
      '/dev/sda1    21467271168 8589934592 11824550912       43% /',
      '__UPTIME__',
      '14:32:05 up 10 days,  3:14,  2 users,  load average: 0.15, 0.22, 0.18',
      '__PSI__',
      'some avg10=0.00 avg60=0.00 avg300=0.00 total=0',
      'full avg10=0.00 avg60=0.00 avg300=0.00 total=0',
    ].join('\n');

    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    const data = envelope.data as { dead_end_risk: boolean };
    expect(data.dead_end_risk).toBe(false);
  });
});

describe('services ps — merges docker inspect data into each entry', () => {
  test('surfaces health/restarts/oom_killed/limits per container', async () => {
    const op = getOp('services', 'ps');
    if (!op) {
      throw new Error('services ps op missing');
    }
    const inspectJson = JSON.stringify([
      {
        Id: 'abc123def4560000000000000000000000000000000000000000000000000',
        Name: '/lms-app',
        Config: {
          Image: 'lms-app:latest',
          Labels: { 'com.docker.compose.project': 'lms', 'com.docker.compose.service': 'app' },
        },
        State: {
          Status: 'running',
          OOMKilled: true,
          ExitCode: 137,
          Health: { Status: 'unhealthy' },
        },
        RestartCount: 3,
        HostConfig: {
          Memory: 536870912,
          NanoCpus: 500000000,
          OomScoreAdj: 500,
          RestartPolicy: { Name: 'on-failure' },
        },
        NetworkSettings: { Ports: { '80/tcp': [{ HostIp: '0.0.0.0', HostPort: '8080' }] } },
      },
    ]);

    const runner = scriptedRunner(connectedRunOutcomes(inspectJson));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(true);
    const entries = envelope.data as Array<Record<string, unknown>>;
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      name: 'lms-app',
      image: 'lms-app:latest',
      state: 'running',
      health: 'unhealthy',
      restart_count: 3,
      oom_killed: true,
      exit_code: 137,
      mem_limit_bytes: 536870912,
      nano_cpus: 500000000,
      oom_score_adj: 500,
      restart_policy: 'on-failure',
      compose_project: 'lms',
      compose_service: 'app',
    });
    expect(entries[0]?.ports).toEqual([
      { host_ip: '0.0.0.0', host_port: 8080, container_port: 80, proto: 'tcp' },
    ]);
  });

  test('a missing docker binary surfaces as a clean COMMAND_FAILED, not a crash or an empty list', async () => {
    const op = getOp('services', 'ps');
    if (!op) {
      throw new Error('services ps op missing');
    }
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check (master already up)
      { code: 127, stdout: '', stderr: '', timedOut: false }, // `command -v docker` guard fails
    ]);

    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(false);
    expect(envelope.data).toBeNull();
    expect(envelope.error).toEqual({
      code: 'COMMAND_FAILED',
      message: 'Remote command exited with a non-zero status',
      remote_exit: 127,
    });
  });
});

describe('logs docker — line objects + next_since', () => {
  test('shapes {ts, stream, text} lines and carries next_since from the last line', async () => {
    const op = getOp('logs', 'docker');
    if (!op) {
      throw new Error('logs docker op missing');
    }
    const stdout = [
      '2026-07-12T10:00:00.100000000Z booting app',
      '2026-07-12T10:00:01.200000000Z listening on :3000',
    ].join('\n');

    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { container: 'lms-app' } },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(true);
    const data = envelope.data as {
      source: string;
      lines_returned: number;
      truncated: boolean;
      lines: Array<{ ts: string; stream: string; text: string }>;
      next_since: string | null;
    };
    expect(data.source).toBe('docker:lms-app');
    expect(data.lines_returned).toBe(2);
    expect(data.truncated).toBe(false);
    expect(data.lines[0]).toEqual({
      ts: '2026-07-12T10:00:00.100000000Z',
      stream: 'stdout',
      text: 'booting app',
    });
    expect(data.next_since).toBe('2026-07-12T10:00:01.200000000Z');
  });
});

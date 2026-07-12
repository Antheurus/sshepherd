import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp, listOps } from '../registry.ts';
import { buildDbOpContext } from '../targets.ts';
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
  test('every read-only op declared in the phase brief is registered (Phases 3-4)', () => {
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
      ['db', 'list'],
      ['db', 'tables'],
      ['db', 'activity'],
      ['db', 'connections'],
      ['db', 'slow'],
      ['db', 'size'],
      ['db', 'query'],
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

/**
 * Real drive, not a string-shape guess: `remoteCmd` is exactly the string ssh hands to the
 * remote login shell to parse (ssh concatenates argv with spaces and the remote shell
 * parses it once), so feeding it to a real local `sh -c` reproduces that exact parse. The
 * injection payload always ends in `touch <marker>` (never `rm`/anything destructive) so
 * that even a genuine quoting failure only creates a harmless temp file instead of doing
 * real damage — a missing `docker`/other binary along the way is expected and ignored.
 */
function freshMarkerPath(): string {
  return join(tmpdir(), `sshepherd-audit-pwn-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

function assertShellParsesRemoteCmdSafely(remoteCmd: string, marker: string): void {
  Bun.spawnSync(['sh', '-c', remoteCmd], { stdout: 'ignore', stderr: 'ignore' });
  expect(existsSync(marker)).toBe(false);
}

describe('quoting — adversarial args never break out of their remote-command argument boundary', () => {
  test('logs docker: a container name shaped like a shell injection cannot splice in a second command', () => {
    const op = getOp('logs', 'docker');
    if (!op) {
      throw new Error('logs docker op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `innocent'; touch ${marker}; echo '`;
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { container: malicious } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    assertShellParsesRemoteCmdSafely(remoteCmd, marker);
  });

  test('files cat: a path shaped like a shell injection is neutralized when actually parsed by a shell', () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `/tmp/foo\`touch ${marker}\`; touch ${marker}`;
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { path: malicious } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    const result = Bun.spawnSync(['sh', '-c', remoteCmd]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString().trim()).toBe('__NOT_FOUND__');
    expect(existsSync(marker)).toBe(false);
  });

  test('services inspect: a container arg with embedded single quotes cannot escape its argument', () => {
    const op = getOp('services', 'inspect');
    if (!op) {
      throw new Error('services inspect op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `web' 'evil'; touch ${marker}; echo '`;
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { container: malicious } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    assertShellParsesRemoteCmdSafely(remoteCmd, marker);
  });
});

describe('files cat — env file masking', () => {
  const ENV_CONTENT = [
    'NODE_ENV=production',
    'DB_PASSWORD=s3cr3t-value',
    'API_KEY=abcd1234',
    '',
  ].join('\n');

  test('a .env path is masked by default — secret values never reach the envelope', async () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const runner = scriptedRunner(connectedRunOutcomes(ENV_CONTENT));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { path: '/srv/app/.env' } },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(true);
    const data = envelope.data as { masked: boolean; content: string | null };
    expect(data.masked).toBe(true);
    expect(data.content).toContain('DB_PASSWORD=***MASKED***');
    expect(data.content).toContain('API_KEY=***MASKED***');
    expect(data.content).toContain('NODE_ENV=***MASKED***');
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain('s3cr3t-value');
    expect(serialized).not.toContain('abcd1234');
  });

  test('an explicit --reveal key unmasks only that key, others stay masked', async () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const runner = scriptedRunner(connectedRunOutcomes(ENV_CONTENT));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { path: '/srv/app/.env', reveal: 'DB_PASSWORD' } },
      { transport: { runner } },
    );

    const data = envelope.data as { masked: boolean; content: string | null };
    expect(data.masked).toBe(true);
    expect(data.content).toContain('DB_PASSWORD=s3cr3t-value');
    expect(data.content).toContain('API_KEY=***MASKED***');
  });

  test('a non-.env path is never masked', async () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const runner = scriptedRunner(connectedRunOutcomes('plain config content\n'));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { path: '/srv/app/config.yml' } },
      { transport: { runner } },
    );

    const data = envelope.data as { masked: boolean; content: string | null };
    expect(data.masked).toBe(false);
    expect(data.content).toBe('plain config content\n');
  });
});

describe('executeOp — zero-knowledge error path never leaks transport stderr', () => {
  test('a COMMAND_FAILED error carries only the static ErrorInfo shape, never raw stderr text', async () => {
    const op = getOp('check', 'ports');
    if (!op) {
      throw new Error('check ports op missing');
    }
    const secretStderr =
      'ssh: connect to host 10.55.66.77 port 22: Connection refused (user deploy)';
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check
      { code: 1, stdout: '', stderr: secretStderr, timedOut: false }, // remote command fails
    ]);

    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(false);
    expect(envelope.data).toBeNull();
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain('10.55.66.77');
    expect(serialized).not.toContain('deploy');
    expect(serialized).not.toContain('Connection refused');
  });
});

describe('db group — layered read-only enforcement', () => {
  function writeFixtureTargets(): string {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-db-registry-test-'));
    const path = join(dir, 'targets.toml');
    writeFileSync(
      path,
      [
        '[prod]',
        'alias = "lms-server"',
        'container = "lms_postgres_1"',
        'user = "sshepherd_ro"',
        'database = "lms"',
        '',
      ].join('\n'),
    );
    return path;
  }

  test('db query rejects a non-SELECT statement at the parser layer with a clear error', () => {
    const op = getOp('db', 'query');
    if (!op) {
      throw new Error('db query op missing');
    }
    const ctx = buildDbOpContext('prod', { sql: 'DELETE FROM users' }, writeFixtureTargets());
    expect(() => op.buildRemote(ctx)).toThrow(/refusing statement type 'delete'/);
  });

  test('a writable-CTE attempt passes the parser (documents the txn-readonly wrapper as the real gate) and fails engine-side', async () => {
    const op = getOp('db', 'query');
    if (!op) {
      throw new Error('db query op missing');
    }
    const ctx = buildDbOpContext(
      'prod',
      { sql: "WITH x AS (INSERT INTO users (name) VALUES ('x') RETURNING *) SELECT * FROM x" },
      writeFixtureTargets(),
    );
    // The parser layer must not throw — a writable CTE parses as `select`.
    expect(() => op.buildRemote(ctx)).not.toThrow();

    // Simulate the engine actually rejecting the write inside the read-only transaction
    // (`ON_ERROR_STOP=1` aborts the whole -c buffer, psql exits non-zero).
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
      { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check
      {
        code: 3,
        stdout: '',
        stderr: 'ERROR:  cannot execute INSERT in a read-only transaction',
        timedOut: false,
      },
    ]);
    const envelope = await executeOp(op, ctx, { transport: { runner } });
    expect(envelope.ok).toBe(false);
    expect(envelope.error).toEqual({
      code: 'COMMAND_FAILED',
      message: 'Remote command exited with a non-zero status',
      remote_exit: 3,
    });
  });

  test('db activity returns numeric query_seconds/blocked_by and backends_total vs max_connections rollups', async () => {
    const op = getOp('db', 'activity');
    if (!op) {
      throw new Error('db activity op missing');
    }
    const stdout = JSON.stringify({
      backends_total: 3,
      max_connections: 100,
      backends: [
        {
          pid: 42,
          usename: 'sshepherd_ro',
          application_name: 'psql',
          state: 'active',
          query_start: '2026-07-12T10:00:00.000Z',
          query_seconds: 12.5,
          wait_event: null,
          blocked_by: [17],
        },
      ],
    });
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const ctx = buildDbOpContext('prod', {}, writeFixtureTargets());
    const envelope = await executeOp(op, ctx, { transport: { runner } });

    expect(envelope.ok).toBe(true);
    const data = envelope.data as {
      backends_total: number;
      max_connections: number;
      backends: Array<{ query_seconds: number; blocked_by: number[] }>;
    };
    expect(data.backends_total).toBe(3);
    expect(data.max_connections).toBe(100);
    expect(typeof data.backends[0]?.query_seconds).toBe('number');
    expect(data.backends[0]?.query_seconds).toBe(12.5);
    expect(data.backends[0]?.blocked_by).toEqual([17]);
  });

  test('db slow degrades gracefully when pg_stat_statements is absent (no error thrown)', async () => {
    const op = getOp('db', 'slow');
    if (!op) {
      throw new Error('db slow op missing');
    }
    const stdout = '{"available":false,"reason":"pg_stat_statements not installed"}';
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const ctx = buildDbOpContext('prod', {}, writeFixtureTargets());
    const envelope = await executeOp(op, ctx, { transport: { runner } });

    expect(envelope.ok).toBe(true);
    expect(envelope.error).toBeNull();
    const data = envelope.data as { available: boolean; reason: string | null; queries: unknown[] };
    expect(data.available).toBe(false);
    expect(data.reason).toBe('pg_stat_statements not installed');
    expect(data.queries).toEqual([]);
  });

  test('db slow returns queries when pg_stat_statements is present', async () => {
    const op = getOp('db', 'slow');
    if (!op) {
      throw new Error('db slow op missing');
    }
    const stdout = JSON.stringify({
      available: true,
      queries: [
        {
          query: 'SELECT * FROM users WHERE id = $1',
          calls: 120,
          total_exec_time: 45.2,
          mean_exec_time: 0.377,
          rows: 120,
        },
      ],
    });
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const ctx = buildDbOpContext('prod', {}, writeFixtureTargets());
    const envelope = await executeOp(op, ctx, { transport: { runner } });

    expect(envelope.ok).toBe(true);
    const data = envelope.data as {
      available: boolean;
      queries: Array<{ mean_exec_time: number }>;
    };
    expect(data.available).toBe(true);
    expect(data.queries).toHaveLength(1);
    expect(data.queries[0]?.mean_exec_time).toBe(0.377);
  });

  test('db list reads targets.toml locally — never opens ssh', async () => {
    const op = getOp('db', 'list');
    if (!op) {
      throw new Error('db list op missing');
    }
    const path = writeFixtureTargets();
    const originalEnv = process.env.SSHEPHERD_TARGETS_PATH;
    process.env.SSHEPHERD_TARGETS_PATH = path;
    try {
      const envelope = await executeOp(op, { alias: '', args: {} }, {});
      expect(envelope.ok).toBe(true);
      expect(envelope.data).toEqual({ targets: ['prod'] });
    } finally {
      if (originalEnv === undefined) {
        delete process.env.SSHEPHERD_TARGETS_PATH;
      } else {
        process.env.SSHEPHERD_TARGETS_PATH = originalEnv;
      }
    }
  });
});

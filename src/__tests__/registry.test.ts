import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { STEP_FAILURE_MARKER } from '../recipes.ts';
import { enforceAllowlist, executeOp, getOp, listOps } from '../registry.ts';
import { buildDbOpContext } from '../targets.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import { type OpSpec, OpRunLocalError } from '../types.ts';

const DEMO_RECIPE_PATH = join(import.meta.dir, 'fixtures', 'deploy.demo.toml');
const NO_ROLLBACK_RECIPE_PATH = join(import.meta.dir, 'fixtures', 'deploy.no-rollback.toml');

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
  const READ_ONLY: Array<[string, string]> = [
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
    ['config', 'get'],
    ['config', 'validate'],
    ['db', 'list'],
    ['db', 'tables'],
    ['db', 'activity'],
    ['db', 'connections'],
    ['db', 'slow'],
    ['db', 'size'],
    ['db', 'query'],
    ['deploy', 'status'],
    ['deploy', 'logs'],
    ['security', 'ssh-audit'],
    ['security', 'listeners'],
    ['security', 'authorized-keys'],
    ['security', 'fail2ban'],
  ];

  const MUTATING: Array<[string, string]> = [
    ['services', 'restart'],
    ['services', 'systemctl-start'],
    ['services', 'systemctl-stop'],
    ['services', 'systemctl-restart'],
    ['services', 'systemctl-reload'],
    ['config', 'put'],
    ['config', 'reload'],
    ['deploy', 'run'],
    ['deploy', 'rollback'],
    ['deploy', 'migrate'],
    ['security', 'harden'],
    ['files', 'upload'],
  ];

  test('every read-only op declared through Phases 3-5 is registered and flagged mutating:false', () => {
    for (const [group, name] of READ_ONLY) {
      const op = getOp(group, name);
      expect(op).toBeDefined();
      expect(op?.mutating).toBe(false);
    }
  });

  test('every mutating op declared in Phase 5 is registered and flagged mutating:true', () => {
    for (const [group, name] of MUTATING) {
      const op = getOp(group, name);
      expect(op).toBeDefined();
      expect(op?.mutating).toBe(true);
    }
  });

  test('listOps returns exactly the read-only + mutating sets, no extras and no drops', () => {
    expect(listOps()).toHaveLength(READ_ONLY.length + MUTATING.length);
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
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-cat-mask-test-'));
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/srv/app/.env"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
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
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });

  test('an explicit --reveal key unmasks only that key, others stay masked', async () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-cat-reveal-test-'));
    const filesAllowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(filesAllowlistPath, '[lms-server]\npaths = ["/srv/app/.env"]\n');
    const revealAllowlistPath = join(dir, 'reveal-allowlist.toml');
    writeFileSync(revealAllowlistPath, '[lms-server]\nkeys = ["NODE_ENV"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = filesAllowlistPath;
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = revealAllowlistPath;
    try {
      const runner = scriptedRunner(connectedRunOutcomes(ENV_CONTENT));
      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { path: '/srv/app/.env', reveal: 'NODE_ENV' } },
        { transport: { runner } },
      );

      const data = envelope.data as { masked: boolean; content: string | null };
      expect(data.masked).toBe(true);
      expect(data.content).toContain('NODE_ENV=production');
      expect(data.content).toContain('DB_PASSWORD=***MASKED***');
      expect(data.content).toContain('API_KEY=***MASKED***');
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
      delete process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
    }
  });

  test('a --reveal key matching the hardcoded secret-pattern denylist is refused even if allowlisted', async () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-cat-reveal-denylist-test-'));
    const filesAllowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(filesAllowlistPath, '[lms-server]\npaths = ["/srv/app/.env"]\n');
    const revealAllowlistPath = join(dir, 'reveal-allowlist.toml');
    // Mistakenly allowlisted anyway — the hardcoded denylist must still win.
    writeFileSync(revealAllowlistPath, '[lms-server]\nkeys = ["DB_PASSWORD"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = filesAllowlistPath;
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = revealAllowlistPath;
    try {
      const runner = scriptedRunner(connectedRunOutcomes(ENV_CONTENT));
      await expect(
        executeOp(
          op,
          { alias: 'lms-server', args: { path: '/srv/app/.env', reveal: 'DB_PASSWORD' } },
          { transport: { runner } },
        ),
      ).rejects.toThrow(/hard-denied secret pattern/);
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
      delete process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
    }
  });

  test('a non-.env path is never masked', async () => {
    const op = getOp('files', 'cat');
    if (!op) {
      throw new Error('files cat op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-cat-plain-test-'));
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/srv/app/config.yml"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
      const runner = scriptedRunner(connectedRunOutcomes('plain config content\n'));
      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { path: '/srv/app/config.yml' } },
        { transport: { runner } },
      );

      const data = envelope.data as { masked: boolean; content: string | null };
      expect(data.masked).toBe(false);
      expect(data.content).toBe('plain config content\n');
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
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

  function writeSensitiveFixtureTargets(): string {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-db-zk-test-'));
    const path = join(dir, 'targets.toml');
    writeFileSync(
      path,
      [
        '[prod]',
        'alias = "lms-server"',
        'compose_file = "/opt/super-secret-path/docker-compose.yml"',
        'service = "secret-db-service"',
        'user = "sshepherd_ro_SECRET_USER"',
        'database = "SECRET_DATABASE_NAME"',
        '',
      ].join('\n'),
    );
    return path;
  }

  test('db op envelope never leaks compose_file/service/db_user/db_name — success path', async () => {
    const op = getOp('db', 'activity');
    if (!op) {
      throw new Error('db activity op missing');
    }
    const ctx = buildDbOpContext('prod', {}, writeSensitiveFixtureTargets());
    const stdout = JSON.stringify({ backends_total: 1, max_connections: 100, backends: [] });
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(op, ctx, { transport: { runner } });

    expect(envelope.ok).toBe(true);
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain('super-secret-path');
    expect(serialized).not.toContain('secret-db-service');
    expect(serialized).not.toContain('SECRET_USER');
    expect(serialized).not.toContain('SECRET_DATABASE_NAME');
    // The alias IS allowed — it's the one identity field the envelope carries.
    expect(envelope.alias).toBe('lms-server');
  });

  test('db op envelope never leaks compose_file/service/db_user/db_name — error path (psql failure)', async () => {
    const op = getOp('db', 'tables');
    if (!op) {
      throw new Error('db tables op missing');
    }
    const ctx = buildDbOpContext('prod', {}, writeSensitiveFixtureTargets());
    // Simulate psql actually failing with an error message that WOULD contain the
    // real user/database name (e.g. `FATAL: role "sshepherd_ro_SECRET_USER" does not
    // exist`) — this must never reach the envelope, only the classified code + a
    // static message + the numeric exit code.
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
      { code: 0, stdout: '', stderr: '', timedOut: false },
      {
        code: 2,
        stdout: '',
        stderr:
          'FATAL:  role "sshepherd_ro_SECRET_USER" does not exist on database SECRET_DATABASE_NAME',
        timedOut: false,
      },
    ]);
    const envelope = await executeOp(op, ctx, { transport: { runner } });

    expect(envelope.ok).toBe(false);
    expect(envelope.error).toEqual({
      code: 'COMMAND_FAILED',
      message: 'Remote command exited with a non-zero status',
      remote_exit: 2,
    });
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain('SECRET_USER');
    expect(serialized).not.toContain('SECRET_DATABASE_NAME');
    expect(serialized).not.toContain('does not exist');
  });
});

function tempAuditLogPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-audit-registry-test-'));
  return join(dir, 'audit.jsonl');
}

function readAuditLines(path: string): Array<Record<string, unknown>> {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, 'utf8')
    .trim()
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('executeOp — mutating gate: the ONE path every mutating op goes through (confirm + audit)', () => {
  test('a mutating op without --yes is refused, never touches ssh, and writes a refused audit line', async () => {
    const op = getOp('services', 'restart');
    if (!op) {
      throw new Error('services restart op missing');
    }
    const auditLogPath = tempAuditLogPath();
    const runner: SshRunner = async () => {
      throw new Error('ssh must never be called for a refused mutating op');
    };
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { container: 'web' } },
      { transport: { runner }, auditLogPath },
    );

    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(envelope.data).toBeNull();

    const lines = readAuditLines(auditLogPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.outcome).toBe('refused');
    expect(lines[0]?.command).toBe('services restart');
    expect(lines[0]?.alias).toBe('lms-server');
  });

  test('a mutating op with --yes proceeds and writes an ok audit line on success', async () => {
    const op = getOp('services', 'restart');
    if (!op) {
      throw new Error('services restart op missing');
    }
    const auditLogPath = tempAuditLogPath();
    const runner = scriptedRunner(connectedRunOutcomes(''));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { container: 'web' } },
      { transport: { runner }, yes: true, auditLogPath },
    );

    expect(envelope.ok).toBe(true);
    const data = envelope.data as { container: string; restarted: boolean };
    expect(data.restarted).toBe(true);

    const lines = readAuditLines(auditLogPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.outcome).toBe('ok');
  });

  test('a mutating op with --yes that fails remotely still writes an error audit line', async () => {
    const op = getOp('services', 'restart');
    if (!op) {
      throw new Error('services restart op missing');
    }
    const auditLogPath = tempAuditLogPath();
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
      { code: 0, stdout: '', stderr: '', timedOut: false },
      { code: 1, stdout: '', stderr: 'no such container', timedOut: false },
    ]);
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { container: 'ghost' } },
      { transport: { runner }, yes: true, auditLogPath },
    );

    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('COMMAND_FAILED');

    const lines = readAuditLines(auditLogPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.outcome).toBe('error');
  });

  test('a non-mutating op never requires --yes and never writes an audit line', async () => {
    const op = getOp('services', 'ps');
    if (!op) {
      throw new Error('services ps op missing');
    }
    const auditLogPath = tempAuditLogPath();
    const runner = scriptedRunner(connectedRunOutcomes('[]'));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner }, auditLogPath },
    );

    expect(envelope.ok).toBe(true);
    expect(readAuditLines(auditLogPath)).toHaveLength(0);
  });

  test('deploy run --dry-run needs no --yes, executes nothing, and writes no audit line', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    const auditLogPath = tempAuditLogPath();
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const runner: SshRunner = async () => {
        throw new Error('dry-run must never touch ssh');
      };
      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo', 'dry-run': true } },
        { transport: { runner }, auditLogPath },
      );

      expect(envelope.ok).toBe(true);
      const data = envelope.data as { steps: Array<{ name: string; mutates: boolean }> };
      expect(data.steps.map((s) => s.name)).toEqual([
        'pull-code',
        'build-image',
        'up',
        'migrate',
        'verify',
      ]);
      expect(data.steps.find((s) => s.name === 'migrate')?.mutates).toBe(true);
      expect(data.steps.find((s) => s.name === 'verify')?.mutates).toBe(false);
      expect(readAuditLines(auditLogPath)).toHaveLength(0);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('deploy run --timeout overrides the default whole-recipe budget passed to the transport', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    const auditLogPath = tempAuditLogPath();
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const seenTimeouts: number[] = [];
      const runner: SshRunner = async (_args, timeoutMs) => {
        seenTimeouts.push(timeoutMs);
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      };
      await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo', timeout: '900', yes: true } },
        { transport: { runner }, auditLogPath, yes: true },
      );

      // Last call is the actual command run, wrapped as `timeout <sec> ...` — its
      // local timeoutMs budget must reflect the override, not DEPLOY_TIMEOUT_SEC (300s).
      const lastTimeout = seenTimeouts[seenTimeouts.length - 1];
      expect(lastTimeout).toBeGreaterThan(900_000);
      expect(lastTimeout).toBeLessThan(905_000);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('deploy run without --timeout keeps the default (300s) budget', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    const auditLogPath = tempAuditLogPath();
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const seenTimeouts: number[] = [];
      const runner: SshRunner = async (_args, timeoutMs) => {
        seenTimeouts.push(timeoutMs);
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      };
      await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo', yes: true } },
        { transport: { runner }, auditLogPath, yes: true },
      );

      const lastTimeout = seenTimeouts[seenTimeouts.length - 1];
      expect(lastTimeout).toBeGreaterThan(300_000);
      expect(lastTimeout).toBeLessThan(305_000);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('deploy run --timeout above the 3600s ceiling is clamped, not passed through raw', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    const auditLogPath = tempAuditLogPath();
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const seenTimeouts: number[] = [];
      const runner: SshRunner = async (_args, timeoutMs) => {
        seenTimeouts.push(timeoutMs);
        return { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false };
      };
      await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo', timeout: '999999', yes: true } },
        { transport: { runner }, auditLogPath, yes: true },
      );

      const lastTimeout = seenTimeouts[seenTimeouts.length - 1];
      expect(lastTimeout).toBeLessThanOrEqual(3_600_000 + 2_000);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });
});

describe('deploy run — non-dry-run executes the combined resolved script (LMS gotcha: migrate after up)', () => {
  test('buildRemote joins every step in resolved order, migrate strictly after up', () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { recipe: 'demo' } });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      expect(remoteCmd).toContain('git pull --ff-only');
      expect(remoteCmd).toContain('docker compose build app');
      expect(remoteCmd).toContain('docker compose up -d');
      expect(remoteCmd).toContain('artisan migrate --force');
      const upIndex = remoteCmd.indexOf('docker compose up -d');
      const migrateIndex = remoteCmd.indexOf('artisan migrate --force');
      expect(migrateIndex).toBeGreaterThan(upIndex);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('deploy migrate runs only the migrate-kind step', () => {
    const op = getOp('deploy', 'migrate');
    if (!op) {
      throw new Error('deploy migrate op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { recipe: 'demo' } });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      expect(remoteCmd).toContain('artisan migrate --force');
      expect(remoteCmd).not.toContain('git pull');
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });
});

describe('deploy run — step-failure attribution (marker on stdout, one round trip)', () => {
  test('the wrapped remote script still has each raw step command intact and a per-step failure wrapper', () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { recipe: 'demo' } });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      expect(remoteCmd).toContain('git pull --ff-only');
      expect(remoteCmd).toContain('docker compose build app');
      expect(remoteCmd).toContain('docker compose up -d');
      expect(remoteCmd).toContain('artisan migrate --force');
      expect(remoteCmd).toContain(STEP_FAILURE_MARKER);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('a failing step (index 1) surfaces failed_step in the envelope; other steps are not implicated', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const stdout = `${STEP_FAILURE_MARKER} 1 compose build-image\n`;
      const runner = scriptedRunner([
        { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
        { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check
        { code: 1, stdout, stderr: '', timedOut: false }, // remote script fails at step 1
      ]);

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo' } },
        { transport: { runner }, yes: true },
      );

      expect(envelope.ok).toBe(false);
      expect(envelope.error?.code).toBe('COMMAND_FAILED');
      expect(envelope.data).toEqual({
        failed_step: { index: 1, kind: 'compose', name: 'build-image' },
      });
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('success (no marker in stdout) yields ok:true with no failed_step', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const runner = scriptedRunner(connectedRunOutcomes('deploy ok\n'));

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo' } },
        { transport: { runner }, yes: true },
      );

      expect(envelope.ok).toBe(true);
      expect(envelope.data).toEqual({ output: 'deploy ok' });
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('deploy migrate attributes a failure to the migrate step within its own subset ordering', async () => {
    const op = getOp('deploy', 'migrate');
    if (!op) {
      throw new Error('deploy migrate op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const stdout = `${STEP_FAILURE_MARKER} 0 migrate migrate\n`;
      const runner = scriptedRunner([
        { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
        { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check
        { code: 1, stdout, stderr: '', timedOut: false }, // remote script fails
      ]);

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo' } },
        { transport: { runner }, yes: true },
      );

      expect(envelope.ok).toBe(false);
      expect(envelope.data).toEqual({
        failed_step: { index: 0, kind: 'migrate', name: 'migrate' },
      });
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('a COMMAND_FAILED with no marker in stdout (transport-level failure) leaves data null, same as any other op', async () => {
    const op = getOp('deploy', 'run');
    if (!op) {
      throw new Error('deploy run op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const runner = scriptedRunner([
        { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false }, // -G validate
        { code: 0, stdout: '', stderr: '', timedOut: false }, // -O check
        { code: 1, stdout: '', stderr: '', timedOut: false }, // no marker at all
      ]);

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { recipe: 'demo' } },
        { transport: { runner }, yes: true },
      );

      expect(envelope.ok).toBe(false);
      expect(envelope.data).toBeNull();
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });
});

describe('deploy rollback — refuses without a [rollback] block, never guesses', () => {
  test('buildRemote throws a clear error for a recipe with no [rollback] block', () => {
    const op = getOp('deploy', 'rollback');
    if (!op) {
      throw new Error('deploy rollback op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = NO_ROLLBACK_RECIPE_PATH;
    try {
      expect(() =>
        op.buildRemote({ alias: 'lms-server', args: { recipe: 'no-rollback' } }),
      ).toThrow(/declares no \[rollback\] block/);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('buildRemote succeeds for a recipe that declares [rollback]', () => {
    const op = getOp('deploy', 'rollback');
    if (!op) {
      throw new Error('deploy rollback op missing');
    }
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { recipe: 'demo' } });
      expect(remoteCmd).toContain('IMAGE_TAG');
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });
});

describe('config put — writes .bak-<date> before overwriting (real sh -c drive on a fixture file)', () => {
  test('the built command backs up the existing file before writing new content, in that order', () => {
    const op = getOp('config', 'put');
    if (!op) {
      throw new Error('config put op missing');
    }

    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-config-put-test-'));
    const targetPath = join(dir, 'nginx.conf');
    writeFileSync(targetPath, 'OLD CONTENT\n');

    const allowlistPath = join(dir, 'config-allowlist.toml');
    writeFileSync(allowlistPath, `[lms-server]\npaths = [${JSON.stringify(targetPath)}]\n`);

    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = allowlistPath;
    try {
      const contentBase64 = Buffer.from('NEW CONTENT\n', 'utf8').toString('base64');
      const remoteCmd = op.buildRemote({
        alias: 'lms-server',
        args: { path: targetPath, 'content-base64': contentBase64 },
      });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }

      const backupIndex = remoteCmd.indexOf('.bak-');
      const writeIndex = remoteCmd.indexOf('base64 -d');
      expect(backupIndex).toBeGreaterThan(-1);
      expect(writeIndex).toBeGreaterThan(backupIndex);

      const result = Bun.spawnSync(['sh', '-c', remoteCmd]);
      expect(result.exitCode).toBe(0);

      expect(readFileSync(targetPath, 'utf8')).toBe('NEW CONTENT\n');

      const backupFiles = readdirSync(dir).filter((f) => f.startsWith('nginx.conf.bak-'));
      expect(backupFiles).toHaveLength(1);
      const backupName = backupFiles[0];
      if (backupName === undefined) {
        throw new Error('expected a backup file');
      }
      expect(readFileSync(join(dir, backupName), 'utf8')).toBe('OLD CONTENT\n');
    } finally {
      delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    }
  });
});

describe('config get/put — allowlist refuses an undeclared path before ssh', () => {
  test('a path not declared for this alias is refused', () => {
    const op = getOp('config', 'get');
    if (!op) {
      throw new Error('config get op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-config-allow-test-'));
    const allowlistPath = join(dir, 'config-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/etc/nginx/nginx.conf"]\n');
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = allowlistPath;
    try {
      expect(() =>
        enforceAllowlist(op.allowlist, { alias: 'lms-server', args: { path: '/etc/shadow' } }),
      ).toThrow(/not on the allowlist/);
      expect(() =>
        enforceAllowlist(op.allowlist, {
          alias: 'lms-server',
          args: { path: '/etc/nginx/nginx.conf' },
        }),
      ).not.toThrow();
    } finally {
      delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    }
  });

  test('a missing allowlist file refuses every path (fail closed)', () => {
    const op = getOp('config', 'get');
    if (!op) {
      throw new Error('config get op missing');
    }
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = join(
      tmpdir(),
      'sshepherd-does-not-exist',
      'config-allowlist.toml',
    );
    try {
      expect(() =>
        enforceAllowlist(op.allowlist, {
          alias: 'lms-server',
          args: { path: '/etc/nginx/nginx.conf' },
        }),
      ).toThrow(/not on the allowlist/);
    } finally {
      delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    }
  });
});

describe('files group — allowlist refuses an undeclared path before ssh', () => {
  test('a path not declared for this alias is refused', () => {
    const op = getOp('files', 'ls');
    if (!op) {
      throw new Error('files ls op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-allow-test-'));
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/opt/lms"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
      expect(() =>
        enforceAllowlist(op.allowlist, { alias: 'lms-server', args: { path: '/etc/shadow' } }),
      ).toThrow(/not on the allowlist/);
      expect(() =>
        enforceAllowlist(op.allowlist, { alias: 'lms-server', args: { path: '/opt/lms' } }),
      ).not.toThrow();
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });

  test('a missing allowlist file refuses every path (fail closed)', () => {
    const op = getOp('files', 'ls');
    if (!op) {
      throw new Error('files ls op missing');
    }
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(
      tmpdir(),
      'sshepherd-does-not-exist',
      'files-allowlist.toml',
    );
    try {
      expect(() =>
        enforceAllowlist(op.allowlist, { alias: 'lms-server', args: { path: '/opt/lms' } }),
      ).toThrow(/not on the allowlist/);
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });

  test('files upload checks remote_path (not local_path) against the allowlist', () => {
    const op = getOp('files', 'upload');
    if (!op) {
      throw new Error('files upload op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-upload-allow-test-'));
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/opt/app/config.yml"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
      expect(() =>
        enforceAllowlist(op.allowlist, {
          alias: 'lms-server',
          args: { local_path: '/anywhere/on/disk.txt', remote_path: '/etc/shadow' },
        }),
      ).toThrow(/not on the allowlist/);
      expect(() =>
        enforceAllowlist(op.allowlist, {
          alias: 'lms-server',
          args: { local_path: '/anywhere/on/disk.txt', remote_path: '/opt/app/config.yml' },
        }),
      ).not.toThrow();
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });
});

describe('files cat --reveal — hard denylist and per-alias reveal-allowlist', () => {
  // These two isolate to just the reveal-keys policy (not op.allowlist, which also carries
  // the files path policy) — they're about --reveal's own gate, not the path gate.
  const REVEAL_ONLY_POLICY = [{ kind: 'reveal-keys' as const, argName: 'reveal' }];

  test('a key not on the reveal-allowlist is refused even though it is not secret-shaped', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-reveal-allow-test-'));
    const revealAllowlistPath = join(dir, 'reveal-allowlist.toml');
    writeFileSync(revealAllowlistPath, '[lms-server]\nkeys = ["NODE_ENV"]\n');
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = revealAllowlistPath;
    try {
      expect(() =>
        enforceAllowlist(REVEAL_ONLY_POLICY, { alias: 'lms-server', args: { reveal: 'REGION' } }),
      ).toThrow(/not on the reveal-allowlist/);
      expect(() =>
        enforceAllowlist(REVEAL_ONLY_POLICY, {
          alias: 'lms-server',
          args: { reveal: 'NODE_ENV' },
        }),
      ).not.toThrow();
    } finally {
      delete process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
    }
  });

  test('a denylisted-pattern key is refused even when explicitly on the reveal-allowlist', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-reveal-denylist-test-'));
    const revealAllowlistPath = join(dir, 'reveal-allowlist.toml');
    writeFileSync(revealAllowlistPath, '[lms-server]\nkeys = ["AWS_SECRET_ACCESS_KEY"]\n');
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = revealAllowlistPath;
    try {
      expect(() =>
        enforceAllowlist(REVEAL_ONLY_POLICY, {
          alias: 'lms-server',
          args: { reveal: 'AWS_SECRET_ACCESS_KEY' },
        }),
      ).toThrow(/hard-denied secret pattern/);
    } finally {
      delete process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
    }
  });

  test('no --reveal flag is a no-op — the reveal-keys policy never fires', () => {
    // Isolated to just the reveal-keys policy (not op.allowlist, which also carries the
    // files path policy) — this test is about --reveal being absent, not about the path.
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = join(
      tmpdir(),
      'sshepherd-does-not-exist',
      'reveal-allowlist.toml',
    );
    try {
      expect(() =>
        enforceAllowlist([{ kind: 'reveal-keys', argName: 'reveal' }], {
          alias: 'lms-server',
          args: {},
        }),
      ).not.toThrow();
    } finally {
      delete process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
    }
  });
});

describe('security harden — --keep-session defaults true and refuses lockout-risky directives', () => {
  test('default (no keep-session arg) never touches PermitRootLogin/PasswordAuthentication', () => {
    const op = getOp('security', 'harden');
    if (!op) {
      throw new Error('security harden op missing');
    }
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: {} });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    expect(remoteCmd).not.toContain('PermitRootLogin');
    expect(remoteCmd).not.toContain('PasswordAuthentication');
    expect(remoteCmd).toContain('X11Forwarding');
    expect(remoteCmd).toContain('sshd -t');
  });

  test('explicit keep-session:false also applies the lockout-risky directives', () => {
    const op = getOp('security', 'harden');
    if (!op) {
      throw new Error('security harden op missing');
    }
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { 'keep-session': false } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    expect(remoteCmd).toContain('PermitRootLogin');
    expect(remoteCmd).toContain('PasswordAuthentication');
  });

  test('backs up sshd_config before validating, and validates before reloading (command sequence)', () => {
    const op = getOp('security', 'harden');
    if (!op) {
      throw new Error('security harden op missing');
    }
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: {} });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    const backupIndex = remoteCmd.indexOf('.bak-');
    const validateIndex = remoteCmd.indexOf('sshd -t');
    const reloadIndex = remoteCmd.indexOf('systemctl reload sshd');
    expect(backupIndex).toBeGreaterThan(-1);
    expect(validateIndex).toBeGreaterThan(backupIndex);
    expect(reloadIndex).toBeGreaterThan(validateIndex);
  });
});

describe('quoting — Phase 5 mutating ops are injection-safe (real sh -c drive)', () => {
  test('services restart: a container arg shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('services', 'restart');
    if (!op) {
      throw new Error('services restart op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `web'; touch ${marker}; echo '`;
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { container: malicious } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    assertShellParsesRemoteCmdSafely(remoteCmd, marker);
  });

  test('services systemctl-restart: a unit arg shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('services', 'systemctl-restart');
    if (!op) {
      throw new Error('services systemctl-restart op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `nginx'; touch ${marker}; echo '`;
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { unit: malicious } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    assertShellParsesRemoteCmdSafely(remoteCmd, marker);
  });

  test('config reload: a service arg shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('config', 'reload');
    if (!op) {
      throw new Error('config reload op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `nginx'; touch ${marker}; echo '`;
    const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { service: malicious } });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    assertShellParsesRemoteCmdSafely(remoteCmd, marker);
  });

  test('config get: a path shaped like a shell injection (present on its own allowlist) is neutralized', () => {
    const op = getOp('config', 'get');
    if (!op) {
      throw new Error('config get op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `/etc/nginx/nginx.conf'; touch ${marker}; echo '`;
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-config-get-inj-test-'));
    const allowlistPath = join(dir, 'config-allowlist.toml');
    writeFileSync(allowlistPath, `[lms-server]\npaths = [${JSON.stringify(malicious)}]\n`);
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = allowlistPath;
    try {
      const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { path: malicious } });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      assertShellParsesRemoteCmdSafely(remoteCmd, marker);
    } finally {
      delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    }
  });

  test('config put: a path shaped like a shell injection (present on its own allowlist) is neutralized', () => {
    const op = getOp('config', 'put');
    if (!op) {
      throw new Error('config put op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `/etc/nginx/nginx.conf'; touch ${marker}; echo '`;
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-config-put-inj-test-'));
    const allowlistPath = join(dir, 'config-allowlist.toml');
    writeFileSync(allowlistPath, `[lms-server]\npaths = [${JSON.stringify(malicious)}]\n`);
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = allowlistPath;
    try {
      const contentBase64 = Buffer.from('hi\n', 'utf8').toString('base64');
      const remoteCmd = op.buildRemote({
        alias: 'lms-server',
        args: { path: malicious, 'content-base64': contentBase64 },
      });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      assertShellParsesRemoteCmdSafely(remoteCmd, marker);
    } finally {
      delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    }
  });

  test('config validate: a caddy path shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('config', 'validate');
    if (!op) {
      throw new Error('config validate op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `/etc/caddy/Caddyfile'; touch ${marker}; echo '`;
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-config-validate-inj-test-'));
    const allowlistPath = join(dir, 'config-allowlist.toml');
    writeFileSync(allowlistPath, `[lms-server]\npaths = [${JSON.stringify(malicious)}]\n`);
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = allowlistPath;
    try {
      const remoteCmd = op.buildRemote({ alias: 'lms-server', args: { path: malicious } });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      assertShellParsesRemoteCmdSafely(remoteCmd, marker);
    } finally {
      delete process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
    }
  });

  test('deploy logs: a tail arg shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('deploy', 'logs');
    if (!op) {
      throw new Error('deploy logs op missing');
    }
    const marker = freshMarkerPath();
    const malicious = `50'; touch ${marker}; echo '`;
    process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
    try {
      const remoteCmd = op.buildRemote({
        alias: 'lms-server',
        args: { recipe: 'demo', tail: malicious },
      });
      if (remoteCmd === null) {
        throw new Error('expected a remote command');
      }
      assertShellParsesRemoteCmdSafely(remoteCmd, marker);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });

  test('deploy rollback (previous-tag): a tag shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('deploy', 'rollback');
    if (!op) {
      throw new Error('deploy rollback op missing');
    }
    const marker = freshMarkerPath();
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-rollback-inj-test-'));
    const recipePath = join(dir, 'recipe.toml');
    const maliciousTag = `v1'; touch ${marker}; echo '`;
    writeFileSync(
      recipePath,
      [
        'name = "inj"',
        'alias = "lms-server"',
        'workdir = "/opt/lms"',
        '[[step]]',
        'name = "up"',
        'kind = "compose"',
        'run = "up -d"',
        '[rollback]',
        'strategy = "previous-tag"',
        `tag = ${JSON.stringify(maliciousTag)}`,
        '',
      ].join('\n'),
    );
    process.env.SSHEPHERD_RECIPE_PATH = recipePath;
    try {
      const cmd = op.buildRemote({ alias: 'lms-server', args: { recipe: 'inj' } });
      if (cmd === null) {
        throw new Error('expected a remote command');
      }
      assertShellParsesRemoteCmdSafely(cmd, marker);
    } finally {
      delete process.env.SSHEPHERD_RECIPE_PATH;
    }
  });
});

describe("security ssh-audit — posture assessment shares harden's recommended values", () => {
  test('shapes each directive into {directive, value, recommended, ok}', async () => {
    const op = getOp('security', 'ssh-audit');
    if (!op) {
      throw new Error('security ssh-audit op missing');
    }
    const stdout = [
      'permitrootlogin yes',
      'passwordauthentication no',
      'permitemptypasswords no',
      'x11forwarding no',
      'maxauthtries 6',
      'clientaliveinterval 300',
      'clientalivecountmax 2',
    ].join('\n');
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(true);
    const data = envelope.data as { directives: Array<Record<string, unknown>> };
    const byDirective = Object.fromEntries(data.directives.map((d) => [d.directive, d]));

    expect(byDirective.PermitRootLogin).toEqual({
      directive: 'PermitRootLogin',
      value: 'yes',
      recommended: 'no',
      ok: false,
    });
    expect(byDirective.PasswordAuthentication).toEqual({
      directive: 'PasswordAuthentication',
      value: 'no',
      recommended: 'no',
      ok: true,
    });
    // MaxAuthTries recommends <= 4 — an effective 6 is worse than recommended.
    expect(byDirective.MaxAuthTries).toEqual({
      directive: 'MaxAuthTries',
      value: '6',
      recommended: '4',
      ok: false,
    });
  });

  test('a directive missing from the effective config reports value:null, ok:false (no crash)', async () => {
    const op = getOp('security', 'ssh-audit');
    if (!op) {
      throw new Error('security ssh-audit op missing');
    }
    const runner = scriptedRunner(connectedRunOutcomes('permitrootlogin no'));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );
    expect(envelope.ok).toBe(true);
    const data = envelope.data as { directives: Array<Record<string, unknown>> };
    const x11 = data.directives.find((d) => d.directive === 'X11Forwarding');
    expect(x11).toEqual({ directive: 'X11Forwarding', value: null, recommended: 'no', ok: false });
  });

  test('when both sshd -T and sshd_config fail, the envelope carries a clean COMMAND_FAILED (no crash)', async () => {
    const op = getOp('security', 'ssh-audit');
    if (!op) {
      throw new Error('security ssh-audit op missing');
    }
    const runner = scriptedRunner([
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
      { code: 0, stdout: '', stderr: '', timedOut: false },
      { code: 1, stdout: '', stderr: '', timedOut: false },
    ]);
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );
    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('COMMAND_FAILED');
    expect(envelope.data).toBeNull();
  });
});

describe('security listeners — same parser and command as check ports, security-group framing', () => {
  test('buildRemote is exactly the same ss -H -tlnp command as check ports', () => {
    const listenersOp = getOp('security', 'listeners');
    const portsOp = getOp('check', 'ports');
    if (!listenersOp || !portsOp) {
      throw new Error('security listeners or check ports op missing');
    }
    expect(listenersOp.buildRemote({ alias: 'lms-server', args: {} })).toBe(
      portsOp.buildRemote({ alias: 'lms-server', args: {} }),
    );
  });

  test('shapes ss -H -tlnp output into {proto, local_addr, port, process, pid} entries', async () => {
    const op = getOp('security', 'listeners');
    if (!op) {
      throw new Error('security listeners op missing');
    }
    const stdout = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))';
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );
    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({
      listening: [{ proto: 'tcp', local_addr: '0.0.0.0', port: 22, process: 'sshd', pid: 1234 }],
    });
  });
});

describe('security authorized-keys — fingerprint + comment + options, never the raw key blob', () => {
  test('correlates RAW lines with FP lines by index, extracts options/type/comment', async () => {
    const op = getOp('security', 'authorized-keys');
    if (!op) {
      throw new Error('security authorized-keys op missing');
    }
    const rawKeyBlob = 'AAAAB3NzaC1yc2EAAAADAQABAAABgQDsecretkeymaterial';
    const stdout = [
      '__RAW__',
      `no-port-forwarding ssh-rsa ${rawKeyBlob} deploy@ci`,
      `ssh-ed25519 ${rawKeyBlob} alice@laptop`,
      '__FP__',
      '2048 SHA256:aaaaBBBBccccDDDDeeeeFFFFgggg1111 deploy@ci (RSA)',
      '256 SHA256:zzzzYYYYxxxxWWWWvvvvUUUUtttt2222 alice@laptop (ED25519)',
    ].join('\n');
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );

    expect(envelope.ok).toBe(true);
    const data = envelope.data as { found: boolean; keys: Array<Record<string, unknown>> };
    expect(data.found).toBe(true);
    expect(data.keys).toEqual([
      {
        type: 'ssh-rsa',
        fingerprint: 'SHA256:aaaaBBBBccccDDDDeeeeFFFFgggg1111',
        comment: 'deploy@ci',
        options: 'no-port-forwarding',
      },
      {
        type: 'ssh-ed25519',
        fingerprint: 'SHA256:zzzzYYYYxxxxWWWWvvvvUUUUtttt2222',
        comment: 'alice@laptop',
        options: null,
      },
    ]);

    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain(rawKeyBlob);
  });

  test('no authorized_keys file yields found:false, keys:[] (no crash)', async () => {
    const op = getOp('security', 'authorized-keys');
    if (!op) {
      throw new Error('security authorized-keys op missing');
    }
    const runner = scriptedRunner(connectedRunOutcomes(''));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );
    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({ found: false, keys: [] });
  });
});

describe('security fail2ban — degrades to {available:false} when fail2ban-client is absent', () => {
  test('fail2ban-client not installed', async () => {
    const op = getOp('security', 'fail2ban');
    if (!op) {
      throw new Error('security fail2ban op missing');
    }
    const runner = scriptedRunner(connectedRunOutcomes('__UNAVAILABLE__'));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );
    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({
      available: false,
      reason: 'fail2ban-client not installed',
      jails: [],
    });
  });

  test('jail status with banned IPs is shaped per jail', async () => {
    const op = getOp('security', 'fail2ban');
    if (!op) {
      throw new Error('security fail2ban op missing');
    }
    const stdout = [
      '__JAIL__:sshd',
      'Status for the jail: sshd',
      '|- Filter',
      '|  |- Currently failed: 0',
      '|  `- Total failed:     10',
      '`- Actions',
      '   |- Currently banned: 2',
      '   |- Total banned:     5',
      '   `- Banned IP list:   1.2.3.4 5.6.7.8',
    ].join('\n');
    const runner = scriptedRunner(connectedRunOutcomes(stdout));
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: {} },
      { transport: { runner } },
    );
    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({
      available: true,
      reason: null,
      jails: [
        {
          jail: 'sshd',
          currently_banned: 2,
          total_banned: 5,
          banned_ips: ['1.2.3.4', '5.6.7.8'],
        },
      ],
    });
  });
});

describe('files download — writes straight to local disk, never inlines content in the envelope', () => {
  const SECRET_CONTENT = ['DB_PASSWORD=s3cr3t-value', 'JWT_SECRET=abcd1234', ''].join('\n');

  test('decoded content lands on local disk, and the raw bytes never appear in the envelope JSON', async () => {
    const op = getOp('files', 'download');
    if (!op) {
      throw new Error('files download op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-download-test-'));
    const localPath = join(dir, 'downloaded.env');
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/opt/app/.env"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
      const contentBase64 = Buffer.from(SECRET_CONTENT, 'utf8').toString('base64');
      const runner = scriptedRunner(
        connectedRunOutcomes(`__OK__:${SECRET_CONTENT.length}\n${contentBase64}`),
      );

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { path: '/opt/app/.env', local_path: localPath } },
        { transport: { runner } },
      );

      expect(envelope.ok).toBe(true);
      expect(envelope.data).toEqual({
        found: true,
        truncated: false,
        size_bytes: SECRET_CONTENT.length,
        written: true,
        local_path: localPath,
      });
      expect(readFileSync(localPath, 'utf8')).toBe(SECRET_CONTENT);

      const serialized = JSON.stringify(envelope);
      expect(serialized).not.toContain('content_base64');
      expect(serialized).not.toContain('s3cr3t-value');
      expect(serialized).not.toContain('abcd1234');
      expect(serialized).not.toContain(contentBase64);
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });

  test('a not-found remote path writes nothing locally and echoes a null local_path', async () => {
    const op = getOp('files', 'download');
    if (!op) {
      throw new Error('files download op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-download-notfound-test-'));
    const localPath = join(dir, 'never-written.txt');
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/opt/app/missing.txt"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
      const runner = scriptedRunner(connectedRunOutcomes('__NOT_FOUND__'));

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { path: '/opt/app/missing.txt', local_path: localPath } },
        { transport: { runner } },
      );

      expect(envelope.ok).toBe(true);
      expect(envelope.data).toEqual({
        found: false,
        truncated: false,
        size_bytes: null,
        written: false,
        local_path: null,
      });
      expect(existsSync(localPath)).toBe(false);
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });

  test('a too-large remote file writes nothing locally and reports truncated', async () => {
    const op = getOp('files', 'download');
    if (!op) {
      throw new Error('files download op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-download-toolarge-test-'));
    const localPath = join(dir, 'never-written.bin');
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/opt/app/huge.bin"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    try {
      const runner = scriptedRunner(connectedRunOutcomes('__TOO_LARGE__:99999999'));

      const envelope = await executeOp(
        op,
        { alias: 'lms-server', args: { path: '/opt/app/huge.bin', local_path: localPath } },
        { transport: { runner } },
      );

      expect(envelope.ok).toBe(true);
      expect(envelope.data).toEqual({
        found: true,
        truncated: true,
        size_bytes: 99999999,
        written: false,
        local_path: null,
      });
      expect(existsSync(localPath)).toBe(false);
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }
  });
});

describe('files upload — base64-over-ssh, no scp/sftp, no backup, gated like every mutating op', () => {
  test('a missing local file fails locally with a clear error before any transport', () => {
    const op = getOp('files', 'upload');
    if (!op) {
      throw new Error('files upload op missing');
    }
    expect(() =>
      op.buildRemote({
        alias: 'lms-server',
        args: {
          local_path: join(tmpdir(), 'sshepherd-upload-does-not-exist-anywhere.txt'),
          remote_path: '/opt/app/config.yml',
        },
      }),
    ).toThrow(/not found or unreadable/);
  });

  test('the built script base64-decodes the local file content onto the remote path (real sh -c drive)', () => {
    const op = getOp('files', 'upload');
    if (!op) {
      throw new Error('files upload op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-upload-test-'));
    const localPath = join(dir, 'source.txt');
    const remotePath = join(dir, 'destination.txt');
    writeFileSync(localPath, 'UPLOADED CONTENT\n');

    const remoteCmd = op.buildRemote({
      alias: 'lms-server',
      args: { local_path: localPath, remote_path: remotePath },
    });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    expect(remoteCmd).toContain('base64 -d');
    expect(remoteCmd).not.toContain('.bak-');

    const result = Bun.spawnSync(['sh', '-c', remoteCmd]);
    expect(result.exitCode).toBe(0);
    expect(readFileSync(remotePath, 'utf8')).toBe('UPLOADED CONTENT\n');
    expect(readdirSync(dir).filter((f) => f.includes('.bak-'))).toHaveLength(0);
  });

  test('mutating gate: no --yes refuses, never touches ssh, and writes a refused audit line', async () => {
    const op = getOp('files', 'upload');
    if (!op) {
      throw new Error('files upload op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-upload-gate-test-'));
    const localPath = join(dir, 'source.txt');
    writeFileSync(localPath, 'content\n');
    const auditLogPath = tempAuditLogPath();
    const runner: SshRunner = async () => {
      throw new Error('ssh must never be called for a refused mutating op');
    };
    const envelope = await executeOp(
      op,
      { alias: 'lms-server', args: { local_path: localPath, remote_path: '/opt/app/config.yml' } },
      { transport: { runner }, auditLogPath },
    );

    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
    const lines = readAuditLines(auditLogPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.outcome).toBe('refused');
    expect(lines[0]?.command).toBe('files upload');
  });

  test('mutating gate: --yes proceeds and writes an ok audit line on success', async () => {
    const op = getOp('files', 'upload');
    if (!op) {
      throw new Error('files upload op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-upload-gate-ok-test-'));
    const localPath = join(dir, 'source.txt');
    writeFileSync(localPath, 'content\n');
    const allowlistPath = join(dir, 'files-allowlist.toml');
    writeFileSync(allowlistPath, '[lms-server]\npaths = ["/opt/app/config.yml"]\n');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = allowlistPath;
    const auditLogPath = tempAuditLogPath();
    let envelope: Awaited<ReturnType<typeof executeOp>>;
    try {
      const runner = scriptedRunner(connectedRunOutcomes(''));
      envelope = await executeOp(
        op,
        {
          alias: 'lms-server',
          args: { local_path: localPath, remote_path: '/opt/app/config.yml' },
        },
        { transport: { runner }, yes: true, auditLogPath },
      );
    } finally {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    }

    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({ written: true, remote_path: '/opt/app/config.yml' });
    const lines = readAuditLines(auditLogPath);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.outcome).toBe('ok');
  });

  test('a remote_path shaped like a shell injection cannot splice a second command', () => {
    const op = getOp('files', 'upload');
    if (!op) {
      throw new Error('files upload op missing');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-files-upload-inj-test-'));
    const localPath = join(dir, 'source.txt');
    writeFileSync(localPath, 'content\n');
    const marker = freshMarkerPath();
    const malicious = `${join(dir, 'dest.txt')}'; touch ${marker}; echo '`;

    const remoteCmd = op.buildRemote({
      alias: 'lms-server',
      args: { local_path: localPath, remote_path: malicious },
    });
    if (remoteCmd === null) {
      throw new Error('expected a remote command');
    }
    assertShellParsesRemoteCmdSafely(remoteCmd, marker);
  });
});

test('executeOp converts a thrown OpRunLocalError into a structured Envelope error', async () => {
  const throwingOp: OpSpec<null> = {
    group: 'test',
    name: 'throws',
    summary: 'test-only op that always throws OpRunLocalError',
    args: [],
    mutating: false,
    timeoutSec: 5,
    output: 'raw',
    buildRemote: () => null,
    shape: () => null,
    runLocal: () => {
      throw new OpRunLocalError('VALIDATION_ERROR', 'kind must be one of local/remote/dynamic');
    },
  };

  const envelope = await executeOp(throwingOp, { alias: '', args: {} }, {});

  expect(envelope.ok).toBe(false);
  expect(envelope.error?.code).toBe('VALIDATION_ERROR');
  expect(envelope.error?.message).toBe('kind must be one of local/remote/dynamic');
  expect(envelope.data).toBeNull();
});

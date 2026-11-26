import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, listOps } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import type { OpSpec } from '../types.ts';

const MAX_TIMEOUT_SEC = 3_600;
const ALIAS = 'contract-host';
const REMOTE_PATH = '/opt/app/config.yml';
const DEMO_RECIPE_PATH = join(import.meta.dir, 'fixtures', 'deploy.demo.toml');
const ENV_KEYS = [
  'SSHEPHERD_FILES_ALLOWLIST_PATH',
  'SSHEPHERD_CONFIG_ALLOWLIST_PATH',
  'SSHEPHERD_TARGETS_PATH',
  'SSHEPHERD_TUNNEL_STATE_DIR',
  'SSHEPHERD_RECIPE_PATH',
] as const;

const FAILING_OUTCOME: SpawnOutcome = { code: 255, stdout: '', stderr: '', timedOut: false };
const failingRunner: SshRunner = async () => FAILING_OUTCOME;

const AUDITED_MUTATING_OPS = [
  'config put',
  'config reload',
  'deploy migrate',
  'deploy rollback',
  'deploy run',
  'files upload',
  'security harden',
  'services restart',
  'services systemctl-reload',
  'services systemctl-restart',
  'services systemctl-start',
  'services systemctl-stop',
  'tunnel close',
  'tunnel open',
];

const UNAUDITED_MUTATING_OPS: string[] = [];

let scratch = '';
const savedEnv: Record<string, string | undefined> = {};

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-registry-contract-'));
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
  }
  const allowlist = `[${ALIAS}]\npaths = ["${REMOTE_PATH}"]\n`;
  writeFileSync(join(scratch, 'files-allowlist.toml'), allowlist);
  writeFileSync(join(scratch, 'config-allowlist.toml'), allowlist);
  writeFileSync(join(scratch, 'targets.toml'), '');
  writeFileSync(join(scratch, 'source.txt'), 'content\n');
  writeFileSync(join(scratch, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
  process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
  process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = join(scratch, 'config-allowlist.toml');
  process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
  process.env.SSHEPHERD_TUNNEL_STATE_DIR = join(scratch, 'tunnels');
  process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = savedEnv[key];
    }
  }
});

const ARG_VALUES: Record<string, () => string> = {
  path: () => REMOTE_PATH,
  remote_path: () => REMOTE_PATH,
  local_path: () => join(scratch, 'source.txt'),
  'content-base64': () => Buffer.from('content\n').toString('base64'),
  recipe: () => 'demo',
  id: () => 'no-such-tunnel',
  kind: () => 'local',
  duration: () => 'not-a-number',
  stream: () => 'access',
  file: () => '/opt/app/docker-compose.yml',
  sql: () => 'SELECT 1',
  db_user: () => 'app',
  db_name: () => 'app',
};

function argsFor(op: OpSpec): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (const spec of op.args) {
    if (spec.required || spec.name === 'duration') {
      args[spec.name] = ARG_VALUES[spec.name]?.() ?? 'app';
    }
  }
  if (op.group === 'db') {
    args.db_user = 'app';
    args.db_name = 'app';
  }
  return args;
}

function auditRows(logPath: string): Array<{ command: string; outcome: string }> {
  try {
    return readFileSync(logPath, 'utf8')
      .split('\n')
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as { command: string; outcome: string });
  } catch {
    return [];
  }
}

interface Probe {
  name: string;
  mutating: boolean;
  rows: Array<{ command: string; outcome: string }>;
}

async function probe(op: OpSpec, index: number): Promise<Probe> {
  const auditLogPath = join(scratch, `audit-${index}.jsonl`);
  try {
    await executeOp(
      op,
      { alias: ALIAS, args: argsFor(op) },
      {
        transport: { runner: failingRunner },
        sshConfigPath: join(scratch, 'ssh_config'),
        yes: true,
        auditLogPath,
      },
    );
  } catch {
    // a throw before the audit line is itself the observed state for this op
  }
  return { name: `${op.group} ${op.name}`, mutating: op.mutating, rows: auditRows(auditLogPath) };
}

describe('registry contract — every op in listOps()', () => {
  const ops = listOps();

  test('registry is non-empty', () => {
    expect(ops.length).toBeGreaterThan(0);
  });

  test('group/name is unique across the registry', () => {
    const keys = ops.map((op) => `${op.group}/${op.name}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  for (const op of ops) {
    test(`${op.group} ${op.name}: 0 < timeoutSec <= ${MAX_TIMEOUT_SEC}`, () => {
      expect(op.timeoutSec).toBeGreaterThan(0);
      expect(op.timeoutSec).toBeLessThanOrEqual(MAX_TIMEOUT_SEC);
    });
  }

  test('audit rows through executeOp: read-only ops write none, mutating ops are the recorded set', async () => {
    const probes: Probe[] = [];
    for (const [index, op] of ops.entries()) {
      probes.push(await probe(op, index));
    }
    for (const p of probes.filter((entry) => !entry.mutating)) {
      expect({ op: p.name, rows: p.rows }).toEqual({ op: p.name, rows: [] });
    }
    const mutating = probes.filter((entry) => entry.mutating);
    const audited = mutating.filter((p) => p.rows.length === 1).map((p) => p.name);
    const unaudited = mutating.filter((p) => p.rows.length === 0).map((p) => p.name);
    expect(audited.sort()).toEqual([...AUDITED_MUTATING_OPS].sort());
    expect(unaudited.sort()).toEqual([...UNAUDITED_MUTATING_OPS].sort());
    for (const p of mutating.filter((entry) => entry.rows.length === 1)) {
      expect(p.rows[0]?.command).toBe(p.name);
      expect(p.rows[0]?.outcome).toBe(p.name === 'tunnel close' ? 'ok' : 'error');
    }
  });
});

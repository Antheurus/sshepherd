import { afterAll, beforeAll, describe, expect, spyOn, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import * as scrubModule from '../scrub.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner } from '../transport.ts';
import type { Envelope, OpContext } from '../types.ts';

/**
 * Block 8 part b audit (Phase 09 + Phase 10). Each test below is one receipt finding and is red on
 * 3133422 by design; the last test is the green scrubber-off proof for container env. Smoke-only:
 * skipped without the fixture (SSHEPHERD_SMOKE_PROJECT picks it).
 */

const REPO = join(import.meta.dir, '..', '..');
const ALIAS = 'smoke-debian';
const ROOT = '/opt/audit0910';

function fixtureNames(): { prefix: string; state: string } {
  const proc = Bun.spawnSync(
    [
      'bash',
      '-c',
      '. "$1"; printf "%s\\n%s" "$SMOKE_PREFIX" "$SMOKE_STATE"',
      'bash',
      join(REPO, 'scripts', 'sshd-fixture', 'project.sh'),
    ],
    { stdout: 'pipe', stderr: 'pipe' },
  );
  const [prefix = '', state = ''] = proc.stdout.toString().split('\n');
  return { prefix, state };
}

const { prefix: PREFIX, state: STATE } = fixtureNames();
const SSHD = `${PREFIX}-sshd-debian`;
const POSTGRES = `${PREFIX}-postgres`;
const SSH_CONFIG = join(STATE, 'ssh_config');
const CANARY = `Au${randomBytes(12).toString('hex')}`;

function running(name: string): boolean {
  const proc = Bun.spawnSync(['docker', 'inspect', '-f', '{{.State.Running}}', name], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const fixtureUp = (): boolean => existsSync(SSH_CONFIG) && running(SSHD) && running(POSTGRES);

function onHost(script: string): void {
  const proc = Bun.spawnSync(['docker', 'exec', '-i', SSHD, 'sh', '-c', script, 'sh', CANARY], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  if (proc.exitCode !== 0) {
    throw new Error(`fixture setup failed: ${proc.stderr.toString().slice(-300)}`);
  }
}

const SAVED = [
  'SSHEPHERD_TARGETS_PATH',
  'SSHEPHERD_FILES_ALLOWLIST_PATH',
  'SSHEPHERD_SSH_CONFIG_PATH',
  'SSHEPHERD_STATE_DIR',
  'XDG_RUNTIME_DIR',
] as const;
const saved: Record<string, string | undefined> = {};
let scratch = '';

async function run(group: string, name: string, ctx: OpContext): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (op === undefined) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(op, ctx, {
    transport: { runner: defaultRunner, sshConfigPath: SSH_CONFIG },
    sshConfigPath: SSH_CONFIG,
    auditLogPath: join(scratch, 'audit.jsonl'),
  });
}

function scrubberOff(): { mockRestore: () => void }[] {
  return [
    spyOn(scrubModule, 'scrub').mockImplementation(((value: unknown) => ({
      value,
      count: 0,
    })) as typeof scrubModule.scrub),
    spyOn(scrubModule, 'scrubText').mockImplementation((text: string) => ({
      value: text,
      count: 0,
    })),
  ];
}

const rowsOf = (data: unknown): Record<string, unknown>[] =>
  (Array.isArray(data) ? data : ((data as { rows?: unknown[] })?.rows ?? [])) as Record<
    string,
    unknown
  >[];

describe.skipIf(!fixtureUp())('audit 0910: Phase 09 + Phase 10 findings (smoke fixture)', () => {
  beforeAll(() => {
    for (const key of SAVED) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit0910-'));
    writeFileSync(
      join(scratch, 'targets.toml'),
      `[prod]\nalias = "${ALIAS}"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
    );
    writeFileSync(
      join(scratch, 'files-allowlist.toml'),
      `[${ALIAS}]\npaths = ["${ROOT}", "${ROOT}/multi.env"]\n`,
    );
    process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
    process.env.SSHEPHERD_SSH_CONFIG_PATH = SSH_CONFIG;
    process.env.SSHEPHERD_STATE_DIR = scratch;
    process.env.XDG_RUNTIME_DIR = join(STATE, 'run');
    onHost(
      [
        'set -e',
        `rm -rf ${ROOT}`,
        `mkdir -p ${ROOT}/rel-2026-11 ${ROOT}/sub`,
        `printf 'NOTE=%sdt\\n' "$1" > ${ROOT}/rel-2026-11/.env`,
        `printf 'tls key backup\\n-----BEGIN RSA PRIVATE KEY-----\\nMIIEow%sbk\\n-----END RSA PRIVATE KEY-----\\n' "$1" > ${ROOT}/sub/backup.txt`,
        `printf 'SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\\n%sml==\\n-----END OPENSSH PRIVATE KEY-----"\\nSPACED = value\\nLAST=ok\\n' "$1" > ${ROOT}/multi.env`,
      ].join('; '),
    );
  });

  afterAll(async () => {
    onHost(`rm -rf ${ROOT}`);
    await closeMaster(ALIAS);
    for (const key of SAVED) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    }
    rmSync(scratch, { recursive: true, force: true });
  });

  // Amended by the Block 8 fix B: the escape string is not a statement on its own (it closes two
  // parentheses it never opened), so no wrapper can run it as written; the bound holds when it is
  // refused before ssh, and the same SELECT ending in a plain `--` comment runs under the limit.
  test('P09 BOUNDS: a trailing -- comment cannot strip the server-side row LIMIT', async () => {
    const escaped = await run(
      'db',
      'query',
      buildDbOpContext('prod', {
        sql: "SELECT id, repeat('x', 5000) AS pad FROM big) sshepherd_q) t --",
        'max-rows': '1',
      }),
    );
    expect(escaped.error?.code).toBe('VALIDATION_ERROR');
    const commented = await run(
      'db',
      'query',
      buildDbOpContext('prod', {
        sql: "SELECT id, repeat('x', 5000) AS pad FROM big --",
        'max-rows': '1',
      }),
    );
    expect(commented.error?.code).toBeUndefined();
    expect(rowsOf(commented.data)).toHaveLength(1);
  }, 60_000);

  // Amended by the Block 8 fix B: orchestrator decision 4 ratified the object `data` at
  // schema_version 1 as a deliberate 0.4.0 break; what must hold is that the committed schema
  // describes the shape the binary returns.
  test('MERGE/P09 G6: db query data stays the row array at schema_version 1 (or the version moves)', async () => {
    const envelope = await run('db', 'query', buildDbOpContext('prod', { sql: 'SELECT 1 AS a' }));
    expect(envelope.ok).toBe(true);
    expect(rowsOf(envelope.data)).toEqual([{ a: 1 }]);
    const schema = JSON.parse(readFileSync(join(REPO, 'docs', 'schema', 'db-query.json'), 'utf8'));
    const data = schema.properties.data as {
      properties?: Record<string, unknown>;
      anyOf?: { type?: string; properties?: Record<string, unknown> }[];
    };
    const shape =
      data.properties ?? data.anyOf?.find((branch) => branch.type === 'object')?.properties;
    expect(Object.keys(shape ?? {})).toEqual(
      expect.arrayContaining(['rows', 'row_count', 'truncated', 'masked_columns']),
    );
  }, 30_000);

  // Amended by the Block 8 fix B: orchestrator decision 3 keeps GRANT pg_read_all_data (so the
  // role can SELECT pg_authid); the leak is closed in depth instead, and this checks the db query
  // half of it: the verifier column comes back masked by deny_columns' default.
  test('P09 LEAK: the recommended read-only role cannot read pg_authid (role password verifiers)', async () => {
    const envelope = await run(
      'db',
      'query',
      buildDbOpContext('prod', {
        sql: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname = 'fixture_app'",
      }),
    );
    expect(envelope.ok).toBe(true);
    const data = envelope.data as { masked_columns?: string[] };
    expect(data.masked_columns).toEqual(['rolpassword']);
    expect(rowsOf(envelope.data)[0]?.rolpassword).toBe('***');
    expect(JSON.stringify(envelope)).not.toContain('SCRAM-SHA-256$');
  }, 30_000);

  test('P09 LEAK: a SCRAM verifier under a neutral column name is masked', async () => {
    const verifier =
      'SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0$c3RvcmVka2V5c3RvcmVka2V5c3RvcmVka2V5c3Q=:c2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2U=';
    const envelope = await run(
      'db',
      'query',
      buildDbOpContext('prod', { sql: `SELECT '${verifier}' AS h` }),
    );
    expect(envelope.ok).toBe(true);
    expect(JSON.stringify(envelope)).not.toContain('c3RvcmVka2V5');
  }, 30_000);

  test('P10 LEAK: env keys never turns a line of a multi-line value into a key (scrubber off)', async () => {
    const spies = scrubberOff();
    try {
      const keys = await run('env', 'keys', { alias: ALIAS, args: { path: `${ROOT}/multi.env` } });
      const againstPath = join(scratch, 'reference.env');
      writeFileSync(againstPath, 'LAST=\n');
      const diff = await run('env', 'diff', {
        alias: ALIAS,
        args: { path: `${ROOT}/multi.env`, against: againstPath },
      });
      expect(keys.ok).toBe(true);
      expect(diff.ok).toBe(true);
      expect(JSON.stringify(keys).includes(CANARY)).toBe(false);
      expect(JSON.stringify(diff).includes(CANARY)).toBe(false);
    } finally {
      for (const spy of spies) {
        spy.mockRestore();
      }
    }
  }, 30_000);

  test('P10 BUG: env keys reports a KEY = value line, as env diff --against reads one', async () => {
    const keys = await run('env', 'keys', { alias: ALIAS, args: { path: `${ROOT}/multi.env` } });
    expect((keys.data as { key: string }[]).map((entry) => entry.key)).toContain('SPACED');
  }, 30_000);

  test('P10 LEAK: files grep masks a .env under a dated directory (rel-2026-11/.env)', async () => {
    const envelope = await run('files', 'grep', {
      alias: ALIAS,
      args: { path: ROOT, pattern: 'NOTE' },
    });
    expect(envelope.ok).toBe(true);
    expect(JSON.stringify(envelope).includes(CANARY)).toBe(false);
  }, 30_000);

  test('P10 LEAK: files grep masks PEM body lines in a file not named like a key', async () => {
    const envelope = await run('files', 'grep', {
      alias: ALIAS,
      args: { path: `${ROOT}/sub`, pattern: 'BEGIN|^[A-Za-z0-9]{20}' },
    });
    expect(envelope.ok).toBe(true);
    expect(JSON.stringify(envelope).includes(CANARY)).toBe(false);
  }, 30_000);
});

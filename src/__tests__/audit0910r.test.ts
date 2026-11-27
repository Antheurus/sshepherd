import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertNoMultiStatementSql, assertSelfContainedSql } from '../db.ts';
import { executeOp, getOp } from '../registry.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner } from '../transport.ts';
import type { Envelope, OpContext } from '../types.ts';

/**
 * Re-audit of Block 8 part b fix B (27f8ab7). Every test here is red on 27f8ab7 by design: one per
 * new or persisting receipt finding. The scanner test runs anywhere; the rest need the smoke
 * fixture (SSHEPHERD_SMOKE_PROJECT picks it).
 */

describe('re-audit 0910: assertSelfContainedSql lexing', () => {
  test('an E-string continued on the next line lexes with E rules, so a `)` it hides is seen', () => {
    // Postgres continues E'a' into the next quoted segment with backslash escapes, so `\'` is a
    // quote character and the segment ends at the next quote, leaving `) sshepherd_q) x` as code.
    const sql =
      "SELECT id, E'a'\n'\\'' AS z FROM big) sshepherd_q) x, LATERAL (SELECT x.* FROM (SELECT 1 -- '";
    expect(() => assertSelfContainedSql(sql)).toThrow();
  });

  // Fix C: the auditor's held probes, refused and accepted, plus every E-string continuation form.
  const ESCAPE_TAIL = "\\'' AS z FROM big) sshepherd_q) x, LATERAL (SELECT x.* FROM (SELECT 1 -- '";
  const REFUSED: [string, string][] = [
    ['unclosed $q$', 'SELECT $q$ ) sshepherd_q) x'],
    ['nested-comment escape', 'SELECT 1 /* a /* b */ c */ ) sshepherd_q) x, (SELECT (SELECT 1'],
    ["U&'\\' ) '", "SELECT U&'\\' ) '"],
    ['-- comment ended by a bare \\r', 'SELECT 1 --x\r) sshepherd_q) x, (SELECT (SELECT 1'],
    ['E continuation after \\n', `SELECT E'a'\n'${ESCAPE_TAIL}`],
    ['E continuation after a -- comment', `SELECT E'a' -- c\n'${ESCAPE_TAIL}`],
    ['E continuation after a comment line', `SELECT E'a'\n-- c\n  '${ESCAPE_TAIL}`],
    ['E continuation after a bare \\r', `SELECT E'a'\r'${ESCAPE_TAIL}`],
    ['lower-case e continuation', `SELECT e'a'\n'${ESCAPE_TAIL}`],
    ['E continuation after \\t\\f\\v and \\r\\n', `SELECT E'a' \t\r\n\f\v'${ESCAPE_TAIL}`],
  ];
  for (const [label, sql] of REFUSED) {
    test(`refused: ${label}`, () => {
      expect(() => assertSelfContainedSql(sql)).toThrow();
    });
  }

  test('refused: any ; at all, even inside a string', () => {
    for (const sql of ['SELECT 1;', "SELECT ';'", 'SELECT 1; SELECT 2', 'SELECT 1 -- ;']) {
      expect(() => assertNoMultiStatementSql(sql)).toThrow();
    }
  });

  const ACCEPTED: [string, string][] = [
    ['$$ ) ( $$', 'SELECT $$ ) ( $$'],
    ['$t$ tagged', 'SELECT $t$ ) ( $t$ AS v'],
    ['nested /* /* ) */ ) */', 'SELECT 1 /* /* ) */ ) */'],
    ["E'\\' ) x'", "SELECT E'\\' ) x'"],
    ["U&'d\\0061t...'", "SELECT U&'d\\0061t\\+000061'"],
    ['quoted identifier with parens', 'SELECT 1 AS "a(b)c)"'],
    ['trailing --x\\r\\n', 'SELECT 1 --x\r\n'],
    ['E continuation that stays a string', "SELECT E'a'\n'b\\' ) c'"],
    ['standard string, then a new line', "SELECT 'a'\n'\\'"],
    ['E string then a block comment then a string', "SELECT (E'a' /* x */)"],
  ];
  for (const [label, sql] of ACCEPTED) {
    test(`accepted: ${label}`, () => {
      expect(() => assertSelfContainedSql(sql)).not.toThrow();
    });
  }
});

const REPO = join(import.meta.dir, '..', '..');
const ALIAS = 'smoke-debian';
const ROOT = '/opt/audit0910r';

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
const UNDECLARED = `${PREFIX}-noisy`;
const SSH_CONFIG = join(STATE, 'ssh_config');
const CANARY = `Rr${randomBytes(12).toString('hex')}`;

function running(name: string): boolean {
  const proc = Bun.spawnSync(['docker', 'inspect', '-f', '{{.State.Running}}', name], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const fixtureUp = (): boolean =>
  existsSync(SSH_CONFIG) && running(SSHD) && running(POSTGRES) && running(UNDECLARED);

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

const MULTI_ENV = `SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1r\\n%sml==\\n-----END OPENSSH PRIVATE KEY-----"\\nLAST=ok\\n`;

describe.skipIf(!fixtureUp())('re-audit 0910: fix B residue (smoke fixture)', () => {
  beforeAll(() => {
    for (const key of SAVED) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit0910r-'));
    writeFileSync(
      join(scratch, 'targets.toml'),
      `[prod]\nalias = "${ALIAS}"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
    );
    writeFileSync(
      join(scratch, 'files-allowlist.toml'),
      `[${ALIAS}]\npaths = ["${ROOT}", "${ROOT}/backup.txt", "${ROOT}/multi.env"]\n`,
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
        `mkdir -p ${ROOT}`,
        `printf 'tls key backup\\n-----BEGIN RSA PRIVATE KEY-----\\nMIIEow%sbk\\n-----END RSA PRIVATE KEY-----\\n' "$1" > ${ROOT}/backup.txt`,
        `printf '${MULTI_ENV}' "$1" > ${ROOT}/multi.env`,
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

  test('db query: the E-string continuation cannot carry the SELECT past the server-side LIMIT', async () => {
    const escaped = await run(
      'db',
      'query',
      buildDbOpContext('prod', {
        sql: "SELECT id, repeat('x', 5000) AS pad, E'a'\n'\\'' AS z FROM big) sshepherd_q) x, LATERAL (SELECT x.* FROM (SELECT 1 -- '",
        'max-rows': '1',
      }),
    );
    expect(escaped.error?.code).toBe('VALIDATION_ERROR');
  }, 60_000);

  test('files grep: a pattern matching only a PEM body line returns it masked', async () => {
    const envelope = await run('files', 'grep', {
      alias: ALIAS,
      args: { path: ROOT, pattern: 'bk$' },
    });
    expect(envelope.ok).toBe(true);
    expect(JSON.stringify(envelope).includes(CANARY)).toBe(false);
  }, 30_000);

  test('files head/tail/cat --lines: a range inside a PEM block returns it masked', async () => {
    for (const op of ['head', 'tail', 'cat']) {
      const envelope = await run('files', op, {
        alias: ALIAS,
        args: { path: `${ROOT}/backup.txt`, lines: '3:3' },
      });
      expect(envelope.ok).toBe(true);
      expect(`${op}:${JSON.stringify(envelope).includes(CANARY)}`).toBe(`${op}:false`);
    }
  }, 60_000);

  test('env diff --against: a local copy of the same multi-line file reports no key missing', async () => {
    const remote = Bun.spawnSync(['docker', 'exec', SSHD, 'cat', `${ROOT}/multi.env`], {
      stdout: 'pipe',
    });
    const against = join(scratch, 'same.env');
    writeFileSync(against, remote.stdout.toString());
    const diff = await run('env', 'diff', {
      alias: ALIAS,
      args: { path: `${ROOT}/multi.env`, against },
    });
    expect(diff.ok).toBe(true);
    expect((diff.data as { missing: string[] }).missing).toEqual([]);
    expect(JSON.stringify(diff).includes(CANARY)).toBe(false);
  }, 30_000);

  test('services inspect: env key names of a container env keys --container refuses stay gated', async () => {
    const keys = await run('env', 'keys', { alias: ALIAS, args: { container: UNDECLARED } });
    expect(keys.error?.code).toBe('VALIDATION_ERROR');
    const inspect = await run('services', 'inspect', {
      alias: ALIAS,
      args: { container: UNDECLARED },
    });
    const env = (inspect.data as { env?: unknown }[] | null)?.[0]?.env;
    expect(Array.isArray(env) && env.length > 0).toBe(false);
  }, 30_000);

  test('N5 (ruling A5): a containers-only table gates env keys and never breaks the db targets', async () => {
    const path = join(scratch, 'targets-apponly.toml');
    writeFileSync(
      path,
      `[prod]\nalias = "${ALIAS}"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n[apponly]\nalias = "smoke-alpine"\ncontainers = ["${PREFIX}-app"]\n`,
    );
    const before = process.env.SSHEPHERD_TARGETS_PATH;
    process.env.SSHEPHERD_TARGETS_PATH = path;
    try {
      const keys = await run('env', 'keys', {
        alias: 'smoke-alpine',
        args: { container: `${PREFIX}-app` },
      });
      expect(keys.ok).toBe(true);
      const list = await run('db', 'list', { alias: '', args: {} });
      expect((list.data as { targets: string[] }).targets).toEqual(['prod']);
      expect(() => buildDbOpContext('apponly', { sql: 'SELECT 1' })).toThrow(
        /declares only containers/,
      );
      const query = await run('db', 'query', buildDbOpContext('prod', { sql: 'SELECT 1 AS one' }));
      expect(query.ok).toBe(true);
    } finally {
      process.env.SSHEPHERD_TARGETS_PATH = before;
      await closeMaster('smoke-alpine');
    }
  }, 60_000);
});

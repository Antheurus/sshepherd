import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertSelfContainedSql } from '../db.ts';
import { executeOp, getOp } from '../registry.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner } from '../transport.ts';
import type { Envelope, OpContext } from '../types.ts';

/**
 * Re-audit of Block 8 fix C2 (1407901): attacks on the E-string continuation lexer, the PEM
 * marker transfer for files grep / head|tail --lines, env diff --against, services inspect's env
 * gate and the A5 containers-only tables. Live tests need the smoke fixture.
 */

const REPO = join(import.meta.dir, '..', '..');
const ROOT = '/opt/audit0910c';

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
const HOSTS = {
  'smoke-debian': `${PREFIX}-sshd-debian`,
  'smoke-alpine': `${PREFIX}-sshd-alpine`,
} as const;
const POSTGRES = `${PREFIX}-postgres`;
const APP = `${PREFIX}-app`;
const UNDECLARED = `${PREFIX}-noisy`;
const SSH_CONFIG = join(STATE, 'ssh_config');
const CANARY = `Cc${randomBytes(12).toString('hex')}`;
const B64 = 'MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV9ffLB5yvH';

function running(name: string): boolean {
  const proc = Bun.spawnSync(['docker', 'inspect', '-f', '{{.State.Running}}', name], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const fixtureUp = (): boolean =>
  existsSync(SSH_CONFIG) &&
  Object.values(HOSTS).every(running) &&
  running(POSTGRES) &&
  running(APP) &&
  running(UNDECLARED);

function onHost(container: string, script: string): void {
  const proc = Bun.spawnSync(
    ['docker', 'exec', '-i', container, 'sh', '-c', script, 'sh', CANARY],
    {
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
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

async function run(
  group: string,
  name: string,
  ctx: OpContext,
  maxBytes?: number,
): Promise<Envelope<unknown>> {
  const op = getOp(group, name);
  if (op === undefined) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(op, ctx, {
    transport: { runner: defaultRunner, sshConfigPath: SSH_CONFIG },
    sshConfigPath: SSH_CONFIG,
    auditLogPath: join(scratch, 'audit.jsonl'),
    ...(maxBytes !== undefined ? { maxBytes } : {}),
  });
}

const leaks = (envelope: Envelope<unknown>): boolean => JSON.stringify(envelope).includes(CANARY);
/** The tags (the suffix after the canary) of every line that came back unmasked. */
const leakTags = (envelope: Envelope<unknown>): string[] =>
  [...JSON.stringify(envelope).matchAll(new RegExp(`${CANARY}([a-z0-9]{0,3})`, 'g'))].map(
    (m) => m[1] ?? '',
  );

const BEGIN = '-----BEGIN RSA PRIVATE KEY-----';
const END = '-----END RSA PRIVATE KEY-----';
const CERT_B = '-----BEGIN CERTIFICATE-----';
const CERT_E = '-----END CERTIFICATE-----';

/** File contents written over stdin (dash printf refuses a format starting with `-`). */
const FILES: Record<string, string> = {
  // L1: a NUL byte on line 1 (grep -I sees a binary file); the body is line 4.
  'nul.txt': `x\0y\n${BEGIN}\n${B64}\n${CANARY}nl\n${END}\n`,
  // L2: cert + key + cert concatenated with no trailing newlines; the key body is line 4.
  'bundle.txt': `${CERT_B}\nMIIBcertAAAA\n${CERT_E}${BEGIN}\n${CANARY}cb\n${END}${CERT_B}\nMIIBcertBBBB\n${CERT_E}\n`,
  // L3: the file ends inside a key body (no END line); body lines 3-4.
  'tailbody.txt': `intro\n${BEGIN}\n${B64}\n${CANARY}tb\n`,
  // L3: END carries trailing text; body lines 3-4.
  'endnote.txt': `intro\n${BEGIN}\n${B64}\n${CANARY}en\n${END} rotated\n`,
  // CRLF markers; body line 3.
  'crlf.txt': `a\r\n${BEGIN}\r\n${CANARY}cr\r\n${END}\r\n`,
  // END before BEGIN, body on both sides.
  'endfirst.txt': `${END}\n${CANARY}ef1\n${BEGIN}\n${CANARY}ef2\n${END}\n`,
  // 300 certificate blocks (600 markers, past the 256 cap), then a key whose body ends "mm".
  'many.txt': `${`${CERT_B}\nMIIBcert\n${CERT_E}\n`.repeat(300)}plain line kept\n${BEGIN}\n${CANARY}mm\n${END}\n`,
  // A front-cut tail --lines: 300 filler lines, a key whose 50 body lines end "zz" and whose END
  // carries text, then ~2 MiB of filler so the kept last 2 MiB starts inside the body.
  'cut.txt': `${`${'f'.repeat(1499)}\n`.repeat(300)}${BEGIN}\n${`${CANARY}zz${'A'.repeat(36)}\n`.repeat(50)}${END} rotated\n${`${'g'.repeat(1499)}\n`.repeat(1396)}${'h'.repeat(1399)}\n`,
  // env shapes: export, CRLF, spaced, escaped quotes, a multi-line value holding KEY= lines.
  'shapes.env': `export A_ONE=1\r\nB_TWO = two\nC_ML="first\nFAKE_INSIDE=${CANARY}\nlast"\nD_ESC="a\\"b"\n# E_COMMENT=x\nF_SQ=${CANARY}q\nG_LAST=ok\n`,
};

function putFile(container: string, path: string, content: string): void {
  const proc = Bun.spawnSync(
    ['docker', 'exec', '-i', container, 'sh', '-c', 'cat > "$1"', 'sh', path],
    {
      stdin: Buffer.from(content, 'utf8'),
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
  if (proc.exitCode !== 0) {
    throw new Error(`fixture write failed: ${proc.stderr.toString().slice(-300)}`);
  }
}

describe('re-audit 0910c: lexer forms (no fixture)', () => {
  const TAIL = "\\'' AS z FROM big) sshepherd_q) x, LATERAL (SELECT x.* FROM (SELECT 1 -- '";
  for (const open of ["E'a'", "e'a'"]) {
    for (const sep of [
      '\n',
      '\r\n',
      '\r',
      ' --c\n',
      '\n--c\n',
      '\t\f\n',
      '\n\t\f ',
      '\r\n--c\r\n ',
    ]) {
      test(`refused: ${JSON.stringify(open + sep)}`, () => {
        expect(() => assertSelfContainedSql(`SELECT ${open}${sep}'${TAIL}`)).toThrow();
      });
    }
  }
});

describe.skipIf(!fixtureUp())('re-audit 0910c: live attacks (smoke fixture)', () => {
  beforeAll(() => {
    for (const key of SAVED) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-audit0910c-'));
    writeFileSync(
      join(scratch, 'targets.toml'),
      `[prod]\nalias = "smoke-debian"\ncontainer = "${POSTGRES}"\nuser = "sshepherd_ro"\ndatabase = "fixture"\ncontainers = ["${APP}"]\n[apponly]\nalias = "smoke-alpine"\ncontainers = ["${APP}"]\n`,
    );
    const paths = [ROOT, ...Object.keys(FILES).map((f) => `${ROOT}/${f}`)];
    const quoted = paths.map((p) => `"${p}"`).join(', ');
    writeFileSync(
      join(scratch, 'files-allowlist.toml'),
      `[smoke-debian]\npaths = [${quoted}]\n[smoke-alpine]\npaths = [${quoted}]\n`,
    );
    process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
    process.env.SSHEPHERD_SSH_CONFIG_PATH = SSH_CONFIG;
    process.env.SSHEPHERD_STATE_DIR = scratch;
    process.env.XDG_RUNTIME_DIR = join(STATE, 'run');
    for (const container of Object.values(HOSTS)) {
      onHost(container, `rm -rf ${ROOT}; mkdir -p ${ROOT}`);
      for (const [name, content] of Object.entries(FILES)) {
        putFile(container, `${ROOT}/${name}`, content);
      }
    }
  });

  afterAll(async () => {
    for (const container of Object.values(HOSTS)) {
      onHost(container, `rm -rf ${ROOT}`);
    }
    for (const alias of Object.keys(HOSTS)) {
      await closeMaster(alias);
    }
    for (const key of SAVED) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    }
    rmSync(scratch, { recursive: true, force: true });
  });

  for (const alias of Object.keys(HOSTS)) {
    test(`[${alias}] L1: head/tail --lines on a key body in a file with a NUL byte comes back masked`, async () => {
      const out: string[] = [];
      for (const op of ['head', 'tail', 'cat']) {
        const envelope = await run('files', op, {
          alias,
          args: { path: `${ROOT}/nul.txt`, lines: '4:4' },
        });
        out.push(`${op}:${envelope.ok}:${leaks(envelope)}`);
      }
      expect(out).toEqual(['head:true:false', 'tail:true:false', 'cat:true:false']);
    }, 60_000);

    test(`[${alias}] L2: a key BEGIN joined to a cert END on one line still masks the body (grep, --lines)`, async () => {
      const out: string[] = [];
      const grep = await run('files', 'grep', { alias, args: { path: ROOT, pattern: 'cb$' } });
      out.push(`grep:${grep.ok}:${leaks(grep)}`);
      for (const op of ['head', 'tail', 'cat']) {
        const envelope = await run('files', op, {
          alias,
          args: { path: `${ROOT}/bundle.txt`, lines: '4:4' },
        });
        out.push(`${op}:${envelope.ok}:${leaks(envelope)}`);
      }
      const whole = await run('files', 'cat', { alias, args: { path: `${ROOT}/bundle.txt` } });
      out.push(`cat-whole:${whole.ok}:${leaks(whole)}`);
      expect(out).toEqual([
        'grep:true:false',
        'head:true:false',
        'tail:true:false',
        'cat:true:false',
        'cat-whole:true:false',
      ]);
    }, 60_000);

    test(`[${alias}] L3: plain tail -n inside a key body (no END / END with trailing text) comes back masked`, async () => {
      const out: string[] = [];
      for (const [file, n] of [
        ['tailbody.txt', '2'],
        ['endnote.txt', '3'],
        ['bundle.txt', '4'],
      ] as const) {
        const envelope = await run('files', 'tail', {
          alias,
          args: { path: `${ROOT}/${file}`, n },
        });
        out.push(`${file}:${envelope.ok}:${leaks(envelope)}`);
      }
      expect(out).toEqual([
        'tailbody.txt:true:false',
        'endnote.txt:true:false',
        'bundle.txt:true:false',
      ]);
    }, 60_000);

    test(`[${alias}] markers past the cap mask every returned line; crafted marker orders still mask`, async () => {
      const out: string[] = [];
      const grep = await run('files', 'grep', {
        alias,
        args: { path: ROOT, pattern: 'mm$|kept$|cr.$|ef2$' },
      });
      out.push(`grep:${grep.ok}:${leaks(grep)}`);
      const kept = ((grep.data as { lines?: string[] } | null)?.lines ?? []).filter((l) =>
        l.includes('plain line kept'),
      );
      out.push(`many-kept-visible:${kept.length}`);
      for (const op of ['head', 'tail']) {
        const envelope = await run('files', op, {
          alias,
          args: { path: `${ROOT}/many.txt`, lines: '900:903' },
        });
        const lines = (envelope.data as { lines?: string[] } | null)?.lines ?? [];
        out.push(`${op}:${envelope.ok}:${leaks(envelope)}:${lines.length}:${lines[1]}:${lines[3]}`);
      }
      for (const [file, lines] of [
        ['crlf.txt', '3:3'],
        ['endfirst.txt', '2:4'],
      ] as const) {
        for (const op of ['head', 'tail', 'cat']) {
          const envelope = await run('files', op, {
            alias,
            args: { path: `${ROOT}/${file}`, lines },
          });
          // ef1 follows an END and opens nothing, so it is prose; only ef2 sits inside a block.
          const inBlock = leakTags(envelope).filter((tag) => tag !== 'ef1');
          out.push(`${file}:${op}:${envelope.ok}:${inBlock.length > 0}`);
        }
      }
      // 600 certificate markers are one secret range (the key), far under MAX_PEM_SECRET_RANGES: the
      // key body is masked, and the prose line before it stays visible.
      expect(out).toEqual([
        'grep:true:false',
        'many-kept-visible:1',
        'head:true:false:4:plain line kept:***',
        'tail:true:false:4:plain line kept:***',
        'crlf.txt:head:true:false',
        'crlf.txt:tail:true:false',
        'crlf.txt:cat:true:false',
        'endfirst.txt:head:true:false',
        'endfirst.txt:tail:true:false',
        'endfirst.txt:cat:true:false',
      ]);
    }, 120_000);
  }

  for (const alias of Object.keys(HOSTS) as (keyof typeof HOSTS)[]) {
    test(`[${alias}] env diff --against: CRLF, export, spaced, escaped-quote and multi-line shapes agree both sides`, async () => {
      const remote = Bun.spawnSync(['docker', 'exec', HOSTS[alias], 'cat', `${ROOT}/shapes.env`], {
        stdout: 'pipe',
      });
      const same = join(scratch, `same-${alias}.env`);
      writeFileSync(same, remote.stdout);
      const diff = await run('env', 'diff', {
        alias,
        args: { path: `${ROOT}/shapes.env`, against: same },
      });
      const minus = join(scratch, `minus-${alias}.env`);
      writeFileSync(
        minus,
        remote.stdout
          .toString()
          .split('\n')
          .filter((l) => !l.startsWith('G_LAST'))
          .join('\n'),
      );
      const diff2 = await run('env', 'diff', {
        alias,
        args: { path: `${ROOT}/shapes.env`, against: minus },
      });
      const keys = await run('env', 'keys', { alias, args: { path: `${ROOT}/shapes.env` } });
      expect({
        same: diff.data,
        minus: diff2.data,
        keys: ((keys.data as { key: string }[] | null) ?? []).map((k) => k.key).sort(),
        leak: leaks(diff) || leaks(diff2) || leaks(keys),
      }).toEqual({
        same: expect.objectContaining({ missing: [] }),
        minus: expect.objectContaining({ missing: [] }),
        keys: ['A_ONE', 'B_TWO', 'C_ML', 'D_ESC', 'F_SQ', 'G_LAST'],
        leak: false,
      });
    }, 60_000);
  }

  test('services inspect: declared container keeps env, undeclared and an alias with no table get none', async () => {
    const declared = await run('services', 'inspect', {
      alias: 'smoke-debian',
      args: { container: APP },
    });
    const undeclared = await run('services', 'inspect', {
      alias: 'smoke-debian',
      args: { container: UNDECLARED },
    });
    const envOf = (e: Envelope<unknown>): number =>
      ((e.data as { env?: unknown[] }[] | null)?.[0]?.env ?? []).length;
    expect({
      declaredOk: declared.ok,
      declaredEnv: envOf(declared) > 0,
      undeclaredOk: undeclared.ok,
      undeclaredEnv: envOf(undeclared),
    }).toEqual({ declaredOk: true, declaredEnv: true, undeclaredOk: true, undeclaredEnv: 0 });
  }, 60_000);

  test('A5: mixed targets - db list, db ops and ro-role refuse the containers-only table only', async () => {
    const list = await run('db', 'list', { alias: '', args: {} });
    expect((list.data as { targets: string[] }).targets).toEqual(['prod']);
    expect(() => buildDbOpContext('apponly', { sql: 'SELECT 1' })).toThrow(
      /declares only containers/,
    );
    const ok = await run(
      'db',
      'query',
      buildDbOpContext('prod', { sql: 'SELECT count(*) AS n FROM big' }),
    );
    expect(ok.ok).toBe(true);
    const keys = await run('env', 'keys', { alias: 'smoke-alpine', args: { container: APP } });
    expect(keys.ok).toBe(true);
  }, 60_000);

  test('db query differential: no quoting form carries the SELECT past --max-rows 1', async () => {
    const opens = ["E'a'", "e'a'", "U&'a'", "B'1'", "X'1F'", "N'a'", "'a'", '$$a$$', '$q$a$q$'];
    const seps = [
      '\n',
      '\r\n',
      '\r',
      ' --c\n',
      '\n--c\n',
      '\t\f\n',
      '\v\n',
      '\n\v',
      '\f\r\n\t',
      ' /*c*/\n',
      '\n/*c*/',
    ];
    const tail = "\\'' AS z FROM big) sshepherd_q) x, LATERAL (SELECT x.* FROM (SELECT 1 -- '";
    const bad: string[] = [];
    const tally: Record<string, number> = {};
    for (const open of opens) {
      for (const sep of seps) {
        const sql = `SELECT id, repeat('x', 5000) AS pad, ${open}${sep}'${tail}`;
        const envelope = await run(
          'db',
          'query',
          buildDbOpContext('prod', { sql, 'max-rows': '1' }),
        );
        const rows = (envelope.data as { row_count?: number } | null)?.row_count ?? 0;
        const verdict = envelope.ok ? `ok:${rows}` : (envelope.error?.code ?? 'unknown');
        tally[verdict] = (tally[verdict] ?? 0) + 1;
        if ((envelope.ok && rows > 1) || envelope.error?.code === 'OUTPUT_TOO_LARGE') {
          bad.push(`${JSON.stringify(open + sep)} -> ${verdict}`);
        }
      }
    }
    console.log(`differential tally ${JSON.stringify(tally)}`);
    const legit = await run(
      'db',
      'query',
      buildDbOpContext('prod', { sql: "SELECT E'it\\'s'\n' continued\\' ) here' AS v" }),
    );
    expect({ bad, legit: legit.ok }).toEqual({ bad: [], legit: true });
  }, 300_000);
  test.skipIf(process.env.A0910C_DIAG !== '1')(
    'which tags leak',
    async () => {
      const table: string[] = [];
      const cases: [string, string, Record<string, string>][] = [];
      for (const alias of Object.keys(HOSTS)) {
        for (const op of ['head', 'tail', 'cat']) {
          cases.push([alias, op, { path: `${ROOT}/nul.txt`, lines: '4:4' }]);
          cases.push([alias, op, { path: `${ROOT}/bundle.txt`, lines: '4:4' }]);
          cases.push([alias, op, { path: `${ROOT}/endfirst.txt`, lines: '2:4' }]);
          cases.push([alias, op, { path: `${ROOT}/endfirst.txt`, lines: '4:4' }]);
        }
        cases.push([alias, 'grep', { path: ROOT, pattern: 'cb$' }]);
        cases.push([alias, 'grep', { path: ROOT, pattern: 'ef2$' }]);
        cases.push([alias, 'grep', { path: ROOT, pattern: 'nl$' }]);
        cases.push([alias, 'tail', { path: `${ROOT}/tailbody.txt`, n: '2' }]);
        cases.push([alias, 'tail', { path: `${ROOT}/endnote.txt`, n: '3' }]);
        cases.push([alias, 'tail', { path: `${ROOT}/bundle.txt`, n: '4' }]);
        cases.push([alias, 'head', { path: `${ROOT}/tailbody.txt`, lines: '3:4' }]);
        cases.push([alias, 'head', { path: `${ROOT}/endnote.txt`, lines: '3:4' }]);
      }
      for (const [alias, op, args] of cases) {
        const e = await run('files', op, { alias, args });
        table.push(
          `${alias} ${op} ${JSON.stringify(args).replace(ROOT, '')} ok=${e.ok} leaked=${JSON.stringify(leakTags(e))}`,
        );
      }
      console.log(table.join('\n'));
    },
    300_000,
  );
  test('tail --lines whose stream is cut from the front keeps the key body masked (both hosts)', async () => {
    const out: string[] = [];
    for (const alias of Object.keys(HOSTS)) {
      for (const op of ['tail', 'head', 'cat']) {
        const envelope = await run(
          'files',
          op,
          { alias, args: { path: `${ROOT}/cut.txt`, lines: '1:1749' } },
          2 * 1024 * 1024,
        );
        const tags = leakTags(envelope);
        const truncated = JSON.stringify(envelope).includes('"truncated":true');
        out.push(`${alias}:${op}:${envelope.ok}:leaked=${tags.length}`);
        const d = envelope.data as { lines?: string[]; lines_returned?: number } | null;
        const ls = d?.lines ?? [];
        const firstReal = ls.findIndex((l) => l.startsWith('g'));
        const begin = ls.findIndex((l) => l.startsWith('-----BEGIN'));
        console.log(
          `cutdetail ${alias} ${op} returned=${ls.length} masked=${ls.filter((l) => l === '***').length} firstG=${firstReal} begin=${begin} trunc=${JSON.stringify((envelope as unknown as { output_truncated?: unknown }).output_truncated)} first=${(ls[0] ?? '').slice(0, 3)} keys=${Object.keys(envelope).join(',')} dkeys=${Object.keys(d ?? {}).join(',')}`,
        );
        console.log(
          `cut ${alias} ${op} ok=${envelope.ok} code=${envelope.error?.code ?? '-'} leaked=${tags.length} truncatedFlag=${truncated}`,
        );
      }
    }
    expect(out.every((row) => row.endsWith('leaked=0'))).toBe(true);
  }, 120_000);
});

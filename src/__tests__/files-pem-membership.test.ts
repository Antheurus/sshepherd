import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_PEM_SECRET_RANGES } from '../limits.ts';
import { executeOp, getOp } from '../registry.ts';
import { closeMaster, defaultRunner, type SpawnOutcome, type SshRunner } from '../transport.ts';
import type { Envelope, OpContext } from '../types.ts';

/**
 * PEM membership for files head|tail|grep|cat: decided on the host from the whole file, one pass.
 * The local half runs the real remote script through this machine's `sh` and feeds what it prints
 * to the op; the live half drives both smoke-fixture hosts.
 */

const REPO = join(import.meta.dir, '..', '..');
const CANARY = `Cc${randomBytes(12).toString('hex')}`;
const B64 = 'MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV9ffLB5yvH';
const BEGIN = `-----BEGIN RSA ${'PRIVATE'} KEY-----`;
const END = `-----END RSA ${'PRIVATE'} KEY-----`;
const CERT_B = '-----BEGIN CERTIFICATE-----';
const CERT_E = '-----END CERTIFICATE-----';

const leaks = (envelope: Envelope<unknown>): boolean => JSON.stringify(envelope).includes(CANARY);
const linesOf = (envelope: Envelope<unknown>): string[] =>
  (envelope.data as { lines?: string[] } | null)?.lines ?? [];

/** A cert bundle of `n` certificates (2n markers), each body tagged with its index. */
const certs = (n: number, tag: string): string =>
  Array.from({ length: n }, (_, i) => `${CERT_B}\nMIIBcert${tag}${i}\n${CERT_E}\n`).join('');

describe('PEM membership through a real sh (no fixture)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-pem-membership-'));
  const alias = 'web-01';
  const saved = process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;

  beforeAll(() => {
    writeFileSync(join(dir, 'files-allowlist.toml'), `[${alias}]\npaths = ["${dir}"]\n`);
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(dir, 'files-allowlist.toml');
  });

  afterAll(() => {
    if (saved === undefined) {
      delete process.env.SSHEPHERD_FILES_ALLOWLIST_PATH;
    } else {
      process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = saved;
    }
    rmSync(dir, { recursive: true, force: true });
  });

  /** Runs the op with its remote command executed by a local `sh -c`; `cut` drops that many bytes
   *  from the front of what it printed, as a transport front cut would. */
  async function local(
    name: string,
    args: Record<string, string>,
    cut = 0,
  ): Promise<Envelope<unknown>> {
    const op = getOp('files', name);
    if (op === undefined) {
      throw new Error(`files ${name} missing`);
    }
    const ctx: OpContext = { alias, args };
    writeFileSync(
      join(dir, 'files-allowlist.toml'),
      `[${alias}]\npaths = [${JSON.stringify(dir)}, ${JSON.stringify(args.path ?? dir)}]\n`,
    );
    const remote = op.buildRemote(ctx);
    if (remote === null) {
      throw new Error('expected a remote command');
    }
    const printed = Bun.spawnSync(['sh', '-c', remote], { stdout: 'pipe', stderr: 'pipe' }).stdout;
    const stdout = printed.subarray(cut).toString('utf8');
    const outcomes: SpawnOutcome[] = [
      { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
      { code: 0, stdout: '', stderr: '', timedOut: false },
      { code: 0, stdout, stderr: '', timedOut: false },
    ];
    let index = 0;
    const runner: SshRunner = async () => {
      const outcome = outcomes[Math.min(index, outcomes.length - 1)];
      index += 1;
      return outcome as SpawnOutcome;
    };
    return executeOp(op, ctx, { transport: { runner }, auditLogPath: join(dir, 'audit.jsonl') });
  }

  test('past MAX_PEM_SECRET_RANGES key blocks every returned line of the file is masked', async () => {
    const block = `${BEGIN}\n${CANARY}ov\n${END}\n`;
    writeFileSync(join(dir, 'over.txt'), `${block.repeat(MAX_PEM_SECRET_RANGES + 1)}last line\n`);
    writeFileSync(join(dir, 'at.txt'), `${block.repeat(MAX_PEM_SECRET_RANGES)}last line\n`);
    const over = await local('tail', { path: join(dir, 'over.txt'), n: '2' });
    const at = await local('tail', { path: join(dir, 'at.txt'), n: '2' });
    expect({
      over: linesOf(over),
      at: linesOf(at),
      leak: leaks(over) || leaks(at),
    }).toEqual({ over: ['***', '***'], at: [END, 'last line'], leak: false });
  });

  test('tail --lines cut from the front is numbered back from its last line, so the body stays masked', async () => {
    const filler = Array.from({ length: 10 }, (_, i) => `filler ${i}`).join('\n');
    const trailer = Array.from({ length: 6 }, (_, i) => `after ${i}`).join('\n');
    // The END carries trailing text, so nothing but the file's own numbering can place line 13.
    const body = `${filler}\n${BEGIN}\n${B64}\n${CANARY}fc\n${END} rotated\n${trailer}\n`;
    writeFileSync(join(dir, 'front.txt'), body);
    // Cut after line 12 (the first body line), as the transport leaves it once it drops the partial
    // first line: what is left starts at line 13, the second body line.
    const cut = Buffer.byteLength(`${filler}\n${BEGIN}\n${B64}\n`);
    const envelope = await local('tail', { path: join(dir, 'front.txt'), lines: '1:20' }, cut);
    expect({ lines: linesOf(envelope), leak: leaks(envelope) }).toEqual({
      lines: [
        '***',
        `${END} rotated`,
        'after 0',
        'after 1',
        'after 2',
        'after 3',
        'after 4',
        'after 5',
      ],
      leak: false,
    });
  });

  test('a cert bundle with a key keeps every certificate body and masks only the key', async () => {
    writeFileSync(
      join(dir, 'bundle.txt'),
      `${certs(2, 'L')}${BEGIN}\n${B64}\n${CANARY}lb\n${END}\n${certs(2, 'M')}`,
    );
    const path = join(dir, 'bundle.txt');
    const head = linesOf(await local('head', { path, n: '20' }));
    const tail = linesOf(await local('tail', { path, n: '20' }));
    const cat = await local('cat', { path, lines: '1:16' });
    const content = (cat.data as { content?: string } | null)?.content ?? '';
    expect({
      head: head.filter((l) => l.startsWith('MIIBcert')),
      tail: tail.filter((l) => l.startsWith('MIIBcert')),
      cat: content.split('\n').filter((l) => l.startsWith('MIIBcert')),
      masked: [head, tail].map((lines) => lines.filter((l) => l === '***').length),
      leak: JSON.stringify([head, tail, content]).includes(CANARY),
    }).toEqual({
      head: ['MIIBcertL0', 'MIIBcertL1', 'MIIBcertM0', 'MIIBcertM1'],
      tail: ['MIIBcertL0', 'MIIBcertL1', 'MIIBcertM0', 'MIIBcertM1'],
      cat: ['MIIBcertL0', 'MIIBcertL1', 'MIIBcertM0', 'MIIBcertM1'],
      masked: [2, 2],
      leak: false,
    });
  });

  test('no membership, a broken one, or a line past its count masks every returned line', async () => {
    writeFileSync(join(dir, 'plain.txt'), 'one\ntwo\n');
    const path = join(dir, 'plain.txt');
    const ok = await local('head', { path, lines: '1:2' });
    expect(linesOf(ok)).toEqual(['one', 'two']);
    const op = getOp('files', 'head');
    if (op === undefined) {
      throw new Error('files head missing');
    }
    for (const stdout of [
      'one\ntwo\n',
      'x =2\u0000one\ntwo\n',
      '1-1\u0000one\ntwo\n',
      '=1\u0000one\ntwo\n',
    ]) {
      const shaped = op.shape(stdout, { alias, args: { path, lines: '1:2' } });
      const data =
        (shaped as { data?: { lines: string[] } }).data ?? (shaped as { lines: string[] });
      expect({ stdout, lines: data.lines }).toEqual({
        stdout,
        lines: stdout.startsWith('=1') ? ['one', '***'] : ['***', '***'],
      });
    }
  });
});

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
const SSH_CONFIG = join(STATE, 'ssh_config');
const ROOT = '/opt/pem-membership';

function running(name: string): boolean {
  const proc = Bun.spawnSync(['docker', 'inspect', '-f', '{{.State.Running}}', name], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const fixtureUp = (): boolean => existsSync(SSH_CONFIG) && Object.values(HOSTS).every(running);

/** Each file's key body lines end with a two-letter tag after the canary. */
const FILES: Record<string, string> = {
  // A NUL inside a body line, and a NUL before a BEGIN on its own line (busybox awk ends a string
  // at a NUL, so an unconverted one would hide that BEGIN).
  'nulkey.txt': `intro\n${BEGIN}\n${B64}\n${CANARY}n1\u0000tail\n${END}\n`,
  'nulbegin.txt': `intro\n\u0000${BEGIN}\n${B64}\n${CANARY}n2\n${END}\n`,
  // Three markers on one line: a cert END, the key BEGIN, then a cert BEGIN, which leaves the key
  // block open.
  'three.txt': `${CERT_B}\nMIIBcertAAAA\n${CERT_E}${BEGIN}${CERT_B}\n${CANARY}t3\n${END}\n`,
  // CRLF lines with the key BEGIN joined to a cert END.
  'crlfjoin.txt': `${CERT_B}\r\nMIIBcertCCCC\r\n${CERT_E}${BEGIN}\r\n${B64}\r\n${CANARY}cj\r\n${END}\r\n`,
  // A cert bundle around a key: the cert bodies must stay visible.
  'bundlekey.txt': `${certs(2, 'D')}${BEGIN}\n${B64}\n${CANARY}bk\n${END}\n${certs(2, 'E')}`,
  // 600 certificate markers around one key (lines 451-454).
  'many600.txt': `${certs(150, 'F')}${BEGIN}\n${B64}\n${CANARY}mz\n${END}\n${certs(150, 'G')}`,
};

describe.skipIf(!fixtureUp())('PEM membership on both fixture hosts', () => {
  const SAVED = [
    'SSHEPHERD_FILES_ALLOWLIST_PATH',
    'SSHEPHERD_SSH_CONFIG_PATH',
    'SSHEPHERD_STATE_DIR',
    'XDG_RUNTIME_DIR',
  ] as const;
  const saved: Record<string, string | undefined> = {};
  let scratch = '';

  async function live(alias: string, name: string, args: Record<string, string>) {
    const op = getOp('files', name);
    if (op === undefined) {
      throw new Error(`files ${name} missing`);
    }
    return executeOp(
      op,
      { alias, args },
      {
        transport: { runner: defaultRunner, sshConfigPath: SSH_CONFIG },
        sshConfigPath: SSH_CONFIG,
        auditLogPath: join(scratch, 'audit.jsonl'),
      },
    );
  }

  function onHost(container: string, script: string, stdin?: string): void {
    const proc = Bun.spawnSync(['docker', 'exec', '-i', container, 'sh', '-c', script], {
      ...(stdin === undefined ? {} : { stdin: Buffer.from(stdin, 'utf8') }),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    if (proc.exitCode !== 0) {
      throw new Error(`fixture setup failed: ${proc.stderr.toString().slice(-300)}`);
    }
  }

  beforeAll(() => {
    for (const key of SAVED) {
      saved[key] = process.env[key];
    }
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-pem-membership-live-'));
    const quoted = [ROOT, ...Object.keys(FILES).map((f) => `${ROOT}/${f}`)]
      .map((path) => `"${path}"`)
      .join(', ');
    writeFileSync(
      join(scratch, 'files-allowlist.toml'),
      `[smoke-debian]\npaths = [${quoted}]\n[smoke-alpine]\npaths = [${quoted}]\n`,
    );
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
    process.env.SSHEPHERD_SSH_CONFIG_PATH = SSH_CONFIG;
    process.env.SSHEPHERD_STATE_DIR = scratch;
    process.env.XDG_RUNTIME_DIR = join(STATE, 'run');
    for (const container of Object.values(HOSTS)) {
      onHost(container, `rm -rf ${ROOT}; mkdir -p ${ROOT}`);
      for (const [name, content] of Object.entries(FILES)) {
        onHost(container, `cat > ${ROOT}/${name}`, content);
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

  /** Every read shape over one file, `--lines` around its body line `body`; each row is
   *  `file op args:ok:leaked`. */
  async function drive(alias: string, file: string, body: number, pattern: string) {
    const path = `${ROOT}/${file}`;
    // The line before the body and the body (no END to lean on), then the body and the line after
    // it: a read whose numbering drifts by one returns the body under a number that is not secret.
    const windows = [`${body - 1}:${body}`, `${body}:${body + 1}`];
    const rows: string[] = [];
    const cases: [string, Record<string, string>][] = [
      ...windows.flatMap((lines): [string, Record<string, string>][] => [
        ['head', { path, lines }],
        ['tail', { path, lines }],
        ['cat', { path, lines }],
      ]),
      ['tail', { path, n: '3' }],
      ['head', { path, n: '50' }],
      ['grep', { path: ROOT, pattern }],
    ];
    for (const [name, args] of cases) {
      const envelope = await live(alias, name, args);
      rows.push(
        `${file} ${name} ${args.lines ?? args.n ?? 'grep'}:${envelope.ok}:${leaks(envelope)}`,
      );
    }
    return rows;
  }

  for (const alias of Object.keys(HOSTS)) {
    test(`[${alias}] a NUL byte inside a key file never lets a body line out`, async () => {
      const rows = [
        ...(await drive(alias, 'nulkey.txt', 4, 'n1')),
        ...(await drive(alias, 'nulbegin.txt', 4, 'n2$')),
      ];
      expect(rows.filter((row) => !row.endsWith(':true:false'))).toEqual([]);
    }, 120_000);

    test(`[${alias}] three markers on one line, and CRLF joined markers, still mask the body`, async () => {
      const rows = [
        ...(await drive(alias, 'three.txt', 4, 't3$')),
        ...(await drive(alias, 'crlfjoin.txt', 5, 'cj')),
      ];
      expect(rows.filter((row) => !row.endsWith(':true:false'))).toEqual([]);
    }, 120_000);

    test(`[${alias}] a cert bundle with a key: cert bodies stay visible, the key body does not`, async () => {
      const rows = await drive(alias, 'bundlekey.txt', 9, 'bk$');
      const head = await live(alias, 'head', { path: `${ROOT}/bundlekey.txt`, n: '20' });
      const grep = await live(alias, 'grep', {
        path: `${ROOT}/bundlekey.txt`,
        pattern: 'MIIBcert',
      });
      expect({
        rows: rows.filter((row) => !row.endsWith(':true:false')),
        head: linesOf(head).filter((l) => l.startsWith('MIIBcert')),
        grep: linesOf(grep).map((l) => l.slice(l.lastIndexOf(':') + 1)),
      }).toEqual({
        rows: [],
        head: ['MIIBcertD0', 'MIIBcertD1', 'MIIBcertE0', 'MIIBcertE1'],
        grep: ['MIIBcertD0', 'MIIBcertD1', 'MIIBcertE0', 'MIIBcertE1'],
      });
    }, 120_000);

    test(`[${alias}] a 600-marker file: no key body anywhere, certificates still visible`, async () => {
      const path = `${ROOT}/many600.txt`;
      const rows = await drive(alias, 'many600.txt', 453, 'mz$');
      const tail = await live(alias, 'tail', { path, n: '460' });
      const head = await live(alias, 'head', { path, n: '460' });
      const cat = await live(alias, 'cat', { path, lines: '440:470' });
      const content = (cat.data as { content?: string } | null)?.content ?? '';
      expect({
        rows: rows.filter((row) => !row.endsWith(':true:false')),
        leak: leaks(tail) || leaks(head) || leaks(cat),
        masked: [tail, head].map((e) => linesOf(e).filter((l) => l === '***').length),
        catCerts: content.split('\n').filter((l) => l.startsWith('MIIBcert')).length,
      }).toEqual({ rows: [], leak: false, masked: [2, 2], catCerts: 9 });
    }, 120_000);
  }
});

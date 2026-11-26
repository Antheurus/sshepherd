import { afterAll, beforeAll, describe, expect, spyOn, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { buildDeployOpContext } from '../recipes.ts';
import { executeOp, listOps } from '../registry.ts';
import * as scrubModule from '../scrub.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner, type SshRunner } from '../transport.ts';
import type { OpContext, OpSpec } from '../types.ts';

/**
 * The leak gate: a random canary is planted on the running smoke fixture (`just smoke-up`) in every
 * secret-shaped place a server keeps one, then EVERY op that exposes output runs against both sshd
 * variants and the canary must appear in none of what sshepherd hands back: the envelope (data,
 * error, stderr_tail), the audit row it wrote, or a file `files download` wrote. Each planted value
 * ends in a placement tag; the raw ssh output is recorded so the test also proves every placement
 * was actually read by some op (a canary nobody reads would make "0 hits" meaningless).
 *
 * Smoke-only: without the fixture the suite is skipped (CI has no Docker fixture). With
 * SSHEPHERD_TEST_SCRUB_IDENTITY=1 the scrubber becomes the identity function inside this test
 * process only, and the test must fail — the falsification run.
 */

const REPO = join(import.meta.dir, '..', '..');
const STATE = process.env.SSHEPHERD_SMOKE_STATE_DIR ?? '/tmp/sshepherd-smoke';
const SSH_CONFIG = join(STATE, 'ssh_config');
const PLANT = join(REPO, 'scripts', 'sshd-fixture', 'canary', 'plant.sh');
const VARIANTS = ['debian', 'alpine'] as const;
const CANARY_CONTAINER = 'sshepherd-fixture-canary';
const IDENTITY_HOOK = 'SSHEPHERD_TEST_SCRUB_IDENTITY';

/** Placement tags, one per planted value (scripts/sshd-fixture/canary/*). */
const PLACEMENTS: Record<string, string> = {
  ev: 'container Env API_TOKEN',
  du: 'container Env DATABASE_URL password (and its log lines)',
  cf: 'compose file environment POSTGRES_PASSWORD',
  lg: 'app log line password=',
  ah: 'app log line Authorization: Bearer',
  qs: 'app log line query-string token=',
  js: 'app log line JSON client_secret',
  de: '.env SECRET_KEY',
  dv: '.env DATABASE_URL password',
  pe: 'prod.env DB_PASSWORD',
  pk: 'prod.env export API_KEY',
  cj: 'config.json client_secret',
  cu: 'config.json database_url password',
  ct: 'config.json token',
  pm: 'server.pem private key body',
  ng: 'nginx access log token=',
  ne: 'nginx error log Authorization: Bearer',
  db: 'db column password',
  dt: 'db column api_token',
};

/** Exposing ops this test cannot drive, each with the reason a reviewer accepted. Growing it means
 *  raising REVIEWED_SKIP_COUNT in the same change, so a skip is never silent. */
const SKIP: Record<string, string> = {};
const REVIEWED_SKIP_COUNT = 0;

const CANARY_FILES = [
  '/opt/canary/.env',
  '/opt/canary/prod.env',
  '/opt/canary/docker-compose.yml',
  '/opt/canary/config.json',
  '/opt/canary/server.pem',
];

function argValues(alias: string): Record<string, string[]> {
  return {
    container: [CANARY_CONTAINER],
    unit: ['canary.service'],
    stream: ['access', 'error'],
    path: CANARY_FILES,
    file: ['/opt/canary/docker-compose.yml'],
    target: [alias],
    sql: ['SELECT * FROM canary_users'],
    recipe: ['canary-ok', 'canary-fail'],
  };
}

const ARG_OVERRIDES: Record<string, Record<string, string[]>> = {
  'files ls': { path: ['/opt/canary'] },
  'files disk-usage': { path: ['/opt/canary'] },
};

interface Drive {
  label: string;
  args: Record<string, string | boolean>;
  downloadPath?: string;
}

function fixtureRunning(): boolean {
  if (!existsSync(SSH_CONFIG)) {
    return false;
  }
  const proc = Bun.spawnSync(
    ['docker', 'inspect', '-f', '{{.State.Running}}', 'sshepherd-fixture-sshd-debian'],
    { stdout: 'pipe', stderr: 'pipe' },
  );
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const FIXTURE_UP = fixtureRunning();

function randomCanary(): string {
  const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from(randomBytes(24), (byte) => alphabet[byte % alphabet.length]).join('');
}

function runPlant(...args: string[]): void {
  const proc = Bun.spawnSync(['bash', PLANT, ...args], { stdout: 'pipe', stderr: 'pipe' });
  if (proc.exitCode !== 0) {
    throw new Error(`plant.sh ${args[0]} failed: ${proc.stderr.toString().slice(-500)}`);
  }
}

function installIdentityScrubber(): void {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(`${IDENTITY_HOOK} is a bun test hook and is refused outside it`);
  }
  spyOn(scrubModule, 'scrub').mockImplementation(((value: unknown) => ({
    value,
    count: 0,
  })) as typeof scrubModule.scrub);
  spyOn(scrubModule, 'scrubText').mockImplementation((text: string) => ({ value: text, count: 0 }));
  spyOn(scrubModule, 'maskEnvContent').mockImplementation((content: string) => content);
  spyOn(scrubModule, 'maskPemLines').mockImplementation((lines: readonly string[]) => [...lines]);
}

const ENV_KEYS = [
  'SSHEPHERD_SSH_CONFIG_PATH',
  'XDG_RUNTIME_DIR',
  'SSHEPHERD_TARGETS_PATH',
  'SSHEPHERD_FILES_ALLOWLIST_PATH',
  'SSHEPHERD_CONFIG_ALLOWLIST_PATH',
  'SSHEPHERD_REVEAL_ALLOWLIST_PATH',
  'SSHEPHERD_RECIPE_PATH',
  'SSHEPHERD_PROFILE',
] as const;
const savedEnv: Record<string, string | undefined> = {};

let canary = '';
let scratch = '';
let runtimeDir = '';
let rawSeen = '';

const recordingRunner: SshRunner = async (args, timeoutMs, options) => {
  const outcome = await defaultRunner(args, timeoutMs, options);
  rawSeen += `${outcome.stdout}\n${outcome.stderr}\n`;
  return outcome;
};

function writeFixtureConfig(): void {
  const aliases = VARIANTS.map((variant) => `smoke-${variant}`);
  const targets = aliases
    .map(
      (alias) =>
        `[${alias}]\nalias = "${alias}"\ncontainer = "sshepherd-fixture-postgres"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
    )
    .join('\n');
  writeFileSync(join(scratch, 'targets.toml'), targets);
  const paths = ['/opt/canary', ...CANARY_FILES].map((path) => `"${path}"`).join(', ');
  const allowlist = aliases.map((alias) => `[${alias}]\npaths = [${paths}]\n`).join('\n');
  writeFileSync(join(scratch, 'files-allowlist.toml'), allowlist);
  writeFileSync(join(scratch, 'config-allowlist.toml'), allowlist);
  writeFileSync(join(scratch, 'reveal-allowlist.toml'), '');
  for (const alias of aliases) {
    writeFileSync(
      join(scratch, `canary-ok.${alias}.toml`),
      [
        'name = "canary-ok"',
        `alias = "${alias}"`,
        'workdir = "/opt/canary"',
        '',
        '[[step]]',
        'name = "show-config"',
        'kind = "shell"',
        'run = "cat .env prod.env config.json"',
        'mutates = false',
        '',
        '[[step]]',
        'name = "app-logs"',
        'kind = "shell"',
        `run = "docker logs --tail 50 ${CANARY_CONTAINER} 2>&1"`,
        'mutates = false',
        '',
        '[[step]]',
        'name = "migrate"',
        'kind = "migrate"',
        'run = "cat config.json"',
        '',
        '[rollback]',
        'strategy = "compose-file"',
        'file = "docker-compose.yml"',
        '',
      ].join('\n'),
    );
    writeFileSync(
      join(scratch, `canary-fail.${alias}.toml`),
      [
        'name = "canary-fail"',
        `alias = "${alias}"`,
        'workdir = "/opt/canary"',
        '',
        '[[step]]',
        'name = "leaky-failure"',
        'kind = "shell"',
        `run = "cat .env prod.env >&2; docker logs --tail 50 ${CANARY_CONTAINER} >&2; exit 3"`,
        'mutates = false',
        '',
        '[[step]]',
        'name = "migrate"',
        'kind = "migrate"',
        'run = "cat .env config.json >&2; exit 3"',
        '',
        '[rollback]',
        'strategy = "compose-file"',
        'file = "missing-compose.yml"',
        '',
      ].join('\n'),
    );
  }
}

/** Every required arg gets each of its values (a new op with an arg nobody named here fails, it
 *  is never skipped); `files download` writes into the scratch dir so the file can be searched. */
function drivesFor(op: OpSpec, alias: string): Drive[] {
  const name = `${op.group} ${op.name}`;
  const values = { ...argValues(alias), ...ARG_OVERRIDES[name] };
  let drives: Drive[] = [{ label: name, args: {} }];
  for (const spec of op.args) {
    if (spec.name === 'local_path') {
      continue;
    }
    const options = values[spec.name];
    if (options === undefined) {
      if (spec.required) {
        throw new Error(`no canary value for required arg '${spec.name}' of '${name}'`);
      }
      continue;
    }
    if (!spec.required && spec.name !== 'stream') {
      continue;
    }
    drives = drives.flatMap((drive) =>
      options.map((value) => ({
        label: `${drive.label} ${spec.name}=${value}`,
        args: { ...drive.args, [spec.name]: value },
      })),
    );
  }
  if (op.args.some((spec) => spec.name === 'local_path')) {
    drives = drives.map((drive, index) => {
      const downloadPath = join(
        scratch,
        `download-${alias}-${index}-${basename(String(drive.args.path))}`,
      );
      return { ...drive, args: { ...drive.args, local_path: downloadPath }, downloadPath };
    });
  }
  return drives;
}

function contextFor(op: OpSpec, alias: string, args: Record<string, string | boolean>): OpContext {
  if (op.group === 'db') {
    return buildDbOpContext(alias, args);
  }
  if (op.group === 'deploy') {
    process.env.SSHEPHERD_RECIPE_PATH = join(scratch, `${String(args.recipe)}.${alias}.toml`);
    return buildDeployOpContext(String(args.recipe), args);
  }
  return { alias, args };
}

interface DriveResult {
  label: string;
  status: string;
  hits: string[];
  reached: string[];
}

async function drive(op: OpSpec, alias: string, entry: Drive, index: number): Promise<DriveResult> {
  const auditLogPath = join(scratch, `audit-${alias}-${index}.jsonl`);
  rawSeen = '';
  const ctx = contextFor(op, alias, entry.args);
  const envelope = await executeOp(op, ctx, {
    transport: { runner: recordingRunner, sshConfigPath: SSH_CONFIG },
    sshConfigPath: SSH_CONFIG,
    yes: true,
    auditLogPath,
  });
  const places: Record<string, string> = {
    stdout: JSON.stringify(envelope),
    error: JSON.stringify(envelope.error ?? null),
    stderr_tail: envelope.error?.stderr_tail ?? '',
    audit_row: existsSync(auditLogPath) ? readFileSync(auditLogPath, 'utf8') : '',
    downloaded_file:
      entry.downloadPath !== undefined && existsSync(entry.downloadPath)
        ? readFileSync(entry.downloadPath, 'latin1')
        : '',
  };
  const hits = Object.entries(places)
    .filter(([, text]) => text.includes(canary))
    .map(([where]) => where);
  // `files download` moves the bytes as one base64 line; decode it so its reach shows too.
  const decoded = (rawSeen.match(/[A-Za-z0-9+/]{32,}={0,2}/g) ?? [])
    .map((token) => Buffer.from(token, 'base64').toString('latin1'))
    .join('\n');
  const reached = Object.keys(PLACEMENTS).filter((tag) =>
    `${rawSeen}\n${decoded}`.includes(`${canary}${tag}`),
  );
  return {
    label: entry.label,
    status: envelope.ok ? 'ok' : (envelope.error?.code ?? 'error'),
    hits,
    reached,
  };
}

const exposingOps = (): OpSpec[] => listOps().filter((op) => op.exposes !== 'none');

describe('canary skip-list is explicit and reviewed', () => {
  test('every skipped op exposes output, carries a reason, and the count is the reviewed one', () => {
    const exposing = exposingOps().map((op) => `${op.group} ${op.name}`);
    for (const [name, reason] of Object.entries(SKIP)) {
      expect({ name, exposes: exposing.includes(name), reason: reason.trim().length > 0 }).toEqual({
        name,
        exposes: true,
        reason: true,
      });
    }
    expect(Object.keys(SKIP).length).toBe(REVIEWED_SKIP_COUNT);
  });

  test(`${IDENTITY_HOOK} is read by no shipped file — only this test can switch the scrubber off`, () => {
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== '__tests__') {
            walk(path);
          }
        } else if (readFileSync(path, 'utf8').includes(IDENTITY_HOOK)) {
          offenders.push(path.slice(REPO.length + 1));
        }
      }
    };
    walk(join(REPO, 'src'));
    walk(join(REPO, 'scripts'));
    expect(offenders).toEqual([]);
  });
});

describe.skipIf(!FIXTURE_UP)('canary leak gate (smoke fixture)', () => {
  beforeAll(() => {
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
    }
    if (process.env[IDENTITY_HOOK] === '1') {
      installIdentityScrubber();
    }
    canary = randomCanary();
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-canary-'));
    runtimeDir = mkdtempSync('/tmp/sshepherd-canary-run-');
    writeFixtureConfig();
    process.env.SSHEPHERD_SSH_CONFIG_PATH = SSH_CONFIG;
    process.env.XDG_RUNTIME_DIR = runtimeDir;
    process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = join(scratch, 'config-allowlist.toml');
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = join(scratch, 'reveal-allowlist.toml');
    delete process.env.SSHEPHERD_PROFILE;
    runPlant('plant', canary);
  }, 120_000);

  afterAll(async () => {
    for (const variant of VARIANTS) {
      await closeMaster(`smoke-${variant}`);
    }
    runPlant('clean');
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = savedEnv[key];
      }
    }
    rmSync(scratch, { recursive: true, force: true });
    rmSync(runtimeDir, { recursive: true, force: true });
  }, 60_000);

  for (const variant of VARIANTS) {
    test(`${variant}: every op with exposes != none returns, audits and downloads 0 canary hits`, async () => {
      const alias = `smoke-${variant}`;
      const results: DriveResult[] = [];
      let index = 0;
      for (const op of exposingOps()) {
        if (SKIP[`${op.group} ${op.name}`] !== undefined) {
          continue;
        }
        for (const entry of drivesFor(op, alias)) {
          results.push(await drive(op, alias, entry, index));
          index += 1;
        }
      }
      for (const result of results) {
        console.log(
          `[${variant}] ${result.label}: ${result.status}; reached ${result.reached.join(',') || '-'}; hits ${result.hits.join(',') || '0'}`,
        );
      }
      const driven = new Set(
        results.map((result) => result.label.split(' ').slice(0, 2).join(' ')),
      );
      expect(exposingOps().length - Object.keys(SKIP).length).toBe(driven.size);

      const hits = results
        .filter((result) => result.hits.length > 0)
        .map((result) => `${result.label}: canary in ${result.hits.join(', ')}`);
      expect(hits).toEqual([]);

      const reached = new Set(results.flatMap((result) => result.reached));
      const unreached = Object.entries(PLACEMENTS)
        .filter(([tag]) => !reached.has(tag))
        .map(([tag, where]) => `${tag} (${where})`);
      expect(unreached).toEqual([]);
    }, 300_000);
  }

  test(`the compiled binary ignores ${IDENTITY_HOOK}: files cat still masks the canary`, async () => {
    const binary = join(scratch, 'sshepherd');
    const build = Bun.spawnSync(
      ['bun', 'build', join(REPO, 'src', 'cli.ts'), '--compile', '--outfile', binary],
      { stdout: 'pipe', stderr: 'pipe' },
    );
    expect(build.exitCode).toBe(0);
    const proc = Bun.spawnSync([binary, 'files', 'cat', 'smoke-debian', '/opt/canary/prod.env'], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env, [IDENTITY_HOOK]: '1', NODE_ENV: 'test' },
    });
    const out = proc.stdout.toString();
    expect(JSON.parse(out)).toMatchObject({ ok: true, data: { found: true, masked: true } });
    expect(out.includes(canary)).toBe(false);
  }, 120_000);
});

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
 * The aliases connect under a canary identity too: a HostName that resolves nowhere (reached through
 * a ProxyCommand to the fixture's published port), a canary uid-0 user and a non-22 port. The remote
 * prints that identity and a documentation-range peer address in a failing command's stderr, sshd
 * journal lines, auth.log, a psql connect error and `ss` output; neither may reach an envelope or an
 * audit row, and with `reveal_addresses = true` only the peer address comes back.
 *
 * Smoke-only: without the fixture the suite is skipped (CI has no Docker fixture). With
 * SSHEPHERD_TEST_SCRUB_IDENTITY=1 the scrubber becomes the identity function inside this test
 * process only, and the test must fail — the falsification run.
 */

const REPO = join(import.meta.dir, '..', '..');
const FIXTURE_DIR = join(REPO, 'scripts', 'sshd-fixture');
const PLANT = join(FIXTURE_DIR, 'canary', 'plant.sh');
const VARIANTS = ['debian', 'alpine'] as const;
const IDENTITY_HOOK = 'SSHEPHERD_TEST_SCRUB_IDENTITY';
const PEER_IP = '203.0.113.77';

/** The fixture's project, container prefix and state dir, from the same project.sh smoke.sh and
 *  plant.sh source (SSHEPHERD_SMOKE_PROJECT / SSHEPHERD_SMOKE_STATE_DIR pick the fixture). */
function fixtureNames(): { prefix: string; state: string } {
  const proc = Bun.spawnSync(
    [
      'bash',
      '-c',
      '. "$1"; printf "%s\\n%s" "$SMOKE_PREFIX" "$SMOKE_STATE"',
      'bash',
      join(FIXTURE_DIR, 'project.sh'),
    ],
    { stdout: 'pipe', stderr: 'pipe' },
  );
  if (proc.exitCode !== 0) {
    throw new Error(`project.sh failed: ${proc.stderr.toString().slice(-300)}`);
  }
  const [prefix = '', state = ''] = proc.stdout.toString().split('\n');
  return { prefix, state };
}

const { prefix: PREFIX, state: STATE } = fixtureNames();
const SMOKE_SSH_CONFIG = join(STATE, 'ssh_config');
const CANARY_CONTAINER = `${PREFIX}-canary`;

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

/** psql error texts that quote the value that failed (scrub.ts `PSQL_DATA_ECHO_RULES`), each one a
 *  `db query` against the planted canary_users row; `marker` is psql's own text, proving it ran.
 *  `secret_pin` holds the digits-only canary, the one value an integer range error can quote. */
const DB_ECHO_PROBES: Record<string, { sql: string; marker: string }> = {
  q1: {
    sql: 'SELECT email, password::int FROM canary_users',
    marker: 'invalid input syntax for type integer: "',
  },
  q2: {
    sql: 'SELECT password::canary_mood FROM canary_users',
    marker: 'invalid input value for enum canary_mood: "',
  },
  q3: {
    sql: 'SELECT secret_pin::int FROM canary_users',
    marker: 'is out of range for type integer',
  },
  q4: { sql: 'SELECT password::text[] FROM canary_users', marker: 'malformed array literal: "' },
  q5: { sql: 'SELECT password::json FROM canary_users', marker: 'JSON data, line 1: ' },
  q6: {
    sql: "SELECT to_date(password, 'FMMonth') FROM canary_users",
    marker: 'invalid value "',
  },
  q7: { sql: 'SELECT secret_pin::date FROM canary_users', marker: 'out of range: "' },
  q10: {
    sql: 'SELECT secret_pin::interval FROM canary_users',
    marker: 'interval field value out of range: "',
  },
  q8: { sql: 'SELECT canary_unique_violation()', marker: 'already exists.' },
  q9: { sql: 'SELECT canary_not_null_violation()', marker: 'Failing row contains (' },
};

interface Identity {
  user: string;
  host: string;
  port: string;
}

/** Where the remote prints the canary identity and the peer address; `marker` is a line only that
 *  placement prints, so reaching it proves the op read it. */
function addressPlacements(id: Identity): Record<string, { where: string; marker: string }> {
  return {
    a1: {
      where: 'deploy run canary-fail stderr (ssh/rsync connect errors)',
      marker: `rsync: [sender] ${id.user}@${id.host}: connection from ${PEER_IP} refused`,
    },
    a2: {
      where: 'sshd journal (fake journalctl): Accepted publickey for <user> from <peer>',
      marker: `Accepted publickey for ${id.user} from ${PEER_IP} port 51234`,
    },
    a3: {
      where: '/var/log/auth.log: Failed password for invalid user <user> from <peer>',
      marker: `Failed password for invalid user ${id.user} from ${PEER_IP}`,
    },
    a4: {
      where: 'psql connect error naming the peer and the identity host/port',
      marker: `could not translate host name "${id.host}"`,
    },
    a5: { where: 'ss -tlnp: a listener on the peer address', marker: `${PEER_IP}:51234` },
  };
}

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
  '/var/log/auth.log',
];

/** The pg-target whose container's PGHOST/PGPORT point at the unreachable peer and identity host. */
const pgConnectTarget = (alias: string): string => `${alias}-pgconnect`;
/** `kind = "container-env"` pg-targets on `canary-dburl`, whose DATABASE_URL carries the canary as
 *  its password: psql in that container, and psql in the fixture postgres (`psql_container`). */
const envUrlTarget = (alias: string): string => `${alias}-envurl`;
const envViaTarget = (alias: string): string => `${alias}-envvia`;
const ENV_URL_CONTAINER = `${PREFIX}-canary-dburl`;

function argValues(alias: string): Record<string, string[]> {
  return {
    container: [CANARY_CONTAINER],
    unit: ['canary.service'],
    stream: ['access', 'error'],
    path: CANARY_FILES,
    file: ['/opt/canary/docker-compose.yml'],
    project_dir: ['/opt/canary'],
    target: [alias, pgConnectTarget(alias), envUrlTarget(alias), envViaTarget(alias)],
    table: ['canary_users'],
    sql: ['SELECT * FROM canary_users', ...Object.values(DB_ECHO_PROBES).map((probe) => probe.sql)],
    recipe: ['canary-ok', 'canary-fail'],
    pattern: ['.'],
  };
}

function argOverrides(alias: string): Record<string, Record<string, string[]>> {
  return {
    'files ls': { path: ['/opt/canary'] },
    'files disk-usage': { path: ['/opt/canary'] },
    'files find': { path: ['/opt/canary'] },
    'files grep': { path: ['/opt/canary', '/var/log/auth.log'] },
    'db query': { target: [alias, envUrlTarget(alias)] },
  };
}

/** Ops whose args are alternatives or paired (`env keys` takes a container or a path, `env diff` a
 *  remote file and a local reference), so the one-value-per-arg product would build calls the op
 *  refuses; each entry lists the exact argument sets to run. */
function explicitDrives(): Record<string, Record<string, string>[]> {
  return {
    'env keys': [{ container: CANARY_CONTAINER }, ...CANARY_FILES.map((path) => ({ path }))],
    'env diff': CANARY_FILES.map((path) => ({ path, against: referenceEnvPath })),
  };
}

interface Drive {
  label: string;
  args: Record<string, string | boolean>;
  downloadPath?: string;
}

function fixtureRunning(): boolean {
  if (!existsSync(SMOKE_SSH_CONFIG)) {
    return false;
  }
  const proc = Bun.spawnSync(
    ['docker', 'inspect', '-f', '{{.State.Running}}', `${PREFIX}-sshd-debian`],
    { stdout: 'pipe', stderr: 'pipe' },
  );
  return proc.exitCode === 0 && proc.stdout.toString().trim() === 'true';
}

const FIXTURE_UP = fixtureRunning();

function randomCanary(): string {
  const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from(randomBytes(24), (byte) => alphabet[byte % alphabet.length]).join('');
}

/** Long enough that no real number in an envelope repeats it by chance; leads with 9 so it is
 *  past the integer range. */
function randomDigits(): string {
  return `9${Array.from(randomBytes(20), (byte) => byte % 10).join('')}`;
}

function randomIdentity(value: string): Identity {
  const lower = value.toLowerCase();
  const port = 41_000 + (randomBytes(2).readUInt16BE(0) % 20_000);
  return { user: `u${lower.slice(0, 20)}`, host: `h${lower}.example.net`, port: String(port) };
}

function runPlant(...args: string[]): void {
  const proc = Bun.spawnSync(['bash', PLANT, ...args], { stdout: 'pipe', stderr: 'pipe' });
  if (proc.exitCode !== 0) {
    throw new Error(`plant.sh ${args[0]} failed: ${proc.stderr.toString().slice(-500)}`);
  }
}

function installIdentityScrubber(): { mockRestore: () => void }[] {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(`${IDENTITY_HOOK} is a bun test hook and is refused outside it`);
  }
  return [
    spyOn(scrubModule, 'scrub').mockImplementation(((value: unknown) => ({
      value,
      count: 0,
    })) as typeof scrubModule.scrub),
    spyOn(scrubModule, 'scrubText').mockImplementation((text: string) => ({
      value: text,
      count: 0,
    })),
    spyOn(scrubModule, 'maskEnvContent').mockImplementation((content: string) => content),
    spyOn(scrubModule, 'maskPemLines').mockImplementation((lines: readonly string[]) => [...lines]),
  ];
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
let digits = '';
let identity: Identity = { user: '', host: '', port: '' };
let scratch = '';
let sshConfig = '';
let runtimeDir = '';
let rawSeen = '';
let referenceEnvPath = '';

const recordingRunner: SshRunner = async (args, timeoutMs, options) => {
  const outcome = await defaultRunner(args, timeoutMs, options);
  rawSeen += `${outcome.stdout}\n${outcome.stderr}\n`;
  return outcome;
};

/** The host port smoke.sh published for an alias, read from the fixture's own ssh config. */
function publishedPort(alias: string): string {
  const text = readFileSync(SMOKE_SSH_CONFIG, 'utf8');
  const block = text.split(/^Host /m).find((entry) => entry.startsWith(`${alias}\n`)) ?? '';
  const port = /^\s*Port\s+(\d+)/m.exec(block)?.[1];
  if (port === undefined) {
    throw new Error(`no Port for ${alias} in ${SMOKE_SSH_CONFIG}`);
  }
  return port;
}

/** The same aliases as the smoke ssh config, connecting under the canary identity: the HostName
 *  resolves nowhere, so a ProxyCommand carries the connection to the published port, and the
 *  canary known_hosts names the host keys under that identity. */
function writeCanarySshConfig(): void {
  const knownHosts: string[] = [];
  const stanzas: string[] = [];
  for (const variant of VARIANTS) {
    const alias = `smoke-${variant}`;
    const keys = Bun.spawnSync(
      [
        'docker',
        'exec',
        `${PREFIX}-sshd-${variant}`,
        'sh',
        '-c',
        'cat /etc/ssh/ssh_host_*_key.pub',
      ],
      { stdout: 'pipe', stderr: 'pipe' },
    );
    for (const line of keys.stdout.toString().split('\n')) {
      const [type, key] = line.trim().split(/\s+/);
      if (type !== undefined && key !== undefined) {
        knownHosts.push(`[${identity.host}]:${identity.port} ${type} ${key}`);
      }
    }
    stanzas.push(
      [
        `Host ${alias}`,
        `  HostName ${identity.host}`,
        `  Port ${identity.port}`,
        `  User ${identity.user}`,
        `  ProxyCommand nc 127.0.0.1 ${publishedPort(alias)}`,
        `  IdentityFile ${join(STATE, 'keys', 'id_ed25519')}`,
        '  IdentitiesOnly yes',
        '  StrictHostKeyChecking yes',
        `  UserKnownHostsFile ${join(scratch, 'known_hosts')}`,
        '',
      ].join('\n'),
    );
  }
  writeFileSync(join(scratch, 'known_hosts'), `${knownHosts.join('\n')}\n`);
  writeFileSync(sshConfig, stanzas.join('\n'));
}

function writeFixtureConfig(): void {
  const aliases = VARIANTS.map((variant) => `smoke-${variant}`);
  const targets = aliases
    .flatMap((alias) => [
      `[${alias}]\nalias = "${alias}"\ncontainer = "${PREFIX}-postgres"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
      `[${pgConnectTarget(alias)}]\nalias = "${alias}"\ncontainer = "${PREFIX}-canary-pg"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
      `[${envUrlTarget(alias)}]\nalias = "${alias}"\nkind = "container-env"\ncontainer = "${ENV_URL_CONTAINER}"\n`,
      `[${envViaTarget(alias)}]\nalias = "${alias}"\nkind = "container-env"\ncontainer = "${ENV_URL_CONTAINER}"\nenv_key = "DATABASE_URL"\npsql_container = "${PREFIX}-postgres"\n`,
    ])
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
        `run = "cat .env prod.env deploy-error.log >&2; docker logs --tail 50 ${CANARY_CONTAINER} >&2; exit 3"`,
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
  const explicit = explicitDrives()[name];
  if (explicit !== undefined) {
    return explicit.map((args) => ({
      label: `${name} ${Object.entries(args)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ')}`,
      args,
    }));
  }
  const values = { ...argValues(alias), ...argOverrides(alias)[name] };
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
    return buildDbOpContext(typeof args.target === 'string' ? args.target : alias, args);
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
  /** The peer address came back in the envelope (expected only with reveal_addresses). */
  peerShown: boolean;
}

/** Each planted value, as the test searches for it: `where` it may never appear. The identity
 *  and the peer address are envelope-and-audit only — a file `files download` writes is the user's
 *  own bytes and keeps its addresses by design. */
function needles(): { name: string; found: (text: string) => boolean; envelopeOnly: boolean }[] {
  const lower = (needle: string) => (text: string) => text.toLowerCase().includes(needle);
  const portPattern = new RegExp(`(?<![\\d.])${identity.port}(?!\\d)`);
  return [
    { name: 'canary', found: (text) => text.includes(canary), envelopeOnly: false },
    { name: 'digits', found: (text) => text.includes(digits), envelopeOnly: false },
    { name: 'identity-user', found: lower(identity.user), envelopeOnly: true },
    { name: 'identity-host', found: lower(identity.host), envelopeOnly: true },
    { name: 'identity-port', found: (text) => portPattern.test(text), envelopeOnly: true },
  ];
}

async function drive(
  op: OpSpec,
  alias: string,
  entry: Drive,
  index: number,
  peerAllowed: boolean,
): Promise<DriveResult> {
  const auditLogPath = join(scratch, `audit-${alias}-${index}.jsonl`);
  rawSeen = '';
  const ctx = contextFor(op, alias, entry.args);
  const envelope = await executeOp(op, ctx, {
    transport: { runner: recordingRunner, sshConfigPath: sshConfig },
    sshConfigPath: sshConfig,
    yes: true,
    auditLogPath,
  });
  const stdout = JSON.stringify(envelope);
  const places: Record<string, string> = {
    stdout,
    error: JSON.stringify(envelope.error ?? null),
    stderr_tail: envelope.error?.stderr_tail ?? '',
    audit_row: existsSync(auditLogPath) ? readFileSync(auditLogPath, 'utf8') : '',
    downloaded_file:
      entry.downloadPath !== undefined && existsSync(entry.downloadPath)
        ? readFileSync(entry.downloadPath, 'latin1')
        : '',
  };
  const checks = [
    ...needles(),
    { name: 'peer-ip', found: (text: string) => text.includes(PEER_IP), envelopeOnly: true },
  ].filter((needle) => !(peerAllowed && needle.name === 'peer-ip'));
  const hits = Object.entries(places).flatMap(([where, text]) =>
    checks
      .filter((needle) => !(needle.envelopeOnly && where === 'downloaded_file'))
      .filter((needle) => needle.found(text))
      .map((needle) => `${needle.name}@${where}`),
  );
  // `files download` moves the bytes as one base64 line; decode it so its reach shows too.
  const decoded = (rawSeen.match(/[A-Za-z0-9+/]{32,}={0,2}/g) ?? [])
    .map((token) => Buffer.from(token, 'base64').toString('latin1'))
    .join('\n');
  const raw = `${rawSeen}\n${decoded}`;
  const reached = [
    ...Object.keys(PLACEMENTS).filter((tag) => raw.includes(`${canary}${tag}`)),
    ...Object.entries(DB_ECHO_PROBES)
      .filter(([, probe]) => entry.args.sql === probe.sql && raw.includes(probe.marker))
      .map(([tag]) => tag),
    ...Object.entries(addressPlacements(identity))
      .filter(([, placement]) => raw.includes(placement.marker))
      .map(([tag]) => tag),
  ];
  return {
    label: entry.label,
    status: envelope.ok ? 'ok' : (envelope.error?.code ?? 'error'),
    hits,
    reached,
    peerShown: stdout.includes(PEER_IP),
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
    digits = randomDigits();
    identity = randomIdentity(randomCanary());
    scratch = mkdtempSync(join(tmpdir(), 'sshepherd-canary-'));
    sshConfig = join(scratch, 'ssh_config');
    runtimeDir = mkdtempSync('/tmp/sshepherd-canary-run-');
    referenceEnvPath = join(scratch, 'reference.env');
    writeFileSync(referenceEnvPath, 'SECRET_KEY=\nAPI_TOKEN=\nNOT_THERE=\n');
    writeFixtureConfig();
    writeCanarySshConfig();
    process.env.SSHEPHERD_SSH_CONFIG_PATH = sshConfig;
    process.env.XDG_RUNTIME_DIR = runtimeDir;
    process.env.SSHEPHERD_TARGETS_PATH = join(scratch, 'targets.toml');
    process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(scratch, 'files-allowlist.toml');
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = join(scratch, 'config-allowlist.toml');
    process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = join(scratch, 'reveal-allowlist.toml');
    delete process.env.SSHEPHERD_PROFILE;
    runPlant('plant', canary, digits, identity.user, identity.host, identity.port);
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
          results.push(await drive(op, alias, entry, index, false));
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
      const placements: Record<string, string> = {
        ...PLACEMENTS,
        ...Object.fromEntries(
          Object.entries(DB_ECHO_PROBES).map(([tag, probe]) => [tag, `db query ${probe.sql}`]),
        ),
        ...Object.fromEntries(
          Object.entries(addressPlacements(identity)).map(([tag, placement]) => [
            tag,
            placement.where,
          ]),
        ),
      };
      const unreached = Object.entries(placements)
        .filter(([tag]) => !reached.has(tag))
        .map(([tag, where]) => `${tag} (${where})`);
      expect(unreached).toEqual([]);
    }, 300_000);
  }

  for (const variant of VARIANTS) {
    test(`${variant}: reveal_addresses = true returns the peer address and still hides the identity`, async () => {
      const alias = `smoke-${variant}`;
      writeFileSync(
        join(scratch, 'reveal-allowlist.toml'),
        `[${alias}.scrub]\nreveal_addresses = true\n`,
      );
      const byName = (name: string): OpSpec => {
        const op = exposingOps().find(
          (candidate) => `${candidate.group} ${candidate.name}` === name,
        );
        if (op === undefined) {
          throw new Error(`no op ${name}`);
        }
        return op;
      };
      const plan: [string, Record<string, string>][] = [
        ['deploy run', { recipe: 'canary-fail' }],
        ['logs service', { unit: 'ssh.service' }],
        ['files cat', { path: '/var/log/auth.log' }],
        ['db tables', { target: pgConnectTarget(alias) }],
        ['check ports', {}],
      ];
      const results: DriveResult[] = [];
      try {
        for (const [index, [name, args]] of plan.entries()) {
          results.push(
            await drive(
              byName(name),
              alias,
              { label: `${name} reveal`, args },
              10_000 + index,
              true,
            ),
          );
        }
      } finally {
        writeFileSync(join(scratch, 'reveal-allowlist.toml'), '');
      }
      for (const result of results) {
        console.log(
          `[${variant}] ${result.label}: ${result.status}; peer shown ${result.peerShown}; hits ${result.hits.join(',') || '0'}`,
        );
      }
      expect(
        results
          .filter((result) => result.hits.length > 0)
          .map((r) => `${r.label}: ${r.hits.join(', ')}`),
      ).toEqual([]);
      expect(results.filter((result) => !result.peerShown).map((result) => result.label)).toEqual(
        [],
      );
    }, 120_000);
  }

  for (const variant of VARIANTS) {
    test(`${variant}: env keys, env diff and services inspect hold 0 canary hits with the scrubber off`, async () => {
      const alias = `smoke-${variant}`;
      const hookOn = process.env[IDENTITY_HOOK] === '1';
      const spies = hookOn ? [] : installIdentityScrubber();
      try {
        const names = new Set(['env keys', 'env diff', 'services inspect']);
        const results: DriveResult[] = [];
        let index = 20_000;
        for (const op of exposingOps().filter((candidate) =>
          names.has(`${candidate.group} ${candidate.name}`),
        )) {
          for (const entry of drivesFor(op, alias)) {
            results.push(await drive(op, alias, entry, index, false));
            index += 1;
          }
        }
        for (const result of results) {
          console.log(
            `[${variant}] scrubber off ${result.label}: ${result.status}; hits ${result.hits.join(',') || '0'}`,
          );
        }
        expect(results.length).toBeGreaterThan(names.size);
        expect(results.filter((result) => result.status !== 'ok').map((r) => r.label)).toEqual([]);
        expect(
          results.filter((result) => result.hits.length > 0).map((r) => `${r.label}: ${r.hits}`),
        ).toEqual([]);

        const envelope = await executeOp(
          exposingOps().find((op) => op.group === 'env' && op.name === 'keys') as OpSpec,
          { alias, args: { container: CANARY_CONTAINER } },
          {
            transport: { runner: defaultRunner, sshConfigPath: sshConfig },
            sshConfigPath: sshConfig,
          },
        );
        const keys = (envelope.data as { key: string; state: string; length_bucket: string }[]).map(
          (entry) => entry.key,
        );
        expect(keys).toEqual(
          expect.arrayContaining([
            'API_TOKEN',
            'DATABASE_URL',
            'POSTGRES_PASSWORD',
            'APP_PASSWORD',
            'BEARER_TOKEN',
            'CALLBACK_TOKEN',
            'OAUTH_CLIENT_SECRET',
          ]),
        );
        expect(JSON.stringify(envelope).includes(canary)).toBe(false);
      } finally {
        for (const spy of spies) {
          spy.mockRestore();
        }
      }
    }, 120_000);
    test(`${variant}: a container-env target connects from the URL, and the URL is in no argv, envelope or audit row`, async () => {
      const alias = `smoke-${variant}`;
      const op = exposingOps().find(
        (candidate) => candidate.group === 'db' && candidate.name === 'query',
      );
      if (op === undefined) {
        throw new Error('no db query op');
      }
      const argvSeen: string[] = [];
      const sampleArgv = (): void => {
        for (const container of [
          `${PREFIX}-sshd-${variant}`,
          ENV_URL_CONTAINER,
          `${PREFIX}-postgres`,
        ]) {
          const proc = Bun.spawnSync(
            ['docker', 'exec', container, 'sh', '-c', 'ps -eo args 2>/dev/null || ps -o args'],
            {
              stdout: 'pipe',
              stderr: 'pipe',
            },
          );
          argvSeen.push(proc.stdout.toString());
        }
      };
      const results: { target: string; ok: boolean; user: unknown; leaked: boolean }[] = [];
      for (const [index, target] of [envUrlTarget(alias), envViaTarget(alias)].entries()) {
        const auditLogPath = join(scratch, `audit-envurl-${alias}-${index}.jsonl`);
        const pending = executeOp(
          op,
          buildDbOpContext(target, { sql: 'SELECT current_user AS u, pg_sleep(2) AS slept' }),
          {
            transport: { runner: defaultRunner, sshConfigPath: sshConfig },
            sshConfigPath: sshConfig,
            auditLogPath,
          },
        );
        await Bun.sleep(1_000);
        sampleArgv();
        const envelope = await pending;
        const rows = (envelope.data as { rows?: { u?: unknown }[] } | null)?.rows ?? [];
        const audit = existsSync(auditLogPath) ? readFileSync(auditLogPath, 'utf8') : '';
        results.push({
          target,
          ok: envelope.ok,
          user: rows[0]?.u,
          leaked: JSON.stringify(envelope).includes(canary) || audit.includes(canary),
        });
      }
      expect(results).toEqual([
        { target: envUrlTarget(alias), ok: true, user: 'sshepherd_ro', leaked: false },
        { target: envViaTarget(alias), ok: true, user: 'sshepherd_ro', leaked: false },
      ]);
      expect(argvSeen.join('\n')).toContain('pg_sleep(2)');
      expect(argvSeen.filter((text) => text.includes(canary))).toEqual([]);
    }, 60_000);
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

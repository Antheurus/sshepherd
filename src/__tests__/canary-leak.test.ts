import { afterAll, beforeAll, describe, expect, spyOn, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { buildDeployOpContext } from '../recipes.ts';
import { executeOp, listOps } from '../registry.ts';
import * as scrubModule from '../scrub.ts';
import { buildDbOpContext } from '../targets.ts';
import { closeMaster, defaultRunner, type SshRunner } from '../transport.ts';
import type { OpContext, OpSpec } from '../types.ts';

/**
 * The leak gate: a random canary is planted on the running smoke fixture (`just smoke-up`) in every
 * secret-shaped place a server keeps one, then EVERY op runs against both sshd variants — whatever
 * its `exposes` label claims, since a label is not proof — and the canary must appear in none of
 * what sshepherd hands back: the envelope (data, error, stderr_tail), the audit row it wrote, or a
 * file `files download` wrote, in plain text or base64/base64url/hex/URL-encoded/gzip+base64. Each
 * op needs at least one drive that succeeded (an op erroring on every drive read nothing). Each
 * planted value ends in a placement tag; the raw ssh output is recorded so the test also proves
 * every placement was actually read by some op (a canary nobody reads would make "0 hits"
 * meaningless).
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
/** Holds API_KEY (the `http --auth` credential); the app answering on each sshd's 127.0.0.1:80. */
const CANARY_APP = `${PREFIX}-canary-app`;
const CANARY_REPO = '/opt/canary/repo';

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
  nj: 'compose env JAVA_OPTS nested -Dspring.datasource.password= (and its log line)',
  hb: 'http get/send response body api_token',
  gm: 'git commit subject token= (/opt/canary/repo)',
  pa: 'php artisan stand-in debug line DB_PASSWORD= (exec run app-artisan)',
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

/** Ops this test does not drive, each with the reason a reviewer accepted. Growing it means raising
 *  REVIEWED_SKIP_COUNT in the same change, so a skip is never silent. Each one is a mutating op
 *  labelled `exposes: 'none'` whose drive would change state the other placements are read from;
 *  `executeOp` scrubs its data regardless of the label. */
const SKIP: Record<string, string> = {
  'services restart':
    'restarts the canary container mid-run, so later log drives can miss its placements',
  'files upload': 'writes a remote file from a local one; nothing remote is read back',
  'config put': 'overwrites a planted file (and backs it up), changing what later drives read',
  'security harden':
    "rewrites the fixture sshd's config and restarts it, cutting the run's connections",
  'tunnel open': 'starts a long-lived forward process; its open path is driven by audit07a-live',
};
const REVIEWED_SKIP_COUNT = 5;

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
    service: ['canary'],
    id: ['t-canary-unknown'],
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
function explicitDrives(alias: string): Record<string, Record<string, string | boolean>[]> {
  const ranged = CANARY_FILES.flatMap((path): Record<string, string>[] => [
    { path },
    { path, lines: '2:4' },
  ]);
  return {
    'env keys': [{ container: CANARY_CONTAINER }, ...CANARY_FILES.map((path) => ({ path }))],
    'env diff': CANARY_FILES.map((path) => ({ path, against: referenceEnvPath })),
    'hosts trust': [{ 'dry-run': true }],
    'files head': ranged,
    'files tail': ranged,
    'files cat': ranged,
    'http get': [
      { url: 'http://127.0.0.1:80/', auth: `env:API_KEY@container=${CANARY_APP}` },
      { url: 'http://127.0.0.1:80/' },
    ],
    'http send': [
      {
        method: 'POST',
        url: 'http://127.0.0.1:80/',
        auth: `env:API_KEY@container=${CANARY_APP}`,
        json: '{"probe":true}',
      },
    ],
    'wait for': [
      { until: `healthy@container=${PREFIX}-app`, timeout: '30' },
      {
        until: `log-contains:canary app ready@container=${CANARY_CONTAINER}`,
        since: '1h',
        timeout: '30',
      },
      { until: 'port-open:22', timeout: '30' },
      { until: 'url:http://127.0.0.1:80/:status=401', timeout: '30' },
    ],
    'exec run': [
      { name: 'app-artisan', param: JSON.stringify(['cmd=migrate:status']) },
      ...CANARY_FILES.filter((path) => path.startsWith('/opt/canary/')).map((path) => ({
        name: 'canary-cat',
        param: JSON.stringify([`file=${path}`]),
      })),
      { name: 'canary-env' },
    ],
    'exec change': [{ name: 'canary-show' }],
    'exec list': [{}],
    'git head': [{ path: CANARY_REPO }],
    'git log': [{ path: CANARY_REPO }],
    'git diff-stat': [{ path: CANARY_REPO }],
    'db exec': [
      { target: alias, file: join(scratch, 'exec-read.sql'), 'dry-run': true },
      { target: alias, file: join(scratch, 'exec-noop.sql') },
      { target: alias, file: join(scratch, 'exec-unique.sql'), 'dry-run': true },
      { target: alias, file: join(scratch, 'exec-cast.sql'), 'dry-run': true },
    ],
    'db backup': [{ target: alias }],
    'db backup-verify': [{ target: alias }],
    'db migrations': [
      ...(argValues(alias).target ?? []).map((target) => ({ target })),
      { target: alias, table: 'schema_migrations' },
      { target: alias, dir: '/opt/canary' },
    ],
  };
}

/** `db exec` change files: a dry run reading every canary column, a committed no-op (so the audit
 *  row and its SQL side file are written), and two that fail on the planted row with psql's
 *  value-quoting error texts. */
const CANARY_EXEC_SQL: Record<string, string> = {
  'exec-read.sql': 'UPDATE canary_users SET email = email;\nSELECT * FROM canary_users;\n',
  'exec-noop.sql': 'UPDATE canary_users SET email = email WHERE false;\n',
  'exec-unique.sql': 'UPDATE canary_users SET email = email;\nSELECT canary_unique_violation();\n',
  'exec-cast.sql': 'SELECT email, password::int FROM canary_users;\n',
};

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
  'SSHEPHERD_AUDIT_PATH',
  'SSHEPHERD_TUNNEL_STATE_DIR',
  'SSHEPHERD_EXEC_DIR',
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
      `[${alias}]\nalias = "${alias}"\ncontainer = "${PREFIX}-postgres"\nuser = "sshepherd_ro"\ndatabase = "fixture"\nwrite_role = "postgres"\ncontainers = ["${CANARY_CONTAINER}", "${CANARY_APP}"]\n`,
      `[${pgConnectTarget(alias)}]\nalias = "${alias}"\ncontainer = "${PREFIX}-canary-pg"\nuser = "sshepherd_ro"\ndatabase = "fixture"\n`,
      `[${envUrlTarget(alias)}]\nalias = "${alias}"\nkind = "container-env"\ncontainer = "${ENV_URL_CONTAINER}"\n`,
      `[${envViaTarget(alias)}]\nalias = "${alias}"\nkind = "container-env"\ncontainer = "${ENV_URL_CONTAINER}"\nenv_key = "DATABASE_URL"\npsql_container = "${PREFIX}-postgres"\n`,
    ])
    .join('\n');
  writeFileSync(join(scratch, 'targets.toml'), targets);
  for (const [name, sql] of Object.entries(CANARY_EXEC_SQL)) {
    writeFileSync(join(scratch, name), sql);
  }
  const paths = ['/opt/canary', CANARY_REPO, ...CANARY_FILES].map((path) => `"${path}"`).join(', ');
  const allowlist = aliases.map((alias) => `[${alias}]\npaths = [${paths}]\n`).join('\n');
  writeFileSync(join(scratch, 'files-allowlist.toml'), allowlist);
  writeFileSync(join(scratch, 'config-allowlist.toml'), allowlist);
  writeFileSync(join(scratch, 'reveal-allowlist.toml'), '');
  mkdirSync(join(scratch, 'exec'), { mode: 0o700 });
  for (const alias of aliases) {
    writeFileSync(join(scratch, 'exec', `${alias}.toml`), execDefs(), { mode: 0o600 });
  }
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

/** The named-exec definitions both aliases declare: the artisan stand-in, a path param under
 *  /opt/canary (each planted file through it), the canary container's whole environment, and a
 *  mutating def that prints the planted files. */
function execDefs(): string {
  return [
    '[app-artisan]',
    'argv = ["php", "artisan", "{cmd}"]',
    'mutating = false',
    '[app-artisan.params.cmd]',
    'type = "enum"',
    'values = ["migrate:status"]',
    '',
    '[canary-cat]',
    'argv = ["cat", "{file}"]',
    'mutating = false',
    '[canary-cat.params.file]',
    'type = "path"',
    'under = "/opt/canary"',
    '',
    '[canary-env]',
    'argv = ["env"]',
    'mutating = false',
    `container = "${CANARY_CONTAINER}"`,
    '',
    '[canary-show]',
    'argv = ["cat", "/opt/canary/.env", "/opt/canary/config.json", "/opt/canary/server.pem"]',
    'mutating = true',
    '',
  ].join('\n');
}

/** Every required arg gets each of its values (a new op with an arg nobody named here fails, it
 *  is never skipped); `files download` writes into the scratch dir so the file can be searched. */
function drivesFor(op: OpSpec, alias: string): Drive[] {
  const name = `${op.group} ${op.name}`;
  const explicit = explicitDrives(alias)[name];
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

/** `value` as an op could hand it back encoded: hex (either case), percent-encoded bytes, and the
 *  base64/base64url core it has at each of the three byte alignments inside a longer payload. */
function encodedForms(value: string): string[] {
  const bytes = Buffer.from(value);
  const hex = bytes.toString('hex');
  const forms = [
    hex,
    hex.toUpperCase(),
    [...bytes].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join(''),
  ];
  for (let offset = 0; offset < 3; offset += 1) {
    const padded = Buffer.concat([Buffer.alloc(offset), bytes]);
    const skip = Math.ceil((offset * 4) / 3) + (offset === 0 ? 0 : 1);
    const base64 = padded.toString('base64').replace(/=+$/, '');
    const core = base64.slice(skip, base64.length - 2);
    forms.push(core, core.replaceAll('+', '-').replaceAll('/', '_'));
  }
  return forms;
}

/** The text with every encoded run decoded beside it: base64/base64url (gunzipped too when it is
 *  gzip), hex, and percent-encoding, so a needle finds a value however an op wrapped it. */
function decodedViews(text: string): string {
  const views = [text];
  for (const run of text.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? []) {
    const bytes = Buffer.from(run.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
    views.push(bytes.toString('latin1'));
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
      try {
        views.push(gunzipSync(bytes).toString('latin1'));
      } catch {
        // a truncated gzip stream decodes to nothing; the base64 view above still stands
      }
    }
  }
  for (const run of text.match(/(?:[0-9a-fA-F]{2}){8,}/g) ?? []) {
    views.push(Buffer.from(run, 'hex').toString('latin1'));
  }
  views.push(
    text.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
      try {
        return decodeURIComponent(run);
      } catch {
        return run;
      }
    }),
  );
  return views.join('\n');
}

/** Each planted value, as the test searches for it: `where` it may never appear, in plain text or
 *  any encoding `encodedForms`/`decodedViews` cover. The identity and the peer address are
 *  envelope-and-audit only — a file `files download` writes is the user's own bytes and keeps its
 *  addresses by design. The port is digits only, so it is matched in plain text only. */
function needles(): { name: string; found: (text: string) => boolean; envelopeOnly: boolean }[] {
  const anyForm = (value: string, fold: boolean) => {
    const forms = encodedForms(value);
    return (text: string) => {
      const plain = fold ? decodedViews(text).toLowerCase() : decodedViews(text);
      return (
        plain.includes(fold ? value.toLowerCase() : value) ||
        forms.some((form) => text.includes(form))
      );
    };
  };
  const portPattern = new RegExp(`(?<![\\d.])${identity.port}(?!\\d)`);
  return [
    { name: 'canary', found: anyForm(canary, false), envelopeOnly: false },
    { name: 'digits', found: anyForm(digits, false), envelopeOnly: false },
    { name: 'identity-user', found: anyForm(identity.user, true), envelopeOnly: true },
    { name: 'identity-host', found: anyForm(identity.host, true), envelopeOnly: true },
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
  test('every skipped op is registered, carries a reason, and the count is the reviewed one', () => {
    const registered = listOps().map((op) => `${op.group} ${op.name}`);
    for (const [name, reason] of Object.entries(SKIP)) {
      expect({
        name,
        registered: registered.includes(name),
        reason: reason.trim().length > 0,
      }).toEqual({
        name,
        registered: true,
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
    process.env.SSHEPHERD_AUDIT_PATH = join(scratch, 'audit-tail-source.jsonl');
    process.env.SSHEPHERD_TUNNEL_STATE_DIR = join(scratch, 'tunnels');
    process.env.SSHEPHERD_EXEC_DIR = join(scratch, 'exec');
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
    test(`${variant}: every op, whatever its exposes label, returns, audits and downloads 0 canary hits`, async () => {
      const alias = `smoke-${variant}`;
      const results: DriveResult[] = [];
      let index = 0;
      for (const op of listOps()) {
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
      const opOf = (result: DriveResult): string => result.label.split(' ').slice(0, 2).join(' ');
      const driven = new Set(results.map(opOf));
      expect(listOps().length - Object.keys(SKIP).length).toBe(driven.size);
      const okDriven = new Set(results.filter((result) => result.status === 'ok').map(opOf));
      expect([...driven].filter((name) => !okDriven.has(name))).toEqual([]);

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
    test(`${variant}: http --auth: the canary key is in no remote process argv while the request runs, nor in what comes back`, async () => {
      const alias = `smoke-${variant}`;
      const op = listOps().find((entry) => entry.group === 'http' && entry.name === 'get');
      if (op === undefined) {
        throw new Error('no op http get');
      }
      const sampler = Bun.spawn(
        [
          'docker',
          'exec',
          `${PREFIX}-sshd-${variant}`,
          'sh',
          '-c',
          'end=$(($(date +%s) + 12)); while [ "$(date +%s)" -lt "$end" ]; do ps -eo args; echo __SAMPLE__; done',
        ],
        { stdout: 'pipe', stderr: 'pipe' },
      );
      await Bun.sleep(500);
      const auditLogPath = join(scratch, `audit-ps-${alias}.jsonl`);
      const envelope = await executeOp(
        op,
        {
          alias,
          args: { url: 'http://127.0.0.1:80/slow', auth: `env:API_KEY@container=${CANARY_APP}` },
        },
        {
          transport: { runner: recordingRunner, sshConfigPath: sshConfig },
          sshConfigPath: sshConfig,
          auditLogPath,
        },
      );
      const samples = await new Response(sampler.stdout).text();
      await sampler.exited;
      const data = envelope.data as { status: number; body_bytes: number } | null;
      const curlSamples = samples.split('\n').filter((line) => line.startsWith('curl '));
      expect({
        status: data?.status,
        bytes: data?.body_bytes,
        sampled: samples.split('__SAMPLE__').length > 10,
        curlSeen: curlSamples.length > 0,
        inArgv: samples.includes(canary),
        inEnvelope: JSON.stringify(envelope).includes(canary),
        inStderrTail: (envelope.error?.stderr_tail ?? '').includes(canary),
        inAudit: readFileSync(auditLogPath, 'utf8').includes(canary),
      }).toEqual({
        status: 200,
        bytes: 4096,
        sampled: true,
        curlSeen: true,
        inArgv: false,
        inEnvelope: false,
        inStderrTail: false,
        inAudit: false,
      });
    }, 60_000);
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
        const names = new Set(['env keys', 'env diff', 'services inspect', 'services ps']);
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
        // No planted value crossed the wire at all: the host reduced Env to key names (inspect)
        // or docker was asked for a template without Config.Env (ps).
        expect(
          results
            .filter((result) => /^services (ps|inspect)\b/.test(result.label))
            .map((result) => `${result.label}: ${result.reached.join(',') || '-'}`),
        ).toEqual(
          results
            .filter((result) => /^services (ps|inspect)\b/.test(result.label))
            .map((result) => `${result.label}: -`),
        );

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

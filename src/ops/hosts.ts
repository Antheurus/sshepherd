import { createHash, createHmac, randomBytes } from 'node:crypto';
import {
  accessSync,
  constants,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { type DiagnoseStage, type DiagnoseStageName, diagnoseHost } from '../hosts-diagnose.ts';
import { HOSTS_TEST_TIMEOUT_SEC } from '../limits.ts';
import { arg, DEFAULT_TIMEOUT_SEC, optBool } from '../op-args.ts';
import { parseOsRelease } from '../parsers/os-release.ts';
import { splitSections } from '../parsers/sections.ts';
import { listHostAliases } from '../parsers/ssh-config.ts';
import { parseUptime } from '../parsers/uptime.ts';
import { shellJoin } from '../quote.ts';
import { closeAllMasters, closeMaster, type ScannedHostKey, scanHostKeys } from '../transport.ts';
import { OpError, OpRunLocalError, type OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

interface HostsListResult {
  aliases: string[];
}

interface HostsTestResult {
  reachable: boolean;
  /** `--diagnose` only. */
  stages?: DiagnoseStage[];
  failed_at?: DiagnoseStageName | null;
  likely_cause?: string | null;
}

interface HostInfoResult {
  hostname: string;
  kernel: string;
  nproc: number;
  uptime: ReturnType<typeof parseUptime>;
  os: Record<string, string>;
}

const hostsList: OpSpec<HostsListResult> = {
  group: 'hosts',
  name: 'list',
  summary: 'List configured ssh aliases (alias names only — never HostName/User/Port).',
  args: [],
  mutating: false,
  exposes: 'none',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as HostsListResult,
  runLocal: (_ctx, sshConfigPath) => ({ aliases: listHostAliases(sshConfigPath) }),
};

const hostsTest: OpSpec<HostsTestResult> = {
  group: 'hosts',
  name: 'test',
  summary:
    'Confirm the alias connects (latency is the envelope duration_ms); --diagnose places a failure at dns, tcp, banner, auth or echo.',
  args: [
    arg(
      'diagnose',
      'flag',
      false,
      'Probe each stage (dns, tcp, banner, auth, echo) with a verdict, instead of one echo.',
    ),
  ],
  mutating: false,
  exposes: 'none',
  timeoutSec: HOSTS_TEST_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) =>
    optBool(ctx, 'diagnose', false) ? null : shellJoin(['echo', 'sshepherd-ok']),
  shape: (parsed) => ({ reachable: (parsed as string).trim() === 'sshepherd-ok' }),
  runLocal: (ctx, _sshConfigPath, transport) => diagnoseHost(ctx.alias, transport),
};

function buildHostsInfoScript(): string {
  return [
    'echo __HOSTNAME__',
    'hostname',
    'echo __UNAME__',
    'uname -a',
    'echo __NPROC__',
    'nproc',
    'echo __UPTIME__',
    'uptime',
    'echo __OS__',
    'cat /etc/os-release 2>/dev/null || true',
  ].join('; ');
}

const hostsInfo: OpSpec<HostInfoResult> = {
  group: 'hosts',
  name: 'info',
  summary: 'Bundled hostname/kernel/nproc/uptime/os-release for the alias.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () => shellJoin(['sh', '-c', buildHostsInfoScript()]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const nproc = Number.parseInt((sections.NPROC ?? '').trim(), 10);
    return {
      hostname: (sections.HOSTNAME ?? '').trim(),
      kernel: (sections.UNAME ?? '').trim(),
      nproc: Number.isNaN(nproc) ? 0 : nproc,
      uptime: parseUptime(sections.UPTIME ?? ''),
      os: parseOsRelease(sections.OS ?? ''),
    };
  },
};

interface HostsDisconnectResult {
  closed: number;
}

const hostsDisconnect: OpSpec<HostsDisconnectResult> = {
  group: 'hosts',
  name: 'disconnect',
  summary:
    'Close the reused SSH connection for an alias, or every one with --all (they self-close after 5 idle minutes).',
  args: [
    arg('alias', 'positional', false, 'Alias whose connection to close.'),
    arg('all', 'flag', false, 'Close the connection of every alias.'),
  ],
  mutating: false,
  exposes: 'none',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as HostsDisconnectResult,
  runLocal: async (ctx, _sshConfigPath, transport) => {
    const all = optBool(ctx, 'all', false);
    if (all && ctx.alias.length > 0) {
      throw new OpRunLocalError(
        'VALIDATION_ERROR',
        'hosts disconnect: pass an alias or --all, not both',
      );
    }
    if (all) {
      return { closed: await closeAllMasters(transport) };
    }
    if (ctx.alias.length === 0) {
      throw new OpRunLocalError('VALIDATION_ERROR', 'hosts disconnect: pass an alias or --all');
    }
    return { closed: (await closeMaster(ctx.alias, transport)) ? 1 : 0 };
  },
};

interface HostKeyFingerprint {
  type: string;
  fingerprint: string;
}

interface HostsTrustResult {
  /** What the host presents right now, as `ssh-keygen -l` prints it. */
  fingerprints: HostKeyFingerprint[];
  written: boolean;
  /** known_hosts lines for this host that the trusted key replaced (a changed key's old entry). */
  replaced_entries: number;
}

const FINGERPRINT_SHAPE = /^SHA256:[A-Za-z0-9+/]{43}$/;

function fingerprintOf(key: ScannedHostKey): string {
  const digest = createHash('sha256').update(Buffer.from(key.key, 'base64')).digest('base64');
  return `SHA256:${digest.replace(/=+$/, '')}`;
}

/** ssh's hashed known_hosts name: `|1|<base64 salt>|<base64 HMAC-SHA1(salt, name)>`. */
function hashedName(name: string, salt: Buffer): string {
  const mac = createHmac('sha1', salt).update(name).digest('base64');
  return `|1|${salt.toString('base64')}|${mac}`;
}

/** Whether a known_hosts line is a plain or hashed entry for one of `names`; markers
 *  (`@cert-authority`, `@revoked`) and comments are never this op's to replace. */
function isEntryFor(line: string, names: string[]): boolean {
  const field = line.trim().split(/\s+/)[0] ?? '';
  if (field.length === 0 || field.startsWith('#') || field.startsWith('@')) {
    return false;
  }
  if (field.startsWith('|1|')) {
    const salt = field.split('|')[2] ?? '';
    return names.some((name) => hashedName(name, Buffer.from(salt, 'base64')) === field);
  }
  return field.split(',').some((entry) => names.includes(entry));
}

interface KnownHostEntry {
  line: string;
  type: string;
  key: string;
}

function readKnownHosts(file: string): string {
  try {
    return readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return '';
    }
    throw unwritable(err);
  }
}

/** This host's plain and hashed entries in `text`. */
function entriesFor(text: string, names: string[]): KnownHostEntry[] {
  return text
    .split('\n')
    .filter((line) => isEntryFor(line, names))
    .map((line) => {
      const [, type = '', key = ''] = line.trim().split(/\s+/);
      return { line, type, key };
    });
}

const UNWRITABLE_REASONS: Record<string, string> = {
  EACCES: 'permission denied',
  EPERM: 'permission denied',
  EROFS: 'it is on a read-only file system',
  ENOSPC: 'the disk is full',
};

/** A known_hosts the trust cannot write, named by kind only: its path sits under the user's home. */
function unwritable(err: unknown): OpRunLocalError {
  const code = (err as NodeJS.ErrnoException).code ?? '';
  const reason = UNWRITABLE_REASONS[code] ?? `the write failed (${code || 'unknown error'})`;
  return new OpRunLocalError(
    'KNOWN_HOSTS_UNWRITABLE',
    `hosts trust: the alias's known_hosts cannot be written: ${reason}; nothing was recorded`,
  );
}

/** Refuses before anything is written when the file is a sink that keeps nothing (`/dev/null`, any
 *  device or other non-regular file) or cannot be written, so a trust never reports `written` for a
 *  key the next connection will not find. */
function assertRecordable(file: string): void {
  if (file === '/dev/null') {
    throw new OpRunLocalError(
      'KNOWN_HOSTS_UNWRITABLE',
      "hosts trust: the alias's UserKnownHostsFile is /dev/null, which keeps nothing, so strict checking can never find a trusted key; nothing was recorded",
      {
        hint: "Point the alias's UserKnownHostsFile at a real file (or remove that line to use ~/.ssh/known_hosts), then run hosts trust again.",
      },
    );
  }
  let target = file;
  try {
    if (!statSync(file).isFile()) {
      throw new OpRunLocalError(
        'KNOWN_HOSTS_UNWRITABLE',
        "hosts trust: the alias's known_hosts is not a regular file, so it cannot keep a trusted key; nothing was recorded",
      );
    }
  } catch (err) {
    if (err instanceof OpRunLocalError) {
      throw err;
    }
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw unwritable(err);
    }
    target = existingAncestor(dirname(file));
  }
  try {
    accessSync(target, constants.W_OK);
  } catch (err) {
    throw unwritable(err);
  }
}

function existingAncestor(dir: string): string {
  let current = dir;
  while (!existsSync(current) && dirname(current) !== current) {
    current = dirname(current);
  }
  return current;
}

/** Records `trusted` and drops this host's stale entries — every one whose key the host no longer
 *  presents — in place (a symlinked known_hosts stays a symlink). An entry the host still presents
 *  is kept, so trusting RSA leaves a valid ed25519 entry alone and a repeat trust adds no
 *  duplicate. Returns how many stale entries were dropped. */
function recordKnownHosts(
  file: string,
  trusted: ScannedHostKey[],
  presented: ScannedHostKey[],
  hashNames: boolean,
): number {
  const names = (trusted[0]?.name ?? '').split(',');
  const existing = readKnownHosts(file);
  const lines = existing.length === 0 ? [] : existing.replace(/\n$/, '').split('\n');
  const isPresented = (type: string, key: string): boolean =>
    presented.some((candidate) => candidate.type === type && candidate.key === key);
  const kept = lines.filter((line) => {
    if (!isEntryFor(line, names)) {
      return true;
    }
    const [, type = '', key = ''] = line.trim().split(/\s+/);
    return isPresented(type, key);
  });
  const keptEntries = entriesFor(kept.join('\n'), names);
  const added = trusted
    .filter((key) => !keptEntries.some((entry) => entry.type === key.type && entry.key === key.key))
    .map((key) => {
      const name = hashNames ? hashedName(names[0] ?? key.name, randomBytes(20)) : key.name;
      return `${name} ${key.type} ${key.key}`;
    });
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, `${[...kept, ...added].join('\n')}\n`, { mode: 0o600 });
  } catch (err) {
    throw unwritable(err);
  }
  return lines.length - kept.length;
}

/** The trusted keys as the file now holds them; a write that did not stick is refused. */
function assertRecorded(file: string, trusted: ScannedHostKey[]): void {
  const names = (trusted[0]?.name ?? '').split(',');
  const entries = entriesFor(readKnownHosts(file), names);
  const missing = trusted.filter(
    (key) => !entries.some((entry) => entry.type === key.type && entry.key === key.key),
  );
  if (missing.length > 0) {
    throw new OpRunLocalError(
      'KNOWN_HOSTS_UNWRITABLE',
      "hosts trust: the alias's known_hosts was written but reading it back does not find the trusted key; nothing that ssh will use was recorded",
    );
  }
}

const TRUST_HINT =
  'Run hosts trust <alias> --dry-run, have a human confirm a fingerprint out of band (the provider console, or ssh-keygen -l on the host itself), then pass it with --fingerprint <SHA256:...> --yes.';

const hostsTrust: OpSpec<HostsTrustResult> = {
  group: 'hosts',
  name: 'trust',
  summary:
    "Show every host key fingerprint the alias presents (--dry-run), or record the key whose fingerprint --fingerprint names in the alias's known_hosts (--yes; --all-types records every presented key).",
  args: [
    arg(
      'fingerprint',
      'flag',
      false,
      'SHA256:... fingerprint a human confirmed out of band; recorded only when the host presents a key with exactly this one.',
    ),
    arg('dry-run', 'flag', false, 'Show the presented fingerprints; record nothing.'),
    arg(
      'all-types',
      'flag',
      false,
      'Once --fingerprint matches one presented key, record every key type the host presents, not only that one.',
    ),
  ],
  mutating: true,
  exposes: 'none',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as HostsTrustResult,
  runLocal: async (ctx, _sshConfigPath, transport) => {
    const scan = await scanHostKeys(ctx.alias, transport);
    if (scan.error !== null) {
      throw new OpError(scan.error.code, scan.error.message, {
        hint: scan.error.hint,
        next: scan.error.next,
        did_you_mean: scan.error.did_you_mean,
      });
    }
    const fingerprints = scan.keys.map((key) => ({
      type: key.type,
      fingerprint: fingerprintOf(key),
    }));
    if (optBool(ctx, 'dry-run', false)) {
      return { fingerprints, written: false, replaced_entries: 0 };
    }
    const expected = ctx.args.fingerprint;
    if (typeof expected !== 'string' || !FINGERPRINT_SHAPE.test(expected)) {
      throw new OpRunLocalError(
        'VALIDATION_ERROR',
        'hosts trust: pass --fingerprint SHA256:<43 base64 chars> — the fingerprint a human confirmed',
        { hint: TRUST_HINT, next: `sshepherd hosts trust ${ctx.alias} --dry-run` },
      );
    }
    const match = scan.keys.find((key) => fingerprintOf(key) === expected);
    if (match === undefined) {
      const presented = fingerprints.map((entry) => entry.fingerprint).join(', ');
      const known = entriesFor(
        readKnownHosts(scan.knownHostsFile),
        (scan.keys[0]?.name ?? '').split(','),
      );
      const changed =
        known.length > 0 &&
        !known.some((entry) =>
          scan.keys.some((key) => key.type === entry.type && key.key === entry.key),
        );
      throw new OpRunLocalError(
        changed ? 'HOST_KEY_CHANGED' : 'HOST_KEY_FINGERPRINT_MISMATCH',
        `hosts trust: the host presents ${presented}, not ${expected}; nothing was recorded`,
        {
          hint: changed
            ? 'known_hosts holds a key for this host that it no longer presents, and none it presents is the one that was confirmed; find out why before trusting anything.'
            : known.length > 0
              ? 'known_hosts already trusts a key this host presents, so this is a fingerprint that does not match rather than a changed key: compare with the fingerprint from the provider console (or ssh-keygen -l on the host itself) and pass the one the host presents.'
              : 'compare with the fingerprint from the provider console (or ssh-keygen -l on the host itself) and pass the one the host presents; nothing was trusted for this host yet.',
          next: `sshepherd hosts trust ${ctx.alias} --dry-run`,
        },
      );
    }
    assertRecordable(scan.knownHostsFile);
    const trusted = optBool(ctx, 'all-types', false) ? scan.keys : [match];
    const replaced = recordKnownHosts(scan.knownHostsFile, trusted, scan.keys, scan.hashNames);
    assertRecorded(scan.knownHostsFile, trusted);
    return { fingerprints, written: true, replaced_entries: replaced };
  },
};

export const hostsOps = [hostsList, hostsTest, hostsInfo, hostsDisconnect, hostsTrust] as OpSpec[];

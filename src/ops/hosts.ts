import { createHash, createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
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

/** Appends the key and drops this host's older entries, in place (a symlinked known_hosts stays
 *  a symlink); returns how many entries were dropped. */
function recordKnownHost(file: string, key: ScannedHostKey, hashNames: boolean): number {
  let existing = '';
  try {
    existing = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
  }
  const names = key.name.split(',');
  const lines = existing.length === 0 ? [] : existing.replace(/\n$/, '').split('\n');
  const kept = lines.filter((line) => !isEntryFor(line, names));
  const name = hashNames ? hashedName(names[0] ?? key.name, randomBytes(20)) : key.name;
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${[...kept, `${name} ${key.type} ${key.key}`].join('\n')}\n`, {
    mode: 0o600,
  });
  return lines.length - kept.length;
}

const TRUST_HINT =
  'Run hosts trust <alias> --dry-run, have a human confirm a fingerprint out of band (the provider console, or ssh-keygen -l on the host itself), then pass it with --fingerprint <SHA256:...> --yes.';

const hostsTrust: OpSpec<HostsTrustResult> = {
  group: 'hosts',
  name: 'trust',
  summary:
    "Show the host key fingerprint the alias presents (--dry-run), or record it in the alias's known_hosts once --fingerprint matches it (--yes).",
  args: [
    arg(
      'fingerprint',
      'flag',
      false,
      'SHA256:... fingerprint a human confirmed out of band; the key is recorded only when the host presents exactly this one.',
    ),
    arg('dry-run', 'flag', false, 'Show the presented fingerprints; record nothing.'),
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
      throw new OpRunLocalError(
        'HOST_KEY_CHANGED',
        `hosts trust: the host presents ${fingerprints.map((entry) => entry.fingerprint).join(', ')}, not ${expected}; nothing was recorded`,
        {
          hint: 'The key the host presents is not the one that was confirmed; find out why before trusting anything.',
          next: `sshepherd hosts trust ${ctx.alias} --dry-run`,
        },
      );
    }
    const replaced = recordKnownHost(scan.knownHostsFile, match, scan.hashNames);
    return { fingerprints, written: true, replaced_entries: replaced };
  },
};

export const hostsOps = [hostsList, hostsTest, hostsInfo, hostsDisconnect, hostsTrust] as OpSpec[];

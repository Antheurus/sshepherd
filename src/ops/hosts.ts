import { HOSTS_TEST_TIMEOUT_SEC } from '../limits.ts';
import { arg, DEFAULT_TIMEOUT_SEC, optBool } from '../op-args.ts';
import { parseOsRelease } from '../parsers/os-release.ts';
import { splitSections } from '../parsers/sections.ts';
import { listHostAliases } from '../parsers/ssh-config.ts';
import { parseUptime } from '../parsers/uptime.ts';
import { shellJoin } from '../quote.ts';
import { closeAllMasters, closeMaster } from '../transport.ts';
import { OpRunLocalError, type OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

interface HostsListResult {
  aliases: string[];
}

interface HostsTestResult {
  reachable: boolean;
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
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as HostsListResult,
  runLocal: (_ctx, sshConfigPath) => ({ aliases: listHostAliases(sshConfigPath) }),
};

const hostsTest: OpSpec<HostsTestResult> = {
  group: 'hosts',
  name: 'test',
  summary: 'Confirm the alias connects (latency is the envelope duration_ms).',
  args: [],
  mutating: false,
  timeoutSec: HOSTS_TEST_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => shellJoin(['echo', 'sshepherd-ok']),
  shape: (parsed) => ({ reachable: (parsed as string).trim() === 'sshepherd-ok' }),
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

export const hostsOps = [hostsList, hostsTest, hostsInfo, hostsDisconnect] as OpSpec[];

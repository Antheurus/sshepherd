import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { auditMutating, confirmGate } from './audit.ts';
import {
  assertNoMultiStatementSql,
  assertSelectOnly,
  buildDbSlowCommand,
  buildPsqlCommand,
  type DbConnection,
  wrapAsJsonAgg,
  wrapReadOnlyTxn,
} from './db.ts';
import { buildEnvelope, splitNdjson } from './output.ts';
import { parseHumanBytes, parseHumanBytesPair, parsePercent } from './parsers/bytes.ts';
import { parseDf, parseDfInodes } from './parsers/df.ts';
import { parseDmesgOom } from './parsers/dmesg-oom.ts';
import { parseDockerLogLines } from './parsers/docker-log.ts';
import { type PortMapping, parseInspectPorts } from './parsers/docker-ports.ts';
import { parseDu } from './parsers/du.ts';
import { parseFree } from './parsers/free.ts';
import { shapeJournalEntry } from './parsers/journal.ts';
import { buildLogsResult } from './parsers/logs-shape.ts';
import { parseLs } from './parsers/ls.ts';
import { parseOsRelease } from './parsers/os-release.ts';
import { parsePs } from './parsers/ps.ts';
import { parsePsi } from './parsers/psi.ts';
import { splitSections } from './parsers/sections.ts';
import { parseSs } from './parsers/ss.ts';
import { listHostAliases } from './parsers/ssh-config.ts';
import { parseSysctl } from './parsers/sysctl.ts';
import { parseSystemctlShow } from './parsers/systemctl-show.ts';
import { parseUptime } from './parsers/uptime.ts';
import { computeDeadEndRisk } from './parsers/verdict.ts';
import { shellJoin, shq } from './quote.ts';
import {
  buildMigrateScript,
  buildRollbackCommand,
  buildRunScript,
  type DeployPlan,
  loadRecipe,
  planRecipe,
} from './recipes.ts';
import { defaultTargetsPath, loadTargets } from './targets.ts';
import { errorInfo, run, type TransportDeps } from './transport.ts';
import type { ArgSpec, Envelope, OpContext, OpSpec, OutputMode } from './types.ts';

const DEFAULT_TIMEOUT_SEC = 12;
const LOG_TIMEOUT_SEC = 20;
const FILE_TIMEOUT_SEC = 25;
const DOWNLOAD_TIMEOUT_SEC = 30;
const DB_TIMEOUT_SEC = 20;
const DEPLOY_TIMEOUT_SEC = 300;
const DEFAULT_LOG_TAIL = 200;
const FILE_CAT_MAX_BYTES = 1_048_576; // 1 MiB
const DOWNLOAD_MAX_BYTES = 10_485_760; // 10 MiB

// ---------------------------------------------------------------------------
// Arg helpers — every buildRemote/shape reads args through these so a missing
// required arg fails the same way everywhere.
// ---------------------------------------------------------------------------

function reqStr(ctx: OpContext, key: string): string {
  const value = ctx.args[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`missing required arg '${key}'`);
  }
  return value;
}

function optStr(ctx: OpContext, key: string, fallback: string): string {
  const value = ctx.args[key];
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

function optStrOrNull(ctx: OpContext, key: string): string | null {
  const value = ctx.args[key];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function optBool(ctx: OpContext, key: string, fallback: boolean): boolean {
  const value = ctx.args[key];
  return typeof value === 'boolean' ? value : fallback;
}

function arg(name: string, kind: ArgSpec['kind'], required: boolean, description: string): ArgSpec {
  return { name, kind, required, description };
}

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
  timeoutSec: DEFAULT_TIMEOUT_SEC,
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

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

interface CheckOverviewResult {
  nproc: number;
  mem: ReturnType<typeof parseFree>;
  disk: ReturnType<typeof parseDf>;
  uptime: ReturnType<typeof parseUptime>;
  psi_mem: ReturnType<typeof parsePsi>;
  dead_end_risk: boolean;
}

const checkOverview: OpSpec<CheckOverviewResult> = {
  group: 'check',
  name: 'overview',
  summary: 'Bundled survival denominators: nproc/mem/disk/uptime/PSI + a dead_end_risk verdict.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    shellJoin([
      'sh',
      '-c',
      [
        'echo __NPROC__',
        'nproc',
        'echo __FREE__',
        'free -b',
        'echo __DF__',
        'df -B1 -P',
        'echo __UPTIME__',
        'uptime',
        'echo __PSI__',
        'cat /proc/pressure/memory 2>/dev/null || true',
      ].join('; '),
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const nproc = Number.parseInt((sections.NPROC ?? '').trim(), 10);
    const disk = parseDf(sections.DF ?? '');
    const psi = parsePsi(sections.PSI ?? '');
    return {
      nproc: Number.isNaN(nproc) ? 0 : nproc,
      mem: parseFree(sections.FREE ?? ''),
      disk,
      uptime: parseUptime(sections.UPTIME ?? ''),
      psi_mem: psi,
      dead_end_risk: computeDeadEndRisk({
        diskUsePercents: disk.map((entry) => entry.use_percent),
        memSomeAvg10: psi ? psi.some_avg10 : null,
      }),
    };
  },
};

interface CheckMemResult {
  mem: ReturnType<typeof parseFree>;
  psi_mem: ReturnType<typeof parsePsi>;
  dead_end_risk: boolean;
}

const checkMem: OpSpec<CheckMemResult> = {
  group: 'check',
  name: 'mem',
  summary: 'Memory usage + PSI pressure with a dead_end_risk verdict.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    shellJoin([
      'sh',
      '-c',
      [
        'echo __FREE__',
        'free -b',
        'echo __PSI__',
        'cat /proc/pressure/memory 2>/dev/null || true',
      ].join('; '),
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const psi = parsePsi(sections.PSI ?? '');
    return {
      mem: parseFree(sections.FREE ?? ''),
      psi_mem: psi,
      dead_end_risk: computeDeadEndRisk({
        diskUsePercents: [],
        memSomeAvg10: psi ? psi.some_avg10 : null,
      }),
    };
  },
};

interface CheckDiskResult {
  disk: ReturnType<typeof parseDf>;
  inodes: ReturnType<typeof parseDfInodes>;
  top_du: ReturnType<typeof parseDu>;
  dead_end_risk: boolean;
}

const checkDisk: OpSpec<CheckDiskResult> = {
  group: 'check',
  name: 'disk',
  summary: 'Disk usage + inodes + top space consumers with a dead_end_risk verdict.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    shellJoin([
      'sh',
      '-c',
      [
        'echo __DF__',
        'df -B1 -P',
        'echo __DFI__',
        'df -i -P',
        'echo __DU__',
        'du -sb /var/log /var/lib/docker 2>/dev/null || true',
      ].join('; '),
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const disk = parseDf(sections.DF ?? '');
    return {
      disk,
      inodes: parseDfInodes(sections.DFI ?? ''),
      top_du: parseDu(sections.DU ?? ''),
      dead_end_risk: computeDeadEndRisk({
        diskUsePercents: disk.map((entry) => entry.use_percent),
        memSomeAvg10: null,
      }),
    };
  },
};

interface CheckCpuResult {
  uptime: ReturnType<typeof parseUptime>;
  nproc: number;
  top_processes: ReturnType<typeof parsePs>;
}

const checkCpu: OpSpec<CheckCpuResult> = {
  group: 'check',
  name: 'cpu',
  summary: 'Load average vs core count + top CPU processes.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    shellJoin([
      'sh',
      '-c',
      [
        'echo __UPTIME__',
        'uptime',
        'echo __NPROC__',
        'nproc',
        'echo __PS__',
        'ps aux --sort=-%cpu | head -n 15',
      ].join('; '),
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const nproc = Number.parseInt((sections.NPROC ?? '').trim(), 10);
    return {
      uptime: parseUptime(sections.UPTIME ?? ''),
      nproc: Number.isNaN(nproc) ? 0 : nproc,
      top_processes: parsePs(sections.PS ?? ''),
    };
  },
};

interface CheckPortsResult {
  listening: ReturnType<typeof parseSs>;
}

const checkPorts: OpSpec<CheckPortsResult> = {
  group: 'check',
  name: 'ports',
  summary: 'Listening TCP ports (ss -tlnp), structured — never a raw address string.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => shellJoin(['ss', '-H', '-tlnp']),
  shape: (parsed) => ({ listening: parseSs(parsed as string) }),
};

interface CheckOomHistoryResult {
  events: ReturnType<typeof parseDmesgOom>;
}

const checkOomHistory: OpSpec<CheckOomHistoryResult> = {
  group: 'check',
  name: 'oom-history',
  summary: 'Kernel OOM-killer events from dmesg (per-container OOM lives in services ps).',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () =>
    shellJoin(['sh', '-c', 'dmesg -T 2>/dev/null | grep -i "killed process" || true']),
  shape: (parsed) => ({ events: parseDmesgOom(parsed as string) }),
};

interface CheckKernelResult {
  swappiness: number | null;
  overcommit_memory: number | null;
  file_max: number | null;
  swapaccount_enabled: boolean;
}

const checkKernel: OpSpec<CheckKernelResult> = {
  group: 'check',
  name: 'kernel',
  summary: 'swappiness/overcommit_memory/file-max + cgroup swapaccount cmdline flag.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    shellJoin([
      'sh',
      '-c',
      [
        'echo __SYSCTL__',
        'sysctl vm.swappiness vm.overcommit_memory fs.file-max 2>/dev/null',
        'echo __CMDLINE__',
        'cat /proc/cmdline 2>/dev/null || true',
      ].join('; '),
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const sysctl = parseSysctl(sections.SYSCTL ?? '');
    const swappiness =
      sysctl['vm.swappiness'] !== undefined
        ? Number.parseInt(sysctl['vm.swappiness'], 10)
        : Number.NaN;
    const overcommit =
      sysctl['vm.overcommit_memory'] !== undefined
        ? Number.parseInt(sysctl['vm.overcommit_memory'], 10)
        : Number.NaN;
    const fileMax =
      sysctl['fs.file-max'] !== undefined ? Number.parseInt(sysctl['fs.file-max'], 10) : Number.NaN;
    return {
      swappiness: Number.isNaN(swappiness) ? null : swappiness,
      overcommit_memory: Number.isNaN(overcommit) ? null : overcommit,
      file_max: Number.isNaN(fileMax) ? null : fileMax,
      swapaccount_enabled: /swapaccount=1/.test(sections.CMDLINE ?? ''),
    };
  },
};

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

function buildLogsDocker(ctx: OpContext): string {
  const container = reqStr(ctx, 'container');
  const tail = optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL));
  const since = optStrOrNull(ctx, 'since');
  const parts = ['docker', 'logs', '--timestamps', '--tail', tail];
  if (since !== null) {
    parts.push('--since', since);
  }
  parts.push(container);
  return shellJoin(parts);
}

const logsDocker: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker',
  summary: 'Tail a container log as {ts, stream, text} line objects + next_since.',
  args: [
    arg('container', 'positional', true, 'Container name or ID.'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
    arg('since', 'flag', false, 'Only lines newer than this timestamp/duration.'),
  ],
  mutating: false,
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: buildLogsDocker,
  shape: (parsed, ctx) => {
    const lines = parseDockerLogLines(parsed as string);
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult(
      `docker:${reqStr(ctx, 'container')}`,
      lines,
      Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit,
    );
  },
};

function buildJournalCommand(unit: string, tail: string): string {
  return shellJoin(['journalctl', '-u', unit, '-n', tail, '-o', 'json', '--no-pager']);
}

function shapeJournalLines(parsed: unknown): ReturnType<typeof shapeJournalEntry>[] {
  const entries = parsed as unknown[];
  return entries.map(shapeJournalEntry).filter((line) => line !== null);
}

const logsService: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'service',
  summary: 'Tail a systemd unit journal as {ts, stream, text} line objects + next_since.',
  args: [
    arg('unit', 'positional', true, 'systemd unit name.'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) =>
    buildJournalCommand(reqStr(ctx, 'unit'), optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL))),
  shape: (parsed, ctx) => {
    const lines = shapeJournalLines(parsed).filter(
      (line): line is NonNullable<typeof line> => line !== null,
    );
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult(
      `service:${reqStr(ctx, 'unit')}`,
      lines,
      Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit,
    );
  },
};

const logsDockerDaemon: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'docker-daemon',
  summary: 'Tail the docker daemon journal (feeds the exit-137 differential).',
  args: [arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`)],
  mutating: false,
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) =>
    buildJournalCommand('docker', optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL))),
  shape: (parsed, ctx) => {
    const lines = shapeJournalLines(parsed).filter(
      (line): line is NonNullable<typeof line> => line !== null,
    );
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult('docker-daemon', lines, Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit);
  },
};

const NGINX_LOG_PATHS: Record<string, string> = {
  error: '/var/log/nginx/error.log',
  access: '/var/log/nginx/access.log',
};

const logsNginx: OpSpec<ReturnType<typeof buildLogsResult>> = {
  group: 'logs',
  name: 'nginx',
  summary: 'Tail the nginx error or access log.',
  args: [
    arg('stream', 'positional', true, '"error" or "access".'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const stream = reqStr(ctx, 'stream');
    const path = NGINX_LOG_PATHS[stream];
    if (path === undefined) {
      throw new Error(`unknown nginx log stream '${stream}' — expected "error" or "access"`);
    }
    return shellJoin(['tail', '-n', optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), path]);
  },
  shape: (parsed, ctx) => {
    const stream = reqStr(ctx, 'stream');
    const lines = (parsed as string)
      .split('\n')
      .map((line) => line.trimEnd())
      .filter((line) => line.length > 0)
      .map((text) => ({ ts: null, stream: 'stdout' as const, text }));
    const limit = Number.parseInt(optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL)), 10);
    return buildLogsResult(
      `nginx:${stream}`,
      lines,
      Number.isNaN(limit) ? DEFAULT_LOG_TAIL : limit,
    );
  },
};

// ---------------------------------------------------------------------------
// services
// ---------------------------------------------------------------------------

interface ServiceEntry {
  id: string;
  name: string;
  image: string;
  state: string;
  health: string | null;
  restart_count: number;
  oom_killed: boolean;
  exit_code: number | null;
  mem_limit_bytes: number | null;
  nano_cpus: number | null;
  oom_score_adj: number | null;
  restart_policy: string | null;
  ports: PortMapping[];
  compose_project: string | null;
  compose_service: string | null;
}

function readRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

function shapeServiceEntry(raw: unknown): ServiceEntry | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const state = readRecord(record.State);
  const hostConfig = readRecord(record.HostConfig);
  const networkSettings = readRecord(record.NetworkSettings);
  const config = readRecord(record.Config);
  const labels = readRecord(config.Labels);
  const health = readRecord(state.Health);
  const restartPolicy = readRecord(hostConfig.RestartPolicy);

  const memLimit =
    typeof hostConfig.Memory === 'number' && hostConfig.Memory > 0 ? hostConfig.Memory : null;
  const nanoCpus =
    typeof hostConfig.NanoCpus === 'number' && hostConfig.NanoCpus > 0 ? hostConfig.NanoCpus : null;

  return {
    id: typeof record.Id === 'string' ? record.Id.slice(0, 12) : '',
    name: typeof record.Name === 'string' ? record.Name.replace(/^\//, '') : '',
    image: typeof config.Image === 'string' ? config.Image : '',
    state: typeof state.Status === 'string' ? state.Status : 'unknown',
    health: typeof health.Status === 'string' ? health.Status : null,
    restart_count: typeof record.RestartCount === 'number' ? record.RestartCount : 0,
    oom_killed: state.OOMKilled === true,
    exit_code: typeof state.ExitCode === 'number' ? state.ExitCode : null,
    mem_limit_bytes: memLimit,
    nano_cpus: nanoCpus,
    oom_score_adj: typeof hostConfig.OomScoreAdj === 'number' ? hostConfig.OomScoreAdj : null,
    restart_policy: typeof restartPolicy.Name === 'string' ? restartPolicy.Name : null,
    ports: parseInspectPorts(networkSettings.Ports),
    compose_project:
      typeof labels['com.docker.compose.project'] === 'string'
        ? (labels['com.docker.compose.project'] as string)
        : null,
    compose_service:
      typeof labels['com.docker.compose.service'] === 'string'
        ? (labels['com.docker.compose.service'] as string)
        : null,
  };
}

const servicesPs: OpSpec<ServiceEntry[]> = {
  group: 'services',
  name: 'ps',
  summary:
    'All containers (running + stopped), each entry merged from docker inspect (health/restarts/oom/limits).',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: () =>
    shellJoin([
      'sh',
      '-c',
      // A missing `docker` binary must surface as COMMAND_FAILED, not a silently empty
      // list — `command -v` guard runs first so the "no containers" and "no docker"
      // cases stay distinguishable (see phase brief §Concerns).
      'command -v docker >/dev/null 2>&1 || exit 127; c=$(docker ps -aq); if [ -z "$c" ]; then echo "[]"; else docker inspect $c; fi',
    ]),
  shape: (parsed) => {
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.map(shapeServiceEntry).filter((entry): entry is ServiceEntry => entry !== null);
  },
};

interface ServiceStatsEntry {
  container: string;
  name: string;
  cpu_percent: number | null;
  mem_used_bytes: number | null;
  mem_limit_bytes: number | null;
  mem_percent: number | null;
  net_rx_bytes: number | null;
  net_tx_bytes: number | null;
  block_read_bytes: number | null;
  block_write_bytes: number | null;
  pids: number | null;
}

function shapeStatsEntry(raw: unknown): ServiceStatsEntry | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const memPair =
    typeof record.MemUsage === 'string'
      ? parseHumanBytesPair(record.MemUsage)
      : { used_bytes: null, limit_bytes: null };
  const netPair =
    typeof record.NetIO === 'string'
      ? parseHumanBytesPair(record.NetIO)
      : { used_bytes: null, limit_bytes: null };
  const blockPair =
    typeof record.BlockIO === 'string'
      ? parseHumanBytesPair(record.BlockIO)
      : { used_bytes: null, limit_bytes: null };
  const pids = typeof record.PIDs === 'string' ? Number.parseInt(record.PIDs, 10) : Number.NaN;

  return {
    container: typeof record.Container === 'string' ? record.Container : '',
    name: typeof record.Name === 'string' ? record.Name : '',
    cpu_percent: typeof record.CPUPerc === 'string' ? parsePercent(record.CPUPerc) : null,
    mem_used_bytes: memPair.used_bytes,
    mem_limit_bytes: memPair.limit_bytes,
    mem_percent: typeof record.MemPerc === 'string' ? parsePercent(record.MemPerc) : null,
    net_rx_bytes: netPair.used_bytes,
    net_tx_bytes: netPair.limit_bytes,
    block_read_bytes: blockPair.used_bytes,
    block_write_bytes: blockPair.limit_bytes,
    pids: Number.isNaN(pids) ? null : pids,
  };
}

const servicesStats: OpSpec<ServiceStatsEntry[]> = {
  group: 'services',
  name: 'stats',
  summary: 'One-shot resource usage snapshot per container, sizes converted to bytes.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: () => shellJoin(['docker', 'stats', '--no-stream', '--format', 'json']),
  shape: (parsed) =>
    (parsed as unknown[])
      .map(shapeStatsEntry)
      .filter((entry): entry is ServiceStatsEntry => entry !== null),
};

interface ServiceInspectDetail extends ServiceEntry {
  started_at: string | null;
  finished_at: string | null;
  cap_add: string[];
  cap_drop: string[];
  privileged: boolean;
}

function shapeInspectDetail(raw: unknown): ServiceInspectDetail | null {
  const base = shapeServiceEntry(raw);
  if (!base || typeof raw !== 'object' || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const state = readRecord(record.State);
  const hostConfig = readRecord(record.HostConfig);
  return {
    ...base,
    started_at: typeof state.StartedAt === 'string' ? state.StartedAt : null,
    finished_at: typeof state.FinishedAt === 'string' ? state.FinishedAt : null,
    cap_add: Array.isArray(hostConfig.CapAdd) ? (hostConfig.CapAdd as string[]) : [],
    cap_drop: Array.isArray(hostConfig.CapDrop) ? (hostConfig.CapDrop as string[]) : [],
    privileged: hostConfig.Privileged === true,
  };
}

const servicesInspect: OpSpec<ServiceInspectDetail[]> = {
  group: 'services',
  name: 'inspect',
  summary: 'Full inspect detail for one container — cap audit + exit-137 evidence in one call.',
  args: [arg('container', 'positional', true, 'Container name or ID.')],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) => shellJoin(['docker', 'inspect', reqStr(ctx, 'container')]),
  shape: (parsed) => {
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map(shapeInspectDetail)
      .filter((entry): entry is ServiceInspectDetail => entry !== null);
  },
};

interface ComposePsEntry {
  id: string;
  name: string;
  service: string;
  image: string;
  state: string;
  health: string | null;
  exit_code: number | null;
  ports: PortMapping[];
}

function shapeComposePsEntry(raw: unknown): ComposePsEntry | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const publishers = Array.isArray(record.Publishers) ? (record.Publishers as unknown[]) : [];
  const ports: PortMapping[] = publishers
    .map((publisher): PortMapping | null => {
      const p = readRecord(publisher);
      const containerPort = typeof p.TargetPort === 'number' ? p.TargetPort : null;
      if (containerPort === null) {
        return null;
      }
      return {
        host_ip: typeof p.URL === 'string' && p.URL.length > 0 ? p.URL : null,
        host_port: typeof p.PublishedPort === 'number' ? p.PublishedPort : null,
        container_port: containerPort,
        proto: typeof p.Protocol === 'string' ? p.Protocol : 'tcp',
      };
    })
    .filter((mapping): mapping is PortMapping => mapping !== null);

  return {
    id: typeof record.ID === 'string' ? record.ID.slice(0, 12) : '',
    name: typeof record.Name === 'string' ? record.Name : '',
    service: typeof record.Service === 'string' ? record.Service : '',
    image: typeof record.Image === 'string' ? record.Image : '',
    state: typeof record.State === 'string' ? record.State : 'unknown',
    health: typeof record.Health === 'string' && record.Health.length > 0 ? record.Health : null,
    exit_code: typeof record.ExitCode === 'number' ? record.ExitCode : null,
    ports,
  };
}

const servicesComposePs: OpSpec<ComposePsEntry[]> = {
  group: 'services',
  name: 'compose-ps',
  summary: 'docker compose ps for a given compose file, ports parsed into structured objects.',
  args: [arg('file', 'positional', true, 'Path to the docker-compose file on the remote.')],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) =>
    shellJoin(['docker', 'compose', '-f', reqStr(ctx, 'file'), 'ps', '--format', 'json']),
  shape: (parsed) =>
    (parsed as unknown[])
      .map(shapeComposePsEntry)
      .filter((entry): entry is ComposePsEntry => entry !== null),
};

interface HealthcheckLogEntry {
  start: string | null;
  end: string | null;
  exit_code: number | null;
  output: string | null;
}

interface HealthcheckResult {
  status: string;
  failing_streak: number;
  log: HealthcheckLogEntry[];
}

const servicesHealthcheck: OpSpec<HealthcheckResult> = {
  group: 'services',
  name: 'healthcheck',
  summary: 'Container .State.Health status + failing streak + last probe log.',
  args: [arg('container', 'positional', true, 'Container name or ID.')],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) =>
    shellJoin([
      'docker',
      'inspect',
      '--format',
      '{{json .State.Health}}',
      reqStr(ctx, 'container'),
    ]),
  shape: (parsed) => {
    if (parsed === null || typeof parsed !== 'object') {
      return { status: 'none', failing_streak: 0, log: [] };
    }
    const record = parsed as Record<string, unknown>;
    const log = Array.isArray(record.Log) ? (record.Log as unknown[]) : [];
    return {
      status: typeof record.Status === 'string' ? record.Status : 'unknown',
      failing_streak: typeof record.FailingStreak === 'number' ? record.FailingStreak : 0,
      log: log.map((entry) => {
        const e = readRecord(entry);
        return {
          start: typeof e.Start === 'string' ? e.Start : null,
          end: typeof e.End === 'string' ? e.End : null,
          exit_code: typeof e.ExitCode === 'number' ? e.ExitCode : null,
          output: typeof e.Output === 'string' ? e.Output : null,
        };
      }),
    };
  },
};

const servicesSystemctlStatus: OpSpec<ReturnType<typeof parseSystemctlShow>> = {
  group: 'services',
  name: 'systemctl-status',
  summary:
    'systemd unit status via `systemctl show --property=` (portable across systemd versions).',
  args: [arg('unit', 'positional', true, 'systemd unit name.')],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) =>
    shellJoin([
      'systemctl',
      'show',
      reqStr(ctx, 'unit'),
      '--property=ActiveState,SubState,LoadState,UnitFileState,MainPID,NRestarts,Result',
    ]),
  shape: (parsed) => parseSystemctlShow(parsed as string),
};

const servicesRestart: OpSpec<{ container: string; restarted: boolean }> = {
  group: 'services',
  name: 'restart',
  summary: 'docker restart a container.',
  args: [arg('container', 'positional', true, 'Container name or ID.')],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => shellJoin(['docker', 'restart', reqStr(ctx, 'container')]),
  shape: (_parsed, ctx) => ({ container: reqStr(ctx, 'container'), restarted: true }),
};

/** One factory for all four systemctl verbs — variation (the verb) is data, not four near-identical OpSpecs. */
function systemctlVerbOp(
  name: string,
  verb: 'start' | 'stop' | 'restart' | 'reload',
): OpSpec<{ unit: string; action: string }> {
  return {
    group: 'services',
    name,
    summary: `systemctl ${verb} a unit.`,
    args: [arg('unit', 'positional', true, 'systemd unit name.')],
    mutating: true,
    timeoutSec: DEFAULT_TIMEOUT_SEC,
    output: 'raw',
    buildRemote: (ctx) => shellJoin(['systemctl', verb, reqStr(ctx, 'unit')]),
    shape: (_parsed, ctx) => ({ unit: reqStr(ctx, 'unit'), action: verb }),
  };
}

const servicesSystemctlStart = systemctlVerbOp('systemctl-start', 'start');
const servicesSystemctlStop = systemctlVerbOp('systemctl-stop', 'stop');
const servicesSystemctlRestart = systemctlVerbOp('systemctl-restart', 'restart');
const servicesSystemctlReload = systemctlVerbOp('systemctl-reload', 'reload');

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

const filesLs: OpSpec<ReturnType<typeof parseLs>> = {
  group: 'files',
  name: 'ls',
  summary: 'Directory listing (structured, byte sizes).',
  args: [arg('path', 'positional', true, 'Remote directory path.')],
  mutating: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => shellJoin(['ls', '-la', '--time-style=long-iso', reqStr(ctx, 'path')]),
  shape: (parsed) => parseLs(parsed as string),
};

const ENV_FILE_PATTERN = /(^|\/)\.env(\.|$)/;

function isEnvFile(path: string): boolean {
  return ENV_FILE_PATTERN.test(path);
}

function maskEnvContent(content: string, revealedKeys: Set<string>): string {
  return content
    .split('\n')
    .map((line) => {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
      if (!match) {
        return line;
      }
      const key = match[1];
      if (key === undefined || revealedKeys.has(key)) {
        return line;
      }
      return `${key}=***MASKED***`;
    })
    .join('\n');
}

interface FilesCatResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  masked: boolean;
  content: string | null;
}

const filesCat: OpSpec<FilesCatResult> = {
  group: 'files',
  name: 'cat',
  summary: `Read a file (size-guarded at ${FILE_CAT_MAX_BYTES} bytes); .env-shaped files are masked unless --reveal names the key.`,
  args: [
    arg('path', 'positional', true, 'Remote file path.'),
    arg('reveal', 'flag', false, 'Comma-separated key names to unmask (env files only).'),
  ],
  mutating: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${FILE_CAT_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else cat "$p"; fi`,
    ].join('; ');
    return shellJoin(['sh', '-c', script]);
  },
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const trimmed = text.trim();
    if (trimmed === '__NOT_FOUND__') {
      return { found: false, truncated: false, size_bytes: null, masked: false, content: null };
    }
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(trimmed);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        masked: false,
        content: null,
      };
    }
    const path = reqStr(ctx, 'path');
    const shouldMask = isEnvFile(path);
    const revealedKeys = new Set(
      optStr(ctx, 'reveal', '')
        .split(',')
        .map((key) => key.trim())
        .filter((key) => key.length > 0),
    );
    return {
      found: true,
      truncated: false,
      size_bytes: Buffer.byteLength(text, 'utf8'),
      masked: shouldMask,
      content: shouldMask ? maskEnvContent(text, revealedKeys) : text,
    };
  },
};

interface FilesTailResult {
  lines: string[];
  lines_returned: number;
}

const filesTail: OpSpec<FilesTailResult> = {
  group: 'files',
  name: 'tail',
  summary: 'Tail N lines of a file.',
  args: [
    arg('path', 'positional', true, 'Remote file path.'),
    arg('n', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) =>
    shellJoin(['tail', '-n', optStr(ctx, 'n', String(DEFAULT_LOG_TAIL)), reqStr(ctx, 'path')]),
  shape: (parsed) => {
    const lines = (parsed as string)
      .split('\n')
      .map((line) => line.trimEnd())
      .filter((line) => line.length > 0);
    return { lines, lines_returned: lines.length };
  },
};

interface FilesDownloadResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  content_base64: string | null;
}

const filesDownload: OpSpec<FilesDownloadResult> = {
  group: 'files',
  name: 'download',
  summary: `Read a file as base64 over the existing ssh channel (size-guarded at ${DOWNLOAD_MAX_BYTES} bytes) — no separate scp/sftp process.`,
  args: [arg('path', 'positional', true, 'Remote file path.')],
  mutating: false,
  timeoutSec: DOWNLOAD_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${DOWNLOAD_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else echo "__OK__:$sz"; base64 "$p" | tr -d '\\n'; fi`,
    ].join('; ');
    return shellJoin(['sh', '-c', script]);
  },
  shape: (parsed) => {
    const text = parsed as string;
    const newlineIndex = text.indexOf('\n');
    const firstLine = (newlineIndex === -1 ? text : text.slice(0, newlineIndex)).trim();

    if (firstLine === '__NOT_FOUND__') {
      return { found: false, truncated: false, size_bytes: null, content_base64: null };
    }
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(firstLine);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        content_base64: null,
      };
    }
    const ok = /^__OK__:(\d+)/.exec(firstLine);
    const size = ok?.[1];
    return {
      found: true,
      truncated: false,
      size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
      content_base64: newlineIndex === -1 ? '' : text.slice(newlineIndex + 1).trim(),
    };
  },
};

interface FilesDiskUsageResult {
  path: string;
  size_bytes: number | null;
}

const filesDiskUsage: OpSpec<FilesDiskUsageResult> = {
  group: 'files',
  name: 'disk-usage',
  summary: 'Total size in bytes of a remote path (du -sb).',
  args: [arg('path', 'positional', true, 'Remote path.')],
  mutating: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => shellJoin(['du', '-sb', reqStr(ctx, 'path')]),
  shape: (parsed, ctx) => {
    const entries = parseDu(parsed as string);
    const first = entries[0];
    return { path: reqStr(ctx, 'path'), size_bytes: first ? first.size_bytes : null };
  },
};

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

interface ConfigAllowlist {
  [alias: string]: string[];
}

function defaultConfigAllowlistPath(): string {
  const override = process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.config', 'sshepherd', 'config-allowlist.toml');
}

/** Missing file yields an empty allowlist (mirrors targets.ts's missing-config behavior) — every path refused until declared. */
function loadConfigAllowlist(path: string = defaultConfigAllowlistPath()): ConfigAllowlist {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return {};
  }
  const parsed = Bun.TOML.parse(text) as Record<string, unknown>;
  const allowlist: ConfigAllowlist = {};
  for (const [alias, raw] of Object.entries(parsed)) {
    const record = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
    const paths = Array.isArray(record.paths) ? record.paths : [];
    allowlist[alias] = paths.filter((p): p is string => typeof p === 'string');
  }
  return allowlist;
}

/** Local refusal, before ssh — a path not declared for this alias never reaches the remote. */
function assertConfigPathAllowed(ctx: OpContext, path: string): void {
  const allowlist = loadConfigAllowlist();
  const allowed = allowlist[ctx.alias] ?? [];
  if (!allowed.includes(path)) {
    throw new Error(`config path '${path}' is not on the allowlist for alias '${ctx.alias}'`);
  }
}

interface ConfigGetResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  content: string | null;
}

const configGet: OpSpec<ConfigGetResult> = {
  group: 'config',
  name: 'get',
  summary: 'Read an allowlisted remote config file (size-guarded).',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be declared in the alias allowlist.'),
  ],
  mutating: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    assertConfigPathAllowed(ctx, path);
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${FILE_CAT_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else cat "$p"; fi`,
    ].join('; ');
    return shellJoin(['sh', '-c', script]);
  },
  shape: (parsed) => {
    const text = parsed as string;
    const trimmed = text.trim();
    if (trimmed === '__NOT_FOUND__') {
      return { found: false, truncated: false, size_bytes: null, content: null };
    }
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(trimmed);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        content: null,
      };
    }
    return {
      found: true,
      truncated: false,
      size_bytes: Buffer.byteLength(text, 'utf8'),
      content: text,
    };
  },
};

function buildConfigValidateCommand(path: string): string {
  if (/nginx/i.test(path)) {
    return shellJoin(['nginx', '-t']);
  }
  if (/sshd_config/i.test(path)) {
    return shellJoin(['sshd', '-t']);
  }
  if (/caddy/i.test(path)) {
    return shellJoin(['caddy', 'validate', '--config', path]);
  }
  if (/(docker-)?compose\.ya?ml$/i.test(path)) {
    return shellJoin(['docker', 'compose', '-f', path, 'config', '-q']);
  }
  throw new Error(`config validate: no known validator for path '${path}'`);
}

const configValidate: OpSpec<{ valid: boolean }> = {
  group: 'config',
  name: 'validate',
  summary:
    'Syntax-check an allowlisted config file (nginx -t / sshd -t / caddy validate / compose config -q).',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be declared in the alias allowlist.'),
  ],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    assertConfigPathAllowed(ctx, path);
    return buildConfigValidateCommand(path);
  },
  shape: () => ({ valid: true }),
};

/** Backs up the existing file to `<path>.bak-<UTCdate>` BEFORE the write, in the same remote script. */
function buildConfigPutScript(path: string, contentBase64: string): string {
  const script = [
    `p=${shq(path)}`,
    'if [ -f "$p" ]; then cp "$p" "$p.bak-$(date -u +%Y%m%dT%H%M%SZ)"; fi',
    `printf '%s' ${shq(contentBase64)} | base64 -d > "$p"`,
  ].join('; ');
  return shellJoin(['sh', '-c', script]);
}

const configPut: OpSpec<{ written: boolean }> = {
  group: 'config',
  name: 'put',
  summary:
    'Write an allowlisted remote config file — backs up the existing file (.bak-<UTCdate>) before overwriting.',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be declared in the alias allowlist.'),
    arg(
      'content-base64',
      'flag',
      true,
      'Base64-encoded content to write (CLI reads the local --from file and encodes it).',
    ),
  ],
  mutating: true,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    assertConfigPathAllowed(ctx, path);
    const contentBase64 = reqStr(ctx, 'content-base64');
    return buildConfigPutScript(path, contentBase64);
  },
  shape: () => ({ written: true }),
};

function buildConfigReloadCommand(service: string): string {
  if (service === 'nginx') {
    return shellJoin(['nginx', '-s', 'reload']);
  }
  return shellJoin(['systemctl', 'reload', service]);
}

const configReload: OpSpec<{ reloaded: boolean }> = {
  group: 'config',
  name: 'reload',
  summary: 'Reload a service after a config change (systemctl reload / nginx -s reload).',
  args: [arg('service', 'positional', true, 'Service name (e.g. nginx, sshd).')],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => buildConfigReloadCommand(reqStr(ctx, 'service')),
  shape: () => ({ reloaded: true }),
};

// ---------------------------------------------------------------------------
// db
// ---------------------------------------------------------------------------

function dbConnectionFromCtx(ctx: OpContext): DbConnection {
  return {
    composeFile: optStr(ctx, 'compose_file', ''),
    service: optStr(ctx, 'service', ''),
    container: optStr(ctx, 'container', ''),
    user: reqStr(ctx, 'db_user'),
    database: reqStr(ctx, 'db_name'),
  };
}

/** `wrapAsJsonAgg` turns zero rows into SQL NULL, which psql -qAt prints as an empty string. */
function parseJsonArray(parsed: unknown): unknown[] {
  if (parsed === null) {
    return [];
  }
  return Array.isArray(parsed) ? parsed : [parsed];
}

interface DbListResult {
  targets: string[];
}

const dbList: OpSpec<DbListResult> = {
  group: 'db',
  name: 'list',
  summary: 'List declared pg-target names from targets.toml (names only — never host/user/db).',
  args: [],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as DbListResult,
  runLocal: () => ({ targets: Object.keys(loadTargets(defaultTargetsPath())) }),
};

interface DbTableEntry {
  schema: string;
  table: string;
  size_bytes: number;
}

const DB_TABLES_SQL =
  'SELECT schemaname AS schema, tablename AS table, ' +
  "pg_total_relation_size(format('%I.%I', schemaname, tablename)) AS size_bytes " +
  "FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') " +
  'ORDER BY size_bytes DESC';

const dbTables: OpSpec<DbTableEntry[]> = {
  group: 'db',
  name: 'tables',
  summary: 'All user tables with total size in bytes (indexes + toast included).',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(wrapAsJsonAgg(DB_TABLES_SQL))),
  shape: (parsed) =>
    parseJsonArray(parsed).map((raw) => {
      const record = readRecord(raw);
      return {
        schema: typeof record.schema === 'string' ? record.schema : '',
        table: typeof record.table === 'string' ? record.table : '',
        size_bytes: typeof record.size_bytes === 'number' ? record.size_bytes : 0,
      };
    }),
};

interface DbActivityBackend {
  pid: number;
  usename: string | null;
  application_name: string | null;
  state: string | null;
  query_start: string | null;
  query_seconds: number | null;
  wait_event: string | null;
  blocked_by: number[];
}

interface DbActivityResult {
  backends_total: number;
  max_connections: number;
  backends: DbActivityBackend[];
}

const DB_ACTIVITY_SQL =
  'SELECT json_build_object(' +
  "'backends_total', (SELECT count(*) FROM pg_stat_activity), " +
  "'max_connections', (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'), " +
  "'backends', (SELECT coalesce(json_agg(b), '[]'::json) FROM (" +
  'SELECT pid, usename, application_name, state, query_start, ' +
  'extract(epoch FROM (now() - query_start)) AS query_seconds, wait_event, ' +
  'pg_blocking_pids(pid) AS blocked_by FROM pg_stat_activity WHERE pid <> pg_backend_pid()' +
  ') b))';

const dbActivity: OpSpec<DbActivityResult> = {
  group: 'db',
  name: 'activity',
  summary:
    'pg_stat_activity per backend (query_seconds, blocked_by) + backends_total vs max_connections.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(DB_ACTIVITY_SQL)),
  shape: (parsed) => {
    const record = readRecord(parsed);
    const backends = Array.isArray(record.backends) ? record.backends : [];
    return {
      backends_total: typeof record.backends_total === 'number' ? record.backends_total : 0,
      max_connections: typeof record.max_connections === 'number' ? record.max_connections : 0,
      backends: backends.map((raw) => {
        const b = readRecord(raw);
        return {
          pid: typeof b.pid === 'number' ? b.pid : 0,
          usename: typeof b.usename === 'string' ? b.usename : null,
          application_name: typeof b.application_name === 'string' ? b.application_name : null,
          state: typeof b.state === 'string' ? b.state : null,
          query_start: typeof b.query_start === 'string' ? b.query_start : null,
          query_seconds: typeof b.query_seconds === 'number' ? b.query_seconds : null,
          wait_event: typeof b.wait_event === 'string' ? b.wait_event : null,
          blocked_by: Array.isArray(b.blocked_by)
            ? b.blocked_by.filter((pid): pid is number => typeof pid === 'number')
            : [],
        };
      }),
    };
  },
};

interface DbConnectionsResult {
  backends_total: number;
  max_connections: number;
  by_state: Record<string, number>;
}

const DB_CONNECTIONS_SQL =
  'SELECT json_build_object(' +
  "'backends_total', (SELECT count(*) FROM pg_stat_activity), " +
  "'max_connections', (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'), " +
  "'by_state', (SELECT coalesce(json_object_agg(coalesce(state, 'unknown'), cnt), '{}'::json) FROM (" +
  'SELECT state, count(*) AS cnt FROM pg_stat_activity GROUP BY state' +
  ') s))';

const dbConnections: OpSpec<DbConnectionsResult> = {
  group: 'db',
  name: 'connections',
  summary: 'Backend count by state vs max_connections.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(DB_CONNECTIONS_SQL)),
  shape: (parsed) => {
    const record = readRecord(parsed);
    const byStateRaw = readRecord(record.by_state);
    const byState: Record<string, number> = {};
    for (const [key, value] of Object.entries(byStateRaw)) {
      if (typeof value === 'number') {
        byState[key] = value;
      }
    }
    return {
      backends_total: typeof record.backends_total === 'number' ? record.backends_total : 0,
      max_connections: typeof record.max_connections === 'number' ? record.max_connections : 0,
      by_state: byState,
    };
  },
};

interface DbSlowQueryEntry {
  query: string;
  calls: number;
  total_exec_time: number;
  mean_exec_time: number;
  rows: number;
}

interface DbSlowResult {
  available: boolean;
  reason: string | null;
  queries: DbSlowQueryEntry[];
}

const dbSlow: OpSpec<DbSlowResult> = {
  group: 'db',
  name: 'slow',
  summary: 'Top queries by mean exec time from pg_stat_statements — degrades cleanly when absent.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) => buildDbSlowCommand(dbConnectionFromCtx(ctx)),
  shape: (parsed) => {
    const record = readRecord(parsed);
    if (record.available !== true) {
      return {
        available: false,
        reason: typeof record.reason === 'string' ? record.reason : null,
        queries: [],
      };
    }
    const rawQueries = Array.isArray(record.queries) ? record.queries : [];
    return {
      available: true,
      reason: null,
      queries: rawQueries.map((raw) => {
        const q = readRecord(raw);
        return {
          query: typeof q.query === 'string' ? q.query : '',
          calls: typeof q.calls === 'number' ? q.calls : 0,
          total_exec_time: typeof q.total_exec_time === 'number' ? q.total_exec_time : 0,
          mean_exec_time: typeof q.mean_exec_time === 'number' ? q.mean_exec_time : 0,
          rows: typeof q.rows === 'number' ? q.rows : 0,
        };
      }),
    };
  },
};

interface DbSizeEntry {
  datname: string;
  size_bytes: number;
}

const DB_SIZE_SQL =
  'SELECT datname, pg_database_size(datname) AS size_bytes ' +
  'FROM pg_database WHERE datistemplate = false ORDER BY size_bytes DESC';

const dbSize: OpSpec<{ databases: DbSizeEntry[] }> = {
  group: 'db',
  name: 'size',
  summary: 'Every non-template database on the server, sized in bytes.',
  args: [arg('target', 'positional', true, 'pg-target name declared in targets.toml.')],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) =>
    buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(wrapAsJsonAgg(DB_SIZE_SQL))),
  shape: (parsed) => ({
    databases: parseJsonArray(parsed).map((raw) => {
      const record = readRecord(raw);
      return {
        datname: typeof record.datname === 'string' ? record.datname : '',
        size_bytes: typeof record.size_bytes === 'number' ? record.size_bytes : 0,
      };
    }),
  }),
};

const dbQuery: OpSpec<unknown[]> = {
  group: 'db',
  name: 'query',
  summary:
    'Ad hoc read-only SQL against a pg-target — SELECT only, enforced by parser rejection + a read-only transaction wrapper.',
  args: [
    arg('target', 'positional', true, 'pg-target name declared in targets.toml.'),
    arg('sql', 'positional', true, 'SELECT statement to run.'),
  ],
  mutating: false,
  timeoutSec: DB_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) => {
    const sql = reqStr(ctx, 'sql');
    assertNoMultiStatementSql(sql);
    assertSelectOnly(sql);
    return buildPsqlCommand(dbConnectionFromCtx(ctx), wrapReadOnlyTxn(wrapAsJsonAgg(sql)));
  },
  shape: (parsed) => parseJsonArray(parsed),
};

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

function loadRecipeFromCtx(ctx: OpContext): ReturnType<typeof loadRecipe> {
  return loadRecipe(reqStr(ctx, 'recipe'));
}

const deployRun: OpSpec<DeployPlan | { output: string }> = {
  group: 'deploy',
  name: 'run',
  summary: 'Execute (or --dry-run plan) a deploy recipe in resolved dependency order.',
  args: [
    arg('recipe', 'positional', true, 'Recipe name.'),
    arg(
      'dry-run',
      'flag',
      false,
      'Print the resolved plan; execute nothing, no confirmation needed.',
    ),
  ],
  mutating: true,
  timeoutSec: DEPLOY_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    if (optBool(ctx, 'dry-run', false)) {
      return null;
    }
    const recipe = loadRecipeFromCtx(ctx);
    return buildRunScript(recipe.steps, recipe.workdir);
  },
  shape: (parsed) => ({ output: (parsed as string).trim() }),
  runLocal: (ctx) => planRecipe(loadRecipeFromCtx(ctx)),
};

const deployStatus: OpSpec<ComposePsEntry[]> = {
  group: 'deploy',
  name: 'status',
  summary: 'docker compose ps for the recipe workdir — live image tag/health per service.',
  args: [arg('recipe', 'positional', true, 'Recipe name.')],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) => {
    const recipe = loadRecipeFromCtx(ctx);
    return shellJoin(['sh', '-c', `cd ${shq(recipe.workdir)} && docker compose ps --format json`]);
  },
  shape: (parsed) =>
    (parsed as unknown[])
      .map(shapeComposePsEntry)
      .filter((entry): entry is ComposePsEntry => entry !== null),
};

const deployRollback: OpSpec<{ output: string }> = {
  group: 'deploy',
  name: 'rollback',
  summary: 'Roll back using the recipe [rollback] block — refuses when the recipe declares none.',
  args: [arg('recipe', 'positional', true, 'Recipe name.')],
  mutating: true,
  timeoutSec: DEPLOY_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => buildRollbackCommand(loadRecipeFromCtx(ctx)),
  shape: (parsed) => ({ output: (parsed as string).trim() }),
};

const deployLogs: OpSpec<{ output: string }> = {
  group: 'deploy',
  name: 'logs',
  summary: 'docker compose logs (tail) for the recipe workdir.',
  args: [
    arg('recipe', 'positional', true, 'Recipe name.'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  timeoutSec: LOG_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const recipe = loadRecipeFromCtx(ctx);
    const tail = optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL));
    return shellJoin([
      'sh',
      '-c',
      `cd ${shq(recipe.workdir)} && docker compose logs --tail=${shq(tail)} --timestamps`,
    ]);
  },
  shape: (parsed) => ({ output: parsed as string }),
};

const deployMigrate: OpSpec<{ output: string }> = {
  group: 'deploy',
  name: 'migrate',
  summary: 'Run only the migrate-kind steps of a recipe, in resolved order.',
  args: [arg('recipe', 'positional', true, 'Recipe name.')],
  mutating: true,
  timeoutSec: DEPLOY_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => {
    const recipe = loadRecipeFromCtx(ctx);
    return buildMigrateScript(recipe.steps, recipe.workdir);
  },
  shape: (parsed) => ({ output: (parsed as string).trim() }),
};

// ---------------------------------------------------------------------------
// security
// ---------------------------------------------------------------------------

/** Directives that cannot self-lockout an already-authenticated session — applied unconditionally. */
const HARDEN_SAFE_DIRECTIVES: Array<[string, string]> = [
  ['X11Forwarding', 'no'],
  ['PermitEmptyPasswords', 'no'],
  ['MaxAuthTries', '4'],
  ['ClientAliveInterval', '300'],
  ['ClientAliveCountMax', '2'],
];

/** Directives that CAN self-lockout (disabling the current session's own auth method) — refused
 *  unless `--keep-session` is explicitly turned off (server-pattern.md §D no-self-lockout rule). */
const HARDEN_RISKY_DIRECTIVES: Array<[string, string]> = [
  ['PermitRootLogin', 'no'],
  ['PasswordAuthentication', 'no'],
];

function buildHardenScript(keepSession: boolean): string {
  const cfg = '/etc/ssh/sshd_config';
  const directives = keepSession
    ? HARDEN_SAFE_DIRECTIVES
    : [...HARDEN_SAFE_DIRECTIVES, ...HARDEN_RISKY_DIRECTIVES];
  const steps = [`cp ${cfg} ${cfg}.bak-$(date -u +%Y%m%dT%H%M%SZ)`];
  for (const [key, value] of directives) {
    steps.push(`sed -i '/^${key} /d' ${cfg}`);
    steps.push(`echo ${shq(`${key} ${value}`)} >> ${cfg}`);
  }
  steps.push('sshd -t');
  steps.push('systemctl reload sshd || service ssh reload');
  return shellJoin(['sh', '-c', steps.join(' && ')]);
}

const securityHarden: OpSpec<{ applied: string[]; keep_session: boolean }> = {
  group: 'security',
  name: 'harden',
  summary:
    'Backs up sshd_config, applies lockout-safe hardening directives, validates (sshd -t), reloads. ' +
    '--keep-session defaults true and refuses PermitRootLogin/PasswordAuthentication changes unless explicitly turned off.',
  args: [
    arg(
      'keep-session',
      'flag',
      false,
      'Default true. Pass false to also apply lockout-risky directives (PermitRootLogin no, PasswordAuthentication no).',
    ),
  ],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => buildHardenScript(optBool(ctx, 'keep-session', true)),
  shape: (_parsed, ctx) => {
    const keepSession = optBool(ctx, 'keep-session', true);
    const directives = keepSession
      ? HARDEN_SAFE_DIRECTIVES
      : [...HARDEN_SAFE_DIRECTIVES, ...HARDEN_RISKY_DIRECTIVES];
    return {
      applied: directives.map(([key, value]) => `${key} ${value}`),
      keep_session: keepSession,
    };
  },
};

// ---------------------------------------------------------------------------
// registry + executor
// ---------------------------------------------------------------------------

const REGISTRY: OpSpec[] = [
  hostsList,
  hostsTest,
  hostsInfo,
  checkOverview,
  checkMem,
  checkDisk,
  checkCpu,
  checkPorts,
  checkOomHistory,
  checkKernel,
  logsDocker,
  logsService,
  logsDockerDaemon,
  logsNginx,
  servicesPs,
  servicesStats,
  servicesInspect,
  servicesComposePs,
  servicesHealthcheck,
  servicesSystemctlStatus,
  servicesRestart,
  servicesSystemctlStart,
  servicesSystemctlStop,
  servicesSystemctlRestart,
  servicesSystemctlReload,
  filesLs,
  filesCat,
  filesTail,
  filesDownload,
  filesDiskUsage,
  configGet,
  configValidate,
  configPut,
  configReload,
  dbList,
  dbTables,
  dbActivity,
  dbConnections,
  dbSlow,
  dbSize,
  dbQuery,
  deployRun,
  deployStatus,
  deployRollback,
  deployLogs,
  deployMigrate,
  securityHarden,
] as OpSpec[];

export function getOp(group: string, name: string): OpSpec | undefined {
  return REGISTRY.find((op) => op.group === group && op.name === name);
}

export function listOps(): OpSpec[] {
  return REGISTRY;
}

export interface ExecuteDeps {
  transport?: TransportDeps;
  sshConfigPath?: string;
  /** Confirms a mutating op — the CLI (Phase 6) sets this after `--yes` or an interactive prompt. */
  yes?: boolean;
  /** Overrides `auditMutating`'s log path — tests point this at a temp file. */
  auditLogPath?: string;
}

function parseByMode(mode: OutputMode, stdout: string): unknown {
  if (mode === 'native-json') {
    return stdout.trim().length > 0 ? JSON.parse(stdout) : null;
  }
  if (mode === 'ndjson') {
    return splitNdjson(stdout);
  }
  if (mode === 'raw') {
    return stdout;
  }
  return mode.parse(stdout);
}

function auditFor(
  deps: ExecuteDeps,
  alias: string,
  command: string,
  ctx: OpContext,
  outcome: 'ok' | 'error' | 'refused',
): void {
  auditMutating(
    { alias, command, argsSummary: ctx.args, outcome },
    deps.auditLogPath ? { logPath: deps.auditLogPath } : undefined,
  );
}

/**
 * The one place an `OpSpec` is turned into an `Envelope`: gate mutating ops through
 * `confirmGate`/`auditMutating` (the ONE mutating path, no per-op bespoke gating), resolve
 * the remote command (or run the host-local fallback), execute it through `transport.run`
 * (the single execution path), parse per `output`, then `shape` into the final payload.
 * `deploy run --dry-run` executes nothing and mutates nothing, so it is exempt from the
 * gate/audit — every other mutating op requires `--yes` (or an interactive confirm the CLI
 * resolves into `deps.yes`) and always writes an audit line, success or failure. The CLI
 * (Phase 6) is the only intended caller in production; tests call this directly with a
 * scripted transport so no real ssh/network is ever touched.
 */
export async function executeOp(
  op: OpSpec,
  ctx: OpContext,
  deps: ExecuteDeps = {},
): Promise<Envelope<unknown>> {
  const startedAtMs = Date.now();
  const command = `${op.group} ${op.name}`;
  const isDryRun = optBool(ctx, 'dry-run', false);
  const requiresConfirm = op.mutating && !isDryRun;

  if (!confirmGate({ mutating: requiresConfirm, yes: deps.yes ?? false })) {
    auditFor(deps, ctx.alias, command, ctx, 'refused');
    return buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data: null,
      error: errorInfo('CONFIRMATION_REQUIRED'),
    });
  }

  const remoteCmd = op.buildRemote(ctx);

  if (remoteCmd === null) {
    if (!op.runLocal) {
      throw new Error(
        `registry: op '${command}' has no buildRemote output and no runLocal fallback`,
      );
    }
    const sshConfigPath = deps.sshConfigPath ?? join(homedir(), '.ssh', 'config');
    const data = op.runLocal(ctx, sshConfigPath);
    const envelope = buildEnvelope({ alias: ctx.alias, command, startedAtMs, data, error: null });
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'ok');
    }
    return envelope;
  }

  const result = await run(ctx.alias, remoteCmd, op.timeoutSec, deps.transport);
  if (result.error) {
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'error');
    }
    return buildEnvelope({
      alias: ctx.alias,
      command,
      startedAtMs,
      data: null,
      error: result.error,
    });
  }

  const parsed = parseByMode(op.output, result.raw.stdout);
  const data = op.shape(parsed, ctx);
  if (requiresConfirm) {
    auditFor(deps, ctx.alias, command, ctx, 'ok');
  }
  return buildEnvelope({ alias: ctx.alias, command, startedAtMs, data, error: null });
}

// Re-exported for parser unit tests and future CLI --help rendering.
export { parseHumanBytes };

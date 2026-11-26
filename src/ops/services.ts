import { SERVICES_TIMEOUT_SEC } from '../limits.ts';
import { arg, type ComposePsEntry, readRecord, reqStr, shapeComposePsEntry } from '../op-args.ts';
import { parseHumanBytesPair, parsePercent } from '../parsers/bytes.ts';
import { type PortMapping, parseInspectPorts } from '../parsers/docker-ports.ts';
import { parseSystemctlShow } from '../parsers/systemctl-show.ts';
import { shellJoin } from '../quote.ts';
import type { OpSpec } from '../types.ts';

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
  exposes: 'metadata',
  timeoutSec: SERVICES_TIMEOUT_SEC,
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
  exposes: 'metadata',
  timeoutSec: SERVICES_TIMEOUT_SEC,
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
  exposes: 'metadata',
  timeoutSec: SERVICES_TIMEOUT_SEC,
  output: 'native-json',
  buildRemote: (ctx) => shellJoin(['docker', 'inspect', '--', reqStr(ctx, 'container')]),
  shape: (parsed) => {
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map(shapeInspectDetail)
      .filter((entry): entry is ServiceInspectDetail => entry !== null);
  },
};

const servicesComposePs: OpSpec<ComposePsEntry[]> = {
  group: 'services',
  name: 'compose-ps',
  summary: 'docker compose ps for a given compose file, ports parsed into structured objects.',
  args: [arg('file', 'positional', true, 'Path to the docker-compose file on the remote.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: SERVICES_TIMEOUT_SEC,
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
  exposes: 'content',
  timeoutSec: SERVICES_TIMEOUT_SEC,
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
  exposes: 'metadata',
  timeoutSec: SERVICES_TIMEOUT_SEC,
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
  exposes: 'none',
  timeoutSec: SERVICES_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => shellJoin(['docker', 'restart', '--', reqStr(ctx, 'container')]),
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
    exposes: 'none',
    timeoutSec: SERVICES_TIMEOUT_SEC,
    output: 'raw',
    buildRemote: (ctx) => shellJoin(['systemctl', verb, '--', reqStr(ctx, 'unit')]),
    shape: (_parsed, ctx) => ({ unit: reqStr(ctx, 'unit'), action: verb }),
  };
}

const servicesSystemctlStart = systemctlVerbOp('systemctl-start', 'start');
const servicesSystemctlStop = systemctlVerbOp('systemctl-stop', 'stop');
const servicesSystemctlRestart = systemctlVerbOp('systemctl-restart', 'restart');
const servicesSystemctlReload = systemctlVerbOp('systemctl-reload', 'reload');

export const servicesOps = [
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
] as OpSpec[];

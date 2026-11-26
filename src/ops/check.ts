import { CHECK_TIMEOUT_SEC } from '../limits.ts';
import { parseDf, parseDfInodes } from '../parsers/df.ts';
import { parseDmesgOom } from '../parsers/dmesg-oom.ts';
import { parseDu } from '../parsers/du.ts';
import { parseFree } from '../parsers/free.ts';
import { parsePs } from '../parsers/ps.ts';
import { parsePsi } from '../parsers/psi.ts';
import { splitSections } from '../parsers/sections.ts';
import { parseSs } from '../parsers/ss.ts';
import { parseSysctl } from '../parsers/sysctl.ts';
import { parseUptime } from '../parsers/uptime.ts';
import { computeDeadEndRisk } from '../parsers/verdict.ts';
import { shellJoin } from '../quote.ts';
import type { OpSpec } from '../types.ts';

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
  timeoutSec: CHECK_TIMEOUT_SEC,
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
  timeoutSec: CHECK_TIMEOUT_SEC,
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
  timeoutSec: CHECK_TIMEOUT_SEC,
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
  timeoutSec: CHECK_TIMEOUT_SEC,
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
  timeoutSec: CHECK_TIMEOUT_SEC,
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
  timeoutSec: CHECK_TIMEOUT_SEC,
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
  timeoutSec: CHECK_TIMEOUT_SEC,
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

export const checkOps = [
  checkOverview,
  checkMem,
  checkDisk,
  checkCpu,
  checkPorts,
  checkOomHistory,
  checkKernel,
] as OpSpec[];

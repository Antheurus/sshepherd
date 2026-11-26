import { CHECK_TIMEOUT_SEC } from '../limits.ts';
import { parseDf, parseDfInodes } from '../parsers/df.ts';
import { parseDmesgOom } from '../parsers/dmesg-oom.ts';
import { parseDu } from '../parsers/du.ts';
import { hasMemRow, parseFree } from '../parsers/free.ts';
import { parsePs } from '../parsers/ps.ts';
import { parsePsi } from '../parsers/psi.ts';
import { splitSections } from '../parsers/sections.ts';
import { parseSs } from '../parsers/ss.ts';
import { parseSysctl } from '../parsers/sysctl.ts';
import { parseUptime } from '../parsers/uptime.ts';
import {
  computeDeadEndRisk,
  degradedSections,
  riskSignals,
  sectionOk,
} from '../parsers/verdict.ts';
import { shellJoin } from '../quote.ts';
import { niced } from '../remote-nice.ts';
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
  /** `null` when a section degraded and nothing that did read is at risk: unknown, not safe. */
  dead_end_risk: boolean | null;
  /** Sections whose command failed or printed nothing usable. */
  degraded: string[];
  /** Readings past their risk threshold (`disk`, `mem_pressure`), even when the verdict is `null`. */
  risk_signals: string[];
}

/** `sec NAME cmd...` prints `__NAME__`, the command's output, then `__NAME_RC__` and its exit status,
 *  so a command that is missing or fails reads as a degraded section, never as an empty healthy one. */
const SECTION_FN = `sec() { n=$1; shift; echo "__\${n}__"; "$@"; r=$?; echo "__\${n}_RC__"; echo "$r"; }`;

/** The remote command of a bundled check: every step niced with the rest. */
function sectionScript(steps: string[]): string {
  return niced(shellJoin(['sh', '-c', [SECTION_FN, ...steps].join('; ')]));
}

const PSI_STEP = 'echo __PSI__; cat /proc/pressure/memory 2>/dev/null || true';

const checkOverview: OpSpec<CheckOverviewResult> = {
  group: 'check',
  name: 'overview',
  summary: 'Bundled survival denominators: nproc/mem/disk/uptime/PSI + a dead_end_risk verdict.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    sectionScript([
      'sec NPROC nproc',
      'sec FREE free -b',
      'sec DF df -B1 -P',
      'sec UPTIME uptime',
      PSI_STEP,
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const nproc = Number.parseInt((sections.NPROC ?? '').trim(), 10);
    const disk = parseDf(sections.DF ?? '');
    const psi = parsePsi(sections.PSI ?? '');
    const uptime = parseUptime(sections.UPTIME ?? '');
    const inputs = {
      diskUsePercents: disk.map((entry) => entry.use_percent),
      memSomeAvg10: psi ? psi.some_avg10 : null,
    };
    const degraded = degradedSections({
      nproc: sectionOk(sections, 'NPROC') && !Number.isNaN(nproc),
      mem: sectionOk(sections, 'FREE') && hasMemRow(sections.FREE ?? ''),
      disk: sectionOk(sections, 'DF') && disk.length > 0,
      uptime: sectionOk(sections, 'UPTIME') && uptime !== null,
    });
    return {
      nproc: Number.isNaN(nproc) ? 0 : nproc,
      mem: parseFree(sections.FREE ?? ''),
      disk,
      uptime,
      psi_mem: psi,
      dead_end_risk: computeDeadEndRisk({ ...inputs, degraded }),
      degraded,
      risk_signals: riskSignals(inputs),
    };
  },
};

interface CheckMemResult {
  mem: ReturnType<typeof parseFree>;
  psi_mem: ReturnType<typeof parsePsi>;
  dead_end_risk: boolean | null;
  degraded: string[];
  risk_signals: string[];
}

const checkMem: OpSpec<CheckMemResult> = {
  group: 'check',
  name: 'mem',
  summary: 'Memory usage + PSI pressure with a dead_end_risk verdict.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () => sectionScript(['sec FREE free -b', PSI_STEP]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const psi = parsePsi(sections.PSI ?? '');
    const inputs = { diskUsePercents: [], memSomeAvg10: psi ? psi.some_avg10 : null };
    const degraded = degradedSections({
      mem: sectionOk(sections, 'FREE') && hasMemRow(sections.FREE ?? ''),
    });
    return {
      mem: parseFree(sections.FREE ?? ''),
      psi_mem: psi,
      dead_end_risk: computeDeadEndRisk({ ...inputs, degraded }),
      degraded,
      risk_signals: riskSignals(inputs),
    };
  },
};

interface CheckDiskResult {
  disk: ReturnType<typeof parseDf>;
  inodes: ReturnType<typeof parseDfInodes>;
  top_du: ReturnType<typeof parseDu>;
  dead_end_risk: boolean | null;
  degraded: string[];
  risk_signals: string[];
}

const checkDisk: OpSpec<CheckDiskResult> = {
  group: 'check',
  name: 'disk',
  summary: 'Disk usage + inodes + top space consumers with a dead_end_risk verdict.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    sectionScript([
      'sec DF df -B1 -P',
      'sec DFI df -i -P',
      'echo __DU__; du -sb /var/log /var/lib/docker 2>/dev/null || true',
    ]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    const disk = parseDf(sections.DF ?? '');
    const inodes = parseDfInodes(sections.DFI ?? '');
    const topDu = parseDu(sections.DU ?? '');
    const inputs = { diskUsePercents: disk.map((entry) => entry.use_percent), memSomeAvg10: null };
    const degraded = degradedSections({
      disk: sectionOk(sections, 'DF') && disk.length > 0,
      inodes: sectionOk(sections, 'DFI') && inodes.length > 0,
      top_du: topDu.length > 0,
    });
    return {
      disk,
      inodes,
      top_du: topDu,
      dead_end_risk: computeDeadEndRisk({ ...inputs, degraded }),
      degraded,
      risk_signals: riskSignals(inputs),
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
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    niced(
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
    ),
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
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => niced(shellJoin(['ss', '-H', '-tlnp'])),
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
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () =>
    niced(shellJoin(['sh', '-c', 'dmesg -T 2>/dev/null | grep -i "killed process" || true'])),
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
  exposes: 'metadata',
  timeoutSec: CHECK_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () =>
    niced(
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
    ),
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

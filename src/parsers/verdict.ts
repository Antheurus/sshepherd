/**
 * `dead_end_risk` verdict computation, shared by `check overview`/`check mem`/`check
 * disk` (Same Business Rule In Two Files Will Diverge — coding-standard.md: this rule
 * must live in exactly one place). Thresholds:
 *  - disk use >90% (stated in the phase brief and in
 *    `devops-engineer/references/server-pattern.md` — "a full disk is its own dead-end").
 *  - PSI memory pressure `some avg10` > 10% (server-pattern.md line 250: "sustained
 *    `some avg10` above ~10% means the host is near OOM").
 */
export const DISK_USE_PERCENT_RISK_THRESHOLD = 90;
export const PSI_MEM_SOME_AVG10_RISK_THRESHOLD = 10;

export function isDiskAtRisk(usePercents: number[]): boolean {
  return usePercents.some((percent) => percent > DISK_USE_PERCENT_RISK_THRESHOLD);
}

export function isMemPressureAtRisk(someAvg10: number | null): boolean {
  return someAvg10 !== null && someAvg10 > PSI_MEM_SOME_AVG10_RISK_THRESHOLD;
}

/** The names of the sections whose command printed nothing usable (`ok` false): a missing `free`
 *  or an unreadable `df` is a hole in the picture, not a healthy reading. */
export function degradedSections(ok: Record<string, boolean>): string[] {
  return Object.entries(ok)
    .filter(([, usable]) => !usable)
    .map(([name]) => name);
}

/** The readings that crossed their risk threshold, whatever else degraded: a full disk stays
 *  visible when the verdict itself is `null`. */
export function riskSignals(input: {
  diskUsePercents: number[];
  memSomeAvg10: number | null;
}): string[] {
  return [
    ...(isDiskAtRisk(input.diskUsePercents) ? ['disk'] : []),
    ...(isMemPressureAtRisk(input.memSomeAvg10) ? ['mem_pressure'] : []),
  ];
}

/** The sections the verdict reads: `disk` for the full-disk half, `mem` for the memory half. A
 *  degraded `nproc`, `uptime`, `inodes` or `top_du` cannot change the verdict. */
const VERDICT_SECTIONS = new Set(['disk', 'mem']);

/** `true` when a reading that did come back is at risk, whatever else degraded (a full disk stays a
 *  dead end when memory cannot be read); `null` when nothing known is at risk and a section the
 *  verdict reads degraded (unknown, never an all-clear); else `false`. */
export function computeDeadEndRisk(input: {
  diskUsePercents: number[];
  memSomeAvg10: number | null;
  degraded: string[];
}): boolean | null {
  if (isDiskAtRisk(input.diskUsePercents) || isMemPressureAtRisk(input.memSomeAvg10)) {
    return true;
  }
  return input.degraded.some((section) => VERDICT_SECTIONS.has(section)) ? null : false;
}

/** Whether the command behind section `NAME` exited 0, per the `__NAME_RC__` line `sec` printed after it. */
export function sectionOk(sections: Record<string, string>, name: string): boolean {
  return (sections[`${name}_RC`] ?? '').trim() === '0';
}

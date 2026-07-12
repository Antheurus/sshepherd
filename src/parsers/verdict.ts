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

export function computeDeadEndRisk(input: {
  diskUsePercents: number[];
  memSomeAvg10: number | null;
}): boolean {
  return isDiskAtRisk(input.diskUsePercents) || isMemPressureAtRisk(input.memSomeAvg10);
}

/**
 * Parses `uptime` (procps). No native JSON flag exists — hand-written parser matched to
 * `jc`'s documented `uptime` schema: `{ time, uptime, users, load_1m, load_5m, load_15m }`.
 * Example input: `14:32:05 up 10 days, 3:14,  2 users,  load average: 0.15, 0.22, 0.18`.
 */
export interface UptimeResult {
  time: string;
  uptime: string;
  users: number;
  load_1m: number;
  load_5m: number;
  load_15m: number;
}

const UPTIME_PATTERN =
  /^(\S+)\s+up\s+(.+?),\s+(\d+)\s+users?,\s+load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)/;

export function parseUptime(stdout: string): UptimeResult | null {
  const match = UPTIME_PATTERN.exec(stdout.trim());
  if (!match) {
    return null;
  }
  const [, time, uptime, users, load1, load5, load15] = match;
  if (
    time === undefined ||
    uptime === undefined ||
    users === undefined ||
    load1 === undefined ||
    load5 === undefined ||
    load15 === undefined
  ) {
    return null;
  }
  return {
    time,
    uptime,
    users: Number.parseInt(users, 10),
    load_1m: Number.parseFloat(load1),
    load_5m: Number.parseFloat(load5),
    load_15m: Number.parseFloat(load15),
  };
}

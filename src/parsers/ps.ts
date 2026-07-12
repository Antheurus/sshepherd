/**
 * Parses `ps aux` (procps). No native JSON flag exists — hand-written parser matched to
 * `jc`'s documented `ps` schema. `VSZ`/`RSS` are reported by `ps aux` in KiB; converted
 * to bytes here to hold the project-wide "all sizes in bytes" rule.
 */
export interface PsEntry {
  user: string;
  pid: number;
  cpu_percent: number;
  mem_percent: number;
  vsz_bytes: number;
  rss_bytes: number;
  tty: string;
  stat: string;
  start: string;
  time: string;
  command: string;
}

const HEADER_COLUMNS = 11;

export function parsePs(stdout: string): PsEntry[] {
  const lines = stdout
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);
  const entries: PsEntry[] = [];

  for (const line of lines) {
    if (line.trim().startsWith('USER') && line.includes('COMMAND')) {
      continue;
    }
    const fields = line.trim().split(/\s+/);
    if (fields.length < HEADER_COLUMNS) {
      continue;
    }
    const [user, pid, cpu, mem, vsz, rss, tty, stat, start, time, ...commandParts] = fields;
    if (
      user === undefined ||
      pid === undefined ||
      cpu === undefined ||
      mem === undefined ||
      vsz === undefined ||
      rss === undefined ||
      tty === undefined ||
      stat === undefined ||
      start === undefined ||
      time === undefined
    ) {
      continue;
    }
    entries.push({
      user,
      pid: Number.parseInt(pid, 10),
      cpu_percent: Number.parseFloat(cpu),
      mem_percent: Number.parseFloat(mem),
      vsz_bytes: Number.parseInt(vsz, 10) * 1024,
      rss_bytes: Number.parseInt(rss, 10) * 1024,
      tty,
      stat,
      start,
      time,
      command: commandParts.join(' '),
    });
  }

  return entries;
}

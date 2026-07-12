/**
 * Parses `dmesg -T | grep -i "killed process"` lines (the kernel OOM-killer's own log
 * line). No native JSON flag exists for `dmesg` — hand-written parser. Example input:
 * `[Sun Jul 12 10:00:00 2026] Killed process 4321 (node) total-vm:1234567kB, anon-rss:987654kB, file-rss:0kB, shmem-rss:0kB`
 */
export interface OomEvent {
  timestamp_raw: string;
  pid: number;
  process: string;
  anon_rss_bytes: number;
}

const OOM_LINE_PATTERN = /^\[(.+?)\]\s+Killed process\s+(\d+)\s+\((.+?)\).*?anon-rss:(\d+)kB/;

export function parseDmesgOom(stdout: string): OomEvent[] {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const events: OomEvent[] = [];

  for (const line of lines) {
    const match = OOM_LINE_PATTERN.exec(line);
    if (!match) {
      continue;
    }
    const [, timestampRaw, pid, process, anonRssKb] = match;
    if (
      timestampRaw === undefined ||
      pid === undefined ||
      process === undefined ||
      anonRssKb === undefined
    ) {
      continue;
    }
    events.push({
      timestamp_raw: timestampRaw,
      pid: Number.parseInt(pid, 10),
      process,
      anon_rss_bytes: Number.parseInt(anonRssKb, 10) * 1024,
    });
  }

  return events;
}

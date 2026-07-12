/**
 * Parses `du -sb <path> [<path> ...]` (byte units via `-b`). No native JSON flag exists
 * for `du` — hand-written parser matched to `jc`'s documented `du` schema. Each line is
 * `<bytes>\t<path>`.
 */
export interface DuEntry {
  path: string;
  size_bytes: number;
}

export function parseDu(stdout: string): DuEntry[] {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const entries: DuEntry[] = [];

  for (const line of lines) {
    const [sizeBytes, ...pathParts] = line.split(/\s+/);
    const path = pathParts.join(' ');
    if (sizeBytes === undefined || path.length === 0) {
      continue;
    }
    entries.push({ path, size_bytes: Number.parseInt(sizeBytes, 10) });
  }

  return entries;
}

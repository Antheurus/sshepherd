/**
 * Parses `free -b` (byte units, no human-readable "3.9Gi" strings). No native JSON flag
 * exists for `free` — hand-written parser matched to the standard procps column layout:
 * `total used free shared buff/cache available` on the `Mem:`/`Swap:` rows.
 */
export interface FreeSection {
  total: number;
  used: number;
  free: number;
}

export interface FreeMemSection extends FreeSection {
  shared: number;
  buff_cache: number;
  available: number;
}

export interface FreeResult {
  mem: FreeMemSection;
  swap: FreeSection;
}

function parseRow(fields: string[]): number[] {
  return fields.map((field) => Number.parseInt(field, 10));
}

export function parseFree(stdout: string): FreeResult {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  let mem: FreeMemSection = { total: 0, used: 0, free: 0, shared: 0, buff_cache: 0, available: 0 };
  let swap: FreeSection = { total: 0, used: 0, free: 0 };

  for (const line of lines) {
    if (line.startsWith('Mem:')) {
      const [total = 0, used = 0, free = 0, shared = 0, buffCache = 0, available = 0] = parseRow(
        line.replace('Mem:', '').trim().split(/\s+/),
      );
      mem = { total, used, free, shared, buff_cache: buffCache, available };
    } else if (line.startsWith('Swap:')) {
      const [total = 0, used = 0, free = 0] = parseRow(
        line.replace('Swap:', '').trim().split(/\s+/),
      );
      swap = { total, used, free };
    }
  }

  return { mem, swap };
}

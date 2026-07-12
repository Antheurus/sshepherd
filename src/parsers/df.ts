/**
 * Parses `df -B1 -P` (POSIX portable format, one line per filesystem, `-B1` forces
 * byte-unit sizes instead of human-readable "3.9Gi" strings). No native JSON flag
 * exists for `df` (see research.md §output shaping), so this is a hand-written parser
 * matched to the documented GNU coreutils `-P` column layout (also `jc`'s reference
 * `df` schema): `Filesystem 1B-blocks Used Available Capacity Mounted on`.
 */
export interface DfEntry {
  filesystem: string;
  size_bytes: number;
  used_bytes: number;
  avail_bytes: number;
  use_percent: number;
  mounted_on: string;
}

export interface DfInodeEntry {
  filesystem: string;
  inodes_total: number;
  inodes_used: number;
  inodes_avail: number;
  inodes_use_percent: number;
  mounted_on: string;
}

/** Parses `df -i -P` (inode counts, same POSIX column layout as `df -B1 -P`). */
export function parseDfInodes(stdout: string): DfInodeEntry[] {
  return parseDf(stdout).map((entry) => ({
    filesystem: entry.filesystem,
    inodes_total: entry.size_bytes,
    inodes_used: entry.used_bytes,
    inodes_avail: entry.avail_bytes,
    inodes_use_percent: entry.use_percent,
    mounted_on: entry.mounted_on,
  }));
}

export function parseDf(stdout: string): DfEntry[] {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const entries: DfEntry[] = [];

  for (const line of lines) {
    if (line.startsWith('Filesystem')) {
      continue;
    }
    const fields = line.split(/\s+/);
    const filesystem = fields[0];
    const sizeBytes = fields[1];
    const usedBytes = fields[2];
    const availBytes = fields[3];
    const capacity = fields[4];
    const mountedOn = fields.slice(5).join(' ');
    if (
      filesystem === undefined ||
      sizeBytes === undefined ||
      usedBytes === undefined ||
      availBytes === undefined ||
      capacity === undefined ||
      mountedOn.length === 0
    ) {
      continue;
    }
    entries.push({
      filesystem,
      size_bytes: Number.parseInt(sizeBytes, 10),
      used_bytes: Number.parseInt(usedBytes, 10),
      avail_bytes: Number.parseInt(availBytes, 10),
      use_percent: Number.parseInt(capacity.replace('%', ''), 10),
      mounted_on: mountedOn,
    });
  }

  return entries;
}

/**
 * Parses `ls -la --time-style=long-iso <path>` (long-iso forces a stable
 * `YYYY-MM-DD HH:MM` timestamp instead of the locale-dependent default). No native JSON
 * flag exists for `ls` — hand-written parser matched to `jc`'s documented `ls -l` schema.
 */
export interface LsEntry {
  name: string;
  permissions: string;
  links: number;
  owner: string;
  group: string;
  size_bytes: number;
  modified_at: string;
  is_dir: boolean;
  is_symlink: boolean;
  link_target: string | null;
}

const ENTRY_PATTERN = /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$/;

export function parseLs(stdout: string): LsEntry[] {
  const lines = stdout
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0);
  const entries: LsEntry[] = [];

  for (const line of lines) {
    if (line.startsWith('total ')) {
      continue;
    }
    const match = ENTRY_PATTERN.exec(line);
    if (!match) {
      continue;
    }
    const [, permissions, links, owner, group, size, date, time, rawName] = match;
    if (
      permissions === undefined ||
      links === undefined ||
      owner === undefined ||
      group === undefined ||
      size === undefined ||
      date === undefined ||
      time === undefined ||
      rawName === undefined
    ) {
      continue;
    }
    const isSymlink = permissions.startsWith('l');
    const [name, linkTarget] = isSymlink ? rawName.split(' -> ') : [rawName, undefined];
    if (name === undefined) {
      continue;
    }
    entries.push({
      name,
      permissions,
      links: Number.parseInt(links, 10),
      owner,
      group,
      size_bytes: Number.parseInt(size, 10),
      modified_at: `${date}T${time}`,
      is_dir: permissions.startsWith('d'),
      is_symlink: isSymlink,
      link_target: linkTarget ?? null,
    });
  }

  return entries;
}

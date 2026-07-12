/**
 * Parses `sysctl <key> <key> ...` output (`key = value` per line, procps format). No
 * native JSON flag exists for `sysctl` — hand-written parser, key/value only.
 */
export function parseSysctl(stdout: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  for (const line of lines) {
    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }
    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim();
    if (key.length === 0) {
      continue;
    }
    result[key] = value;
  }

  return result;
}

/**
 * Parses `/etc/os-release` (`KEY=value` or `KEY="value"` per line, freedesktop.org
 * standard format). No native JSON flag exists — hand-written parser.
 */
export function parseOsRelease(stdout: string): Record<string, string> {
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
    let value = line.slice(separatorIndex + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    if (key.length === 0) {
      continue;
    }
    result[key] = value;
  }

  return result;
}

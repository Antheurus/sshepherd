/**
 * Parses `sshd -T` (effective config: lowercase directive names, one `directive value`
 * pair per line, no comments) OR a raw `/etc/ssh/sshd_config` (mixed-case directives,
 * `#`-comments, only explicitly-set directives) into the same shape — a lowercase-keyed
 * map of directive -> value. `security ssh-audit` (registry.ts) degrades from the first
 * source to the second on the remote; this parser accepts either without needing to know
 * which one produced the text.
 */
export function parseSshdDirectives(stdout: string): Record<string, string> {
  const result: Record<string, string> = {};

  for (const rawLine of stdout.split('\n')) {
    const withoutComment = (rawLine.split('#')[0] ?? '').trim();
    if (withoutComment.length === 0) {
      continue;
    }
    const match = /^(\S+)\s+(.+)$/.exec(withoutComment);
    if (!match) {
      continue;
    }
    const key = match[1]?.toLowerCase();
    const value = match[2]?.trim();
    if (key === undefined || value === undefined) {
      continue;
    }
    result[key] = value;
  }

  return result;
}

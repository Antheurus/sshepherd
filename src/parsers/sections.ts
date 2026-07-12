/**
 * Splits stdout that was assembled from several `echo __MARKER__; <command>` pairs (used
 * to bundle multiple read-only commands into one ssh round-trip — see `check overview`,
 * `hosts info`) back into `{ MARKER: "<command output>" }`.
 */
export function splitSections(stdout: string): Record<string, string> {
  const sections: Record<string, string> = {};
  let current: string | null = null;
  let buffer: string[] = [];

  const flush = (): void => {
    if (current !== null) {
      sections[current] = buffer.join('\n');
    }
    buffer = [];
  };

  for (const line of stdout.split('\n')) {
    const marker = /^__([A-Z0-9_]+)__$/.exec(line.trim());
    if (marker) {
      flush();
      current = marker[1] ?? null;
      continue;
    }
    if (current !== null) {
      buffer.push(line);
    }
  }
  flush();

  return sections;
}

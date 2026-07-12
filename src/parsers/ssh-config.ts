import { readFileSync } from 'node:fs';

/**
 * Parses `Host` stanzas out of an OpenSSH client config for `hosts list`. Returns ALIAS
 * NAMES ONLY — this file is read purely to enumerate aliases, never to surface
 * HostName/User/Port/IdentityFile (zero-knowledge hygiene rule; see research.md
 * §zero-knowledge output hygiene, which explicitly overrides the original scope-research
 * proposal to echo the full connection tuple). Wildcard/glob patterns (`Host *`,
 * `Host web-*`) are skipped since they aren't connectable aliases.
 */
const HOST_LINE_PATTERN = /^Host\s+(.+)$/i;

function isWildcardPattern(token: string): boolean {
  return token.includes('*') || token.includes('?');
}

export function parseSshConfigAliases(configText: string): string[] {
  const aliases: string[] = [];

  for (const rawLine of configText.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const match = HOST_LINE_PATTERN.exec(line);
    if (!match) {
      continue;
    }
    const patterns = match[1]?.trim().split(/\s+/) ?? [];
    for (const pattern of patterns) {
      if (!isWildcardPattern(pattern)) {
        aliases.push(pattern);
      }
    }
  }

  return aliases;
}

/** Reads and parses the ssh client config at `configPath`; missing file yields `[]`. */
export function listHostAliases(configPath: string): string[] {
  let text: string;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch {
    return [];
  }
  return parseSshConfigAliases(text);
}

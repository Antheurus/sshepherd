import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';

/**
 * Parses `Host` stanzas out of an OpenSSH client config for `hosts list`. Returns ALIAS
 * NAMES ONLY — this file is read purely to enumerate aliases, never to surface
 * HostName/User/Port/IdentityFile (zero-knowledge hygiene rule; see research.md
 * §zero-knowledge output hygiene, which explicitly overrides the original scope-research
 * proposal to echo the full connection tuple). Wildcard/glob patterns (`Host *`,
 * `Host web-*`) are skipped since they aren't connectable aliases.
 */
const HOST_LINE_PATTERN = /^Host\s+(.+)$/i;
const MATCH_LINE_PATTERN = /^Match(\s|=)/i;
const INCLUDE_LINE_PATTERN = /^Include(?:\s*=\s*|\s+)(.+)$/i;

/** OpenSSH's own nesting limit for `Include` (READCONF_MAX_DEPTH). */
const MAX_INCLUDE_DEPTH = 16;

function isWildcardPattern(token: string): boolean {
  return token.includes('*') || token.includes('?') || token.startsWith('!');
}

function tokens(value: string): string[] {
  return value
    .trim()
    .split(/\s+/)
    .map((token) => token.replace(/^"(.*)"$/, '$1'))
    .filter((token) => token.length > 0);
}

export function parseSshConfigAliases(configText: string): string[] {
  return scanConfigText(configText).aliases;
}

interface ConfigScan {
  aliases: string[];
  patternLines: string[][];
  hasMatch: boolean;
  includes: string[];
}

function scanConfigText(configText: string): ConfigScan {
  const scan: ConfigScan = { aliases: [], patternLines: [], hasMatch: false, includes: [] };

  for (const rawLine of configText.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    if (MATCH_LINE_PATTERN.test(line)) {
      scan.hasMatch = true;
      continue;
    }
    const include = INCLUDE_LINE_PATTERN.exec(line);
    if (include) {
      scan.includes.push(...tokens(include[1] ?? ''));
      continue;
    }
    const match = HOST_LINE_PATTERN.exec(line);
    if (!match) {
      continue;
    }
    const patterns = tokens(match[1] ?? '');
    if (patterns.some(isWildcardPattern)) {
      scan.patternLines.push(patterns);
    }
    for (const pattern of patterns) {
      if (!isWildcardPattern(pattern)) {
        scan.aliases.push(pattern);
      }
    }
  }

  return scan;
}

/** What one ssh client config, with every file it `Include`s, can say about a host name. */
export interface SshConfigNames {
  /** Literal `Host` names — the connectable aliases `hosts list` shows. */
  aliases: string[];
  /** Each `Host` line that carries a wildcard or negated pattern, as its full pattern list. */
  patternLines: string[][];
  /** A `Match` block can apply to any name, so its presence means "possibly declared". */
  hasMatch: boolean;
}

function expandGlob(pattern: string): string[] {
  if (!/[*?[]/.test(pattern)) {
    return [pattern];
  }
  const segments = pattern.split('/');
  const firstGlob = segments.findIndex((segment) => /[*?[]/.test(segment));
  const base = segments.slice(0, firstGlob).join('/') || '/';
  const rest = segments.slice(firstGlob).join('/');
  try {
    return [...new Bun.Glob(rest).scanSync({ cwd: base, absolute: true, onlyFiles: true })].sort();
  } catch {
    return [];
  }
}

/** ssh resolves a relative `Include` against `~/.ssh`; a config handed over with `-F` is also
 *  read beside its own directory, so both places are searched. */
function includeCandidates(token: string, configPath: string): string[] {
  const expanded = token.startsWith('~/') ? join(homedir(), token.slice(2)) : token;
  if (isAbsolute(expanded)) {
    return expandGlob(expanded);
  }
  const bases = [...new Set([join(homedir(), '.ssh'), dirname(configPath)])];
  return bases.flatMap((base) => expandGlob(join(base, expanded)));
}

function collect(configPath: string, depth: number, seen: Set<string>, into: SshConfigNames): void {
  if (depth > MAX_INCLUDE_DEPTH || seen.has(configPath)) {
    return;
  }
  seen.add(configPath);
  let text: string;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch {
    return;
  }
  const scan = scanConfigText(text);
  into.aliases.push(...scan.aliases);
  into.patternLines.push(...scan.patternLines);
  into.hasMatch ||= scan.hasMatch;
  for (const token of scan.includes) {
    for (const included of includeCandidates(token, configPath)) {
      collect(included, depth + 1, seen, into);
    }
  }
}

/** Reads the ssh client config at `configPath` and every file it `Include`s; a missing file
 *  contributes nothing. */
export function readSshConfigNames(configPath: string): SshConfigNames {
  const names: SshConfigNames = { aliases: [], patternLines: [], hasMatch: false };
  collect(configPath, 0, new Set(), names);
  return names;
}

/** Reads and parses the ssh client config at `configPath`; missing file yields `[]`. */
export function listHostAliases(configPath: string): string[] {
  return readSshConfigNames(configPath).aliases;
}

function globToRegExp(pattern: string): RegExp {
  const body = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replaceAll('*', '.*')
    .replaceAll('?', '.');
  return new RegExp(`^${body}$`, 'i');
}

/** OpenSSH's rule for one `Host` line: a negated pattern that matches vetoes the line, otherwise
 *  any positive pattern matching wins. A bare `*` is skipped: it holds defaults for every host,
 *  so it would make any bare hostname look like a declared alias. */
function patternLineMatches(patterns: string[], name: string): boolean {
  const negated = patterns.filter((pattern) => pattern.startsWith('!'));
  if (negated.some((pattern) => globToRegExp(pattern.slice(1)).test(name))) {
    return false;
  }
  return patterns
    .filter((pattern) => !pattern.startsWith('!') && pattern !== '*')
    .some((pattern) => globToRegExp(pattern).test(name));
}

/** True when the config could apply to `name`: a literal `Host` entry, a wildcard `Host` line
 *  that matches it, or any `Match` block (which sshepherd does not evaluate, so it defers to ssh). */
export function configMayDeclare(names: SshConfigNames, name: string): boolean {
  return (
    names.aliases.includes(name) ||
    names.hasMatch ||
    names.patternLines.some((patterns) => patternLineMatches(patterns, name))
  );
}

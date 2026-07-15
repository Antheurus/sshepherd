import { auditMutating, confirmGate } from './audit.ts';
import {
  defaultRevealAllowlistPath,
  loadRevealAllowlist,
  REVEAL_DENYLIST_PATTERNS,
} from './registry.ts';
import {
  appendBlock,
  joinLines,
  readTextOrEmpty,
  splitLines,
  writeTextSecure,
} from './setup-file-io.ts';
import { buildSetupResult, type SetupResult } from './setup-types.ts';
import { tomlQuote } from './toml-quote.ts';

export interface ScaffoldOptions {
  keys: string[];
  yes: boolean;
}

export interface ScaffoldData {
  alias: string;
  keys: string[];
}

type FindTableResult =
  | { kind: 'not_found' }
  | { kind: 'found'; startIndex: number; endIndex: number };

/** Mirrors `setup-config-allowlist.ts`/`setup-files-allowlist.ts`'s `findTable` — same TOML
 *  shape, different file/field (`keys` instead of `paths`). */
function findTable(lines: string[], alias: string): FindTableResult {
  const header = `[${alias}]`;
  const startIndex = lines.findIndex((line) => line.trim() === header);
  if (startIndex === -1) {
    return { kind: 'not_found' };
  }

  let endIndex = lines.length - 1;
  for (let i = startIndex + 1; i < lines.length; i++) {
    if (/^\[.+\]$/.test(lines[i]?.trim() ?? '')) {
      endIndex = i - 1;
      break;
    }
  }
  while (endIndex > startIndex && lines[endIndex] === '') {
    endIndex -= 1;
  }

  return { kind: 'found', startIndex, endIndex };
}

/** Preserves insertion order: every existing key first, then any incoming key not already
 *  present — so a repeated scaffold call never duplicates or reorders what's already there. */
function unionKeys(existingKeys: string[], incomingKeys: string[]): string[] {
  const merged = [...existingKeys];
  const seen = new Set(existingKeys);
  for (const key of incomingKeys) {
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(key);
    }
  }
  return merged;
}

function formatKeysLine(keys: string[]): string {
  return `keys = [${keys.map((key) => tomlQuote(key)).join(', ')}]`;
}

function buildAllowlistTableLines(alias: string, keys: string[]): string[] {
  return [`[${alias}]`, formatKeysLine(keys)];
}

/** A key matching `REVEAL_DENYLIST_PATTERNS` can never be scaffolded onto the reveal-
 *  allowlist — the hardcoded denylist wins even over an explicit human request, since
 *  `assertRevealKeysAllowed` checks it first and unconditionally at reveal time regardless
 *  of what this file contains. Refusing it here too means a mistaken `--keys DB_PASSWORD`
 *  fails loud at scaffold time instead of silently writing a key that can never actually be
 *  revealed. */
function findDenylistedKey(keys: string[]): string | undefined {
  return keys.find((key) => REVEAL_DENYLIST_PATTERNS.some((pattern) => pattern.test(key)));
}

/**
 * Appends a `[<alias>]` table to `reveal-allowlist.toml`, or, if `<alias>` already has a
 * table, unions its existing `keys` with the newly supplied ones in place. Refuses with
 * `VALIDATION_ERROR` if `keys` is empty or any key matches the hardcoded secret-pattern
 * denylist — both checked before the `--yes` gate and before any file write. Gates
 * `files cat --reveal` — see `registry.ts`'s `assertRevealKeysAllowed`.
 */
export function scaffold(
  alias: string,
  options: ScaffoldOptions,
  path: string = defaultRevealAllowlistPath(),
): SetupResult<ScaffoldData> {
  const command = 'setup reveal-allowlist scaffold';
  const argsSummary = { keys: options.keys.join(',') };

  if (options.keys.length === 0) {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'VALIDATION_ERROR',
        message: `alias '${alias}' needs at least one --keys entry`,
      },
    });
  }

  const denylistedKey = findDenylistedKey(options.keys);
  if (denylistedKey !== undefined) {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'VALIDATION_ERROR',
        message: `key '${denylistedKey}' matches a hard-denied secret pattern and can never be revealed`,
      },
    });
  }

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'scaffold requires --yes' },
    });
  }

  const existingAllowlist = loadRevealAllowlist(path);
  const mergedKeys = unionKeys(existingAllowlist[alias] ?? [], options.keys);
  const tableLines = buildAllowlistTableLines(alias, mergedKeys);

  const existingText = readTextOrEmpty(path);
  const lines = splitLines(existingText);
  const found = findTable(lines, alias);
  const newText =
    found.kind === 'found'
      ? joinLines([
          ...lines.slice(0, found.startIndex),
          ...tableLines,
          ...lines.slice(found.endIndex + 1),
        ])
      : appendBlock(existingText, tableLines.join('\n'));

  writeTextSecure(path, newText);

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({ command, data: { alias, keys: mergedKeys } });
}

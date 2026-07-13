import { auditMutating, confirmGate } from './audit.ts';
import { defaultConfigAllowlistPath, loadConfigAllowlist } from './registry.ts';
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
  paths: string[];
  yes: boolean;
}

export interface ScaffoldData {
  alias: string;
  paths: string[];
}

type FindTableResult =
  | { kind: 'not_found' }
  | { kind: 'found'; startIndex: number; endIndex: number };

/**
 * Locates the `[<alias>]` table by its header line. `endIndex` is the last line belonging to
 * the table — either the line right before the next `[...]` header or the last line of the
 * file — with any trailing blank separator lines trimmed back off, so replacing
 * `[startIndex, endIndex]` never consumes the blank line that separates this table from the
 * next one.
 */
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

/** Preserves insertion order: every existing path first, then any incoming path not already
 *  present — so a repeated scaffold call never duplicates or reorders what's already there. */
function unionPaths(existingPaths: string[], incomingPaths: string[]): string[] {
  const merged = [...existingPaths];
  const seen = new Set(existingPaths);
  for (const path of incomingPaths) {
    if (!seen.has(path)) {
      seen.add(path);
      merged.push(path);
    }
  }
  return merged;
}

function formatPathsLine(paths: string[]): string {
  return `paths = [${paths.map((path) => tomlQuote(path)).join(', ')}]`;
}

function buildAllowlistTableLines(alias: string, paths: string[]): string[] {
  return [`[${alias}]`, formatPathsLine(paths)];
}

/**
 * Appends a `[<alias>]` table to `config-allowlist.toml`, or, if `<alias>` already has a
 * table, unions its existing `paths` with the newly supplied ones in place — never errors on
 * a repeat alias and never duplicates the table. Refuses with `VALIDATION_ERROR` if `paths`
 * is empty, checked before the `--yes` gate and before any file write.
 */
export function scaffold(
  alias: string,
  options: ScaffoldOptions,
  path: string = defaultConfigAllowlistPath(),
): SetupResult<ScaffoldData> {
  const command = 'setup config-allowlist scaffold';
  const argsSummary = { paths: options.paths.join(',') };

  if (options.paths.length === 0) {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'VALIDATION_ERROR',
        message: `alias '${alias}' needs at least one --paths entry`,
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

  const existingAllowlist = loadConfigAllowlist(path);
  const mergedPaths = unionPaths(existingAllowlist[alias] ?? [], options.paths);
  const tableLines = buildAllowlistTableLines(alias, mergedPaths);

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
  return buildSetupResult({ command, data: { alias, paths: mergedPaths } });
}

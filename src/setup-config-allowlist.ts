import { auditMutating, confirmGate } from './audit.ts';
import { defaultConfigAllowlistPath, loadConfigAllowlist } from './registry.ts';
import { readTextOrEmpty, writeTextSecure } from './setup-file-io.ts';
import { buildSetupResult, type SetupResult } from './setup-types.ts';

export interface ScaffoldOptions {
  paths: string[];
  yes: boolean;
}

export interface ScaffoldData {
  alias: string;
  paths: string[];
}

/** Splits a config's text into lines with no trailing empty element — mirrors
 *  setup-ssh-alias.ts's splitLines/joinLines pair. */
function splitLines(text: string): string[] {
  const withoutTrailingNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return withoutTrailingNewline.length === 0 ? [] : withoutTrailingNewline.split('\n');
}

function joinLines(lines: string[]): string {
  return lines.length === 0 ? '' : `${lines.join('\n')}\n`;
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
  return `paths = [${paths.map((path) => `"${path}"`).join(', ')}]`;
}

function buildAllowlistTableLines(alias: string, paths: string[]): string[] {
  return [`[${alias}]`, formatPathsLine(paths)];
}

/** Appends a blank-line-separated table after any existing content; the file always ends in
 *  exactly one trailing newline — mirrors setup-db-target.ts's appendTargetTable. */
function appendAllowlistTable(existingLines: string[], tableLines: string[]): string[] {
  if (existingLines.length === 0) {
    return tableLines;
  }
  return [...existingLines, '', ...tableLines];
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

  const lines = splitLines(readTextOrEmpty(path));
  const found = findTable(lines, alias);
  const newLines =
    found.kind === 'found'
      ? [...lines.slice(0, found.startIndex), ...tableLines, ...lines.slice(found.endIndex + 1)]
      : appendAllowlistTable(lines, tableLines);

  writeTextSecure(path, joinLines(newLines));

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({ command, data: { alias, paths: mergedPaths } });
}

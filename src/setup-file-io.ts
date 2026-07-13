import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Shared file-I/O primitives for `setup`'s local-config writers (ssh-alias, db-target, and
 * later config-allowlist / deploy-recipe) — extracted so the read-missing-returns-empty and
 * write-at-0o600-with-0o700-parent behavior lives in exactly one place instead of being
 * hand-copied per phase.
 */

export function readTextOrEmpty(path: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
}

export function writeTextSecure(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, text, { mode: 0o600 });
}

/**
 * Appends `newBlock` after `existingContent` with exactly one blank-line separator; when
 * `existingContent` is empty (or all-whitespace), returns `newBlock` as-is with a single
 * trailing newline. The shared "append a new block" tail shared by ssh-alias/db-target/
 * config-allowlist/deploy-recipe — each of those still owns its own locate/merge logic
 * (finding a stanza/table to update), which genuinely diverges per file grammar; this is
 * only the trivial common ending they all had hand-copied independently.
 */
export function appendBlock(existingContent: string, newBlock: string): string {
  const trimmed = existingContent.replace(/\s+$/, '');
  return trimmed.length === 0 ? `${newBlock}\n` : `${trimmed}\n\n${newBlock}\n`;
}

/** Splits a config's text into lines with no trailing empty element, so line indices map
 *  exactly onto what a human editor would show — `joinLines` is its exact inverse. Shared by
 *  setup-ssh-alias.ts and setup-config-allowlist.ts, which both need to locate and rewrite a
 *  specific stanza/table by line index. */
export function splitLines(text: string): string[] {
  const withoutTrailingNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return withoutTrailingNewline.length === 0 ? [] : withoutTrailingNewline.split('\n');
}

export function joinLines(lines: string[]): string {
  return lines.length === 0 ? '' : `${lines.join('\n')}\n`;
}

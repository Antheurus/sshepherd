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

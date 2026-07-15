import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * `setup ssh-alias` writes sshepherd's own local config files and must stay structurally
 * separate from the 9 registry-driven groups: it never dispatches through `registry.ts`'s
 * `OpSpec`/`executeOp`, and it never routes a real remote op through `transport.ts`'s ssh
 * execution path (research.md's resolved Open Question: "Should the 'setup ⊥ registry'
 * boundary get an enforcing test?"). This test enforces that boundary by grepping every
 * `setup-ssh-alias*.ts` source file for a `from './registry'` or `from './transport'`
 * import and asserting zero matches.
 */
const SRC_DIR = join(import.meta.dir, '..');

function setupSshAliasSourceFiles(): string[] {
  return readdirSync(SRC_DIR)
    .filter((name) => name.startsWith('setup-ssh-alias') && name.endsWith('.ts'))
    .map((name) => join(SRC_DIR, name));
}

describe('setup ssh-alias — never imports registry.ts or transport.ts', () => {
  const files = setupSshAliasSourceFiles();

  test('found the setup-ssh-alias source files (sanity on the file glob itself)', () => {
    expect(files.length).toBeGreaterThanOrEqual(2);
  });

  test('no setup-ssh-alias*.ts file imports from ./registry or ./transport', () => {
    const offenders: Array<{ file: string; line: string }> = [];
    for (const file of files) {
      const lines = readFileSync(file, 'utf8').split('\n');
      for (const line of lines) {
        if (
          /from ['"]\.\/registry(\.ts)?['"]/.test(line) ||
          /from ['"]\.\/transport(\.ts)?['"]/.test(line)
        ) {
          offenders.push({ file, line: line.trim() });
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

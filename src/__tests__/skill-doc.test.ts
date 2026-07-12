import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getOp, listOps } from '../registry.ts';

const SKILL_MD_PATH = join(import.meta.dir, '..', '..', 'SKILL.md');

/** Extracts every `sshepherd <group> <action>` command line from SKILL.md's fenced
 *  ```bash blocks — the same lines a reader would copy-paste and run. */
function extractDocumentedCommands(skillMd: string): Array<[string, string]> {
  const commands: Array<[string, string]> = [];
  const pattern = /^sshepherd (\S+) (\S+)/gm;
  let match: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: standard regex-exec-loop idiom
  while ((match = pattern.exec(skillMd)) !== null) {
    const group = match[1] as string;
    const action = match[2] as string;
    if (group === '<group>' || action.startsWith('--')) {
      continue; // skip the literal usage-shape lines ("sshepherd <group> <action> ...")
    }
    commands.push([group, action]);
  }
  return commands;
}

describe('SKILL.md — Quick reference has no drift against the registry', () => {
  const skillMd = readFileSync(SKILL_MD_PATH, 'utf8');
  const documentedCommands = extractDocumentedCommands(skillMd);

  test('extracted at least one command line per registry op (sanity on the parser itself)', () => {
    expect(documentedCommands.length).toBeGreaterThanOrEqual(listOps().length);
  });

  test('every documented `sshepherd <group> <action>` line matches a real registry op', () => {
    const missing = documentedCommands.filter(([group, action]) => !getOp(group, action));
    expect(missing).toEqual([]);
  });

  test('every registry op appears at least once in the Quick reference (no silent omission)', () => {
    const documented = new Set(documentedCommands.map(([group, action]) => `${group} ${action}`));
    const undocumented = listOps()
      .map((op) => `${op.group} ${op.name}`)
      .filter((command) => !documented.has(command));
    expect(undocumented).toEqual([]);
  });
});

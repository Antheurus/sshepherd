import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getOp, listOps } from '../registry.ts';
import { SETUP_SUB_GROUPS } from '../setup.ts';

const SKILL_MD_PATH = join(import.meta.dir, '..', '..', 'SKILL.md');

/** Extracts every `sshepherd <group> <action>` command line from SKILL.md's fenced
 *  ```bash blocks — the same lines a reader would copy-paste and run. `setup` lines are
 *  skipped here (validated separately below against `SETUP_SUB_GROUPS`, since `setup` is
 *  deliberately off the registry and would never match `getOp`). */
function extractDocumentedCommands(skillMd: string): Array<[string, string]> {
  const commands: Array<[string, string]> = [];
  const pattern = /^sshepherd (\S+) (\S+)/gm;
  let match: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: standard regex-exec-loop idiom
  while ((match = pattern.exec(skillMd)) !== null) {
    const group = match[1] as string;
    const action = match[2] as string;
    if (group === '<group>' || group === 'setup' || action.startsWith('--')) {
      continue; // skip the literal usage-shape lines and setup lines (checked separately)
    }
    commands.push([group, action]);
  }
  return commands;
}

/** Extracts every `sshepherd setup <sub-group> <action>` command line from SKILL.md's
 *  `# setup` Quick-reference block. */
function extractDocumentedSetupCommands(skillMd: string): Array<[string, string]> {
  const commands: Array<[string, string]> = [];
  const pattern = /^sshepherd setup (\S+) (\S+)/gm;
  let match: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: standard regex-exec-loop idiom
  while ((match = pattern.exec(skillMd)) !== null) {
    commands.push([match[1] as string, match[2] as string]);
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

describe('SKILL.md — setup section has no drift against SETUP_SUB_GROUPS', () => {
  const skillMd = readFileSync(SKILL_MD_PATH, 'utf8');
  const documentedSetupCommands = extractDocumentedSetupCommands(skillMd);

  test('every documented `sshepherd setup <sub-group> <action>` line matches a real setup action', () => {
    const missing = documentedSetupCommands.filter(
      ([subGroup, action]) =>
        !SETUP_SUB_GROUPS.some((sub) => sub.name === subGroup && sub.actions.includes(action)),
    );
    expect(missing).toEqual([]);
  });

  test('every setup sub-group/action appears at least once in the Quick reference', () => {
    const documented = new Set(
      documentedSetupCommands.map(([subGroup, action]) => `${subGroup} ${action}`),
    );
    const undocumented = SETUP_SUB_GROUPS.flatMap((sub) =>
      sub.actions.map((action) => `${sub.name} ${action}`),
    ).filter((command) => !documented.has(command));
    expect(undocumented).toEqual([]);
  });

  test("Quick reference heading's counts match listOps()/SETUP_SUB_GROUPS (no stale numbers)", () => {
    const headingMatch = skillMd.match(
      /## Quick reference — (\d+) registry-driven groups \((\d+) ops\) \+ 1 `setup` group \((\d+) sub-groups, (\d+) actions\)/,
    );
    expect(headingMatch).not.toBeNull();
    const [, groupsCount, opsCount, setupSubGroupsCount, setupActionsCount] =
      headingMatch as RegExpMatchArray;

    const registryGroupCount = new Set(listOps().map((op) => op.group)).size;
    const setupActionsTotal = SETUP_SUB_GROUPS.reduce((sum, sub) => sum + sub.actions.length, 0);

    expect(Number(groupsCount)).toBe(registryGroupCount);
    expect(Number(opsCount)).toBe(listOps().length);
    expect(Number(setupSubGroupsCount)).toBe(SETUP_SUB_GROUPS.length);
    expect(Number(setupActionsCount)).toBe(setupActionsTotal);
  });
});

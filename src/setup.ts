import { hasFlag, parseArgv } from './cli.ts';
import { buildSetupResult, printSetupResult } from './setup-types.ts';

/**
 * A `setup` sub-group's declared action names — data-driven the same way `registry.ts`
 * drives the 9 existing groups, but deliberately kept out of `REGISTRY`/`OpSpec`
 * entirely (see research.md, why `OpSpec.runLocal` can't express `setup`).
 */
interface SetupSubGroupSpec {
  name: string;
  summary: string;
  actions: string[];
}

const SETUP_SUB_GROUPS: SetupSubGroupSpec[] = [
  {
    name: 'ssh-alias',
    summary: 'Register, generate a keypair for, or remove a ~/.ssh/config alias.',
    actions: ['register', 'keygen', 'remove'],
  },
  {
    name: 'db-target',
    summary: 'Scaffold a [<name>] table into targets.toml.',
    actions: ['scaffold'],
  },
  {
    name: 'config-allowlist',
    summary: 'Scaffold a [<alias>] entry into config-allowlist.toml.',
    actions: ['scaffold'],
  },
  {
    name: 'deploy-recipe',
    summary: 'Scaffold a minimal deploy recipe TOML skeleton.',
    actions: ['scaffold'],
  },
];

function formatSetupTopHelp(): string {
  return [
    'sshepherd setup <sub-group> <action> [flags]',
    '',
    "setup writes sshepherd's own local config files (~/.ssh/config, targets.toml,",
    'config-allowlist.toml, deploy recipes). Human-only — an AI agent must never invoke it.',
    '',
    'Sub-groups:',
    ...SETUP_SUB_GROUPS.map((sub) => `  ${sub.name}`.padEnd(20) + sub.summary),
    '',
    'Run `sshepherd setup <sub-group> --help` to see actions for a sub-group.',
  ].join('\n');
}

function formatSetupSubGroupHelp(sub: SetupSubGroupSpec): string {
  return [
    `sshepherd setup ${sub.name} <action> [flags]`,
    '',
    sub.summary,
    '',
    'Actions:',
    ...sub.actions.map((action) => `  ${action}`),
  ].join('\n');
}

function printUnknownSubGroup(subGroupName: string): void {
  const result = buildSetupResult({
    command: `setup ${subGroupName}`,
    error: {
      code: 'UNKNOWN_SUBGROUP',
      message: `unknown setup sub-group "${subGroupName}". Sub-groups: ${SETUP_SUB_GROUPS.map((sub) => sub.name).join(', ')}`,
    },
  });
  printSetupResult(result, false);
  process.exitCode = 1;
}

function printUnknownAction(sub: SetupSubGroupSpec, action: string): void {
  const result = buildSetupResult({
    command: `setup ${sub.name} ${action}`,
    error: {
      code: 'UNKNOWN_SUBGROUP',
      message: `unknown action "${action}" for setup sub-group "${sub.name}". Actions: ${sub.actions.join(', ')}`,
    },
  });
  printSetupResult(result, false);
  process.exitCode = 1;
}

/**
 * Every real sub-group (ssh-alias, db-target, config-allowlist, deploy-recipe) is wired
 * to this stub in Phase 1 — later phases replace each entry's handling with real
 * config-writing logic. `--yes` is parsed here (same `parseArgv`/`hasFlag` the 9 existing
 * groups use) so a later phase can thread `{mutating, yes}` through to `confirmGate`
 * without changing how the dispatcher reads argv.
 */
function runStubAction(sub: SetupSubGroupSpec, action: string, argTail: string[]): void {
  const { flags } = parseArgv(argTail);
  const pretty = hasFlag(flags, 'pretty');
  const result = buildSetupResult({
    command: `setup ${sub.name} ${action}`,
    error: {
      code: 'NOT_IMPLEMENTED',
      message: `setup ${sub.name} ${action} is not implemented yet`,
    },
  });
  printSetupResult(result, pretty);
  process.exitCode = 1;
}

/**
 * `setup`'s own dispatcher — a fully separate path from `run()`'s `OpSpec`/`executeOp`
 * flow (see research.md, why `runLocal` can't express `setup`). `cli.ts` intercepts
 * `first === 'setup'` and hands the remaining argv (everything after `setup`) to this
 * function before the existing `GROUPS` validation ever runs.
 */
export async function runSetup(tail: string[]): Promise<void> {
  const [first, ...rest] = tail;
  if (first === undefined || first === '--help' || first === '-h') {
    process.stdout.write(`${formatSetupTopHelp()}\n`);
    return;
  }

  const subGroup = SETUP_SUB_GROUPS.find((sub) => sub.name === first);
  if (!subGroup) {
    printUnknownSubGroup(first);
    return;
  }

  const [actionOrHelp, ...argTail] = rest;
  if (actionOrHelp === undefined || actionOrHelp === '--help' || actionOrHelp === '-h') {
    process.stdout.write(`${formatSetupSubGroupHelp(subGroup)}\n`);
    return;
  }

  if (!subGroup.actions.includes(actionOrHelp)) {
    printUnknownAction(subGroup, actionOrHelp);
    return;
  }

  runStubAction(subGroup, actionOrHelp, argTail);
}

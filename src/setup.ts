import { getFlag, hasFlag, parseArgv } from './cli.ts';
import { scaffold as scaffoldConfigAllowlist } from './setup-config-allowlist.ts';
import { scaffold } from './setup-db-target.ts';
import { scaffold as scaffoldDeployRecipe } from './setup-deploy-recipe.ts';
import { keygen, register, remove } from './setup-ssh-alias.ts';
import { buildSetupResult, printSetupResult, type SetupResult } from './setup-types.ts';

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
 * `ssh-alias` is the first setup sub-group to leave stub status (Phase 2) — real
 * register/keygen/remove logic lives in `setup-ssh-alias.ts`. Every other sub-group still
 * falls through to `runStubAction` until its own phase lands.
 */
async function runSshAliasAction(action: string, argTail: string[]): Promise<void> {
  const command = `setup ssh-alias ${action}`;
  const { positionals, flags } = parseArgv(argTail);
  const pretty = hasFlag(flags, 'pretty');
  const yes = hasFlag(flags, 'yes');
  const alias = positionals[0];

  if (alias === undefined) {
    const result = buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: missing required positional argument 'alias'`,
      },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  let result: SetupResult<unknown>;
  if (action === 'register') {
    const host = getFlag(flags, 'host');
    const user = getFlag(flags, 'user');
    const portRaw = getFlag(flags, 'port');
    const port = portRaw === undefined ? undefined : Number(portRaw);
    if (host === undefined || user === undefined) {
      result = buildSetupResult({
        command,
        error: { code: 'INVALID_ARGS', message: `${command}: --host and --user are required` },
      });
    } else if (port !== undefined && !Number.isInteger(port)) {
      result = buildSetupResult({
        command,
        error: { code: 'INVALID_ARGS', message: `${command}: --port must be an integer` },
      });
    } else {
      result = register(alias, { host, user, port, overwrite: hasFlag(flags, 'overwrite'), yes });
    }
  } else if (action === 'keygen') {
    result = await keygen(alias, { yes });
  } else {
    result = await remove(alias, { yes });
  }

  printSetupResult(result, pretty);
  process.exitCode = result.ok ? 0 : 1;
}

/**
 * `db-target` is the second setup sub-group to leave stub status (Phase 3) — real scaffold
 * logic lives in `setup-db-target.ts`. `db-target` only ever has one action (`scaffold`), so
 * unlike `runSshAliasAction` there is no action-name branching here.
 */
function runDbTargetAction(argTail: string[]): void {
  const command = 'setup db-target scaffold';
  const { positionals, flags } = parseArgv(argTail);
  const pretty = hasFlag(flags, 'pretty');
  const yes = hasFlag(flags, 'yes');
  const name = positionals[0];

  if (name === undefined) {
    const result = buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: missing required positional argument 'name'`,
      },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  const alias = getFlag(flags, 'alias');
  const user = getFlag(flags, 'user');
  const database = getFlag(flags, 'database');
  if (alias === undefined || user === undefined || database === undefined) {
    const result = buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: --alias, --user, and --database are required`,
      },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  const result = scaffold(name, {
    alias,
    user,
    database,
    composeFile: getFlag(flags, 'compose-file'),
    service: getFlag(flags, 'service'),
    container: getFlag(flags, 'container'),
    yes,
  });

  printSetupResult(result, pretty);
  process.exitCode = result.ok ? 0 : 1;
}

/**
 * `config-allowlist` is the third setup sub-group to leave stub status (Phase 4) — real
 * scaffold logic lives in `setup-config-allowlist.ts`. `config-allowlist` only ever has one
 * action (`scaffold`), same shape as `runDbTargetAction`.
 */
function runConfigAllowlistAction(argTail: string[]): void {
  const command = 'setup config-allowlist scaffold';
  const { positionals, flags } = parseArgv(argTail);
  const pretty = hasFlag(flags, 'pretty');
  const yes = hasFlag(flags, 'yes');
  const alias = positionals[0];

  if (alias === undefined) {
    const result = buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: missing required positional argument 'alias'`,
      },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  const pathsRaw = getFlag(flags, 'paths');
  if (pathsRaw === undefined) {
    const result = buildSetupResult({
      command,
      error: { code: 'INVALID_ARGS', message: `${command}: --paths is required` },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  const paths = pathsRaw
    .split(',')
    .map((path) => path.trim())
    .filter((path) => path.length > 0);

  const result = scaffoldConfigAllowlist(alias, { paths, yes });

  printSetupResult(result, pretty);
  process.exitCode = result.ok ? 0 : 1;
}

/**
 * `deploy-recipe` is the fourth setup sub-group to leave stub status (Phase 5) — real
 * scaffold logic lives in `setup-deploy-recipe.ts`. `deploy-recipe` only ever has one action
 * (`scaffold`), same shape as `runDbTargetAction`/`runConfigAllowlistAction`.
 */
function runDeployRecipeAction(argTail: string[]): void {
  const command = 'setup deploy-recipe scaffold';
  const { positionals, flags } = parseArgv(argTail);
  const pretty = hasFlag(flags, 'pretty');
  const yes = hasFlag(flags, 'yes');
  const name = positionals[0];

  if (name === undefined) {
    const result = buildSetupResult({
      command,
      error: {
        code: 'INVALID_ARGS',
        message: `${command}: missing required positional argument 'name'`,
      },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  const alias = getFlag(flags, 'alias');
  const workdir = getFlag(flags, 'workdir');
  if (alias === undefined || workdir === undefined) {
    const result = buildSetupResult({
      command,
      error: { code: 'INVALID_ARGS', message: `${command}: --alias and --workdir are required` },
    });
    printSetupResult(result, pretty);
    process.exitCode = 1;
    return;
  }

  const result = scaffoldDeployRecipe(name, { alias, workdir, yes });

  printSetupResult(result, pretty);
  process.exitCode = result.ok ? 0 : 1;
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

  if (subGroup.name === 'ssh-alias') {
    await runSshAliasAction(actionOrHelp, argTail);
    return;
  }

  if (subGroup.name === 'db-target') {
    runDbTargetAction(argTail);
    return;
  }

  if (subGroup.name === 'config-allowlist') {
    runConfigAllowlistAction(argTail);
    return;
  }

  if (subGroup.name === 'deploy-recipe') {
    runDeployRecipeAction(argTail);
    return;
  }

  runStubAction(subGroup, actionOrHelp, argTail);
}

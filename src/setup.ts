import { getFlag, hasFlag, parseArgv } from './cli.ts';
import { setupProfileDenial } from './profiles.ts';
import { scaffold as scaffoldConfigAllowlist } from './setup-config-allowlist.ts';
import { discover, roRole, scaffold } from './setup-db-target.ts';
import { scaffold as scaffoldDeployRecipe } from './setup-deploy-recipe.ts';
import { scaffold as scaffoldFilesAllowlist } from './setup-files-allowlist.ts';
import { scaffold as scaffoldRevealAllowlist } from './setup-reveal-allowlist.ts';
import { install, keygen, list, register, remove, status, update } from './setup-ssh-alias.ts';
import {
  buildSetupResult,
  printSetupResult,
  type SetupResult,
  setupExitCode,
} from './setup-types.ts';
import { didYouMean, didYouMeanOrAll } from './suggest.ts';

/**
 * A `setup` sub-group's declared action names — data-driven the same way `registry.ts`
 * drives the 9 existing groups, but deliberately kept out of `REGISTRY`/`OpSpec`
 * entirely (see research.md, why `OpSpec.runLocal` can't express `setup`).
 */
export interface SetupSubGroupSpec {
  name: string;
  summary: string;
  actions: string[];
}

/** Exported (data only, same precedent as `registry.ts`'s `export { parseHumanBytes }`)
 *  so `skill-doc.test.ts` can assert SKILL.md's documented sub-group/action counts against
 *  this real data structure instead of a static string check. */
export const SETUP_SUB_GROUPS: SetupSubGroupSpec[] = [
  {
    name: 'ssh-alias',
    summary: 'Register, generate a keypair for, install a key on, or remove a ~/.ssh/config alias.',
    actions: ['register', 'keygen', 'remove', 'install', 'list', 'status', 'update'],
  },
  {
    name: 'db-target',
    summary:
      'Scaffold a [<name>] table into targets.toml, print the read-only role SQL for one, or discover postgres containers on a host.',
    actions: ['scaffold', 'ro-role', 'discover'],
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
  {
    name: 'files-allowlist',
    summary: 'Scaffold a [<alias>] entry into files-allowlist.toml (gates the files group).',
    actions: ['scaffold'],
  },
  {
    name: 'reveal-allowlist',
    summary: 'Scaffold a [<alias>] entry into reveal-allowlist.toml (gates files cat --reveal).',
    actions: ['scaffold'],
  },
];

/** Flags every setup action accepts. */
const SETUP_GLOBAL_FLAGS = ['pretty', 'yes'];

/** The flags each setup action reads, by `<sub-group> <action>`; any other flag is refused. */
const SETUP_ACTION_FLAGS: Record<string, string[]> = {
  'ssh-alias register': ['host', 'user', 'port', 'overwrite'],
  'ssh-alias update': ['host', 'user', 'port'],
  'db-target scaffold': ['alias', 'user', 'database', 'compose-file', 'service', 'container'],
  'db-target ro-role': ['print-sql', 'role', 'all-data', 'tables-only'],
  'db-target discover': [],
  'config-allowlist scaffold': ['paths'],
  'files-allowlist scaffold': ['paths'],
  'reveal-allowlist scaffold': ['keys'],
  'deploy-recipe scaffold': ['alias', 'workdir'],
};

/** Refuses a flag the action does not read, so a typo such as `--ovewrite` never runs as if
 *  it were absent; true when it printed the refusal. */
function rejectUnknownSetupFlags(
  sub: SetupSubGroupSpec,
  action: string,
  argTail: string[],
): boolean {
  const known = [...SETUP_GLOBAL_FLAGS, ...(SETUP_ACTION_FLAGS[`${sub.name} ${action}`] ?? [])];
  const unknown = [...parseArgv(argTail).flags.keys()].find((name) => !known.includes(name));
  if (unknown === undefined) {
    return false;
  }
  const result = buildSetupResult({
    command: `setup ${sub.name} ${action}`,
    error: {
      code: 'PARSE_ERROR',
      message: `unknown flag --${unknown} for 'setup ${sub.name} ${action}'. Flags: ${known.map((flag) => `--${flag}`).join(', ')}`,
      next: `sshepherd setup ${sub.name} --help`,
      did_you_mean: didYouMean(unknown, known).map((flag) => `--${flag}`),
    },
  });
  printSetupResult(result, false);
  process.exitCode = setupExitCode(result);
  return true;
}

function formatSetupTopHelp(): string {
  return [
    'sshepherd setup <sub-group> <action> [flags]',
    '',
    "setup writes sshepherd's own local config files (~/.ssh/config, targets.toml,",
    'config-allowlist.toml, deploy recipes). Agent-invocable like every other group, gated',
    'by --yes — the one exception is ssh-alias install, where a human types the password',
    'into a one-shot browser form the agent never sees.',
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
      did_you_mean: didYouMeanOrAll(
        subGroupName,
        SETUP_SUB_GROUPS.map((sub) => sub.name),
      ),
    },
  });
  printSetupResult(result, false);
  process.exitCode = setupExitCode(result);
}

function printUnknownAction(sub: SetupSubGroupSpec, action: string): void {
  const result = buildSetupResult({
    command: `setup ${sub.name} ${action}`,
    error: {
      code: 'UNKNOWN_SUBGROUP',
      message: `unknown action "${action}" for setup sub-group "${sub.name}". Actions: ${sub.actions.join(', ')}`,
      next: `sshepherd setup ${sub.name} --help`,
      did_you_mean: didYouMeanOrAll(action, sub.actions),
    },
  });
  printSetupResult(result, false);
  process.exitCode = setupExitCode(result);
}

/**
 * `ssh-alias` is the first setup sub-group to leave stub status (Phase 2) — real
 * register/keygen/remove logic lives in `setup-ssh-alias.ts`.
 */
async function runSshAliasAction(action: string, argTail: string[]): Promise<void> {
  const command = `setup ssh-alias ${action}`;
  const { positionals, flags } = parseArgv(argTail);
  const pretty = hasFlag(flags, 'pretty');
  const yes = hasFlag(flags, 'yes');

  if (action === 'list') {
    const result = list();
    printSetupResult(result, pretty);
    process.exitCode = setupExitCode(result);
    return;
  }

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
    process.exitCode = setupExitCode(result);
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
  } else if (action === 'install') {
    result = await install(alias, { yes });
  } else if (action === 'status') {
    result = status(alias);
  } else if (action === 'update') {
    const host = getFlag(flags, 'host');
    const user = getFlag(flags, 'user');
    const portRaw = getFlag(flags, 'port');
    const port = portRaw === undefined ? undefined : Number(portRaw);
    if (host === undefined && user === undefined && port === undefined) {
      result = buildSetupResult({
        command,
        error: {
          code: 'INVALID_ARGS',
          message: `${command}: at least one of --host, --user, --port is required`,
        },
      });
    } else if (port !== undefined && !Number.isInteger(port)) {
      result = buildSetupResult({
        command,
        error: { code: 'INVALID_ARGS', message: `${command}: --port must be an integer` },
      });
    } else {
      result = update(alias, { host, user, port, yes });
    }
  } else {
    result = await remove(alias, { yes });
  }

  printSetupResult(result, pretty);
  process.exitCode = setupExitCode(result);
}

/** `setup db-target ro-role <target> --print-sql [--role <name>] [--all-data]`: the SQL is the whole output
 *  (plain text a human pipes into psql); only a refusal prints a setup result. */
function runDbTargetRoRole(argTail: string[]): void {
  const { positionals, flags } = parseArgv(argTail);
  const printSql = getFlag(flags, 'print-sql');
  const allData = getFlag(flags, 'all-data');
  const tablesOnly = getFlag(flags, 'tables-only');
  // `--print-sql <target>` / `--all-data <target>` / `--tables-only <target>`: no flag takes a
  // value, so a word after one is the target.
  for (const value of [printSql, allData, tablesOnly]) {
    if (value !== undefined && value !== 'true') {
      positionals.unshift(value);
    }
  }
  const target = positionals[0];
  if (target === undefined) {
    const result = buildSetupResult({
      command: 'setup db-target ro-role',
      error: {
        code: 'INVALID_ARGS',
        message: "setup db-target ro-role: missing required positional argument 'target'",
        next: 'sshepherd db list',
      },
    });
    printSetupResult(result, hasFlag(flags, 'pretty'));
    process.exitCode = setupExitCode(result);
    return;
  }
  const outcome = roRole(target, {
    printSql: printSql !== undefined,
    role: getFlag(flags, 'role'),
    allData: allData !== undefined,
    tablesOnly: tablesOnly !== undefined,
  });
  if ('sql' in outcome) {
    process.stdout.write(outcome.sql);
    return;
  }
  printSetupResult(outcome, hasFlag(flags, 'pretty'));
  process.exitCode = setupExitCode(outcome);
}

async function runDbTargetDiscover(argTail: string[]): Promise<void> {
  const { positionals, flags } = parseArgv(argTail);
  const alias = positionals[0];
  const result =
    alias === undefined
      ? buildSetupResult({
          command: 'setup db-target discover',
          error: {
            code: 'INVALID_ARGS',
            message: "setup db-target discover: missing required positional argument 'alias'",
            next: 'sshepherd hosts list',
          },
        })
      : await discover(alias);
  printSetupResult(result, hasFlag(flags, 'pretty'));
  process.exitCode = setupExitCode(result);
}

/**
 * `db-target` is the second setup sub-group to leave stub status (Phase 3) — real scaffold
 * logic lives in `setup-db-target.ts`; `ro-role` and `discover` branch off before it.
 */
async function runDbTargetAction(action: string, argTail: string[]): Promise<void> {
  if (action === 'ro-role') {
    runDbTargetRoRole(argTail);
    return;
  }
  if (action === 'discover') {
    await runDbTargetDiscover(argTail);
    return;
  }
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
    process.exitCode = setupExitCode(result);
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
    process.exitCode = setupExitCode(result);
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
  process.exitCode = setupExitCode(result);
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
    process.exitCode = setupExitCode(result);
    return;
  }

  const pathsRaw = getFlag(flags, 'paths');
  if (pathsRaw === undefined) {
    const result = buildSetupResult({
      command,
      error: { code: 'INVALID_ARGS', message: `${command}: --paths is required` },
    });
    printSetupResult(result, pretty);
    process.exitCode = setupExitCode(result);
    return;
  }

  const paths = pathsRaw
    .split(',')
    .map((path) => path.trim())
    .filter((path) => path.length > 0);

  const result = scaffoldConfigAllowlist(alias, { paths, yes });

  printSetupResult(result, pretty);
  process.exitCode = setupExitCode(result);
}

/**
 * `files-allowlist` gates the `files` group's 6 ops the same way `config-allowlist` gates
 * `config get`/`validate`/`put` — same shape as `runConfigAllowlistAction`, different target
 * file (`setup-files-allowlist.ts`).
 */
function runFilesAllowlistAction(argTail: string[]): void {
  const command = 'setup files-allowlist scaffold';
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
    process.exitCode = setupExitCode(result);
    return;
  }

  const pathsRaw = getFlag(flags, 'paths');
  if (pathsRaw === undefined) {
    const result = buildSetupResult({
      command,
      error: { code: 'INVALID_ARGS', message: `${command}: --paths is required` },
    });
    printSetupResult(result, pretty);
    process.exitCode = setupExitCode(result);
    return;
  }

  const paths = pathsRaw
    .split(',')
    .map((path) => path.trim())
    .filter((path) => path.length > 0);

  const result = scaffoldFilesAllowlist(alias, { paths, yes });

  printSetupResult(result, pretty);
  process.exitCode = setupExitCode(result);
}

/**
 * `reveal-allowlist` gates `files cat --reveal` the same way `config-allowlist` gates
 * `config` ops — same shape as `runFilesAllowlistAction`, `--keys` instead of `--paths`,
 * target file `setup-reveal-allowlist.ts`.
 */
function runRevealAllowlistAction(argTail: string[]): void {
  const command = 'setup reveal-allowlist scaffold';
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
    process.exitCode = setupExitCode(result);
    return;
  }

  const keysRaw = getFlag(flags, 'keys');
  if (keysRaw === undefined) {
    const result = buildSetupResult({
      command,
      error: { code: 'INVALID_ARGS', message: `${command}: --keys is required` },
    });
    printSetupResult(result, pretty);
    process.exitCode = setupExitCode(result);
    return;
  }

  const keys = keysRaw
    .split(',')
    .map((key) => key.trim())
    .filter((key) => key.length > 0);

  const result = scaffoldRevealAllowlist(alias, { keys, yes });

  printSetupResult(result, pretty);
  process.exitCode = setupExitCode(result);
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
    process.exitCode = setupExitCode(result);
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
    process.exitCode = setupExitCode(result);
    return;
  }

  const result = scaffoldDeployRecipe(name, { alias, workdir, yes });

  printSetupResult(result, pretty);
  process.exitCode = setupExitCode(result);
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

  if (argTail.includes('--help') || argTail.includes('-h')) {
    process.stdout.write(`${formatSetupSubGroupHelp(subGroup)}\n`);
    return;
  }

  if (rejectUnknownSetupFlags(subGroup, actionOrHelp, argTail)) {
    return;
  }

  const denied = setupProfileDenial(`${subGroup.name} ${actionOrHelp}`);
  if (denied !== null) {
    const result = buildSetupResult({
      command: `setup ${subGroup.name} ${actionOrHelp}`,
      error: { code: 'PROFILE_DENIED', message: denied.message, hint: denied.hint },
    });
    printSetupResult(result, hasFlag(parseArgv(argTail).flags, 'pretty'));
    process.exitCode = setupExitCode(result);
    return;
  }

  if (subGroup.name === 'ssh-alias') {
    await runSshAliasAction(actionOrHelp, argTail);
    return;
  }

  if (subGroup.name === 'db-target') {
    await runDbTargetAction(actionOrHelp, argTail);
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

  if (subGroup.name === 'files-allowlist') {
    runFilesAllowlistAction(argTail);
    return;
  }

  if (subGroup.name === 'reveal-allowlist') {
    runRevealAllowlistAction(argTail);
    return;
  }
}

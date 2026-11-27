import { DEPLOY_TIMEOUT_SEC } from '../limits.ts';
import {
  arg,
  type ComposePsEntry,
  DEFAULT_LOG_TAIL,
  DEFAULT_TIMEOUT_SEC,
  LOG_TIMEOUT_SEC,
  optBool,
  optStr,
  reqStr,
  shapeComposePsEntry,
} from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import {
  buildMigrateScript,
  buildRollbackCommand,
  buildRunScript,
  type DeployPlan,
  loadRecipe,
  parseFailedStepMarker,
  planRecipe,
} from '../recipes.ts';
import type { OpContext, OpSpec, RawResult } from '../types.ts';

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

function loadRecipeFromCtx(ctx: OpContext): ReturnType<typeof loadRecipe> {
  return loadRecipe(reqStr(ctx, 'recipe'));
}

/** Attributes a `COMMAND_FAILED` deploy/migrate failure to the step that actually failed,
 *  by recovering the `STEP_FAILURE_MARKER` line `buildRunScript` wraps each step to echo. */
function shapeDeployError(raw: RawResult): Record<string, unknown> | undefined {
  const failedStep = parseFailedStepMarker(raw.stdout);
  return failedStep ? { failed_step: failedStep } : undefined;
}

const deployRun: OpSpec<DeployPlan | { output: string }> = {
  group: 'deploy',
  name: 'run',
  summary: 'Execute (or --dry-run plan) a deploy recipe in resolved dependency order.',
  args: [
    arg('recipe', 'positional', true, 'Recipe name.'),
    arg(
      'dry-run',
      'flag',
      false,
      'Print the resolved plan; execute nothing, no confirmation needed.',
    ),
  ],
  mutating: true,
  exposes: 'content',
  timeoutSec: DEPLOY_TIMEOUT_SEC,
  truncateKeeps: 'tail',
  maskEnvBlocks: true,
  output: 'raw',
  buildRemote: (ctx) => {
    if (optBool(ctx, 'dry-run', false)) {
      return null;
    }
    const recipe = loadRecipeFromCtx(ctx);
    return buildRunScript(recipe.steps, recipe.workdir);
  },
  shape: (parsed) => ({ output: (parsed as string).trim() }),
  shapeError: shapeDeployError,
  runLocal: (ctx) => planRecipe(loadRecipeFromCtx(ctx)),
};

const deployStatus: OpSpec<ComposePsEntry[]> = {
  group: 'deploy',
  name: 'status',
  summary: 'docker compose ps for the recipe workdir — live image tag/health per service.',
  args: [arg('recipe', 'positional', true, 'Recipe name.')],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'ndjson',
  buildRemote: (ctx) => {
    const recipe = loadRecipeFromCtx(ctx);
    return shellJoin(['sh', '-c', `cd ${shq(recipe.workdir)} && docker compose ps --format json`]);
  },
  shape: (parsed) =>
    (parsed as unknown[])
      .map(shapeComposePsEntry)
      .filter((entry): entry is ComposePsEntry => entry !== null),
};

const deployRollback: OpSpec<{ output: string }> = {
  group: 'deploy',
  name: 'rollback',
  summary: 'Roll back using the recipe [rollback] block — refuses when the recipe declares none.',
  args: [arg('recipe', 'positional', true, 'Recipe name.')],
  mutating: true,
  exposes: 'content',
  timeoutSec: DEPLOY_TIMEOUT_SEC,
  truncateKeeps: 'tail',
  maskEnvBlocks: true,
  output: 'raw',
  buildRemote: (ctx) => buildRollbackCommand(loadRecipeFromCtx(ctx)),
  shape: (parsed) => ({ output: (parsed as string).trim() }),
};

const deployLogs: OpSpec<{ output: string }> = {
  group: 'deploy',
  name: 'logs',
  summary: 'docker compose logs (tail) for the recipe workdir.',
  args: [
    arg('recipe', 'positional', true, 'Recipe name.'),
    arg('tail', 'flag', false, `Number of lines (default ${DEFAULT_LOG_TAIL}).`),
  ],
  mutating: false,
  exposes: 'content',
  timeoutSec: LOG_TIMEOUT_SEC,
  truncateKeeps: 'tail',
  output: 'raw',
  buildRemote: (ctx) => {
    const recipe = loadRecipeFromCtx(ctx);
    const tail = optStr(ctx, 'tail', String(DEFAULT_LOG_TAIL));
    return shellJoin([
      'sh',
      '-c',
      `cd ${shq(recipe.workdir)} && docker compose logs --tail=${shq(tail)} --timestamps`,
    ]);
  },
  shape: (parsed) => ({ output: parsed as string }),
};

const deployMigrate: OpSpec<{ output: string }> = {
  group: 'deploy',
  name: 'migrate',
  summary: 'Run only the migrate-kind steps of a recipe, in resolved order.',
  args: [arg('recipe', 'positional', true, 'Recipe name.')],
  mutating: true,
  exposes: 'content',
  timeoutSec: DEPLOY_TIMEOUT_SEC,
  truncateKeeps: 'tail',
  maskEnvBlocks: true,
  output: 'raw',
  buildRemote: (ctx) => {
    const recipe = loadRecipeFromCtx(ctx);
    return buildMigrateScript(recipe.steps, recipe.workdir);
  },
  shape: (parsed) => ({ output: (parsed as string).trim() }),
  shapeError: shapeDeployError,
};

export const deployOps = [
  deployRun,
  deployStatus,
  deployRollback,
  deployLogs,
  deployMigrate,
] as OpSpec[];

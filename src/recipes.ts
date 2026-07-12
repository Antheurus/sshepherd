import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { shellJoin, shq } from './quote.ts';
import type { OpContext } from './types.ts';

/**
 * Typed deploy-recipe steps (Kamal-style declarative, research.md §"deploy recipes").
 * `shell`/`migrate`/`compose` embed `run` verbatim into the remote shell — this is the
 * ONE named pressure valve for raw shell (research.md: "raw shell allowed only inside a
 * declared, named, versioned recipe step"), never quoted, because a step legitimately
 * contains shell syntax like `&&` or flags. Everything else (workdir, targets, urls) is
 * still routed through `shq`/`shellJoin` like every other op in the registry.
 */
export interface ShellStep {
  kind: 'shell';
  name: string;
  run: string;
  mutates: boolean;
  depends_on?: string;
}

export interface ComposeStep {
  kind: 'compose';
  name: string;
  run: string;
  depends_on?: string;
}

export interface MigrateStep {
  kind: 'migrate';
  name: string;
  run: string;
  depends_on?: string;
}

export interface HealthcheckStep {
  kind: 'healthcheck';
  name: string;
  target: string;
  timeout: string;
  depends_on?: string;
}

export interface HttpProbeStep {
  kind: 'http-probe';
  name: string;
  url: string;
  expect_status: number;
  retries: number;
  interval: number;
  depends_on?: string;
}

export interface WaitStep {
  kind: 'wait';
  name: string;
  seconds: number;
  depends_on?: string;
}

export type RecipeStep =
  | ShellStep
  | ComposeStep
  | MigrateStep
  | HealthcheckStep
  | HttpProbeStep
  | WaitStep;

export type RollbackSpec =
  | { strategy: 'previous-tag'; tag: string }
  | { strategy: 'compose-file'; file: string };

export interface Recipe {
  name: string;
  alias: string;
  workdir: string;
  description: string;
  steps: RecipeStep[];
  rollback: RollbackSpec | null;
}

export interface PlanStep {
  name: string;
  kind: RecipeStep['kind'];
  mutates: boolean;
  depends_on: string | null;
  remote_command: string;
}

export interface DeployPlan {
  recipe: string;
  alias: string;
  workdir: string;
  steps: PlanStep[];
}

/** Overridable via `SSHEPHERD_RECIPE_PATH` for tests — mirrors targets.ts's SSHEPHERD_TARGETS_PATH override. */
export function resolveRecipePath(name: string): string {
  const override = process.env.SSHEPHERD_RECIPE_PATH;
  if (override && override.length > 0) {
    return override;
  }
  const inRepo = join(process.cwd(), '.sshepherd', `deploy.${name}.toml`);
  if (existsSync(inRepo)) {
    return inRepo;
  }
  return join(homedir(), '.config', 'sshepherd', 'recipes', `${name}.toml`);
}

interface RawStep {
  name?: unknown;
  kind?: unknown;
  run?: unknown;
  mutates?: unknown;
  depends_on?: unknown;
  target?: unknown;
  timeout?: unknown;
  url?: unknown;
  expect_status?: unknown;
  retries?: unknown;
  interval?: unknown;
  seconds?: unknown;
}

function readDependsOn(raw: RawStep): string | undefined {
  return typeof raw.depends_on === 'string' && raw.depends_on.length > 0
    ? raw.depends_on
    : undefined;
}

function readStep(raw: unknown): RecipeStep {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('recipe step is not a table');
  }
  const r = raw as RawStep;
  const name = typeof r.name === 'string' && r.name.length > 0 ? r.name : null;
  if (!name) {
    throw new Error("recipe step is missing 'name'");
  }
  const kind = typeof r.kind === 'string' ? r.kind : '';
  const dependsOn = readDependsOn(r);

  switch (kind) {
    case 'shell': {
      const run = typeof r.run === 'string' ? r.run : '';
      if (!run) {
        throw new Error(`step '${name}': shell step needs 'run'`);
      }
      const mutates = typeof r.mutates === 'boolean' ? r.mutates : true;
      return { kind: 'shell', name, run, mutates, depends_on: dependsOn };
    }
    case 'compose': {
      const run = typeof r.run === 'string' ? r.run : '';
      if (!run) {
        throw new Error(`step '${name}': compose step needs 'run'`);
      }
      return { kind: 'compose', name, run, depends_on: dependsOn };
    }
    case 'migrate': {
      const run = typeof r.run === 'string' ? r.run : '';
      if (!run) {
        throw new Error(`step '${name}': migrate step needs 'run'`);
      }
      return { kind: 'migrate', name, run, depends_on: dependsOn };
    }
    case 'healthcheck': {
      const target = typeof r.target === 'string' ? r.target : '';
      if (!target) {
        throw new Error(`step '${name}': healthcheck step needs 'target'`);
      }
      const timeout = typeof r.timeout === 'string' && r.timeout.length > 0 ? r.timeout : '30s';
      return { kind: 'healthcheck', name, target, timeout, depends_on: dependsOn };
    }
    case 'http-probe': {
      const url = typeof r.url === 'string' ? r.url : '';
      if (!url) {
        throw new Error(`step '${name}': http-probe step needs 'url'`);
      }
      const expectStatus = typeof r.expect_status === 'number' ? r.expect_status : 200;
      const retries = typeof r.retries === 'number' ? r.retries : 3;
      const interval = typeof r.interval === 'number' ? r.interval : 5;
      return {
        kind: 'http-probe',
        name,
        url,
        expect_status: expectStatus,
        retries,
        interval,
        depends_on: dependsOn,
      };
    }
    case 'wait': {
      const seconds = typeof r.seconds === 'number' ? r.seconds : 0;
      if (seconds <= 0) {
        throw new Error(`step '${name}': wait step needs a positive 'seconds'`);
      }
      return { kind: 'wait', name, seconds, depends_on: dependsOn };
    }
    default:
      throw new Error(`step '${name}': unknown kind '${kind}'`);
  }
}

function readRollback(raw: unknown): RollbackSpec | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const r = raw as Record<string, unknown>;
  const strategy = typeof r.strategy === 'string' ? r.strategy : '';
  if (strategy === 'previous-tag') {
    const tag = typeof r.tag === 'string' ? r.tag : '';
    if (!tag) {
      throw new Error("rollback strategy 'previous-tag' needs 'tag'");
    }
    return { strategy: 'previous-tag', tag };
  }
  if (strategy === 'compose-file') {
    const file = typeof r.file === 'string' ? r.file : '';
    if (!file) {
      throw new Error("rollback strategy 'compose-file' needs 'file'");
    }
    return { strategy: 'compose-file', file };
  }
  throw new Error(`rollback: unknown strategy '${strategy}'`);
}

/**
 * Declared-order-preserving topological sort: a step with `depends_on` is placed
 * immediately after the dependency is resolved, independent steps keep file order.
 * Rejects an unknown `depends_on` target and a dependency cycle — never silently drops
 * or guesses an order (the LMS gotcha: `migrate depends_on up` must sort after `up`
 * even when declared earlier in the file).
 */
export function resolveStepOrder(steps: RecipeStep[]): RecipeStep[] {
  const byName = new Map<string, RecipeStep>();
  for (const step of steps) {
    byName.set(step.name, step);
  }
  for (const step of steps) {
    if (step.depends_on !== undefined && !byName.has(step.depends_on)) {
      throw new Error(`recipe step '${step.name}' depends_on unknown step '${step.depends_on}'`);
    }
  }

  const resolved: RecipeStep[] = [];
  const visiting = new Set<string>();
  const visited = new Set<string>();

  function visit(step: RecipeStep): void {
    if (visited.has(step.name)) {
      return;
    }
    if (visiting.has(step.name)) {
      throw new Error(`recipe has a dependency cycle at step '${step.name}'`);
    }
    visiting.add(step.name);
    if (step.depends_on !== undefined) {
      const dep = byName.get(step.depends_on);
      if (dep) {
        visit(dep);
      }
    }
    visiting.delete(step.name);
    visited.add(step.name);
    resolved.push(step);
  }

  for (const step of steps) {
    visit(step);
  }
  return resolved;
}

/** Parses `'60s'`/`'2m'` into seconds — no other units, matches the TOML example's shape. */
function parseDurationSeconds(text: string): number {
  const match = /^(\d+)(s|m)?$/.exec(text.trim());
  if (!match) {
    throw new Error(`invalid duration '${text}' — expected e.g. '60s' or '2m'`);
  }
  const value = Number.parseInt(match[1] as string, 10);
  return match[2] === 'm' ? value * 60 : value;
}

function cdPrefix(workdir: string): string {
  return `cd ${shq(workdir)}`;
}

function healthcheckScript(target: string, timeoutSec: number): string {
  const t = shq(target);
  return (
    `to=${timeoutSec}; el=0; while true; do ` +
    `st=$(docker inspect --format '{{.State.Health.Status}}' ${t} 2>/dev/null || echo unknown); ` +
    `if [ "$st" = healthy ]; then exit 0; fi; ` +
    `el=$((el+2)); if [ "$el" -ge "$to" ]; then echo healthcheck-timeout >&2; exit 1; fi; ` +
    'sleep 2; done'
  );
}

function httpProbeScript(
  url: string,
  expectStatus: number,
  retries: number,
  interval: number,
): string {
  const u = shq(url);
  return (
    `i=0; while [ "$i" -lt ${retries} ]; do ` +
    `code=$(curl -s -o /dev/null -w '%{http_code}' ${u} || echo 000); ` +
    `if [ "$code" = "${expectStatus}" ]; then exit 0; fi; ` +
    'i=$((i+1)); sleep ' +
    `${interval}; done; echo http-probe-failed >&2; exit 1`
  );
}

/** The unwrapped shell fragment for one step — combined with `&&` for a multi-step script. */
function buildStepInnerScript(step: RecipeStep, workdir: string): string {
  switch (step.kind) {
    case 'shell':
    case 'migrate':
      return `${cdPrefix(workdir)} && ${step.run}`;
    case 'compose':
      return `${cdPrefix(workdir)} && docker compose ${step.run}`;
    case 'healthcheck':
      return healthcheckScript(step.target, parseDurationSeconds(step.timeout));
    case 'http-probe':
      return httpProbeScript(step.url, step.expect_status, step.retries, step.interval);
    case 'wait':
      return `sleep ${step.seconds}`;
    default: {
      const exhaustiveCheck: never = step;
      throw new Error(`unhandled step kind: ${JSON.stringify(exhaustiveCheck)}`);
    }
  }
}

function stepMutates(step: RecipeStep): boolean {
  switch (step.kind) {
    case 'shell':
      return step.mutates;
    case 'compose':
    case 'migrate':
      return true;
    case 'healthcheck':
    case 'http-probe':
    case 'wait':
      return false;
    default: {
      const exhaustiveCheck: never = step;
      throw new Error(`unhandled step kind: ${JSON.stringify(exhaustiveCheck)}`);
    }
  }
}

/** Prefix of the marker a wrapped step echoes to STDOUT (never stderr — the transport
 *  discards stderr entirely) on failure, so the caller can attribute a `COMMAND_FAILED`
 *  to the step that actually failed. */
export const STEP_FAILURE_MARKER = '__SSHEPHERD_STEP_FAILED__';

/**
 * Wraps one step's inner script so a non-zero exit echoes a parseable failure marker
 * before aborting the `&&` chain (`exit 1` keeps the stop-on-first-failure semantics).
 * The marker text is built entirely from author-controlled recipe data (the step's own
 * declared index/kind/name) and passed to `echo` as a single `shq`-quoted argument, so
 * a step name containing shell metacharacters cannot break out of the wrapper.
 */
function wrapStepScript(inner: string, index: number, kind: string, name: string): string {
  const marker = `${STEP_FAILURE_MARKER} ${index} ${kind} ${name}`;
  return `{ ${inner} ; } || { echo ${shq(marker)}; exit 1; }`;
}

export interface FailedStep {
  index: number;
  kind: string;
  name: string;
}

/**
 * Recovers which step failed from the deploy script's captured STDOUT. Returns
 * `undefined` when no step wrapper fired (e.g. a transport-level failure that never
 * reached the remote script at all).
 */
export function parseFailedStepMarker(stdout: string): FailedStep | undefined {
  const pattern = new RegExp(`^${STEP_FAILURE_MARKER} (\\d+) (\\S+) (.+)$`, 'm');
  const match = pattern.exec(stdout);
  if (!match) {
    return undefined;
  }
  return { index: Number(match[1]), kind: match[2] as string, name: match[3] as string };
}

/** One ssh round trip for the whole recipe: every step wrapped + joined with `&&` so the
 *  first failure stops the rest and echoes a `STEP_FAILURE_MARKER` line identifying itself. */
export function buildRunScript(steps: RecipeStep[], workdir: string): string {
  const combined = steps
    .map((step, index) =>
      wrapStepScript(buildStepInnerScript(step, workdir), index, step.kind, step.name),
    )
    .join(' && ');
  return shellJoin(['sh', '-c', combined]);
}

/** Runs only the `migrate`-kind steps, in their already-resolved order (LMS: after `up`, never a bare `artisan migrate`). */
export function buildMigrateScript(steps: RecipeStep[], workdir: string): string {
  const migrateSteps = steps.filter((step): step is MigrateStep => step.kind === 'migrate');
  if (migrateSteps.length === 0) {
    throw new Error('recipe has no migrate steps');
  }
  return buildRunScript(migrateSteps, workdir);
}

/** Refuses when the recipe declares no `[rollback]` block — never infers a rollback. */
export function buildRollbackCommand(recipe: Recipe): string {
  if (!recipe.rollback) {
    throw new Error(
      `recipe '${recipe.name}' declares no [rollback] block — refusing to guess a rollback`,
    );
  }
  const cd = cdPrefix(recipe.workdir);
  if (recipe.rollback.strategy === 'previous-tag') {
    return shellJoin([
      'sh',
      '-c',
      `${cd} && IMAGE_TAG=${shq(recipe.rollback.tag)} docker compose up -d`,
    ]);
  }
  return shellJoin(['sh', '-c', `${cd} && docker compose -f ${shq(recipe.rollback.file)} up -d`]);
}

/** The dry-run plan: resolved order, exact remote command per step, which steps mutate — executes nothing. */
export function planRecipe(recipe: Recipe): DeployPlan {
  return {
    recipe: recipe.name,
    alias: recipe.alias,
    workdir: recipe.workdir,
    steps: recipe.steps.map((step) => ({
      name: step.name,
      kind: step.kind,
      mutates: stepMutates(step),
      depends_on: step.depends_on ?? null,
      remote_command: shellJoin(['sh', '-c', buildStepInnerScript(step, recipe.workdir)]),
    })),
  };
}

/** Loads + validates a recipe TOML into a typed `Recipe` with steps already dependency-ordered. */
export function loadRecipe(name: string, path?: string): Recipe {
  const resolvedPath = path ?? resolveRecipePath(name);
  let text: string;
  try {
    text = readFileSync(resolvedPath, 'utf8');
  } catch {
    throw new Error(`recipe '${name}' not found`);
  }
  const parsed = Bun.TOML.parse(text) as Record<string, unknown>;
  const recipeName = typeof parsed.name === 'string' && parsed.name.length > 0 ? parsed.name : name;
  const alias = typeof parsed.alias === 'string' ? parsed.alias : '';
  const workdir = typeof parsed.workdir === 'string' ? parsed.workdir : '';
  const description = typeof parsed.description === 'string' ? parsed.description : '';
  if (!alias) {
    throw new Error(`recipe '${name}' is missing 'alias'`);
  }
  if (!workdir) {
    throw new Error(`recipe '${name}' is missing 'workdir'`);
  }

  const rawSteps = Array.isArray(parsed.step) ? parsed.step : [];
  if (rawSteps.length === 0) {
    throw new Error(`recipe '${name}' has no steps`);
  }
  const steps = rawSteps.map(readStep);

  const seenNames = new Set<string>();
  for (const step of steps) {
    if (seenNames.has(step.name)) {
      throw new Error(`recipe '${name}' has duplicate step '${step.name}'`);
    }
    seenNames.add(step.name);
  }

  const orderedSteps = resolveStepOrder(steps);
  const rollback = readRollback(parsed.rollback);

  return { name: recipeName, alias, workdir, description, steps: orderedSteps, rollback };
}

/**
 * Resolves a recipe name into the `OpContext` a `deploy`/`config` op's `buildRemote`
 * reads — `ctx.alias` becomes the recipe's ssh alias, mirroring `buildDbOpContext`
 * (targets.ts). `buildRemote`/`runLocal` reload the recipe fresh via `ctx.args.recipe`
 * (same resolution path), so no step data needs to be flattened into `ctx.args`.
 */
export function buildDeployOpContext(
  recipeName: string,
  extraArgs: Record<string, string | boolean>,
  path?: string,
): OpContext {
  const recipe = loadRecipe(recipeName, path);
  return {
    alias: recipe.alias,
    args: { ...extraArgs, recipe: recipeName },
  };
}

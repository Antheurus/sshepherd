import { existsSync } from 'node:fs';
import { auditMutating, confirmGate } from './audit.ts';
import { resolveRecipePath } from './recipes.ts';
import { appendBlock, readTextOrEmpty, writeTextSecure } from './setup-file-io.ts';
import { buildSetupResult, type SetupResult } from './setup-types.ts';

export interface ScaffoldOptions {
  alias: string;
  workdir: string;
  yes: boolean;
}

export interface ScaffoldData {
  name: string;
  alias: string;
  workdir: string;
}

/**
 * A minimal, valid recipe skeleton: `name`/`alias`/`workdir` filled in, plus ONE placeholder
 * `[[step]]` (`kind = "shell"`) the human edits further. No `[rollback]` block — its absence
 * is a valid, safe default (see `references/recipes.md`: `deploy rollback` refuses rather
 * than inferring a rollback strategy).
 */
function buildRecipeLines(name: string, alias: string, workdir: string): string[] {
  return [
    `name = "${name}"`,
    `alias = "${alias}"`,
    `workdir = "${workdir}"`,
    '',
    '[[step]]',
    'name = "example"',
    'kind = "shell"',
    '# run = "docker compose pull && docker compose up -d"  # replace with your real deploy command',
    `run = "echo 'sshepherd setup deploy-recipe: replace this placeholder step'"`,
  ];
}

/**
 * Writes a recipe skeleton to `resolveRecipePath(name)` (global `~/.config/sshepherd/recipes/
 * <name>.toml` by default, honoring the same `SSHEPHERD_RECIPE_PATH` override `loadRecipe`
 * itself respects). Refuses with `RECIPE_EXISTS` if a recipe file for `name` already exists,
 * leaving it untouched.
 */
export function scaffold(
  name: string,
  options: ScaffoldOptions,
  path: string = resolveRecipePath(name),
): SetupResult<ScaffoldData> {
  const command = 'setup deploy-recipe scaffold';
  const argsSummary = { alias: options.alias, workdir: options.workdir };

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'scaffold requires --yes' },
    });
  }

  if (existsSync(path)) {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: { code: 'RECIPE_EXISTS', message: `recipe '${name}' already exists at ${path}` },
    });
  }

  const recipeLines = buildRecipeLines(name, options.alias, options.workdir);
  const newText = appendBlock(readTextOrEmpty(path), recipeLines.join('\n'));
  writeTextSecure(path, newText);

  auditMutating({ alias: options.alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: { name, alias: options.alias, workdir: options.workdir },
  });
}

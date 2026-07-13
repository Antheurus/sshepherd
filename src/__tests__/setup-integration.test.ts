import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { listHostAliases } from '../parsers/ssh-config.ts';
import { loadRecipe, resolveStepOrder } from '../recipes.ts';
import { assertConfigPathAllowed } from '../registry.ts';
import { scaffold as scaffoldConfigAllowlist } from '../setup-config-allowlist.ts';
import { scaffold as scaffoldDbTarget } from '../setup-db-target.ts';
import { scaffold as scaffoldDeployRecipe } from '../setup-deploy-recipe.ts';
import { keygen, register, remove } from '../setup-ssh-alias.ts';
import { loadTargets } from '../targets.ts';
import type { OpContext } from '../types.ts';

/**
 * Drives the full `setup` onboarding sequence a human would actually run —
 * register → keygen → db-target → config-allowlist → deploy-recipe → remove — through the
 * same real functions the CLI dispatcher (`runSetup`) calls, against a shared temp
 * environment wired the same way the CLI wires it: an explicit ssh-config path for
 * `register`/`keygen`/`remove`, and env-var overrides (`SSHEPHERD_TARGETS_PATH`/
 * `SSHEPHERD_CONFIG_ALLOWLIST_PATH`/`SSHEPHERD_RECIPE_PATH`) for the other three, exactly
 * like `runDbTargetAction`/`runConfigAllowlistAction`/`runDeployRecipeAction` call `scaffold`
 * with no explicit path. Each per-file `setup-*.test.ts` only exercises its own sub-command
 * in isolation; this is the one place that proves state written by an earlier step (the ssh
 * alias `register` creates) is what a later step (`db-target scaffold`) actually references.
 */
function ctxFor(alias: string): OpContext {
  return { alias, args: {} };
}

describe('setup cross-sub-command integration', () => {
  test('register -> keygen -> db-target -> config-allowlist -> deploy-recipe -> remove', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sshepherd-setup-integration-'));
    const sshConfigPath = join(dir, 'ssh_config');
    const targetsPath = join(dir, 'targets.toml');
    const allowlistPath = join(dir, 'config-allowlist.toml');
    const recipePath = join(dir, 'deploy.demo.toml');

    const previousEnv = {
      sshConfig: process.env.SSHEPHERD_SSH_CONFIG_PATH,
      targets: process.env.SSHEPHERD_TARGETS_PATH,
      allowlist: process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH,
      recipe: process.env.SSHEPHERD_RECIPE_PATH,
    };
    process.env.SSHEPHERD_SSH_CONFIG_PATH = sshConfigPath;
    process.env.SSHEPHERD_TARGETS_PATH = targetsPath;
    process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = allowlistPath;
    process.env.SSHEPHERD_RECIPE_PATH = recipePath;

    try {
      const alias = 'prod-server';

      // Step 1: register — writes the managed stanza via the env-var-driven default path.
      const registerResult = register(alias, { host: '10.0.0.9', user: 'deploy', yes: true });
      expect(registerResult.ok).toBe(true);
      expect(listHostAliases(sshConfigPath)).toEqual([alias]);

      // Step 2: keygen — generates a real ed25519 keypair and rewrites IdentityFile in place.
      const keygenResult = await keygen(alias, { yes: true });
      expect(keygenResult.ok).toBe(true);
      const keyPath = join(dir, `sshepherd_${alias}_ed25519`);
      expect(existsSync(keyPath)).toBe(true);
      expect(existsSync(`${keyPath}.pub`)).toBe(true);

      // Step 3: db-target scaffold — the target's alias must be the same ssh alias register
      // just created, since that's what a real onboarding session would type.
      const dbTargetResult = scaffoldDbTarget('prod', {
        alias,
        user: 'sshepherd_ro',
        database: 'app',
        container: 'app_pg',
        yes: true,
      });
      expect(dbTargetResult.ok).toBe(true);
      expect(dbTargetResult.data?.alias).toBe(alias);
      const targets = loadTargets(targetsPath);
      expect(targets.prod?.alias).toBe(alias);

      // Step 4: config-allowlist scaffold — same alias again, gates config-path reads for it.
      const allowlistResult = scaffoldConfigAllowlist(alias, {
        paths: ['/opt/app/.env'],
        yes: true,
      });
      expect(allowlistResult.ok).toBe(true);
      expect(() => assertConfigPathAllowed(ctxFor(alias), '/opt/app/.env')).not.toThrow();

      // Step 5: deploy-recipe scaffold — the recipe's alias is the same ssh alias too.
      const recipeResult = scaffoldDeployRecipe('demo', { alias, workdir: '/opt/app', yes: true });
      expect(recipeResult.ok).toBe(true);
      const recipe = loadRecipe('demo', recipePath);
      expect(recipe.alias).toBe(alias);
      expect(recipe.workdir).toBe('/opt/app');
      expect(resolveStepOrder(recipe.steps)).toHaveLength(1);

      // Step 6: remove — cleans up the managed stanza and the keypair generated in step 2.
      const removeResult = await remove(alias, { yes: true });
      expect(removeResult.ok).toBe(true);
      expect(removeResult.data).toEqual({ alias, configRemoved: true, keyRemoved: true });
      expect(listHostAliases(sshConfigPath)).toEqual([]);
      expect(existsSync(keyPath)).toBe(false);
      expect(existsSync(`${keyPath}.pub`)).toBe(false);

      // The db-target/config-allowlist/deploy-recipe files remain untouched by `remove` —
      // only the ssh-alias's own stanza and keypair are in scope for that command.
      expect(loadTargets(targetsPath).prod?.alias).toBe(alias);
    } finally {
      for (const [envVar, value] of [
        ['SSHEPHERD_SSH_CONFIG_PATH', previousEnv.sshConfig],
        ['SSHEPHERD_TARGETS_PATH', previousEnv.targets],
        ['SSHEPHERD_CONFIG_ALLOWLIST_PATH', previousEnv.allowlist],
        ['SSHEPHERD_RECIPE_PATH', previousEnv.recipe],
      ] as const) {
        if (value === undefined) {
          delete process.env[envVar];
        } else {
          process.env[envVar] = value;
        }
      }
    }
  }, 15_000);
});

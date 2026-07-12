# Deploy recipes — TOML format

Deep reference for `src/recipes.ts`, which backs the `deploy` group. A recipe is a
Kamal-style declarative deploy plan: a named, versioned, reviewable sequence of steps —
never a free-text shell string handed to the agent.

## Where a recipe lives

Two-tier lookup, resolved in `resolveRecipePath`:

1. `SSHEPHERD_RECIPE_PATH` env var (tests only — points at one exact file).
2. In-repo `.sshepherd/deploy.<name>.toml` in the current working directory — preferred,
   versioned alongside the project it deploys.
3. `~/.config/sshepherd/recipes/<name>.toml` — a central fallback.

## Top-level fields

```toml
name = "lms-prod"                 # defaults to the lookup name if omitted
alias = "lms-server"              # required — the ssh alias this recipe deploys to
workdir = "/opt/lms"              # required — cwd on the remote for every step
description = "Laravel LMS — code baked into image, migrate needs rebuild"
```

`buildDeployOpContext(recipeName, extraArgs)` loads the recipe fresh and returns
`{ alias: recipe.alias, args: { ...extraArgs, recipe: recipeName } }` — the same shape
every other op's `OpContext` uses, so `deploy` ops need no special-casing anywhere except
at this one resolution point.

## Step kinds

Every `[[step]]` table needs a unique `name` and a `kind`. `depends_on` (optional) names
another step by `name` — see Ordering below.

| `kind` | Required fields | What it becomes |
|---|---|---|
| `shell` | `run` (string), `mutates` (bool, default `true`) | `cd <workdir> && <run>` |
| `compose` | `run` (string) | `cd <workdir> && docker compose <run>` |
| `migrate` | `run` (string) | `cd <workdir> && <run>` (same as `shell`, but selectable alone via `deploy migrate`) |
| `healthcheck` | `target` (container name), `timeout` (e.g. `"60s"`, `"2m"`, default `"30s"`) | polls `docker inspect --format '{{.State.Health.Status}}'` every 2s until `healthy` or timeout |
| `http-probe` | `url`, `expect_status` (default `200`), `retries` (default `3`), `interval` (default `5`, seconds) | polls the URL with `curl` until the expected status or retries exhausted |
| `wait` | `seconds` (must be > 0) | `sleep <seconds>` |

`shell` is the **one named pressure valve for raw shell** in the entire tool — research.md
calls it out explicitly: "raw shell allowed only inside a declared, named, versioned
recipe step." A `shell`/`compose`/`migrate` step's `run` value is embedded into the remote
script **verbatim, not `shq`-quoted** — deliberately, because a step legitimately contains
shell syntax (`&&`, flags, redirects). Everything else in a recipe (`workdir`, URLs,
targets) is still routed through `shq`/`shellJoin` like every other op in the registry.
Only put a `run` value in a recipe you'd trust to run unattended — there is no sandboxing.

`shell.mutates` defaults to `true` (assume mutating unless told otherwise);
`compose`/`migrate` are always treated as mutating; `healthcheck`/`http-probe`/`wait` never
mutate. This drives the `mutates` field in a `--dry-run` plan (see below) — it's advisory
information for the plan, not an enforcement mechanism (the whole `deploy run` is already
gated behind one `--yes`, per-step).

## Ordering — `depends_on`, not file order

`resolveStepOrder` is a declared-order-preserving topological sort: a step with
`depends_on` is placed immediately after its dependency resolves; independent steps keep
their file order otherwise. This is the direct fix for the real-world LMS gotcha
("migrations need a rebuild, not just artisan migrate") — a `migrate` step can be
*declared* early in the file (for readability) while still *running* after `up`:

```toml
[[step]]
name = "pull-code"
kind = "shell"
run = "git pull --ff-only"

[[step]]
name = "build-image"
kind = "compose"
run = "build app"

[[step]]
name = "migrate"                  # declared here...
kind = "migrate"
run = "docker compose run --rm app php artisan migrate --force"
depends_on = "up"                 # ...but always runs after "up" resolves

[[step]]
name = "up"
kind = "compose"
run = "up -d"

[[step]]
name = "verify"
kind = "healthcheck"
target = "app"
timeout = "60s"
```

Resolved order for the recipe above: `pull-code`, `build-image`, `up`, `migrate`,
`verify` — exactly what a hand-ordered file would produce, derived from data instead of
having to be re-typed in the right order every time.

An unknown `depends_on` target, or a dependency cycle, is a load error (`loadRecipe`
throws) — the sort never silently drops or guesses an order. A duplicate step `name` in
the same recipe is also a load error.

## `[rollback]`

```toml
[rollback]
strategy = "previous-tag"         # or "compose-file"
tag = "v1.2.2"                    # required for "previous-tag"
# file = "docker-compose.prev.yml"  # required for "compose-file" instead
```

`deploy rollback` **refuses outright** when a recipe declares no `[rollback]` block —
`buildRollbackCommand` throws rather than inferring anything. This is deliberate: a
guessed rollback on a production deploy is worse than no rollback command at all.

- `previous-tag` runs `cd <workdir> && IMAGE_TAG=<tag> docker compose up -d`.
- `compose-file` runs `cd <workdir> && docker compose -f <file> up -d`.

## `--dry-run` — the plan shape

`deploy run <recipe> --dry-run` executes nothing and needs no `--yes` (the confirm gate is
exempted specifically for dry-run in `executeOp`) — it calls `planRecipe(recipe)` locally
and returns the fully resolved plan as the envelope's `data`:

```json
{
  "recipe": "demo",
  "alias": "lms-server",
  "workdir": "/opt/lms",
  "steps": [
    {
      "name": "pull-code",
      "kind": "shell",
      "mutates": true,
      "depends_on": null,
      "remote_command": "'sh' '-c' 'cd '\\''/opt/lms'\\'' && git pull --ff-only'"
    }
  ]
}
```

Every step lists its resolved position, kind, whether it mutates, its `depends_on` (or
`null`), and the **exact** remote command that would run — read this before ever running
the real thing against a production recipe.

## Failure attribution — `failed_step`

`buildRunScript` wraps every step so a non-zero exit echoes a parseable marker
(`STEP_FAILURE_MARKER <index> <kind> <name>`) to **stdout** (never stderr — the transport
discards stderr entirely) before aborting the `&&` chain. `parseFailedStepMarker` recovers
that marker from `RawResult.stdout` on the failure path, and `deployRun`/`deployMigrate`
wire it as `shapeError`, so a `COMMAND_FAILED` envelope from `deploy run`/`deploy migrate`
carries:

```json
{ "failed_step": { "index": 2, "kind": "migrate", "name": "migrate" } }
```

Never guess which step broke from the raw combined output alone — read `data.failed_step`
first.

## `deploy migrate`

Runs **only** the `migrate`-kind steps of a recipe, in their already-resolved order — this
is what makes "migrations need a rebuild first" actually safe to automate: `deploy migrate`
on the recipe above still runs after `up` because the dependency order was resolved once,
at load time, and both `deploy run` and `deploy migrate` reuse it. A recipe with zero
`migrate` steps makes `deploy migrate` refuse (`buildMigrateScript` throws).

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
name = "myapp-prod"                 # defaults to the lookup name if omitted
alias = "web-01"              # required — the ssh alias this recipe deploys to
workdir = "/opt/myapp"              # required — cwd on the remote for every step
description = "Laravel app — code baked into image, migrate needs rebuild"
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
their file order otherwise. This is the direct fix for a real-world gotcha
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
  "alias": "web-01",
  "workdir": "/opt/myapp",
  "steps": [
    {
      "name": "pull-code",
      "kind": "shell",
      "mutates": true,
      "depends_on": null,
      "remote_command": "'sh' '-c' 'cd '\\''/opt/myapp'\\'' && git pull --ff-only'"
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

## `--timeout` — overriding the whole-recipe budget

`deploy run`/`deploy migrate` default to a 300s whole-recipe timeout (`DEPLOY_TIMEOUT_SEC`
in `src/registry.ts`), wrapped as a remote `timeout <N> --kill-after=10 <script>`. That
budget covers **the entire recipe**, not per-step — a multi-step recipe with one slow
statement (a big migration, a slow build) can eat the whole thing on that one step. When a
step is known to be slow ahead of time, pass `--timeout <seconds>` to raise the ceiling
(clamped to 3600s) instead of retrying the same fixed budget blind:

```bash
sshepherd deploy run big-migration --timeout 900 --yes
```

A `SSH_TRANSPORT_ERROR`/`COMMAND_TIMEOUT` on a `deploy run` carries **zero signal** about
how close the step was to finishing — treat it as "raise `--timeout` and look at what's
actually happening server-side," not as "the recipe is broken."

## Idle-connection drops (`SSH_TRANSPORT_ERROR` around ~140s) and orphaned remote processes

Two related gotchas, both caused real incidents before the fix:

**Idle timeout.** A long remote command that produces no stdout/stderr for minutes (a quiet
SQL `DELETE`, a slow build with no output) can look "idle" to network middleboxes (cloud
NAT gateways, load balancers, stateful firewalls — commonly a 120–150s idle window) even
though it's actively working. The middlebox silently drops the TCP session; `ssh` then
exits 255 with no useful stderr, which `classify()` reports as a generic
`SSH_TRANSPORT_ERROR` that has nothing to do with any timeout sshepherd itself set. Fixed
as of the version that added `ServerAliveInterval=15`/`ServerAliveCountMax=4` to the
ControlMaster — a keepalive every 15s (60s tolerance) keeps the session looking active
through a genuinely long, quiet command. If you still see this on an older build, that's
the missing keepalive, not a real network fault.

**A client-side timeout does not stop the remote process.** GNU `timeout <N> <cmd>` with no
escalation sends one SIGTERM to its direct child and gives up if that child (or something
inside it) ignores the signal. Critically: **`docker exec` does not forward signals into
the exec'd process inside the container** under sshepherd's non-tty invocation — a step
like `docker exec postgres psql -c "<slow DELETE>"` wrapped in `timeout 300 ...` can hit
the 300s wall, sshepherd reports `COMMAND_TIMEOUT`/exit 124, and the `psql` statement
**keeps running inside the container regardless**, fully unaware anything timed out.
`--kill-after=10` (added alongside the fix above) guarantees the *local* `ssh`/`sh`/`timeout`
process tree actually dies, but it structurally cannot reach a process already running
inside a container's own namespace.

**What this means in practice:**
- Before retrying a `deploy run`/`deploy migrate` that just failed with a timeout-shaped
  error, check server-side for an orphaned process (e.g. `SELECT pid, query, now()-query_start
  FROM pg_stat_activity WHERE state != 'idle'` for a DB step) before running the recipe
  again — retrying blind piles up multiple orphaned attempts all competing for the same
  I/O, which makes the *next* attempt slower too, not faster.
- For a recipe step that runs something genuinely long and quiet inside a container, set a
  server-side timeout of its own (e.g. `SET statement_timeout = '120s'` before the SQL, or
  an application-level cancellation) — don't rely on sshepherd's wrapper to reach inside the
  container, because it can't.
- If a step really did just need more time and isn't stuck, `--timeout <seconds>` (above) is
  the fix, not a retry loop.

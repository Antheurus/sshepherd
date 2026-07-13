---
feature: setup-command-group
created: 2026-07-13
updated: 2026-07-13T05:40Z
status: ready-for-plan
---

# Research — setup command group

## Definition of done

> "the whole point of /sshepherd was so the agent DOESN'T handle credentials directly... we need a CLI version so humans can do this stuff themselves, like `sshepherd auth`"
> — user, 2026-07-13

Scope confirmed via two follow-up clarifications:
- "Scope: SSH auth only, or a broader unified `setup` group covering targets.toml / config-allowlist.toml / deploy-recipe scaffolding too?" → **"Satu setup group buat semua 4"** (one setup group for all 4).
- "`setup ssh-alias` — does it need to install a public key on the remote (needs one interactive password), or just write the local `~/.ssh/config` stanza?" → **"Cukup local write doang"** (local write only — this is the actual incident that started the request; no remote install needed).
- "Return shape for setup's local-only commands — reuse `Envelope<T>` with an empty `alias`, or a dedicated shape?" → **"Shape baru, lebih pas"** (a new, dedicated shape).

Done when: a human can run `sshepherd setup ssh-alias register/keygen/remove`, `sshepherd setup db-target`, `sshepherd setup config-allowlist`, and `sshepherd setup deploy-recipe` entirely from their own terminal to bootstrap every sshepherd config surface — without the AI agent ever hand-parsing a `.env` file or hand-editing `~/.ssh/config` again (real incident: an agent using sshepherd on 2026-07-11/12 had no way to register a new SSH alias except reading raw credentials out of a project's `.env` and writing `~/.ssh/config` directly, defeating the tool's zero-knowledge design). `SKILL.md` documents `setup` as human-only, agent-forbidden, so no future agent session ever invokes it either.

## Verbatim captures

### `references/transport.md:105-114` — the alias-only hygiene rule (governs the sign-off question)

```
## The alias-only hygiene rule

Nothing in this codebase ever holds a hostname, IP, username, or port in a variable that
escapes the transport layer — not a log line, not an error message, not a field on the
`Envelope`. The only identity string that crosses the boundary back to a caller is the
alias itself, which the caller supplied in the first place. If a future change needs to
surface any connection detail (a resolved IP for a status page, say), that is a deliberate
architecture change requiring explicit sign-off — not an incremental addition, because it
breaks the zero-knowledge guarantee this whole transport layer exists to provide.
```

Scope note (validated by context-gatherer): this rule guards *outbound* leakage of connection details back to a caller (the agent). `setup` writes connection details *forward*, into local config files, and never returns them to any caller — a different direction than what this rule literally guards. The rule is still the reason this feature needs explicit user sign-off (which was obtained via the two clarifications above), but it is not being violated by `setup`'s existence.

### `CONTRIBUTING.md:38-41` — the "one array entry" rule this feature deliberately does NOT follow

```
`src/registry.ts` — every op as data: group, action, args, whether it mutates, how its
remote command is built, how its output is parsed and shaped. Adding an op is one array
entry here, dispatched through `executeOp` — never a new bespoke execution path or an
if/elif chain in the CLI.
```

This rule governs the 9 *existing* groups, all of which share one property: they resolve an ssh alias and (usually) open a connection. `setup` structurally cannot follow this rule — see Code intelligence, `runLocal` signature — and needs its own execution path, not a `REGISTRY` entry.

### `src/types.ts:66-70,87` — why `OpSpec.runLocal` cannot express `setup`

```ts
// buildRemote returns null for the handful of host-local ops (e.g. `hosts list`) that
// never open an ssh connection; those ops must supply `runLocal` instead.
...
runLocal?: (ctx: OpContext, sshConfigPath: string) => T;
```

`runLocal` is **synchronous** and returns a plain `T` (not `Promise<T>`); `executeOp` (`registry.ts:2140-2146`) calls it with no `await` and forces the result through `buildEnvelope({alias: ctx.alias, ...})`. `setup` needs async subprocess spawns (`ssh-keygen`) and requires no pre-existing alias/`OpContext` (registering an alias is what CREATES it) — neither fits.

### `src/audit.ts` — full file (47 lines), the reusable primitive

```ts
import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const DEFAULT_LOG_PATH = join(homedir(), '.local', 'state', 'sshepherd', 'audit.jsonl');

export interface AuditEntryInput {
  alias: string;
  command: string;
  argsSummary: Record<string, string>;
  outcome: 'ok' | 'error' | 'refused';
}

export interface AuditDeps {
  logPath?: string;
}

export function auditMutating(input: AuditEntryInput, deps: AuditDeps = {}): void {
  const logPath = deps.logPath ?? DEFAULT_LOG_PATH;
  const dir = join(logPath, '..');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const argsHash = Bun.hash.crc32(
    JSON.stringify(Object.keys(input.argsSummary).sort().map((k) => [k, input.argsSummary[k]]))
  ).toString(16);
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    alias: input.alias,
    command: input.command,
    args_hash: argsHash,
    outcome: input.outcome,
  });
  appendFileSync(logPath, line + '\n', { mode: 0o600 });
}

export function confirmGate(input: { mutating: boolean; yes: boolean }): boolean {
  return !input.mutating || input.yes;
}
```

(Reconstructed from context-gatherer's line-cited read of `src/audit.ts:1-46`; imports confirmed as `node:fs`/`node:os`/`node:path` only — zero `Envelope`/`OpSpec` coupling.)

### `targets.example.toml` — full contents (the template pattern to imitate)

```toml
# Example sshepherd `db` group targets — copy to ~/.config/sshepherd/targets.toml and
# fill in real values. Each `[<name>]` table is a `<pg-target>`: the `db` group's
# equivalent of an SSH alias, so the agent invoking `db <op> <target>` never sees or
# passes a database password.
#
# Password handling — read this before wiring a real target:
#   sshepherd never transports a database password. `docker exec`/`docker compose exec`
#   reaches psql INSIDE the container, so auth is whatever that container/psql already
#   trusts: Postgres `peer`/`trust` auth for the exec'd user, or a `~/.pgpass` file that
#   already exists on the remote host (in the container image or a mounted volume) that
#   psql reads on its own. If neither is set up, `psql` will prompt for a password and
#   the non-interactive `-c` invocation will simply fail — configure peer/trust or
#   `.pgpass` on the target before declaring it here.
#
# Read-only enforcement — three layers, only the first is YOUR responsibility:
#   1. Read-only DB role (recommended, engine-side boundary): the `user` below should be
#      a role with SELECT-only grants, e.g.
#        CREATE ROLE sshepherd_ro WITH LOGIN;
#        GRANT pg_read_all_data TO sshepherd_ro;            -- PG14+
#        ALTER ROLE sshepherd_ro SET default_transaction_read_only = on;
#      This is the real boundary — it catches writable CTEs and volatile functions that
#      no client-side parser can reliably detect.
#   2. sshepherd wraps every query in `BEGIN TRANSACTION READ ONLY; ...; ROLLBACK;`
#      (defense in depth, not a substitute for #1 — a session can revoke read-only on
#      itself).
#   3. sshepherd rejects an obviously non-SELECT statement (INSERT/UPDATE/DELETE/DDL)
#      locally before ever opening an ssh connection (UX guardrail only).

# Compose-hosted Postgres — `docker compose -f <compose_file> exec -T <service> psql ...`
[prod]
alias = "lms-server"                        # ssh alias this pg-target rides on
compose_file = "/opt/lms/docker-compose.yml" # path to the compose file ON THE REMOTE
service = "db"                               # compose service name for the db container
user = "sshepherd_ro"                        # read-only role (see above)
database = "lms"

# Plain-container Postgres — `docker exec -i <container> psql ...`
[staging]
alias = "staging-1"
container = "staging_postgres_1"             # container name or ID ON THE REMOTE
user = "sshepherd_ro"
database = "app"
```

### `src/parsers/ssh-config.ts` — full file (50 lines), confirms marker-comment safety

```ts
import { readFileSync } from 'node:fs';

const HOST_LINE_PATTERN = /^Host\s+(.+)$/i;

function isWildcardPattern(token: string): boolean {
  return token.includes('*') || token.includes('?');
}

export function parseSshConfigAliases(configText: string): string[] {
  const aliases: string[] = [];
  for (const rawLine of configText.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const match = HOST_LINE_PATTERN.exec(line);
    if (!match) continue;
    const patterns = match[1]?.trim().split(/\s+/) ?? [];
    for (const pattern of patterns) {
      if (!isWildcardPattern(pattern)) aliases.push(pattern);
    }
  }
  return aliases;
}

export function listHostAliases(configPath: string): string[] {
  let text: string;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch {
    return [];
  }
  return parseSshConfigAliases(text);
}
```

Line 22 (`if (line.startsWith('#')) continue`) guarantees any `# sshepherd-managed: <alias>` marker line is skipped by alias enumeration — safe to use as the managed-stanza marker.

### `SKILL.md:172-203` — existing Gotchas section (style to match for gotcha #9)

```
## Gotchas

1. **Zero-knowledge is not optional per-call.** ...
2. **Every mutating op needs `--yes`, always writes an audit line.** sshepherd never
   prompts interactively (agent-first design) — without `--yes` a mutating op returns a
   `CONFIRMATION_REQUIRED` envelope and refuses before touching ssh. ...
3. **No raw exec, ever.** There is no `sshepherd exec "<any command>"`. ... `plain ssh
   <alias>` remains the intentional human break-glass for one-off exploration.
4. **`deploy rollback` refuses without a `[rollback]` block.** ...
5. **`config put` backs up before writing, always.** ...
6. **`db` is Postgres-only, read-only, v1.** ...
7. **A deploy failure names the step that failed.** ...
8. **`security harden` won't lock out the current session unless told to.** ...
```

## Code intelligence

- `src/cli.ts:17` — `GROUPS = [...new Set(listOps().map(op => op.group))]`, derived from `REGISTRY`. A non-registry `setup` group will NOT appear here automatically — must be special-cased.
- `src/cli.ts:228-281` — `run(argv)`: group validated against `GROUPS` at `:239-242`. **Interception point**: `setup` must be checked and dispatched to a parallel path BEFORE this line, or it 404s as "unknown group."
- `src/cli.ts:123-157` — `buildOpContext()`, the per-group first-positional special-casing (`hosts list`/`db list` → local; `db`/`deploy` → resolve via `targets.ts`/`recipes.ts`; else → ssh alias). `setup` does not build an `OpContext` at all.
- `src/cli.ts:198-224` — `formatTopHelp`/`formatGroupHelp`, both 100% `listOps()`-derived. `setup --help` needs its own render function; `formatGroupHelp('setup')` would throw (filters `listOps()`, throws on empty match, `cli.ts:216`).
- `src/registry.ts:2110-2168` — `executeOp`, the single mutating-gate/audit/dispatch path for the 9 existing groups. `setup` does not go through this.
- `src/registry.ts:114-125` — `hostsList`, the canonical local-only-op precedent (`buildRemote: () => null`, `runLocal` reads `~/.ssh/config`). Confirms local-only ops are an established pattern in spirit, even though `setup`'s specific needs (async, no pre-existing alias) don't fit the `OpSpec.runLocal` signature.
- `src/targets.ts:24-30,32-66,69-82` — `defaultTargetsPath()` (`~/.config/sshepherd/targets.toml`, override `SSHEPHERD_TARGETS_PATH`), `readTarget` schema validation (`alias`+`user`+`database` required, exactly one of `{compose_file+service}` or `{container}`), `loadTargets` (`Bun.TOML.parse`, missing file → `{}`).
- `src/registry.ts:1192-1225` — config-allowlist: `defaultConfigAllowlistPath()` (`~/.config/sshepherd/config-allowlist.toml`, override `SSHEPHERD_CONFIG_ALLOWLIST_PATH`), schema `[<alias>]` → `paths: string[]`, `assertConfigPathAllowed`. **No example/template file exists for this one** (confirmed absent).
- `src/recipes.ts:99-109,144-226,447-485` — recipe path resolution (`SSHEPHERD_RECIPE_PATH` → `./.sshepherd/deploy.<name>.toml` → `~/.config/sshepherd/recipes/<name>.toml`), step schema (6 kinds), optional `[rollback]` block, `Bun.TOML.parse`. Fixtures: `src/__tests__/fixtures/deploy.{demo,no-rollback}.toml`.
- `src/audit.ts` (full, quoted above) — `auditMutating`/`confirmGate`, zero `Envelope`/`OpSpec` imports, directly reusable by `setup`.
- `src/transport.ts:115` and `src/audit.ts:32,40` — existing local-write precedent (`mkdirSync(dir, {mode:0o700})` + file writes at `0o600`) to model `setup`'s config writers on, using plain `node:fs` sync APIs — not `Bun.write`.
- Repo-wide grep (independently re-verified by context-gatherer): zero hits for `Bun.serve`, `Bun.password`, `readline`, `process.stdin`, `setRawMode`, `ssh-copy-id` anywhere in `src/`, `references/`, `README.md`, `docs/`. Moot now — the approved scope (local file writes only) needs none of these.
- `README.md:129-132` — "The only runtime dependency is `node-sql-parser`... no other npm package runs at runtime." `setup` introduces zero new runtime code paths beyond `node:fs`/`node:child_process` (for `ssh-keygen`), both already used elsewhere (`node:fs` throughout, `Bun.spawn` in `transport.ts`) — no new dependency.
- `references/output-shapes.md:14-23` — `Envelope<T>` requires a non-optional `alias: string` field; confirmed awkward fit for a command with no alias, which is why the user chose a dedicated shape.
- `package.json:3` — version `0.1.0`. `docs/changelog.md` — one entry so far (`## v0.1.0`).
- `SKILL.md` — 166 lines, hardcodes "9 command groups" (`:3,68`) and "52 ops" (`:97`) in three places; needs bumping. Quick-reference block pattern per group at `:99-169`.

## Risks & unknowns

- The exact `~/.ssh/config` marker-comment string is a fresh design choice (no in-repo precedent to copy) — proposed in the plan, not yet user-confirmed word-for-word.
- `config-allowlist.toml` has no example/template file to base the scaffold's exact formatting/comment style on (unlike `targets.toml`) — the writer will generate from the in-code schema (`registry.ts:1211-1213`) directly.
- Default write location for `setup deploy-recipe` (global `~/.config/sshepherd/recipes/<name>.toml` vs cwd-local `./.sshepherd/deploy.<name>.toml`) — plan proposes global, since `setup` is an onboarding/bootstrap surface, not a per-project override; flagged as an assumption, not blocking.
- `setup ssh-alias keygen` needs to decide passphrase policy for the generated key. Proposed: passphrase-less (`ssh-keygen -N ""`), matching the manual pattern already used earlier in this session for the same real-world use case (aliases need to authenticate non-interactively when used by sshepherd's own ops). Flagged as an assumption.
- Whether `setup`'s mutating actions should require `--yes` like the other 9 groups. Proposed: yes, for consistency of mental model (documented as a cross-phase guideline), even though `setup` is never agent-invoked. Flagged as an assumption.

## Open questions

- [BLOCKING — resolved via AskUserQuestion 2026-07-13] `setup ssh-alias` scope: local `~/.ssh/config` write only (confirmed) vs. also remote key install (rejected). No further ambiguity.
- [BLOCKING — resolved via AskUserQuestion 2026-07-13] Return shape: dedicated `SetupResult<T>`, not `Envelope<T>` (confirmed).
- Marker-comment exact string — non-blocking, proposed in plan, cosmetic if the user wants a different format later.
- `--yes` requirement for setup mutations — non-blocking, proposed in plan as "yes, for consistency."

## Reference artifacts

- Prior plan for this same repo: `docs/plan/2026-07-12-sshepherd-v1/{research,plan,handover}.md` — v1 shipped the 9 existing groups; confirms this repo's own established plan/research doc convention, followed here.

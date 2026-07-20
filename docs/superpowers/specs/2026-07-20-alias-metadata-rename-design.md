# Alias metadata (desc/tags/network) + alias rename

## Why

Every ssh alias in `~/.ssh/config` today carries a bare name and nothing else. Two problems
fall out of that:

1. **The name is the only place project/ownership context can live, so it gets overloaded.**
   `otofiliate-vps` hosts both `/opt/otofiliate` and `/opt/mendadak-tools` (per
   `files-allowlist.toml`), but its name only mentions one. Worse, the underlying Tailscale
   device is actually named `otomasiaja-server3` — the alias doesn't even match the real
   infra identity it points at. An agent (or a human) reading the alias name alone draws the
   wrong conclusion about what's on the box and what it's called upstream.
2. **Nothing records how a box is reached.** Some aliases resolve to addresses in Tailscale's
   `100.64.0.0/10` CGNAT range, others to plain LAN `10.x` addresses — with no record of
   which. An agent driving `sshepherd` has no way to know, before it tries a connection,
   whether it needs a VPN client up first, and has been getting stuck re-discovering this
   every time.

This adds two things: per-alias metadata (`desc`, `tags`, `network`) so an alias carries
real context instead of just a name, and an alias `rename` action so a name that's already
wrong (like `otofiliate-vps`) can be corrected without breaking every file that references it.

## Storage & schema

A new file, `~/.config/sshepherd/alias-meta.toml`, follows the exact convention already used
by `targets.toml` / `config-allowlist.toml` / `files-allowlist.toml` / `reveal-allowlist.toml`:
one `[<alias>]` table per alias, loaded by a `defaultAliasMetaPath()` + `loadAliasMeta()` pair
in a new `alias-meta.ts` (mirrors `targets.ts`), written by a new `setup-alias-meta.ts`
(mirrors `setup-db-target.ts`).

```toml
[otomasiaja-server3]
desc = "VPS in the 'Otomasi Aja' Tailscale tailnet (real device name: otomasiaja-server3); hosts otofiliate and mendadak-tools via Docker Compose under /opt."
tags = ["otofiliate", "mendadak-tools"]
network = "tailscale"
```

- `desc` — free text, one string. Validated at write time against
  `REVEAL_DENYLIST_PATTERNS` (already defined in `registry.ts` for `reveal-allowlist`'s
  secret-pattern gate) — reused, not duplicated. A `desc` containing `PASSWORD`, `SECRET`,
  `TOKEN`, `PRIVATE_KEY`, `CREDENTIAL`, `API_KEY`, etc. is refused with `VALIDATION_ERROR`,
  same failure shape `setup reveal-allowlist scaffold` already uses for a denylisted key.
- `tags` — string array, free-form (project names, ownership, whatever groups aliases
  meaningfully). No dedup/validation beyond "array of non-empty strings."
- `network` — closed enum: `tailscale | netbird | wireguard | lan | direct | other`.
  Rejected with `VALIDATION_ERROR` if the value isn't one of these. `other` covers anything
  not yet named rather than silently accepting typos.

All three fields are optional independently — an alias can have `network` set without `desc`,
etc. A `[<alias>]` table with no matching `~/.ssh/config` `Host` is not an error at load time
(same "load what's there" tolerance `targets.ts` already has); it only becomes reachable once
a real alias with that name exists.

## CLI surface

No new sub-group. `setup ssh-alias update` (already the action that rewrites an alias's
`HostName`/`User`/`Port`) gains three more optional flags:

```
sshepherd setup ssh-alias update otomasiaja-server3 \
  --desc "VPS in the 'Otomasi Aja' Tailscale tailnet..." \
  --tags otofiliate,mendadak-tools \
  --network tailscale \
  --yes
```

`update()` in `setup-ssh-alias.ts` keeps writing host/user/port into the `~/.ssh/config`
stanza exactly as it does today; when any of `--desc`/`--tags`/`--network` is present, it also
calls into `setup-alias-meta.ts`'s writer for that alias. The existing rule "at least one of
the recognized flags is required" extends to include the three new ones — `update` with zero
flags at all stays a `VALIDATION_ERROR`.

## Exposure to the agent

Two surfaces, matching the two existing places alias info already shows up:

- **`hosts list`** (registry op, host-local, the first thing an agent reaches for to
  orient). `HostsListResult.aliases` changes shape from `string[]` to
  `Array<{ name: string; desc: string | null; tags: string[]; network: string | null }>`.
  This is a breaking shape change to that one op's `data`, accepted because the project is
  pre-1.0 (`0.2.x`) and this is exactly the call an agent makes before doing anything else —
  putting the context there directly is the fix for "sshepherd keeps forgetting and going in
  circles."
- **`setup ssh-alias status <alias>`** — already documented as the one narrow exception that
  echoes `host`/`user`/`port`/`hasKey` for a single alias (SKILL.md, "zero-knowledge model").
  `desc`/`tags`/`network` are added to that same response for a one-alias deep-dive.

Neither surface introduces a new exception to the zero-knowledge boundary: `desc`/`tags`/
`network` never contain `HostName`/`User`/`Port`/`IdentityFile` by construction (closed enum
+ denylist-checked free text), so this doesn't weaken the "no host/user/port/ip in any
response" invariant `types.ts`/`SKILL.md` document.

## Rename

New action: `setup ssh-alias rename <old> <new>`, alongside the existing
`register/keygen/install/status/update/remove/list`.

**Cascade scope.** A rename touches every place `sshepherd` itself owns and can safely
rewrite mechanically:

1. `~/.ssh/config` — the `# sshepherd-managed: <old>` marker line and `Host <old>` line,
   rewritten to `<new>`.
2. The physical key file, **only if** its `IdentityFile` matches the
   `sshepherd_<old>_ed25519` naming convention `keyPathFor()` already generates (i.e., a key
   `sshepherd` itself created via `keygen`) — renamed to `sshepherd_<new>_ed25519` and the
   stanza's `IdentityFile` line updated to match. A manually supplied `IdentityFile` that
   doesn't match this pattern is left untouched.
3. `targets.toml` — every `[<name>]` table whose `alias = "<old>"` field is rewritten to
   `alias = "<new>"`. The target's own `[<name>]` table name is unrelated to the ssh alias
   and is never touched.
4. `config-allowlist.toml`, `files-allowlist.toml`, `reveal-allowlist.toml`,
   `alias-meta.toml` — each has a `[<old>]` table keyed directly by alias name, rewritten to
   `[<new>]`. An alias with no table in a given file (it was never scaffolded/set there) is a
   no-op for that file, not an error — `rename` only rewrites tables that exist.

This list is driven by one small data table, `ALIAS_REFERENCE_SOURCES` (new, in
`setup-ssh-alias.ts` or a sibling module), not an if/else chain — each entry names a file, how
to find its alias references, and how to rewrite them. Adding a future alias-keyed file means
adding one entry, not touching `rename`'s control flow (same registry-over-branching shape the
rest of the codebase already follows for `SETUP_SUB_GROUPS`/`REGISTRY`).

**Recipes are excluded from the cascade.** A recipe TOML's `alias = "<old>"` field is one
property among several on an artifact that has its own identity (its own filename, its own
`name` field) — rewriting inside it silently reaches beyond what a rename should touch.
Instead, `rename` scans `~/.config/sshepherd/recipes/*.toml` for `alias = "<old>"` and, if any
match, still completes the rename but returns a **warning** in its result data listing the
recipe file paths that still reference the old name, so they can be fixed by hand (a recipe's
own `alias` field is just `setup deploy-recipe`'s territory, edited directly).

**Safety.** Same gates every other mutating `setup` action already has: refuses without
`--yes` (`confirmGate`), writes one `auditMutating` line, refuses with `ALIAS_NOT_FOUND` if
`<old>` has no managed stanza, refuses with `ALIAS_EXISTS` if `<new>` already has one. All
file rewrites happen after every precondition check has passed — no partial rename left behind
because a later file failed a check the first file would also have failed.

## First real-world use

This design gets applied immediately to the one alias that motivated it:

```
sshepherd setup ssh-alias rename otofiliate-vps otomasiaja-server3 --yes
sshepherd setup ssh-alias update otomasiaja-server3 \
  --desc "VPS in the 'Otomasi Aja' Tailscale tailnet (real device name: otomasiaja-server3); hosts otofiliate and mendadak-tools via Docker Compose under /opt." \
  --tags otofiliate,mendadak-tools \
  --network tailscale \
  --yes
```

`otomasiaja-server2` (100.103.182.84) already matches its real Tailscale device name and
needs no rename — only a `desc`/`tags`/`network` pass once `update` supports the new flags.
`module-brighty-prod`/`module-brighty-db` live in a separate Tailscale tailnet that hasn't
been cross-checked and are explicitly out of scope for this pass.

## Testing

- `alias-meta.ts` — load/parse tests mirroring `targets.test.ts` (missing file → `{}`,
  malformed table → thrown error with the same message shape).
- `setup-alias-meta.ts` — scaffold/update tests mirroring `setup-reveal-allowlist.test.ts`:
  denylisted `desc` refused, invalid `network` enum value refused, valid write round-trips
  through `loadAliasMeta`.
- `setup-ssh-alias.ts` `update` — new flags tested alongside existing host/user/port cases;
  zero-flags-at-all still refused.
- `setup-ssh-alias.ts` `rename` — happy path (all reference files rewritten), key-file rename
  only when the naming convention matches, recipe-reference warning surfaced without recipe
  content changing, `ALIAS_NOT_FOUND`/`ALIAS_EXISTS`/missing `--yes` refusals.
- `hosts list` / `setup ssh-alias status` — shape tests asserting the new fields appear and
  are `null`/`[]` when no `alias-meta.toml` entry exists for that alias.
- `SKILL.md` — the zero-knowledge model section and the `ssh-alias` action list both need
  updating; `skill-doc.test.ts` (which asserts documented action counts against
  `SETUP_SUB_GROUPS`) needs its `ssh-alias` actions list extended with `rename`.

# sshepherd Progress

## Session — 2026-07-16 — v0.2.2 (files-allowlist + reveal-allowlist, registry-driven allowlist enforcement)

Closed two real security gaps flagged by CodeRabbit during an external code-review pass on
a PR that copied sshepherd's SKILL.md into rohitg00/awesome-claude-code-toolkit: `files
download`/`upload` (and, by extension, `ls`/`cat`/`tail`/`disk-usage`) had no allowlist at
all — any remote path could be read or written, unlike `config get`/`put`, which already
refuse an undeclared path via `config-allowlist.toml` — and `files cat --reveal` could
unmask any key name the agent typed, including a genuinely secret one (`DB_PASSWORD`,
`AWS_SECRET_ACCESS_KEY`), since masking only checked whether a key was in the requested
`--reveal` list, never whether the key itself looked like a secret. Fixed both by
generalizing the allowlist mechanism instead of adding two more copy-pasted per-op checks:
added a declarative `allowlist?: AllowlistPolicy[]` field to `OpSpec` (`src/types.ts`) and
moved enforcement into one place, `enforceAllowlist()` called from `executeOp()` in
`registry.ts` right before `buildRemote` runs — the same "one gate, not per-op bespoke
logic" pattern the file already used for `confirmGate`. `config get`/`validate`/`put`
migrated to the same declarative mechanism (their inline `assertConfigPathAllowed` calls
are gone, replaced by an `allowlist` field); the six `files` ops gained `files-allowlist.toml`
gating (same TOML shape and fail-closed rule as `config-allowlist.toml` — missing file
refuses everything); `files cat --reveal` gained a second gate, a hardcoded
non-overridable secret-pattern denylist (`PASSWORD`, `SECRET`, `TOKEN`, `PRIVATE_KEY`,
`CREDENTIAL`, `API_KEY`, trailing `_KEY`/`_PASS`) checked before a per-alias
`reveal-allowlist.toml`. New `setup files-allowlist scaffold`/`setup reveal-allowlist
scaffold` sub-groups (mirroring `setup config-allowlist scaffold` — `src/setup-files-allowlist.ts`,
`src/setup-reveal-allowlist.ts`, wired in `src/setup.ts`) write those TOML files; the reveal
scaffolder also refuses at scaffold time if a `--keys` entry matches the denylist, so a
mistaken `DB_PASSWORD` never even makes it into `reveal-allowlist.toml`. This is a breaking
change (`files`/`--reveal` were previously unrestricted) — bumped to v0.2.2 as a
security-hardening fix, pre-1.0 so no deprecation cycle. Updated `SKILL.md` (Gotchas #11,
zero-knowledge model bullets, Quick reference — 9 groups/52 ops unchanged, `setup` now 6
sub-groups/9 actions) and `README.md` (zero-knowledge model section, `setup` group
description) to document the real command surface accurately — the copied SKILL.md in the
rohitg00 PR that triggered this had also drifted to only 39 of the 52 real ops, fixed
separately in that PR's own branch, not this repo. Verified: `just check` clean (0
typecheck/lint errors), `just test` 255/255 passing (added test coverage for files-allowlist
fail-closed behavior, `files upload`'s `remote_path`-not-`local_path` check, the reveal
denylist beating a mistaken allowlist entry, and the reveal-keys policy no-op when
`--reveal` is absent), and `just smoke` 16/16 live E2E checks passing against a real
disposable sshd fixture (added a `setup files-allowlist scaffold` step to the smoke script
before the `files ls` check, using `SSHEPHERD_FILES_ALLOWLIST_PATH` the same way the
existing fixture config uses `SSHEPHERD_TARGETS_PATH`/`SSHEPHERD_RECIPE_PATH`). Merged
directly to `main`.

---

## Session — 2026-07-14 — v0.2.1 (files download no longer inlines raw content)

Fixed a zero-knowledge-breaking bug in `files download` (`src/registry.ts`), found via a
real incident: an agent ran `files download <alias> <remote .env.docker path>
/tmp/dest.tmp`, expecting scp-like behavior (bytes land on local disk, never enter the
agent's context) based on the command's name and the old doc example. The old `filesDownload`
`OpSpec` declared only one positional arg (`<path>`, remote-only) — the local destination the
agent typed was silently discarded by `mapArgsToCtx` (extra positionals beyond an op's
declared `ArgSpec[]` are dropped with no error, not even a usage warning), and `shape()`
returned the entire file as `content_base64` in the `Envelope`'s `data`, which `cli.ts`
prints straight to stdout — i.e. straight into the calling agent's tool-result context, in a
trivially-reversible encoding. Unlike `files cat`, `files download` had never had `.env`
masking applied to it at all, so it leaked a real `.env.docker` (DB passwords, `JWT_SECRET`,
`ACCOUNT_ENC_KEY`, marketplace API secrets) into a transcript. Root cause was twofold: (1) no
local-destination arg existed on the op at all, so there was structurally no way to ask for
scp-like behavior even if the agent had read the (single-positional) example correctly, and
(2) even had it existed, the old design returned content in the JSON response regardless.
Fix: `filesDownload` now takes two required positionals, `<path>` (remote source) and
`<local_path>` (local destination); `shape()` decodes the base64 client-side and
`writeFileSync`s it directly to `local_path`, and the envelope's `data` shape changed to
`{found, truncated, size_bytes, written, local_path}` — `content_base64` no longer exists
anywhere in the type or the runtime output, success or failure. The 10 MiB
`DOWNLOAD_MAX_BYTES` guard is unchanged (still refuses via `truncated: true` above that size,
still no partial write). Updated `SKILL.md`'s quick-reference example and zero-knowledge
bullet list, and added Gotchas #10 documenting the incident and the fixed shape so a future
agent session (or an old pre-fix compiled `dist/sshepherd`) doesn't repeat it. Added three new
`bun test` cases in `src/__tests__/registry.test.ts` (`files download` describe block)
covering the found/not-found/too-large paths, asserting the local file's real bytes on disk
*and* that the serialized envelope JSON never contains the secret plaintext or
`content_base64`. `just check`, `bun test` (243 pass), and `just build` all green. Bumped
`package.json`/`cli.ts` `VERSION` to `0.2.1` (fix-level bump — bug fix, not a new
capability). This is a breaking CLI change for anyone already scripting `files download
<alias> <path>` with only one path arg — it now requires a second, local-destination
positional.

---

## Session — 2026-07-13 (cont) — v0.2.0 (setup command group)

Added `setup`, a tenth, deliberately separate command group that writes sshepherd's own
local config files instead of talking to a remote host — explicitly human-only, never
invoked by an AI agent, and dispatched through its own `runSetup` shell in `src/setup.ts`
rather than the registry-driven `OpSpec`/`executeOp` path the other 9 groups use (there's no
remote command or `Envelope<T>` to build; `SetupResult<T>` is its own return shape). Four
sub-groups: `ssh-alias` (register/keygen/remove a managed `~/.ssh/config` stanza, generating
a passphrase-less ed25519 keypair), `db-target` (scaffold a `[<name>]` table into
`targets.toml`), `config-allowlist` (scaffold/union a `[<alias>]` paths table into
`config-allowlist.toml`), and `deploy-recipe` (scaffold a minimal recipe TOML skeleton).
Each writer refuses loudly rather than guessing — `ALIAS_EXISTS`/`TARGET_EXISTS`/
`RECIPE_EXISTS` on a collision, `PARSE_MISMATCH` when a marker doesn't match the exact shape
`register` itself writes, `CONFIRMATION_REQUIRED` without `--yes` — and every mutating action
goes through the same `confirmGate`/`auditMutating` pair the other 9 groups use. Built across
6 phases plus a docs pass, then closed by a cross-phase audit that found and fixed 6 issues:
(1) CRITICAL — none of the 3 TOML scaffolders escaped `"`/`\` in interpolated values, so a
value like `my"alias` wrote a corrupt file that crashed the *next* `db list`/`deploy run`
with a raw, unhandled `Bun.TOML.parse` stack trace; fixed with a new `src/toml-quote.ts`
(`tomlQuote`), hand-rolled rather than `JSON.stringify` because `JSON.stringify`'s `\t`
escape round-trips incorrectly through `Bun.TOML.parse` (a real Bun parser bug — it comes
back as `\f`), so `tomlQuote` leaves tab literal (valid per the TOML spec) and only escapes
`"`, `\`, and the other control characters; (2) `splitLines`/`joinLines` were duplicated
byte-for-byte between `setup-ssh-alias.ts` and `setup-config-allowlist.ts`, extracted into
`setup-file-io.ts` alongside the other shared write primitives; (3) `runStubAction` in
`setup.ts` was dead code once all 4 sub-groups left stub status, deleted along with its
now-stale doc comments; (4) no test exercised the full cross-sub-command sequence a real
onboarding session runs, added `src/__tests__/setup-integration.test.ts` driving
register→keygen→db-target→config-allowlist→deploy-recipe→remove against one shared temp
environment and asserting later steps see the same alias earlier steps wrote; (5) this
progress log entry itself, previously missing across all 8 commits of the build; (6) `setup
ssh-alias` had no path-override mechanism unlike the other 3 sub-commands, added
`SSHEPHERD_SSH_CONFIG_PATH` (purely additive — the real default `~/.ssh/config` is unchanged
when unset), consistent with `SSHEPHERD_TARGETS_PATH`/`SSHEPHERD_CONFIG_ALLOWLIST_PATH`/
`SSHEPHERD_RECIPE_PATH`. `bun test` 221/221, `tsc --noEmit` and `biome check` both clean.
Version bumped to v0.2.0 (`package.json`, `src/cli.ts`'s `VERSION` const).

---

## Session — 2026-07-13 — v0.1.0 (sshepherd v1 complete)

sshepherd's v1 build finished across 7 orchestrated phases. Phase 1 scaffolded the Bun/TS/
biome/just toolchain mirrored from `anywrite`. Phase 2 built the zero-knowledge transport
core (`src/transport.ts`, `src/output.ts`, `src/audit.ts`) — every op runs through one
`transport.run()` execution path, the `Envelope<T>` type structurally has no host/user/port/
ip field, and ssh's own stderr is discarded entirely (classified into a static error enum
instead) so no allowlist-based redaction can ever leak a hostname. Phase 3 built the
registry-dispatch pattern (`src/registry.ts`) and the read-only groups — `hosts`, `check`,
`logs`, `services` (read side), `files` (read side) — with hand-written and native-JSON
parsers for df/free/uptime/ps/du/ls/ss/dmesg/journalctl/docker inspect-stats-compose-ps.
Phase 4 added the `db` group (Postgres, read-only v1) with three enforcement layers — a
recommended read-only engine role, a `BEGIN TRANSACTION READ ONLY; ...; ROLLBACK;` wrapper
around every query, and a local `node-sql-parser` SELECT-only check — and the phase audit
caught a real security defect: a crafted `db query` payload could close the `json_agg`
wrapper's subquery boundary early and inject a bare `COMMIT` to end the read-only
transaction before an injected write ran; fixed with `assertNoMultiStatementSql`, which
rejects any bare `;` in `db query`'s free-text SQL before parsing, re-verified live. Phase 5
added the mutating groups — `services` (restart/systemctl verbs), `config`, `deploy`
(TOML recipes with typed steps, topological `depends_on` ordering, dry-run planning,
declared `[rollback]` blocks), and `security harden` — behind one shared `confirmGate` +
`auditMutating` gate in `executeOp`, the only exemption being `deploy run --dry-run` (plans
locally, touches no ssh). That phase's audit found a second defect: a deploy step failure
surfaced as a bare `COMMAND_FAILED` with no indication which step broke; fixed by wrapping
each step with a `__SSHEPHERD_STEP_FAILED__ <idx> <kind> <name>` stdout marker surfaced via
a new `OpSpec.shapeError` hook into `data.failed_step`, re-verified live including an
injection-safe marker check. Phase 5B closed a scope gap (the four read-only `security` ops
and `files upload` had never been assigned a phase despite being part of the locked 9-group
set). Phase 6 wrote the real CLI dispatcher (`src/cli.ts`, replacing the Phase 1 placeholder)
and `SKILL.md` at the repo root with `references/{transport,recipes,db,output-shapes}.md`,
plus a bidirectional drift test proving the doc and the registry can't silently diverge.
Phase 7 (this session) is OSS packaging: `README.md` (four install channels — `npx skills
add`, `/plugin marketplace add`, release binaries, `just build` — plus a "What sshepherd
NEVER does" trust section), `SECURITY.md` (threat model + GitHub private vulnerability
reporting), `CONTRIBUTING.md`, `.github/workflows/ci.yml` (typecheck+lint+test+build on
every push/PR), `.github/workflows/release.yml` (cross-compiles darwin-arm64/darwin-x64/
linux-x64/linux-arm64 on tag push, generates SHA-256 checksums per binary, and attests build
provenance via `actions/attest-build-provenance`), `.claude-plugin/{marketplace,plugin}.json`
for `/plugin marketplace add`, and a Docker-based smoke fixture (`scripts/sshd-fixture/` —
an sshd container with docker CLI mounted against the host daemon, a sibling Postgres seeded
with a read-only role, and a sibling app container — plus `scripts/smoke.sh`, wired to `just
smoke`) that spot-checks a representative read-only op per group, a `db` op, and a `deploy
run --dry-run` against a real Linux host. Across the whole build the zero-knowledge
invariant held structurally the entire way — no phase ever added a host/user/port field to
any type, and both audit-found defects were injection/observability bugs in the SQL and
deploy layers, never a credential leak. The suite sits at 160 passing tests (`bun test`),
`just check` (tsc + biome) clean throughout. The one remaining gap, carried forward from
Phase 3 and closed only in shape (not in verification) by this phase: every Linux command
shape in the registry (`docker stats`/`compose ps` field names, `ss -H -tlnp` columns,
`systemctl show` properties, the `db` introspection SQL's column names across PG13/14+) was
authored from docs/man-pages on a macOS dev box, never live-captured — the smoke fixture and
script built this session are complete and correct on inspection, but Docker was not
available at the time of authoring, so `just smoke` had not yet been run. **That gap was
closed in the continuation session below — `just smoke` ran 15/15 green against a live Docker
fixture, so those command shapes are now live-verified, not doc-derived.**

---

## Session — 2026-07-13 (cont) — v0.1.0 (smoke verified live + published)

Closed the one carried verification gap and published. Docker became available, so `just
smoke` was run for real: it built the `scripts/sshd-fixture/` stack (an sshd container with
the docker CLI, a sibling Postgres seeded with a read-only `sshepherd_ro` role, and a sibling
app container), generated an ephemeral ed25519 keypair, temporarily registered a
`sshepherd-smoke` alias in `~/.ssh/config`, and drove the compiled `dist/sshepherd` binary
against the live Linux host — **15/15 checks passed**: `hosts test` (reachable), `check
overview` (dead_end_risk boolean + nproc>0), `services ps` (container list from docker
inspect), `logs docker` (LogsResult shape with next_since), `files ls`, `security listeners`
(sshd's own port 22 present), `db list`/`db tables`/`db query` (the seeded fixture row came
back through the read-only transaction wrapper), and `deploy run --dry-run` (correct plan, no
execution). The fixture torn down cleanly (`docker compose down --volumes`) and the temporary
ssh-config block removed by the exit trap — verified no residue. This promotes every registry
command shape and the db introspection SQL from doc-derived (SHIPPED-UNVERIFIED) to
VERIFIED-LIVE. The repo was then created on GitHub (`Antheurus/sshepherd`, public, MIT) and
pushed; the `v0.1.0` tag was cut to trigger `release.yml` (the 4-platform binary build +
SHA-256 + build-provenance attestation runs on GitHub's runners). Note for a future smoke
pass: the cross-phase auditor flagged that `docker compose ps --format json` on newer compose
can emit a single JSON array rather than NDJSON — `services ps` (which uses `docker ps` +
`docker inspect`, not `compose ps`) passed here, but `deploy status`/`services compose-ps`
specifically weren't in the smoke matrix, so that one parse path is still worth a targeted
check.

---

## Session — 2026-07-12 — v0.1.0 (scaffold)

Repo scaffolded to mirror anywrite's Bun/TypeScript/biome/just toolchain: package.json with build/dev/test/typecheck/lint/check scripts, tsconfig.json in strict mode targeting ESNext, biome.jsonc for lint + format, and a justfile exposing install/build/test/check/smoke/clean recipes as the only command interface. Zero runtime dependencies — only @biomejs/biome, @types/bun, and typescript as devDependencies, per the plan's constraint to keep runtime deps at or under two (Bun.TOML covers config parsing later, no toml package needed; node-sql-parser is deferred to Phase 4). Added a placeholder src/cli.ts that reads a hardcoded VERSION constant and prints it plain or via --version/-v, just enough to give `bun build --compile` a real entry point. `just build` compiles to dist/sshepherd and `just check` (tsc --noEmit + biome check) runs clean. This is Phase 1 of a 7-phase orchestrated build defined in docs/plan/2026-07-12-sshepherd-v1/plan.md; later phases add ops/transport logic and the SKILL.md content, neither of which this phase touches.

---

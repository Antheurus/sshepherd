---
descriptor: 2026-07-12-sshepherd-v1
research_doc: docs/plan/2026-07-12-sshepherd-v1/research.md
created: 2026-07-12
status: planning
plan_confidence: 8/10
execution_readiness: 8/10
risk: medium
isolation: none
---

# sshepherd v1 — Orchestration Plan

## TLDR — North Star

> Build `sshepherd`: a compiled Bun/TypeScript CLI + root `SKILL.md` that runs 9 groups of
> curated, structured-JSON server operations over SSH where the agent passes only an alias
> name and credentials never enter the process (we shell out to system `ssh`, never `ssh2`).
> The governing rule: **zero-knowledge is a hard invariant, not a feature** — every op goes
> through the one transport core that discards ssh transport stderr and echoes only the
> alias, so no phase may ever put a HostName/IP/User/port/key into output. Ship it packaged
> exactly like `anywrite` (public repo, root SKILL.md, release binaries, trust signals).

## Open Questions

**Concerns** — none blocking. (DB `<pg-target>` declaration file, audit-log path, and
per-project alias allowlist are recorded as non-blocking design decisions in research.md
§Open questions; Phase 2 fixes their concrete shapes and the user can redirect at review.)

**Confusions** — none. Name and scope are resolved (user sign-off 2026-07-12).

**Assumptions:**
- v1 targets **Linux** remote servers only (native-JSON flags assume systemd/iproute2/
  util-linux). macOS/BSD remotes are out of scope for v1.
- v1 DB support is **Postgres only**; MySQL deferred.
- Bun's built-in `Bun.TOML` can parse deploy recipes, so the only pure-JS runtime dep is
  `node-sql-parser`. If `Bun.TOML` proves insufficient, add one TOML parser — still ≤2 deps.

## Executive summary

sshepherd solves two linked pains: SSH creds the agent must never see, and remote command
output too messy to reason over. It is a single compiled binary (no runtime install, like
anywrite) wired as a Claude Code skill. The agent invokes `sshepherd <group> <action>
<alias> [flags]`; the CLI resolves the alias through `~/.ssh/config` + ssh-agent entirely
inside OpenSSH, runs a curated remote command from a central ops registry, and returns one
JSON envelope with bytes-not-strings and computed verdict fields. There is no raw-exec
escape hatch — novel needs are authored as named, typed deploy-recipe steps; plain `ssh`
stays the human break-glass. It ships open-source packaged for `npx skills add` discovery
with the full post-ToxicSkills trust-signal set.

## 5W+1H

- **What:** Bun/TS CLI + SKILL.md, 9 command groups (hosts, check, logs, services, deploy,
  config, db, files, security), zero-knowledge SSH, structured JSON, open-source repo.
- **Why:** agent-safe remote ops without exposing credentials (user value); one transport
  core + one envelope so every op is consistent and auditable (technical value).
- **Who:** the user + any Claude Code / terminal user managing Linux VPS/docker-compose
  stacks; affected systems = remote servers reached only via existing SSH aliases.
- **When:** done = all 9 groups implemented, `just check`/`just test` green, smoke suite
  green against local sshd container, repo publishable. See research.md §Definition of done.
- **Where:** new repo `~/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd`; runtime touches only
  `~/.ssh/config`, ssh-agent, `~/.config/sshepherd/`, `~/.local/state/sshepherd/`.
- **How:** registry-dispatch — a central ops registry is the extension seam; a transport
  core executes any registry entry; the CLI parses argv and dispatches. Mirrors anywrite's
  registry.ts/client.ts/cli.ts split.

## Diagrams

```mermaid
flowchart TD
    A["sshepherd group action alias --flags"] --> B[cli.ts: parse argv + resolve op from registry]
    B --> C{op.mutating && not --yes?}
    C -->|yes| D[confirm + audit-log intent]
    C -->|no| E[transport core]
    D --> E
    E --> F["ssh -G alias (validate only, never echoed)"]
    F --> G["ControlMaster session: ssh alias -- timeout N remoteTemplate"]
    G --> H{exit code}
    H -->|255| I[classify: UNKNOWN_ALIAS / CONNECT_TIMEOUT / AUTH_FAILED / HOST_KEY_MISMATCH]
    H -->|other| J["op.output: native-json | ndjson | Parser<T>"]
    I --> K[envelope: ok=false, error=enum, alias only]
    J --> L[envelope: ok=true, data, alias only, bytes not strings]
    K --> M[stdout JSON]
    L --> M
```

```mermaid
classDiagram
    class OpSpec {
      +string group
      +string name
      +ArgSpec[] args
      +buildRemote(ctx) string
      +OutputMode output
      +bool mutating
      +ErrorMap errorMap
    }
    class Envelope {
      +bool ok
      +string alias
      +string ran_at
      +string command
      +int duration_ms
      +unknown data
      +ErrorInfo error
    }
    class Transport {
      +openMaster(alias) Session
      +run(alias, remoteCmd, timeout) RawResult
      +closeMaster(alias)
    }
    class Registry {
      +get(group, name) OpSpec
      +list() OpSpec[]
    }
    Registry o-- OpSpec
    OpSpec ..> Envelope : produces
    OpSpec ..> Transport : executes via
```

## File inventory

### Files to create

Repo scaffold + config:
- `package.json` — private, bin `sshepherd` → `./dist/sshepherd`, scripts mirror anywrite
- `tsconfig.json`, `biome.jsonc`, `justfile`, `.gitignore` (ignore `dist/`, `node_modules/`)
- `LICENSE` (MIT), `README.md`, `CONTRIBUTING.md`, `SECURITY.md`
- `.github/workflows/ci.yml` (typecheck + lint + test), `.github/workflows/release.yml`
  (4-platform build + checksums + `actions/attest-build-provenance`)
- `.claude-plugin/marketplace.json`, `.claude-plugin/plugin.json`
- `docs/progress.md`, `docs/changelog.md`

Core (`src/`):
- `src/types.ts` — `Envelope`, `OpSpec`, `ArgSpec`, `OutputMode`, `ErrorInfo`, error enum
- `src/quote.ts` — single remote-shell quoting function (single-quote wrap, `'\''` escape)
- `src/output.ts` — envelope builder, byte helpers, NDJSON splitter, `--pretty` renderer
- `src/transport.ts` — ssh shell-out, ControlMaster lifecycle, `-G` validation, error
  classification, transport-stderr discard
- `src/parsers/` — TS parsers for non-JSON commands (`df.ts`, `free.ts`, `uptime.ts`,
  `ps.ts`, `du.ts`, `ls.ts`), shapes matched to jc reference
- `src/registry.ts` — the 9-group op registry (single source of truth)
- `src/recipes.ts` — TOML deploy-recipe loader + typed-step validator + dry-run planner
- `src/targets.ts` — DB `<pg-target>` resolver (`~/.config/sshepherd/targets.toml`)
- `src/db.ts` — read-only SQL enforcement (role note + txn wrapper + node-sql-parser check)
- `src/audit.ts` — append-only audit log for mutating ops
- `src/cli.ts` — argv parse, allowlist check, confirm/`--yes` gate, dispatch
- `SKILL.md` — root skill file (command matrix + gotchas), `references/*.md` deep docs

Tests:
- `src/__tests__/*.test.ts` — unit (mocked `Bun.spawn`), quoting, parsers, classification,
  SQL-enforcement, recipe validation, envelope hygiene (no host/IP ever present)
- `scripts/smoke.sh` — E2E against a local disposable sshd container
- `scripts/sshd-fixture/Dockerfile` — sshd + docker-cli + coreutils fixture host

### Files to modify

None — greenfield repo. (No gitnexus impact analysis applicable: no existing symbols.)

### Files to NOT touch

- `~/.ssh/config`, `~/.ssh/*` — read via OpenSSH only, never written or parsed for values
- The `anywrite` repo — reference/template only, never edited
- Any real remote server — all automated tests hit the local sshd container only

## Phase breakdown

### Phase 1: Repo scaffold + tooling

**Goal:** `just check` runs clean on an empty-but-configured project that compiles.

**Files:**
- Create: package.json, tsconfig.json, biome.jsonc, justfile, .gitignore, LICENSE,
  placeholder src/cli.ts (prints version), docs/progress.md, docs/changelog.md

**Dependencies:**
- Requires: none (first phase)
- Provides: build/lint/typecheck/test harness every later phase relies on

**Separation of concerns:**
- Handles: toolchain, bun compile target, biome config, just recipes (mirror anywrite)
- Does NOT handle: any ops, transport, or SKILL.md content

**Success criteria:**
- [ ] `just build` produces `dist/sshepherd` that prints a version string
- [ ] `just check` (tsc --noEmit + biome) exits 0
- [ ] `.gitignore` excludes `dist/` and `node_modules/`

**Context:**
- Pattern to follow: `~/Documents/PROJECT_MISPAQUL_ATTORIQ/anywrite/{package.json,justfile,
  biome.jsonc,tsconfig.json}` verbatim shape, renamed to sshepherd.

**Concerns:**
- Keep runtime deps ≤2 (node-sql-parser, maybe a TOML parser) → confirm `Bun.TOML` exists.

---

### Phase 2: Types + transport core + output (the zero-knowledge invariant)

**Goal:** a `transport.run(alias, remoteCmd, timeout)` that connects via ControlMaster,
classifies errors, discards transport stderr, and a `buildEnvelope()` that structurally
cannot include a host/IP/user/port.

**Files:**
- Create: src/types.ts, src/quote.ts, src/transport.ts, src/output.ts, src/audit.ts,
  their unit tests

**Dependencies:**
- Requires: Phase 1 harness
- Provides: the single execution path every op in Phases 3–5 goes through

**Separation of concerns:**
- Handles: ssh shell-out, master socket lifecycle (open/reuse/`-O exit`, opaque short
  socket path), `-G` alias validation (presence only), error enum, envelope shape, quoting
- Does NOT handle: any specific op's remote command or output parsing

**Success criteria:**
- [ ] Unit test: a simulated ssh transport-stderr line containing an IP never appears in
      the envelope (hygiene invariant test)
- [ ] Unit test: exit 255 + "Permission denied" → `AUTH_FAILED`; non-255 → `COMMAND_FAILED`
      with the remote code carried
- [ ] Unit test: quoting escapes `'` as `'\''` and blocks command injection via args
- [ ] `--yes` gate + audit-log entry produced for a mutating op (mocked)

**Context:**
- See research.md §"SSH transport", §"output hygiene", §"error classification",
  §"response envelope". BatchMode/LogLevel/ControlPath/timeout flags are specified there.

**Concerns:**
- ControlPath length <104 chars → derive a short `$XDG_RUNTIME_DIR`/tmp dir + opaque name.
- Never `-t`, never `StrictHostKeyChecking=no`.

---

### Phase 3: Ops registry + read-only groups (hosts, check, logs, services-read, files-read)

**Goal:** the registry exists and every read-only op returns a correct structured envelope
against the sshd fixture (or a mocked transport for CI).

**Files:**
- Create: src/registry.ts, src/parsers/*.ts, tests. (services read-only actions: ps, stats,
  inspect, compose-ps, healthcheck, systemctl status; files read-only: ls, cat, tail,
  download, disk-usage.)

**Dependencies:**
- Requires: Phase 2 transport/output
- Provides: the registry seam + all parsers; proves the native-JSON/NDJSON/parser modes

**Separation of concerns:**
- Handles: registry entries + parsers for read-only ops across hosts/check/logs/
  services/files; NDJSON splitting; bytes + verdict fields (dead_end_risk); log line objects
- Does NOT handle: any mutating op, deploy, db, security-harden

**Success criteria:**
- [ ] `hosts list` returns alias names only (no HostName/User/Port) — hygiene test
- [ ] `check overview` returns all-bytes fields + `dead_end_risk` boolean
- [ ] `services ps` merges inspect data (health/restarts/oom_killed/limits) into each entry
- [ ] `logs docker` returns `{ts, stream, text}` line objects + `next_since`
- [ ] parser unit tests for df/free/uptime/ps/du/ls match expected shapes

**Context:**
- See research.md §"output shaping per remote command", §"ops registry architecture",
  §"command inventory". Native-JSON flag table is authoritative.

**Concerns:**
- Docker `--format json` is NDJSON, `docker inspect` is an array — tag output mode per op.
- `pg_stat_statements`-style "feature absent" degradation applies later (db); here ensure
  a missing command (e.g. no docker) yields a clean `COMMAND_FAILED`, not a crash.

---

### Phase 4: db group (read-only enforcement) + targets

**Goal:** `db` group runs SELECT-only queries against a Postgres reachable via
`docker exec` on the fixture, with layered read-only enforcement.

**Files:**
- Create: src/targets.ts, src/db.ts, db registry entries, tests

**Dependencies:**
- Requires: Phase 2 transport, Phase 3 registry
- Provides: DB introspection ops (list, tables, activity, connections, slow, size)

**Separation of concerns:**
- Handles: `<pg-target>` resolution, `docker compose exec -T db psql` invocation, txn-
  readonly wrapper, node-sql-parser statement-type rejection, pg_stat_activity rollups
- Does NOT handle: any write path (deferred to a future version behind --confirm), MySQL

**Success criteria:**
- [ ] `db query` rejects a non-SELECT statement at the parser layer with a clear error
- [ ] A writable-CTE attempt fails (documents the txn-readonly wrapper as the real gate;
      role-based enforcement noted in target config docs)
- [ ] `db activity` returns numeric `query_seconds`, `blocked_by`, and top-level rollups
      (`backends_total` vs `max_connections`)
- [ ] `db slow` degrades gracefully when `pg_stat_statements` is absent (no error thrown)

**Context:**
- See research.md §"DB access". Layer order: role (doc) → txn wrapper (enforced) →
  parser (UX). `<pg-target>` mirrors the SSH-alias no-credentials model.

**Concerns:**
- Password never transits sshepherd — docker-exec relies on container peer/trust or remote
  `.pgpass`; document this in targets.toml.

---

### Phase 5: mutating groups (services-restart, config, deploy recipes, security-harden)

**Goal:** the mutating surface works with dry-run + confirm + audit, and deploy recipes
load/validate/plan from TOML including the LMS rebuild-then-migrate ordering.

**Files:**
- Create: src/recipes.ts, mutating registry entries (services restart/systemctl-verbs,
  config put/reload/validate, deploy run/status/rollback/logs/migrate, security harden),
  tests + fixture recipe

**Dependencies:**
- Requires: Phases 2–3 (transport, registry, files upload for config put)
- Provides: the full mutating command set — completes the 9 groups

**Separation of concerns:**
- Handles: typed recipe steps (shell|compose|healthcheck|http-probe|wait|migrate),
  `--dry-run` JSON plan, backup-before-write (config put), `--keep-session` harden guard,
  declared-only rollback
- Does NOT handle: multi-host fan-out, package installs, interactive tools (all out of scope)

**Success criteria:**
- [ ] `deploy run <recipe> --dry-run` prints the resolved ordered plan as JSON, executes
      nothing, and marks which steps mutate
- [ ] A recipe with `migrate depends_on up` orders correctly (LMS gotcha expressible)
- [ ] `config put` writes a `.bak-<date>` before overwriting (verified on fixture)
- [ ] `deploy rollback` with no `[rollback]` block refuses with a clear message, never guesses
- [ ] every mutating op requires `--yes` (or interactive confirm) and writes an audit line

**Context:**
- See research.md §"deploy recipes", §"command inventory" (mutating ops marked †),
  and `~/.claude/skills/devops-engineer/references/server-pattern.md` §D for the harden
  no-self-lockout rule.

**Concerns:**
- `shell`-kind steps are the only raw pressure valve — keep them inside named recipes only,
  never expose an ad-hoc `exec`.

---

### Phase 6: SKILL.md + references + CLI polish

**Goal:** a root SKILL.md (anywrite shape) that documents the full command matrix + gotchas,
plus `--help` per group and `references/*.md` deep docs.

**Files:**
- Create: SKILL.md, references/{transport.md,recipes.md,db.md,output-shapes.md}; finalize
  src/cli.ts help output

**Dependencies:**
- Requires: Phases 3–5 (all ops exist to document accurately)
- Provides: the agent-facing contract + human docs

**Separation of concerns:**
- Handles: SKILL.md description (pushy triggering), command matrix, zero-knowledge gotchas,
  per-group `--help`
- Does NOT handle: OSS packaging files (Phase 7)

**Success criteria:**
- [ ] SKILL.md frontmatter has name `sshepherd` + a triggering description covering "ssh",
      "server", "deploy", "remote db", "zero-knowledge creds"
- [ ] `sshepherd <group> --help` lists actions + flags for every group
- [ ] Every documented command matches an actual registry entry (no doc drift — test)

**Context:**
- Pattern to follow: `anywrite/SKILL.md` structure (command shape, quick reference, gotchas,
  errors). Keep it short + human-reviewable (a trust signal).

**Concerns:**
- Doc/registry drift — add a test asserting every SKILL.md command exists in the registry.

---

### Phase 7: OSS packaging + trust signals + release pipeline

**Goal:** the repo is publishable and `npx skills add`-compatible with the full trust set.

**Files:**
- Create: README.md, CONTRIBUTING.md, SECURITY.md, .github/workflows/{ci,release}.yml,
  .claude-plugin/{marketplace,plugin}.json; finalize docs/{progress,changelog}.md

**Dependencies:**
- Requires: Phase 6 (SKILL.md exists at root for the skills walk)
- Provides: publishable open-source project

**Separation of concerns:**
- Handles: README (keyword-rich, install channels, "What sshepherd NEVER does",
  no-telemetry), SECURITY.md, CI + release workflow (4-platform + checksums + provenance),
  plugin marketplace manifests, GitHub topics list in README
- Does NOT handle: pushing to GitHub / creating the remote (user-driven; needs their auth)

**Success criteria:**
- [ ] README has install blocks for `npx skills add`, `/plugin marketplace add`, release
      binary download, and `just build`
- [ ] README "What sshepherd NEVER does" section present (no ~/.ssh key reads, zero outbound
      calls except user SSH, no telemetry, no arbitrary exec)
- [ ] release.yml builds darwin-arm64/darwin-x64/linux-x64/linux-arm64 + SHA-256 +
      `actions/attest-build-provenance`
- [ ] `.claude-plugin/marketplace.json` + `plugin.json` valid
- [ ] SKILL.md is at repo root (skills two-level walk compatibility)

**Context:**
- See research.md §"OSS packaging". Verify against `anywrite`'s README/CONTRIBUTING/workflow
  files as the proven template.

**Concerns:**
- Do NOT commit `dist/` — binaries ship via Releases only.
- Pushing the repo + awesome-list PRs are user-driven (auth + social-proof gate) — leave as
  documented follow-ups, don't attempt them autonomously.

## Cross-phase guidelines

- **Zero-knowledge is the invariant.** No phase may put a HostName/IP/User/port/key into
  any output, log, or error. Every op executes through `src/transport.ts` — never spawn ssh
  directly from an op or the CLI. Each phase touching output adds/keeps a hygiene test.
- **Registry is the only seam.** Adding an op = one `src/registry.ts` row. No if/elif
  dispatch chains, no per-op bespoke execution path (registry-dispatch pattern).
- **One envelope everywhere.** Success and error exit through `buildEnvelope()`; sizes in
  bytes; alias-only identity.
- **Mutating ⇒ dry-run/confirm/audit.** Every op with `mutating: true` requires `--yes` (or
  interactive confirm) and writes one audit line. Read-only ops never prompt.
- **No raw exec.** The only raw-shell path is a named, typed `shell` recipe step. Plain
  `ssh <alias>` is the documented human break-glass; the tool never fakes a REPL over JSON.
- Standards: `~/.claude/rules/coding-standard.md` (KISS, explicit types, one logger, no
  emojis), `~/.claude/rules/persona.md`. Logging: pick one module at init.
- Progress + changelog per `~/.claude/rules/progress-changelog.md` — prepend an entry when
  real work lands.

## Progress log

(Append-only. Executor subagents add one entry after completing each phase.)

### Phase 1: Repo scaffold + tooling — 2026-07-12

**Status:** Complete
**Files created:** package.json, tsconfig.json, biome.jsonc, justfile, .gitignore, LICENSE, src/cli.ts (placeholder), docs/progress.md, docs/changelog.md
**Files modified:** none
**Key decisions:**
- Mirrored anywrite's Bun/TS/biome/just toolchain verbatim, renamed to sshepherd.
- Dropped anywrite's `codegen` script + openapi-typescript/yaml devdeps (no OpenAPI spec here).
- Zero runtime deps confirmed; `Bun.TOML` built in (Bun 1.3.6) so no TOML npm dep needed. Only future runtime dep is `node-sql-parser` (Phase 4).
**Issues:** none
**Deviations from plan:** none
**Notes for next phase:** Build works: `just build` → `dist/sshepherd`, `--version` prints `sshepherd 0.1.0`. `just check` (tsc + biome) green. cli.ts is a throwaway placeholder — Phase 6 rewrites it as the real argv dispatcher. tsconfig has `noUncheckedIndexedAccess` + `verbatimModuleSyntax` on, so transport/parser code must use explicit `type` imports and guard array access.

### Phase 2: Types + transport core + output — 2026-07-12

**Status:** Complete (audited ✅)
**Files created:** src/types.ts, src/quote.ts, src/transport.ts, src/output.ts, src/audit.ts, src/__tests__/{quote,transport,output,audit}.test.ts
**Files modified:** none
**Key decisions:**
- `Envelope<T>` has `alias` as the ONLY identity field — no host/user/port/ip field exists in the type, so the zero-knowledge guarantee is structural (compiler-enforced), not test-enforced.
- `ErrorInfo.message` is a static per-code constant (`ERROR_MESSAGES` lookup), never interpolated from ssh stderr. Classifier reads `transportStderr` to pick the code, then discards it.
- Transport is unit-testable via an injectable `SshRunner` (`deps.runner`, defaults to a `Bun.spawn` wrapper). Tests use a `scriptedRunner` fake — zero real ssh invoked.
- Socket path: opaque `crc32(alias)` base36 name (no %h/%r/%p tokens), 0700 dir, length-guarded <100 chars. Flags: BatchMode=yes + LogLevel=ERROR on every call; never -t; never StrictHostKeyChecking=no.
- Audit log (`~/.local/state/sshepherd/audit.jsonl`, 0600) stores `args_hash` (crc32), never raw arg values.
**Issues:** none. Audit added 2 adversarial tests (remote-stderr-non-255 routing, remote-stdout passthrough) → 28 tests pass.
**Deviations from plan:** humanToBytes + --pretty renderer deferred (YAGNI, to Phases 3/6).
**Notes for next phase (LOAD-BEARING for auditors):**
- `RawResult` (`transport.run().raw`) is INTERNAL — it holds `transportStderr`/`commandStderr`. The CLI/registry must NEVER serialize `raw` directly into output; only `error`/`data` may reach `buildEnvelope`. A future phase serializing `raw` would reintroduce a leak. Phase 3+ auditors must check this.
- ssh's exit-code protocol can't distinguish a remote command that legitimately exits 255 from ssh's own transport 255 — a rare misclassification, never a leak (message stays static).
- Phase 3 ops build remote command strings ONLY via `shq`/`shellJoin` from src/quote.ts — never string-concat a value into a remote command. `run(alias, remoteCmd, timeoutSec, deps)` is the single execution path; ops must go through it, never spawn ssh directly.

### Phase 3: Ops registry + read-only groups — 2026-07-12

**Status:** Complete (audited ✅)
**Files created:** src/registry.ts (25 read-only ops + getOp/listOps/executeOp), src/parsers/*.ts (bytes/df/free/uptime/ps/du/ls/sysctl/dmesg-oom/ss/journal/docker-log/docker-ports/logs-shape/os-release/sections/verdict/psi/systemctl-show/ssh-config), src/__tests__/{parsers,registry}.test.ts
**Files modified:** src/types.ts (OpSpec expanded: buildRemote→string|null, added runLocal, shape takes (parsed, ctx); added ArgSpec)
**Key decisions:**
- `executeOp` is the registry↔transport glue: resolves buildRemote/runLocal → `transport.run` (single path) → parse per output mode → shape → buildEnvelope. Only `data`/`error` reach the envelope; `raw` never serialized (Phase 2 rule held, audit-verified live).
- `hosts list` reads ~/.ssh/config LOCALLY (runLocal, no ssh), returns alias names ONLY, skips `Host *` wildcards.
- Native JSON where it exists (docker inspect/stats/compose-ps, journalctl -o json → all NDJSON via splitNdjson); hand-written parsers for df -B1/free -b/uptime/ps/du -sb/ls, ss -H, dmesg, systemctl show (chose `systemctl show --property=` over `-o json` for cross-version safety).
- All sizes in bytes (df -B1/free -b/du -sb); `dead_end_risk` computed from real thresholds (disk >90%, PSI some_avg10 >10%).
- `logs docker` → `{ts, stream, text}` lines + `next_since`; stream always 'stdout' (docker logs CLI has no reliable per-line stream tag — documented limitation).
- `files cat` masks `.env` KEY=value lines by default, `--reveal <key>` opts a key out (audit added the missing tests).
- `files download` reads base64 over the ssh channel (stays on the one transport path, no separate scp).
- Missing remote binary (e.g. no docker) → clean COMMAND_FAILED via `command -v docker || exit 127` guard.
**Issues:** audit found `.env` masking had zero tests (added 3) + added real-shell injection drives + a zero-knowledge error-path test → 50 tests pass.
**Deviations from plan:** scripts/sshd-fixture/Dockerfile deferred (optional this phase).
**Notes for next phase (LOAD-BEARING):**
- CARRIED-FORWARD for Phase 6/7 smoke suite: these command output shapes were coded from docs/man-pages, NOT live-captured (dev box is macOS, target is Linux) — MUST be spot-checked against a real Linux+docker host before SKILL.md ships them: `docker stats --format json` field names, `docker compose ps --format json` (Publishers[]), `dmesg -T` format, `journalctl -o json` fields, `ss -H -tlnp` columns, `systemctl show` properties. Build scripts/sshd-fixture/Dockerfile (sshd + docker-cli + coreutils) for this.
- Phase 4 (db) and Phase 5 (mutating) both APPEND ops to the same `src/registry.ts` REGISTRY array — they cannot run in parallel (file contention), stay sequential. Follow the exact OpSpec shape; add entries, don't restructure.
- `services stats` parses docker's human byte strings via `parseHumanBytes` (the one place a human size is parsed) — fine, documented.

### Phase 4: db group (read-only enforcement) + targets — 2026-07-12

**Status:** Complete (audited ✅, one security gap found + fixed + re-verified)
**Files created:** src/targets.ts (PgTarget, loadTargets/resolveTarget via Bun.TOML, SSHEPHERD_TARGETS_PATH override, buildDbOpContext), src/db.ts (assertSelectOnly, assertNoMultiStatementSql, wrapReadOnlyTxn, wrapAsJsonAgg, buildPsqlCommand, buildDbSlowCommand), src/__tests__/{db,targets}.test.ts, targets.example.toml
**Files modified:** src/registry.ts (7 db ops appended: list/tables/activity/connections/slow/size/query), src/__tests__/registry.test.ts, package.json/bun.lock (added node-sql-parser — first + only runtime dep)
**Key decisions:**
- `node-sql-parser` is the only runtime dep; confirmed it bundles + runs under `bun build --compile` (independent registry.ts compile test, exit 0).
- Three-layer read-only enforcement: (1) read-only ROLE recommended in targets.example.toml (engine-side, the real boundary — documented); (2) txn-readonly wrapper `wrapReadOnlyTxn` (BEGIN TRANSACTION READ ONLY; ...; ROLLBACK) wraps EVERY db op's SQL — the enforced gate; (3) node-sql-parser `assertSelectOnly` rejects positively-identified INSERT/UPDATE/DELETE/DDL locally before ssh (advisory; exotic-valid syntax passes through).
- Zero-knowledge holds for db: pg-target NAME is the only identity echoed; container name / compose dir / db user / db name / connection details from targets.toml never reach any envelope or error (psql's own stderr is discarded like all transportStderr). Verified live on success + COMMAND_FAILED paths.
- Fixed introspection SQL (list/tables/activity/connections/slow/size) authored to emit JSON via json_agg/json_build_object, wrapped in wrapReadOnlyTxn uniformly. `db list` reads declared target names LOCALLY (runLocal, mirrors `hosts list`), no psql round trip.
- `db slow` degrades gracefully: presence-checks pg_stat_statements first, returns `{available:false, reason}` (ok:true) when absent, never errors.
- psql invoked via `docker compose exec -T db psql` (or plain `docker exec`) with ON_ERROR_STOP=1; all values interpolated via shq/shellJoin (injection-verified with real `sh -c` marker-file drives).
**Issues:** Audit found a REAL security gap — a crafted `db query` payload (`SELECT 1) t; COMMIT; DROP TABLE foo; SELECT (SELECT 1`) closed wrapAsJsonAgg's `FROM (...) t` boundary early and injected a COMMIT that ended the read-only txn before a write ran; parser threw on the fragment and the advisory catch let it pass. FIXED (578cf52): `assertNoMultiStatementSql` rejects any `db query` sql containing a bare `;` locally, before ssh, scoped ONLY to the free-text query op (static introspection SQL untouched). Re-verified live: payload rejected, plain SELECT passes, trailing-semicolon SELECT rejected.
**Test count:** 50 → 85 pass (audit + fix added drives), 0 fail, `just check` clean.
**Deviations from plan:** added `db query` op (success criteria demand it; introspection-only "Provides" line was incomplete).
**Notes for next phase (LOAD-BEARING):**
- Phase 5 (mutating) APPENDS ops to the same src/registry.ts REGISTRY array — sequential, no parallel. Follow the OpSpec shape; add entries, don't restructure. db ops occupy the tail of the array now.
- CARRIED-FORWARD (known issue #2→resolved-in-code / db SQL correctness): the introspection SQL (column names like pg_stat_statements total_exec_time vs total_time across PG13/14+) has NOT been driven against a real Postgres — no fixture DB exists. Must be spot-checked in the Phase 6/7 smoke suite alongside the Linux command shapes (build a Postgres container into scripts/sshd-fixture).
- Auth model documented in targets.example.toml: password never transits sshepherd (container peer/trust or remote .pgpass).

### Phase 5: mutating groups (services/config/deploy/security) — 2026-07-13

**Status:** Complete (audited ✅ mostly, one observability gap found + fixed + re-verified)
**Files created:** src/recipes.ts (typed steps shell|compose|migrate|healthcheck|http-probe|wait, Bun.TOML loader w/ SSHEPHERD_RECIPE_PATH override mirroring targets.ts, resolveStepOrder topo sort w/ cycle+unknown-dep rejection, planRecipe dry-run planner, buildRunScript/buildMigrateScript/buildRollbackCommand, buildDeployOpContext), src/__tests__/recipes.test.ts, fixtures deploy.demo.toml + deploy.no-rollback.toml
**Files modified:** src/registry.ts (15 mutating ops appended: services restart+start/stop/restart/reload, config get/validate/put/reload, deploy run/status/rollback/logs/migrate, security harden; executeOp rewired: confirmGate+auditMutating gate), src/types.ts (added CONFIRMATION_REQUIRED to SshErrorCode; added optional OpSpec.shapeError hook), src/transport.ts (CONFIRMATION_REQUIRED static message + exported errorInfo), src/__tests__/registry.test.ts
**Key decisions:**
- ONE mutating gate in executeOp: every `mutating:true` op flows confirmGate (unless deps.yes) → refusal audits outcome:'refused' + returns CONFIRMATION_REQUIRED with ssh never touched → proceed runs + audits ok/error. `deploy run --dry-run` is the sole exemption (runLocal, executes nothing). No per-op bespoke gating.
- Recipe steps are a discriminated union on `kind`; `run` field of shell/compose/migrate is the ONE raw-shell pressure valve (unquoted by design, matches research.md's pyinfra server.shell model — recipe files are author-controlled like a Makefile), reachable ONLY via a loaded named TOML recipe. No ad-hoc `exec` op anywhere.
- LMS gotcha expressible: `migrate depends_on = "up"` sorts after the compose build/up step (fixture declares them out of order to prove real reordering).
- config ops gated by a per-alias path allowlist, fail-closed before ssh (get/validate/put). config put writes `.bak-<UTCdate>` before overwrite in one round trip (own cp+base64 script — files upload never existed). config reload takes a unit NAME not a path (no allowlist applicable, mirrors services systemctl verbs).
- security harden ships the SAFE subset by default (X11Forwarding/PermitEmptyPasswords/MaxAuthTries/ClientAlive*); PermitRootLogin/PasswordAuthentication only with explicit keep-session:false. Never self-locks-out by default.
- deploy step-failure attribution (audit fix e377540): each step wrapped so a failure echoes `__SSHEPHERD_STEP_FAILED__ <idx> <kind> <name>` on stdout (stderr stays discarded); surfaced via new additive `OpSpec.shapeError` hook → `data.failed_step`. One round trip preserved, executeOp not restructured.
**Test count:** 85 → 143 pass (executor + audit + fix drives), 0 fail, `just check` clean.
**Deviations from plan:** compose step shape follows research.md's `run="build app"` (not brief's {service,action}); rollback strategies previous-tag/compose-file (research specifies only the refusal behavior); config put self-contained (no files upload dep).
**Notes for next phase (LOAD-BEARING):**
- SCOPE GAP found by audit + being closed in a follow-up executor BEFORE Phase 6: the four READ-ONLY security ops (ssh-audit/listeners/authorized-keys/fail2ban) and standalone `files upload` from research.md's locked 9-group inventory were never assigned a phase — the user locked the FULL 9-group set, so these must exist before SKILL.md documents the set. Being appended to the registry as read-only (security) + mutating-gated (files upload) ops.
- `buildDeployOpContext` (recipes.ts) is built + unit-tested but UNWIRED (its caller is cli.ts, Phase 6's placeholder) — Phase 6 must wire it, not reinvent it.
- CARRIED: no live docker/compose/sshd host drive (no fixture container) — Phase 6/7 smoke suite must build scripts/sshd-fixture (sshd + docker-cli + coreutils + postgres) and spot-check the mutating command shapes + db SQL + Linux read-only shapes against it.

## Review findings

(Filled by auditor subagents.)

### Phase 4 audit — 2026-07-12
✅ All 4 success criteria met + verified live (assertSelectOnly rejects non-SELECT; txn wrapper wraps every op; db activity numeric rollups; db slow graceful degradation). Zero-knowledge, registry pattern, and shq/shellJoin injection safety all held under live adversarial `sh -c` marker-file drives. One genuine security defect found and reproduced (COMMIT-injection bypass of the read-only txn via crafted subquery-boundary escape) → fix-implementer closed it (578cf52, `assertNoMultiStatementSql`), re-verified live. DEFERRED (carried, not ❌): live Postgres drive (no fixture DB — Phase 6/7 smoke suite). Final: 85 tests pass, `just check` clean.

### Phase 5 audit — 2026-07-13
Mostly ✅: all 5 success criteria met + verified live (deploy run --dry-run plans-only no ssh; migrate depends_on reorders; config put writes .bak before overwrite via real fixture drive; rollback refuses without [rollback]; every mutating op shares one confirm+audit gate). 8/9 cross-phase invariants clean: ONE mutating gate (single confirmGate call site, --dry-run the only exemption), audit hygiene (args_hash never raw), zero-knowledge (no host/user/port in plans/audit/errors), NO raw exec (shell steps only via named recipe), injection safety (14 interpolation points driven with real `sh -c`), config allowlist (fail-closed before ssh), harden no-self-lockout (safe subset default, risky gated behind keep-session:false), recipe validation (cycle/unknown-dep throw). One FAILED invariant → FIXED (e377540): deploy step-failure attribution — buildRunScript joined steps with `&&` giving a bare COMMAND_FAILED with no step identity; fix wraps each step with a stdout `__SSHEPHERD_STEP_FAILED__ <idx> <kind> <name>` marker (stderr stays discarded, one round trip preserved) surfaced via a new additive `OpSpec.shapeError` hook (mirrors runLocal pattern, executeOp not restructured) → `data.failed_step`. Re-verified live incl. injection-safe marker. Auditor added injection + wiring drives (df08a0b). Final: 143 tests pass, `just check` clean.

## Final status

(One paragraph at the end.)

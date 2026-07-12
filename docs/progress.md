# sshepherd Progress

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
available in this execution environment, so `just smoke` has **not been run**. Those command
shapes remain doc-derived, not live-verified, until a maintainer runs `just smoke` on a
machine with Docker.

---

## Session — 2026-07-12 — v0.1.0 (scaffold)

Repo scaffolded to mirror anywrite's Bun/TypeScript/biome/just toolchain: package.json with build/dev/test/typecheck/lint/check scripts, tsconfig.json in strict mode targeting ESNext, biome.jsonc for lint + format, and a justfile exposing install/build/test/check/smoke/clean recipes as the only command interface. Zero runtime dependencies — only @biomejs/biome, @types/bun, and typescript as devDependencies, per the plan's constraint to keep runtime deps at or under two (Bun.TOML covers config parsing later, no toml package needed; node-sql-parser is deferred to Phase 4). Added a placeholder src/cli.ts that reads a hardcoded VERSION constant and prints it plain or via --version/-v, just enough to give `bun build --compile` a real entry point. `just build` compiles to dist/sshepherd and `just check` (tsc --noEmit + biome check) runs clean. This is Phase 1 of a 7-phase orchestrated build defined in docs/plan/2026-07-12-sshepherd-v1/plan.md; later phases add ops/transport logic and the SKILL.md content, neither of which this phase touches.

---

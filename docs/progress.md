# sshepherd Progress

## Session — 2026-07-12 — v0.1.0 (scaffold)

Repo scaffolded to mirror anywrite's Bun/TypeScript/biome/just toolchain: package.json with build/dev/test/typecheck/lint/check scripts, tsconfig.json in strict mode targeting ESNext, biome.jsonc for lint + format, and a justfile exposing install/build/test/check/smoke/clean recipes as the only command interface. Zero runtime dependencies — only @biomejs/biome, @types/bun, and typescript as devDependencies, per the plan's constraint to keep runtime deps at or under two (Bun.TOML covers config parsing later, no toml package needed; node-sql-parser is deferred to Phase 4). Added a placeholder src/cli.ts that reads a hardcoded VERSION constant and prints it plain or via --version/-v, just enough to give `bun build --compile` a real entry point. `just build` compiles to dist/sshepherd and `just check` (tsc --noEmit + biome check) runs clean. This is Phase 1 of a 7-phase orchestrated build defined in docs/plan/2026-07-12-sshepherd-v1/plan.md; later phases add ops/transport logic and the SKILL.md content, neither of which this phase touches.

---

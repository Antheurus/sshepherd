---
descriptor: 2026-07-12-sshepherd-v1
plan: docs/plan/2026-07-12-sshepherd-v1/plan.md
research: docs/plan/2026-07-12-sshepherd-v1/research.md
written_at: 2026-07-12 15:55 UTC
written_by: cc-toriq session (Fable) — od-execute orchestrator, phases 1-3
reason: context-limit
---

# Handover — sshepherd v1

## State snapshot

**Current DAG block:** Block 4 of 7 — sequential (all blocks are sequential; phases 3/4/5
all append to src/registry.ts so cannot parallelize).

**Phase registry (verbatim from TaskList):**

| Phase | Task | Name | Status | Notes |
|---|---|---|---|---|
| 1 | #9 | Repo scaffold + tooling | complete | audited via inline verify |
| 2 | #10 | Types + transport core + output | complete | audited ✅ (zero-knowledge invariant) |
| 3 | #11 | Ops registry + read-only groups | complete | audited ✅ |
| 4 | #12 | db group + targets | pending | NEXT — blocked by nothing now (#11 done) |
| 5 | #13 | mutating groups | pending | depends on #11 (registry) |
| 6 | #14 | SKILL.md + references + CLI polish | pending | blocked by #12, #13 |
| 7 | #15 | OSS packaging + trust signals | pending | blocked by #14 |

**Repo:** /Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd (isolation: none, branch main)
**HEAD at handover:** d1cbfcb (all phases 1-3 committed; working tree clean)
**Commit trail:** b5b6241 (scaffold) → 54140cf (transport) → fc507a2 (transport audit tests)
→ bbcd82c (registry) → e701ee7 (registry audit tests) → d1cbfcb (progress log)
**Test/build state:** `just check` green (tsc + biome), `just test` = 50 pass / 0 fail across 6 files.

**Last completed action:** Phase 3 audit returned ✅ (added .env-masking tests + real-shell
injection drives + zero-knowledge error-path test, 50 tests), committed, progress log updated,
task #11 marked complete.

**Immediate next action:** Resume od-execute at Block 4. Dispatch ONE orchestration-executor
for Phase 4 (db group + targets) using the brief at plan.md §Phase 4. Baseline SHA for the
Phase 4 audit = d1cbfcb. After Phase 4 audits ✅, proceed to Block 5 (Phase 5 mutating).

---

## In-flight context

### User confirmations (verbal, not in artifacts)
- Name: **sshepherd** (chosen over ssh-ops/helmsman-ssh). Locked.
- Scope: **full 9-group set in v1** (chose full over phased read-only-first). Locked.
- The user is going open-source with this exactly like their `anywrite` repo
  (github.com/Antheurus/anywrite) — that repo is the packaging template. Public, MIT, under Antheurus.
- Pushing to GitHub + awesome-list PRs are USER-DRIVEN follow-ups (need their auth + a stars
  gate) — do NOT attempt them autonomously in Phase 7. Leave as documented next steps.

### Discoveries made mid-run
- `Bun.TOML` is built into Bun 1.3.6 (confirmed) → deploy-recipe TOML parsing needs NO npm dep.
  The ONLY runtime dep for the whole project is `node-sql-parser` (added in Phase 4 for the
  db SELECT-only guard). Everything else is Bun/web natives, like anywrite.
- tsconfig has `noUncheckedIndexedAccess` + `verbatimModuleSyntax` + full strict ON — executors
  must use `import type` and guard every array/record index. Biome: single quotes, semicolons,
  2-space, lineWidth 100, no emojis.
- `transport.run(alias, remoteCmd, timeoutSec, deps?)` is the SINGLE ssh execution path.
  `deps.runner` is injectable (a `scriptedRunner` fake) → every op is unit-testable with ZERO
  real ssh. Phase 4/5 tests MUST follow this pattern (canned stdout fixtures, no live ssh).
- `RawResult` (`transport.run().raw`) is INTERNAL — holds transportStderr. NEVER serialize it
  into an envelope; only `data`/`error` may reach `buildEnvelope`. Every phase auditor checks this.
- `executeOp` in src/registry.ts is the registry↔transport glue; Phase 4/5 ops plug into the
  same REGISTRY array + OpSpec shape (buildRemote via shq/shellJoin, shape(parsed, ctx), output
  mode). Adding an op = one array entry. No if/elif.

### Deviations from plan (already logged in plan.md progress log — no action needed)
- Phase 2: humanToBytes + --pretty renderer deferred to Phases 3/6 (YAGNI).
- Phase 3: scripts/sshd-fixture/Dockerfile deferred (was optional this phase).

### Environment / tooling notes
- Dev box is **macOS** (M2 Pro); target servers are **Linux**. `df`/`free`/etc. differ on mac —
  Phase 3 parsers were coded to documented Linux shapes, NOT live-captured. This is the #1 carried
  risk (see Known issues #1).
- Commits use the machine's configured git identity (`mispaqul.attoriq@gmail.com`) — just run
  plain `git commit`, do not override the email with `-c user.email=...`.
- Each phase is committed separately so the next audit has a clean baseline diff. Follow this.

---

## Known issues and blockers

| # | Severity | Description | Status |
|---|---|---|---|
| 1 | risk | Phase 3's Linux command output shapes (docker stats/compose-ps field names, `dmesg -T`, `journalctl -o json` fields, `ss -H -tlnp` columns, `systemctl show` props) were coded from docs/man-pages, NOT live-captured (dev box is macOS). MUST be spot-checked against a real Linux+docker host in Phase 6/7. | carried-forward — build scripts/sshd-fixture Dockerfile (sshd + docker-cli + coreutils) in Phase 6/7 and run the smoke suite against it |
| 2 | watch | Phase 4 db read-only enforcement: real boundary is a read-only DB ROLE (engine-side) + txn-readonly wrapper; node-sql-parser is UX-only (regex can't catch writable CTEs / volatile functions). Enforce all three layers; document the role requirement in targets.toml. Postgres-only in v1. | to-implement in Phase 4 |
| 3 | watch | Phase 5 deploy: rollback must REFUSE (not guess) when a recipe has no `[rollback]` block. `shell`-kind recipe steps are the ONLY raw-shell pressure valve — keep them inside named/versioned recipes, never expose an ad-hoc `exec`. Every mutating op needs --yes/confirm + an audit.jsonl line. | to-implement in Phase 5 |
| 4 | watch | Phase 7: do NOT commit dist/. Binaries ship via GitHub Releases (4 platforms + SHA-256 + actions/attest-build-provenance). SKILL.md must be at repo ROOT for npx-skills compatibility. README needs a "What sshepherd NEVER does" section (post-ToxicSkills trust signal). | to-implement in Phase 7 |

---

## Resume prompt

Copy this entire block and paste it as the first message in the new session.

---

```
RESUME ORCHESTRATION

Descriptor: 2026-07-12-sshepherd-v1
Repo: ~/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd (isolation: none, branch main, HEAD d1cbfcb)
Handover: docs/plan/2026-07-12-sshepherd-v1/handover.md
Plan: docs/plan/2026-07-12-sshepherd-v1/plan.md
Research: docs/plan/2026-07-12-sshepherd-v1/research.md

Read all three in order: handover.md -> plan.md -> research.md (skim). Phases 1-3 are
COMPLETE, committed, audited green (50 tests pass, just check clean).

Then invoke Skill({skill: "od-execute"}) and resume at Block 4:
- Dispatch ONE orchestration-executor for Phase 4 (db group + targets) per plan.md §Phase 4.
  Baseline SHA for its audit = d1cbfcb. Enforce db read-only via role + txn-readonly + parser
  (all three, see Known issue #2). Add node-sql-parser as the only runtime dep. Postgres-only.
- Then Block 5 (Phase 5 mutating), Block 6 (Phase 6 SKILL.md), Block 7 (Phase 7 OSS packaging).
- Phases 3/4/5 all append to src/registry.ts -> keep sequential, never parallel.
- Commit each phase separately (plain `git commit` — the machine git identity is mispaqul.attoriq@gmail.com).
- Do NOT push to GitHub or file awesome-list PRs (user-driven, needs their auth).

Do not re-plan. Do not re-ask answered questions. Pick up at Phase 4.
```

---

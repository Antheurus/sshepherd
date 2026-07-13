---
descriptor: 2026-07-13-setup-install-agent-invocable
plan: docs/plan/2026-07-13-setup-install-agent-invocable/plan.md
research: none (Lean mode — research folded directly into plan.md's Executive Summary + 5W+1H + Diagrams)
written_at: 2026-07-13 10:35 UTC
written_by: Claude (orchestrator, this session)
reason: user-request
---

# Handover — sshepherd setup: agent-invocable + install action

## State snapshot

**Current DAG block:** Block 1 of 2 — sequential (Phase 1 was about to be dispatched, interrupted before the executor `Agent` call actually ran)

**Phase registry:**

| Phase | Name | Status | Notes |
|---|---|---|---|
| 1 | Implement `setup ssh-alias install` | **not yet dispatched** | Task #7 shows `in_progress` in the tracker, but that only reflects the orchestrator marking it before dispatch — no `Agent(subagent_type: "orchestration-executor")` call was ever made. Treat as **pending**, not actually started. Zero code from this plan exists on disk yet. |
| 2 | Rewrite `setup` docs to agent-invocable framing | pending | blocked by #7 |

(Copied from `TaskList` output at handover time — do not trust "in_progress" on #7 as meaning real work happened.)

**Last completed action:** Plan approved via `ExitPlanMode` (plan.md fully written, ≥8/8 confidence, Lean mode). Tasks #7/#8 created with `addBlockedBy` wired. DAG announced in-chat. The very next tool call (dispatching Phase 1's executor) was interrupted by the user running `/od-handover`.

**Immediate next action:** Dispatch Phase 1's executor exactly as planned — one `Agent(subagent_type: "orchestration-executor")` call, `WORKING DIRECTORY: /Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd`, spec = plan.md §Phase 1 verbatim (implement `src/setup-ssh-alias-install-server.ts` + wire `install` into `src/setup-ssh-alias.ts`/`src/setup.ts`/`src/setup-types.ts`). Then `od-audit` in-loop, then Phase 2, then `od-finish` (cross-phase audit — this time explicitly include a check for whether `install`'s password ever transits anywhere it shouldn't, since that's the single highest-stakes correctness property of this whole feature).

---

## In-flight context

### User confirmations (verbal, not in artifacts)

- **The entire premise of "human-only setup" from the FIRST build (already shipped, PR #1) was a miscommunication, now corrected.** User confirmed twice via `AskUserQuestion`: (1) `register`/`keygen`/`remove`/all 3 scaffolders should be fully agent-invocable — "kenapa yang register/keygen/remove/scaffolder jadi human only? kan ini agent first, kecuali pas login isi creds, ini perlu bisa fully autonomous skill" (why human-only? this is agent-first, except when entering creds — needs to be a fully autonomous skill). (2) The browser-based password form for `install` should ALSO be agent-invocable (agent triggers it, waits, gets `{ok:true}` back) — the wall is specifically around the password content, not around who calls the command.
- User explicitly confirmed research finding that this required **zero code change** to the 4 already-shipped setup files — only a documentation/framing rewrite (Phase 2) plus one new action (Phase 1). User reacted with relief/validation to this ("bad code will stays or it's actually easier now") — confirms Phase 1/2 split as planned, no revert of the first build needed or wanted.
- Plannotator is NOT installed in this environment (confirmed both orchestration runs this session) — plan review always goes through `EnterPlanMode`/`ExitPlanMode` pointing at the real `plan.md`, never a duplicated plan body.

### Discoveries made mid-run

- `src/setup.ts`'s dispatch and all 4 setup-*.ts action functions have **zero caller-identity gating of any kind** — confirmed via direct code read (`confirmGate`/`auditMutating` in `src/audit.ts` take only `{mutating, yes}`, never anything about who's calling). The "human-only" restriction that shipped in the first build was 100% prose (`SKILL.md` gotcha 9, a help-text string literal in `setup.ts:50`, README.md prose) — the tool's own gotcha 9 even says "even though nothing enforces this technically." This is why Phase 1/2 are scoped the way they are.
- Bun.serve() research (see plan.md's Diagrams/5W1H) confirmed: bind `127.0.0.1` + `port:0` (ephemeral) for loopback-only; `sshpass` is NOT installed by default on macOS and must be checked via `Bun.which('sshpass')` up front with a clean typed error, not assumed present; the password should be piped via **stdin** to `sshpass -f /dev/stdin ssh ...`, never via `env` (env is a real, if narrow, local-leak surface via `/proc/<pid>/environ`/`ps -eww` and is more likely to get accidentally logged).
- `src/transport.ts`'s `defaultRunner` and `src/setup-ssh-alias.ts`'s `keygen()` are the two closest existing patterns to mirror for the install server's child-process spawn + timeout + exit-code-mapping shape — both already read, cited with line numbers in plan.md.

### Deviations from plan (not yet logged)

- None yet — no phase has executed. Nothing to flush into plan.md's progress log.

### Environment / tooling notes

- Repo: `/Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd`, branch `feat/setup-command-group` (confirm this is still checked out before dispatching — do NOT create a new branch, do NOT touch `main`). PR #1 (https://github.com/Antheurus/sshepherd/pull/1) is already open against `main` for the first build's work on this same branch — this plan's commits will land as additional commits on the SAME branch/PR, not a new PR.
- The compiled binary at `~/.local/bin/sshepherd` (symlinked to `dist/sshepherd`) is STALE as of this handover — it does not include this plan's `install` action (doesn't exist yet) and was last rebuilt right after the first build's fix-cycle. Rebuild (`just build` or `bun run build`) after Phase 1 lands before doing any live manual drive.
- Three real SSH aliases already exist in the user's real `~/.ssh/config` from earlier this session (`module-brighty-prod`, `module-brighty-db`, `dev-server`) — `module-brighty-prod` and `dev-server` are confirmed passwordless-working already (keys pre-installed by hand before `setup` existed). `module-brighty-db` is publickey-only server-side and was never resolved (parked, not blocking). **Do not use any of these 3 real aliases for `install`'s live end-to-end test** unless the user explicitly opts in — `install` is designed to CHANGE `authorized_keys` on a real remote, and these are real infrastructure the user depends on. Prefer a disposable/throwaway test target for the live drive, or ask the user first.
- `sshpass` availability on this specific machine (the one running this Claude Code session) has NOT been checked yet — Phase 1's executor should check it early (`Bun.which('sshpass')` or `which sshpass` in Bash) since the whole feature's live-testability depends on it being installed here.

---

## Known issues and blockers

| # | Severity | Description | Status |
|---|---|---|---|
| 1 | watch | `install`'s live end-to-end verification needs a real reachable SSH target with a real password — do not reuse the user's 3 already-configured real aliases without explicit confirmation (see Environment notes). May need the user to supply a disposable test box or explicitly bless one of the existing 3. | unresolved |
| 2 | watch | `sshpass` may not be installed on this machine — Phase 1 must check this early and surface `SSHPASS_NOT_FOUND` clearly if absent, per plan.md's own success criteria; this is expected/planned-for, not a surprise, but flagging since it could stall the live-drive portion of Phase 1's verification specifically. | unresolved |
| 3 | risk | The cross-phase audit for the FIRST build (already merged into this branch) caught a real crash bug (unescaped TOML strings) that no per-phase audit could see alone. The `install` server is genuinely new, security-sensitive surface (password handling) — `od-finish`'s cross-phase audit for THIS plan should be briefed explicitly to trace the password's full lifecycle end-to-end (form → stdin → child process → never logged/returned), not just check per-criterion compliance. | not yet reached (Phase 1/2 haven't run) |

---

## Resume prompt

```
RESUME ORCHESTRATION

Descriptor: 2026-07-13-setup-install-agent-invocable
Handover: docs/plan/2026-07-13-setup-install-agent-invocable/handover.md
Plan: docs/plan/2026-07-13-setup-install-agent-invocable/plan.md
Research: none (Lean mode, folded into plan.md)

Read handover.md → plan.md, in that order, before touching anything.

Then do exactly this: dispatch Phase 1's executor (one orchestration-executor Agent call,
WORKING DIRECTORY /Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd, branch
feat/setup-command-group — confirm checked out first, never touch main), spec = plan.md
§Phase 1 verbatim. Then od-audit in-loop. Then Phase 2 (docs rewrite). Then od-finish, with
an explicit instruction to the cross-phase auditor to trace the install password's full
lifecycle end-to-end as the highest-priority check.

Do not re-plan. Do not re-ask the user whether setup should be agent-invocable — that is
already confirmed twice (see handover.md's User confirmations). Do not use any of the
user's 3 existing real SSH aliases for install's live end-to-end test without asking first.
```

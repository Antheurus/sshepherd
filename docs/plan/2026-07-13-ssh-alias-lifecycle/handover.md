---
descriptor: 2026-07-13-ssh-alias-lifecycle
plan: docs/plan/2026-07-13-ssh-alias-lifecycle/plan.md
research: docs/plan/2026-07-13-ssh-alias-lifecycle/research.md
written_at: 2026-07-13 13:55 UTC
written_by: Claude (orchestrator, this session)
reason: user-request
---

# Handover — setup ssh-alias: host lifecycle + smarter install

## State snapshot

**Current DAG block:** Block 1 of 5 — sequential (Phase 1 was about to be dispatched, interrupted before the executor `Agent` call actually ran — same pattern as the last handover this session)

**Phase registry:**

| Phase | Name | Status | Notes |
|---|---|---|---|
| 1 | `setup ssh-alias list` + `status` | **not yet dispatched** | Task #9 shows `in_progress` — that only reflects the orchestrator marking it right before dispatch. No `Agent(subagent_type: "orchestration-executor")` call was ever made. Treat as pending, zero code exists yet. |
| 2 | `setup ssh-alias update` | pending | blocked by #9 |
| 3 | `install` already-trusted + Tailscale-fronted pre-checks | pending | blocked by #10 |
| 4 | `install` private-key paste credential method | pending | blocked by #11 |
| 5 | Docs rewrite + import-boundary test | pending | blocked by #12 |

(Copied from `TaskList` output at handover time — tasks #9-#13 in this session's tracker.)

**Last completed action:** Plan approved via `ExitPlanMode`. New branch `feat/setup-ssh-alias-lifecycle` created off `main` (the two prior `setup` builds — PR #1 — are already merged). `research.md` + `plan.md` committed (`53ffc4d`). Tasks #9-#13 created with `addBlockedBy` wired sequentially. DAG announced in-chat. The very next action (dispatching Phase 1's executor) was interrupted by the user running `/od-handover`.

**Immediate next action:** Dispatch Phase 1's executor — one `Agent(subagent_type: "orchestration-executor")` call, `WORKING DIRECTORY: /Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd`, confirm branch `feat/setup-ssh-alias-lifecycle` is checked out first (never touch `main`), spec = plan.md §Phase 1 verbatim. Then `od-audit` in-loop for Phase 1. Then continue the sequential chain through Phases 2-5 exactly as blocked in the tracker, `od-finish` (cross-phase audit) once all 5 are ✅.

---

## In-flight context

### User confirmations (verbal, not in artifacts)

- **The zero-knowledge output tension is resolved.** User explicitly chose, via `AskUserQuestion`: `setup ssh-alias status <alias>` MAY echo host/user/port (a scoped exception — the caller already supplied that data as input to `register`); `setup ssh-alias list` stays name-only; the 9 registry-driven groups (`hosts list` included) are completely untouched, their structural "no host/user/port/ip anywhere in any response" guarantee is not weakened. This is already baked into `research.md`/`plan.md` — do not re-ask it.
- **Scope is deliberately NOT full Termius parity.** User explicitly corrected mid-session: host CRUD (list/status/update, on top of existing register/keygen/remove/install) + credential-method diversity (password + pasted private key) ONLY. No agent-forwarding, no proxy, no host-chaining, no Mosh, no themes. If a future session feels tempted to add any of these, that's scope creep — stop and ask.
- **File upload for the private key is explicitly OUT of v1** — paste only. Confirmed via research (an open, unresolved Bun multipart-parser null-byte-truncation bug, plus an unverified assumption about `bun build --compile` binary parity for `formData()`/file handling). Satisfies the user's actual ask ("with \n one liner or a copy pasted from pem file").
- **Passphrase-protected pasted keys are explicitly REJECTED in v1**, not supported via an `ssh-agent`+`SSH_ASKPASS` chain — confirmed via direct OpenSSH source research this session; that chain multiplies secret-bearing temp artifacts and contradicts the "gone immediately" guarantee. Detect via a `ssh-keygen -y -f <path> -P ''` preflight.
- **`install()`'s CLI-level call shape does not change** for this whole feature — the credential-method toggle (password vs. paste-key) lives entirely inside the browser form/POST handler in `setup-ssh-alias-install-server.ts`. The agent never needs to know or pass which method the human will pick. Confirmed by the context-gatherer directly against the current code.

### Discoveries made mid-run

- **`findManagedStanza` only LOCATES one alias by exact name — it does NOT enumerate.** This was a real gap in the orchestrator's own first-draft research bundle, caught by the context-gatherer. `Phase 1`'s `list()` needs fresh enumeration code (regex-scan every `# sshepherd-managed: <name>` marker line across the whole config, or filter `listHostAliases`'s output per-alias through `findManagedStanza`) — do not assume `findManagedStanza` can be reused directly for `list`.
- **The "setup ⊥ registry/transport" import boundary is a followed convention, not an enforced invariant.** Confirmed via Grep by the context-gatherer: no lint rule or test currently fails if `setup-ssh-alias*.ts` imports `registry.ts`/`transport.ts`. Phase 5 adds a cheap grep-based test to close this gap — don't skip it as "already guaranteed."
- **`register`'s actual `argsSummary` shape is `{ host, user, port: String(port), overwrite }`** — i.e. it already includes real connection-detail STRINGS in the audit-log args hash input (not booleans, not omitted). Phase 2 (`update`)'s own `argsSummary` should match this existing precedent for consistency rather than inventing a stricter boolean-only rule — flagged explicitly in plan.md §Phase 2's Concerns, don't second-guess it without checking the real `register` code first.
- **Tailscale SSH claims port 22 per NETWORK PATH, not per-ACL-rule-match.** Confirmed via external research (Tailscale docs + community issues): once a target is reached over its tailnet IP with Tailscale SSH enabled, `~/.ssh/authorized_keys` is structurally irrelevant for that connection specifically — there's no automatic fallback to the OS sshd on ACL non-match, the connection is simply refused. Phase 3's Tailscale-detected diagnosis message must say this precisely (install can never work over THIS path), not just "wrong password" or a generic failure.
- **A pasted private key CANNOT achieve the same "never touches disk" guarantee the password path has** — confirmed via direct OpenSSH source read (`authfile.c`): `ssh -i <path>` requires a real, `fstat`-able regular file (`sshkey_perm_ok` enforces exactly-0600-or-tighter). This is a structural asymmetry from the password path (`sshpass -f /dev/stdin`), not a design gap — Phase 4 commits to the safest known pattern (mkdtemp 0700 dir, `O_CREAT|O_EXCL|O_WRONLY` 0600 key file, `ssh -i`, `finally`-cleanup for both success and failure) and documents the SIGKILL residual risk honestly rather than claiming full parity with the password path.

### Deviations from plan (not yet logged)

- None yet — no phase has executed. Nothing to flush into plan.md's progress log.

### Environment / tooling notes

- Repo: `/Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd`, branch `feat/setup-ssh-alias-lifecycle` (newly created this session off `main`, confirm this is still checked out before dispatching — do NOT create a second new branch, do NOT touch `main`). This is a brand-new branch/PR, NOT a continuation of the old `feat/setup-command-group` branch (that one's PR #1 is already merged and closed).
- The compiled binary at `~/.local/bin/sshepherd` reflects the state as of `main`'s tip (register/keygen/install/remove + the dark-theme styling + the relative-URL fix) — it does NOT include anything from this plan yet (list/status/update/pre-checks/key-paste don't exist in code). Rebuild after Phase 4 lands (or after Phase 5, whichever the next session prefers) before doing any live manual drive.
- Three real SSH aliases exist in the user's real `~/.ssh/config` from earlier this session: `module-brighty-prod`, `module-brighty-db`, `dev-server` (all pre-existing, hand-configured, unrelated to sshepherd's managed-stanza marker). A FOURTH, throwaway alias `otomasiaja-server2` was registered+keygen'd+tested this session (against a real Tailscale-SSH-fronted box) and then fully cleaned up afterward (local alias/key removed, remote `authorized_keys` entry stripped) — it should NOT exist in `~/.ssh/config` anymore; if a future session finds it there, that's a cleanup regression worth investigating, not expected state.
- `otomasiaja-server2` (100.103.182.84, reachable via Tailscale, user `root`) is a REAL, LIVE Tailscale-SSH-fronted box confirmed reachable this session — it is the natural live-test target for Phase 3's Tailscale-detected diagnosis (should return `TAILSCALE_SSH_DETECTED`, never hang). Do NOT attempt password-based install against it (confirmed structurally impossible — Tailscale SSH doesn't offer password auth at all).
- `dev-server` (172.16.20.134, user `server-internal`) is confirmed real, reachable, and NOT Tailscale-SSH-fronted (plain OpenSSH+password) — this remains the natural live-test target for Phase 3's already-trusted probe (register a throwaway test alias against the SAME box, same pattern as the prior session's live-verification, never mutate the real `dev-server` alias directly) and for Phase 4's key-paste install.
- A real, sensitive credential (`PASSWORD_SSH2` for `otomasiaja-server2`) was pasted directly into this session's chat transcript by the user earlier — it has already been used and the box cleaned up; the user was told to rotate it. Not relevant to this plan's execution, noted only so a future session doesn't need to re-derive why `otomasiaja-server2`'s prior test happened via a direct curl POST rather than a real browser.

---

## Known issues and blockers

| # | Severity | Description | Status |
|---|---|---|---|
| 1 | watch | Phase 4's live end-to-end verification (a real pasted-key install against a reachable box) needs a real private key the human/agent has access to install with — `dev-server`'s existing `~/.ssh/id_ed25519` or a fresh disposable keypair generated locally would work; do not reuse any of the user's 3 real production aliases without asking first, same standing rule as the previous `install` build. | unresolved |
| 2 | watch | Phase 3's Tailscale-banner detection is a best-effort heuristic against an undocumented Tailscale banner string (`SSH-2.0-Tailscale`) — per research.md, must fail soft (never crash, never misreport an ordinary sshd) if the banner format ever changes. Flag this explicitly to whichever auditor reviews Phase 3 — it's the single riskiest external assumption in this plan. | not yet reached |
| 3 | risk | Every new secret-touching code path (Phase 4's pasted key) needs the SAME 3x-independent-trace discipline (per-phase audit + cross-phase audit, both re-deriving from scratch) the password path received twice already this session — do not let a single pass "looks fine" substitute for this. Explicitly bake this into Phase 4's audit dispatch AND into `od-finish`'s cross-phase audit dispatch, mirroring exactly how the prior `install`-password build's dispatches were worded. | not yet reached |

---

## Resume prompt

```
RESUME ORCHESTRATION

Descriptor: 2026-07-13-ssh-alias-lifecycle
Handover: docs/plan/2026-07-13-ssh-alias-lifecycle/handover.md
Plan: docs/plan/2026-07-13-ssh-alias-lifecycle/plan.md
Research: docs/plan/2026-07-13-ssh-alias-lifecycle/research.md

Read all three files in this order: handover.md → plan.md → research.md (skim).

Then do exactly this: dispatch Phase 1's executor (one orchestration-executor Agent call,
WORKING DIRECTORY /Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd, branch
feat/setup-ssh-alias-lifecycle — confirm checked out first, never touch main), spec = plan.md
§Phase 1 verbatim. Then od-audit in-loop. Then continue sequentially through Phases 2-5 exactly
as blocked in the task tracker (#9→#10→#11→#12→#13). Then od-finish once all 5 are ✅, with the
cross-phase auditor explicitly instructed to re-trace Phase 4's pasted-key secret lifecycle from
scratch, same discipline as the already-shipped install-password feature got twice.

Do not re-plan. Do not re-ask whether status may echo host/user/port (already resolved, see
handover.md's User confirmations) or whether this should be Termius-scoped (explicitly rejected
by the user — CRUD + credential diversity only, nothing more).
```

# Contributing

Thanks for looking at `sshepherd`. Issues and PRs are welcome.

## Setup

```bash
git clone https://github.com/Antheurus/sshepherd.git
cd sshepherd
just install
```

Requires [Bun](https://bun.sh) and [`just`](https://github.com/casey/just).

## Before opening a PR

```bash
just check   # typecheck + lint (tsc --noEmit, biome check)
just test    # bun test — unit tests, no live ssh required
just build   # compiles dist/sshepherd
```

CI runs the same typecheck, lint, test, and build steps on every push and PR
(`.github/workflows/ci.yml`) and must pass. Do not commit `dist/` — it's gitignored; release
binaries ship via GitHub Releases only. Add an
entry to `docs/progress.md` describing what changed and why (and `docs/changelog.md` too, if
the change is user-facing) — see the note at the bottom of this file.

`just smoke` runs `scripts/smoke.sh` against a disposable local sshd + Postgres Docker
fixture (`scripts/sshd-fixture/`). It isn't part of CI (no Docker host to drive in a GitHub
runner), but if your change touches a remote command's output shape — a new parser, a new
`db` query, a new `check`/`services`/`logs` op — run it locally before submitting. It's the
closest thing this project has to a regression suite for real Linux/Postgres behavior, since
`bun test` mocks the transport layer entirely.

## Where things live

- `src/registry.ts` — every op as data: group, action, args, whether it mutates, how its
  remote command is built, how its output is parsed and shaped. Adding an op is one array
  entry here, dispatched through `executeOp` — never a new bespoke execution path or an
  if/elif chain in the CLI.
- `src/transport.ts` — the zero-knowledge core. Every op reaches the network through
  `transport.run()`, the single execution path; nothing spawns `ssh` directly outside this
  file. It owns the ControlMaster socket lifecycle, the error classification enum, and
  discarding ssh's own stderr before it can ever leak into an `ErrorInfo`.
- `src/output.ts` — the one place an `Envelope<T>` is constructed (`buildEnvelope`), plus
  the `--pretty` renderer.
- `src/db.ts` / `src/targets.ts` — the `db` group's read-only enforcement (SQL parsing,
  the read-only transaction wrapper, pg-target resolution).
- `src/recipes.ts` — the `deploy` group's TOML recipe loader, step ordering, and dry-run
  planner.
- `src/quote.ts` — `shq`/`shellJoin`, the only sanctioned way to interpolate a value into a
  remote command string.
- `src/cli.ts` — argv parsing and group/action dispatch, generated from the registry (help
  text is registry-derived, never a second hand-written list).
- `src/__tests__/` — one test file per module, `bun test` runner, an injectable fake ssh
  runner (no real network calls).

## The zero-knowledge rule contributors must never break

- No host, user, port, or IP ever reaches a response, a log line, or an error message.
  `Envelope<T>` has no such field by design — don't add one, and don't smuggle host/user
  data into `data` on a new op.
- Every remote command runs through `transport.run()`. Never spawn `ssh`/`scp` directly from
  an op, a parser, or the CLI.
- Every value interpolated into a remote command string goes through `shq`/`shellJoin`
  (`src/quote.ts`). Never string-concatenate an unquoted value into a command.
- A mutating op (`mutating: true` in its registry entry) must go through the single
  `confirmGate` + `auditMutating` path in `executeOp` — don't add a second, parallel
  confirmation mechanism for a new op.
- `db query`'s free-text SQL path must keep going through `assertSelectOnly` +
  `assertNoMultiStatementSql` + the read-only transaction wrapper. If you're touching
  `src/db.ts`, read `references/db.md` first — the three enforcement layers and why each one
  exists are documented there.

## Style

No new abstractions or refactors bundled into a feature/fix PR — keep changes scoped to what
they're fixing. Match the existing patterns (data-driven registry, one transport path, one
envelope constructor) rather than introducing a parallel approach for the same problem.
`biome check` enforces formatting — run `just check` before pushing, or `bun run lint:fix` to
auto-fix.

## Docs

If a change is user-facing, update `docs/changelog.md`. Either way, add an entry to
`docs/progress.md` describing what changed and why — it's the project's own history log,
read by whoever (human or agent) picks up the next session.

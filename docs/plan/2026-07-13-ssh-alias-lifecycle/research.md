---
feature: ssh-alias-host-lifecycle
created: 2026-07-13
updated: 2026-07-13T13:45Z
status: ready-for-plan
---

# Research — sshepherd `setup ssh-alias` host lifecycle + smarter `install`

## Definition of done

> "we only need host pages that were for knowing which host we're on, and to add, delete, update
> host, literally a mvp BUT it's still need to worth value to use... the product should be worth to
> use and give value for the masses" — user, this session.

Concretely: `setup ssh-alias` gains full CRUD (`list`, `status` alongside the existing
`register`/`remove`; new `update`) and `install` stops being a dumb "always ask for a password"
flow — it checks whether the target is already reachable before asking a human for anything, gives
an accurate diagnosis when a target is Tailscale-SSH-fronted (where password/key install is
structurally pointless), and adds a second credential method (pasting an existing private key)
alongside the existing password method. Explicitly OUT of scope: agent forwarding, host chaining,
proxy, Mosh, themes, or any other Termius feature beyond credential-method diversity and host CRUD —
confirmed via direct user correction mid-session.

## Verbatim captures

### Live Tailscale SSH failure (this session, real target `otomasiaja-server2`, 100.103.182.84)

`ssh -v` output (relevant excerpt) when a valid Tailscale-tailnet host has Tailscale SSH enabled:

```
debug1: Remote protocol version 2.0, remote software version Tailscale
debug1: compat_banner: no match: Tailscale
...
debug1: SSH2_MSG_SERVICE_ACCEPT received
# Tailscale SSH requires an additional check.
# To authenticate, visit: https://login.tailscale.com/a/<code>
```
`sshpass`-driven password auth against this target hangs (no password prompt is ever offered) until
sshepherd's own connect-timeout fires — confirmed NOT a sshepherd bug, confirmed via direct `ssh -v`
trace that this is Tailscale's own SSH proxy intercepting the connection before password/publickey
auth methods are even offered.

### Current `SetupErrorCode` union (verbatim, `src/setup-types.ts:38-52`, confirmed character-for-character by context-gatherer)

```ts
export type SetupErrorCode =
  | 'NOT_IMPLEMENTED'
  | 'UNKNOWN_SUBGROUP'
  | 'INVALID_ARGS'
  | 'CONFIRMATION_REQUIRED'
  | 'ALIAS_EXISTS'
  | 'ALIAS_NOT_FOUND'
  | 'PARSE_MISMATCH'
  | 'KEYGEN_FAILED'
  | 'VALIDATION_ERROR'
  | 'TARGET_EXISTS'
  | 'RECIPE_EXISTS'
  | 'SSHPASS_NOT_FOUND'
  | 'INSTALL_TIMED_OUT'
  | 'INSTALL_FAILED';
```
String union (docstring confirms later phases add to it) — new codes drop in with zero call-site churn.

### `buildSshpassArgs` — exact current argv (`src/setup-ssh-alias-install-server.ts:74-89`)

```ts
export function buildSshpassArgs(target: InstallTarget, remoteCmd: string): string[] {
  return [
    'sshpass', '-f', '/dev/stdin', 'ssh',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', `ConnectTimeout=${INSTALL_CONNECT_TIMEOUT_S}`,   // 10
    '-p', String(target.port),
    `${target.user}@${target.host}`,
    remoteCmd,
  ];
}
```
Connects directly to `user@host:port` — NOT alias-resolved via `~/.ssh/config`. No password parameter
in the function signature at all — structurally cannot leak the password into argv.

### `hosts test` OpSpec — the already-shipped "is this alias already reachable" probe (`src/registry.ts:127-137`)

```ts
const hostsTest: OpSpec<HostsTestResult> = {
  group: 'hosts',
  name: 'test',
  summary: 'Confirm the alias connects (latency is the envelope duration_ms).',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,   // 12
  output: 'raw',
  buildRemote: () => shellJoin(['echo', 'sshepherd-ok']),
  shape: (parsed) => ({ reachable: (parsed as string).trim() === 'sshepherd-ok' }),
};
```
Runs `ssh -o BatchMode=yes -o LogLevel=ERROR -o ControlPath=<sock> <alias> -- timeout 12 echo
sshepherd-ok` — resolves the alias's default identity (agent, `IdentityFile` if set, or nothing)
entirely via the system `ssh` binary. Confirmed: this already answers "is this box reachable without
any new credential" for free, for any alias already registered — but `setup` cannot literally call it
(no `registry.ts`/`transport.ts` import allowed in `setup`), so `install`'s own pre-check needs its own
small, direct `user@host:port` probe mirroring this shape.

### Zero-knowledge OUTPUT hygiene rule — already documented, already enforced for the 9 registry groups

`src/parsers/ssh-config.ts` docstring (paraphrased by context-gatherer, not literal quote): `hosts
list`/`listHostAliases` return alias **names only** — a prior research pass explicitly considered
echoing the full connection tuple (HostName/User/Port) and rejected it, precisely to keep response
shapes structurally free of any host/user/port/IP field. `SKILL.md` states this as an absolute,
structural claim ("no host/user/port/ip field anywhere in the response shape, structurally" — line 51)
for the 9 registry-driven groups.

**Resolved by user this session (AskUserQuestion):** `setup ssh-alias status <alias>` is a deliberate,
scoped exception — it MAY echo host/user/port, because the caller already supplied that data as input
to `register` in the same `setup` group. `setup ssh-alias list` (all aliases) stays name-only. The 9
registry groups (`hosts list` included) are completely untouched — their structural zero-knowledge
output guarantee is not touched or weakened by this feature.

## Code intelligence

All paths relative to `/Users/macbook/Documents/PROJECT_MISPAQUL_ATTORIQ/sshepherd/`. Not GitNexus-indexed.

### `src/setup-ssh-alias.ts` (510 lines) — current exports and reusable internals

- `findManagedStanza(lines, alias): FindStanzaResult` (107-130) — **locates ONE alias by exact name**
  (`not_found | mismatch | found`), does NOT enumerate. Any `list` implementation needs new
  enumeration code (regex-scan every `# sshepherd-managed: <name>` marker line, or filter
  `listHostAliases`'s output per-alias through `findManagedStanza`) — this was a real gap in the
  original research bundle, corrected by the context-gatherer.
- `stanzaPropertyValue(block, property): string | undefined` (166-172) — generic single-property
  extractor from an already-bounded block. Reusable as-is for `status`.
- `stanzaInstallTarget(lines, stanza)` (179-199) — reads HostName/User/Port/IdentityFile from a
  bounded block; returns `undefined` if HostName, User, **or IdentityFile** is missing. `install()`
  hard-requires this to be defined (lines 458-468, exact message: `` `alias '${alias}' has no
  generated key yet; run 'setup ssh-alias keygen ${alias}' first` ``, code `INSTALL_FAILED`).
  **`status` must NOT reuse this directly** — it needs to work even when `keygen` hasn't run yet
  (report `hasKey: false` rather than erroring), so needs its own lighter read that only requires
  HostName/User (Port/IdentityFile optional).
- `upsertIdentityFile(lines, stanza, keyPath)` (151-164) — add-or-replace-one-property-line pattern.
  `update` needs the SAME shape generalized across 3 properties (HostName/User/Port) — extracting a
  generic `upsertStanzaProperty(lines, stanza, property, value)` and having `upsertIdentityFile`
  become a thin wrapper is justified (3+ call sites, matches the project's "reused in 2+ places"
  extraction bar).
- `register`/`keygen`/`remove`/`install` all follow the identical skeleton: `confirmGate` →
  `findManagedStanza` guard (`not_found`/`mismatch`) → do the work → `writeTextSecure` →
  `auditMutating` → `buildSetupResult`. Every new action (`list`/`status`/`update`) must follow this
  exact skeleton for consistency (note: `list`/`status` are non-mutating reads — they skip
  `confirmGate`/`auditMutating` the same way `hosts test` does in the registry path, mutating:false).
- `install()` is dispatched as `install(alias, { yes })` from `setup.ts:141-142` — its own signature
  is `install(alias, options, configPath?, serverDeps?)`. Confirmed: the credential-method toggle
  (password vs. paste-a-key) can live entirely inside `runInstallServer`'s form/POST handler —
  `install()`'s CLI-level call shape does not need to change for this feature.

### `src/setup-ssh-alias-install-server.ts` (288 lines)

- `InstallTarget {alias, host, user, port, publicKeyPath}`, `InstallOutcome = installed | timed_out |
  ssh_failed{exitCode} | sshpass_not_found`, `InstallServerDeps {which, serve, spawnInstall,
  announceUrl, randomToken, timeoutMs}` — fully overridable via `Partial<InstallServerDeps>`, the
  exact test seam already used by 19 existing tests (never opens a real port/spawns real sshpass in
  `bun test`).
- `defaultSpawnInstall(password, target)` (95-124) — the spawn+timeout+cleanup shape to mirror for
  BOTH new spawn functions this feature needs (the already-trusted probe, and the key-based install).
  Explicitly excluded from `bun test` ("reserved for the manual/live verification step" — JSDoc
  91-94) — any new spawn function follows the same pattern: unit-tested via injected fakes, verified
  for real only by a live drive.
- `runInstallServer(target, overrides)` (201-288) exact current order: `which('sshpass')` check →
  generate token → `Bun.serve` (127.0.0.1, ephemeral) → GET renders form → POST reads `password`,
  calls `spawnInstall`, maps outcome → 3-minute timeout race → stop server, return outcome. The new
  already-trusted/Tailscale pre-checks must run **before** the `which('sshpass')` check and **before**
  any server opens — if either short-circuits to a definitive outcome, zero human interaction and zero
  password prompt should ever be shown.
- **A real bug was found and fixed live this session**: `renderFormHtml`'s `<form action="submit">`
  was a RELATIVE URL, which a real browser resolves against the page's own URL (`/TOKEN`, no trailing
  slash) by replacing the last path segment — silently dropping the token and 404ing on real
  submission. Fixed to `action="/${token}/submit"` (commit `30cf3be`). Missed by 19 unit tests + 3
  code-reading audits because every test hand-constructs its `POST` request with the already-correct
  path, never rendering the real markup. **Standing rule for this feature: any new form field/route
  gets a test that resolves the REAL rendered markup's `action`/URLs via `new URL(x, pageUrl)`, the
  same mechanism a browser uses — never just a hand-built `Request` object.**
- `PAGE_STYLE` (159-177) — inline-only dark/terminal CSS, zero external stylesheet/script (deliberate,
  page handles secrets). A new `<textarea>` for key-paste and a method toggle stay under this same
  constraint.
- `src/audit.ts`'s `auditMutating`'s `argsSummary` is always `{}` for `install()` (setup-ssh-alias.ts
  line 425) — traced end-to-end by 3 independent audits already this session to confirm nothing
  password-shaped can reach the audit log. **Any new secret type (pasted private key) needs the
  identical `argsSummary: {}` treatment and the identical 3x-independent-trace discipline at review
  time** — this is the single highest-priority correctness property in this whole feature, same as it
  was for the password path.

### Structural boundary: `setup` never imports `registry.ts`/`transport.ts`

Confirmed by context-gatherer: `setup-ssh-alias.ts`/`setup-ssh-alias-install-server.ts` genuinely
import neither today. **This is a followed CONVENTION, not an enforced invariant** — no lint rule or
test currently fails if the import is added. Given this feature adds new probe code that could be
tempted to reuse `transport.run`, this plan should add a lightweight enforcing test (grep-based or
import-graph assertion) rather than relying on convention alone.

## Risks & unknowns

- **Pasted private key cannot achieve the same "never touches disk" guarantee the password enjoys.**
  Confirmed via direct OpenSSH source read (`authfile.c`): `ssh -i <path>` requires a real,
  `fstat`-able regular file — `sshkey_perm_ok()` enforces `mode & 077 == 0` (must be exactly 0600 or
  tighter). Unlike `sshpass -f /dev/stdin`, there is no safe pipe/FD-based equivalent for `-i`. The
  design must state this asymmetry honestly rather than imply parity with the password path.
- **Passphrase-protected pasted keys**: with `BatchMode=yes` (mandatory, same as the rest of the
  project's ssh invocations), a passphrase-protected key fails FAST and CLEANLY — no hang — because
  there's no TTY to prompt against and BatchMode suppresses the askpass fallback. Building a working
  non-interactive passphrase flow (`ssh-agent` + `SSH_ASKPASS`) is possible but multiplies
  secret-bearing temp artifacts and contradicts the "gone immediately" guarantee — v1 should REJECT
  passphrase-protected keys outright with a clear, specific error, detected via a `ssh-keygen -y -f
  <path> -P ''` preflight (format-agnostic, doesn't need the actual passphrase to detect its presence).
- **Tailscale banner detection is a best-effort heuristic against an undocumented string.** The
  observed `SSH-2.0-Tailscale` banner is empirically real (independently confirmed via a public GitHub
  issue transcript) but Tailscale has never documented it as a stable contract. Detection must fail
  soft — never crash, never misreport an ordinary sshd as "definitely Tailscale" — the same fail-soft
  philosophy `transport.ts`'s `classify()` already applies to ssh's own unstable stderr phrasing.
- **Tailscale SSH claims port 22 per network path, not per-ACL-rule-match.** Once a target is reached
  over its tailnet IP with Tailscale SSH enabled, `~/.ssh/authorized_keys` is structurally irrelevant
  for that connection — there is no automatic fallback to the OS sshd on ACL non-match, the connection
  is simply refused. This means the Tailscale-detected diagnosis must say precisely this (install can
  never work over this specific path) rather than a generic "wrong password" message.
- **File upload (vs. paste) carries real, currently-open risk**: an unresolved Bun issue
  (oven-sh/bun#27478) shows the native multipart parser truncating small files at the first null byte;
  ASCII PEM/OpenSSH keys don't contain null bytes so this specific bug likely doesn't bite, but
  combined with an unverified assumption about `bun build --compile` binary parity for `formData()`,
  the safer v1 scope is **paste-only, no file upload** — fully satisfies the user's stated ask ("with
  \n one liner or a copy pasted from pem file").
- **CRLF corruption**: pasting from a Windows-originated clipboard through a browser textarea can
  introduce `\r\n`, which corrupts PEM parsing with an opaque `error in libcrypto` message — must
  normalize `\r\n` → `\n` on the pasted text before writing the temp file, regardless of detected format.
- **`list`'s enumeration has no existing implementation to reuse** — `findManagedStanza` only locates
  one alias by name; new code is needed (regex-scan for marker lines, or a loop over
  `listHostAliases`'s output filtered through `findManagedStanza`).
- **SIGKILL is an accepted residual risk** for the pasted-key temp file — a `finally` block cannot run
  on SIGKILL. Mitigated only by keeping the subprocess lifetime short (same `ConnectTimeout`-bounded
  window the password path already uses); documented as an accepted limitation, not silently ignored.

## Open questions

- [RESOLVED] Whether `status`/`list` may echo host/user/port — user chose "echo it in status only,
  list stays name-only" via `AskUserQuestion` this session. Baked into the plan below.
- [RESOLVED] `update` scope — HostName/User/Port only, not alias rename (rename is cleanly
  `remove`+`register` today, already achievable, not duplicated). Confirmed sound by context-gatherer.
- [RESOLVED] Credential-method selection lives inside the browser form (toggle), not a new CLI flag on
  `install` — confirmed the CLI call shape (`install(alias, {yes})`) does not need to change.
- Does `update` want its own distinct "nothing changed" signal when called with no host/user/port
  flags, or is that simply `INVALID_ARGS` at the CLI level (same as register's "--host and --user are
  required" pattern)? Lean: `INVALID_ARGS` — "at least one of --host/--user/--port is required" —
  consistent with the existing CLI-level validation convention, not a new error code.
- Should the "setup ⊥ registry" boundary get an enforcing test as part of this work? Lean: yes, small
  and cheap (grep `setup-ssh-alias*.ts` source for `from './registry'` / `from './transport'`, assert
  zero matches) — added as a low-risk addition to Phase 5's test suite, not a blocking question.

## Reference artifacts

- Live `ssh -v` transcript against `otomasiaja-server2` (100.103.182.84) — captured verbatim above,
  not saved to a separate file (no `.automation/` capture directory exists in this repo; the excerpt
  above is the complete load-bearing evidence).
- Context-gatherer validation pass (this session) — confirmed all file:line citations above against
  commit `b37fdd6` (current `origin/main` at research time).

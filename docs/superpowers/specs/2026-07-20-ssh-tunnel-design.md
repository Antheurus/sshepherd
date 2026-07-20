# SSH tunnel / port-forwarding (`tunnel` op group)

## Why

Researched Voltius (a Termius-alternative GUI SSH client) for feature ideas worth porting into
`sshepherd`. Most of its surface (local terminal, split panes, themes, terminal sharing) solves a
different problem — a human-facing GUI client — and doesn't apply to a zero-knowledge, agent-driven
CLI. One gap does apply directly and was explicitly asked for: **port forwarding / tunneling**.
Today `sshepherd` has zero way to reach a service that only listens on a remote box (a Postgres/Redis
instance bound to `localhost` on the server, an internal API with no public port) — the agent's only
options are ops that already exist per-service (`db query`, `files cat`, ...) or nothing. A tunnel
closes that gap generically, for any TCP service, without opening a new op per service type.

This is the first of five gaps identified in that research pass; the other four (jump-host support in
`setup ssh-alias`, a host-level process manager, ad-hoc command snippets, host↔host file transfer) are
each their own sub-project, planned separately after this one ships.

## Why this needs a new execution primitive, not a new `OpSpec` entry

Every existing op (49 of them, across 9 groups) shares one execution shape: `transport.ts` runs
`ssh <alias> <command>`, blocks until it exits, captures stdout within `timeoutSec`, and returns.
A tunnel (`ssh -N -L/-R/-D ...`) is `ssh` invoked specifically to run FOREVER (no remote command, `-N`
suppresses one) — it must keep running after the CLI process that opened it has already exited, which
the existing blocking-exec/timeout model cannot express. `tunnel open` needs to spawn a **detached**
background process, record it, and return immediately; `tunnel list`/`tunnel close` operate on that
record, not on a fresh ssh round-trip.

## New module: `src/tunnel.ts`

Mirrors the shape of `targets.ts`/`alias-meta.ts` (a dedicated module with its own state file), but for
runtime state instead of config — state lives in `~/.local/state/sshepherd/tunnels/<id>.json`
(`XDG_RUNTIME_DIR`-adjacent to where `audit.jsonl` already lives), one file per open tunnel:

```json
{
  "id": "t-a1b2c3",
  "alias": "otomasiaja-server3",
  "kind": "local",
  "localPort": 54217,
  "remoteTarget": "localhost:5432",
  "pid": 48213,
  "openedAt": "2026-07-20T10:00:00Z",
  "expiresAt": "2026-07-20T11:00:00Z"
}
```

- **`openTunnel(alias, spec)`**
  1. For `kind: "local"` / `"dynamic"`, resolve a free local port by binding an ephemeral listener
     (`localPort: 0`) and reading back the OS-assigned port, then releasing it immediately before ssh
     binds it for real — same pattern any "find a free port" utility uses; a race between release and
     ssh's own bind is possible but exceedingly unlikely on localhost, and `openTunnel` surfaces
     `TUNNEL_PORT_TAKEN` if ssh's own bind fails so the caller can retry.
  2. Build the ssh invocation per kind:
     - `local`: `ssh -N -L <localPort>:<remoteTarget> <alias>`
     - `remote`: `ssh -N -R <remote host:port>:<local host:port> <alias>` — for this kind, `--remote`
       (the flag name is unchanged for consistency) supplies the BIND address on the alias's own network
       (e.g. `0.0.0.0:8080` to expose it beyond the alias's own loopback), and a second required flag,
       `--local <host:port>`, supplies what's being exposed FROM the operator's machine (e.g.
       `localhost:3000`, a dev server running locally). `remote` is the only kind needing both flags,
       since it's the only kind forwarding traffic in the opposite direction from `local`/`dynamic`.
     - `dynamic`: `ssh -N -D <localPort> <alias>`
  3. Wrap the whole invocation with `timeout <durationSec>` (defaults to 3600s / 1 hour, overridable via
     `--duration`, capped the same way `MAX_TIMEOUT_OVERRIDE_SEC` caps other ops) — `sshepherd` itself has
     no standing daemon that could actively enforce an expiry from outside, so the tunnel process is made
     to self-terminate; this is the only reliable way to guarantee "auto-expire" without a background
     service.
  4. `Bun.spawn` **detached**, `stdio: 'ignore'`, `unref()`'d — the child must survive the parent CLI
     process exiting. Write the state JSON, return `{id, localPort, remoteTarget, expiresAt}`.
- **`listTunnels()`** — reads every state file, checks liveness via `kill -0 <pid>` (throws `ESRCH` if
  dead), silently prunes (deletes the state file for) any dead or past-`expiresAt` entry, returns the
  rest with `remainingSec`. This is where expired-but-not-yet-self-terminated entries (e.g. the `timeout`
  wrapper is still winding down) get cleaned up opportunistically, matching how `hosts list` already
  tolerates a stale/missing config file rather than erroring.
- **`closeTunnel(id)`** — `kill -9 <pid>` **by the exact PID recorded in the state file**, never a
  name-pattern kill (`pkill`) — same lesson `orchestrated-development`'s own learnings file already
  captures about backgrounded servers: a `timeout`-wrapped `ssh` child has a different process name than
  the launch command, so pattern-matching would miss it. Removes the state file after a successful kill;
  `TUNNEL_NOT_FOUND` if the id has no state file, treated as already-closed (idempotent).

## CLI surface

New registry group `tunnel`, three ops:

```
sshepherd tunnel open <alias> --kind local|remote|dynamic --remote <host:port> [--duration <sec>] --yes
sshepherd tunnel list
sshepherd tunnel close <id> --yes
```

- `--remote <host:port>` is required for `local`/`remote`, omitted for `dynamic` (a SOCKS proxy has no
  single target). `--local <host:port>` is required ONLY for `remote` kind (what's being exposed from the
  operator's machine) and rejected as `INVALID_ARGS` for `local`/`dynamic` (where the local side is
  always the auto-assigned port, never agent-supplied). `buildRemote`'s arg validation documents this
  per-kind rather than trying to force one flag name to mean the same thing in every direction.
- `open`/`close` are `mutating: true` (gated by `--yes` via `confirmGate`, logged via `auditMutating`,
  same as every other mutating op in the registry). `list` is non-mutating and host-local, same
  classification as `hosts list`.
- All three return through the standard `Envelope<T>` shape used by every other registry op (not
  `SetupResult`, since this isn't a `setup` config-writing command — it's a live op producing runtime
  state), with `data` holding the fields above and nothing else.

## Zero-knowledge boundary

`tunnel open`'s response carries `{id, alias, localPort, remoteTarget, expiresAt}` — `alias` echoes back
only the name (as every op already does), never the alias's own `HostName`/`User`/`Port`. `remoteTarget`
(the `--remote host:port` the agent supplies) is **not** the alias's connection identity — it's a
description of where on the alias's own network to forward to (almost always `localhost:<port>`, since
the overwhelmingly common case is reaching a service bound to the box itself), so it stays free-text the
agent supplies directly, the same way `db query`'s SQL text or `config get`'s path argument are
agent-supplied without violating the zero-knowledge invariant — the invariant is specifically about the
alias's own transport tuple, not about every string an op accepts.

## Error codes

New `SshErrorCode`-style additions scoped to this group: `TUNNEL_PORT_TAKEN` (ssh's own bind failed after
port pre-selection), `TUNNEL_NOT_FOUND` (close on an unknown/already-closed id — treated as a no-op
success, not a hard error, matching idempotent-remove precedent elsewhere in the codebase),
`TUNNEL_SPAWN_FAILED` (the detached `Bun.spawn` itself failed to start, e.g. `ssh` binary missing).

## Testing

- `tunnel.ts` unit tests: port pre-selection returns a bindable port; state file round-trips through
  `openTunnel`→`listTunnels`→`closeTunnel`; `listTunnels` prunes a state file whose PID doesn't exist
  (simulate via a state file pointing at PID `1` after that process would legitimately be gone — or more
  reliably, spawn+kill a real short-lived process first and confirm `listTunnels` prunes it) and one past
  `expiresAt`; `closeTunnel` on an unknown id returns success (idempotent), never throws.
- Registry-level tests for the three `tunnel` ops mirroring the existing `hosts`/`db` op test shape:
  arg validation (missing `--remote` on `local`/`remote` kind → `INVALID_ARGS`), mutating gate (`open`/
  `close` refuse without `--yes`), envelope shape (no `alias`-identity leak beyond the name).
- A live smoke step (added to `scripts/smoke.sh`, matching the sshepherd-v1 precedent of a
  Docker-fixture-driven smoke suite marked BUILT-BUT-NOT-RUN until a Docker host is available): open a
  local-forward tunnel against the disposable sshd fixture to a port the fixture listens on, curl through
  the forwarded local port, confirm the response, then close and confirm the port is released.

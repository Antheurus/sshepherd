# Jump host / `ProxyJump` support in `setup ssh-alias`

## Why

Second of five feature gaps found comparing `sshepherd` against Voltius (a Termius-alternative GUI SSH
client researched for feature ideas): Voltius supports jump-host chains as a first-class alias property.
`sshepherd` today has no way to register an alias that reaches its target through a bastion — OpenSSH's
own `ProxyJump` directive works fine if hand-added to `~/.ssh/config`, but `setup ssh-alias register`/
`update` don't know about it, so a bastion setup has to be edited outside `sshepherd`'s own tooling. That
breaks the "everything is managed through `sshepherd`" story the rest of the `setup` group already
delivers for `HostName`/`User`/`Port`/`IdentityFile`.

## Assumption surfaced (no user confirmation available — this is a one-shot subtask; flag for review)

Assuming the natural, lowest-friction design: `ProxyJump` targets **another already-registered
`sshepherd` alias by name**, never a raw host/user/port. This is both the zero-knowledge-correct choice
(no new place for a connection tuple to leak into agent-visible output) and exactly how OpenSSH's own
`ProxyJump` directive already works — it accepts either a `user@host:port` spec OR the name of another
`Host` block in the same config file, and `sshepherd`-managed aliases are already `Host` blocks in
`~/.ssh/config`. If this assumption is wrong (e.g. the real need is jumping through a box that will never
itself be a registered alias), the design changes to accept a raw spec and that reopens the
zero-knowledge question — flagging this explicitly rather than guessing further.

## CLI surface

Extends the existing `register`/`update` actions — no new sub-group, no new action, matching how `desc`/
`tags`/`network` extended `update` rather than getting their own command:

```
sshepherd setup ssh-alias register edge-box --host 10.0.0.5 --user deploy \
  --proxy-jump bastion-1 --yes
sshepherd setup ssh-alias update edge-box --proxy-jump bastion-1,bastion-2 --yes
sshepherd setup ssh-alias update edge-box --clear-proxy-jump --yes
```

- `--proxy-jump <alias>[,<alias>...]` — one or more already-registered alias names, comma-separated for a
  multi-hop chain (OpenSSH's own `ProxyJump a,b` syntax, walked left-to-right: connect to `a`, then from
  there to `b`, then to the target). Every named alias must already have a managed stanza in
  `~/.ssh/config` at write time — refused with a new code `PROXY_ALIAS_NOT_FOUND` (naming the specific
  missing alias) otherwise, so a typo fails loud instead of writing a `ProxyJump` line OpenSSH will only
  fail on later, opaquely, at connect time.
- `--clear-proxy-jump` (boolean, `update` only) — removes an existing `ProxyJump` line. Needed because
  `upsertStanzaProperty` (the existing helper `update` already uses for `HostName`/`User`/`Port`) only
  ever adds-or-replaces a property line, never removes one — `ProxyJump` is the first OPTIONAL stanza
  property `update` handles (`HostName`/`User` are required, `Port` always has a default), so this is
  also the first time `update` needs a genuine removal path. New small helper `removeStanzaProperty`
  alongside `upsertStanzaProperty` in `setup-ssh-alias.ts`, same file, same pattern (locate the property
  line inside the stanza block, splice it out if present, no-op if absent).
- `--proxy-jump` and `--clear-proxy-jump` together in the same call is `INVALID_ARGS` (contradictory
  intent — set and clear in one call is always a caller mistake, not a case worth guessing at).

## Cycle prevention

Before writing, walk the proposed chain and refuse (`PROXY_JUMP_CYCLE`) if the alias being
registered/updated appears anywhere in its own chain, directly or transitively through another alias's
already-recorded `ProxyJump`. OpenSSH itself has no such guard — a cycle just hangs or fails with an
opaque connection-timeout at connect time, far from the config-writing moment that actually caused it.
Implementation: `resolveProxyChain(configPath, aliasBeingSet, [proposed names])` follows each named
alias's own `ProxyJump` line (if any) up to a small fixed depth (e.g. 8 hops — matching the kind of
sane upper bound `MAX_TIMEOUT_OVERRIDE_SEC` already sets elsewhere for a different runaway-input class),
refusing with `PROXY_JUMP_CYCLE` the moment the alias being modified reappears, or `PROXY_JUMP_TOO_DEEP`
if the depth cap is hit without a cycle (almost certainly a mistake either way, since a real bastion chain
longer than a handful of hops is not a normal topology).

## Zero-knowledge boundary

The `ProxyJump` line written into `~/.ssh/config` is `ProxyJump <alias>[,<alias>]` — alias names only,
resolved by OpenSSH itself exactly the way `HostName`/`User`/`Port` already are. No new field is added
anywhere that could carry a raw host/user/port; the only new agent-visible surface is a list of names,
which is the same class of information `hosts list` already exposes today.

## Exposure

`setup ssh-alias status <alias>` — already the one documented exception surface that echoes
`host`/`user`/`port`/`hasKey` (never expanded to `hosts list`/`hosts info`, which stay name-only) — gains
a `proxyJump: string[] | null` field, parsed the same way `stanzaPropertyValue(block, 'ProxyJump')` reads
any other property, split on `,`. This mirrors exactly how `desc`/`tags`/`network` were added to `status`
in the alias-metadata design (`2026-07-20-alias-metadata-rename-design.md`) rather than to `hosts list`.

## Testing

- `setup-ssh-alias.ts` `register`/`update`: `--proxy-jump` with 1 and 2+ existing aliases writes the
  correct comma-joined `ProxyJump` line; missing bastion alias → `PROXY_ALIAS_NOT_FOUND` naming it;
  `--clear-proxy-jump` removes an existing line and is a no-op (not an error) when none exists;
  `--proxy-jump` + `--clear-proxy-jump` together → `INVALID_ARGS`.
- Cycle detection: direct self-reference (`update a --proxy-jump a`) → `PROXY_JUMP_CYCLE`; 2-hop cycle
  (`a`'s chain already includes `b`, then `update b --proxy-jump a`) → `PROXY_JUMP_CYCLE`; a chain at
  exactly the depth cap → allowed; one hop past it → `PROXY_JUMP_TOO_DEEP`.
- `status`: `proxyJump` is `null` for an alias with no `ProxyJump` line, and the correct parsed array
  otherwise.
- A live smoke step (added alongside the tunnel group's smoke addition in `scripts/smoke.sh`): register
  two disposable aliases against the sshd fixture, one with `--proxy-jump` pointing at the other, run
  `hosts test` through the chain, confirm it connects — the only way to prove a written `ProxyJump` line
  is actually connectable, not just syntactically present.

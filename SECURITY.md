# Security

## Threat model

### The zero-knowledge invariant

`sshepherd` is built so that the process running it — and any agent driving it — never
holds a credential. It only ever accepts a *name*: an ssh alias, a Postgres target name, or
a deploy recipe name. Every one of those names is declared ahead of time, outside the
process, in a file the user controls:

- `~/.ssh/config` — the ssh alias, including `HostName`/`User`/`Port`/`IdentityFile`.
- `~/.config/sshepherd/targets.toml` — a Postgres target's ssh alias, container/compose
  location, database user and name (never a database password).
- a recipe TOML — a deploy's steps, referencing an ssh alias.

`sshepherd` shells out to the system `ssh` binary for every remote operation (never the
`ssh2` npm library), so authentication itself is entirely OpenSSH's responsibility, running
in OpenSSH's own trusted code path. The `Envelope<T>` response type has no host/user/port/ip
field at all — that's a structural guarantee, not a redaction step that could be bypassed.
ssh's own stderr is discarded in full before any error reaches the caller (never logged,
never surfaced) and replaced with a static message keyed by a small error-code enum,
because stderr phrasing varies by OpenSSH version and locale and can leak a hostname no
allowlist would reliably catch.

**What this guarantees:** the `sshepherd` binary, its stdout, its audit log, and anything an
agent driving it can see, is structurally incapable of exposing a host, user, port, IP,
password, or private key — because that data never enters the process at all.

**What this does not guarantee:** `sshepherd` cannot protect `~/.ssh/config` itself, the
private keys `ssh-agent` holds, or the machine's own OS-level access controls. Securing
those — file permissions on `~/.ssh/config` and `~/.ssh/*`, which keys are loaded into
`ssh-agent`, who has shell access to the machine running `sshepherd` — remains the user's
responsibility, exactly as it would be for a bare `ssh` invocation. `sshepherd` is a
narrower, safer interface *on top of* an ssh setup the user already trusts; it is not a
replacement for that setup's own security.

### Read-only by default, mutating behind confirm + audit

Every op in the registry (`src/registry.ts`) is tagged `mutating: true` or left untagged
(read-only). A mutating op — `services restart`, `config put`, `deploy run`, `security
harden`, `files upload`, and similar — refuses to touch ssh at all unless invoked with
`--yes`; there is no interactive prompt to intercept or spoof, and no ambient "yes" state
that persists between calls. Every mutating op, whether it runs or is refused, writes one
line to the audit log (`~/.local/state/sshepherd/audit.jsonl`, created `0700`/`0600`):
timestamp, alias, command, an `args_hash` (a hash of the argument values, never the raw
values themselves — an argument can be a file path or SQL fragment that shouldn't be
sitting in a log verbatim), and outcome (`ok` / `error` / `refused`). Read-only ops never
prompt and never write an audit line — they can't mutate anything, so there's nothing to
gate or record.

`deploy run --dry-run` is the one exemption: it plans a recipe locally and executes nothing,
so it needs no `--yes` and touches no ssh connection.

### Database read-only enforcement — three layers

The `db` group only ever runs `SELECT`-shaped queries, enforced across three independent
layers (`references/db.md` has the full detail):

1. **A read-only database role, engine-side.** The Postgres role declared in a pg-target
   should have SELECT-only grants — this is the real boundary. It's the only layer that can
   catch a writable CTE or a volatile function; no client-side parser can reliably detect
   either.
2. **A read-only transaction wrapper.** Every query `sshepherd` sends is wrapped in
   `BEGIN TRANSACTION READ ONLY; <sql>; ROLLBACK;` — defense in depth, not a substitute for
   layer 1.
3. **A local SQL parser check (`node-sql-parser`).** A fast, advisory rejection of an
   unambiguously non-SELECT top-level statement, plus a separate guard that rejects any bare
   `;` in `db query`'s free-text SQL before it's parsed at all — closing a real injection
   shape found during development, where a crafted payload could close the query wrapper's
   parenthesis early and append a `COMMIT` to end the read-only transaction ahead of an
   injected write. This layer is a UX guardrail, not the security boundary; layer 1 is.

Treat layers 2 and 3 as belt-and-suspenders. If a pg-target's declared database user is not
genuinely read-only at the engine level, `sshepherd`'s other protections are not a
substitute.

### No raw exec

There is no `sshepherd exec "<arbitrary command>"`. Every op is a curated, registry-defined
operation with a fixed argument shape. The one place a raw shell command can run is a
`shell`/`compose`/`migrate` step inside a deploy recipe TOML — a file the user authors and
controls ahead of time, versioned like any other config, never free text an agent
constructs mid-session. Every value interpolated into a remote command anywhere in the
codebase goes through a single shell-quoting helper (`src/quote.ts`); no remote command is
ever built by string-concatenating an unquoted value.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

`sshepherd` is pre-1.0; security fixes land on the latest `0.x` release. There is no
long-term-support branch yet.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security report.

Preferred: use
[GitHub's private vulnerability reporting](https://github.com/Antheurus/sshepherd/security/advisories/new)
on this repository.

Backup: email mispaqul.attoriq@gmail.com with a description of the issue, steps to
reproduce, and the affected version. A response should be expected within a few days.

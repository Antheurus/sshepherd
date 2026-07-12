# sshepherd

[![CI](https://github.com/Antheurus/sshepherd/actions/workflows/ci.yml/badge.svg)](https://github.com/Antheurus/sshepherd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Bun](https://img.shields.io/badge/runtime-bun-fbf0df?logo=bun)](https://bun.sh)

A zero-knowledge SSH ops CLI for Claude Code and any other agent or terminal — server
health checks, docker/systemd control, log tailing, config edits, read-only Postgres
introspection, and declarative deploys, without ever letting the agent see a password,
private key, hostname, user, or port.

## Why

Two pains motivated this: an agent driving real infrastructure either (a) ends up holding
credentials it has no business seeing — a host, a user, a private key, a password, all
sitting in its context window and its tool-call log — or (b) gets handed raw, messy remote
output (`ssh box 'df -h'`, a wall of `docker logs`) that it then has to parse ad hoc every
single time, with no consistent shape and no guardrails against a destructive command.

`sshepherd`'s answer is a **one-transport core + one-envelope contract**: every op shells
out to the system `ssh` binary through a single execution path (`src/transport.ts`), and
every response comes back as the same typed `Envelope<T>` (`ok`, `alias`, `data`, `error`),
never a raw terminal dump. The agent never types a hostname or password; it types a *name*
— an ssh alias, a Postgres target, a deploy recipe — that resolves entirely outside the
process.

A [Claude Code](https://claude.com/claude-code) skill for `ssh`/`devops`/`cli` server
operations, built `zero-knowledge` from the ground up: safe `postgres` introspection,
declarative `deploy` recipes, and a `security` posture check, all reachable as
`claude-skills`/`agent-skills` without the agent ever handling a credential.

## Install

**a. As a Claude Code skill via `npx skills add`:**

```bash
npx skills add Antheurus/sshepherd
```

**b. As a Claude Code plugin marketplace:**

```
/plugin marketplace add Antheurus/sshepherd
```

**c. Prebuilt release binary** — no Bun required at runtime. Grab one from
[Releases](https://github.com/Antheurus/sshepherd/releases) for your platform
(`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`), verify the SHA-256 against the
published checksum, then run it directly:

```bash
curl -LO https://github.com/Antheurus/sshepherd/releases/latest/download/sshepherd-linux-x64
curl -LO https://github.com/Antheurus/sshepherd/releases/latest/download/sshepherd-linux-x64.sha256
sha256sum -c sshepherd-linux-x64.sha256
chmod +x sshepherd-linux-x64
./sshepherd-linux-x64 --version
```

Each release binary also carries a
[GitHub Actions build-provenance attestation](https://github.com/Antheurus/sshepherd/attestations) —
verify it with `gh attestation verify sshepherd-linux-x64 --repo Antheurus/sshepherd`.

**d. Build from source.** Requires [Bun](https://bun.sh) and [`just`](https://github.com/casey/just).

```bash
git clone https://github.com/Antheurus/sshepherd.git
cd sshepherd
just build          # -> dist/sshepherd
```

`just build` installs dependencies and compiles the binary. Other targets: `just test`,
`just check` (typecheck + lint), `just smoke` (rebuilds, then runs a live E2E smoke suite
against a disposable local sshd + Postgres fixture — see [`CONTRIBUTING.md`](./CONTRIBUTING.md)).

## The zero-knowledge model

The agent passes only a **name**: an ssh alias (`lms-server`), a pg-target name (`prod`),
or a recipe name (`demo`). Every alias/target/recipe is declared once, ahead of time —
`~/.ssh/config`, `~/.config/sshepherd/targets.toml`, or a recipe TOML — never on the
command line and never inside a prompt an agent constructs.

OpenSSH resolves the real connection tuple (`HostName`/`User`/`Port`/`IdentityFile`)
internally; `sshepherd` shells out to the system `ssh` binary (never the `ssh2` npm
library), so credential handling stays entirely inside OpenSSH's own trusted code path.
Every response echoes back only the `alias` it was given — there is no host/user/port/ip
field anywhere in the response type, structurally, not by convention. Database access
follows the same rule: a pg-target resolves to *how* to reach `psql` on a host, never a
database password — `psql` runs inside the target container, authenticated by
peer/trust/`.pgpass` that already lives on the remote.

## Usage

```
sshepherd <group> <action> [positionals...] [--flag value]
```

Nine command groups — `hosts`, `check`, `logs`, `services`, `deploy`, `config`, `db`,
`files`, `security` — 52 ops total. The full command matrix, every op's arguments, output
shapes, and gotchas live in [`SKILL.md`](./SKILL.md), which doubles as the Claude Code
skill definition:

```bash
./dist/sshepherd --help                 # list groups
./dist/sshepherd check --help           # list actions + flags for one group
./dist/sshepherd check overview lms-server
```

Output is JSON to stdout by default (add `--pretty` for a human table/key-value view).

## What sshepherd NEVER does

- **Never reads `~/.ssh` private keys or any key material.** Authentication happens
  entirely inside the system `ssh` binary and `ssh-agent`; `sshepherd` never opens, parses,
  or transmits a private key, passphrase, or password.
- **Zero outbound network calls except the SSH connections you explicitly request.** No
  telemetry, no phone-home, no analytics, no update checker silently pinging a server.
  Every network call this tool makes is an `ssh`/`scp`-equivalent round trip to an alias
  you declared.
- **No arbitrary remote exec.** There is no `sshepherd exec "<any command>"` escape hatch —
  only a fixed set of curated, read-only or confirm-gated ops, plus named, versioned recipe
  steps for deploys. A raw shell command can only run as an authored step inside a recipe
  TOML file you wrote and control, never as free text typed by an agent mid-session.
- **Never writes a host, user, port, or IP into any output, log, or audit line.** Every
  response echoes back only the alias/target/recipe *name* you passed in; the audit log
  (`~/.local/state/sshepherd/audit.jsonl`) records a timestamp, alias, command, and a hash
  of the arguments — never the raw argument values.
- **The only runtime dependency is `node-sql-parser`**, used to give `db query` a local,
  advisory SELECT-only check before anything reaches the network. No other npm package runs
  at runtime — `bun build --compile` ships a single ~60MB binary with nothing to
  `npm install`.

See [`SECURITY.md`](./SECURITY.md) for the full threat model, including where the
zero-knowledge guarantee's boundary sits (it's OpenSSH's own security, not sshepherd's, that
protects `~/.ssh/config` and the agent) and how mutating ops are gated.

## Call the binary by absolute path

Like most compiled CLIs installed for a single project, `dist/sshepherd` is not placed on
`PATH`. When wiring this up as a Claude Code skill, call it by its absolute path
(`SKILL.md` does this consistently) — every example in this README uses the bare
`sshepherd` name for brevity; substitute the real path when invoking.

## Development

```bash
just install    # bun install
just build      # compile dist/sshepherd
just test       # bun test (unit tests, no live ssh required)
just check      # typecheck + lint
just smoke      # rebuild + run scripts/smoke.sh against a disposable sshd+postgres fixture
```

`src/registry.ts` is the single source of truth for every op (group, action, args, whether
it mutates); `src/transport.ts` is the one zero-knowledge execution path every op runs
through; `src/cli.ts` parses argv and dispatches. See [`CONTRIBUTING.md`](./CONTRIBUTING.md)
for setup, the pre-PR checklist, and where things live.

## License

[MIT](./LICENSE)

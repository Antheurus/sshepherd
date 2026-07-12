---
feature: sshepherd-v1
created: 2026-07-12
updated: 2026-07-12T15:10Z
status: ready-for-plan
---

# Research — sshepherd v1

Facts assembled from three parallel research agents (command scope, SSH implementation,
OSS distribution) run 2026-07-12 in the cc-toriq session, plus live inspection of the
`anywrite` repo (the packaging template). Availability claims were checked live at
research time (npm HTTP + GitHub search API).

## Definition of done

> The user's ask, verbatim intent: "it needs to be safe in env but agent can run it...
> zero-knowledge about the creds... a super zero-trust... server checking, server
> configuration to project like deploying, understand its db... full fledged open source
> just like our anywrite, make it easy to find for others."

Done means: a public `Antheurus/sshepherd` GitHub repo containing a compiled Bun/TS CLI
covering all 9 command groups, a root `SKILL.md` installable via
`npx skills add Antheurus/sshepherd`, prebuilt release binaries, and the full trust-signal
set (SECURITY.md, no-telemetry, checksums, provenance). Verified by unit tests (mocked
spawn) + an E2E smoke suite against a local disposable sshd container.

## Verbatim captures

### Decision: SSH transport (impl-research, confidence 9/10)

Shell out to system `ssh` via `Bun.spawn` — **never** the `ssh2` npm library:

- Creds never enter our process (key material, agent handshake, `~/.ssh/config`
  resolution all happen inside OpenSSH).
- `~/.ssh/config` incl. `Include`/`Match`/`ProxyJump` is resolved natively; ssh2 parses
  none of it.
- ssh2 pulls optional native addon `cpu-features` (`.node`) which breaks
  `bun build --compile` (oven-sh/bun#11947, opennextjs-cloudflare#1226).

ControlMaster multiplexing, lifecycle managed explicitly:

```
# open master (background, no command):
ssh -o BatchMode=yes -o ConnectTimeout=10 \
    -o ControlMaster=auto -o ControlPath=<socket> -o ControlPersist=60 \
    -M -N -f <alias>
# each op reuses it:
ssh -o BatchMode=yes -o ControlPath=<socket> <alias> -- <remote-cmd>
# teardown:
ssh -o ControlPath=<socket> -O exit <alias>
```

- `-o BatchMode=yes` mandatory (spawned child can't answer prompts; fail fast instead of hang).
- ControlPath socket: private `0700` dir, opaque name (never `%h`/`%r` tokens), total
  path < 104 chars (macOS Unix-socket cap; 108 Linux).
- `-o LogLevel=ERROR`; never `-o StrictHostKeyChecking=no`; never `-t`.
- ssh-agent works via inherited `SSH_AUTH_SOCK` — nothing to wire.
- Stale-socket defense: `-O check` / `-O exit` at startup; ControlPersist=60 backstop.

### Decision: zero-knowledge output hygiene (impl-research)

- Remote command stdout is the ONLY thing that enters the envelope's `data`.
- ssh transport stderr is **discarded entirely** — classified into an error enum, text
  never surfaced (redaction allowlists miss OpenSSH version/locale variations).
- `ssh -G <alias>` dumps HostName/User/Port/IdentityFile — use only internally for
  alias-exists validation (check exit status/presence, don't parse values into variables);
  never echo any field.
- The envelope echoes only the alias back, never the resolved connection tuple.
- **Conflict resolution (orchestrator):** scope-research proposed `hosts list` returning
  HostName/User/Port/IdentityFile per alias — hygiene rule wins; `hosts list` returns
  alias names only.

### Decision: error classification (impl-research)

`ssh` exits **255** for its own failures; otherwise returns the remote command's exit code.

| Enum | Detection |
|---|---|
| `UNKNOWN_ALIAS` | `ssh -G` validation fails before any connection |
| `CONNECT_TIMEOUT` | exit 255 + ConnectTimeout elapsed |
| `AUTH_FAILED` | exit 255 + `Permission denied` in (discarded) stderr |
| `HOST_KEY_MISMATCH` | exit 255 + `REMOTE HOST IDENTIFICATION HAS CHANGED` |
| `SSH_TRANSPORT_ERROR` | exit 255, unclassified |
| `COMMAND_FAILED` | non-255 remote exit code (carried in envelope) |
| `COMMAND_TIMEOUT` | our wall-clock timeout / remote `timeout <n>` wrapper fired |

Timeouts: `-o ConnectTimeout=10` + wrap remote command in `timeout <n>` (kills the remote
process, not just local abandonment) + local wall-clock abort.

### Decision: response envelope (scope-research, per one-envelope rule)

```json
{ "ok": true, "alias": "lms-server", "ran_at": "2026-07-12T15:00:00Z",
  "command": "check overview", "duration_ms": 412, "data": { }, "error": null }
```

- All sizes in **bytes** (never `3.9Gi` strings).
- Logs as line objects `{ts, stream, text}` with `next_since` paging cursor.
- Computed verdict fields where the survival-pattern conclusion is derivable
  (e.g. `dead_end_risk: true` when disk >90% or memory pressure sustained).
- Ports parsed into `{host, container, proto}` objects, never raw `0.0.0.0:8080->80/tcp`.

### Decision: output shaping per remote command (impl-research)

Prefer native JSON flags; NDJSON must be split on newlines before parse:

| Command | Flag | Shape |
|---|---|---|
| `docker ps`/`images`/`stats` | `--format json` (23.0+) | NDJSON |
| `docker inspect` | native | JSON array |
| `docker compose ps` | `--format json` | NDJSON |
| `systemctl list-units`/`show` | `-o json` | JSON |
| `journalctl` | `-o json` (+ `--output-fields`) | NDJSON |
| `ss` | `-j` | JSON |
| `ip` | `-j` | JSON |
| `lsblk` / `findmnt` | `-J` | JSON |

No native JSON (write small TS parsers, shapes matched to `jc`'s documented schemas as
reference only — `jc` is Python, never a runtime dep): `df`, `free`, `uptime`, `ps aux`,
`du`, `ls`. Conventions: iproute2 lowercase `-j`, util-linux uppercase `-J`, systemd
`-o json`, docker `--format json`.

### Decision: ops registry architecture (impl-research + coding rules)

Each curated op is one registry entry:

```ts
{ group, name, args, remoteTemplate, output: "native-json" | "ndjson" | Parser<T>,
  mutating: boolean, errorMap }
```

Adding an op = one registry row (registry-dispatch pattern; matches runner/worker rule).
One quoting function for all interpolation: wrap in single quotes, escape embedded as
`'\''`. Never string-concat values into remote commands.

### Decision: DB access (impl-research, confidence 7/10)

- Run the client ON the remote via `ssh <alias> -- docker compose -f <path> exec -T db
  psql -U <user> -d <db> -v ON_ERROR_STOP=1 -qAt -c '<query>'` (`-T` = no TTY, required).
  Compose-hosted PG usually has no published host port, so local tunnels often can't
  reach it; running remotely also avoids exposing the DB on a local port.
- Read-only enforcement is **layered, engine-side boundary first**:
  1. Read-only DB role (`GRANT pg_read_all_data` PG14+ / `GRANT SELECT`, plus
     `ALTER ROLE ro SET default_transaction_read_only = on`) — catches writable CTEs
     (`WITH x AS (INSERT…) SELECT`) and volatile functions that any parser misses.
  2. Transaction wrapper (`BEGIN; SET TRANSACTION READ ONLY; …; ROLLBACK;`) — defense in
     depth, NOT a security boundary (PG docs: session can revoke it on itself).
  3. Pure-JS `node-sql-parser` statement-type check — UX guardrail only (fast, friendly
     rejection). Never `libpg_query` (native bindings → `.node` → breaks bun compile).
- `<pg-target>` is a pre-declared named target (like an SSH alias, for DBs) so the agent
  never passes DB credentials. v1 is Postgres-only.

### Decision: command inventory, 9 groups (scope-research)

Full table in the session transcript; summary with mutating ops marked (†):

- `hosts` — list (alias names only), test (connect + latency + auth method), info
  (hostnamectl/uname/os-release/nproc/uptime).
- `check` — overview (bundled denominators: nproc/free/df/uptime/swapon/ulimit/PSI),
  mem, disk (+inodes, top-du), cpu (loadavg vs cores, top procs), ports (ss -tlnp),
  oom-history (dmesg + per-container OOMKilled/RestartCount), kernel (swappiness/
  overcommit/swapaccount/file-max).
- `logs` — docker (--tail/--since/--timestamps), service (journalctl -u -o json),
  nginx (error|access), docker-daemon (journalctl -u docker; feeds exit-137 differential).
- `services` — ps (docker ps -a + inspect merge: health/restarts/oom/limits/compose
  labels), stats, inspect (cap audit + exit-137 evidence in one call), compose-ps,
  restart†, systemctl <unit> status|restart†|reload†|start†|stop†, healthcheck
  (.State.Health + last probes).
- `deploy` — run† <recipe> [--dry-run], status (live image tag/digest + git SHA),
  rollback† (only if declared), logs, migrate†.
- `config` — get (allowlisted paths), validate (nginx -t/caddy validate/sshd -t/
  compose config -q), put† (--from local, backup-first mandatory), reload†.
- `db` — list, tables, activity (pg_stat_activity + pg_blocking_pids rollups),
  connections (vs max_connections), slow (pg_stat_statements if present), size.
- `files` — ls, cat (size guard; env files masked by default, `--reveal <key>` names
  the key + logs reason), tail, download, upload† (--backup), disk-usage.
- `security` — ssh-audit (sshd_config posture), listeners, authorized-keys
  (fingerprints only), fail2ban, harden† (--keep-session: backup + sshd -t + reload,
  refuses without a confirmed alternate path in — survival surface D).

Escape-hatch doctrine: no `exec "<string>"` ever. Novel needs = author a **named recipe
step** (reviewed, versioned). Interactive tools (vim/top/REPLs) and package installs are
explicitly out of scope; plain `ssh <alias>` remains the human break-glass. Multi-host
fan-out deferred (one alias per invocation keeps the audit trail clean).

### Decision: deploy recipes (scope-research; Kamal-style declarative)

TOML, two-tier lookup: in-repo `.sshepherd/deploy.<name>.toml` (preferred, versioned
with the project) or central `~/.config/sshepherd/recipes/<project>.<name>.toml`.

```toml
name = "lms-prod"
alias = "lms-server"
workdir = "/opt/lms"
description = "Laravel LMS — code baked into image, migrate needs rebuild"

[[step]]
name = "pull-code"
kind = "shell"                  # typed: shell | compose | healthcheck | http-probe | wait | migrate
run  = "git pull --ff-only"
[[step]]
name = "build-image"
kind = "compose"
run  = "build app"
[[step]]
name = "up"
kind = "compose"
run  = "up -d"
[[step]]
name = "migrate"
kind = "shell"
run  = "docker compose run --rm app php artisan migrate --force"
depends_on = "up"
[[step]]
name = "verify"
kind = "healthcheck"
target = "app"
timeout = "60s"

[rollback]
strategy = "previous-tag"       # or "compose-file"; absent => rollback refuses, never guesses
```

- `--dry-run` prints the fully resolved plan as JSON (every step, exact remote command,
  workdir, which steps mutate) and executes nothing.
- The user's real LMS gotcha ("migrations need a rebuild, not just artisan migrate") is
  expressible as ordered `depends_on` data.
- `shell` steps are the single named pressure valve: raw shell allowed only inside a
  declared, named, versioned recipe step (pyinfra `server.shell` model).

### Decision: OSS packaging (oss-research; anywrite layout verified live)

- `SKILL.md` at repo **root** — `npx skills add Antheurus/sshepherd` does a two-level
  walk, shallower wins. skills.sh is the discovery site.
- Do NOT commit `dist/` — GitHub Releases with `darwin-arm64`, `darwin-x64`,
  `linux-x64`, `linux-arm64` + SHA-256 checksums + GitHub Actions build-provenance
  attestations (`actions/attest-build-provenance`). `just build` = from-source fallback.
- `.claude-plugin/marketplace.json` + `plugin.json` → `/plugin marketplace add
  Antheurus/sshepherd`.
- Trust signals (mandatory post-ToxicSkills — Snyk found 36.8% of 3,984 marketplace
  skills flawed; SSH keys were the literal AMOS-infostealer payload target):
  SECURITY.md (disclosure contact), README "What sshepherd NEVER does" section (never
  reads `~/.ssh` private keys, zero outbound calls except user-initiated SSH, no
  telemetry, no arbitrary exec), stated dep count, dry-run everywhere, short
  human-reviewable SKILL.md.
- GitHub topics: `claude-code`, `claude-skills`, `claude-code-skills`, `agent-skills`,
  `ssh`, `devops`, `cli`, `security`.
- Awesome-list PRs (hesreallyhim/awesome-claude-code 36.8k★; ComposioHQ + travisvn
  awesome-claude-skills) only AFTER some stars. Skip ClawHub deliberately.
- Name availability at research time: `sshepherd` free on npm, `Antheurus/sshepherd`
  free, zero starred GitHub collisions. Avoid: agentssh, sshield (starred collisions),
  safeshell (npm taken).

## Code intelligence

No existing codebase — greenfield. The architectural template is the sibling repo:

- `~/Documents/PROJECT_MISPAQUL_ATTORIQ/anywrite/` — layout to mirror: root `SKILL.md`,
  `README.md`, `CONTRIBUTING.md`, `LICENSE` (MIT), `package.json` (private, bin →
  `./dist/<name>`), `tsconfig.json`, `biome.jsonc`, `justfile` (build/test/check/smoke),
  `.github/workflows/` (CI + release), `references/`, `scripts/smoke.sh`, `src/`,
  `docs/{progress,changelog}.md`. Build: `bun build ./src/cli.ts --compile --outfile
  ./dist/<name>`. Zero runtime npm deps in anywrite; sshepherd needs at most 2 pure-JS
  runtime deps (`node-sql-parser`, a TOML parser — Bun has `Bun.TOML` built in, so
  possibly only 1).
- `anywrite/src/` structure to mirror: `registry.ts` (single source of truth per
  endpoint/op), `client.ts` (executes any registry entry), `cli.ts` (argv parse +
  dispatch), `output.ts`.
- E2E precedent: `anywrite/scripts/smoke.sh` runs against a live local target. sshepherd
  equivalent: a disposable local sshd container (`linuxserver/openssh-server` or
  hand-rolled Dockerfile with sshd + docker-cli stubs) so transport/E2E tests never
  touch a real server.

## Risks & unknowns

- ControlPath socket path length (<104 chars macOS) — keep socket dir short.
- Docker `--format json` is NDJSON while `docker inspect` is a JSON array — registry
  must tag output shape per op or naive `JSON.parse` throws.
- Native-JSON flags assume Linux remotes (systemd/iproute2/util-linux); macOS/BSD
  remotes would need per-OS command variants — v1 targets Linux servers only.
- OpenSSH 10.0: scp/sftp no longer create masters (will reuse) — affects
  `files download/upload` ordering: open master via `ssh` first.
- Zombie masters if CLI crashes between open and teardown — ControlPersist=60 backstop
  + startup `-O check`.
- `pg_stat_statements` often absent — `db slow` must degrade gracefully ("extension not
  installed"), never error.
- Redaction can't be perfect if we ever surface transport stderr — that's why the
  decision is discard-entirely, allowlist-nothing.
- Mutating ops on real servers during development — all E2E happens against the local
  sshd container; real-host testing only with the user driving.

## Open questions

- ~~Name~~ — resolved: `sshepherd` (user sign-off 2026-07-12).
- ~~Scope cut~~ — resolved: full 9-group set in v1 (user sign-off 2026-07-12).
- DB target declaration file: proposed `~/.config/sshepherd/targets.toml` mapping
  `<pg-target>` → `{alias, method: docker-exec|remote-psql, container/compose path,
  user, database}` — password never transits sshepherd (docker-exec uses container
  peer/trust auth or the remote's `.pgpass`). Treated as a design decision, not blocking.
- Audit log location: proposed `~/.local/state/sshepherd/audit.jsonl` (local, append-only,
  one line per mutating op: ts/alias/command/args-hash/outcome). Not blocking.
- Per-project alias allowlist: proposed `.sshepherd/allow.toml` (`aliases = [...]`) —
  when present, commands against a non-listed alias refuse. Not blocking.

## Reference artifacts

- Full research reports: cc-toriq session transcript 2026-07-12 (three teammate messages:
  scope-research, impl-research, oss-research) — this doc carries the load-bearing facts.
- Memory: `~/.claude/projects/-Users-macbook-Documents-PROJECT-MISPAQUL-ATTORIQ-cc-toriq/memory/project_ssh-ops-skill-design.md`
- Server-survival probes source: `~/.claude/skills/devops-engineer/references/server-pattern.md`
- Packaging template: `~/Documents/PROJECT_MISPAQUL_ATTORIQ/anywrite/`

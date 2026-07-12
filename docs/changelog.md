# sshepherd Changelog

## v0.1.0 — sshepherd v1: safe SSH server ops from Claude Code

- New: `sshepherd`, a single CLI you (or an agent driving Claude Code) can use to check on
  and manage a remote server over SSH — health checks, docker/systemd control, log tailing,
  config edits, read-only database introspection, and one-command deploys — without ever
  typing or exposing a password, private key, hostname, or port to the agent.
- Nine command groups, 52 operations total: `hosts`, `check`, `logs`, `services`, `deploy`,
  `config`, `db`, `files`, `security`. Every response comes back as one consistent JSON
  shape (or a readable table with `--pretty`).
- Read-only Postgres introspection (`db` group): table sizes, active queries, connection
  counts, slow queries, database sizes, and ad hoc `SELECT`-only queries — enforced
  read-only at the database role, the query wrapper, and the client, so it's safe to point
  at a production database.
- Declarative deploys (`deploy` group): describe a deploy as a TOML recipe (build, migrate,
  restart, health-check, in whatever order they actually depend on each other) and run it
  with one command, preview it first with `--dry-run`, or roll it back if you declared how.
- Anything that changes something on the server requires an explicit `--yes` and is
  recorded in a local audit log — nothing runs by accident.
- Install via `npx skills add Antheurus/sshepherd`, `/plugin marketplace add
  Antheurus/sshepherd`, a prebuilt release binary, or build from source with `just build`.
  See the README for all four options.

**Action required before first use:**
- Add the servers you want to manage as aliases in your `~/.ssh/config` (with `ssh-agent`
  or a key file already working for each one) — `sshepherd` only ever takes an alias name,
  never a host, user, or password.
- To use the `db` group, declare each database as a named target in
  `~/.config/sshepherd/targets.toml` (see `targets.example.toml` for the format).

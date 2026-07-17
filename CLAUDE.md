# sshepherd — project rules

This is a **public, shared tool** (github.com/Antheurus/sshepherd) — other people install and
use it against their own servers. It is not personal tooling, even though it was built by and
for one user originally.

## Never bake personal/account-specific data into shipped files

`SKILL.md`, `README.md`, `references/*.md`, and `targets.example.toml` are read by every user
of this tool, not just the original author. Never hardcode:

- A real server/project name as the running example (a 2026-07-18 session found `lms-server`,
  `lms-app`, `/opt/lms`, `database = "lms"`, and a `lms-prod` deploy recipe used pervasively
  throughout `SKILL.md`/`README.md`/`references/db.md`/`references/output-shapes.md`/
  `references/recipes.md`/`targets.example.toml` — the user's real Learning Management System
  project. Fixed by genericizing to `web-01` (ssh alias), `myapp` (docker/db name), `/opt/myapp`
  (path), `myapp-prod` (recipe name).
- Real hostnames, IPs, ssh aliases, or pg-target names from any actual server this tool has
  been used against
- Real recipe names, compose service names, or deploy paths tied to one person's actual
  infrastructure

Use neutral placeholder names in every example: `web-01`/`prod`/`staging` for aliases,
`myapp` for app/container/db names, `/opt/myapp` for remote paths. If a new example needs a
"realistic" feel, invent a generic one — never reuse whatever server/project is actually being
managed in the current session.

Legitimate exceptions: the actual GitHub repo URL (`github.com/Antheurus/sshepherd`) in
README/CI badges/clone instructions — that's not personal infrastructure data, it's just
where the code lives.

## Where this was caught before

Before adding new examples or docs, check they'd make sense to a stranger cloning this repo
to manage their own servers — not just to the original author's own boxes.

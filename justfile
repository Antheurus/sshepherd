default:
    @just --list

install:
    bun install

build: install
    bun run build

clean:
    rm -rf dist node_modules

test: install
    bun run test

check: install
    bun run check

# Test, check, build with the version/sha/time/registry stamp, install atomically. SSHEPHERD_INSTALL_DIR overrides ~/.local/bin.
release version:
    bash scripts/release.sh release {{version}}

# Restore sshepherd.prev over the installed binary.
rollback:
    bash scripts/release.sh rollback

# The skill-doc test: SKILL.md's documented ops must equal the registry.
check-skill: install
    bun test src/__tests__/skill-doc.test.ts

# Raw ssh vs sshepherd calls per intent bucket from the local Claude Code transcripts (counts only, never a command or host), classified by ~/.claude/hooks/ssh-secret-guard.py. --out writes the JSON report outside this repo.
ssh-usage *args:
    python3 scripts/ssh-usage.py {{args}}

# Bring the smoke fixture (debian + alpine sshd, postgres, nginx) up under compose project sshepherd-smoke (SSHEPHERD_SMOKE_PROJECT names another, on ephemeral ports). Refuses when that project is already running.
smoke-up:
    bash scripts/smoke.sh up

# Tear the fixture down. Only that compose project (sshepherd-smoke, or SSHEPHERD_SMOKE_PROJECT) is touched, and not while a smoke run holds it.
smoke-down:
    bash scripts/smoke.sh down

# Live matrix on both sshd variants, then the canary leak gate (canary-leak.test.ts); records outputs under src/__tests__/fixtures/live/. Tears down what it brought up.
smoke: build
    bash scripts/smoke.sh

# The leak gate on its own: smoke-up, canary-leak.test.ts (fails on any hit, any skip, or an op with no ok drive), smoke-down. CI cannot run it (no Docker fixture there); this recipe is the gate.
canary-fixture: build
    bash scripts/smoke.sh canary-gate

# Read-only ops against a real alias; diffs envelope key sets against src/__tests__/fixtures/canary/.
canary alias:
    bash scripts/smoke.sh canary {{alias}}

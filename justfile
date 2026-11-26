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

# Bring the smoke fixture (debian + alpine sshd, postgres, nginx) up under compose project sshepherd-smoke (SSHEPHERD_SMOKE_PROJECT names another, on ephemeral ports).
smoke-up:
    bash scripts/smoke.sh up

# Tear the fixture down. Only that compose project (sshepherd-smoke, or SSHEPHERD_SMOKE_PROJECT) is touched.
smoke-down:
    bash scripts/smoke.sh down

# Live matrix on both sshd variants; records outputs under src/__tests__/fixtures/live/. Always tears down.
smoke: build
    bash scripts/smoke.sh

# Read-only ops against a real alias; diffs envelope key sets against src/__tests__/fixtures/canary/.
canary alias:
    bash scripts/smoke.sh canary {{alias}}

# Sourced by scripts/smoke.sh, canary/plant.sh and src/__tests__/canary-leak.test.ts: the one place a
# fixture's compose project, container-name prefix and state dir are derived, so two worktrees can
# each run their own fixture at once.
#
#   SSHEPHERD_SMOKE_PROJECT    compose project (default sshepherd-smoke)
#   SSHEPHERD_SMOKE_STATE_DIR  keys, ssh config and outputs (default /tmp/<project>)
#
# The default project keeps the container prefix `sshepherd-fixture` and the fixed host ports
# 8413/8414; any other project prefixes its containers with `<project>-fixture` and binds its host
# ports ephemerally (smoke.sh reads them back with `docker compose port`).

SMOKE_DEFAULT_PROJECT=sshepherd-smoke
SMOKE_PROJECT="${SSHEPHERD_SMOKE_PROJECT:-$SMOKE_DEFAULT_PROJECT}"
if [[ ! "$SMOKE_PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]]; then
  echo "SSHEPHERD_SMOKE_PROJECT must be 1-41 lowercase letters, digits, '-' or '_'" >&2
  exit 2
fi
if [[ "$SMOKE_PROJECT" == "$SMOKE_DEFAULT_PROJECT" ]]; then
  SMOKE_PREFIX=sshepherd-fixture
else
  SMOKE_PREFIX="$SMOKE_PROJECT-fixture"
fi
SMOKE_STATE="${SSHEPHERD_SMOKE_STATE_DIR:-/tmp/$SMOKE_PROJECT}"

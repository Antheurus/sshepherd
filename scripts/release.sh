#!/usr/bin/env bash
# `just release <semver>` and `just rollback`: build a stamped binary and install it atomically.
#   release <semver>  tests + checks, builds with version/git sha/UTC time/registry hash compiled in,
#                     keeps the previous target's BYTES as sshepherd.prev, then renames a temp file
#                     over the target (a symlink there is replaced by a regular file, never followed).
#   rollback          renames a copy of sshepherd.prev over the target.
# Install dir: ${SSHEPHERD_INSTALL_DIR:-$HOME/.local/bin}.
set -euo pipefail

cd "$(dirname "$0")/.."

INSTALL_DIR="${SSHEPHERD_INSTALL_DIR:-$HOME/.local/bin}"
TARGET="$INSTALL_DIR/sshepherd"
PREV="$INSTALL_DIR/sshepherd.prev"

# Copies $1 to a fresh temp file beside the target and renames it over $2: same filesystem, so the
# rename is atomic and a reader sees the old file or the new one, never a partial write.
install_atomically() {
  local source="$1" destination="$2" staged
  staged="$(mktemp "$INSTALL_DIR/.sshepherd.XXXXXX")"
  if ! { cp -L "$source" "$staged" && chmod 755 "$staged" && mv -f "$staged" "$destination"; }; then
    rm -f "$staged"
    return 1
  fi
}

release() {
  local version="${1:-}"
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "release: '$version' is not a semver (e.g. 0.4.0 or 0.4.0-rc.4)" >&2
    exit 2
  fi
  local pkg_version
  pkg_version="$(bun -e "process.stdout.write(require('./package.json').version)")"
  if [[ "$pkg_version" != "$version" ]]; then
    echo "release: package.json is $pkg_version, not $version; bump it first so --version tells the truth" >&2
    exit 2
  fi

  bun test
  bun run check

  local sha time registry
  sha="$(git rev-parse --short HEAD)"
  if [[ -n "$(git status --porcelain)" ]]; then
    sha="$sha-dirty"
  fi
  time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  registry="$(bun -e "import { registryHash } from './src/version.ts'; process.stdout.write(registryHash())")"

  bun build ./src/cli.ts --compile --outfile ./dist/sshepherd \
    --define "SSHEPHERD_BUILD_STAMP={\"sha\":\"$sha\",\"time\":\"$time\",\"registry\":\"$registry\"}"

  local expected="sshepherd $version ($sha, $time, registry $registry)"
  local built
  built="$(./dist/sshepherd --version)"
  if [[ "$built" != "$expected" ]]; then
    echo "release: built binary printed '$built', expected '$expected'" >&2
    exit 1
  fi

  mkdir -p "$INSTALL_DIR"
  if [[ -e "$TARGET" ]]; then
    install_atomically "$TARGET" "$PREV"
  fi
  install_atomically ./dist/sshepherd "$TARGET"

  local installed
  installed="$("$TARGET" --version)"
  if [[ "$installed" != "$expected" ]]; then
    echo "release: installed binary printed '$installed', expected '$expected'; run: just rollback" >&2
    exit 1
  fi
  echo "$installed"
}

rollback() {
  if [[ ! -f "$PREV" ]]; then
    echo "rollback: no $PREV to restore" >&2
    exit 1
  fi
  install_atomically "$PREV" "$TARGET"
  "$TARGET" --version
}

case "${1:-}" in
  release) shift; release "$@" ;;
  rollback) rollback ;;
  *) echo "usage: scripts/release.sh release <semver> | rollback" >&2; exit 2 ;;
esac

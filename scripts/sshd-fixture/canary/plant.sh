#!/usr/bin/env bash
# Plants (or removes) the canary for src/__tests__/canary-leak.test.ts in the running smoke fixture
# (`just smoke-up`). Every docker command names one of the fixture's own containers; nothing else on
# the daemon is touched.
#
#   plant.sh plant <canary>   copy every template below with __C__ replaced by <canary> onto both sshd
#                             fixtures, seed the canary_users table, start the canary service
#   plant.sh clean            remove the canary service, the planted files and the table
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SSHD=(sshepherd-fixture-sshd-debian sshepherd-fixture-sshd-alpine)
POSTGRES=sshepherd-fixture-postgres
CANARY_CONTAINER=sshepherd-fixture-canary
COMPOSE_FILE=/opt/canary/docker-compose.yml
# template:destination on each sshd fixture
FILES=(
  "docker-compose.yml:$COMPOSE_FILE"
  "env.tmpl:/opt/canary/.env"
  "prod.env.tmpl:/opt/canary/prod.env"
  "config.json.tmpl:/opt/canary/config.json"
  "server.pem.tmpl:/opt/canary/server.pem"
  "access-log.tmpl:/var/log/nginx/access.log"
  "error-log.tmpl:/var/log/nginx/error.log"
)
READY_LINE="canary app ready"
READY_WAIT_SEC=30

render() {
  sed "s/__C__/$CANARY/g" "$DIR/$1"
}

plant() {
  CANARY="${1:-}"
  if [[ ! "$CANARY" =~ ^[A-Za-z0-9]{16,64}$ ]]; then
    echo "plant.sh: the canary must be 16-64 letters and digits" >&2
    exit 2
  fi
  for container in "${SSHD[@]}"; do
    docker exec "$container" mkdir -p /opt/canary /var/log/nginx
    for pair in "${FILES[@]}"; do
      render "${pair%%:*}" | docker exec -i "$container" sh -c "cat > '${pair#*:}'"
    done
  done
  render seed.sql.tmpl | docker exec -i "$POSTGRES" psql -q -v ON_ERROR_STOP=1 -U postgres -d fixture >/dev/null
  docker exec "${SSHD[0]}" docker compose -f "$COMPOSE_FILE" up -d --force-recreate canary >/dev/null
  for _ in $(seq 1 "$READY_WAIT_SEC"); do
    if docker logs "$CANARY_CONTAINER" 2>&1 | grep -q "$READY_LINE"; then
      return 0
    fi
    sleep 1
  done
  echo "plant.sh: $CANARY_CONTAINER never printed '$READY_LINE'" >&2
  exit 1
}

clean() {
  docker exec "${SSHD[0]}" docker compose -f "$COMPOSE_FILE" rm -sf canary >/dev/null
  for container in "${SSHD[@]}"; do
    docker exec "$container" rm -rf /opt/canary /var/log/nginx/access.log /var/log/nginx/error.log
  done
  docker exec "$POSTGRES" psql -q -U postgres -d fixture -c 'DROP TABLE IF EXISTS canary_users' >/dev/null
}

case "${1:-}" in
  plant) plant "${2:-}" ;;
  clean) clean ;;
  *)
    echo "usage: plant.sh plant <canary> | plant.sh clean" >&2
    exit 2
    ;;
esac

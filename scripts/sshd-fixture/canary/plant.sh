#!/usr/bin/env bash
# Plants (or removes) the canary for src/__tests__/canary-leak.test.ts in the running smoke fixture
# (`just smoke-up`; SSHEPHERD_SMOKE_PROJECT picks which one, see ../project.sh). Every docker command
# names one of that fixture's own containers; nothing else on the daemon is touched.
#
#   plant.sh plant <canary> <digits> <user> <host> <port>
#                             copy every template below with __C__ (the canary), __D__ (a digits-only
#                             canary), __U__/__H__/__P__ (the canary connection identity) replaced onto
#                             both sshd fixtures; add <user> as a uid-0 login sharing root's key, open
#                             a listener on the documentation-range peer, seed the canary_users table,
#                             start the canary services
#   plant.sh clean            remove all of it again
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../project.sh
source "$DIR/../project.sh"
SSHD=("$SMOKE_PREFIX-sshd-debian" "$SMOKE_PREFIX-sshd-alpine")
POSTGRES="$SMOKE_PREFIX-postgres"
CANARY_CONTAINER="$SMOKE_PREFIX-canary"
COMPOSE_FILE=/opt/canary/docker-compose.yml
# The user planted by `plant`, read back by `clean` (outside /opt/canary, which clean removes first).
USER_RECORD=/root/.canary-user
PEER_LISTEN=203.0.113.77:51234
LISTENER_PIDFILE=/run/canary-listener.pid
# template:destination on each sshd fixture
FILES=(
  "docker-compose.yml:$COMPOSE_FILE"
  "env.tmpl:/opt/canary/.env"
  "prod.env.tmpl:/opt/canary/prod.env"
  "config.json.tmpl:/opt/canary/config.json"
  "server.pem.tmpl:/opt/canary/server.pem"
  "access-log.tmpl:/var/log/nginx/access.log"
  "error-log.tmpl:/var/log/nginx/error.log"
  "auth-log.tmpl:/var/log/auth.log"
  "journal.ndjson.tmpl:/opt/canary/journal.ndjson"
  "deploy-error.tmpl:/opt/canary/deploy-error.log"
  "journalctl.tmpl:/usr/bin/journalctl"
)
READY_LINE="canary app ready"
READY_WAIT_SEC=30

render() {
  sed -e "s/__C__/$CANARY/g" -e "s/__D__/$DIGITS/g" -e "s/__U__/$IDENTITY_USER/g" \
    -e "s/__H__/$IDENTITY_HOST/g" -e "s/__P__/$IDENTITY_PORT/g" \
    -e "s/__N__/$SMOKE_PROJECT/g" -e "s/__X__/$SMOKE_PREFIX/g" "$DIR/$1"
}

require() {
  if [[ ! "$2" =~ $3 ]]; then
    echo "plant.sh: the $1 must match $3" >&2
    exit 2
  fi
}

# A second uid-0 login whose home is /root, so it reaches root's bind-mounted authorized_keys and the
# docker socket while its own name is the canary; root stays first in /etc/passwd, so `ls -l`/`ps`
# still print root.
add_user() {
  docker exec "$1" sh -c '
    u="$1"
    grep -q "^$u:" /etc/passwd && exit 0
    line="$(sed -n "s/^root:/$u:/p" /etc/passwd)"
    printf "%s\n" "$line" >>/etc/passwd
    printf "%s:*:19000:0:99999:7:::\n" "$u" >>/etc/shadow
    printf "%s\n" "$u" >'"$USER_RECORD"'
  ' sh "$IDENTITY_USER"
}

plant() {
  CANARY="${1:-}"
  DIGITS="${2:-}"
  IDENTITY_USER="${3:-}"
  IDENTITY_HOST="${4:-}"
  IDENTITY_PORT="${5:-}"
  require canary "$CANARY" '^[A-Za-z0-9]{16,64}$'
  require "digits canary" "$DIGITS" '^[0-9]{12,40}$'
  require "identity user" "$IDENTITY_USER" '^[a-z][a-z0-9]{7,30}$'
  require "identity host" "$IDENTITY_HOST" '^[a-z0-9]+\.example\.net$'
  require "identity port" "$IDENTITY_PORT" '^[1-9][0-9]{3,4}$'
  for container in "${SSHD[@]}"; do
    docker exec "$container" mkdir -p /opt/canary /var/log/nginx
    for pair in "${FILES[@]}"; do
      render "${pair%%:*}" | docker exec -i "$container" sh -c "cat > '${pair#*:}'"
    done
    docker exec "$container" chmod 755 /usr/bin/journalctl
    add_user "$container"
    docker exec "$container" /usr/sbin/sshd -o "ListenAddress=$PEER_LISTEN" -o "PidFile=$LISTENER_PIDFILE"
  done
  render seed.sql.tmpl | docker exec -i "$POSTGRES" psql -q -v ON_ERROR_STOP=1 -U postgres -d fixture >/dev/null
  docker exec "${SSHD[0]}" docker compose -f "$COMPOSE_FILE" up -d --force-recreate canary canary-pg canary-dburl >/dev/null
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
  docker exec "${SSHD[0]}" docker compose -f "$COMPOSE_FILE" rm -sf canary canary-pg canary-dburl >/dev/null
  for container in "${SSHD[@]}"; do
    docker exec "$container" sh -c '
      if [ -f '"$LISTENER_PIDFILE"' ]; then kill "$(cat '"$LISTENER_PIDFILE"')" 2>/dev/null || true; fi
      if [ -f '"$USER_RECORD"' ]; then
        u="$(cat '"$USER_RECORD"')"
        sed -i "/^$u:/d" /etc/passwd /etc/shadow
        rm -f '"$USER_RECORD"'
      fi
    '
    docker exec "$container" rm -rf /opt/canary /var/log/nginx/access.log /var/log/nginx/error.log \
      /var/log/auth.log /usr/bin/journalctl
  done
  docker exec "$POSTGRES" psql -q -U postgres -d fixture -c \
    'DROP FUNCTION IF EXISTS canary_unique_violation(); DROP FUNCTION IF EXISTS canary_not_null_violation(); DROP TABLE IF EXISTS canary_users; DROP TYPE IF EXISTS canary_mood' >/dev/null
}

case "${1:-}" in
  plant) shift; plant "$@" ;;
  clean) clean ;;
  *)
    echo "usage: plant.sh plant <canary> <digits> <user> <host> <port> | plant.sh clean" >&2
    exit 2
    ;;
esac

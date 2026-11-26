#!/usr/bin/env bash
# Live smoke matrix for the compiled dist/sshepherd binary against a disposable local Docker
# fixture (scripts/sshd-fixture/): a debian and an alpine sshd, a postgres and an nginx app, all
# in ONE compose project, `sshepherd-smoke` unless SSHEPHERD_SMOKE_PROJECT names another (so two
# worktrees can each run one at once; scripts/sshd-fixture/project.sh derives the names). Every
# docker command here is scoped to that project; nothing else on the daemon is started, stopped or
# removed.
#
#   scripts/smoke.sh                 up, run the matrix on both sshd variants, always tear down
#   scripts/smoke.sh up | down       bring the fixture up / tear it down
#   scripts/smoke.sh canary <alias>  read-only ops against a real alias; key-set diff only
#
# The ssh aliases live in a fixture-only ssh config ($STATE/ssh_config, reached through
# SSHEPHERD_SSH_CONFIG_PATH), never in ~/.ssh/config. The keypair is generated per run and never
# committed. Host ports of the default project: 8413 (debian) and 8414 (alpine), override with
# SSHEPHERD_SMOKE_DEBIAN_PORT / SSHEPHERD_SMOKE_ALPINE_PORT; any other project binds ephemeral
# ports and reads them back with `docker compose port`, so nobody picks one by hand.
set -euo pipefail

BIN="${BIN:-./dist/sshepherd}"
FIXTURE_DIR="scripts/sshd-fixture"
# shellcheck source=sshd-fixture/project.sh
source "$FIXTURE_DIR/project.sh"
COMPOSE_PROJECT="$SMOKE_PROJECT"
PREFIX="$SMOKE_PREFIX"
STATE="$SMOKE_STATE"
if [[ "$COMPOSE_PROJECT" == "$SMOKE_DEFAULT_PROJECT" ]]; then
  DEBIAN_PORT="${SSHEPHERD_SMOKE_DEBIAN_PORT:-8413}"
  ALPINE_PORT="${SSHEPHERD_SMOKE_ALPINE_PORT:-8414}"
else
  DEBIAN_PORT=""
  ALPINE_PORT=""
fi
KEYDIR="$STATE/keys"
LIVE_DIR="src/__tests__/fixtures/live"
CANARY_DIR="src/__tests__/fixtures/canary"
VARIANTS=(debian alpine)

PASS_COUNT=0
FAIL_COUNT=0
step() { printf '\n[STEP] %s\n' "$1"; }
pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS: %s\n' "$1"
}
fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

compose() {
  (cd "$FIXTURE_DIR" && SSHEPHERD_SMOKE_KEYDIR="$KEYDIR" \
    SSHEPHERD_SMOKE_PROJECT="$COMPOSE_PROJECT" SSHEPHERD_SMOKE_CONTAINER_PREFIX="$PREFIX" \
    SSHEPHERD_SMOKE_DEBIAN_PORT="$DEBIAN_PORT" SSHEPHERD_SMOKE_ALPINE_PORT="$ALPINE_PORT" \
    docker compose -p "$COMPOSE_PROJECT" "$@")
}

# The host port an sshd variant is published on: the fixed one, or the ephemeral one compose
# picked, read back from the running project.
port_for() {
  local fixed
  if [[ "$1" == debian ]]; then fixed="$DEBIAN_PORT"; else fixed="$ALPINE_PORT"; fi
  if [[ -n "$fixed" ]]; then
    echo "$fixed"
    return
  fi
  local published
  published="$(compose port "sshd-$1" 22)"
  echo "${published##*:}"
}

# The sshd's own public host keys, read through docker: the out-of-band channel a human would use
# to confirm a fingerprint before trusting it.
host_keys() {
  docker exec "$PREFIX-sshd-$1" sh -c 'cat /etc/ssh/ssh_host_*_key.pub'
}

# -- bring-up / tear-down ---------------------------------------------------------------------

fixture_up() {
  for port in "$DEBIAN_PORT" "$ALPINE_PORT"; do
    if [[ -n "$port" ]] && lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "smoke: host port $port is already listening; free it or set SSHEPHERD_SMOKE_*_PORT" >&2
      exit 1
    fi
  done

  step "generate ephemeral ssh keypair + fixture-only ssh config"
  mkdir -p "$KEYDIR" "$STATE/run" "$STATE/state" "$STATE/tunnels"
  chmod 700 "$STATE"
  rm -f "$KEYDIR/id_ed25519" "$KEYDIR/id_ed25519.pub"
  ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/id_ed25519"
  cp "$KEYDIR/id_ed25519.pub" "$KEYDIR/authorized_keys"
  chmod 600 "$KEYDIR/id_ed25519" "$KEYDIR/authorized_keys"
  pass "keypair written under $STATE"

  step "bring up the $COMPOSE_PROJECT compose project (debian + alpine sshd, postgres, app)"
  compose up -d --build
  DEBIAN_PORT="$(port_for debian)"
  ALPINE_PORT="$(port_for alpine)"
  pass "fixture containers started"

  step "write the fixture-only ssh config for the published ports"
  : >"$STATE/ssh_config"
  for variant in "${VARIANTS[@]}"; do
    {
      printf 'Host smoke-%s\n' "$variant"
      printf '  HostName 127.0.0.1\n'
      printf '  Port %s\n' "$(port_for "$variant")"
      printf '  User root\n'
      printf '  IdentityFile %s\n' "$KEYDIR/id_ed25519"
      printf '  IdentitiesOnly yes\n'
      printf '  StrictHostKeyChecking yes\n'
      printf '  UserKnownHostsFile %s\n\n' "$STATE/known_hosts"
    } >>"$STATE/ssh_config"
  done
  pass "fixture ssh config written: debian on $(port_for debian), alpine on $(port_for alpine)"

  step "record the fixture host keys, read from each container (strict checking, never accept-new)"
  : >"$STATE/known_hosts"
  chmod 600 "$STATE/known_hosts"
  for variant in "${VARIANTS[@]}"; do
    host_keys "$variant" | while read -r type key _; do
      printf '[127.0.0.1]:%s %s %s\n' "$(port_for "$variant")" "$type" "$key"
    done >>"$STATE/known_hosts"
  done
  pass "fixture known_hosts holds both variants' host keys"

  for variant in "${VARIANTS[@]}"; do
    step "wait for the $variant sshd on port $(port_for "$variant")"
    local ready=false
    for _ in $(seq 1 60); do
      if ssh -F "$STATE/ssh_config" -o BatchMode=yes -o ConnectTimeout=3 "smoke-$variant" true 2>/dev/null; then
        ready=true
        break
      fi
      sleep 1
    done
    [[ "$ready" == true ]] || fail "$variant sshd never accepted a key login on port $(port_for "$variant")"
    pass "$variant sshd accepts the fixture key"
  done

  step "wait for the postgres fixture to finish its init scripts"
  local db_ready=false
  for _ in $(seq 1 60); do
    if docker exec "$PREFIX-postgres" psql -U sshepherd_ro -d fixture -tAc 'SELECT 1 FROM smoke_fixture' >/dev/null 2>&1; then
      db_ready=true
      break
    fi
    sleep 1
  done
  [[ "$db_ready" == true ]] || fail "postgres fixture never exposed smoke_fixture to sshepherd_ro"
  pass "postgres fixture seeded and readable by the read-only role"

  step "wait for the noisy fixture to finish printing its 5 MiB"
  local noisy_ready=false
  for _ in $(seq 1 60); do
    if docker logs --tail 1 "$PREFIX-noisy" 2>&1 | grep -q NOISY-DONE; then
      noisy_ready=true
      break
    fi
    sleep 1
  done
  [[ "$noisy_ready" == true ]] || fail "noisy fixture never finished printing"
  pass "noisy fixture printed 5 MiB and is idle"
}

fixture_down() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$STATE"
}

# -- CLI drive helpers ------------------------------------------------------------------------

use_fixture_env() {
  export SSHEPHERD_SSH_CONFIG_PATH="$STATE/ssh_config"
  export SSHEPHERD_STATE_DIR="$STATE/state"
  export SSHEPHERD_TUNNEL_STATE_DIR="$STATE/tunnels"
  export SSHEPHERD_TARGETS_PATH="$STATE/targets.toml"
  export SSHEPHERD_FILES_ALLOWLIST_PATH="$STATE/files-allowlist.toml"
  export SSHEPHERD_REVEAL_ALLOWLIST_PATH="$STATE/reveal-allowlist.toml"
  export XDG_RUNTIME_DIR="$STATE/run"
}

# run_cli <label> <args...>: stores stdout in $OUT/<label>.json; a non-zero exit fails the smoke.
run_cli() {
  local label="$1"
  shift
  if ! "$BIN" "$@" >"$OUT/$label.json" 2>"$OUT/$label.err"; then
    cat "$OUT/$label.json" "$OUT/$label.err" >&2
    fail "command failed: sshepherd $*"
  fi
}

# run_cli_any: same, but the exit code is the caller's to judge (error-path steps).
run_cli_any() {
  local label="$1"
  shift
  "$BIN" "$@" >"$OUT/$label.json" 2>"$OUT/$label.err" || true
}

# assert_json <desc> <label> <python expr over d>: d is the parsed envelope in $OUT/<label>.json.
assert_json() {
  local desc="$1" label="$2" expr="$3"
  if ! python3 -c "
import json, sys
d = json.load(open('$OUT/$label.json'))
sys.exit(0 if bool($expr) else 1)
"; then
    printf '  -- response was:\n' >&2
    head -c 2000 "$OUT/$label.json" >&2
    printf '\n' >&2
    fail "$desc"
  fi
  pass "$desc"
}

socket_for() {
  python3 -c "
import hashlib, sys
print('$XDG_RUNTIME_DIR/sshepherd/' + hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16] + '.sock')
" "$1"
}

write_fixture_config() {
  local variant="$1" alias="smoke-$1"
  cat >"$STATE/targets.toml" <<TOML
[$alias]
alias = "$alias"
container = "$PREFIX-postgres"
user = "sshepherd_ro"
database = "fixture"
TOML
  cat >"$STATE/deploy.$alias.toml" <<TOML
name = "$alias"
alias = "$alias"
workdir = "/root"
description = "Smoke-test recipe, exercised with --dry-run only"

[[step]]
name = "check-app"
kind = "shell"
run = "echo smoke-deploy-ok"
mutates = false

[rollback]
strategy = "compose-file"
file = "docker-compose.yml"
TOML
  export SSHEPHERD_RECIPE_PATH="$STATE/deploy.$alias.toml"
}

wait_port() {
  local port="$1" want="$2"
  for _ in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 3<&-
      [[ "$want" == open ]] && return 0
    elif [[ "$want" == closed ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_matrix() {
  local variant="$1" alias="smoke-$1"
  OUT="$STATE/out/$variant"
  mkdir -p "$OUT"
  write_fixture_config "$variant"

  step "[$variant] strict host keys: unknown and changed keys are typed errors, hosts trust records a verified key"
  local known_name fingerprints fp
  known_name="[127.0.0.1]:$(port_for "$variant")"
  fingerprints="$(host_keys "$variant" | ssh-keygen -lf - | awk '{print $2}')"
  ssh-keygen -R "$known_name" -f "$STATE/known_hosts" >/dev/null 2>&1
  run_cli_any hk_unknown hosts test "$alias"
  assert_json "[$variant] no known_hosts entry: HOST_KEY_UNKNOWN, next names hosts trust" hk_unknown \
    "d['ok'] is False and d['error']['code'] == 'HOST_KEY_UNKNOWN' and 'hosts trust' in d['error']['next']"
  run_cli hk_dry hosts trust "$alias" --dry-run
  fp="$(python3 -c "import json; print(json.load(open('$OUT/hk_dry.json'))['data']['fingerprints'][0]['fingerprint'])")"
  if grep -qxF "$fp" <<<"$fingerprints"; then
    pass "[$variant] hosts trust --dry-run shows a fingerprint of the container's own host key"
  else
    fail "[$variant] hosts trust --dry-run fingerprint is not one of the container's host keys"
  fi
  run_cli_any hk_wrong hosts trust "$alias" --fingerprint "SHA256:$(printf 'x%.0s' $(seq 1 43))" --yes
  assert_json "[$variant] hosts trust with a fingerprint the host did not present: refused" hk_wrong \
    "d['ok'] is False and d['error']['code'] == 'HOST_KEY_CHANGED'"
  if ssh-keygen -F "$known_name" -f "$STATE/known_hosts" >/dev/null; then
    fail "[$variant] a refused hosts trust still wrote known_hosts"
  fi
  pass "[$variant] the refused hosts trust left known_hosts without an entry"
  run_cli hk_trust hosts trust "$alias" --fingerprint "$fp" --yes
  assert_json "[$variant] hosts trust --fingerprint --yes: written" hk_trust \
    "d['ok'] is True and d['data']['written'] is True"
  run_cli hk_test_trusted hosts test "$alias"
  assert_json "[$variant] hosts test after trust: ok" hk_test_trusted "d['ok'] is True"
  run_cli hk_disconnect hosts disconnect "$alias"
  rm -f "$STATE/impostor_key" "$STATE/impostor_key.pub"
  ssh-keygen -q -t ed25519 -N '' -f "$STATE/impostor_key"
  ssh-keygen -R "$known_name" -f "$STATE/known_hosts" >/dev/null 2>&1
  printf '%s %s\n' "$known_name" "$(cut -d' ' -f1,2 "$STATE/impostor_key.pub")" >>"$STATE/known_hosts"
  run_cli_any hk_changed hosts test "$alias"
  assert_json "[$variant] known_hosts holds another key: HOST_KEY_CHANGED" hk_changed \
    "d['ok'] is False and d['error']['code'] == 'HOST_KEY_CHANGED'"
  run_cli hk_retrust hosts trust "$alias" --fingerprint "$fp" --yes
  assert_json "[$variant] hosts trust replaces the stale entry" hk_retrust \
    "d['ok'] is True and d['data']['written'] is True and d['data']['replaced_entries'] == 1"
  run_cli hk_test_retrusted hosts test "$alias"
  assert_json "[$variant] hosts test after re-trust: ok" hk_test_retrusted "d['ok'] is True"
  run_cli hk_disconnect_again hosts disconnect "$alias"

  step "[$variant] hosts test, twice: one ControlMaster socket survives across processes"
  run_cli hosts_test hosts test "$alias"
  assert_json "[$variant] hosts test: ok + reachable" hosts_test \
    "d['ok'] is True and d['data']['reachable'] is True"
  run_cli hosts_test_again hosts test "$alias"
  assert_json "[$variant] second hosts test: ok" hosts_test_again "d['ok'] is True"
  local sock
  sock="$(socket_for "$alias")"
  if [[ -S "$sock" ]] && ssh -F "$SSHEPHERD_SSH_CONFIG_PATH" -o ControlPath="$sock" -O check "$alias" 2>/dev/null; then
    pass "[$variant] one live master socket remains after both processes exited"
  else
    fail "[$variant] no live ControlMaster socket at the alias's path after two sequential runs"
  fi

  step "[$variant] check overview"
  run_cli check_overview check overview "$alias"
  assert_json "[$variant] check overview: ok + nproc > 0 + dead_end_risk boolean + nothing degraded" check_overview \
    "d['ok'] is True and isinstance(d['data']['dead_end_risk'], bool) and d['data']['nproc'] > 0 and d['data']['degraded'] == []"

  step "[$variant] hosts test --diagnose"
  run_cli hosts_diagnose hosts test "$alias" --diagnose
  assert_json "[$variant] hosts test --diagnose: dns, tcp, banner, auth, echo, every one passing or skipped" hosts_diagnose \
    "d['ok'] is True and d['data']['reachable'] is True and [s['stage'] for s in d['data']['stages']] == ['dns','tcp','banner','auth','echo'] and all(s['verdict'] in ('ok','skipped') for s in d['data']['stages'])"

  step "[$variant] services ps"
  run_cli services_ps services ps "$alias"
  assert_json "[$variant] services ps: lists the fixture app container" services_ps \
    "d['ok'] is True and any('$PREFIX-app' in str(c) for c in d['data'])"

  step "[$variant] logs docker"
  run_cli logs_docker logs docker "$alias" "$PREFIX-app" --tail 5
  assert_json "[$variant] logs docker: LogsResult shape" logs_docker \
    "d['ok'] is True and 'lines' in d['data'] and 'next_since' in d['data']"

  step "[$variant] logs docker merges stderr: a line a container wrote to stderr comes back"
  run_cli logs_stderr logs docker "$alias" "$PREFIX-stderr-writer" --grep boom --since 60m
  assert_json "[$variant] logs docker --grep boom --since 60m: the stderr line, not truncated, next_since set" logs_stderr \
    "d['ok'] is True and d['data']['lines_returned'] == 1 and 'boom' in d['data']['lines'][0]['text'] and d['data']['truncated'] is False and d['data']['next_since'] is not None"

  step "[$variant] setup files-allowlist scaffold, then files ls"
  run_cli setup_files_allowlist setup files-allowlist scaffold "$alias" \
    --paths /root,/opt/myapp,/opt/myapp/.env,/opt/myapp/prod.env,/opt/myapp/start.sh --yes
  assert_json "[$variant] files-allowlist scaffolded for /root" setup_files_allowlist \
    "d['ok'] is True and '/root' in d['data']['paths']"
  run_cli files_ls files ls "$alias" /root
  assert_json "[$variant] files ls: array of entries" files_ls \
    "d['ok'] is True and isinstance(d['data'], list)"

  step "[$variant] secret-shaped files: files cat / tail / download mask every value"
  run_cli files_cat_env files cat "$alias" /opt/myapp/prod.env
  assert_json "[$variant] files cat prod.env: masked, no fake value" files_cat_env \
    "d['ok'] is True and d['data']['masked'] is True and 'fake-secret-value' not in json.dumps(d) and 'DB_PASSWORD=***' in d['data']['content'] and 'export API_KEY=' in d['data']['content']"
  run_cli files_cat_export files cat "$alias" /opt/myapp/start.sh
  assert_json "[$variant] files cat start.sh: export KEY=v scrubbed, PORT kept" files_cat_export \
    "d['ok'] is True and 'export SESSION_SECRET=***' in d['data']['content'] and 'export PORT=3000' in d['data']['content'] and d['scrubbed'] == 1 and 'fake-secret-value' not in json.dumps(d)"
  run_cli files_tail_env files tail "$alias" /opt/myapp/prod.env
  assert_json "[$variant] files tail prod.env: masked, no fake value" files_tail_env \
    "d['ok'] is True and 'DB_PASSWORD=***MASKED***' in d['data']['lines'] and 'fake-secret-value' not in json.dumps(d)"
  run_cli files_tail_export files tail "$alias" /opt/myapp/start.sh
  assert_json "[$variant] files tail start.sh: export KEY=v scrubbed" files_tail_export \
    "d['ok'] is True and 'export SESSION_SECRET=***' in d['data']['lines'] and 'fake-secret-value' not in json.dumps(d)"
  run_cli files_download_env files download "$alias" /opt/myapp/prod.env "$OUT/prod.env.download"
  assert_json "[$variant] files download prod.env: masked bytes on disk" files_download_env \
    "d['ok'] is True and d['data']['masked'] is True and 'fake-secret-value' not in open('$OUT/prod.env.download').read() and 'DB_PASSWORD=***MASKED***' in open('$OUT/prod.env.download').read()"
  run_cli files_download_export files download "$alias" /opt/myapp/start.sh "$OUT/start.sh.download"
  assert_json "[$variant] files download start.sh: export KEY=v scrubbed on disk" files_download_export \
    "d['ok'] is True and 'export SESSION_SECRET=***' in open('$OUT/start.sh.download').read() and 'export PORT=3000' in open('$OUT/start.sh.download').read() and 'fake-secret-value' not in open('$OUT/start.sh.download').read()"

  step "[$variant] env keys / env diff / services inspect: key names only, values never read"
  run_cli env_keys_file env keys "$alias" --path /opt/myapp/.env
  assert_json "[$variant] env keys --path: key, state, length_bucket per variable, no value" env_keys_file \
    "d['ok'] is True and {(e['key'], e['state'], e['length_bucket']) for e in d['data']} == {('APP_NAME','set','1-8'),('DB_PASSWORD','set','9-32'),('EMPTY_KEY','empty','0'),('LOG_LEVEL','set','1-8')} and 'fake-secret-value' not in json.dumps(d)"
  run_cli env_keys_container env keys "$alias" --container "$PREFIX-app"
  assert_json "[$variant] env keys --container: names only, PATH listed, no '=' in a key" env_keys_container \
    "d['ok'] is True and any(e['key'] == 'PATH' for e in d['data']) and all(set(e) == {'key','state','length_bucket'} and '=' not in e['key'] for e in d['data'])"
  run_cli env_diff env diff "$alias" --path /opt/myapp/.env --against ./fixtures/.env.example
  assert_json "[$variant] env diff: API_URL missing, LOG_LEVEL extra, EMPTY_KEY empty" env_diff \
    "d['ok'] is True and d['data'] == {'missing': ['API_URL'], 'extra': ['LOG_LEVEL'], 'empty': ['EMPTY_KEY']}"
  run_cli services_inspect services inspect "$alias" "$PREFIX-app" --fields mounts,ports,health,env
  assert_json "[$variant] services inspect --fields mounts,ports,health,env: env is key names only" services_inspect \
    "d['ok'] is True and all(set(e) == {'key','state','length_bucket'} for e in d['data'][0]['env']) and any(e['key'] == 'PATH' for e in d['data'][0]['env']) and 'mounts' in d['data'][0]"

  step "[$variant] files grep / find / head: allowlisted roots only, scrubbed, capped"
  run_cli files_grep files grep "$alias" /opt/myapp 'ERROR' --max-bytes 8192
  assert_json "[$variant] files grep ERROR: the log line comes back" files_grep \
    "d['ok'] is True and any('upstream refused' in l for l in d['data']['lines']) and len(open('$OUT/files_grep.json','rb').read()) <= 8192"
  run_cli files_grep_env files grep "$alias" /opt/myapp 'DB_PASSWORD'
  assert_json "[$variant] files grep over env files: values masked, no fake value" files_grep_env \
    "d['ok'] is True and len(d['data']['lines']) >= 2 and 'fake-secret-value' not in json.dumps(d)"
  run_cli files_find files find "$alias" /opt/myapp --name '*.log'
  assert_json "[$variant] files find --name '*.log': exactly the log" files_find \
    "d['ok'] is True and d['data']['paths'] == ['/opt/myapp/app.log'] and d['data']['truncated'] is False"
  run_cli files_head files head "$alias" /opt/myapp/.env --n 2
  assert_json "[$variant] files head --n 2: two lines, values masked" files_head \
    "d['ok'] is True and d['data']['lines_returned'] == 2 and 'fake-secret-value' not in json.dumps(d)"
  run_cli_any files_find_root files find "$alias" / --name passwd
  assert_json "[$variant] files find on /: refused by the allowlist before any ssh call" files_find_root \
    "d['ok'] is False and d['error']['code'] == 'VALIDATION_ERROR'"
  run_cli_any files_find_dotdot files find "$alias" /opt/myapp/../../etc --name passwd
  assert_json "[$variant] files find with .. out of the root: refused" files_find_dotdot \
    "d['ok'] is False and d['error']['code'] == 'VALIDATION_ERROR'"
  run_cli_any files_find_escape files find "$alias" /opt/myapp/escape --name passwd
  assert_json "[$variant] files find through a symlink out of the root: refused, nothing read" files_find_escape \
    "d['ok'] is False and d['error']['code'] == 'VALIDATION_ERROR' and 'passwd' not in json.dumps(d['data'])"

  step "[$variant] security listeners"
  run_cli security_listeners security listeners "$alias"
  assert_json "[$variant] security listeners: sshd port 22 listed" security_listeners \
    "d['ok'] is True and any(e['port'] == 22 for e in d['data']['listening'])"

  step "[$variant] db list / tables / query / describe / count / migrations"
  run_cli db_list db list
  assert_json "[$variant] db list: fixture target declared" db_list \
    "d['ok'] is True and '$alias' in d['data']['targets']"
  run_cli db_tables db tables "$alias"
  assert_json "[$variant] db tables: smoke_fixture present" db_tables \
    "d['ok'] is True and any(t['table'] == 'smoke_fixture' for t in d['data'])"
  run_cli db_query db query "$alias" "SELECT note FROM smoke_fixture"
  assert_json "[$variant] db query: seeded row comes back" db_query \
    "d['ok'] is True and d['data']['rows'][0]['note'] == 'hello from sshepherd smoke fixture'"
  run_cli db_query_big db query "$alias" "SELECT * FROM big"
  assert_json "[$variant] db query over 1200 rows: 500 rows, truncated" db_query_big \
    "d['ok'] is True and d['data']['row_count'] == 500 and d['data']['truncated'] is True and len(d['data']['rows']) == 500"
  run_cli db_describe db describe "$alias" users
  assert_json "[$variant] db describe users: columns, indexes, foreign key" db_describe \
    "d['ok'] is True and [c['name'] for c in d['data']['columns']][:2] == ['id', 'email'] and any(i['primary'] for i in d['data']['indexes']) and d['data']['foreign_keys'][0]['references_table'] == 'orgs'"
  run_cli db_count db count "$alias" users --where-eq id=1
  assert_json "[$variant] db count users --where-eq id=1: 1" db_count \
    "d['ok'] is True and d['data'] == {'count': 1}"
  run_cli db_migrations db migrations "$alias"
  assert_json "[$variant] db migrations: the seeded prisma and rails histories" db_migrations \
    "d['ok'] is True and [t['framework'] for t in d['data']['tables']] == ['prisma', 'rails'] and d['data']['tables'][0]['migrations'][0]['name'] == '20261102103000_add_users_nickname'"
  "$BIN" setup db-target ro-role "$alias" --print-sql >"$OUT/ro_role.sql"
  if grep -qx 'GRANT pg_read_all_data TO sshepherd_ro;' "$OUT/ro_role.sql"; then
    pass "[$variant] setup db-target ro-role --print-sql prints the read-only role SQL"
  else
    fail "[$variant] setup db-target ro-role --print-sql did not print the GRANT line"
  fi

  run_cli_any db_query_error db query "$alias" "SELECT nonexistent"
  assert_json "[$variant] db query error: sql_error names the column, no password text" db_query_error \
    "d['ok'] is False and 'column' in d['error']['data']['sql_error']['message'] and 'password' not in json.dumps(d).lower()"

  step "[$variant] deploy run --dry-run"
  run_cli deploy_dry_run deploy run "$alias" --dry-run
  assert_json "[$variant] deploy run --dry-run: plan only" deploy_dry_run \
    "d['ok'] is True and len(d['data']['steps']) == 1 and d['data']['steps'][0]['name'] == 'check-app'"

  step "[$variant] output cap: a container that printed 5 MiB comes back under 64 KiB, newest lines kept"
  run_cli cap_logs_noisy logs docker "$alias" "$PREFIX-noisy" --tail 5000
  assert_json "[$variant] logs docker of a 5 MiB container: output_truncated, at most 65536 bytes, the last line is the newest" cap_logs_noisy \
    "d['ok'] is True and d['output_truncated'] is True and len(open('$OUT/cap_logs_noisy.json','rb').read()) <= 65536 and d['data']['lines'][-1]['text'].endswith('NOISY-DONE')"
  run_cli cap_hosts_test_1 hosts test "$alias"
  run_cli cap_hosts_test_2 hosts test "$alias"
  assert_json "[$variant] two ordinary calls after a capped one both succeed" cap_hosts_test_2 \
    "d['ok'] is True and d['data']['reachable'] is True"
  if ssh -F "$SSHEPHERD_SSH_CONFIG_PATH" -o ControlPath="$sock" -O check "$alias" 2>/dev/null; then
    pass "[$variant] the ControlMaster is still live after the capped call"
  else
    fail "[$variant] the capped call wedged or killed the ControlMaster"
  fi

  step "[$variant] --fields, --limit and --max-bytes"
  run_cli fields_db_query db query "$alias" "SELECT 1 AS a, 2 AS b" --fields data.rows.a
  assert_json "[$variant] --fields data.rows.a: only that key per row" fields_db_query \
    "d['ok'] is True and d['data'] == {'rows': [{'a': 1}]} and 'fields_unmatched' not in d"
  run_cli fields_db_query_rows db query "$alias" "SELECT 1 AS a" --fields data.rows
  assert_json "[$variant] --fields data.rows: only data.rows" fields_db_query_rows \
    "d['ok'] is True and d['data'] == {'rows': [{'a': 1}]} and 'fields_unmatched' not in d"
  run_cli limit_db_query db query "$alias" "SELECT generate_series(1,5) AS n" --limit 2
  assert_json "[$variant] --limit 2: two rows, row_count recounted, output_truncated" limit_db_query \
    "d['ok'] is True and len(d['data']['rows']) == 2 and d['data']['row_count'] == 2 and d['output_truncated'] is True"
  run_cli_any bad_max_bytes hosts test "$alias" --max-bytes 10
  assert_json "[$variant] --max-bytes below the floor: INVALID_ARGS" bad_max_bytes \
    "d['ok'] is False and d['error']['code'] == 'INVALID_ARGS'"

  step "[$variant] deploy run (echo only), then audit tail"
  run_cli deploy_run deploy run "$alias" --yes
  assert_json "[$variant] deploy run: ok, output returned" deploy_run \
    "d['ok'] is True and 'smoke-deploy-ok' in d['data']['output']"
  run_cli audit_tail audit tail --n 5 --op "deploy run"
  assert_json "[$variant] audit tail: deploy run row names the recipe, duration, exit, sha256 of args" audit_tail \
    "d['ok'] is True and d['data']['rows'][-1]['recipe'] == '$alias' and d['data']['rows'][-1]['remote_exit'] == 0 and isinstance(d['data']['rows'][-1]['duration_ms'], int) and len(d['data']['rows'][-1]['args_sha256']) == 64"

  step "[$variant] --timeout 2 against a 10 s query: statement_timeout (1 s) cancels it"
  run_cli_any timeout_query db query "$alias" "SELECT pg_sleep(10)" --timeout 2
  assert_json "[$variant] timed-out query: COMMAND_TIMEOUT well before 10 s" timeout_query \
    "d['ok'] is False and d['error']['code'] == 'COMMAND_TIMEOUT' and d['duration_ms'] < 9000"

  step "[$variant] tunnel open / curl / list / close"
  run_cli tunnel_open tunnel open "$alias" --kind local --remote app:80 --duration 120 --yes
  assert_json "[$variant] tunnel open: local kind + auto-assigned port" tunnel_open \
    "d['ok'] is True and d['data']['kind'] == 'local' and isinstance(d['data']['localPort'], int)"
  local tunnel_id tunnel_port
  tunnel_id="$(python3 -c "import json; print(json.load(open('$OUT/tunnel_open.json'))['data']['id'])")"
  tunnel_port="$(python3 -c "import json; print(json.load(open('$OUT/tunnel_open.json'))['data']['localPort'])")"
  wait_port "$tunnel_port" open || fail "[$variant] forwarded port $tunnel_port never opened"
  if curl -fsS "http://127.0.0.1:$tunnel_port/" | grep -qi nginx; then
    pass "[$variant] tunnel carried a real HTTP response from the fixture nginx"
  else
    fail "[$variant] no nginx response through the tunnel on 127.0.0.1:$tunnel_port"
  fi
  run_cli tunnel_list tunnel list
  assert_json "[$variant] tunnel list: the opened tunnel is active" tunnel_list \
    "d['ok'] is True and any(t['id'] == '$tunnel_id' and t['remainingSec'] > 0 for t in d['data']['tunnels'])"
  run_cli tunnel_close tunnel close "$tunnel_id" --yes
  assert_json "[$variant] tunnel close: closed" tunnel_close \
    "d['ok'] is True and d['data']['closed'] is True"
  wait_port "$tunnel_port" closed && pass "[$variant] forwarded port $tunnel_port released" \
    || fail "[$variant] forwarded port $tunnel_port still open after close"

  step "[$variant] hosts disconnect removes the master"
  run_cli hosts_disconnect hosts disconnect "$alias"
  assert_json "[$variant] hosts disconnect: ok" hosts_disconnect "d['ok'] is True"
  if [[ -S "$sock" ]]; then
    fail "[$variant] master socket still present after hosts disconnect"
  fi
  pass "[$variant] master socket gone after hosts disconnect"
}

# Only the default project records: the committed fixtures name its containers, and two fixtures
# running at once must not both write them.
record_outputs() {
  if [[ "$COMPOSE_PROJECT" != "$SMOKE_DEFAULT_PROJECT" ]]; then
    printf '\n[STEP] outputs not recorded: project %s is not %s\n' "$COMPOSE_PROJECT" "$SMOKE_DEFAULT_PROJECT"
    return
  fi
  for variant in "${VARIANTS[@]}"; do
    mkdir -p "$LIVE_DIR/$variant"
    python3 - "$STATE/out/$variant" "$LIVE_DIR/$variant" "$PREFIX-" <<'PY'
import json, os, sys
src, dst, prefix = sys.argv[1:4]
for name in sorted(os.listdir(src)):
    if not name.endswith('.json'):
        continue
    d = json.load(open(os.path.join(src, name)))
    if name.startswith(('cap_', 'fields_', 'limit_', 'bad_', 'hk_')):
        continue
    if name == 'services_ps.json':
        d['data'] = [c for c in d['data'] if prefix in json.dumps(c)]
    json.dump(d, open(os.path.join(dst, name), 'w'), indent=2)
    open(os.path.join(dst, name), 'a').write('\n')
PY
  done
}

# -- canary: read-only ops against a real alias, envelope KEY SETS only --------------------------
# Runs hosts test, check overview, services ps, logs docker --tail 5 (first container, if any) and
# db tables (a pg-target named like the alias, if any); compares each envelope's key set (never a
# value) with $CANARY_DIR/expected-keys.json. `--record` rewrites that file from the run.
canary() {
  local alias="${1:-}" record="${2:-}"
  if [[ -z "$alias" ]]; then
    echo "usage: scripts/smoke.sh canary <alias> [--record]" >&2
    exit 2
  fi
  mkdir -p "$CANARY_DIR"
  BIN="$BIN" ALIAS="$alias" EXPECTED="$CANARY_DIR/expected-keys.json" RECORD="$record" python3 - <<'PY'
import json, os, subprocess, sys

binary, alias = os.environ["BIN"], os.environ["ALIAS"]
expected_path, record = os.environ["EXPECTED"], os.environ["RECORD"] == "--record"


def call(*args):
    out = subprocess.run([binary, *args], capture_output=True, text=True).stdout
    return json.loads(out)


def shape(envelope):
    data = envelope.get("data")
    if isinstance(data, dict):
        keys = sorted(data)
    elif isinstance(data, list):
        keys = sorted({k for row in data if isinstance(row, dict) for k in row})
    else:
        keys = []
    return {"ok": envelope.get("ok"), "envelope": sorted(envelope), "data": keys}


ops = {
    "hosts test": ["hosts", "test", alias],
    "check overview": ["check", "overview", alias],
}
services = call("services", "ps", alias)
ops["services ps"] = ["services", "ps", alias]
containers = services.get("data") or []
if containers:
    ops["logs docker"] = ["logs", "docker", alias, containers[0]["name"], "--tail", "5"]
if alias in ((call("db", "list").get("data") or {}).get("targets") or []):
    ops["db tables"] = ["db", "tables", alias]

actual = {name: shape(call(*argv)) for name, argv in ops.items()}
if record:
    json.dump(actual, open(expected_path, "w"), indent=2, sort_keys=True)
    open(expected_path, "a").write("\n")
    print(f"canary: recorded {len(actual)} op shapes to {expected_path}")
    sys.exit(0)

expected = json.load(open(expected_path))
drift = {n: {"expected": expected.get(n), "actual": a} for n, a in actual.items() if expected.get(n) != a}
for name, pair in drift.items():
    print(f"DRIFT {name}: {json.dumps(pair, sort_keys=True)}", file=sys.stderr)
print(f"canary: {len(actual) - len(drift)}/{len(actual)} ops match the expected key sets")
sys.exit(1 if drift else 0)
PY
}

case "${1:-all}" in
  up) fixture_up ;;
  down) fixture_down ;;
  canary) shift; canary "$@" ;;
  all)
    trap fixture_down EXIT
    fixture_up
    use_fixture_env
    for variant in "${VARIANTS[@]}"; do
      run_matrix "$variant"
    done
    record_outputs
    printf '\n%d PASS, %d FAIL\n' "$PASS_COUNT" "$FAIL_COUNT"
    ;;
  *) echo "usage: scripts/smoke.sh [up|down|canary <alias>]" >&2; exit 2 ;;
esac

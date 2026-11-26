#!/usr/bin/env bash
# Live smoke matrix for the compiled dist/sshepherd binary against a disposable local Docker
# fixture (scripts/sshd-fixture/): a debian and an alpine sshd, a postgres and an nginx app, all
# in ONE compose project, `sshepherd-smoke`. Every docker command here is scoped to that project;
# nothing else on the daemon is started, stopped or removed.
#
#   scripts/smoke.sh                 up, run the matrix on both sshd variants, always tear down
#   scripts/smoke.sh up | down       bring the fixture up / tear it down
#   scripts/smoke.sh canary <alias>  read-only ops against a real alias; key-set diff only
#
# The ssh aliases live in a fixture-only ssh config ($STATE/ssh_config, reached through
# SSHEPHERD_SSH_CONFIG_PATH), never in ~/.ssh/config. The keypair is generated per run and never
# committed. Host ports: 8413 (debian) and 8414 (alpine), override with
# SSHEPHERD_SMOKE_DEBIAN_PORT / SSHEPHERD_SMOKE_ALPINE_PORT.
set -euo pipefail

BIN="${BIN:-./dist/sshepherd}"
FIXTURE_DIR="scripts/sshd-fixture"
COMPOSE_PROJECT="sshepherd-smoke"
DEBIAN_PORT="${SSHEPHERD_SMOKE_DEBIAN_PORT:-8413}"
ALPINE_PORT="${SSHEPHERD_SMOKE_ALPINE_PORT:-8414}"
STATE="${SSHEPHERD_SMOKE_STATE_DIR:-/tmp/sshepherd-smoke}"
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
    SSHEPHERD_SMOKE_DEBIAN_PORT="$DEBIAN_PORT" SSHEPHERD_SMOKE_ALPINE_PORT="$ALPINE_PORT" \
    docker compose -p "$COMPOSE_PROJECT" "$@")
}

port_for() {
  if [[ "$1" == debian ]]; then echo "$DEBIAN_PORT"; else echo "$ALPINE_PORT"; fi
}

# -- bring-up / tear-down ---------------------------------------------------------------------

fixture_up() {
  for port in "$DEBIAN_PORT" "$ALPINE_PORT"; do
    if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
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
  : >"$STATE/ssh_config"
  for variant in "${VARIANTS[@]}"; do
    {
      printf 'Host smoke-%s\n' "$variant"
      printf '  HostName 127.0.0.1\n'
      printf '  Port %s\n' "$(port_for "$variant")"
      printf '  User root\n'
      printf '  IdentityFile %s\n' "$KEYDIR/id_ed25519"
      printf '  IdentitiesOnly yes\n'
      printf '  StrictHostKeyChecking accept-new\n'
      printf '  UserKnownHostsFile %s\n\n' "$STATE/known_hosts"
    } >>"$STATE/ssh_config"
  done
  pass "keypair and fixture ssh config written under $STATE"

  step "bring up the $COMPOSE_PROJECT compose project (debian + alpine sshd, postgres, app)"
  compose up -d --build
  pass "fixture containers started"

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
    if docker exec sshepherd-fixture-postgres psql -U sshepherd_ro -d fixture -tAc 'SELECT 1 FROM smoke_fixture' >/dev/null 2>&1; then
      db_ready=true
      break
    fi
    sleep 1
  done
  [[ "$db_ready" == true ]] || fail "postgres fixture never exposed smoke_fixture to sshepherd_ro"
  pass "postgres fixture seeded and readable by the read-only role"
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
container = "sshepherd-fixture-postgres"
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
run = "docker ps"
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
  assert_json "[$variant] check overview: ok + nproc > 0 + dead_end_risk boolean" check_overview \
    "d['ok'] is True and isinstance(d['data']['dead_end_risk'], bool) and d['data']['nproc'] > 0"

  step "[$variant] services ps"
  run_cli services_ps services ps "$alias"
  assert_json "[$variant] services ps: lists the fixture app container" services_ps \
    "d['ok'] is True and any('sshepherd-fixture-app' in str(c) for c in d['data'])"

  step "[$variant] logs docker"
  run_cli logs_docker logs docker "$alias" sshepherd-fixture-app --tail 5
  assert_json "[$variant] logs docker: LogsResult shape" logs_docker \
    "d['ok'] is True and 'lines' in d['data'] and 'next_since' in d['data']"

  step "[$variant] setup files-allowlist scaffold, then files ls"
  run_cli setup_files_allowlist setup files-allowlist scaffold "$alias" \
    --paths /root,/opt/myapp/prod.env,/opt/myapp/start.sh --yes
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

  step "[$variant] security listeners"
  run_cli security_listeners security listeners "$alias"
  assert_json "[$variant] security listeners: sshd port 22 listed" security_listeners \
    "d['ok'] is True and any(e['port'] == 22 for e in d['data']['listening'])"

  step "[$variant] db list / tables / query"
  run_cli db_list db list
  assert_json "[$variant] db list: fixture target declared" db_list \
    "d['ok'] is True and '$alias' in d['data']['targets']"
  run_cli db_tables db tables "$alias"
  assert_json "[$variant] db tables: smoke_fixture present" db_tables \
    "d['ok'] is True and any(t['table'] == 'smoke_fixture' for t in d['data'])"
  run_cli db_query db query "$alias" "SELECT note FROM smoke_fixture"
  assert_json "[$variant] db query: seeded row comes back" db_query \
    "d['ok'] is True and d['data'][0]['note'] == 'hello from sshepherd smoke fixture'"

  run_cli_any db_query_error db query "$alias" "SELECT nonexistent"
  assert_json "[$variant] db query error: sql_error names the column, no password text" db_query_error \
    "d['ok'] is False and 'column' in d['error']['data']['sql_error']['message'] and 'password' not in json.dumps(d).lower()"

  step "[$variant] deploy run --dry-run"
  run_cli deploy_dry_run deploy run "$alias" --dry-run
  assert_json "[$variant] deploy run --dry-run: plan only" deploy_dry_run \
    "d['ok'] is True and len(d['data']['steps']) == 1 and d['data']['steps'][0]['name'] == 'check-app'"

  step "[$variant] --timeout 2 against a 10 s query: remote timeout -k fires"
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

record_outputs() {
  for variant in "${VARIANTS[@]}"; do
    mkdir -p "$LIVE_DIR/$variant"
    python3 - "$STATE/out/$variant" "$LIVE_DIR/$variant" <<'PY'
import json, os, sys
src, dst = sys.argv[1:3]
for name in sorted(os.listdir(src)):
    if not name.endswith('.json'):
        continue
    d = json.load(open(os.path.join(src, name)))
    if name == 'services_ps.json':
        d['data'] = [c for c in d['data'] if 'sshepherd-fixture-' in json.dumps(c)]
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

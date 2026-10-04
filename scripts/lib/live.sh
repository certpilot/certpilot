# shellcheck shell=bash
# Shared by the scripts/live-*.sh checks. Sourced, never run.
#
# Each of those scripts answers one question the status page used to mark 🧪:
# does this feature work against the real thing — a real SMTP server, a real
# identity provider, a real CT index — rather than the fake its unit tests use?
# They share the dull half of the job: a core started from this tree on its
# in-memory store, signed into as a real administrator, and torn down however
# the run ends. That half is here so each script can be read as the question it
# asks.
#
# The start-up and sign-in sequence is the one scripts/agent-lifecycle.sh
# arrived at the hard way, including its two waits — for the gateway to
# register, and for the bootstrap administrator to exist before the one login
# attempt. Its comments explain why each wait is there.
#
# Before sourcing, set:
#   LIVE_NAME   short name; the work directory is .live/$LIVE_NAME
#   CORE_PORT   a port nothing else uses
#
# Then:
#   live_start_core [extra YAML appended to the config]
#                     LIVE_CORE_ENV="K=V …" adds to the core's environment
#                     LIVE_GATEWAYS is YAML for plugins.gateways, if any
#                     LIVE_AUTH is more YAML under auth:, and
#                     LIVE_BOOTSTRAP_ADMINS more entries in its list
#   live_sign_in
#   api …             curl with the session cookie
#   live_on_exit cmd  run at teardown, before the core stops

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

WORK="$ROOT/.live/$LIVE_NAME"
rm -rf "$WORK"
mkdir -p "$WORK"
API="http://127.0.0.1:$CORE_PORT"

say()  { printf '%s\n' "$*" >&2; }
die()  { say "FAIL: $*"; exit 1; }
pass() { say "  ok   $*"; }
skip() { say "  --   $*"; }

api() { curl -sS -b "$WORK/cookies" -c "$WORK/cookies" "$@"; }

# jq is not a dependency of this repository and python3 already is.
field() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }

_live_exit_hooks=()
live_on_exit() { _live_exit_hooks+=("$*"); }

_live_core_pid=""
_live_cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  local hook
  for hook in "${_live_exit_hooks[@]+"${_live_exit_hooks[@]}"}"; do
    eval "$hook" >/dev/null 2>&1 || true
  done
  if [[ -n "$_live_core_pid" ]]; then
    local kid
    for kid in $(pgrep -P "$_live_core_pid" 2>/dev/null || true); do
      kill -TERM "$kid" 2>/dev/null || true
    done
    kill -TERM "$_live_core_pid" 2>/dev/null || true
  fi
  local pids
  pids="$(lsof -ti:"$CORE_PORT" 2>/dev/null || true)"
  # Unquoted on purpose: one pid per word.
  # shellcheck disable=SC2086
  [[ -n "$pids" ]] && kill -TERM $pids 2>/dev/null || true
  wait 2>/dev/null || true
  if (( rc != 0 )) && [[ -s "$WORK/core.log" ]]; then
    say ""
    say "── the last of $WORK/core.log ──"
    tail -40 "$WORK/core.log" >&2
  fi
  exit "$rc"
}
trap _live_cleanup EXIT INT TERM

if lsof -ti:"$CORE_PORT" >/dev/null 2>&1; then
  die "port $CORE_PORT is already in use; something is still listening from an earlier run (lsof -ti:$CORE_PORT | xargs kill)"
fi

# Waits for an HTTP endpoint to answer 2xx.
live_wait_http() {
  local url="$1" what="$2" tries="${3:-600}"
  until curl -sf -m 2 "$url" >/dev/null 2>&1; do
    (( tries-- )) || die "$what never answered on $url"
    sleep 0.1
  done
}

# live_start_core [extra-yaml]
#
# The config is written here rather than taken from the core's development
# fallback, for the reasons agent-lifecycle.sh gives: the fallback hard-codes
# its ports, and config.dev.yaml differs between machines.
live_start_core() {
  local extra="${1:-}"
  cat >"$WORK/core.yaml" <<YAML
server:
  host: 127.0.0.1
  port: $CORE_PORT
  mode: development
auth:
  role_claim: certpilot_role
  bootstrap_admins:
    - admin@certpilot.local${LIVE_BOOTSTRAP_ADMINS:-}${LIVE_AUTH:-}
plugins:
  # Plain gRPC on loopback. Whether the core can dial a gateway over mutual TLS
  # is what gateway-compatibility.sh measures; none of these checks is about it.
  tls:
    insecure: true
  gateways:${LIVE_GATEWAYS:- []}
YAML
  [[ -n "$extra" ]] && printf '%s\n' "$extra" >>"$WORK/core.yaml"

  # Built, then run, rather than `go run`: a check that sets SSL_CERT_FILE for
  # the core would otherwise set it for the go command too, and the go command
  # fetching a module would then trust nothing but the check's own CA.
  say "building the core"
  go build -o "$WORK/certpilot-core" ./core/cmd/ || die "the core did not build"

  say "starting the core on :$CORE_PORT"
  # CERTPILOT_DB_URL is cleared so an exported one cannot point this at a real
  # database and leave test rows in it. LIVE_CORE_ENV is how a check hands the
  # core anything else, such as a CA bundle to trust.
  # shellcheck disable=SC2086
  env CERTPILOT_DB_URL= ${LIVE_CORE_ENV:-} "$WORK/certpilot-core" --config="$WORK/core.yaml" \
    >"$WORK/core.log" 2>&1 &
  _live_core_pid=$!

  local tries=900
  until curl -sf -m 2 "$API/healthz" >/dev/null 2>&1; do
    # A core that refused its configuration has exited, and waiting ninety
    # seconds for it to answer would only delay the one line that says why.
    kill -0 "$_live_core_pid" 2>/dev/null || die "the core exited before it answered"
    (( tries-- )) || die "the core never answered on $API/healthz"
    sleep 0.1
  done
}

# live_sign_in — as the bootstrap administrator, exactly once.
live_sign_in() {
  local password="" tries=600
  while (( tries-- )); do
    password="$(awk -F'password:' '/password:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$WORK/core.log")"
    [[ -n "$password" ]] && break
    sleep 0.1
  done
  [[ -n "$password" ]] || die "the core printed no bootstrap password; see $WORK/core.log"

  tries=600
  until grep -q "created the first administrator" "$WORK/core.log"; do
    (( tries-- )) || die "the core never created the bootstrap administrator; see $WORK/core.log"
    sleep 0.1
  done

  local body response
  body="$(printf '%s' "$password" | python3 -c '
import json, sys
print(json.dumps({"email": "admin@certpilot.local", "password": sys.stdin.read().strip()}))')"
  response="$(api -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' -d "$body")"
  grep -q 'certpilot_session' "$WORK/cookies" \
    || die "could not sign in as the bootstrap administrator: $response"
  pass "core up, signed in"
}

# live_docker_run name args… — a container removed at teardown, whatever happens.
live_docker_run() {
  local name="$1"; shift
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" "$@" >/dev/null || die "could not start $name"
  live_on_exit "docker rm -f $name"
}

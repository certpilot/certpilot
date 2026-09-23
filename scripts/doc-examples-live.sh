#!/usr/bin/env bash
# Send every documented API example that is safe to send to a core built from
# this tree, signed in as an administrator, and require each one to succeed.
#
# check-doc-examples.py already reads every curl in docs/ against the route
# table, which proves an example *could* run: the route exists, and the example
# carries a credential if the route needs one. It cannot prove the route answers
# the way the page implies. This does, for the subset where the answer is safe
# to ask for anywhere — a GET, carrying a credential, with nothing in its path or
# query the reader was meant to fill in.
#
# Against this tree's core, not a released one. The pages describe what is on
# main; a route documented today and released next month is correct here and a
# 404 against the last release, and that is not a documentation fault.
#
#   ./scripts/doc-examples-live.sh
#
# Exit status is the verdict.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Clear of dev.sh (8080), gateway-compatibility.sh (18080) and
# agent-lifecycle.sh (18081), so any of them can be running beside this.
CORE_PORT=18082
API="http://127.0.0.1:$CORE_PORT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/doc-examples-live.XXXXXX")"
core_pid=""

say() { printf '%s\n' "$*" >&2; }
die() { say "FAIL: $*"; exit 1; }

cleanup() {
  trap - EXIT INT TERM
  if [[ -n "$core_pid" ]]; then
    local kid
    for kid in $(pgrep -P "$core_pid" 2>/dev/null || true); do kill -TERM "$kid" 2>/dev/null || true; done
    kill -TERM "$core_pid" 2>/dev/null || true
  fi
  # -sTCP:LISTEN: without it lsof also lists every process holding a *client*
  # connection to the port, and killing those takes out whatever else is running.
  local pids
  pids="$(lsof -ti:"$CORE_PORT" -sTCP:LISTEN 2>/dev/null || true)"
  [[ -n "$pids" ]] && kill -TERM $pids 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

if lsof -ti:"$CORE_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  say "port $CORE_PORT is already in use; something is still listening from an earlier run"
  exit 2
fi

# A config written here rather than the core's development fallback, for the
# reason agent-lifecycle.sh gives: the fallback hard-codes port 8080, and
# config.dev.yaml is gitignored, so relying on either makes two people on one
# commit test two different cores. No gateway: every example sent here is a
# read, and a gateway would only add a second thing that can fail for reasons
# that say nothing about the documentation.
cat >"$WORK/core.yaml" <<YAML
server:
  host: 127.0.0.1
  port: $CORE_PORT
  mode: development
auth:
  role_claim: certpilot_role
  bootstrap_admins:
    - admin@certpilot.local
# Required even with no gateway listed: the core validates its gateway channel's
# TLS settings at startup whether or not anything will use them.
plugins:
  tls:
    insecure: true
YAML

say "starting a core from this tree on :$CORE_PORT"
# CERTPILOT_DB_URL cleared: exported, it would point this at a real database.
CERTPILOT_DB_URL= go run ./core/cmd/ --config="$WORK/core.yaml" >"$WORK/core.log" 2>&1 &
core_pid=$!

# Watching the process as well as the port: a core that refuses its config exits
# in a second, and without this the loop would wait the full ninety for a
# process that was already gone.
tries=900
until curl -sf -m 2 "$API/healthz" >/dev/null 2>&1; do
  if ! kill -0 "$core_pid" 2>/dev/null || (( tries-- <= 0 )); then
    die "the core never answered on $API:
$(tail -8 "$WORK/core.log")"
  fi
  sleep 0.1
done

# Waited for, then attempted once: the password is printed before its account
# exists, and retrying a sign-in trips the lockout. agent-lifecycle.sh has the
# long version of why.
tries=600
until grep -q "created the first administrator" "$WORK/core.log"; do
  (( tries-- )) || die "the core never created the bootstrap administrator"
  sleep 0.1
done
password="$(awk -F'password:' '/password:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$WORK/core.log")"
[[ -n "$password" ]] || die "the core printed no bootstrap password"

body="$(printf '%s' "$password" | python3 -c '
import json, sys
print(json.dumps({"email": "admin@certpilot.local", "password": sys.stdin.read().strip()}))')"
curl -sS -c "$WORK/jar" -X POST "$API/api/v1/auth/login" \
  -H 'Content-Type: application/json' -d "$body" >/dev/null
grep -q certpilot_session "$WORK/jar" || die "could not sign in as the bootstrap administrator"

python3 scripts/check-doc-examples.py --live "$API" --cookie-jar "$WORK/jar"

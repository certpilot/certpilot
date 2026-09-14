#!/usr/bin/env bash
# Does the core in this tree still work with the agent?
#
# Nothing asks that today. core/api/agents_test.go tests the core's handlers,
# agent/*_test.go tests the agent's logic, there is no agent/client_test.go, and
# scripts/dev.sh never starts an agent. Both halves test their own side against
# their own reading of the contract, and the contract itself — HTTP with an
# ed25519 signature over the body, described by certpilot-agent-sdk — is
# verified by nobody end to end.
#
# That is survivable while both halves are in one repository and one pull
# request compiles them together. It stops being survivable when the agent moves
# to its own repository and releases on its own schedule, which is the same
# problem the gateways have and the reason scripts/gateway-compatibility.sh
# exists. This is that script's counterpart, built before the move rather than
# after it.
#
# The whole lifecycle, against a real core, a real gateway and a real agent
# binary:
#
#   enrol → grant → request → install → report
#
#   ./scripts/agent-lifecycle.sh
#   AGENT_BIN=/path/to/certpilot-agent ./scripts/agent-lifecycle.sh
#
# AGENT_BIN is the seam. It builds the agent from this tree by default; once the
# agent lives in its own repository, pointing it at `go install
# github.com/certpilot/certpilot-agent/cmd@$VERSION` turns this into the
# compatibility matrix without changing anything else.
#
# Exit status is the verdict.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$ROOT/.agentlife"
BIN="$WORK/bin"
rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/served" "$WORK/state"

# Well away from the development stack *and* from gateway-compatibility.sh, so
# running this fights neither a core somebody has open in another terminal nor
# the other harness running beside it.
CORE_PORT=18081
GW_PORT=19092
API="http://127.0.0.1:$CORE_PORT"

# The name is under a .test domain, which RFC 6761 reserves and guarantees will
# never resolve. Nothing here should reach the network, and a name that cannot
# be looked up is the cheapest way to keep that true.
CERT_NAME="web.lifecycle.test"

# `grep … | head -1` would be the obvious spelling and is a trap under
# `set -o pipefail`: head exits after the first line, grep gets SIGPIPE writing
# the second, and the pipeline fails. One awk, no pipe, no trap.
GW_VERSION="${GW_VERSION:-$(awk '/^GW_VERSION/ {print $3; exit}' Makefile)}"
AGENT_BIN="${AGENT_BIN:-}"

core_pid=""
gw_pid=""

# Stopping these is not `kill $pid`, and getting it wrong is expensive.
#
# `go run` compiles to a temporary binary and runs it as a *child*. The pid this
# script holds is the parent, so killing it leaves the binary that actually owns
# the port running, unparented and invisible to the next run. What then happens
# is not a clean failure: the next core cannot bind, the harness talks to the
# previous one, and it fails with a wrong bootstrap password, a stale gateway
# registration and eventually an account lockout — none of which mention a
# process. Three separate bugs were chased here before the orphan was the
# answer.
#
# Killing the process group would be the neat fix and would take this script
# with it: a background job in a non-interactive shell shares its parent's
# group. So the children are killed by parentage, and then anything still
# holding one of the two ports is killed by port — which is safe precisely
# because these ports were chosen to belong to nobody else.
stop() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  local kid
  for kid in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill -TERM "$kid" 2>/dev/null || true
  done
  kill -TERM "$pid" 2>/dev/null || true
}

cleanup() {
  trap - EXIT INT TERM
  stop "$gw_pid"
  stop "$core_pid"
  local port pids
  for port in "$CORE_PORT" "$GW_PORT"; do
    pids="$(lsof -ti:"$port" 2>/dev/null || true)"
    [[ -n "$pids" ]] && kill -TERM $pids 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Refuse to start on a port somebody is already using, rather than binding
# nothing and talking to whatever is there. This is the check that would have
# turned the orphan above into one clear line.
for port in "$CORE_PORT" "$GW_PORT"; do
  if lsof -ti:"$port" >/dev/null 2>&1; then
    say "port $port is already in use; something is still listening from an earlier run"
    say "  lsof -ti:$port | xargs kill"
    exit 2
  fi
done

say()  { printf '%s\n' "$*" >&2; }
die()  { say "FAIL: $*"; exit 1; }
pass() { say "  ok   $*"; }

api() { curl -sS -b "$WORK/cookies" -c "$WORK/cookies" "$@"; }

# jq is not a dependency of this repository and python3 already is — both
# extract-routes.py and seed-demo.sh rely on it.
field() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }

wait_for_port() {
  local port="$1" tries=600
  while (( tries-- )); do
    lsof -ti:"$port" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

# ── The agent under test ──────────────────────────────────────────────────────

if [[ -z "$AGENT_BIN" ]]; then
  say "building the agent from this tree"
  # GOWORK=off because the agent is a standalone module and building it as one
  # is the thing being preserved. A build that quietly needed the workspace
  # would be a regression this harness should notice.
  ( cd "$ROOT/agent" && GOWORK=off go build -o "$BIN/certpilot-agent" ./cmd/ )
  AGENT_BIN="$BIN/certpilot-agent"
fi
[[ -x "$AGENT_BIN" ]] || die "no agent binary at $AGENT_BIN"
say "agent: $("$AGENT_BIN" --version) ($AGENT_BIN)"

# ── The gateway, then the core, in that order ─────────────────────────────────
#
# The order is not a preference. The core connects to its gateway plugins when
# it starts, so a core started first registers nothing and every issuance fails
# with "gateway selfsigned not found or disconnected" while the gateway sits
# there listening perfectly.

say "starting the self-signed gateway on :$GW_PORT ($GW_VERSION)"
go run "github.com/certpilot/certpilot-gateway-selfsigned/cmd@$GW_VERSION" \
  --port="$GW_PORT" --insecure >"$WORK/gateway.log" 2>&1 &
gw_pid=$!
wait_for_port "$GW_PORT" || die "the gateway never listened; see $WORK/gateway.log"

# --insecure on loopback, deliberately. What this harness is testing is the
# core-to-agent contract; whether the core can dial a gateway over mutual TLS is
# what gateway-compatibility.sh already measures, and doing it here would add a
# PKI to build and a second thing that can fail for reasons that say nothing
# about the agent.

say "starting the core on :$CORE_PORT"

# A config written here rather than the core's own development fallback.
#
# The fallback is what runs when no config file is found, and it hard-codes both
# port 8080 and a gateway at localhost:9091 — so a harness relying on it could
# not move off those ports, and running it would fight whatever somebody has
# open in another terminal. There is no environment variable for either; the
# port comes from this file and nowhere else.
#
# Writing it also makes the run hermetic, which pointing at the default would
# not: config.dev.yaml is gitignored and present on most developers' machines,
# so two people on the same commit would be testing two different cores.
cat >"$WORK/core.yaml" <<YAML
server:
  host: 127.0.0.1
  port: $CORE_PORT
  mode: development
auth:
  role_claim: certpilot_role
  # No anonymous fallback, which is the point: the harness signs in as a real
  # administrator and exercises the same authorisation the console does.
  bootstrap_admins:
    - admin@certpilot.local
renewal:
  scan_interval: 60
  default_lead_days: 30
plugins:
  tls:
    insecure: true
  gateways:
    - name: selfsigned
      addr: 127.0.0.1:$GW_PORT
      type: selfsigned
YAML

# CERTPILOT_DB_URL is cleared deliberately. Exported in the shell — which it is,
# for anybody who has run the store tests — it would point this harness at a
# real database and seed a template, a grant and an agent into it.
CERTPILOT_DB_URL= go run ./core/cmd/ --config="$WORK/core.yaml" >"$WORK/core.log" 2>&1 &
core_pid=$!

tries=900
until curl -sf -m 2 "$API/healthz" >/dev/null 2>&1; do
  (( tries-- )) || die "the core never answered on $API; see $WORK/core.log"
  sleep 0.1
done

# Waited for, not checked once. /healthz answers as soon as the HTTP server is
# listening, and gateway registration is a separate dial that finishes whenever
# it finishes — so a single grep here passes or fails depending on which of the
# two won, which is precisely the flake this found on its second run.
tries=600
until grep -q "gateway registered successfully" "$WORK/core.log"; do
  (( tries-- )) || die "the core never registered the gateway; see $WORK/core.log"
  sleep 0.1
done
pass "core up, gateway registered"

# ── Become an administrator ───────────────────────────────────────────────────
#
# The bootstrap password is printed once, to stdout, and never stored anywhere
# it can be read back. Scraped the way scripts/dev.sh scrapes it.

# Waited for on its own, and not inferred from anything earlier. The core
# registers its gateways before it creates the first administrator — line 7 of
# the log against line 13 — so a harness that took "gateway registered" as its
# cue to read the credential read a log that did not have one yet, roughly half
# the time.
#
# Extracted with one awk rather than `grep | head -1 | sed`, which is a trap
# under `set -o pipefail`: head exits after the first line, grep is SIGPIPEd
# writing the next, the pipeline fails, and `set -e` ends the script with no
# message at all.
password=""
tries=600
while (( tries-- )); do
  password="$(awk -F'password:' '/password:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$WORK/core.log")"
  [[ -n "$password" ]] && break
  sleep 0.1
done
[[ -n "$password" ]] || die "the core printed no bootstrap password; see $WORK/core.log"

# Checked, not assumed. `curl -sS` without -f exits 0 on a 401, so the obvious
# spelling of this reports a successful sign-in for a refused one and the run
# fails three steps later with "this request carried no credential".
login_body="$(printf '%s' "$password" | python3 -c '
import json, sys
print(json.dumps({"email": "admin@certpilot.local", "password": sys.stdin.read().strip()}))')"

# Waited for, then attempted once. Both halves of that matter.
#
# The credential is printed before the account it belongs to exists — the core
# writes its box at log line 13 and records "created the first administrator" at
# line 19 — so a harness quick enough to read the password and post it arrives
# before the row is there and is told, accurately and unhelpfully, that the
# email and password do not match an account. A person typing it never sees
# this; something reading it out of a log sees it every time.
#
# The obvious repair is to retry the login, and that is worse. The core locks an
# account out after a few failures, so a loop that posts a good password a
# hundred times in ten seconds is indistinguishable from an attack and the core
# treats it as one: "too many failed attempts for this account". Waiting for the
# account instead means the one attempt is made when it can succeed.
tries=600
until grep -q "created the first administrator" "$WORK/core.log"; do
  (( tries-- )) || die "the core never created the bootstrap administrator; see $WORK/core.log"
  sleep 0.1
done

login_response="$(api -X POST "$API/api/v1/auth/login" \
  -H 'Content-Type: application/json' -d "$login_body")"
grep -q 'certpilot_session' "$WORK/cookies" \
  || die "could not sign in as the bootstrap administrator: $login_response"
pass "signed in"

# ── Enrol ─────────────────────────────────────────────────────────────────────

# The response is captured before it is parsed, so a refusal is reported as what
# the core said rather than as a Python traceback about a missing key.
token_response="$(api -X POST "$API/api/v1/agent-enrol-tokens" -H 'Content-Type: application/json' \
  -d '{"name":"agent-lifecycle harness"}')"
token="$(printf '%s' "$token_response" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)"
[[ -n "$token" ]] || die "no enrolment token was issued: $token_response"

enrol_out="$("$AGENT_BIN" enrol --server "$API" --token "$token" \
  --name lifecycle-host --state-dir "$WORK/state" 2>&1)" \
  || die "enrol failed: $enrol_out"
agent_id="$(printf '%s\n' "$enrol_out" | awk '/agent id/ {print $NF}')"
[[ -n "$agent_id" ]] || die "enrol printed no agent id: $enrol_out"
pass "enrolled as $agent_id"

# ── Grant it something ────────────────────────────────────────────────────────
#
# After enrolment, not before. A grant targets an agent by id or by label, and
# `enrol` has no way to set a label — so the id is the only handle that exists,
# and it does not exist until the agent has enrolled.

ca_id="$(api "$API/api/v1/ca-accounts" | field '["data"][0]["id"]')"
template_id="$(api -X POST "$API/api/v1/certificate-templates" -H 'Content-Type: application/json' \
  -d "{\"slug\":\"lifecycle-host\",\"name\":\"Lifecycle host\",\"ca_account_id\":\"$ca_id\"}" \
  | field '["id"]')"
api -X POST "$API/api/v1/agent-grants" -H 'Content-Type: application/json' \
  -d "{\"name\":\"lifecycle\",\"template_id\":\"$template_id\",\"names\":[\"*.lifecycle.test\"],\"agent_id\":\"$agent_id\"}" \
  >/dev/null || die "could not create the grant"
pass "granted *.lifecycle.test"

# ── Request ───────────────────────────────────────────────────────────────────

"$AGENT_BIN" request --name "$CERT_NAME" --state-dir "$WORK/state" >"$WORK/request.log" 2>&1 \
  || { cat "$WORK/request.log" >&2; die "the agent could not obtain a certificate"; }
pass "requested $CERT_NAME"

# ── Install ───────────────────────────────────────────────────────────────────

cat >"$WORK/installs.json" <<JSON
{
  "destinations": [
    {
      "name": "web",
      "certificate": "$CERT_NAME",
      "cert_path": "$WORK/served/cert.pem",
      "key_path": "$WORK/served/privkey.pem",
      "key_mode": "0600"
    }
  ]
}
JSON

"$AGENT_BIN" run --once --state-dir "$WORK/state" --installs "$WORK/installs.json" \
  >"$WORK/run.log" 2>&1 || { cat "$WORK/run.log" >&2; die "the agent's cycle failed"; }
pass "installed and reported"

# ── What the two halves agree about ───────────────────────────────────────────
#
# Each of these is a fact the core can only know because the agent told it, over
# the contract, and each fails differently.

[[ -s "$WORK/served/cert.pem" && -s "$WORK/served/privkey.pem" ]] \
  || die "the destination files were not written"

# python3 rather than stat, which spells this differently on the two platforms
# this runs on and does not fail cleanly between them. `stat -f` is the format
# flag on BSD and means "filesystem status" on GNU, where it *succeeds* with
# unrelated output — so a `stat -f … || stat -c …` fallback never reaches the
# second form on Linux and compares a line about the filesystem to "600".
mode="$(python3 -c 'import os, sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, "03o"))' \
  "$WORK/served/privkey.pem")"
[[ "$mode" == "600" ]] || die "the installed private key is mode $mode, not 600"
pass "key written 0600"

status="$(api "$API/api/v1/agents/$agent_id" | field '.get("data",{}).get("status","")')"
[[ "$status" == "ACTIVE" ]] || die "the core has this agent as '$status', not ACTIVE"
pass "the fleet has it ACTIVE"

issued="$(api "$API/api/v1/certificates" | python3 -c "
import sys, json
for c in json.load(sys.stdin).get('data', []):
    if c.get('common_name') == '$CERT_NAME':
        print(c.get('status', ''))
        break
")"
[[ "$issued" == "ISSUED" ]] || die "the core has $CERT_NAME as '${issued:-absent}', not ISSUED"
pass "the core has $CERT_NAME ISSUED"

# The assertion this harness exists for.
#
# Everything above can pass while the two halves disagree about *which*
# certificate: the core can hold one it issued, the host can hold one it got
# from somewhere else, and every status field still reads correctly. Comparing
# the fingerprint the core recorded against the SHA-256 of the file actually on
# disk is the one check that cannot be satisfied by two systems that are merely
# both working.
reported="$(api "$API/api/v1/agent-installations" | python3 -c "
import sys, json
rows = json.load(sys.stdin)
rows = rows.get('data', rows) if isinstance(rows, dict) else rows
for r in rows:
    if r.get('agent_id') == '$agent_id' and r.get('certificate_name') == '$CERT_NAME':
        print(r.get('fingerprint_sha256', ''))
        break
")"
[[ -n "$reported" ]] || die "the core recorded no installation for $CERT_NAME on this agent"

on_disk="$(openssl x509 -in "$WORK/served/cert.pem" -outform DER 2>/dev/null | openssl dgst -sha256 -hex | awk '{print $NF}')"
[[ "$reported" == "$on_disk" ]] \
  || die "the core recorded $reported and the file on disk is $on_disk — the two halves do not hold the same certificate"
pass "the installed file is the certificate the core issued ($on_disk)"

say ""
say "the agent and this core agree, end to end."

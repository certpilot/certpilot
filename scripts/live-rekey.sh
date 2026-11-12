#!/usr/bin/env bash
# Can the key encryption key be rotated, and the old one then dropped?
#
# The unit tests re-seal envelopes they wrote themselves, in a store that has
# no columns. This does it to a PostgreSQL database a core filled through its
# own API, with a core running beside the re-seal, and then takes the old key
# away and uses everything it sealed.
#
#   1. a core with key A fills a database: a CA account, a certificate with its
#      private key, a deployment target, a notification channel, a cloud
#      connection and an ACME credential
#   2. the core restarts with key B, and A retired. The report must say A still
#      seals every one of those, and B nothing
#   3. `certpilot-core --reseal` runs while that core serves. Afterwards the
#      report must say A seals nothing; a second run must have nothing to do
#   4. the core restarts with key B alone, and then
#        - the private key sealed under A exports, byte for byte as before
#        - the CA account sealed under A issues, and the certificate renews
#        - the channel and the target sealed under A sign a delivery with the
#          secret they were given, which the receiver checks
#        - nothing in the database names key A as sealing a record
#
# What step 4 does not claim: audit entries key A signed can no longer be
# checked without it. The report names that range, and the check asserts it
# does.
#
#   ./scripts/live-rekey.sh
#
# Needs Docker, Go, python3 and openssl. Exit status is the verdict.

LIVE_NAME=rekey
CORE_PORT=18095
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

GW_VERSION="${GW_VERSION:-v0.4.3}"
GW_PORT=19295
PG_PORT=55441
HOOK_PORT=18096
PG_IMAGE="${PG_IMAGE:-postgres:17-alpine}"
DB_URL="postgres://postgres:rekey@127.0.0.1:$PG_PORT/postgres?sslmode=disable"

# json path — reads JSON on stdin and prints one value, or nothing.
json() { python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print($1)
except (ValueError, KeyError, IndexError, TypeError, AttributeError):
    pass"; }

# create what path body — POSTs, prints the new record's id, or dies with the
# core's answer.
create() {
  local response id
  response="$(api -X POST "$API/api/v1/$2" -H 'Content-Type: application/json' -d "$3")"
  id="$(printf '%s' "$response" | json '(d.get("data") or d.get("certificate") or d)["id"]')"
  [[ -n "$id" ]] || die "could not create $1: $response"
  printf '%s' "$id"
}

# ── PostgreSQL, the gateway and a receiver ────────────────────────────────────

live_docker_run certpilot-live-rekey-pg -e POSTGRES_PASSWORD=rekey -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE"
for _ in $(seq 1 60); do
  docker exec certpilot-live-rekey-pg pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 0.5
done
sleep 1

say "building the core"
go build -o "$WORK/certpilot-core" ./core/cmd/ || die "the core did not build"
"$WORK/certpilot-core" --migrate --db "$DB_URL" --migrations migrations >"$WORK/migrate.log" 2>&1 \
  || die "the migrations did not apply: $(tail -5 "$WORK/migrate.log")"

say "starting the self-signed gateway on :$GW_PORT ($GW_VERSION)"
GOWORK=off GOBIN="$WORK/bin" go install "github.com/certpilot/certpilot-gateway-selfsigned/cmd@$GW_VERSION" \
  || die "could not fetch the self-signed gateway $GW_VERSION"
"$WORK/bin/cmd" --port="$GW_PORT" --insecure >"$WORK/gateway.log" 2>&1 &
live_on_exit "kill $!"
for _ in $(seq 1 100); do
  (exec 3<>"/dev/tcp/127.0.0.1/$GW_PORT") 2>/dev/null && break
  sleep 0.1
done
LIVE_GATEWAYS="
    - name: selfsigned
      addr: 127.0.0.1:$GW_PORT
      type: selfsigned"

# Records each delivery and whether its signature verifies with the secret the
# channel or target was created with. A secret that came back wrong from a
# re-seal would still deliver; it would not verify.
HOOK_SECRET="$(openssl rand -hex 16)"
HOOK_LOG="$WORK/webhook.jsonl"
: >"$HOOK_LOG"
cat >"$WORK/receiver.py" <<'PY'
import hashlib, hmac, json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port, secret, log = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3]

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ts = self.headers.get("X-CertPilot-Timestamp", "")
        want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        with open(log, "a") as f:
            f.write(json.dumps({
                "path": self.path,
                "verified": hmac.compare_digest(want, self.headers.get("X-CertPilot-Signature", "")),
            }) + "\n")
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", port), Receiver).serve_forever()
PY
python3 "$WORK/receiver.py" "$HOOK_PORT" "$HOOK_SECRET" "$HOOK_LOG" 2>"$WORK/receiver.log" &
live_on_exit "kill $!"
live_wait_http "http://127.0.0.1:$HOOK_PORT/ready" "the webhook receiver"

# delivered path — waits for a delivery to that path and requires it verified.
delivered() {
  python3 - "$HOOK_LOG" "$1" <<'PY' || die "no verified delivery to $1 after the retired key was dropped"
import json, sys, time
log, path = sys.argv[1], sys.argv[2]
deadline = time.time() + 30
while time.time() < deadline:
    rows = [json.loads(l) for l in open(log) if l.strip()]
    rows = [r for r in rows if r["path"] == path]
    if rows:
        sys.exit(0 if rows[-1]["verified"] else "the delivery to %s did not verify with the secret it was created with" % path)
    time.sleep(0.5)
sys.exit("nothing was delivered to %s" % path)
PY
}

# ── Two keys, and a core that can be restarted with either ────────────────────

new_kek() { "$WORK/certpilot-core" --generate-kek 2>/dev/null | sed 's/^CERTPILOT_KEK=//'; }
KEK_A="$(new_kek)"
KEK_B="$(new_kek)"
[[ -n "$KEK_A" && -n "$KEK_B" && "$KEK_A" != "$KEK_B" ]] || die "could not generate two keys"

# start_core primary [retired] — (re)starts the core on the same database. The
# session cookie is a row in that database, so it survives the restart.
start_core() {
  if [[ -n "$_live_core_pid" ]]; then
    kill -TERM "$_live_core_pid" 2>/dev/null || true
    wait "$_live_core_pid" 2>/dev/null || true
    for _ in $(seq 1 100); do
      curl -sf -m 1 "$API/healthz" >/dev/null 2>&1 || break
      sleep 0.1
    done
    cat "$WORK/core.log" >>"$WORK/core.previous.log"
  fi
  LIVE_CORE_ENV="CERTPILOT_DB_URL=$DB_URL CERTPILOT_KEK=$1 CERTPILOT_KEK_RETIRED=${2:-}"
  live_start_core
}

# report — the key report, saved to $WORK/report.json.
report() {
  local status
  status="$(api -o "$WORK/report.json" -w '%{http_code}' "$API/api/v1/secrets/keys")"
  [[ "$status" == 200 ]] || die "GET /secrets/keys answered $status: $(cat "$WORK/report.json")"
}

# sealed_by key-id — how many records the report says that key seals.
sealed_by() {
  python3 - "$WORK/report.json" "$1" <<'PY'
import json, sys
keys = {k["key_id"]: k for k in json.load(open(sys.argv[1]))["keys"]}
print(keys[sys.argv[2]]["sealed_total"] if sys.argv[2] in keys else "absent")
PY
}

# ── 1. Key A fills the database ───────────────────────────────────────────────

start_core "$KEK_A"
live_sign_in
report
KEY_A="$(json 'd["primary_key_id"]' <"$WORK/report.json")"

ca_id="$(create "the CA account" ca-accounts \
  "{\"name\":\"rekey\",\"provider_type\":\"selfsigned\",\"gateway_addr\":\"127.0.0.1:$GW_PORT\",\"config\":{\"organization\":\"Rekey Check\"}}")"

cert_id="$(create "a certificate under key A" certificates \
  "{\"common_name\":\"before.rekey.example.local\",\"ca_account_id\":\"$ca_id\",\"key_type\":\"ECDSA\",\"key_size\":256}")"
api "$API/api/v1/certificates/$cert_id/private-key" >"$WORK/key.before.json"
key_before="$(json 'd.get("private_key_pem") or d["data"]["private_key_pem"]' <"$WORK/key.before.json")"
[[ "$key_before" == *"PRIVATE KEY"* ]] || die "the private key did not export under key A: $(cat "$WORK/key.before.json")"

target_id="$(create "the deployment target" deployment-targets "{
  \"name\":\"rekey receiver\",\"target_type\":\"webhook\",
  \"config\":{\"url\":\"http://127.0.0.1:$HOOK_PORT/deploy\",\"signing_secret\":\"$HOOK_SECRET\",\"allow_insecure_http\":true}}")"
api -X POST "$API/api/v1/certificates/$cert_id/targets" -H 'Content-Type: application/json' \
  -d "{\"target_id\":\"$target_id\"}" >"$WORK/bind.json" || die "could not bind the certificate to the target"

channel_id="$(create "the notification channel" notification-channels "{
  \"name\":\"rekey hook\",\"channel_type\":\"webhook\",\"severity_threshold\":\"INFO\",
  \"config\":{\"url\":\"http://127.0.0.1:$HOOK_PORT/alert\",\"signing_secret\":\"$HOOK_SECRET\",\"allow_insecure_http\":true}}")"

conn_id="$(create "the cloud connection" cloud/connections '{
  "name":"rekey aws","provider":"aws_acm","sync_interval_minutes":1440,"is_enabled":false,
  "config":{"region":"eu-west-1","access_key_id":"AKIAREKEYCHECK000000","secret_access_key":"not-a-real-secret-not-a-real-secret-0000"}}')"
: "$conn_id"

api -X POST "$API/api/v1/certificate-templates" -H 'Content-Type: application/json' -d "{
  \"slug\":\"rekey\",\"name\":\"Rekey\",\"ca_account_id\":\"$ca_id\",\"subject_mode\":\"SUPPLIED\",
  \"allowed_key_types\":[\"ECDSA\"],\"key_custody_required\":\"ANY\",\"renew_before_days\":30,
  \"is_enabled\":true,\"san_rules\":{\"suffixes\":[\".example.local\"]}}" >/dev/null
cred="$(api -X POST "$API/api/v1/acme/credentials" -H 'Content-Type: application/json' \
  -d '{"name":"rekey","template":"rekey"}')"
[[ "$cred" == *kid* ]] || die "could not create the ACME credential: $cred"

report
python3 - "$WORK/report.json" "$KEY_A" <<'PY' || exit 1
import json, sys
keys = {k["key_id"]: k for k in json.load(open(sys.argv[1]))["keys"]}
a = keys[sys.argv[2]]
kinds = ["ca_account", "certificate", "deployment_target", "notification_channel", "cloud_connection", "acme_credential"]
missing = [k for k in kinds if a["sealed"].get(k, 0) < 1]
if missing:
    sys.exit("FAIL: under key A the report shows nothing sealed for: %s" % ", ".join(missing))
PY
sealed_under_a="$(sealed_by "$KEY_A")"
pass "key $KEY_A seals $sealed_under_a records, at least one of each of the six kinds"

# ── 2. Rotate: B is primary, A is retired ─────────────────────────────────────

start_core "$KEK_B" "$KEK_A"
report
KEY_B="$(json 'd["primary_key_id"]' <"$WORK/report.json")"
[[ "$KEY_B" != "$KEY_A" ]] || die "after the rotation the primary key is still $KEY_A"
[[ "$(sealed_by "$KEY_A")" == "$sealed_under_a" && "$(sealed_by "$KEY_B")" == 0 ]] \
  || die "after the rotation the report reads A=$(sealed_by "$KEY_A") B=$(sealed_by "$KEY_B"), want A=$sealed_under_a B=0"
status_a="$(python3 -c '
import json, sys
print({k["key_id"]: k["status"] for k in json.load(open(sys.argv[1]))["keys"]}[sys.argv[2]])' "$WORK/report.json" "$KEY_A")"
[[ "$status_a" == retired ]] || die "key A reads $status_a after the rotation, want retired"
pass "rotated: key $KEY_B seals nothing yet, key $KEY_A is retired and still seals all $sealed_under_a"

# ── 3. Re-seal beside the running core ────────────────────────────────────────

reseal() {
  env CERTPILOT_DB_URL="$DB_URL" CERTPILOT_KEK="$KEK_B" CERTPILOT_KEK_RETIRED="$KEK_A" \
    "$WORK/certpilot-core" --reseal --config="$WORK/core.yaml"
}
reseal >"$WORK/reseal.1.log" 2>&1 || die "--reseal failed: $(tail -20 "$WORK/reseal.1.log")"
grep -q "^re-sealed $sealed_under_a record(s) under key $KEY_B" "$WORK/reseal.1.log" \
  || die "--reseal did not report re-sealing $sealed_under_a records: $(cat "$WORK/reseal.1.log")"
report
[[ "$(sealed_by "$KEY_A")" == 0 && "$(sealed_by "$KEY_B")" == "$sealed_under_a" ]] \
  || die "after the re-seal the report reads A=$(sealed_by "$KEY_A") B=$(sealed_by "$KEY_B"), want A=0 B=$sealed_under_a"
pass "--reseal moved all $sealed_under_a records to key $KEY_B while the core was serving"

reseal >"$WORK/reseal.2.log" 2>&1 || die "a second --reseal failed: $(tail -20 "$WORK/reseal.2.log")"
grep -q "^re-sealed 0 record(s)" "$WORK/reseal.2.log" \
  || die "a second --reseal had work to do: $(cat "$WORK/reseal.2.log")"
pass "a second --reseal has nothing to do"

# ── 4. Drop key A, and use everything it sealed ───────────────────────────────

start_core "$KEK_B"
pass "the core starts with key $KEY_B alone"

api "$API/api/v1/certificates/$cert_id/private-key" >"$WORK/key.after.json"
key_after="$(json 'd.get("private_key_pem") or d["data"]["private_key_pem"]' <"$WORK/key.after.json")"
[[ -n "$key_after" && "$key_after" == "$key_before" ]] \
  || die "the private key sealed under key A does not export as it did: $(head -c 300 "$WORK/key.after.json")"
pass "the private key sealed under the dropped key exports, unchanged"

create "a certificate through the CA account sealed under key A" certificates \
  "{\"common_name\":\"after.rekey.example.local\",\"ca_account_id\":\"$ca_id\",\"key_type\":\"ECDSA\",\"key_size\":256}" >/dev/null
pass "the CA account sealed under the dropped key issues"

job="$(api -X POST "$API/api/v1/certificates/$cert_id/renew")"
job_id="$(printf '%s' "$job" | json '(d.get("data") or d).get("job_id") or (d.get("data") or d)["id"]')"
[[ -n "$job_id" ]] || die "the renewal was not queued: $job"
renewed=""
for _ in $(seq 1 60); do
  renewed="$(api "$API/api/v1/certificates/$cert_id" | json '(d.get("data") or d)["renewal_count"]')"
  [[ "$renewed" == 1 ]] && break
  sleep 0.5
done
[[ "$renewed" == 1 ]] || die "the certificate did not renew through the re-sealed CA account"
pass "the certificate renews"

test_status="$(api -o "$WORK/test.json" -w '%{http_code}' -X POST "$API/api/v1/notification-channels/$channel_id/test")"
[[ "$test_status" == 200 ]] || die "the channel test answered $test_status: $(cat "$WORK/test.json")"
delivered /alert
pass "the notification channel signs with the secret it was given"

deploy="$(api -X POST "$API/api/v1/certificates/$cert_id/deploy")"
[[ "$deploy" == *queued* ]] || die "the deployment was not queued: $deploy"
delivered /deploy
pass "the deployment target signs with the secret it was given"

report
[[ "$(sealed_by "$KEY_A")" == 0 ]] || die "after the drop, $(sealed_by "$KEY_A") records still name key A"
python3 - "$WORK/report.json" "$KEY_A" <<'PY' || exit 1
import json, sys
keys = {k["key_id"]: k for k in json.load(open(sys.argv[1]))["keys"]}
a = keys.get(sys.argv[2])
if not a or a["status"] != "missing" or not a.get("audit") or a["audit"]["first_seq"] != 1:
    sys.exit("FAIL: the report does not name the dropped key as missing with the audit entries it signed: %r" % a)
print("  ok   the report names the dropped key as missing, and the audit entries it signed: %d to %d"
      % (a["audit"]["first_seq"], a["audit"]["last_seq"]), file=sys.stderr)
PY

say ""
say "rekey: every check passed. Key $KEY_A was retired, re-sealed away from and dropped; everything it sealed still works under $KEY_B"

#!/usr/bin/env bash
# Does External Account Binding work against an ACME server that requires it?
#
# ZeroSSL, Google Trust Services and SSL.com will not open an ACME account
# without EAB: a key id and an HMAC key issued out of band, with which the
# client signs its new account key. The ACME gateway builds that binding, and
# its unit tests check the configuration around it; nothing checked that a
# server which requires a binding accepts the one it builds.
#
# This asks Pebble, the ACME server Let's Encrypt builds for testing clients,
# in its EAB-required mode, through the whole path an operator uses: a CA
# account on the core, the released ACME gateway, and a certificate requested
# from the core.
#
#   the right key id and HMAC key      a certificate, then a renewal through the
#                                      same account
#   no binding at all                  refused, and the refusal says why
#   the right key id, a wrong HMAC     refused
#   a key id Pebble never issued       refused
#
# Pebble is told to treat every authorization as valid, because what is under
# test is the account, not the challenge; the challenge is exercised against
# Pebble in docs/walkthroughs/acme-nginx.md. What this cannot tell you is
# anything about a commercial CA's own EAB rules, such as a key id that works
# once only.
#
#   ./scripts/live-eab.sh
#   GATEWAY_VERSION=0.2.0 ./scripts/live-eab.sh
#
# Needs Docker and python3. Exit status is the verdict.

LIVE_NAME=eab
CORE_PORT=18087
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.10.1}"
# The gateway people run, as released, like agent-lifecycle.sh runs the
# released agent.
GATEWAY_VERSION="${GATEWAY_VERSION:-$(awk '/^GW_VERSION/ {sub(/^v/, "", $3); print $3; exit}' Makefile)}"
GATEWAY_IMAGE="ghcr.io/certpilot/gateway-acme:$GATEWAY_VERSION"
GW_PORT=19097
NET=certpilot-live-eab

EAB_KID=certpilot-live
# 32 random bytes, base64url without padding, the form CAs hand out.
EAB_HMAC="$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode())')"
WRONG_HMAC="$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode())')"

# ── Pebble, requiring a binding ───────────────────────────────────────────────

docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null || die "could not create a Docker network"
live_on_exit "docker network rm $NET"

# Pebble's own test CA, which signs the certificate its API serves. The gateway
# is handed it to trust, so the gateway verifies Pebble rather than skipping it.
cid="$(docker create "$PEBBLE_IMAGE")" || die "could not pull $PEBBLE_IMAGE"
docker cp "$cid:/test/certs/pebble.minica.pem" "$WORK/pebble-ca.pem" >/dev/null
docker cp "$cid:/test/config/pebble-config.json" "$WORK/pebble-default.json" >/dev/null
docker rm "$cid" >/dev/null

python3 - "$WORK/pebble-default.json" "$EAB_KID" "$EAB_HMAC" >"$WORK/pebble.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
config["pebble"]["externalAccountBindingRequired"] = True
config["pebble"]["externalAccountMACKeys"] = {sys.argv[2]: sys.argv[3]}
print(json.dumps(config))
PY
chmod a+r "$WORK/pebble.json" "$WORK/pebble-ca.pem"

say "starting Pebble ($PEBBLE_IMAGE), EAB required"
live_docker_run certpilot-live-pebble --network "$NET" --network-alias pebble \
  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 \
  -v "$WORK/pebble.json:/eab.json:ro" \
  "$PEBBLE_IMAGE" -config /eab.json

say "starting the ACME gateway ($GATEWAY_IMAGE)"
live_docker_run certpilot-live-gateway-acme --network "$NET" -p "127.0.0.1:$GW_PORT:9092" \
  -e SSL_CERT_FILE=/pebble-ca.pem -v "$WORK/pebble-ca.pem:/pebble-ca.pem:ro" \
  --tmpfs /state \
  "$GATEWAY_IMAGE" --port=9092 --insecure --state-dir=/state \
  --directory=https://pebble:14000/dir

tries=300
until docker logs certpilot-live-pebble 2>&1 | grep -q 'Listening on: 0.0.0.0:14000'; do
  (( tries-- )) || die "Pebble never started: $(docker logs certpilot-live-pebble 2>&1 | tail -5)"
  sleep 0.1
done
tries=300
until nc -z 127.0.0.1 "$GW_PORT" 2>/dev/null; do
  (( tries-- )) || die "the ACME gateway never listened: $(docker logs certpilot-live-gateway-acme 2>&1 | tail -5)"
  sleep 0.1
done
pass "Pebble requires EAB; the gateway trusts Pebble's CA"

# ── The core ──────────────────────────────────────────────────────────────────

live_start_core
live_sign_in

# account name email [eab-json-fields] — a CA account through the ACME gateway.
# Prints its id.
account() {
  local body response extra="${3:-}"
  [[ -n "$extra" ]] || extra='{}'
  body="$(python3 -c '
import json, sys
config = {"directory_url": "https://pebble:14000/dir", "email": sys.argv[2], "challenge": "http-01"}
config.update(json.loads(sys.argv[3]))
print(json.dumps({"name": sys.argv[1], "provider_type": "acme",
                  "gateway_addr": "127.0.0.1:" + sys.argv[4], "config": config}))' \
    "$1" "$2" "$extra" "$GW_PORT")"
  response="$(api -X POST "$API/api/v1/ca-accounts" -H 'Content-Type: application/json' -d "$body")"
  printf '%s' "$response" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null \
    || die "the core would not save CA account $1: $response"
}

# issue account-id name — prints "<http status> <body>".
issue() {
  api -o "$WORK/issue.json" -w '%{http_code}' -X POST "$API/api/v1/certificates" \
    -H 'Content-Type: application/json' \
    -d "{\"common_name\":\"$2\",\"ca_account_id\":\"$1\",\"key_type\":\"ECDSA\",\"key_size\":256}"
  printf ' '
  cat "$WORK/issue.json"
}

# refused what result words… — the request failed, and the reason names at
# least one of the words.
refused() {
  local what="$1" result="$2"; shift 2
  [[ "$result" != 20* ]] || die "$what: a certificate was issued: ${result:0:300}"
  printf '%s: %s\n' "$what" "$result" >>"$WORK/refusals.txt"
  local word
  for word in "$@"; do
    grep -qi -- "$word" <<<"$result" && return 0
  done
  die "$what: refused, but the answer does not say why: ${result:0:600}"
}

no_eab="$(account "no binding" noeab@live.test)"
refused "no binding" "$(issue "$no_eab" noeab.live.test)" "externalAccountRequired" "external account"
pass "an account with no binding is refused, and the answer says a binding is required"

wrong="$(account "wrong HMAC" wronghmac@live.test "{\"eab_key_id\":\"$EAB_KID\",\"eab_hmac_key\":\"$WRONG_HMAC\"}")"
refused "wrong HMAC" "$(issue "$wrong" wronghmac.live.test)" "external account binding"
pass "the right key id with the wrong HMAC key is refused"

unknown="$(account "unknown kid" unknownkid@live.test "{\"eab_key_id\":\"never-issued\",\"eab_hmac_key\":\"$EAB_HMAC\"}")"
refused "unknown kid" "$(issue "$unknown" unknownkid.live.test)" "not known to the ACME server"
pass "a key id Pebble never issued is refused"

good="$(account "bound" bound@live.test "{\"eab_key_id\":\"$EAB_KID\",\"eab_hmac_key\":\"$EAB_HMAC\"}")"
result="$(issue "$good" bound.live.test)"
[[ "$result" == 20* ]] || die "the bound account could not issue: ${result:0:600}"
cert_id="$(python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))
b = b.get("data", b)
print(b["id"])' "$WORK/issue.json")"

# The certificate must be one Pebble signed, and must be ISSUED, not merely
# accepted as a request.
tries=60
while :; do
  cert="$(api "$API/api/v1/certificates/$cert_id")"
  status="$(printf '%s' "$cert" | python3 -c 'import sys,json; b=json.load(sys.stdin); print(b.get("data",b).get("status",""))')"
  [[ "$status" == ISSUED ]] && break
  [[ "$status" == FAILED ]] && die "the bound account's certificate failed: ${cert:0:600}"
  (( tries-- )) || die "the bound account's certificate never reached ISSUED (status $status)"
  sleep 1
done
issuer="$(printf '%s' "$cert" | python3 -c 'import sys,json; b=json.load(sys.stdin); print(b.get("data",b).get("issuer_dn",""))')"
grep -qi pebble <<<"$issuer" || die "the certificate was issued, but not by Pebble: $issuer"
pass "the bound account issued a certificate, signed by Pebble ($issuer)"

# A second order through the same account. The gateway registers the account
# again before each order, with the binding again, and a server that has
# already bound this key must answer with the existing account.
status="$(api -o "$WORK/renew.json" -w '%{http_code}' -X POST "$API/api/v1/certificates/$cert_id/renew")"
[[ "$status" == 20* ]] || die "the renewal was refused: $status $(cat "$WORK/renew.json")"
tries=90
while :; do
  renewed="$(api "$API/api/v1/certificates/$cert_id")"
  serial_now="$(printf '%s' "$renewed" | python3 -c 'import sys,json; b=json.load(sys.stdin); print(b.get("data",b).get("serial_number",""))')"
  serial_was="$(printf '%s' "$cert" | python3 -c 'import sys,json; b=json.load(sys.stdin); print(b.get("data",b).get("serial_number",""))')"
  [[ -n "$serial_now" && "$serial_now" != "$serial_was" ]] && break
  (( tries-- )) || die "the renewal through the bound account never produced a new certificate: ${renewed:0:600}"
  sleep 1
done
pass "a renewal through the same bound account issued a new certificate"

say ""
say "eab: every check passed against Pebble ($PEBBLE_IMAGE) through $GATEWAY_IMAGE"

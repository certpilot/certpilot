#!/usr/bin/env bash
# Do real ACME clients get certificates from the core's ACME server?
#
# The server's unit tests drive it with the Go ACME client and with requests
# built by hand. Neither is what an operator runs. This runs three that are,
# each as released, against a core built from this tree and the released
# self-signed gateway:
#
#   certbot   registers with a credential, is issued two names, renews in
#             place, is told by renewalInfo when to renew, and revokes
#   lego      the same through renewalInfo and replaces, which it sends
#   acme.sh   registers, is issued, renews in place
#
# and the refusals that matter: no credential, and a name the template does not
# allow. lego and acme.sh refuse a plain-HTTP directory, so the core is put
# behind a TLS proxy with a CA made for the run, and all three are handed that
# CA to trust.
#
#   ./scripts/live-acme.sh
#
# Needs Docker, openssl and python3. Exit status is the verdict.

LIVE_NAME=acme
CORE_PORT=18095
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

CERTBOT_IMAGE="${CERTBOT_IMAGE:-certbot/certbot:v5.8.0}"
LEGO_IMAGE="${LEGO_IMAGE:-goacme/lego:v4.28.1}"
ACMESH_IMAGE="${ACMESH_IMAGE:-neilpang/acme.sh:3.1.1}"
GW_VERSION="${GW_VERSION:-$(awk '/^GW_VERSION/ {print $3; exit}' Makefile)}"
GW_PORT=19095
TLS_PORT=18496

# On Linux the clients share the host's network and reach the proxy on
# localhost. Docker Desktop has no such network, and reaches the host by name.
if [[ "$(uname -s)" == Linux ]]; then
  HOST=localhost
  DOCKER_NET=(--network host)
else
  HOST=host.docker.internal
  # Never empty: macOS's bash 3.2 calls an empty array unbound under set -u.
  DOCKER_NET=(--add-host host.docker.internal:host-gateway)
fi
ORIGIN="https://$HOST:$TLS_PORT"
DIRECTORY="$ORIGIN/acme/live-web/directory"

# ── The self-signed gateway, then the core ────────────────────────────────────

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
live_start_core "acme:
  enabled: true
  external_url: $ORIGIN"
tries=600
until grep -q "gateway registered successfully" "$WORK/core.log"; do
  (( tries-- )) || die "the core never registered the gateway; see $WORK/core.log"
  sleep 0.1
done
live_sign_in

# ── TLS in front of it ────────────────────────────────────────────────────────

mkdir -p "$WORK/tls" "$WORK/tlsproxy"
(
  cd "$WORK/tls"
  # The extensions are not decoration: certbot's Python verifies strictly and
  # refuses a CA without key usage, or a leaf without an authority key id.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem \
    -days 1 -subj "/CN=CertPilot live-acme CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout proxy.key -out proxy.csr \
    -subj "/CN=$HOST" 2>/dev/null
  printf '%s\n' 'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1' \
    'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'authorityKeyIdentifier=keyid' 'subjectKeyIdentifier=hash' >ext
  openssl x509 -req -in proxy.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out proxy.pem -days 1 \
    -extfile ext 2>/dev/null
  chmod 644 ca.pem
) || die "could not make the run's TLS certificates"

cat >"$WORK/tlsproxy/main.go" <<'GO'
package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func main() {
	target, _ := url.Parse(os.Args[1])
	panic(http.ListenAndServeTLS(os.Args[2], os.Args[3], os.Args[4], httputil.NewSingleHostReverseProxy(target)))
}
GO
printf 'module tlsproxy\n\ngo 1.26\n' >"$WORK/tlsproxy/go.mod"
(cd "$WORK/tlsproxy" && GOWORK=off go build -o "$WORK/bin/tlsproxy" .) || die "could not build the TLS proxy"
"$WORK/bin/tlsproxy" "$API" ":$TLS_PORT" "$WORK/tls/proxy.pem" "$WORK/tls/proxy.key" >"$WORK/tlsproxy.log" 2>&1 &
live_on_exit "kill $!"
curl -s --retry 30 --retry-delay 0 --retry-all-errors -o /dev/null --cacert "$WORK/tls/ca.pem" \
  --resolve "$HOST:$TLS_PORT:127.0.0.1" "$DIRECTORY" || die "the TLS proxy never answered"

# ── A template and a credential per client ────────────────────────────────────

ca_id="$(api -X POST "$API/api/v1/ca-accounts" -H 'Content-Type: application/json' \
  -d "{\"name\":\"selfsigned\",\"provider_type\":\"selfsigned\",\"gateway_addr\":\"127.0.0.1:$GW_PORT\"}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("data") or d)["id"])')" \
  || die "could not create the CA account"
api -X POST "$API/api/v1/certificate-templates" -H 'Content-Type: application/json' -d "{
  \"slug\":\"live-web\",\"name\":\"Live web\",\"ca_account_id\":\"$ca_id\",\"subject_mode\":\"SUPPLIED\",
  \"allowed_key_types\":[\"RSA\",\"ECDSA\"],\"key_custody_required\":\"ANY\",\"renew_before_days\":30,
  \"is_enabled\":true,\"san_rules\":{\"suffixes\":[\".example.com\"]}}" >/dev/null \
  || die "could not create the template"

# credential name — prints "KID HMAC".
credential() {
  api -X POST "$API/api/v1/acme/credentials" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\",\"template\":\"live-web\"}" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"]["kid"], d["hmac_key"])'
}

# record name — the inventory row for a certificate with this common name or
# SAN, as JSON with the fields this checks.
record() {
  api "$API/api/v1/certificates?limit=500" | python3 -c '
import json, sys
name = sys.argv[1]
rows = [c for c in json.load(sys.stdin)["data"] if c.get("discovered_via") == "ACME"
        and (c.get("common_name") == name or name in (c.get("sans") or []))]
print(json.dumps({"count": len(rows), "rows": [{k: c.get(k) for k in
      ("status", "renewal_count", "key_custody", "auto_renew")} for c in rows]}))' "$1"
}

# expect check json — one of a fixed set of checks on what record printed.
expect() {
  python3 - "$1" "$2" <<'PY'
import json, sys
check, r = sys.argv[1], json.loads(sys.argv[2])
row = r["rows"][0] if r["rows"] else {}
ok = {
    "one held by the client": r["count"] == 1 and row.get("key_custody") == "EXTERNAL" and not row.get("auto_renew"),
    "renewed in place": r["count"] == 1 and row.get("renewal_count") == 1,
    "revoked": row.get("status") == "REVOKED",
}[check]
sys.exit(0 if ok else 1)
PY
}

mkdir -p "$WORK/www"

# ── certbot ──────────────────────────────────────────────────────────────────

mkdir -p "$WORK/certbot"
certbot() {
  docker run --rm "${DOCKER_NET[@]}" -e REQUESTS_CA_BUNDLE=/ca/ca.pem \
    -v "$WORK/tls:/ca:ro" -v "$WORK/certbot:/etc/letsencrypt" -v "$WORK/www:/www" \
    "$CERTBOT_IMAGE" --server "$DIRECTORY" --non-interactive "$@" 2>&1
}

out="$(mkdir -p "$WORK/certbot-anon" && docker run --rm "${DOCKER_NET[@]}" -e REQUESTS_CA_BUNDLE=/ca/ca.pem \
  -v "$WORK/tls:/ca:ro" -v "$WORK/certbot-anon:/etc/letsencrypt" "$CERTBOT_IMAGE" \
  register --server "$DIRECTORY" --non-interactive --agree-tos -m ops@example.com 2>&1)" \
  && die "certbot registered with no credential: $out"
grep -qi "external account" <<<"$out" || die "certbot was refused without a credential, but not told why: $out"
pass "certbot: no credential, refused, and told a binding is required"

read -r kid hmac < <(credential certbot)
out="$(certbot register --agree-tos -m ops@example.com --eab-kid "$kid" --eab-hmac-key "$hmac")" \
  || die "certbot could not register: $out"
out="$(certbot certonly --webroot -w /www -d web.example.com -d api.example.com --key-type ecdsa)" \
  || die "certbot was not issued a certificate: $out"
r="$(record web.example.com)"
expect "one held by the client" "$r" \
  || die "certbot's certificate is not recorded as held by the client: $r"
pass "certbot: registered with a credential and issued two names, recorded as the client's key"

out="$(certbot certonly --webroot -w /www -d payroll.other.test --key-type ecdsa)" \
  && die "certbot was issued a name the template does not allow: $out"
grep -q "other.test" <<<"$out" || die "a name outside the template was refused without saying which: $out"
pass "certbot: a name outside the template is refused, naming it"

out="$(certbot renew --force-renewal --no-random-sleep-on-renew)" || die "certbot could not renew: $out"
r="$(record web.example.com)"
expect "renewed in place" "$r" \
  || die "certbot's renewal did not renew the record in place: $r"
grep -q "/renewal-info/" "$WORK/core.log" || die "certbot never asked renewalInfo"
pass "certbot: renewed in place, after asking renewalInfo"

out="$(certbot revoke --cert-name web.example.com --reason keycompromise --no-delete-after-revoke)" \
  || die "certbot could not revoke: $out"
r="$(record web.example.com)"
expect "revoked" "$r" || die "certbot's revocation was not recorded: $r"
pass "certbot: revoked, at the CA and in the inventory"

# ── lego ─────────────────────────────────────────────────────────────────────

mkdir -p "$WORK/lego"
read -r kid hmac < <(credential lego)
lego() {
  docker run --rm "${DOCKER_NET[@]}" -e LEGO_CA_CERTIFICATES=/ca/ca.pem \
    -v "$WORK/tls:/ca:ro" -v "$WORK/lego:/data" -v "$WORK/www:/www" "$LEGO_IMAGE" \
    --server "$DIRECTORY" --accept-tos --email ops@example.com --eab --kid "$kid" --hmac "$hmac" \
    --path /data --domains lego.example.com --http --http.webroot /www "$@" 2>&1
}
out="$(lego run)" || die "lego was not issued a certificate: $out"
out="$(lego renew --days 100 --no-random-sleep)" || die "lego could not renew: $out"
r="$(record lego.example.com)"
expect "renewed in place" "$r" \
  || die "lego's renewal did not renew the record in place: $r"
pass "lego: issued, and renewed in place"

# ── acme.sh ──────────────────────────────────────────────────────────────────

mkdir -p "$WORK/acmesh"
read -r kid hmac < <(credential acme.sh)
acmesh() {
  docker run --rm "${DOCKER_NET[@]}" -v "$WORK/tls:/ca:ro" -v "$WORK/acmesh:/acme.sh" -v "$WORK/www:/www" \
    "$ACMESH_IMAGE" acme.sh --server "$DIRECTORY" --ca-bundle /ca/ca.pem "$@" 2>&1
}
out="$(acmesh --register-account -m ops@example.com --eab-kid "$kid" --eab-hmac-key "$hmac")" \
  || die "acme.sh could not register: $out"
out="$(acmesh --issue -d sh.example.com -w /www --keylength ec-256)" || die "acme.sh was not issued a certificate: $out"
out="$(acmesh --renew -d sh.example.com --ecc --force)" || die "acme.sh could not renew: $out"
r="$(record sh.example.com)"
expect "renewed in place" "$r" \
  || die "acme.sh's renewal did not renew the record in place: $r"
pass "acme.sh: registered, issued, and renewed in place"

say "acme: every check passed — $CERTBOT_IMAGE, $LEGO_IMAGE and $ACMESH_IMAGE against the core's ACME server"

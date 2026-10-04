#!/usr/bin/env bash
# Does the Kubernetes inventory work against a real cluster?
#
# core/engine/cloudsync is tested against an httptest server that answers the
# paths the provider asks for with JSON its author wrote. That proves the code
# agrees with its author's reading of the Kubernetes API. This asks a real
# API server, in a kind cluster, with the things a real cluster has and the fake
# does not:
#
#   - a service account token scoped the way the documentation says to scope it
#     — get and list on secrets and ingresses, nothing else — and TLS verified
#     against the cluster's own CA
#   - the API server's own field selector for kubernetes.io/tls, with an Opaque
#     secret beside the TLS ones that must not be reported
#   - more TLS secrets than one page holds, so the continue token is followed
#   - a certificate issued by cert-manager itself, carrying whatever annotation
#     cert-manager actually writes, which must read as renewed by cert-manager
#   - an Ingress referencing a secret, which must read as attached
#   - a token with no rights, which must fail loudly rather than report an
#     empty cluster; and one that can read secrets but not ingresses, which
#     must say it does not know what is attached rather than guess "nothing"
#   - a secret deleted between two syncs, which must be marked removed
#
#   ./scripts/live-kubernetes.sh
#   KEEP_CLUSTER=1 ./scripts/live-kubernetes.sh      leave the cluster up after
#
# Needs Docker and Go; kind is fetched if it is not on the PATH. The cluster is
# created and deleted by this script, under a name nothing else uses.
# cert-manager's release manifest is downloaded from GitHub. Exit status is the
# verdict.

LIVE_NAME=kubernetes
CORE_PORT=18086
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

CLUSTER=certpilot-live
KIND_VERSION="${KIND_VERSION:-v0.33.0}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.2}"
# One more than the provider's page size (500), so the continue token has to
# be followed for the inventory to be complete.
BULK_SECRETS="${BULK_SECRETS:-501}"

# ── A cluster ─────────────────────────────────────────────────────────────────

KIND="$(command -v kind || true)"
if [[ -z "$KIND" ]]; then
  say "fetching kind $KIND_VERSION"
  GOWORK=off GOBIN="$WORK/bin" go install "sigs.k8s.io/kind@$KIND_VERSION" || die "could not fetch kind"
  KIND="$WORK/bin/kind"
fi

"$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
say "creating kind cluster $CLUSTER"
"$KIND" create cluster --name "$CLUSTER" --wait 120s >"$WORK/kind.log" 2>&1 \
  || die "kind could not create a cluster; see $WORK/kind.log"
[[ -n "${KEEP_CLUSTER:-}" ]] || live_on_exit "$KIND delete cluster --name $CLUSTER"

NODE="$CLUSTER-control-plane"
# kubectl as the cluster administrator, from inside the node, so the host needs
# no kubectl. Only the setup uses this; the core gets a narrow token.
kc() { docker exec -i "$NODE" kubectl --kubeconfig=/etc/kubernetes/admin.conf "$@"; }

"$KIND" get kubeconfig --name "$CLUSTER" >"$WORK/kubeconfig"
read -r API_SERVER CA_PEM_FILE < <(python3 - "$WORK/kubeconfig" "$WORK" <<'PY'
import base64, re, sys
text, work = open(sys.argv[1]).read(), sys.argv[2]
server = re.search(r"server:\s*(\S+)", text).group(1)
ca = base64.b64decode(re.search(r"certificate-authority-data:\s*(\S+)", text).group(1))
open(work + "/cluster-ca.pem", "wb").write(ca)
print(server, work + "/cluster-ca.pem")
PY
)
pass "cluster up; API server at $API_SERVER"

# ── cert-manager, issuing one certificate the way it really does ──────────────

say "installing cert-manager $CERT_MANAGER_VERSION"
curl -fsSL "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" \
  -o "$WORK/cert-manager.yaml" || die "could not download cert-manager $CERT_MANAGER_VERSION"
kc apply -f - <"$WORK/cert-manager.yaml" >/dev/null || die "could not install cert-manager"
kc -n cert-manager wait deployment --all --for=condition=Available --timeout=300s >/dev/null \
  || die "cert-manager never became available"

kc create namespace shop >/dev/null
kc create namespace internal >/dev/null
kc create namespace bulk >/dev/null

# The webhook can take a moment after its deployment is Available to accept a
# request, so the first apply is retried.
tries=30
until kc apply -f - >/dev/null 2>&1 <<'YAML'
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: self, namespace: internal}
spec: {selfSigned: {}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: billing, namespace: internal}
spec:
  secretName: billing-tls
  commonName: billing.internal.live.test
  dnsNames: [billing.internal.live.test]
  issuerRef: {name: self, kind: Issuer}
YAML
do
  (( tries-- )) || die "cert-manager's webhook never accepted an Issuer"
  sleep 2
done
kc -n internal wait certificate/billing --for=condition=Ready --timeout=120s >/dev/null \
  || die "cert-manager never issued the billing certificate"
pass "cert-manager $CERT_MANAGER_VERSION issued internal/billing-tls"

# ── Secrets made by hand, the way most clusters have them ─────────────────────
#
# Generated with Go rather than openssl so a certificate can be made that has
# already expired: the openssl on CI's Ubuntu cannot backdate one.

mkdir -p "$WORK/mkcert"
cat >"$WORK/mkcert/main.go" <<'GO'
// Writes <name>.crt and <name>.key for each "name cn from-days to-days" line on
// stdin, validity relative to now. Self-signed; what is under test is how the
// inventory reads a certificate, not who signed it.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	dir := os.Args[1]
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var name, cn string
		var from, to int
		if _, err := fmt.Sscan(in.Text(), &name, &cn, &from, &to); err != nil {
			panic(err)
		}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     []string{cn},
			NotBefore:    now.AddDate(0, 0, from),
			NotAfter:     now.AddDate(0, 0, to),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		_ = os.WriteFile(dir+"/"+name+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		_ = os.WriteFile(dir+"/"+name+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	}
}
GO
printf 'web shop.live.test -30 60\norphan old-shop.live.test -30 200\nexpired legacy.live.test -120 -10\nbulk bulk.live.test -1 365\n' \
  | (cd "$WORK/mkcert" && GOWORK=off go run main.go "$WORK") || die "could not generate the test certificates"

python3 - "$WORK" "$BULK_SECRETS" >"$WORK/secrets.json" <<'PY'
import base64, json, sys
work, bulk = sys.argv[1], int(sys.argv[2])
b64 = lambda name, ext: base64.b64encode(open(f"{work}/{name}.{ext}", "rb").read()).decode()

def tls(ns, name, cert):
    return {"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
            "metadata": {"namespace": ns, "name": name},
            "data": {"tls.crt": b64(cert, "crt"), "tls.key": b64(cert, "key")}}

items = [
    tls("shop", "web-tls", "web"),
    tls("shop", "orphan-tls", "orphan"),
    tls("shop", "expired-tls", "expired"),
    # Not a TLS secret. The API server's field selector should keep it out,
    # and if the selector were ignored it would arrive with no tls.crt.
    {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
     "metadata": {"namespace": "shop", "name": "database-password"},
     "data": {"password": base64.b64encode(b"not-a-certificate").decode()}},
    {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
     "metadata": {"namespace": "shop", "name": "web"},
     "spec": {"tls": [{"hosts": ["shop.live.test"], "secretName": "web-tls"}],
              "rules": [{"host": "shop.live.test", "http": {"paths": [{
                  "path": "/", "pathType": "Prefix",
                  "backend": {"service": {"name": "web", "port": {"number": 80}}}}]}}]}},
]
items += [tls("bulk", "bulk-%03d" % i, "bulk") for i in range(bulk)]
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
PY
kc apply -f - <"$WORK/secrets.json" >/dev/null || die "could not create the test secrets"
pass "created 3 TLS secrets by hand, an Opaque secret, an Ingress, and $BULK_SECRETS more to page through"

# ── Tokens: scoped as documented, and two that are not ────────────────────────

kc apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Namespace
metadata: {name: certpilot}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: reader, namespace: certpilot}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: secrets-only, namespace: certpilot}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: nobody, namespace: certpilot}
---
# What the provider's own error message and docs/discovery.md say to grant.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: certpilot-inventory}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: certpilot-inventory}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: certpilot-inventory}
subjects: [{kind: ServiceAccount, name: reader, namespace: certpilot}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: certpilot-secrets-only}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: certpilot-secrets-only}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: certpilot-secrets-only}
subjects: [{kind: ServiceAccount, name: secrets-only, namespace: certpilot}]
YAML
token() { kc -n certpilot create token "$1" --duration=1h; }
READER_TOKEN="$(token reader)"
SECRETS_ONLY_TOKEN="$(token secrets-only)"
NOBODY_TOKEN="$(token nobody)"

# ── The core ──────────────────────────────────────────────────────────────────

live_start_core
live_sign_in

# connect name token — a Kubernetes connection, TLS verified against the
# cluster's CA. Prints its id.
connect() {
  local body response
  body="$(python3 -c '
import json, sys
print(json.dumps({"name": sys.argv[1], "provider": "kubernetes", "config": {
    "api_url": sys.argv[2], "token": sys.argv[3], "ca_cert": open(sys.argv[4]).read()}}))' \
    "$1" "$API_SERVER" "$2" "$CA_PEM_FILE")"
  response="$(api -X POST "$API/api/v1/cloud/connections" -H 'Content-Type: application/json' -d "$body")"
  printf '%s' "$response" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null \
    || die "the core would not save connection $1: $response"
}

# sync id — prints the HTTP status; the body is in $WORK/sync.json.
sync() { api -o "$WORK/sync.json" -w '%{http_code}' -X POST "$API/api/v1/cloud/connections/$1/sync"; }

# inventory id [extra query] — every certificate for the connection, all pages.
inventory() {
  python3 - "$API" "$WORK/cookies" "$1" "${2:-}" <<'PY'
import json, sys, urllib.request
api, cookies, conn, extra = sys.argv[1:5]
# curl's jar, read by hand: it writes the HttpOnly session cookie behind a
# "#HttpOnly_" prefix that Python's own jar reader skips as a comment.
cookie = "; ".join(
    f"{f[5]}={f[6]}" for f in (l.rstrip("\n").split("\t") for l in open(cookies))
    if len(f) == 7 and (not f[0].startswith("#") or f[0].startswith("#HttpOnly_")))
rows, offset = [], 0
while True:
    req = urllib.request.Request(
        f"{api}/api/v1/cloud/certificates?connection_id={conn}&limit=200&offset={offset}{extra}",
        headers={"Cookie": cookie})
    page = json.load(urllib.request.urlopen(req))
    rows += page["data"]
    offset += 200
    if offset >= page["total"]:
        break
print(json.dumps(rows))
PY
}

# ── A token with no rights ────────────────────────────────────────────────────

id="$(connect "no rights" "$NOBODY_TOKEN")"
status="$(sync "$id")"
[[ "$status" == 502 ]] || die "a token with no rights synced with $status: $(cat "$WORK/sync.json")"
python3 - "$WORK/sync.json" <<'PY' || exit 1
import json, sys
b = json.load(open(sys.argv[1]))
if "forbidden" not in b.get("error", "").lower():
    sys.exit("the refusal does not carry the API server's reason: %r" % b.get("error"))
if "not the same as finding no certificates" not in b.get("message", ""):
    sys.exit("the refusal does not say it learned nothing: %r" % b.get("message"))
PY
pass "a token with no rights fails the sync with the API server's reason, not an empty inventory"

# ── The documented scope ──────────────────────────────────────────────────────

reader="$(connect "documented scope" "$READER_TOKEN")"
status="$(sync "$reader")"
[[ "$status" == 200 ]] || die "the documented scope could not sync: $status $(cat "$WORK/sync.json")"
inventory "$reader" >"$WORK/reader.json"

python3 - "$WORK/reader.json" "$BULK_SECRETS" <<'PY' || exit 1
import json, sys
rows, bulk = json.load(open(sys.argv[1])), int(sys.argv[2])
by = {r["resource_id"]: r for r in rows}
codes = lambda r: sorted(f["code"] for f in r.get("findings") or [])
problems = []

want = 4 + bulk
if len(rows) != want:
    problems.append("%d certificates reported, expected %d (3 by hand, 1 from cert-manager, %d bulk)"
                    % (len(rows), want, bulk))
if "shop/database-password" in by:
    problems.append("the Opaque secret was reported as a certificate")
bulk_seen = sum(1 for k in by if k.startswith("bulk/"))
if bulk_seen != bulk:
    problems.append("%d of the %d bulk secrets were reported; the continue token was not followed"
                    % (bulk_seen, bulk))

web = by.get("shop/web-tls")
if not web:
    problems.append("shop/web-tls is missing")
else:
    if web.get("attached") is not True or web.get("attached_to") != ["ingress shop/web"]:
        problems.append("shop/web-tls: attached=%r to %r, expected the ingress" % (web.get("attached"), web.get("attached_to")))
    if web.get("will_renew") is not False or "will_not_renew" not in codes(web):
        problems.append("shop/web-tls: will_renew=%r findings=%s" % (web.get("will_renew"), codes(web)))
    if web.get("common_name") != "shop.live.test":
        problems.append("shop/web-tls: common name %r" % web.get("common_name"))

orphan = by.get("shop/orphan-tls")
if not orphan or orphan.get("attached") is not False or "unattached" not in codes(orphan):
    problems.append("shop/orphan-tls should read unattached: %s" % (orphan and (orphan.get("attached"), codes(orphan))))

expired = by.get("shop/expired-tls")
if not expired or not {"expired", "will_not_renew"} <= set(codes(expired)):
    problems.append("shop/expired-tls should read expired and not renewed: %s" % (expired and codes(expired)))

billing = by.get("internal/billing-tls")
if not billing:
    problems.append("cert-manager's internal/billing-tls is missing")
else:
    if billing.get("renewal_mode") != "cert-manager: billing" or billing.get("will_renew") is not True:
        problems.append("internal/billing-tls: renewal_mode=%r will_renew=%r, expected cert-manager: billing"
                        % (billing.get("renewal_mode"), billing.get("will_renew")))
    if "will_not_renew" in codes(billing):
        problems.append("internal/billing-tls is reported as not renewed although cert-manager renews it")

if problems:
    sys.exit("documented scope:\n  " + "\n  ".join(problems))
PY
pass "every TLS secret and only those, across two pages of the API"
pass "the Ingress's secret reads attached, the unreferenced one unattached"
pass "hand-made secrets read as not renewed, and the expired one as expired too"
pass "cert-manager's own certificate reads as renewed by cert-manager"

# ── Secrets, but not ingresses ────────────────────────────────────────────────

narrow="$(connect "secrets only" "$SECRETS_ONLY_TOKEN")"
status="$(sync "$narrow")"
[[ "$status" == 200 ]] || die "a secrets-only token could not sync: $status $(cat "$WORK/sync.json")"
inventory "$narrow" >"$WORK/narrow.json"
python3 - "$WORK/narrow.json" <<'PY' || exit 1
import json, sys
rows = json.load(open(sys.argv[1]))
guessed = [r["resource_id"] for r in rows if r.get("attached") is not None
           or any(f["code"] == "unattached" for f in r.get("findings") or [])]
if guessed:
    sys.exit("with no right to read ingresses, %d secrets still claim to know whether they are attached, e.g. %s"
             % (len(guessed), guessed[:3]))
PY
pass "without the right to read ingresses, nothing claims to know whether it is attached"

# ── A secret deleted between syncs ────────────────────────────────────────────

kc -n shop delete secret orphan-tls >/dev/null
status="$(sync "$reader")"
[[ "$status" == 200 ]] || die "the second sync failed: $status"
inventory "$reader" >"$WORK/after.json"
inventory "$reader" '&include_removed=true' >"$WORK/after-all.json"
python3 - "$WORK/after.json" "$WORK/after-all.json" <<'PY' || exit 1
import json, sys
current = {r["resource_id"] for r in json.load(open(sys.argv[1]))}
everything = {r["resource_id"]: r for r in json.load(open(sys.argv[2]))}
if "shop/orphan-tls" in current:
    sys.exit("a deleted secret is still listed as present")
if not everything.get("shop/orphan-tls", {}).get("removed_at"):
    sys.exit("a deleted secret is not marked removed")
PY
pass "a secret deleted from the cluster is marked removed on the next sync"

say ""
say "kubernetes: every check passed against kind ($("$KIND" version | awk '{print $2}')) and cert-manager $CERT_MANAGER_VERSION"

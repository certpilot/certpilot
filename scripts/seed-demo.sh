#!/usr/bin/env bash
# Fill a running CertPilot with a realistic estate to look at.
#
# A CA hierarchy spanning ten years down to three weeks, certificates from two
# days to thirteen months, metadata fields of every type, and values on every
# certificate — enough that the horizon has something to plot, the urgency sort
# has something to sort, and the metadata filters have something to filter.
#
#   ./scripts/dev.sh          # in one terminal
#   ./scripts/seed-demo.sh    # in another
#
# Idempotent by name: rerunning skips what is already there. Nothing here
# deletes anything.

set -euo pipefail

api="${CERTPILOT_API:-http://127.0.0.1:8080}"
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$project_dir/.certpilot/demo"
mkdir -p "$work"

if ! curl -sf -m 3 "$api/healthz" >/dev/null; then
  echo "CertPilot is not answering at $api — start it with ./scripts/dev.sh" >&2
  exit 1
fi

# Signed in, because there is no anonymous mode even locally. Without this every
# call below got a 401, and the first one parsed that error body as a list and
# died on `KeyError: 'data'` — which named nothing an operator could act on.
# shellcheck source=scripts/dev-session.sh
source "$project_dir/scripts/dev-session.sh"
jar="$(dev_session "$api" "$project_dir/.certpilot")" || exit 1
# The python blocks below use urllib, which cannot read curl's jar.
CERTPILOT_COOKIE="$(dev_session_cookie "$jar")"
export CERTPILOT_COOKIE

post() { curl -sS -m 30 -b "$jar" -X POST "$api$1" -H 'Content-Type: application/json' -d "$2"; }

accounts_body="$(curl -sS -m 10 -b "$jar" "$api/api/v1/ca-accounts")"
account=$(printf '%s' "$accounts_body" | python3 -c '
import sys, json

try:
    body = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit("the CA account list was not JSON; is $api really CertPilot?")

# An error body is an object with "error", not a list under "data". Reading it
# as the success shape is how a 401 surfaced as KeyError: "data".
if isinstance(body, dict) and body.get("error"):
    sys.exit("CertPilot refused the CA account list: " + str(body["error"]))

data = body.get("data") if isinstance(body, dict) else None
if data is None:
    sys.exit("the CA account list had no \"data\"; got: " + str(body)[:200])

print(data[0]["id"] if data else "")')
if [[ -z "$account" ]]; then
  echo "No CA account is registered. Start the stack with ./scripts/dev.sh first." >&2
  exit 1
fi

# ── Metadata fields ──────────────────────────────────────────────────────────
# One of each type, because the point is that an organisation defines its own.
printf 'Metadata fields...\n'
while IFS='|' read -r label body; do
  [[ -z "$label" ]] && continue
  # A conflict is this script being run twice, not a failure. Printing the raw
  # error makes a successful rerun look broken.
  printf '  %-14s %s\n' "$label" "$(post /api/v1/metadata-fields "$body" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if d.get("key"):
    print(d["key"])
elif "already uses the key" in d.get("error", ""):
    print("already defined")
else:
    print(d.get("error", "")[:70])')"
done <<'FIELDS'
Cost centre|{"label":"Cost centre","field_type":"TEXT","help_text":"Finance code this certificate is billed to","sort_order":1}
PCI in scope|{"label":"PCI in scope","field_type":"BOOLEAN","display":"RADIO","is_required":true,"sort_order":2}
Service tier|{"label":"Service tier","field_type":"SELECT","display":"RADIO","help_text":"Drives the renewal lead time we hold ourselves to","sort_order":3,"options":[{"label":"Tier 1"},{"label":"Tier 2"},{"label":"Tier 3"}]}
Regions|{"label":"Regions","field_type":"MULTI_SELECT","sort_order":4,"options":[{"label":"EMEA"},{"label":"AMER"},{"label":"APAC"}]}
Change ticket|{"label":"Change ticket","field_type":"TEXT","help_text":"The CR that authorised this certificate","sort_order":5}
FIELDS

# ── CA hierarchy ─────────────────────────────────────────────────────────────
# Real certificates from openssl rather than fixtures, so the parsing, the
# chain resolution and the expiry maths are all exercised on genuine DER.
printf 'Certificate authorities...\n'
mkca() {
  local file="$1" days="$2" cn="$3"
  [[ -f "$work/$file.pem" ]] && return 0
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$work/$file.key" -out "$work/$file.pem" -days "$days" \
    -subj "/C=US/O=Example Corp/CN=$cn" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "crlDistributionPoints=URI:http://crl.example.com/$file.crl" 2>/dev/null
}
mkca root       3650 "Example Corp Global Root CA G2"
mkca policy     1825 "Example Corp Policy CA 2026"
mkca web         400 "Example Corp Web Issuing CA 03"
mkca dev         210 "Example Corp Development Issuing CA"
mkca legacy       26 "Example Corp Legacy Issuing CA 01"
mkca iot          95 "Example Corp IoT Device CA"

ca() {
  python3 - "$api" "$1" "$work/$2.pem" "${3:-}" <<'PY'
import json, os, sys, urllib.request, urllib.error
api, name, pem, parent = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
H = {"Content-Type": "application/json", "Cookie": os.environ["CERTPILOT_COOKIE"]}

def get(url):
    return json.load(urllib.request.urlopen(
        urllib.request.Request(url, headers=H), timeout=30))

body = {"name": name, "certificate_pem": open(pem).read()}
if parent:
    body["parent_ca_id"] = parent
req = urllib.request.Request(f"{api}/api/v1/pki/authorities", method="POST",
    data=json.dumps(body).encode(), headers=H)
try:
    print(json.load(urllib.request.urlopen(req, timeout=30))["id"])
except urllib.error.HTTPError as e:
    # 409 is already present; find it by name so children still attach. A 401
    # is not that, and swallowing it here is how a whole unseeded estate used
    # to look like a successful run.
    if e.code in (401, 403):
        sys.exit(f"CertPilot refused the request ({e.code}); the session is not valid")
    listing = get(f"{api}/api/v1/pki/authorities")
    print(next((a["id"] for a in listing["data"] if a["name"] == name), ""))
PY
}
root=$(ca "Example Corp Global Root CA G2" root)
policy=$(ca "Example Corp Policy CA 2026" policy "$root")
ca "Example Corp Web Issuing CA 03"        web    "$policy" >/dev/null
ca "Example Corp Development Issuing CA"   dev    "$policy" >/dev/null
ca "Example Corp Legacy Issuing CA 01"     legacy "$policy" >/dev/null
ca "Example Corp IoT Device CA"            iot    "$policy" >/dev/null
printf '  6 authorities, 25 to 3,650 days\n'

# Somebody to call, and one problem already being worked.
python3 - "$api" <<'PY'
import json, os, urllib.request, sys
api = sys.argv[1]
H = {"Content-Type": "application/json", "Cookie": os.environ["CERTPILOT_COOKIE"]}
cas = json.load(urllib.request.urlopen(
    urllib.request.Request(f"{api}/api/v1/pki/authorities", headers=H), timeout=30))["data"]
def call(path, body, method):
    req = urllib.request.Request(f"{api}{path}", method=method,
        data=json.dumps(body).encode(), headers=H)
    try: urllib.request.urlopen(req, timeout=30)
    except Exception: pass
for ca in cas:
    if "Legacy" in ca["name"]:
        call(f"/api/v1/pki/authorities/{ca['id']}/owner",
             {"owner_team": "Platform Engineering", "owner_email": "pki@example.com"}, "PUT")
    if "IoT" in ca["name"]:
        call(f"/api/v1/pki/authorities/{ca['id']}/owner",
             {"owner_team": "Device Fleet", "owner_email": "iot@example.com"}, "PUT")
        call(f"/api/v1/pki/authorities/{ca['id']}/acknowledge",
             {"note": "Replacement CA cut on Thursday, migration tracked in PKI-2291",
              "silence_days": 7}, "POST")
PY

# ── Certificates ─────────────────────────────────────────────────────────────
printf 'Certificates...\n'
python3 - "$api" "$account" <<'PY'
import json, os, sys, urllib.request, urllib.error
api, account = sys.argv[1], sys.argv[2]
H = {"Content-Type": "application/json", "Cookie": os.environ["CERTPILOT_COOKIE"]}

existing = {c["common_name"] for c in
            json.load(urllib.request.urlopen(
                urllib.request.Request(f"{api}/api/v1/certificates", headers=H),
                timeout=30))["data"]}

# cn, days, environment, team, metadata
estate = [
  ("canary.example.com",       3,   "development", "Platform Engineering",
   {"pci_in_scope": False, "service_tier": "tier_3", "cost_centre": "CC-1100", "regions": ["emea"]}),
  ("metrics.example.com",      7,   "staging",     "Observability",
   {"pci_in_scope": False, "service_tier": "tier_3", "cost_centre": "CC-1100", "regions": ["emea", "amer"]}),
  ("build-agent.example.com",  12,  "development", "Developer Experience",
   {"pci_in_scope": False, "service_tier": "tier_3", "cost_centre": "CC-2050"}),
  ("grafana.corp.example.com", 14,  "staging",     "Observability",
   {"pci_in_scope": False, "service_tier": "tier_2", "cost_centre": "CC-1100", "regions": ["emea"]}),
  ("legacy-soap.example.com",  20,  "production",  "Integrations",
   {"pci_in_scope": True,  "service_tier": "tier_1", "cost_centre": "CC-4471",
    "regions": ["emea"], "change_ticket": "CR-88214"}),
  ("ldap.corp.example.com",    30,  "production",  "Identity",
   {"pci_in_scope": False, "service_tier": "tier_1", "cost_centre": "CC-3300", "regions": ["emea", "amer", "apac"]}),
  ("internal-mq.example.com",  45,  "staging",     "Integrations",
   {"pci_in_scope": False, "service_tier": "tier_2", "cost_centre": "CC-2050"}),
  ("cdn-edge.example.com",     60,  "production",  "Platform Engineering",
   {"pci_in_scope": False, "service_tier": "tier_2", "cost_centre": "CC-1100", "regions": ["amer", "apac"]}),
  ("checkout.example.com",     90,  "production",  "Payments",
   {"pci_in_scope": True,  "service_tier": "tier_1", "cost_centre": "CC-4471",
    "regions": ["emea", "amer"], "change_ticket": "CR-90551"}),
  ("auth.example.com",         120, "production",  "Identity",
   {"pci_in_scope": True,  "service_tier": "tier_1", "cost_centre": "CC-3300", "regions": ["emea", "amer", "apac"]}),
  ("vpn.corp.example.com",     180, "production",  "Network",
   {"pci_in_scope": False, "service_tier": "tier_2", "cost_centre": "CC-5000", "regions": ["emea"]}),
  ("shop.example.com",         270, "production",  "Storefront",
   {"pci_in_scope": True,  "service_tier": "tier_1", "cost_centre": "CC-4471", "regions": ["amer"]}),
  ("api.prod.example.com",     365, "production",  "Platform Engineering",
   {"pci_in_scope": False, "service_tier": "tier_1", "cost_centre": "CC-1100", "regions": ["emea", "amer", "apac"]}),
  ("wildcard.corp.example.com",398, "production",  "Platform Engineering",
   {"pci_in_scope": False, "service_tier": "tier_2", "cost_centre": "CC-1100"}),
]

made = skipped = 0
for cn, days, env, team, meta in estate:
    if cn in existing:
        skipped += 1
        continue
    body = {"common_name": cn, "sans": [cn], "ca_account_id": account,
            "key_type": "ECDSA", "key_size": 256, "validity_days": days,
            "environment": env, "team": team, "auto_renew": True, "metadata": meta}
    req = urllib.request.Request(f"{api}/api/v1/certificates", method="POST",
        data=json.dumps(body).encode(), headers=H)
    try:
        urllib.request.urlopen(req, timeout=45)
        made += 1
    except urllib.error.HTTPError as e:
        print(f"  {cn}: {e.read().decode()[:100]}", file=sys.stderr)
print(f"  {made} issued, {skipped} already present")
PY

# ── One certificate whose key never came here ────────────────────────────────
if [[ ! -f "$work/external.csr" ]]; then
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
    -keyout "$work/external.key" -out "$work/external.csr" \
    -subj "/C=US/O=Example Corp/CN=hsm-backed.example.com" \
    -addext "subjectAltName=DNS:hsm-backed.example.com" 2>/dev/null
fi
python3 - "$api" "$account" "$work/external.csr" <<'PY'
import json, os, sys, urllib.request, urllib.error
api, account, csr = sys.argv[1], sys.argv[2], sys.argv[3]
H = {"Content-Type": "application/json", "Cookie": os.environ["CERTPILOT_COOKIE"]}
existing = {c["common_name"] for c in
            json.load(urllib.request.urlopen(
                urllib.request.Request(f"{api}/api/v1/certificates", headers=H),
                timeout=30))["data"]}
if "hsm-backed.example.com" in existing:
    print("  CSR-signed certificate already present")
else:
    body = {"ca_account_id": account, "csr_pem": open(csr).read(), "validity_days": 365,
            "environment": "production", "team": "Payments",
            "metadata": {"pci_in_scope": True, "service_tier": "tier_1",
                         "cost_centre": "CC-4471", "change_ticket": "CR-90552"}}
    req = urllib.request.Request(f"{api}/api/v1/certificates", method="POST",
        data=json.dumps(body).encode(), headers=H)
    try:
        urllib.request.urlopen(req, timeout=45)
        print("  hsm-backed.example.com signed from a CSR — key custody EXTERNAL")
    except urllib.error.HTTPError as e:
        print("  CSR:", e.read().decode()[:120], file=sys.stderr)
PY

printf '\nDone. http://127.0.0.1:3000/\n'

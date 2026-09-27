#!/usr/bin/env bash
# Does Certificate Transparency monitoring work against the real index?
#
# core/engine/ctlog is tested against a fake crt.sh that returns rows its
# author wrote. This asks the real one, about a domain whose certificates are
# public, and checks what the core makes of the answer against two things it
# did not produce: the certificate the domain is actually serving, read here
# over TLS by Python, and crt.sh's own rows.
#
#   1. read the serial of the certificate CT_DOMAIN serves, independently
#   2. scan CT_DOMAIN with the core's discovery and import what it found, so
#      that one certificate is in the inventory
#   3. watch CT_DOMAIN in CT, check it now, and require that
#        - the served certificate is found, once, and reads MANAGED, matched to
#          the certificate that was imported
#        - its precertificate is recorded and marked as one, not counted twice
#        - everything else crt.sh reports reads UNMANAGED
#        - a second check adds nothing
#
# The serial comparison is the point of step 3. Python prints the serial in
# upper case, crt.sh pads it with a leading zero, and the core stores it as
# big.Int.Text(16); they are three spellings of one number, and a mismatch
# silently files your own certificate as one nobody manages.
#
# This talks to crt.sh and to CT_DOMAIN over the internet, so it is not run on
# pull requests: an answer that depends on somebody else's service being up
# belongs on a schedule, where a red run reads as "look at this" rather than
# "your change broke it".
#
#   ./scripts/live-ct.sh
#   CT_DOMAIN=example.org ./scripts/live-ct.sh
#
# Needs python3 and network access. Exit status is the verdict.

LIVE_NAME=ct
CORE_PORT=18085
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

# badssl.com: run by the Chromium project for exactly this kind of testing, and
# a handful of current certificates rather than thousands.
CT_DOMAIN="${CT_DOMAIN:-badssl.com}"

# ── What the domain is serving, read without the core ─────────────────────────

served="$(python3 - "$CT_DOMAIN" <<'PY'
import json, socket, ssl, sys
host = sys.argv[1]
ctx = ssl.create_default_context()
with socket.create_connection((host, 443), timeout=15) as raw:
    with ctx.wrap_socket(raw, server_hostname=host) as tls:
        cert = tls.getpeercert()
print(json.dumps({"serial": cert["serialNumber"], "not_after": cert["notAfter"]}))
PY
)" || die "could not read the certificate $CT_DOMAIN serves"
served_serial="$(printf '%s' "$served" | field '["serial"]')"
pass "$CT_DOMAIN serves serial $served_serial"

live_start_core
live_sign_in

# ── Into the inventory, through discovery ─────────────────────────────────────

scan="$(api -X POST "$API/api/v1/discovery/scan" -H 'Content-Type: application/json' \
  -d "{\"host\":\"$CT_DOMAIN\",\"port\":443}")"
printf '%s' "$scan" >"$WORK/scan.json"
result_id="$(python3 -c '
import json, sys
rows = [r for r in json.load(open(sys.argv[1])).get("data") or [] if r.get("reachable")]
print(rows[0]["id"] if rows else "")' "$WORK/scan.json")"
[[ -n "$result_id" ]] || die "the discovery scan of $CT_DOMAIN found nothing: $scan"

imported="$(api -X POST "$API/api/v1/discovery/import" -H 'Content-Type: application/json' \
  -d "{\"result_id\":\"$result_id\"}")"
printf '%s' "$imported" >"$WORK/imported.json"
cert_id="$(python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))
for key in ("data", "certificate"):
    if isinstance(b.get(key), dict) and b[key].get("id"):
        b = b[key]
print(b.get("id", ""))' "$WORK/imported.json")"
[[ -n "$cert_id" ]] || die "the discovered certificate could not be imported: $imported"
pass "discovery scanned $CT_DOMAIN and the certificate it serves is in the inventory"

# ── Watched in CT ─────────────────────────────────────────────────────────────

monitor="$(api -X POST "$API/api/v1/ct/monitors" -H 'Content-Type: application/json' \
  -d "{\"domain\":\"$CT_DOMAIN\"}")"
monitor_id="$(printf '%s' "$monitor" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null || true)"
[[ -n "$monitor_id" ]] || die "the core would not watch $CT_DOMAIN: $monitor"

# check — POST .../check, retried, because crt.sh answering 502 or timing out is
# common enough that one failure says more about crt.sh than about the core.
# Each failure must still be reported as a check that did not run.
check() {
  local attempt status
  for attempt in 1 2 3 4; do
    status="$(api -o "$WORK/check.json" -w '%{http_code}' -X POST "$API/api/v1/ct/monitors/$monitor_id/check")"
    [[ "$status" == 200 ]] && return 0
    if [[ "$status" == 502 ]]; then
      grep -q 'not the same as finding no certificates' "$WORK/check.json" \
        || die "a failed CT check was not reported as one: $(cat "$WORK/check.json")"
      skip "crt.sh did not answer (attempt $attempt): $(field '["error"]' <"$WORK/check.json")"
      sleep $(( attempt * 15 ))
      continue
    fi
    die "the CT check answered $status: $(cat "$WORK/check.json")"
  done
  die "crt.sh did not answer in four attempts; nothing was learned about $CT_DOMAIN"
}

check
api "$API/api/v1/ct/certificates?monitor_id=$monitor_id&limit=500" >"$WORK/final.json"
api "$API/api/v1/ct/certificates?monitor_id=$monitor_id&limit=500&include_precertificates=true" >"$WORK/all.json"

counts="$(python3 - "$WORK/final.json" "$WORK/all.json" "$served_serial" "$cert_id" <<'PY'

import json, sys
final = json.load(open(sys.argv[1]))["data"]
everything = json.load(open(sys.argv[2]))["data"]
served, cert_id = sys.argv[3].lower().lstrip("0"), sys.argv[4]

def norm(s):
    return (s or "").lower().replace(":", "").lstrip("0")

if not final:
    sys.exit("CT: the check succeeded and reported no certificates at all for a domain that is serving one")

mine = [c for c in final if norm(c["serial_number"]) == served]
if len(mine) != 1:
    sys.exit("CT: the served certificate appears %d times among final certificates, expected once" % len(mine))
if mine[0]["management_state"] != "MANAGED":
    sys.exit("CT: the served certificate reads %s although it is in the inventory; its serial did not match"
             % mine[0]["management_state"])
if mine[0].get("matched_certificate_id") != cert_id:
    sys.exit("CT: the served certificate is matched to %r, not to the imported certificate"
             % mine[0].get("matched_certificate_id"))

pair = [c for c in everything if norm(c["serial_number"]) == served]
if sorted(c["is_precertificate"] for c in pair) != [False, True]:
    sys.exit("CT: expected the served certificate once as a precertificate and once as the final "
             "certificate, found %s" % [c["is_precertificate"] for c in pair])

others = [c for c in final if norm(c["serial_number"]) != served]
wrong = [c["serial_number"] for c in others if c["management_state"] != "UNMANAGED"]
if wrong:
    sys.exit("CT: certificates that are not in the inventory read as managed: %s" % wrong)

serials = [norm(c["serial_number"]) for c in final]
if len(serials) != len(set(serials)):
    sys.exit("CT: a certificate is counted more than once among final certificates")

print("%d certificates, %d of them unmanaged" % (len(final), len(others)))
PY
)" || exit 1
pass "crt.sh reports $counts for $CT_DOMAIN"
pass "crt.sh's record of the served certificate reads MANAGED, matched to the imported one, across three spellings of its serial"
pass "its precertificate is recorded and marked, and counted once, not twice"

total_before="$(field '["total"]' <"$WORK/final.json")"
check
total_after="$(api "$API/api/v1/ct/certificates?monitor_id=$monitor_id&limit=1" | field '["total"]')"
[[ "$total_after" == "$total_before" ]] \
  || die "a second check changed the count from $total_before to $total_after"
pass "a second check adds nothing ($total_before certificates, unmanaged ones reported as UNMANAGED)"

say ""
say "ct: every check passed against crt.sh for $CT_DOMAIN"

#!/usr/bin/env bash
# Do CertPilot's alerts reach a real mail server and a real webhook receiver?
#
# The unit tests in core/engine/notifications answer that against fakes written
# for them, which proves the code agrees with its author's reading of SMTP and
# of its own signing scheme. This asks two independent parties, through the
# core's own API and the way an operator would — save a channel, press "test",
# look at what arrived — and then lets a CA cross an expiry threshold and
# checks that the alert arrives on its own, with nobody pressing anything.
#
# Email goes to Mailpit, an SMTP server nobody here wrote. Three of them, one
# per encryption mode the channel form offers:
#
#   starttls   STARTTLS required, password required, certificate from a CA the
#              core is told to trust
#   tls        implicit TLS, password required, certificate from a CA the core
#              has never heard of
#   none       plain, no password — a relay on a trusted network
#
# Webhooks go to a receiver that verifies the signature with the snippet
# printed in docs/api-reference.md, character for character. A generic webhook
# has no single real service to test against; what an integrator actually runs
# is the documented recipe, so that is the receiver.
#
# Slack is the one transport not here: it needs a workspace.
#
#   ./scripts/live-notifications.sh
#   MAILPIT_IMAGE=axllent/mailpit:latest ./scripts/live-notifications.sh
#
# Needs Docker, openssl and python3. Exit status is the verdict.

LIVE_NAME=notifications
CORE_PORT=18083
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

# Pinned, so a Mailpit release cannot change the answer between two runs of
# the same commit. Override it to ask the question of a newer one.
MAILPIT_IMAGE="${MAILPIT_IMAGE:-axllent/mailpit:v1.31.3}"

SMTP_USER=certpilot
# Generated per run; it is a password for a mailbox that exists for a minute.
SMTP_PASSWORD="$(openssl rand -hex 12)"

# ── Certificates ──────────────────────────────────────────────────────────────
#
# Two CAs, because a check that only ever presents a trusted certificate cannot
# tell "verification works" from "verification is off".

CERTS="$WORK/certs"
mkdir -p "$CERTS"

make_ca() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$CERTS/$1-ca.key" -out "$CERTS/$1-ca.pem" -days 2 \
    -subj "/CN=CertPilot live-notifications $1 CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
    2>/dev/null || die "openssl could not make the $1 CA"
}
make_leaf() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$CERTS/$1.key" -out "$CERTS/$1.csr" -subj "/CN=127.0.0.1" 2>/dev/null
  printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$CERTS/$1.ext"
  openssl x509 -req -in "$CERTS/$1.csr" -CA "$CERTS/$1-ca.pem" -CAkey "$CERTS/$1-ca.key" \
    -CAcreateserial -days 2 -extfile "$CERTS/$1.ext" -out "$CERTS/$1.pem" 2>/dev/null \
    || die "openssl could not sign the $1 certificate"
  # Read by Mailpit inside its container, whose user is not this one.
  chmod 0644 "$CERTS/$1.key"
}
make_ca trusted;   make_leaf trusted
make_ca untrusted; make_leaf untrusted

# ── Mailpit ───────────────────────────────────────────────────────────────────

# name smtp-port api-port args…
start_mailpit() {
  local name="$1" smtp="$2" http="$3"; shift 3
  live_docker_run "certpilot-live-mailpit-$name" \
    -p "127.0.0.1:$smtp:1025" -p "127.0.0.1:$http:8025" \
    -v "$CERTS:/certs:ro" "$@"
}

say "starting three Mailpit servers ($MAILPIT_IMAGE)"
start_mailpit starttls 12587 18587 -e "MP_SMTP_AUTH=$SMTP_USER:$SMTP_PASSWORD" \
  "$MAILPIT_IMAGE" --smtp-tls-cert /certs/trusted.pem --smtp-tls-key /certs/trusted.key \
  --smtp-require-starttls
start_mailpit tls 12465 18465 -e "MP_SMTP_AUTH=$SMTP_USER:$SMTP_PASSWORD" \
  "$MAILPIT_IMAGE" --smtp-tls-cert /certs/untrusted.pem --smtp-tls-key /certs/untrusted.key \
  --smtp-require-tls
start_mailpit none 12025 18025 "$MAILPIT_IMAGE"

for http in 18587 18465 18025; do
  live_wait_http "http://127.0.0.1:$http/api/v1/messages" "Mailpit on :$http"
done
pass "Mailpit up"

# mailbox api-port query [count] — the newest message matching a Mailpit search,
# as JSON with its headers and text, once at least `count` match. Waits, because
# delivery from the dispatcher is asynchronous and "not yet" is not "never".
#
# Searched by recipient rather than counted, because the in-memory store the
# core runs on is seeded with sample CAs, and a channel with no topic filter
# is entitled to hear about them.
mailbox() {
  python3 - "$1" "$2" "${3:-1}" <<'PY'
import json, sys, time, urllib.parse, urllib.request
port, query, want = sys.argv[1], sys.argv[2], int(sys.argv[3])
base = f"http://127.0.0.1:{port}/api/v1"
get = lambda p: json.load(urllib.request.urlopen(base + p, timeout=5))
deadline = time.time() + 30
while True:
    listing = get("/search?query=" + urllib.parse.quote(query))
    if listing["messages_count"] >= want:
        break
    if time.time() > deadline:
        print(json.dumps({"total": listing["messages_count"]}))
        sys.exit(0)
    time.sleep(0.5)
newest = listing["messages"][0]
full = get(f"/message/{newest['ID']}")
headers = get(f"/message/{newest['ID']}/headers")
print(json.dumps({"total": listing["messages_count"], "subject": newest["Subject"],
                  "to": [a["Address"] for a in newest["To"]],
                  "from": newest["From"]["Address"],
                  "headers": headers, "text": full.get("Text", "")}))
PY
}

# ── The core ──────────────────────────────────────────────────────────────────
#
# SSL_CERT_FILE is how the core is told to trust the first CA. Go reads it on
# Linux and not on macOS, where verification goes through the system keychain
# instead; there the strict half of the STARTTLS check is skipped and says so,
# rather than turning verification off and calling the result a pass.
strict_tls=1
if [[ "$(uname -s)" == Linux ]]; then
  LIVE_CORE_ENV="SSL_CERT_FILE=$CERTS/trusted-ca.pem"
else
  strict_tls=0
fi

live_start_core
live_sign_in

# create_channel name config-json [extra-json-fields] — prints the id. An email
# channel unless the extra fields say otherwise.
create_channel() {
  local body response id extra="${3:-}"
  [[ -n "$extra" ]] || extra='{}'
  body="$(python3 -c '
import json, sys
req = {"name": sys.argv[1], "channel_type": "email", "config": json.loads(sys.argv[2]),
       "severity_threshold": "INFO"}
req.update(json.loads(sys.argv[3]))
print(json.dumps(req))' "$1" "$2" "$extra")"
  response="$(api -X POST "$API/api/v1/notification-channels" -H 'Content-Type: application/json' -d "$body")"
  id="$(printf '%s' "$response" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null || true)"
  [[ -n "$id" ]] || die "the core would not save channel $1: $response"
  printf '%s' "$id"
}

# test_channel id — prints "<http status> <body>".
test_channel() {
  api -o "$WORK/test.json" -w '%{http_code}' -X POST "$API/api/v1/notification-channels/$1/test"
  printf ' '
  cat "$WORK/test.json"
}

expect_delivered() {
  local what="$1" result="$2"
  [[ "$result" == 200* ]] || die "$what: the core did not deliver: $result"
}
expect_refused() {
  local what="$1" result="$2" words="$3"
  [[ "$result" == 502* ]] || die "$what: expected the server to refuse, got: $result"
  grep -qi -- "$words" <<<"$result" || die "$what: refused, but not for the expected reason ($words): $result"
}

# check_test_mail port count what to — the test alert, as the recipient sees it.
check_test_mail() {
  mailbox "$1" "to:$4 subject:\"test alert\"" "$2" >"$WORK/mail.json"
  python3 - "$WORK/mail.json" "$2" "$3" "$4" <<'PY' || exit 1
import json, sys
m = json.load(open(sys.argv[1]))
count, what, to = int(sys.argv[2]), sys.argv[3], sys.argv[4]
if m["total"] < count:
    sys.exit("%s: Mailpit holds %d message(s), expected %d" % (what, m["total"], count))
headers = {k.lower(): v for k, v in m["headers"].items()}
problems = []
if m["subject"] != "[CertPilot WARNING] CertPilot test alert":
    problems.append("subject was %r" % m["subject"])
if m["to"] != [to]:
    problems.append("recipients were %s" % m["to"])
if m["from"] != "certpilot@live.test":
    problems.append("sender was %s" % m["from"])
if headers.get("x-certpilot-severity") != ["WARNING"]:
    problems.append("no X-CertPilot-Severity: WARNING header")
if "delivery is working" not in m["text"]:
    problems.append("the body is not the test alert")
if problems:
    sys.exit(what + ": " + "; ".join(problems))
PY
}

# ── STARTTLS, with a password ─────────────────────────────────────────────────

starttls_cfg="{\"host\":\"127.0.0.1\",\"port\":12587,\"encryption\":\"starttls\",
  \"username\":\"$SMTP_USER\",\"password\":\"$SMTP_PASSWORD\",
  \"from\":\"certpilot@live.test\",\"to\":[\"ops@live.test\"]"
if (( strict_tls )); then
  id="$(create_channel "STARTTLS" "$starttls_cfg}")"
  expect_delivered "STARTTLS, verified" "$(test_channel "$id")"
  check_test_mail 18587 1 "STARTTLS, verified" ops@live.test
  pass "STARTTLS with a password, certificate verified against the CA the core was given"
else
  id="$(create_channel "STARTTLS" "$starttls_cfg,\"insecure_skip_verify\":true}")"
  expect_delivered "STARTTLS" "$(test_channel "$id")"
  check_test_mail 18587 1 "STARTTLS" ops@live.test
  pass "STARTTLS with a password"
  skip "STARTTLS certificate verification: Go ignores SSL_CERT_FILE on macOS; CI runs this half"
fi

bad_cfg="${starttls_cfg/$SMTP_PASSWORD/not-the-password},\"insecure_skip_verify\":true}"
id="$(create_channel "STARTTLS, wrong password" "$bad_cfg")"
expect_refused "wrong password" "$(test_channel "$id")" "authentication failed"
pass "a wrong password is refused, and the answer says so"

# ── Implicit TLS, from a CA nobody trusts ─────────────────────────────────────

tls_cfg="{\"host\":\"127.0.0.1\",\"port\":12465,\"encryption\":\"tls\",
  \"username\":\"$SMTP_USER\",\"password\":\"$SMTP_PASSWORD\",
  \"from\":\"certpilot@live.test\",\"to\":[\"security@live.test\"]"

id="$(create_channel "TLS, unverified CA" "$tls_cfg}")"
expect_refused "untrusted certificate" "$(test_channel "$id")" "certificate"
pass "a server certificate from an unknown CA is refused by default"

id="$(create_channel "TLS, verification off" "$tls_cfg,\"insecure_skip_verify\":true}")"
expect_delivered "implicit TLS" "$(test_channel "$id")"
check_test_mail 18465 1 "implicit TLS" security@live.test
pass "implicit TLS with a password, once verification is explicitly turned off"

# ── Plain, and a STARTTLS request the server cannot honour ────────────────────

plain_cfg='{"host":"127.0.0.1","port":12025,"from":"certpilot@live.test","to":["relay@live.test"]'

id="$(create_channel "STARTTLS to a plain relay" "$plain_cfg,\"encryption\":\"starttls\"}")"
expect_refused "STARTTLS unavailable" "$(test_channel "$id")" "does not offer STARTTLS"
pass "STARTTLS is not silently downgraded when the server does not offer it"

id="$(create_channel "Plain relay" "$plain_cfg,\"encryption\":\"none\"}")"
expect_delivered "plain relay" "$(test_channel "$id")"
check_test_mail 18025 1 "plain relay" relay@live.test
pass "a plain relay with no password"

# ── A signed webhook, verified the way the documentation says to ─────────────

HOOK_PORT=18091
HOOK_SECRET="$(openssl rand -hex 16)"
HOOK_LOG="$WORK/webhook.jsonl"
: >"$HOOK_LOG"

# Records every delivery with the verdict of the documented check. The two
# lines that compute `want` and `ok` are the ones in docs/api-reference.md; if
# that snippet changes, this should change with it.
cat >"$WORK/receiver.py" <<'PY'
import hashlib, hmac, json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

port, secret, log = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3]

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ts = self.headers.get("X-CertPilot-Timestamp", "")
        signature = self.headers.get("X-CertPilot-Signature", "")
        want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(want, signature)
        # The same check with a secret the core was never given must fail, or
        # the check above is not checking anything.
        forged = hmac.new(b"not-the-secret", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        fresh = ts.isdigit() and abs(time.time() - int(ts)) < 300
        with open(log, "a") as f:
            f.write(json.dumps({
                "path": self.path,
                "event": self.headers.get("X-CertPilot-Event"),
                "content_type": self.headers.get("Content-Type"),
                "verified": ok,
                "forgery_rejected": not hmac.compare_digest(forged, signature),
                "fresh": fresh,
                "body": json.loads(body or b"null"),
            }) + "\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", port), Receiver).serve_forever()
PY
python3 "$WORK/receiver.py" "$HOOK_PORT" "$HOOK_SECRET" "$HOOK_LOG" 2>"$WORK/receiver.log" &
live_on_exit "kill $!"

# delivery topic — the newest delivery to the receiver for that topic, waiting.
delivery() {
  python3 - "$HOOK_LOG" "$1" <<'PY'
import json, sys, time
log, topic = sys.argv[1], sys.argv[2]
deadline = time.time() + 30
while time.time() < deadline:
    rows = [json.loads(l) for l in open(log) if l.strip()]
    rows = [r for r in rows if r["event"] == topic]
    if rows:
        print(json.dumps(rows[-1]))
        sys.exit(0)
    time.sleep(0.5)
print("null")
PY
}

hook_cfg="{\"url\":\"http://127.0.0.1:$HOOK_PORT/certpilot\",\"signing_secret\":\"$HOOK_SECRET\",\"allow_insecure_http\":true}"
id="$(create_channel "Webhook" "$hook_cfg" '{"channel_type":"webhook","topics":["ca.expiry_alert"]}')"
expect_delivered "webhook" "$(test_channel "$id")"
delivery notification.test >"$WORK/hook.json"
python3 - "$WORK/hook.json" <<'PY' || exit 1
import json, sys
d = json.load(open(sys.argv[1]))
if d is None:
    sys.exit("webhook: the receiver saw no delivery")
problems = []
if not d["verified"]:
    problems.append("the documented signature check failed")
if not d["forgery_rejected"]:
    problems.append("a signature made with the wrong secret also verified")
if not d["fresh"]:
    problems.append("the timestamp is not within five minutes of now")
if not (d["content_type"] or "").startswith("application/json"):
    problems.append("content type was %r" % d["content_type"])
body = d["body"] or {}
for key in ("severity", "topic", "title", "summary", "timestamp", "source"):
    if key not in body:
        problems.append("the body has no %r" % key)
if body.get("topic") != "notification.test":
    problems.append("topic was %r" % body.get("topic"))
if problems:
    sys.exit("webhook: " + "; ".join(problems))
PY
pass "a signed webhook verified with the documentation's own snippet"

# ── A real alert, with nobody pressing anything ───────────────────────────────
#
# A CA certificate with twenty days left is registered. Its first health check
# runs by itself and crosses the 30-day threshold, which is published, picked
# up by the dispatcher, and sent to every channel that asked for CA expiry
# alerts — here, one on the plain relay and the webhook above.

create_channel "CA expiry" "$plain_cfg,\"encryption\":\"none\",\"to\":[\"pki@live.test\"]}" \
  '{"topics":["ca.expiry_alert"]}' >/dev/null
# On the same relay, and interested only in failed renewals. It must stay quiet.
create_channel "Renewal failures" "$plain_cfg,\"encryption\":\"none\",\"to\":[\"renewals@live.test\"]}" \
  '{"topics":["cert.renewal_failed"]}' >/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$CERTS/expiring-ca.key" -out "$CERTS/expiring-ca.pem" -days 20 \
  -subj "/CN=Expiring Issuing CA" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
ca_body="$(python3 -c '
import json, sys
print(json.dumps({"name": "Expiring Issuing CA", "certificate_pem": open(sys.argv[1]).read()}))' \
  "$CERTS/expiring-ca.pem")"
response="$(api -X POST "$API/api/v1/pki/authorities" -H 'Content-Type: application/json' -d "$ca_body")"
grep -q '"id"' <<<"$response" || die "the core would not register the CA: $response"

mailbox 18025 'to:pki@live.test subject:"Expiring Issuing CA"' >"$WORK/mail.json"
python3 - "$WORK/mail.json" <<'PY' || exit 1
import json, sys
m = json.load(open(sys.argv[1]))
if m["total"] < 1:
    sys.exit("CA expiry: no alert arrived within 30 seconds of the CA being registered")
headers = {k.lower(): v for k, v in m["headers"].items()}
problems = []
if m["subject"] != "[CertPilot CRITICAL] CA expiring: Expiring Issuing CA":
    problems.append("subject was %r" % m["subject"])
if headers.get("x-certpilot-topic") != ["ca.expiry_alert"]:
    problems.append("no X-CertPilot-Topic: ca.expiry_alert header")
for want in ("Expiring Issuing CA", "30-day threshold", "stops validating"):
    if want not in m["text"]:
        problems.append("the body does not mention %r" % want)
if problems:
    sys.exit("CA expiry: " + "; ".join(problems))
PY
pass "a CA crossing its 30-day threshold alerted by email, unprompted"

delivery ca.expiry_alert >"$WORK/hook.json"
python3 - "$WORK/hook.json" <<'PY' || exit 1
import json, sys
d = json.load(open(sys.argv[1]))
if d is None:
    sys.exit("CA expiry: the webhook receiver saw no alert")
body, problems = d["body"] or {}, []
if not d["verified"]:
    problems.append("the documented signature check failed")
if body.get("severity") != "CRITICAL":
    problems.append("severity was %r" % body.get("severity"))
if "Expiring Issuing CA" not in body.get("title", ""):
    problems.append("title was %r" % body.get("title"))
if problems:
    sys.exit("CA expiry, webhook: " + "; ".join(problems))
PY
pass "the same alert reached the webhook, signed"

# The filter is the other half of the promise. A team that routes CA alerts to
# the PKI mailbox and renewal failures to another should get one each, not both.
quiet="$(mailbox 18025 'to:renewals@live.test' 1 | field '["total"]')"
[[ "$quiet" == 0 ]] || die "the channel filtered to renewal failures received $quiet message(s)"
pass "a channel filtered to other topics stayed quiet"

say ""
say "notifications: every check passed — email against Mailpit ($MAILPIT_IMAGE), webhook against the documented verifier"

#!/usr/bin/env bash
# Does single sign-on work against a real identity provider?
#
# core/server/middleware tests token verification against an httptest JWKS
# endpoint that serves whatever key the test just generated. That proves the
# verifier agrees with the test's idea of a token. This asks Keycloak — a real
# OpenID provider, with its own login page, its own token format and its own
# idea of how a key is rotated — through the same sequence the console runs:
#
#   authorization code with PKCE and a nonce, the code redeemed by the core,
#   a session cookie back, and /me reporting who signed in
#
# and then the bearer-token path an API client uses, the refusals that keep
# either path honest, and a signing-key rotation at the provider.
#
#   ./scripts/live-oidc.sh
#   KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:latest ./scripts/live-oidc.sh
#
# Needs Docker and python3. Exit status is the verdict.

LIVE_NAME=oidc
CORE_PORT=18084
# shellcheck source=scripts/lib/live.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/live.sh"

KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.7.4}"
KC_PORT=18180
KC="http://127.0.0.1:$KC_PORT"
ISSUER="$KC/realms/certpilot"
CLIENT_ID=certpilot-console
REDIRECT_URI="$API/auth/callback"

# Generated per run, for accounts that exist for a minute.
KC_ADMIN_PASSWORD="$(openssl rand -hex 12)"
ALICE_PASSWORD="$(openssl rand -hex 12)"
BOB_PASSWORD="$(openssl rand -hex 12)"

# ── Keycloak ──────────────────────────────────────────────────────────────────
#
# Two realms. `certpilot` is the one the core trusts. `elsewhere` has an
# identical client and an identical user, and exists to be refused: a token
# that is perfectly valid, from a provider the core was never told about.

mkdir -p "$WORK/realms"
python3 - "$WORK/realms" "$REDIRECT_URI" "$ALICE_PASSWORD" "$BOB_PASSWORD" <<'PY'
import json, sys
out, redirect, alice, bob = sys.argv[1:]

def user(name, first, password):
    return {"username": name, "email": f"{name}@live.test", "emailVerified": True,
            "firstName": first, "lastName": "Example", "enabled": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}]}

def realm(name):
    return {
        "realm": name, "enabled": True,
        "clients": [{
            "clientId": "certpilot-console",
            # Public, as the console is: a single-page application cannot keep
            # a secret, so the core redeems the code with PKCE and no secret.
            "publicClient": True,
            "standardFlowEnabled": True,
            # For the bearer-token half only. An API client would normally use
            # a confidential client; what matters here is a token Keycloak
            # signed, and this is the shortest way to one.
            "directAccessGrantsEnabled": True,
            "redirectUris": [redirect],
            "attributes": {"pkce.code.challenge.method": "S256"},
            # Access tokens carry the client in `aud`, so the core's audience
            # check has something to match.
            "protocolMappers": [{
                "name": "audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.client.audience": "certpilot-console",
                           "access.token.claim": "true", "id.token.claim": "false"},
            }],
        }],
        "users": [user("alice", "Alice", alice), user("bob", "Bob", bob)],
    }

for name in ("certpilot", "elsewhere"):
    json.dump(realm(name), open(f"{out}/{name}.json", "w"))
PY
chmod -R a+rX "$WORK/realms"

say "starting Keycloak ($KEYCLOAK_IMAGE)"
live_docker_run certpilot-live-keycloak -p "127.0.0.1:$KC_PORT:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e "KC_BOOTSTRAP_ADMIN_PASSWORD=$KC_ADMIN_PASSWORD" \
  -e "KC_HOSTNAME=$KC" \
  -v "$WORK/realms:/opt/keycloak/data/import:ro" \
  "$KEYCLOAK_IMAGE" start-dev --import-realm
# Keycloak takes a while, and longer on a cold runner.
live_wait_http "$ISSUER/.well-known/openid-configuration" "Keycloak" 1800
pass "Keycloak up, realms imported"

# ── The core, trusting one realm ──────────────────────────────────────────────

LIVE_BOOTSTRAP_ADMINS="
    - alice@live.test"
LIVE_AUTH="
  jwks_url: $ISSUER/protocol/openid-connect/certs
  issuer: $ISSUER
  audience: $CLIENT_ID
  client_id: $CLIENT_ID"
live_start_core
live_sign_in

config="$(curl -sS "$API/api/v1/auth/config")"
python3 - "$config" "$ISSUER" "$CLIENT_ID" <<'PY' || exit 1
import json, sys
c, issuer, client = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
if (c.get("mode"), c.get("issuer"), c.get("client_id")) != ("oidc", issuer, client):
    sys.exit("/auth/config does not describe the provider: %s" % c)
PY
pass "/auth/config hands the console Keycloak's issuer and client"

# ── A browser, without the browser ────────────────────────────────────────────
#
# What lib/oidc.ts does, step for step: read the provider's metadata, build the
# authorization URL with a PKCE challenge, a state and a nonce, follow Keycloak
# to its login page, submit the form, and take the code off the redirect back.
cat >"$WORK/browser.py" <<'PY'
import base64, hashlib, html, http.cookiejar, json, re, secrets, sys
import urllib.error, urllib.parse, urllib.request

issuer, client_id, redirect_uri, username, password = sys.argv[1:6]
# sys.argv[6] is where a refusal page is kept, for whoever has to read it.

class Stop(urllib.request.HTTPRedirectHandler):
    # Keycloak's own redirects are followed; the one back to the application
    # is where a browser would hand over, so it is captured instead.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(redirect_uri):
            raise Handover(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class Handover(Exception):
    pass

class Loopback(http.cookiejar.DefaultCookiePolicy):
    # Keycloak marks its login cookies Secure. A browser still sends them to
    # http://127.0.0.1, because loopback counts as a secure context; Python's
    # jar does not, and Keycloak then reports the login as expired. This is
    # the browser's rule, not a relaxation of Keycloak's.
    def return_ok_secure(self, cookie, request):
        return True if request.host.split(":")[0] in ("127.0.0.1", "localhost") \
            else super().return_ok_secure(cookie, request)

jar = http.cookiejar.CookieJar(policy=Loopback())
browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), Stop)

metadata = json.load(urllib.request.urlopen(issuer + "/.well-known/openid-configuration"))
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
query = urllib.parse.urlencode({
    "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
    "scope": "openid profile email", "state": state, "nonce": nonce,
    "code_challenge": challenge, "code_challenge_method": "S256",
})

page = browser.open(metadata["authorization_endpoint"] + "?" + query).read().decode()
form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page)
if not form:
    sys.exit("Keycloak did not show its login form")
try:
    browser.open(html.unescape(form.group(1)),
                 urllib.parse.urlencode({"username": username, "password": password}).encode())
    sys.exit("Keycloak did not redirect back after the password was submitted")
except Handover as done:
    back = urllib.parse.parse_qs(urllib.parse.urlparse(str(done)).query)
except urllib.error.HTTPError as refused:
    body = refused.read().decode(errors="replace")
    open(sys.argv[6], "w").write(body)
    reason = re.search(r'kc-feedback-text">([^<]+)<|<title>([^<]+)</title>', body)
    sys.exit("Keycloak answered the login form with %d: %s" % (
        refused.code, html.unescape(next(g for g in reason.groups() if g)) if reason else body[:300]))

if back.get("state") != [state]:
    sys.exit("the state that came back is not the one sent")
print(json.dumps({"code": back["code"][0], "code_verifier": verifier,
                  "redirect_uri": redirect_uri, "nonce": nonce}))
PY

# sign_in user password [override-json] — runs the browser half, then posts the
# callback the way the console does. Prints "<http status> <body>" and keeps
# the session in $WORK/<user>.cookies.
sign_in() {
  local user="$1" password="$2" override="${3:-}" callback
  callback="$(python3 "$WORK/browser.py" "$ISSUER" "$CLIENT_ID" "$REDIRECT_URI" "$user" "$password" \
    "$WORK/$user.refused.html")" \
    || die "the browser half of $user's sign-in failed"
  printf '%s' "$callback" >"$WORK/$user.callback.json"
  if [[ -n "$override" ]]; then
    callback="$(python3 -c 'import json,sys; c=json.loads(sys.argv[1]); c.update(json.loads(sys.argv[2])); print(json.dumps(c))' \
      "$callback" "$override")"
  fi
  rm -f "$WORK/$user.cookies"
  curl -sS -c "$WORK/$user.cookies" -o "$WORK/callback.out" -w '%{http_code}' \
    -X POST "$API/api/v1/auth/callback" -H 'Content-Type: application/json' -d "$callback"
  printf ' '
  cat "$WORK/callback.out"
}

as() { local user="$1"; shift; curl -sS -b "$WORK/$user.cookies" "$@"; }

# ── Signing in ────────────────────────────────────────────────────────────────

result="$(sign_in alice "$ALICE_PASSWORD")"
[[ "$result" == 200* ]] || die "alice could not sign in: $result"
me="$(as alice "$API/api/v1/me")"
python3 - "$me" <<'PY' || exit 1
import json, sys
me = json.loads(sys.argv[1])
want = {"email": "alice@live.test", "role": "admin", "auth_method": "session"}
got = {k: me.get(k) for k in want}
if got != want:
    sys.exit("alice's /me is %s, expected %s" % (got, want))
if me.get("display_name") != "Alice Example":
    sys.exit("alice's display name is %r" % me.get("display_name"))
PY
pass "alice signed in through Keycloak: a session, and admin because she is a bootstrap admin"

result="$(sign_in bob "$BOB_PASSWORD")"
[[ "$result" == 200* ]] || die "bob could not sign in: $result"
role="$(as bob "$API/api/v1/me" | field '["role"]')"
[[ "$role" == viewer ]] || die "bob signed in as $role, expected viewer"
status="$(as bob -o /dev/null -w '%{http_code}' -X POST "$API/api/v1/notification-channels" \
  -H 'Content-Type: application/json' -d '{"name":"x","channel_type":"email","config":{}}')"
[[ "$status" == 403 ]] || die "bob, a viewer, was answered $status creating a channel, expected 403"
pass "bob signed in as a viewer, and a viewer is refused an operator's action"

# The identity is recorded against Keycloak's issuer and subject, not the email.
users="$(api "$API/api/v1/users")"
python3 - "$users" "$ISSUER" <<'PY' || exit 1
import json, sys
body, issuer = json.loads(sys.argv[1]), sys.argv[2]
rows = body.get("data", body) if isinstance(body, dict) else body
alice = [u for u in rows if u.get("email") == "alice@live.test"]
if len(alice) != 1:
    sys.exit("expected one account for alice, found %d" % len(alice))
if alice[0].get("issuer") != issuer:
    sys.exit("alice's account is keyed to issuer %r, not Keycloak's" % alice[0].get("issuer"))
if not alice[0].get("subject") or "@" in alice[0]["subject"]:
    sys.exit("alice's subject is %r, not Keycloak's opaque id" % alice[0].get("subject"))
PY
pass "the account is keyed to Keycloak's issuer and opaque subject"

# ── What must be refused ──────────────────────────────────────────────────────

# The code alice already redeemed, presented again.
code="$(cat "$WORK/alice.callback.json")"
status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/api/v1/auth/callback" \
  -H 'Content-Type: application/json' -d "$code")"
[[ "$status" == 401 ]] || die "a replayed authorization code was answered $status, expected 401"
pass "a replayed authorization code is refused"

result="$(sign_in alice "$ALICE_PASSWORD" '{"nonce":"not-the-nonce-that-was-sent"}')"
[[ "$result" == 401* ]] || die "a mismatched nonce was answered: $result"
pass "an ID token whose nonce is not this sign-in's is refused"

result="$(sign_in alice "$ALICE_PASSWORD" '{"code_verifier":"a-verifier-that-was-never-challenged-0123456789abcdef"}')"
[[ "$result" == 401* ]] || die "a wrong PKCE verifier was answered: $result"
pass "a code redeemed with the wrong PKCE verifier is refused"

# ── Bearer tokens ─────────────────────────────────────────────────────────────

# token realm user password — an access token straight from Keycloak.
token() {
  curl -sS -X POST "$KC/realms/$1/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=$CLIENT_ID" -d "username=$2" --data-urlencode "password=$3" \
    | field '["access_token"]'
}
bearer() { curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$API/api/v1/me"; }
kid() { python3 -c 'import base64,json,sys; h=sys.argv[1].split(".")[0]; print(json.loads(base64.urlsafe_b64decode(h+"="*(-len(h)%4)))["kid"])' "$1"; }

alice_token="$(token certpilot alice "$ALICE_PASSWORD")"
[[ "$(bearer "$alice_token")" == 200 ]] || die "alice's access token was refused"
pass "an access token from Keycloak is accepted as a bearer credential"

# One character of the signature changed. Flipping the last character is not
# enough on its own: its low bits can be padding the decoder ignores.
tampered="$(python3 -c '
import sys
t = sys.argv[1]; head, sig = t.rsplit(".", 1)
i = len(sig) // 2
print(head + "." + sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i+1:])' "$alice_token")"
[[ "$(bearer "$tampered")" == 401 ]] || die "a token with an altered signature was accepted"
pass "a token with an altered signature is refused"

foreign="$(token elsewhere alice "$ALICE_PASSWORD")"
[[ "$(bearer "$foreign")" == 401 ]] || die "a token from a realm the core does not trust was accepted"
pass "a valid token from a provider the core was not told about is refused"

# ── Key rotation at the provider ──────────────────────────────────────────────
#
# Keycloak rotates by adding a key with a higher priority; it signs with the
# new one immediately and keeps publishing the old one. The core has already
# fetched the key set by now, for the tokens above. A token signed with a key
# it has not seen must make it look again, not wait out its refresh interval
# while every new sign-in fails.
#
# "Again" is at most once every ten seconds (jwksRefetchFloor), because a key
# id is read before a signature is checked and anybody can invent one. The
# foreign-realm token above was exactly that, seconds ago, so this is the case
# that measures the bound rather than the easy one.

admin_token="$(curl -sS -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin \
  --data-urlencode "password=$KC_ADMIN_PASSWORD" | field '["access_token"]')"
realm_id="$(curl -sS -H "Authorization: Bearer $admin_token" "$KC/admin/realms/certpilot" | field '["id"]')"
status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$KC/admin/realms/certpilot/components" \
  -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' \
  -d "{\"name\":\"rotated\",\"providerId\":\"rsa-generated\",\"providerType\":\"org.keycloak.keys.KeyProvider\",
       \"parentId\":\"$realm_id\",\"config\":{\"priority\":[\"500\"],\"enabled\":[\"true\"],\"active\":[\"true\"],\"algorithm\":[\"RS256\"]}}")"
[[ "$status" == 201 ]] || die "Keycloak would not add a signing key: $status"

rotated_token="$(token certpilot alice "$ALICE_PASSWORD")"
[[ "$(kid "$rotated_token")" != "$(kid "$alice_token")" ]] \
  || die "Keycloak is still signing with the old key; the rotation did not happen"
rotated_at="$(date +%s)"
until [[ "$(bearer "$rotated_token")" == 200 ]]; do
  (( $(date +%s) - rotated_at <= 15 )) \
    || die "fifteen seconds after Keycloak rotated its signing key, tokens signed with the new key are still refused"
  sleep 1
done
waited=$(( $(date +%s) - rotated_at ))
result="$(sign_in alice "$ALICE_PASSWORD")"
[[ "$result" == 200* ]] || die "after Keycloak rotated its signing key, alice could not sign in: $result"
pass "after the provider rotates its signing key, the new key is accepted ${waited}s later, and sign-in works"

[[ "$(bearer "$alice_token")" == 200 ]] || die "a token signed with the old, still-published key was refused after rotation"
pass "a token signed before the rotation is still accepted while its key is published"

say ""
say "oidc: every check passed against Keycloak ($KEYCLOAK_IMAGE)"

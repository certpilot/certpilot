#!/usr/bin/env bash
# Does the console send the headers a browser needs to protect it?
#
#   scripts/check-console-headers.sh http://localhost:3000
#
# The console is the page an administrator signs in to and revokes
# certificates from. Without these a script injected into it runs with that
# person's session, another site can frame it, and a wall display's token in
# the URL leaves in the Referer of any link followed from it.
set -euo pipefail

base="${1:?usage: $0 <console base URL>}"
failed=0

headers() { curl -fsS -o /dev/null -D - "$@" | tr -d '\r'; }
has() {
  local name="$1" want="$2" got
  got="$({ grep -i "^$name:" <<<"$plain" || true; } | head -n 1 | cut -d: -f2- | sed 's/^ *//')"
  if [[ "$got" == *"$want"* ]]; then
    echo "  ok   $name has $want"
  else
    echo "  FAIL $name: want it to contain \"$want\", got \"${got:-nothing}\""
    failed=1
  fi
}

plain="$(headers "$base/")"
has Content-Security-Policy "script-src 'self'"
has Content-Security-Policy "object-src 'none'"
has Content-Security-Policy "frame-ancestors 'none'"
has Content-Security-Policy "base-uri 'self'"
has X-Content-Type-Options nosniff
has X-Frame-Options DENY
has Referrer-Policy no-referrer

# HSTS only means something over HTTPS, and TLS ends in front of the console.
# It is sent when the proxy says the browser came over HTTPS, and not otherwise:
# on a plain-HTTP evaluation it would be ignored at best.
if grep -qi '^Strict-Transport-Security:' <<<"$plain"; then
  echo "  FAIL Strict-Transport-Security sent on a plain-HTTP request"
  failed=1
else
  echo "  ok   no Strict-Transport-Security over plain HTTP"
fi
plain="$(headers -H 'X-Forwarded-Proto: https' "$base/")"
has Strict-Transport-Security "max-age="

if grep -qiE '^Server: nginx/[0-9]' <<<"$plain"; then
  echo "  FAIL the Server header names nginx's version"
  failed=1
else
  echo "  ok   the Server header does not name a version"
fi

[ "$failed" = 0 ] && echo "console headers: every check passed" || { echo "console headers: FAILED"; exit 1; }

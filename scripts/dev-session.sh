#!/usr/bin/env bash
# An authenticated session against a local CertPilot, for the other scripts.
#
# There is no anonymous mode, including locally — `auth.allow_anonymous` is
# refused by configuration validation rather than ignored. So every script that
# talks to the API has to sign in, and two of them did not: dev.sh registered
# the selfsigned CA account and seed-demo.sh filled the estate, both with bare
# curl, and both got a 401. dev.sh swallowed it behind `-sf` and printed "add
# one from the Settings page"; seed-demo.sh crashed on `KeyError: 'data'`
# because it parsed the error body as a list. A fresh clone therefore came up
# with no CA account and could not be seeded, and neither script said why.
#
# Source this and call dev_session. It echoes the path to a cookie jar:
#
#   source "$(dirname "$0")/dev-session.sh"
#   jar="$(dev_session "$api" "$state_dir")" || exit 1
#   curl -sS -b "$jar" "$api/api/v1/certificates"
#
# The credential comes from .certpilot/dev-admin, which dev.sh captures from the
# one time the core prints it. Nothing here writes, echoes or logs it.

# dev_session <api-url> <state-dir>
#
# Echoes a cookie jar path on success. On failure it explains which of the two
# things went wrong, because they need different fixes.
dev_session() {
  local api="$1" state_dir="$2"
  local admin_file="$state_dir/dev-admin"
  local jar="$state_dir/dev-session-cookies"

  # dev.sh captures the credential in a background subshell that waits for the
  # core to print it, so a caller started at the same moment can arrive first.
  # Waiting here rather than in each caller keeps that race in one place.
  local waited=0
  while [[ ! -s "$admin_file" ]]; do
    if (( waited >= 60 )); then
      echo "dev-session: $admin_file never appeared." >&2
      echo "  The core prints the administrator password once, on the first start" >&2
      echo "  against a database with no account that has one. If this database" >&2
      echo "  already has an administrator, sign in as them instead." >&2
      return 1
    fi
    sleep 0.5
    waited=$(( waited + 1 ))
  done

  local email password
  email="$(sed -n 's/^ *email: *//p' "$admin_file" | head -1)"
  password="$(sed -n 's/^ *password: *//p' "$admin_file" | head -1)"
  if [[ -z "$email" || -z "$password" ]]; then
    echo "dev-session: could not read an email and password from $admin_file." >&2
    echo "  Expected the two lines the core prints. Delete it and start again," >&2
    echo "  or sign in through the console." >&2
    return 1
  fi

  local body http_status
  body="$(python3 -c '
import json, sys
print(json.dumps({"email": sys.argv[1], "password": sys.argv[2]}))' "$email" "$password")"

  rm -f "$jar"
  http_status="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
    -c "$jar" -X POST "$api/api/v1/auth/login" \
    -H 'Content-Type: application/json' -d "$body")" || return 1

  if [[ "$http_status" != "200" ]]; then
    echo "dev-session: signing in as $email returned HTTP $http_status." >&2
    if [[ "$http_status" == "401" ]]; then
      # The common one, and not obvious: the file records the password from the
      # one time it was printed. Changing it — which the console insists on at
      # first sign-in — leaves this file describing a password that is gone.
      echo "  $admin_file holds the password the core generated. If it has been" >&2
      echo "  changed since (the console requires that on first sign-in), the" >&2
      echo "  file is stale. Update it, or run against a fresh database." >&2
    fi
    return 1
  fi

  chmod 600 "$jar" 2>/dev/null || true
  printf '%s' "$jar"
}

# dev_session_cookie <jar>
#
# Echoes the session cookie as `name=value`, for the parts of a script that talk
# to the API through something other than curl. seed-demo.sh does most of its
# work in python urllib blocks, which have no access to curl's jar.
dev_session_cookie() {
  local jar="$1"
  # Netscape format: domain, tailmatch, path, secure, expires, name, value. The
  # leading #HttpOnly_ prefix is curl's, and the session cookie carries it.
  awk -F'\t' '!/^#/ || /^#HttpOnly_/ { if (NF >= 7) print $6 "=" $7 }' "$jar" | tail -1
}

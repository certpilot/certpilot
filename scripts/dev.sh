#!/usr/bin/env bash
# Start CertPilot's local development stack in one terminal: PostgreSQL, the
# self-signed gateway, the API, and the frontend.
#
# The store is a real local PostgreSQL rather than the in-memory fallback. That
# matters for two reasons: the store code exercised here is the code that runs
# in production, and a certificate issued before lunch is still there after it.
#
#   ./scripts/dev.sh
#
# Export CERTPILOT_DB_URL first to point at a database of your own; the
# PostgreSQL bootstrap below is skipped entirely when you do.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

db_name="${CERTPILOT_DEV_DB:-certpilot_dev}"
state_dir="$project_dir/.certpilot"
kek_file="$state_dir/dev-kek"

gateway_pid=""
core_pid=""
frontend_pid=""
pg_ctl_bin=""
pg_data=""
started_postgres=""
local_db=""

mkdir -p "$state_dir"

cleanup() {
  trap - EXIT INT TERM
  printf '\nStopping CertPilot development services...\n'

  for pid in "$frontend_pid" "$core_pid" "$gateway_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done

  wait 2>/dev/null || true

  # Stop PostgreSQL only if this script started it — leaving a server running
  # that somebody started deliberately is the ruder of the two mistakes. The
  # data lives in the data directory either way, so stopping loses nothing.
  if [[ -n "$started_postgres" ]]; then
    printf 'Stopping PostgreSQL...\n'
    "$pg_ctl_bin" -D "$pg_data" -s stop >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

# ── PostgreSQL ────────────────────────────────────────────────────────────────
if [[ -z "${CERTPILOT_DB_URL:-}" ]]; then
  if ! command -v pg_ctl >/dev/null 2>&1; then
    cat >&2 <<'MISSING'
PostgreSQL is not installed, so there is nowhere to keep certificates.

  brew install postgresql@17

Or point the stack at a database you already have:

  export CERTPILOT_DB_URL=postgres://user:pass@host:5432/certpilot
MISSING
    exit 1
  fi

  pg_ctl_bin="$(command -v pg_ctl)"

  # PGDATA wins; otherwise take the first Homebrew data directory that has
  # actually been initialised.
  if [[ -n "${PGDATA:-}" ]]; then
    pg_data="$PGDATA"
  else
    for candidate in "$(brew --prefix 2>/dev/null || echo /usr/local)"/var/postgresql@*; do
      if [[ -f "$candidate/PG_VERSION" ]]; then
        pg_data="$candidate"
        break
      fi
    done
    if [[ -z "$pg_data" && -f "$(brew --prefix 2>/dev/null)/var/postgres/PG_VERSION" ]]; then
      pg_data="$(brew --prefix)/var/postgres"
    fi
  fi

  if [[ -z "$pg_data" ]]; then
    echo 'PostgreSQL is installed but no data directory is initialised. Run initdb, or set PGDATA.' >&2
    exit 1
  fi

  if ! pg_isready -q -h 127.0.0.1 -p 5432 2>/dev/null; then
    printf 'Starting PostgreSQL (%s)...\n' "$pg_data"
    if ! "$pg_ctl_bin" -D "$pg_data" -l "$state_dir/postgres.log" -w start >/dev/null; then
      echo "PostgreSQL did not start. See $state_dir/postgres.log" >&2
      exit 1
    fi
    started_postgres=1
  fi

  if ! psql -h 127.0.0.1 -p 5432 -d postgres -tAc \
      "select 1 from pg_database where datname = '$db_name'" | grep -q 1; then
    printf 'Creating database %s...\n' "$db_name"
    createdb -h 127.0.0.1 -p 5432 "$db_name"
  fi

  export CERTPILOT_DB_URL="postgres://$(id -un)@127.0.0.1:5432/$db_name?sslmode=disable"
  local_db=1
fi

# ── Key encryption key ────────────────────────────────────────────────────────
# Certificate private keys and CA credentials are encrypted with this. It is
# written once and reused: generating a fresh one on every start would make
# every secret already in the development database permanently unreadable.
if [[ -z "${CERTPILOT_KEK:-}" ]]; then
  if [[ ! -s "$kek_file" ]]; then
    printf 'Generating a development key encryption key...\n'
    kek_line="$(go run ./core/cmd/ --generate-kek 2>/dev/null)"
    printf '%s\n' "${kek_line#CERTPILOT_KEK=}" > "$kek_file"
    chmod 600 "$kek_file"
  fi
  CERTPILOT_KEK="$(cat "$kek_file")"
  export CERTPILOT_KEK
  if [[ -z "$CERTPILOT_KEK" ]]; then
    echo "No key encryption key in $kek_file. Delete it and rerun." >&2
    exit 1
  fi
fi

# ── Schema ────────────────────────────────────────────────────────────────────
# No prelude: every migration applies to a stock PostgreSQL server. There used
# to be one here, creating the objects migration 001 borrowed from a hosted
# platform, and it was the reason this script could not point at an arbitrary
# database somebody brought themselves.
#
# Applied here rather than by the server, which never migrates itself.
printf 'Applying migrations...\n'
go run ./core/cmd/ --migrate

# ── Services ──────────────────────────────────────────────────────────────────
#
# The self-signed gateway is fetched from its own repository rather than built
# from this tree, which is where it used to live. Pinned to a release so this
# script is reproducible and does not follow whatever is on somebody's main
# branch — and left as `go run`, because the first run of the day should still
# be one command and not a container pull.
#
# The first invocation downloads the module and can take a few seconds longer
# than the wait loop below would suggest; that is why the loop waits 30s rather
# than a couple.
GATEWAY_SELFSIGNED="github.com/certpilot/certpilot-gateway-selfsigned/cmd@v0.2.0"

printf 'Starting self-signed gateway on :9091 (%s)...\n' "$GATEWAY_SELFSIGNED"
go run "$GATEWAY_SELFSIGNED" --port=9091 --insecure &
gateway_pid=$!

# Let the gateway bind before the core registers it as a plugin.
for _ in {1..300}; do
  if nc -z 127.0.0.1 9091 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if ! nc -z 127.0.0.1 9091 2>/dev/null; then
  echo 'The self-signed gateway did not start on port 9091.' >&2
  echo 'It is fetched from the network now; if this is a first run on a machine' >&2
  echo 'with no module cache and no connectivity, that is the likely reason.' >&2
  exit 1
fi

printf 'Starting API on :8080...\n'
# With no config.dev.yaml, the core selects its in-memory local-development
# defaults and permits the loopback gateway above without TLS.
#
# The output is teed rather than left to scroll. On a first run the core prints
# an administrator password exactly once, and it is the only thing standing
# between the operator and an instance they cannot sign into — losing it among
# a hundred engine start-up lines means dropping the database and starting over.
go run ./core/cmd/ --config=config.dev.yaml 2>&1 | tee "$state_dir/core.log" &
core_pid=$!

# Captured to a file of its own, so a second `make dev` can still tell somebody
# what the password was. Not a secret store — a note, in a gitignored directory,
# for a credential that only ever reaches a local database.
(
  for _ in {1..600}; do
    if grep -q 'An administrator account has been created' "$state_dir/core.log" 2>/dev/null; then
      grep -A 4 'An administrator account has been created' "$state_dir/core.log" \
        | grep -E 'email:|password:' \
        | sed 's/^│ *//' > "$state_dir/dev-admin"
      chmod 600 "$state_dir/dev-admin"
      break
    fi
    sleep 0.5
  done
) &

printf 'Starting frontend on :3000...\n'
(cd frontend && npm run dev) &
frontend_pid=$!

# A store that starts empty is correct, but a UI with no CA account behind it is
# a dead end — nothing can be issued and every page reads zero. Register the
# gateway that is already running, once, through the same API a person would.
(
  for _ in {1..600}; do
    if curl -sf -m 1 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done

  if curl -sf -m 5 http://127.0.0.1:8080/api/v1/ca-accounts 2>/dev/null \
      | grep -q '"selfsigned-dev"'; then
    exit 0
  fi

  printf 'Registering the selfsigned-dev CA account...\n'
  if ! curl -sf -m 15 -X POST http://127.0.0.1:8080/api/v1/ca-accounts \
      -H 'Content-Type: application/json' \
      -d '{"name":"selfsigned-dev","provider_type":"selfsigned","gateway_addr":"localhost:9091","is_default":true}' \
      >/dev/null 2>&1; then
    echo 'Could not register the CA account; add one from the Settings page.' >&2
  fi
) &

printf '\nCertPilot is running:\n  Frontend: http://127.0.0.1:3000/\n  API:      http://127.0.0.1:8080/healthz\n  Database: %s\n\nPress Ctrl-C to stop all services.\n\n' "$CERTPILOT_DB_URL"

wait

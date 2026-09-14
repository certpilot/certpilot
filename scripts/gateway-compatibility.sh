#!/usr/bin/env bash
# Does the core in this tree still work with the gateways that are released?
#
# The gateways used to live in this repository, so a change that broke the
# core-to-gateway channel failed before it merged. They do not any more: each is
# its own repository, built and released on its own. Nothing now asks the
# question this script asks, and the failure mode of not asking it is a contract
# that drifted months ago and is discovered by whoever deploys next.
#
# Two things are checked per gateway, because they fail differently.
#
#   contract    The SDK's conformance probe makes real calls and reports what
#               the gateway got wrong. This is the same probe the guide tells a
#               third party to run, and the same one the in-house gateways run
#               in their own CI.
#
#   core        The core built from this tree dials the gateway over mutual TLS
#               and reads its capabilities back. A gateway can satisfy the
#               contract and still be unreachable by this core — a TLS setting,
#               a renamed field, a version skew in the generated stubs — and
#               only dialling it finds that.
#
#   ./scripts/gateway-compatibility.sh                  # all of them
#   ./scripts/gateway-compatibility.sh selfsigned       # just one
#   GW_VERSION=v0.2.0 ./scripts/gateway-compatibility.sh
#
# Writes docs/compatibility.md. Exit status is non-zero if any pair failed, so
# this is usable as a check as well as a generator.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GW_VERSION="${GW_VERSION:-$(grep -E '^GW_VERSION' Makefile | head -1 | awk '{print $3}')}"
SDK_VERSION="${SDK_VERSION:-$(grep -oE 'certpilot-gateway-sdk v[0-9.]+' core/go.mod | head -1 | awk '{print $2}')}"
OUT="${OUT:-docs/compatibility.md}"

WORK="$ROOT/.compat"
PKI="$WORK/pki"
BIN="$WORK/bin"
rm -rf "$WORK"
mkdir -p "$PKI" "$BIN"

# Ports well away from the development stack, so running this does not fight a
# core somebody has open in another terminal.
CORE_PORT=18080
GW_PORT=19091

core_pid=""
gw_pid=""

cleanup() {
  trap - EXIT INT TERM
  [[ -n "$gw_pid" ]] && kill "$gw_pid" 2>/dev/null || true
  [[ -n "$core_pid" ]] && kill "$core_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

say() { printf '%s\n' "$*" >&2; }

# ── What to test ──────────────────────────────────────────────────────────────

ALL=(selfsigned acme vault)
if (( $# )); then
  WANTED=("$@")
else
  WANTED=("${ALL[@]}")
fi

for name in "${WANTED[@]}"; do
  known=""
  for a in "${ALL[@]}"; do [[ "$a" == "$name" ]] && known=1; done
  if [[ -z "$known" ]]; then
    say "no gateway called '$name' — known: ${ALL[*]}"
    exit 2
  fi
done

# ── Build the core and its development PKI once ───────────────────────────────

say "building the core from this tree"
go build -o "$BIN/certpilot-core" ./core/cmd/

"$BIN/certpilot-core" --generate-dev-certs="$PKI" >/dev/null
KEK="$("$BIN/certpilot-core" --generate-kek 2>/dev/null | head -1 | cut -d= -f2-)"

# ── One gateway at a time ─────────────────────────────────────────────────────

declare -a ROWS=()
failures=0

wait_for_port() {
  local port="$1" tries=100
  while (( tries-- )); do
    if lsof -ti:"$port" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  return 1
}

for name in "${WANTED[@]}"; do
  say ""
  say "── $name @ $GW_VERSION ─────────────────────────────"

  contract="not run"
  core_result="not run"
  issuance="not run"
  detail=""

  # Whether this gateway can issue a certificate with nothing configured behind
  # it. Only the self-signed one can: it is its own CA.
  case "$name" in
    selfsigned) can_issue="yes"; domain="compat.example.com" ;;
    acme)       can_issue="no";  domain="compat.example.com" ;;
    vault)      can_issue="no";  domain="compat.example.com" ;;
  esac

  # Install the released gateway. A failure here is itself a result: it means
  # the version this repository points at cannot be built.
  if ! GOBIN="$BIN" go install "github.com/certpilot/certpilot-gateway-$name/cmd@$GW_VERSION" >"$WORK/$name-install.log" 2>&1; then
    say "  could not install the gateway"
    ROWS+=("| \`$name\` | $GW_VERSION | **will not build** | — | — | \`go install\` failed |")
    failures=$((failures + 1))
    continue
  fi
  mv -f "$BIN/cmd" "$BIN/gw-$name"

  # Start it with mutual TLS, which is how the core talks to it in production.
  "$BIN/gw-$name" --port="$GW_PORT" \
    --tls-cert="$PKI/gateway.pem" \
    --tls-key="$PKI/gateway-key.pem" \
    --tls-ca="$PKI/ca.pem" >"$WORK/$name-gateway.log" 2>&1 &
  gw_pid=$!

  if ! wait_for_port "$GW_PORT"; then
    say "  the gateway never listened"
    ROWS+=("| \`$name\` | $GW_VERSION | **did not start** | — | — | see $name-gateway.log |")
    failures=$((failures + 1))
    kill "$gw_pid" 2>/dev/null || true; gw_pid=""
    continue
  fi

  # ── contract ────────────────────────────────────────────────────────────────
  # Run against the SDK version the core actually depends on, not the latest:
  # the question is whether this pair works, and the core is one half of it.
  go run "github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@$SDK_VERSION" \
      -addr "localhost:$GW_PORT" \
      -cert "$PKI/core.pem" -key "$PKI/core-key.pem" -ca "$PKI/ca.pem" \
      -server-name localhost \
      -domain "$domain" >"$WORK/$name-conformance.log" 2>&1 || true

  # The probe's exit status is not the verdict this table wants, and taking it
  # as one would make the table lie.
  #
  # Only the self-signed gateway can issue with nothing behind it. The ACME
  # gateway reaches a real CA and is refused for example.com by policy; the
  # Vault gateway is asked to issue with no Vault address and correctly refuses
  # with InvalidArgument. Both are the gateway behaving properly, and both make
  # the probe exit 1. Reporting that as a failed contract would train everybody
  # to ignore this table, which is worse than not having it.
  #
  # So the contract verdict is every check that is not issuance, and issuance is
  # reported in its own column against what this environment can actually offer.
  # grep -c prints 0 and exits 1 when it matches nothing, so a `|| echo 0`
  # here would append a second zero and the arithmetic below would fail.
  fail_lines="$(grep -E '^[[:space:]]+FAIL' "$WORK/$name-conformance.log" 2>/dev/null || true)"
  contract_fails=0
  issue_fails=0
  if [[ -n "$fail_lines" ]]; then
    contract_fails="$(printf '%s\n' "$fail_lines" | wc -l | tr -d ' ')"
    issue_fails="$(printf '%s\n' "$fail_lines" | grep -c 'IssueCertificate' || true)"
    issue_fails="${issue_fails//[^0-9]/}"
    : "${issue_fails:=0}"
  fi
  other_fails=$(( contract_fails - issue_fails ))

  if (( other_fails > 0 )); then
    contract="**fail**"
    failures=$((failures + 1))
  else
    contract="pass"
  fi

  if (( issue_fails == 0 )) && grep -qE '^[[:space:]]+ok[[:space:]]+IssueCertificate' "$WORK/$name-conformance.log" 2>/dev/null; then
    issuance="pass"
  elif [[ "$can_issue" == "yes" ]]; then
    # This one has no excuse: a gateway that can issue standalone and did not
    # is a real failure.
    issuance="**fail**"
    failures=$((failures + 1))
  else
    issuance="not exercised"
  fi

  summary="$(grep -E '[0-9]+ passed' "$WORK/$name-conformance.log" | tail -1 || true)"
  say "  contract: $contract  (${summary:-})"
  say "  issuance: $issuance"

  # ── core ────────────────────────────────────────────────────────────────────
  cat >"$WORK/$name-core.yaml" <<YAML
server:
  host: "127.0.0.1"
  port: $CORE_PORT
  mode: "development"
auth:
  role_claim: "certpilot_role"
  bootstrap_admins: ["admin@certpilot.local"]
plugins:
  discovery_mode: "static"
  tls:
    cert_file: "$PKI/core.pem"
    key_file: "$PKI/core-key.pem"
    ca_file: "$PKI/ca.pem"
  gateways:
    - name: "$name"
      addr: "localhost:$GW_PORT"
      type: "$name"
      server_name: "localhost"
YAML

  CERTPILOT_KEK="$KEK" "$BIN/certpilot-core" --config "$WORK/$name-core.yaml" \
    >"$WORK/$name-core.log" 2>&1 &
  core_pid=$!

  if wait_for_port "$CORE_PORT"; then
    # The core logs each gateway it reached and the capabilities it read back.
    if grep -q "gateway registered successfully" "$WORK/$name-core.log" 2>/dev/null; then
      core_result="pass"
      detail="registered over mTLS"
    elif grep -qE "failed to connect to gateway|gateway.*(unreachable|error)" "$WORK/$name-core.log"; then
      core_result="**fail**"
      detail="the core could not reach it"
      failures=$((failures + 1))
    else
      # Reached and started, with nothing said either way. Reported as such
      # rather than guessed at: a green table built on an assumption is the
      # thing this script exists to replace.
      core_result="started"
      detail="core came up; no gateway verdict in the log"
    fi
  else
    core_result="**fail**"
    detail="the core did not start"
    failures=$((failures + 1))
  fi
  say "  core:     $core_result  $detail"

  kill "$core_pid" 2>/dev/null || true; core_pid=""
  kill "$gw_pid" 2>/dev/null || true; gw_pid=""
  wait 2>/dev/null || true

  ROWS+=("| \`certpilot-gateway-$name\` | $GW_VERSION | $contract | $issuance | $core_result | ${summary:-—} |")
done

# ── The table ─────────────────────────────────────────────────────────────────

{
  cat <<HEADER
<!-- Generated by scripts/gateway-compatibility.sh. Do not edit by hand. -->

# Gateway compatibility

Which released gateways the current core works with, measured rather than
maintained by hand.

The gateways are separate repositories and release on their own schedule, so
nothing about a green build here guarantees a pair that was never tried. This
table is produced by starting each gateway and talking to it: first with the
conformance probe from the gateway SDK, then with a core built from this
repository dialling it over mutual TLS.

| Gateway | Version | Contract | Issuance | Core | Probe, all checks |
|:---|:---|:---|:---|:---|:---|
HEADER
  printf '%s\n' "${ROWS[@]}"
  cat <<FOOTER

**Contract** is every check in \`cmd/conformance\` from
[certpilot-gateway-sdk](https://github.com/certpilot/certpilot-gateway-sdk)
except issuance, run at $SDK_VERSION — the version this core builds against,
rather than the newest, because the question is whether this pair works.

**Issuance** is separate because only the self-signed gateway can issue with
nothing configured behind it; it is its own CA. The ACME gateway reaches a real
CA and is refused for \`example.com\` by policy, and the Vault gateway is asked
to issue with no Vault address and correctly refuses. Both of those are the
gateway behaving properly, so they are recorded as *not exercised* rather than
counted as failures. Exercising them needs a CA target this job does not have.

**Core** is a core built from this repository, configured with that gateway and
mutual TLS, reporting whether it reached it and read its capabilities back.

The last column is the probe's own totals across every check including
issuance, so a row can read "contract: pass" beside a non-zero failure count.
That is the distinction above, not a contradiction.

Generated $(date -u '+%Y-%m-%d') from core \`$(git rev-parse --short HEAD 2>/dev/null || echo unknown)\`.
FOOTER
} >"$OUT"

say ""
say "wrote $OUT"

if (( failures )); then
  say "$failures check(s) failed"
  exit 1
fi
say "all pairs working"

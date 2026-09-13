#!/usr/bin/env bash
#
# Prove every platform profile by installing to the real service.
#
# Not a unit test. For each profile this starts the actual server in a
# container, hands it a bootstrap certificate so it comes up, then runs this
# agent's own `install --offline` inside that container — the real spec loader,
# the real profile fill, the real renderer, the real atomic write, and the
# profile's own check and reload commands. Then it completes a TLS handshake
# from outside and compares the certificate the service served against the one
# that was installed.
#
# The bootstrap certificate is the point. If the service came up with the final
# certificate already in place, a handshake would prove nothing about the
# reload — and the reload is the half of a profile most likely to be wrong.
# Serving a *different* certificate after the install than before it is the
# only evidence that the four fields in a profile actually work together.
#
#   ./scripts/verify-profiles.sh            every profile
#   ./scripts/verify-profiles.sh nginx      one of them
#   KEEP=1 ./scripts/verify-profiles.sh …   leave the container up to poke at
#
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
PROFILES_DIR="$ROOT/scripts/profiles"
WORK=""
CONTAINER=""
KEEP="${KEEP:-}"

cleanup() {
    if [[ -n "$CONTAINER" ]]; then
        if [[ -n "$KEEP" ]]; then
            echo "  (container $CONTAINER left running)"
        else
            docker rm -f "$CONTAINER" >/dev/null 2>&1
        fi
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

die() { echo "error: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is not installed; this script cannot verify anything without it"
docker version >/dev/null 2>&1 || die "docker is installed but the daemon is not answering"

# ── The material ────────────────────────────────────────────
#
# A two-level chain, because a profile's fullchain.pem is worth nothing if the
# only certificate it was tried with was self-signed and had no chain to carry.
# Two leaves: one the service boots with, one the agent installs.
NAME="verify.certpilot.test"

make_chain() {
    local dir="$1" cn="$2"
    mkdir -p "$dir"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
        -keyout "$dir/ca.key" -out "$dir/ca.pem" \
        -subj "/CN=CertPilot Profile Verification CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1 || return 1
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$dir/key.pem" -out "$dir/csr.pem" -subj "/CN=$cn" >/dev/null 2>&1 || return 1
    openssl x509 -req -in "$dir/csr.pem" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
        -CAcreateserial -days 2 -sha256 -out "$dir/cert.pem" \
        -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$cn") \
            >/dev/null 2>&1 || return 1
    cp "$dir/ca.pem" "$dir/chain.pem"
    cat "$dir/cert.pem" "$dir/chain.pem" > "$dir/fullchain.pem"
    cat "$dir/cert.pem" "$dir/chain.pem" "$dir/key.pem" > "$dir/combined.pem"
    return 0
}

fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

# ── The state directory the agent installs from ─────────────
#
# Exactly what `agent request` would have written: cert.pem, key.pem,
# chain.pem and a meta.json naming the certificate. Built by hand here because
# the alternative is standing up a core and a CA account to verify an nginx
# reload, and `install --offline` deliberately needs neither.
build_state() {
    local dir="$1" src="$2"
    mkdir -p "$dir/certificates/verify"
    cp "$src/cert.pem" "$src/key.pem" "$src/chain.pem" "$dir/certificates/verify/"
    cat > "$dir/certificates/verify/meta.json" <<META
{
  "certificate_id": "00000000-0000-0000-0000-000000000000",
  "names": ["$NAME"],
  "not_after": "2035-01-01T00:00:00Z",
  "renew_after": "2034-01-01T00:00:00Z",
  "issued_at": "2025-01-01T00:00:00Z"
}
META
}

# ── The agent binary the container runs ─────────────────────
#
# Built for the container's architecture, statically, so it runs on an Alpine
# image as readily as a Debian one. CGO off matters: the agent looks up an
# owner and a group, and a dynamically linked binary doing that on musl is a
# way to fail for reasons that have nothing to do with the profile.
build_agent() {
    local arch
    arch="$(docker version --format '{{.Server.Arch}}' 2>/dev/null)"
    [[ -n "$arch" ]] || arch=amd64
    echo "  building the agent for linux/$arch"
    (cd "$ROOT/agent" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go build -o "$WORK/certpilot-agent" ./cmd) || return 1
}

# ── One profile ─────────────────────────────────────────────

pass=0
fail=0
declare -a FAILED=()

verify_one() {
    local profile="$1"
    local def="$PROFILES_DIR/$profile.sh"
    [[ -f "$def" ]] || { echo "SKIP $profile — no $def"; return 0; }

    echo ""
    echo "── $profile ─────────────────────────────────────────"

    # IMAGE, PORT, and the two hooks a platform needs, set by the definition.
    #
    # DOCKERFILE is the one worth explaining. Where an official image exists
    # and puts the binaries where a distribution package would, IMAGE is
    # enough. Where it does not — the httpd image builds from source into
    # /usr/local/apache2, which is not where /usr/sbin/apachectl lives on any
    # host running the Debian or Red Hat package — the definition supplies a
    # Dockerfile that installs the actual package. Verifying a profile's
    # absolute paths against a layout no packaged host has would be verifying
    # nothing.
    IMAGE=""; DOCKERFILE=""; PORT=""; READY_TRIES=40; VERSION_CMD="true"; STARTTLS=""; EXPECT_CHAIN=2
    # MOUNT_LIVE=0 for a service that owns its certificate directory: the
    # bootstrap material is COPYed into the image instead of bind-mounted.
    # PostgreSQL refuses to start if its key is not owned by the account it
    # runs as, and ownership through a bind mount on a virtiofs share is not a
    # thing worth relying on when the alternative is one COPY line.
    MOUNT_LIVE=1
    # CMD_ARGS go after the image name, for an image whose entrypoint takes
    # the server's own flags.
    CMD_ARGS=""
    # PROBE_IN_CONTAINER=1 runs the handshake with the container's own openssl
    # instead of this host's. Needed for MariaDB, and the reason is worth
    # recording: OpenSSL 3.6 refuses MariaDB's greeting with "Only MySQL
    # protocol version 10 is supported", while OpenSSL 3.0 reads the same
    # greeting without complaint. The service is fine either way — what
    # differs is the test tool, and a profile must not fail verification
    # because of the openssl on the machine running the script.
    PROBE_IN_CONTAINER=0
    # SPEC_EXTRA is extra JSON for the destination, for a profile that cannot
    # be complete on its own. Tomcat is the case: a keystore needs a password
    # and there is deliberately no default for one, so a profile alone does not
    # produce an installable destination and the spec here must say so too.
    SPEC_EXTRA=""
    bootstrap_config() { :; }   # writes the service's own configuration
    container_args()   { :; }   # anything the image needs beyond the defaults
    reload_override=""          # when the shipped reload cannot run in a container
    # shellcheck disable=SC1090
    source "$def"

    local case_dir="$WORK/$profile"
    mkdir -p "$case_dir"
    make_chain "$case_dir/boot" "$NAME" || { echo "FAIL $profile — could not make the bootstrap certificate"; return 1; }
    make_chain "$case_dir/final" "$NAME" || { echo "FAIL $profile — could not make the final certificate"; return 1; }
    build_state "$case_dir/state" "$case_dir/final"

    local boot_fp final_fp
    boot_fp="$(fingerprint "$case_dir/boot/cert.pem")"
    final_fp="$(fingerprint "$case_dir/final/cert.pem")"
    if [[ "$boot_fp" == "$final_fp" ]]; then
        echo "FAIL $profile — the two certificates are identical, so the handshake would prove nothing"
        return 1
    fi

    # The spec: a platform name and a certificate name, and nothing else. That
    # is the entire claim this script exists to check.
    mkdir -p "$case_dir/etc"
    cat > "$case_dir/etc/installs.json" <<SPEC
{
  "destinations": [
    {
      "name": "verify",
      "certificate": "$NAME",
      "profile": "$profile"$( [[ -n "$reload_override" ]] && printf ',\n      "reload": %s' "$reload_override" )$SPEC_EXTRA
    }
  ]
}
SPEC

    mkdir -p "$case_dir/live"
    bootstrap_config "$case_dir"

    if [[ -n "$DOCKERFILE" ]]; then
        IMAGE="certpilot-verify-$profile:latest"
        echo "  building $IMAGE from a distribution package"
        if ! printf '%s\n' "$DOCKERFILE" | docker build -q -t "$IMAGE" -f - "$case_dir" >/dev/null 2>"$case_dir/build.log"; then
            echo "FAIL $profile — the image would not build"
            tail -20 "$case_dir/build.log" | sed 's/^/                 /'
            return 1
        fi
    fi

    CONTAINER="certpilot-verify-$profile-$$"
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    # shellcheck disable=SC2046
    docker run -d --name "$CONTAINER" -p "127.0.0.1:0:$PORT" \
        -v "$WORK/certpilot-agent:/usr/local/bin/certpilot-agent:ro" \
        -v "$case_dir/state:/var/lib/certpilot" \
        -v "$case_dir/etc/installs.json:/etc/certpilot/installs.json:ro" \
        $( [[ "$MOUNT_LIVE" == 1 ]] && echo "-v $case_dir/live:/etc/certpilot/live" ) \
        $(container_args "$case_dir") \
        "$IMAGE" $CMD_ARGS >/dev/null || { echo "FAIL $profile — the container would not start"; return 1; }

    local mapped
    mapped="$(docker port "$CONTAINER" "$PORT" 2>/dev/null | head -1 | sed 's/.*://')"
    [[ -n "$mapped" ]] || { echo "FAIL $profile — no published port"; docker logs "$CONTAINER" 2>&1 | tail -20; return 1; }

    # Up and serving the bootstrap certificate, or there is nothing to reload.
    local served="" i=0
    while (( i < READY_TRIES )); do
        served="$(handshake "$mapped")"
        [[ -n "$served" ]] && break
        sleep 0.5
        i=$((i + 1))
    done
    if [[ -z "$served" ]]; then
        echo "FAIL $profile — the service never answered a TLS handshake on :$PORT"
        docker logs "$CONTAINER" 2>&1 | tail -25
        return 1
    fi
    if [[ "$served" != "$boot_fp" ]]; then
        echo "FAIL $profile — the service came up serving something that is not the bootstrap certificate"
        return 1
    fi
    echo "  up, serving the bootstrap certificate"

    # The whole point: the real install, through the real agent.
    local out
    out="$(docker exec "$CONTAINER" /usr/local/bin/certpilot-agent install --offline \
        --state-dir /var/lib/certpilot --installs /etc/certpilot/installs.json 2>&1)"
    local status=$?
    echo "$out" | sed 's/^/  | /'
    if [[ $status -ne 0 ]]; then
        echo "FAIL $profile — the install failed"
        return 1
    fi

    # And the evidence: a different certificate on the wire than a moment ago.
    #
    # Polled rather than asked once. Every reload worth having is asynchronous:
    # the command returns as soon as the signal is delivered, and nginx starts
    # new workers while the old ones finish what they are doing. A single
    # handshake immediately after the install is a race, and one that would
    # have failed intermittently on a slower machine rather than never.
    served=""
    i=0
    while (( i < 40 )); do
        served="$(handshake "$mapped")"
        [[ "$served" == "$final_fp" ]] && break
        sleep 0.25
        i=$((i + 1))
    done
    if [[ "$served" != "$final_fp" ]]; then
        if [[ "$served" == "$boot_fp" ]]; then
            echo "FAIL $profile — the install reported success and the service is still serving"
            echo "                 the certificate it booted with. The files were written; the"
            echo "                 reload did not take."
        else
            echo "FAIL $profile — after the install the service is serving $served"
            echo "                 which is neither what it booted with nor what was installed"
        fi
        echo "                 installed: $final_fp"
        docker exec "$CONTAINER" ls -la "/etc/certpilot/live/$NAME/" 2>&1 | sed 's/^/                 /'
        docker logs "$CONTAINER" 2>&1 | tail -25
        return 1
    fi

    # The chain, separately. EXPECT_CHAIN is 2 everywhere a profile claims to
    # install a chain, and a definition lowers it only for a service that
    # genuinely cannot send one.
    local depth
    depth="$(served_chain_length "$mapped")"
    if (( depth < EXPECT_CHAIN )); then
        echo "FAIL $profile — serving the right certificate, but sending $depth certificate(s)"
        echo "                 and the profile claims a chain, so $EXPECT_CHAIN were expected."
        echo "                 A leaf with no issuer is what a cold client rejects."
        return 1
    fi

    echo "  PASS — served the installed certificate after its own reload"
    echo "         chain depth $depth"
    echo "  VERSION $profile: $(docker exec "$CONTAINER" sh -c "$VERSION_CMD" 2>/dev/null | head -1 | tr -d '\r')"
    echo "         $(docker exec "$CONTAINER" sh -c "$VERSION_CMD" 2>/dev/null | head -1)"
    return 0
}

# handshake returns the SHA-256 fingerprint of the leaf a service is serving.
#
# STARTTLS, where a definition sets it, is not a detail: half the services worth
# a profile do not speak TLS from the first byte. Postfix, Dovecot and
# PostgreSQL all negotiate upward from a plaintext greeting, and a plain
# s_client against them hangs rather than failing — which would look exactly
# like a service that never came up.
handshake() {
    local port="$1"
    if [[ "${PROBE_IN_CONTAINER:-0}" == 1 ]]; then
        docker exec "$CONTAINER" sh -c \
            "openssl s_client ${STARTTLS:+-starttls $STARTTLS} -connect 127.0.0.1:$PORT </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" \
            2>/dev/null | cut -d= -f2
        return
    fi
    local args=(-connect "127.0.0.1:$port" -servername "$NAME")
    [[ -n "${STARTTLS:-}" ]] && args+=(-starttls "$STARTTLS")
    openssl s_client "${args[@]}" </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

# served_chain_length counts the certificates a service sends.
#
# Worth checking separately, and this script did not check it at first — which
# is how a profile shipped for about an hour with cert_path pointing at a file
# called fullchain.pem. The installer writes the *leaf* to cert_path and the
# leaf plus its issuers to fullchain_path, so naming one file after the other
# produces a file whose name is a lie and a service that serves a bare leaf.
#
# A fingerprint check cannot see that. Every client that matters can: a leaf
# with no issuer is what a browser rejects on a cold cache while working
# perfectly on the machine that installed it.
served_chain_length() {
    local port="$1"
    if [[ "${PROBE_IN_CONTAINER:-0}" == 1 ]]; then
        docker exec "$CONTAINER" sh -c \
            "openssl s_client ${STARTTLS:+-starttls $STARTTLS} -showcerts -connect 127.0.0.1:$PORT </dev/null 2>/dev/null" \
            2>/dev/null | grep -c "BEGIN CERTIFICATE"
        return
    fi
    local args=(-connect "127.0.0.1:$port" -servername "$NAME" -showcerts)
    [[ -n "${STARTTLS:-}" ]] && args+=(-starttls "$STARTTLS")
    openssl s_client "${args[@]}" </dev/null 2>/dev/null \
        | grep -c "BEGIN CERTIFICATE"
}

# ── Run ─────────────────────────────────────────────────────

# ── Where the work happens ──────────────────────────────────
#
# Everything here is bind-mounted into a container, so the work directory has
# to be somewhere the container runtime can actually read. That is not a
# given: Docker Desktop shares a configured list of host paths, and this
# machine's list does not include $TMPDIR. The failure when it cannot is the
# reason this is probed rather than assumed — a bind mount of a path Docker
# cannot resolve is **not an error**. Docker creates an empty directory at that
# path inside the container instead, and what you see is the service refusing
# to read its own configuration file, which sends you looking at the
# configuration.
pick_work_dir() {
    local candidates=()
    [[ -n "${VERIFY_WORK_DIR:-}" ]] && candidates+=("$VERIFY_WORK_DIR")
    candidates+=("$(cd "$(mktemp -d)" && pwd -P)" "$ROOT/.verify-work")

    local c
    for c in "${candidates[@]}"; do
        mkdir -p "$c/probe" 2>/dev/null || continue
        echo probe > "$c/probe/file"
        if [[ "$(docker run --rm -v "$c/probe/file:/probe:ro" alpine:3 cat /probe 2>/dev/null)" == "probe" ]]; then
            rm -rf "$c/probe"
            echo "$c"
            return 0
        fi
        rm -rf "$c/probe"
        echo "  $c is not readable by the container runtime; trying elsewhere" >&2
    done
    return 1
}

docker image inspect alpine:3 >/dev/null 2>&1 || docker pull -q alpine:3 >/dev/null 2>&1
WORK="$(pick_work_dir)" || die "no directory on this host can be bind-mounted into a container; set VERIFY_WORK_DIR to one that can"
echo "  work directory: $WORK"

build_agent || die "could not build the agent"

# No mapfile: macOS ships bash 3.2, which predates it by about a decade, and a
# script that only runs under a bash somebody installed themselves is one that
# quietly stops being run.
wanted=()
if [[ $# -gt 0 ]]; then
    wanted=("$@")
else
    for f in "$PROFILES_DIR"/*.sh; do
        [[ -e "$f" ]] || continue
        wanted+=("$(basename "$f" .sh)")
    done
fi
(( ${#wanted[@]} )) || die "no profile definitions in $PROFILES_DIR"

for p in "${wanted[@]}"; do
    if verify_one "$p"; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        FAILED+=("$p")
    fi
    if [[ -n "$CONTAINER" && -z "$KEEP" ]]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1
        CONTAINER=""
    fi
done

echo ""
echo "═════════════════════════════════════════════════════"
echo "$pass verified, $fail failed"
if [[ $fail -gt 0 ]]; then
    printf 'failed: %s\n' "${FAILED[*]:-}"
    exit 1
fi

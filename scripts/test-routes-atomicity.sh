#!/usr/bin/env bash
#
# docs/routes.json must be byte-identical after a failed `make routes`.
#
# This is asserted rather than trusted because the defect class it covers is a
# step that reports failure while having already done damage (#50). The old
# two-writer pipeline left the file valid JSON, listing every route, and
# missing every request and response shape — the half docs/api-reference.md is
# generated from. Nothing looked broken.
#
# Three ways the command can fail, and the file survives all three:
#
#   1. schemagen cannot resolve a handler   the failure that caused #50
#   2. schemagen is handed nothing at all   an empty first pass
#   3. the first pass itself fails          the one a pipeline hides without
#                                           pipefail, by reporting only the
#                                           last command's status
#   4. the first pass succeeds and the       #50 itself, reproduced through
#      second fails, through the real        the real recipe rather than by
#      `make routes`                         calling the second pass by hand
#   5. the first pass emits a whole          the only one a pipeline gets wrong
#      document and *then* fails             silently: the last command in it
#                                            succeeded, so without pipefail
#                                            make calls the whole thing a pass
#
set -uo pipefail

cd "$(dirname "$0")/.."

ROUTES=docs/routes.json
TMP="$(mktemp -d)"

# Every case here deliberately runs a generator that fails, and one of them
# fails by damaging the file. Keep a copy and put it back, so a run of this
# script is never the thing that leaves a gutted inventory in a working copy.
cp "$ROUTES" "$TMP/routes.json.orig" 2>/dev/null || true
restore() {
    if [[ -f "$TMP/routes.json.orig" ]]; then
        cp "$TMP/routes.json.orig" "$ROUTES"
    fi
    rm -rf "$TMP"
}
trap restore EXIT

# sha256sum on Linux, shasum on macOS. Neither is everywhere.
if command -v sha256sum >/dev/null 2>&1; then
    sum() { sha256sum "$ROUTES" | cut -d' ' -f1; }
else
    sum() { shasum -a 256 "$ROUTES" | cut -d' ' -f1; }
fi

# Captured before PATH is shadowed below, so a stub can still call the real one.
REAL_PYTHON="$(command -v python3)"

if [[ ! -f "$ROUTES" ]]; then
    echo "FAIL: $ROUTES does not exist; nothing to protect" >&2
    exit 1
fi

BEFORE="$(sum)"
failures=0

check() {
    local name="$1" status="$2"
    if [[ "$status" -eq 0 ]]; then
        echo "FAIL: $name — the command succeeded; it was supposed to fail" >&2
        failures=$((failures + 1))
        return
    fi
    local after
    after="$(sum)"
    if [[ "$after" != "$BEFORE" ]]; then
        echo "FAIL: $name — $ROUTES changed after a failed run" >&2
        echo "      before $BEFORE" >&2
        echo "      after  $after" >&2
        failures=$((failures + 1))
        return
    fi
    echo "ok: $name — failed, and left $ROUTES alone"
}

# 1. A handler schemagen cannot resolve. Exactly #50's trigger: a type that
#    moved, found only on the second pass, after the first had already written.
echo '{"routes":[{"method":"GET","path":"/x","handler":"nosuchvar.Method"}]}' \
    | go run scripts/schemagen/main.go -o "$ROUTES" >/dev/null 2>&1
check "unresolvable handler" $?

# 2. Nothing on stdin.
: | go run scripts/schemagen/main.go -o "$ROUTES" >/dev/null 2>&1
check "empty input" $?

# 3. The first pass fails. A python3 on PATH that does nothing but exit 1, so
#    the real recipe runs and the real pipeline decides. Without pipefail this
#    case passes while being completely broken.
mkdir -p "$TMP/bin"
printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/python3"
chmod +x "$TMP/bin/python3"
PATH="$TMP/bin:$PATH" make routes >/dev/null 2>&1
check "first pass fails" $?

# 4. #50 exactly: a first pass that succeeds, a second that fails. This is the
#    check that fails if the two-writer arrangement ever comes back, because
#    the other three pass under it — the damage needed a first pass that had
#    already written the target before the second one refused.
cat > "$TMP/bin/python3" <<'STUB'
#!/bin/sh
# extract-routes.py's own interface: a path argument is written to, and
# stdout is the fallback. Both halves matter — a stub that only ever wrote to
# stdout could not reproduce the two-writer damage this case exists to catch.
doc='{"routes":[{"method":"GET","path":"/x","handler":"nosuchvar.Method"}]}'
for arg in "$@"; do
    case "$arg" in
        -*|*.py) continue ;;
        *) echo "$doc" > "$arg"; exit 0 ;;
    esac
done
echo "$doc"
STUB
chmod +x "$TMP/bin/python3"
PATH="$TMP/bin:$PATH" make routes >/dev/null 2>&1
check "second pass fails after a good first pass" $?

# 5. A first pass that produces a perfectly good document and then fails. The
#    only failure a pipeline hides on its own: the last command succeeded, so
#    the pipeline's status is zero and make reports a pass. Nothing is damaged
#    here — what is wrong is that a failed step was called a success, which is
#    how the next one of these goes unnoticed.
cat > "$TMP/bin/python3" <<STUB
#!/bin/sh
"$REAL_PYTHON" "\$@"
exit 1
STUB
chmod +x "$TMP/bin/python3"
PATH="$TMP/bin:$PATH" make routes >/dev/null 2>&1
check "first pass emits output, then fails" $?

# And the honest half: the command still works.
if make routes >/dev/null 2>&1 && [[ "$(sum)" == "$BEFORE" ]]; then
    echo "ok: a successful run reproduces the checked-in inventory"
else
    echo "FAIL: make routes no longer reproduces $ROUTES" >&2
    failures=$((failures + 1))
fi

if [[ "$failures" -ne 0 ]]; then
    echo "$failures check(s) failed" >&2
    exit 1
fi
echo "routes.json survives a failing generator."

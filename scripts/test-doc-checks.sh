#!/usr/bin/env bash
# Break each documentation check's input on purpose, and require it to fail;
# then correct it, and require it to pass.
#
# A check that has never been seen to fail has not been shown to work, and this
# repository has shipped three that passed while checking less than they said:
# the examples checker that never recursed into docs/gateways/, the link checker
# whose slugifier passed a link dead in both renderers, and the anchor check on
# the docs site that exited 0 whenever there was nothing to read. Each broken
# case below is a failure that actually happened, not an invented one.
#
# Every case works on a copy in a temporary directory; nothing under docs/ is
# touched. The version cases ask real registries and so need the network, and
# fail rather than skip without it.
#
#   ./scripts/test-doc-checks.sh
#
# Exit status is the verdict.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
T="$(mktemp -d "${TMPDIR:-/tmp}/doc-checks.XXXXXX")"
trap 'rm -rf "$T"' EXIT
failures=0

# expect <name> <exit code> <text the output must contain, or ""> <command...>
expect() {
  local name="$1" want="$2" text="$3"; shift 3
  local out code
  out="$("$@" 2>&1)"; code=$?
  if [[ "$code" == "$want" && ( -z "$text" || "$out" == *"$text"* ) ]]; then
    printf 'ok    %s\n' "$name"
  else
    printf 'FAIL  %s — wanted exit %s%s, got %s:\n%s\n' "$name" "$want" \
      "${text:+ and \"$text\"}" "$code" "$(printf '%s' "$out" | sed 's/^/        /')"
    failures=$((failures + 1))
  fi
}

page() { mkdir -p "$(dirname "$T/$1")"; cat >"$T/$1"; }

echo "── check-doc-examples.py: an example that could not run"

page examples/broken.md <<'MD'
```bash
curl -sS localhost:8080/api/v1/certificates
```
MD
expect "an example with no credential fails" 1 "carries no credential — it is a 401" \
  python3 scripts/check-doc-examples.py "$T/examples/broken.md"

page examples/fixed.md <<'MD'
```bash
curl -sS -b "$JAR" localhost:8080/api/v1/certificates
```
MD
expect "the same example with a session passes" 0 "" \
  python3 scripts/check-doc-examples.py "$T/examples/fixed.md"

page examples/noroute.md <<'MD'
```bash
curl -sS -b "$JAR" localhost:8080/api/v1/certificats
```
MD
expect "an example naming a route that does not exist fails" 1 "is not a route" \
  python3 scripts/check-doc-examples.py "$T/examples/noroute.md"

# The fence the first version of the parser lost: a ```text block's closing
# fence was read as the next opener, hiding the example after it.
page examples/fence.md <<'MD'
```text
some output
```

```bash
curl -sS localhost:8080/api/v1/certificates
```
MD
expect "an example after a non-shell fence is still read" 1 "carries no credential" \
  python3 scripts/check-doc-examples.py "$T/examples/fence.md"

echo "── check-doc-links.py: a link a reader cannot follow"

# Pages placed where the real ones are, so relative links resolve the same way.
mkdir -p "$T/links/docs"
cp docs/operations.md docs/getting-started.md "$T/links/docs/"
page links/docs/digit.md <<'MD'
[Issue from a real CA](getting-started.md#5-issue-from-a-real-ca)
MD
expect "a digit-leading anchor spelled GitHub's way fails, naming the site's spelling" 1 \
  "renders that heading as #_5-issue-from-a-real-ca" \
  python3 scripts/check-doc-links.py "$T/links/docs/digit.md"

page links/docs/emdash.md <<'MD'
[Delete](operations.md#delete-not-a-substitute-for-revoking)
MD
expect "the em-dash anchor the old slugifier passed now fails" 1 "has no heading matching" \
  python3 scripts/check-doc-links.py "$T/links/docs/emdash.md"

page links/docs/fixed.md <<'MD'
[Issue from a real CA](getting-started.md#_5-issue-from-a-real-ca) and
[Delete](operations.md#delete-—-not-a-substitute-for-revoking).
MD
expect "both links, spelled the way the site renders them, pass" 0 "" \
  python3 scripts/check-doc-links.py "$T/links/docs/fixed.md"

page links/docs/nopage.md <<'MD'
[Gone](no-such-page.md)
MD
expect "a link to a page that does not exist fails" 1 "does not exist" \
  python3 scripts/check-doc-links.py "$T/links/docs/nopage.md"

echo "── check-doc-versions.py: a version a reader cannot run"

page versions/missing.md <<'MD'
docker run ghcr.io/certpilot/gateway-vault:0.9.9
go install github.com/certpilot/certpilot-agent/cmd@v0.9.9
MD
expect "an image tag and a module version that were never published fail" 1 \
  "no such image tag is published" \
  python3 scripts/check-doc-versions.py "$T/versions/missing.md"

page versions/drift.md <<'MD'
CERTPILOT_VERSION=0.1.1 GATEWAY_VERSION=0.3.0 docker compose up -d

| `ghcr.io/certpilot/gateway-selfsigned` | 0.2.0 |
MD
expect "a page whose table and command disagree fails" 1 "pinned to more than one version" \
  python3 scripts/check-doc-versions.py --offline "$T/versions/drift.md"

page versions/fixed.md <<'MD'
CERTPILOT_VERSION=0.1.1 GATEWAY_VERSION=0.3.0 docker compose up -d

| `ghcr.io/certpilot/gateway-selfsigned` | 0.3.0 |
MD
expect "the same page, agreeing with itself and published, passes" 0 "" \
  python3 scripts/check-doc-versions.py "$T/versions/fixed.md"

echo "── run-evaluation-doc.py: a page that has changed shape (no Docker needed)"

sed 's|^mkdir certpilot-eval \&\& cd certpilot-eval$|mkdir certpilot-eval \&\& cd certpilot-eval \&\& echo <your-licence-key>|' \
  docs/evaluation.md >"$T/evaluation-placeholder.md"
expect "a page that starts asking the reader for something new fails before running it" 1 \
  "has not been taught to fill in" \
  python3 scripts/run-evaluation-doc.py --page "$T/evaluation-placeholder.md" --workdir "$T/eval"

python3 - "$T/evaluation-nostep.md" <<'PY'
import re, sys
text = open("docs/evaluation.md").read()
# Drop step 7's shell block, which is what a page reorganised around a
# different cleanup would look like to this script.
start = text.index("## 7. Put it back")
end = text.index("```", text.index("```", start) + 3) + 3
open(sys.argv[1], "w").write(text[:start] + "## 7. Put it back\n\nDelete the directory." + text[end:])
PY
expect "a page that lost a step's commands fails before running anything" 1 \
  "no shell block under step(s) [7]" \
  python3 scripts/run-evaluation-doc.py --page "$T/evaluation-nostep.md" --workdir "$T/eval"

echo "── check-comparison-sources.py: a vendor page that changed under a quote"

# A local server stands in for the vendor, so this needs no network. The cases
# are about what the checker does with a page, not about any vendor's page. The
# first page spells its text the way vendor HTML does, with an entity for the
# apostrophe, a non-breaking space and a zero-width one, which is how DigiCert
# writes its own name. The second is how Keyfactor answers a moved page: status
# 200, and a title saying it is not there.
mkdir -p "$T/vendor"
cat >"$T/vendor/docs.html" <<'HTML'
<html><head><title>Vendor docs</title></head><body>
<p>The&nbsp;platform&rsquo;s agent generates the key&#8203; on the host.</p></body></html>
HTML
cat >"$T/vendor/moved.html" <<'HTML'
<html><head><title>Oops! Page Not Found</title></head><body>Try the home page.</body></html>
HTML
port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$T/vendor" >/dev/null 2>&1 &
server=$!
disown "$server"  # killed on exit; without this bash reports it as "Terminated"
trap 'kill "$server" 2>/dev/null; rm -rf "$T"' EXIT
for _ in $(seq 1 20); do
  python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port/docs.html')" 2>/dev/null && break
  sleep 0.25
done

# comparison <file> <cited id> <quoted text> <path on the stand-in vendor>
comparison() {
  page "$1" <<MD
# Comparison

It generates keys on the host ([$2](#sources)).

## Sources

| ID | Vendor | Page | Version or date | Reviewed | Quoted |
|:--|:--|:--|:--|:--|:--|
| K1 | Vendor | [Docs](http://127.0.0.1:$port/$4) | 1.0 | 2026-09-24 | $3 |
MD
}

comparison comparison/ok.md K1 "The platform's agent generates the key on the host." docs.html
expect "a quote still on its page passes, however the page spells its spaces" 0 "" \
  python3 scripts/check-comparison-sources.py --page "$T/comparison/ok.md"

comparison comparison/reworded.md K1 "The platform's agent generates the key in the cloud." docs.html
expect "a quote the vendor has since reworded fails, naming the row" 1 \
  "K1 (Vendor): the quoted text is no longer on" \
  python3 scripts/check-comparison-sources.py --page "$T/comparison/reworded.md"

comparison comparison/moved.md K1 "The platform's agent generates the key on the host." moved.html
expect "a page that moved and answers 200 anyway fails" 1 "now serves a not-found page" \
  python3 scripts/check-comparison-sources.py --page "$T/comparison/moved.md"

comparison comparison/uncited.md K2 "The platform's agent generates the key on the host." docs.html
expect "a claim citing a source that is not listed fails, offline too" 1 \
  "the page cites K2, which is not in Sources" \
  python3 scripts/check-comparison-sources.py --offline --page "$T/comparison/uncited.md"

echo
if (( failures )); then
  echo "$failures case(s) did not behave"
  exit 1
fi
echo "every check failed on its broken input and passed on its corrected one"

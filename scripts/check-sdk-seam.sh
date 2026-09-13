#!/usr/bin/env bash
#
# The three modules under pkg/ must not import each other.
#
# A module boundary is a promise about what may import what, and nothing
# enforces it while they share a tree — `go build` is perfectly happy to let
# pkg/secrets import the gateway SDK, and the first sign of trouble would be
# the day somebody tries to move one out.
#
# Checked rather than trusted, for the same reason every other invariant here
# is: the seam closes the first time somebody reaches across it, and the
# compiler will not say so.
set -euo pipefail

fail=0
note() { echo "  ✗ $*"; fail=1; }

# -maxdepth keeps each check inside its own module: pkg/ contains the other two
# as subdirectories, and a naive recursive grep reports their imports as its own.
# That mistake is why this is a script and not a one-liner in a workflow.
pkg_files=$(find pkg -maxdepth 2 -name '*.go' -not -path 'pkg/gatewaysdk/*' -not -path 'pkg/agentsdk/*')

echo "==> pkg must not import either SDK"
if [ -n "$pkg_files" ] && grep -l "certpilot-gateway-sdk\|certpilot-agent-sdk" $pkg_files 2>/dev/null; then
  note "the files above import an SDK. pkg is what is left over after the SDKs;"
  note "anything it needs from them belongs in one of them instead."
fi

echo "==> the gateway SDK must not import the agent SDK, or pkg"
if grep -rl "certpilot-agent-sdk\|certpilot/certpilot/pkg" --include='*.go' pkg/gatewaysdk 2>/dev/null; then
  note "the gateway SDK reaches outside itself. It is published on its own and"
  note "cannot depend on anything that is not."
fi

echo "==> the agent SDK must not import the gateway SDK, or pkg"
if grep -rl "certpilot-gateway-sdk\|certpilot/certpilot/pkg" --include='*.go' pkg/agentsdk 2>/dev/null; then
  note "the agent SDK reaches outside itself. An agent speaks HTTP with a"
  note "signature and has never needed the provider proto; keep it that way."
fi

echo "==> neither SDK may import the core"
if grep -rl "certpilot/certpilot/core" --include='*.go' pkg/gatewaysdk pkg/agentsdk 2>/dev/null; then
  note "an SDK imports the core. The dependency runs the other way."
fi

if [ "$fail" -eq 1 ]; then
  echo
  echo "See #42. These three are separate modules so they can become separate"
  echo "repositories; an import across them is the thing that stops that."
  exit 1
fi
echo "the seam holds"

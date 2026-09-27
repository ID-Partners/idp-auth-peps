#!/usr/bin/env bash
# Every component says one version: both Kong rockspecs (file name, version, source tag,
# and the sideband rock's pin on authzen-pdp), both handlers and sideband.lua, the
# PingAccess pom, the Node package, its lockfile and the version the SDK sends in MCP's
# initialize, a CHANGELOG section, and every image and rock a document points at. The
# release workflow's first job runs it, and so does scripts/release.sh.
#
#   scripts/check-versions.sh 0.4.1
set -uo pipefail
cd "$(dirname "$0")/.."

v="${1:?usage: scripts/check-versions.sh X.Y.Z}"
fail=0

# says LABEL FILE STRING...: FILE holds every STRING, verbatim.
says() {
  local label=$1 file=$2
  shift 2
  for want in "$@"; do
    if ! grep -qF -- "$want" "$file" 2>/dev/null; then
      echo "::error::$label does not say $v (wanted in $file: $want)"
      fail=1
      return
    fi
  done
}

says "Kong authzen-pdp rockspec" "gateways/kong/authzen-pdp/kong-plugin-authzen-pdp-$v-1.rockspec" \
  "version = \"$v-1\"" "tag = \"v$v\","
says "Kong sideband-pdp rockspec" "gateways/kong/sideband-pdp/kong-plugin-sideband-pdp-$v-1.rockspec" \
  "version = \"$v-1\"" "tag = \"v$v\"," "\"kong-plugin-authzen-pdp == $v\""
says "Kong authzen-pdp handler" gateways/kong/authzen-pdp/handler.lua "VERSION = \"$v\","
says "Kong sideband-pdp handler" gateways/kong/sideband-pdp/handler.lua "VERSION = \"$v\","
says "Kong sideband module" gateways/kong/sideband-pdp/sideband.lua "S.VERSION = \"$v\""
says "PingAccess pom" gateways/pingaccess/authzen-pdp/pom.xml "<version>$v</version>"
says "Node package.json" sdk/node/package.json "\"version\": \"$v\","
says "Node package-lock.json" sdk/node/package-lock.json "\"version\": \"$v\","
says "Node SDK_VERSION" sdk/node/src/mcp.ts "SDK_VERSION = '$v';"
says "CHANGELOG.md" CHANGELOG.md "## [$v]"

# A document that shows an image, a rock, the rock's pin or "the version" shows this
# one. The CHANGELOG is history, and the workflows carry examples.
x='[0-9]+\.[0-9]+\.[0-9]+'
stale=$(git grep -h -o -E "coaz-pep:$x(-[a-z0-9]+)?|kong-plugin-(authzen|sideband)-pdp-$x-[0-9]+|kong-plugin-authzen-pdp(</code>|\`) $x|Version $x;" \
    -- . ':!CHANGELOG.md' ':!.github' \
  | sort -u \
  | grep -v -x -F -e "coaz-pep:$v" -e "kong-plugin-authzen-pdp-$v-1" -e "kong-plugin-sideband-pdp-$v-1" \
      -e "kong-plugin-authzen-pdp</code> $v" -e "kong-plugin-authzen-pdp\` $v" -e "Version $v;" || true)
if [ -n "$stale" ]; then
  while read -r ref; do
    echo "::error::a document points at $ref, not $v: $(git grep -l -F "$ref" -- . ':!CHANGELOG.md' ':!.github' | tr '\n' ' ')"
  done <<< "$stale"
  fail=1
fi

exit $fail

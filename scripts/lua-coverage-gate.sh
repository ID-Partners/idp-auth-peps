#!/usr/bin/env bash
# Lua coverage ratchet for the Kong plugin.
#
# Same contract as the Go and JS gates: a floor set just under the current number, so a
# change that drops coverage fails and one that raises it needs nothing here. Raise the
# floor when coverage rises; never lower it to make CI pass.
set -euo pipefail

FLOOR=85

cd "$(dirname "$0")/../gateways/kong"

busted --coverage --lpath="./?.lua;./?/init.lua" spec/ >/dev/null
luacov

# The report's Total line is "Total <hits> <missed> <pct>%".
pct=$(awk '/^Total/ { gsub(/%/, "", $4); print $4 }' .luacov.report.out)
if [ -z "${pct:-}" ]; then
  echo "FAIL could not read a total from .luacov.report.out"
  exit 1
fi

if awk "BEGIN{exit !($pct < $FLOOR)}"; then
  echo "FAIL gateways/kong: ${pct}% is below the ${FLOOR}% floor"
  exit 1
fi
echo "ok   gateways/kong: ${pct}% (floor ${FLOOR}%)"

#!/usr/bin/env bash
# Go coverage ratchet.
#
# A floor per package, set just under the number on the day it was added. A change that
# drops coverage fails; one that raises it needs nothing here. Raise a floor when
# coverage rises — never lower one to make CI pass.
#
# Plain case/esac rather than an associative array: macOS still ships bash 3.2.
set -euo pipefail

floor_for() {
  case "$1" in
    */core/coaz)          echo 94 ;;
    */core/cmd/coaz-pep)  echo 95 ;;
    */core/jose)          echo 95 ;;
    */core/federation)    echo 96 ;;
    */core/authzen/discovery) echo 94 ;;
    */core/internal/ttlcache)  echo 98 ;;
    */core/internal/metafetch) echo 94 ;;
    *)                    echo "" ;;
  esac
}

cd "$(dirname "$0")/../core"

fail=0
found=0
while read -r line; do
  case "$line" in ok*) ;; *) continue ;; esac
  pkg=$(echo "$line" | awk '{print $2}')
  pct=$(echo "$line" | sed -nE 's/.*coverage: ([0-9.]+)% of statements.*/\1/p')
  [ -z "$pct" ] && continue
  found=$((found + 1))
  floor=$(floor_for "$pkg")
  if [ -z "$floor" ]; then
    echo "??   $pkg has no floor — add one to scripts/coverage-gate.sh"
    fail=1
  elif awk "BEGIN{exit !($pct < $floor)}"; then
    echo "FAIL $pkg: ${pct}% is below the ${floor}% floor"
    fail=1
  else
    echo "ok   $pkg: ${pct}% (floor ${floor}%)"
  fi
done < <(go test ./... -cover 2>/dev/null)

if [ "$found" -eq 0 ]; then
  echo "FAIL no package coverage was measured — did the tests run?"
  exit 1
fi
exit $fail

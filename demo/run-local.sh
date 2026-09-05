#!/usr/bin/env bash
# The same demo without Docker: builds the two Go binaries, runs the stubs and the three
# PEPs on this machine, runs demo.sh, and cleans up. Needs Go 1.25+.
set -euo pipefail
cd "$(dirname "$0")"
OUT="${TMPDIR:-/tmp}/idp-auth-peps-demo"
mkdir -p "$OUT"

(cd ../core && go build -o "$OUT/coaz-pep" ./cmd/coaz-pep && go build -o "$OUT/demo-stubs" ./cmd/demo-stubs)

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT

STUB_HOST=localhost ANCHORS_FILE="$OUT/anchors.json" "$OUT/demo-stubs" >"$OUT/stubs.log" 2>&1 &
pids+=($!)
until curl -sf http://localhost:9000/healthz >/dev/null; do sleep 0.2; done

common=(AUTHZEN_URL=http://localhost:9002 AUTHZEN_API_KEY=static-pdp-key CHECK_API_TOKEN=demo MCP_UPSTREAM_ALLOWLIST=http://localhost:9004 HTTP_ADDR=127.0.0.1)
env "${common[@]}" PORT=9291 HTTP_PORT=9192 "$OUT/coaz-pep" >"$OUT/pep-static.log" 2>&1 &
pids+=($!)
# Allowlists match scheme + host + port at a path boundary, so each stub is listed.
# pep-resource deliberately has NO PDP_ALLOWLIST (it warns): the point of scenario 2 is
# what happens when a resource's own word is the only bound. pep-federation has one.
resources="http://localhost:9001,http://localhost:9004,http://localhost:9005,http://localhost:9006,http://localhost:9007"
env "${common[@]}" PORT=9292 HTTP_PORT=9193 PDP_DISCOVERY=resource PDP_DISCOVERY_INSECURE=true \
  RESOURCE_METADATA_ALLOWLIST="$resources" "$OUT/coaz-pep" >"$OUT/pep-resource.log" 2>&1 &
pids+=($!)
env "${common[@]}" PORT=9293 HTTP_PORT=9194 PDP_DISCOVERY=federation PDP_DISCOVERY_INSECURE=true \
  RESOURCE_METADATA_ALLOWLIST="$resources" PDP_ALLOWLIST=http://localhost:9002 \
  FEDERATION_TRUST_ANCHORS_FILE="$OUT/anchors.json" \
  FEDERATION_FETCH_ALLOWLIST=http://localhost:9000 \
  "$OUT/coaz-pep" >"$OUT/pep-federation.log" 2>&1 &
pids+=($!)
for p in 9192 9193 9194; do until curl -sf "http://localhost:$p/healthz" >/dev/null; do sleep 0.2; done; done

STUBS_HOST=localhost ./demo.sh
echo "logs in $OUT (stubs.log shows which PDP was consulted)"

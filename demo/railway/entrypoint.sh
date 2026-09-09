#!/bin/sh
# One container, the whole demo: the stubs, three PEPs and the console, all on
# localhost, the console on $PORT (Railway sets it; 8088 otherwise). The wiring is
# ../run-local.sh's and ../docker-compose.yml's. PDP_DISCOVERY_INSECURE is here because
# everything is plain http inside one container — do not copy that anywhere real.
set -eu

# The stubs' identifiers carry a host name. "stubs" keeps them identical to the compose
# run (http://stubs:9004 and so on); it needs a line in /etc/hosts, which most container
# runtimes allow. When they do not, localhost is just as correct.
host=localhost
if echo "127.0.0.1 stubs" >> /etc/hosts 2>/dev/null; then host=stubs; fi
port="${PORT:-8088}"
anchors=/tmp/anchors.json
pids=""

ready() { until wget -q -O /dev/null "http://127.0.0.1:$1/healthz" 2>/dev/null; do sleep 0.2; done; }

STUB_HOST="$host" ANCHORS_FILE="$anchors" demo-stubs &
pids="$pids $!"
ready 9099

# What every PEP shares. PDP_METADATA_TTL is short so the console's trace shows the
# fetches on every run; the shipped default is 5m.
export AUTHZEN_URL="http://$host:9002/tenants/bank-a" AUTHZEN_API_KEY=static-pdp-key CHECK_API_TOKEN=demo
export HTTP_ADDR=127.0.0.1 PDP_METADATA_TTL=15s
export MCP_UPSTREAM_ALLOWLIST="http://$host:9001,http://$host:9004,http://$host:9005,http://$host:9006,http://$host:9009"
# Allowlists match scheme + host + port at a path boundary, so each stub is listed.
resources="http://$host:9001,http://$host:9004,http://$host:9005,http://$host:9006,http://$host:9007,http://$host:9009,http://$host:9194"

# pep-static: told where its PDP is, no discovery.
PORT=9291 HTTP_PORT=9192 coaz-pep &
pids="$pids $!"
# pep-resource: trusts each resource's own well-known. Deliberately no PDP_ALLOWLIST (it
# warns at boot): scenario 2 is what happens when a resource's own word is the only
# bound on who decides.
PORT=9292 HTTP_PORT=9193 PDP_DISCOVERY=resource PDP_DISCOVERY_INSECURE=true \
  RESOURCE_METADATA_ALLOWLIST="$resources" coaz-pep &
pids="$pids $!"
# pep-federation: trusts the federation's word, and only PDPs on its allowlist. It is
# also the federation face of the API it fronts (http://$host:9194): it holds a key,
# publishes a minimal entity configuration for the anchor to onboard, and republishes
# what the federation resolves as that API's RFC 9728 document.
PORT=9293 HTTP_PORT=9194 PDP_DISCOVERY=federation PDP_DISCOVERY_INSECURE=true \
  RESOURCE_METADATA_ALLOWLIST="$resources" \
  PDP_ALLOWLIST="http://$host:9002,http://$host:9008,http://$host:9098" \
  FEDERATION_TRUST_ANCHORS_FILE="$anchors" FEDERATION_FETCH_ALLOWLIST="http://$host:9000" \
  FEDERATION_ENTITY_ID="http://$host:9194" FEDERATION_ENTITY_KEY_FILE=/tmp/entity-key.json FEDERATION_ENTITY_KEY_GENERATE=true \
  FEDERATION_AUTHORITY_HINTS="http://$host:9000" coaz-pep &
pids="$pids $!"
for p in 9192 9193 9194; do ready "$p"; done

LISTEN=":$port" STUBS_BASE="http://$host" STUBS_CONTROL="http://$host:9099" \
  PEP_STATIC=http://127.0.0.1:9192 PEP_RESOURCE=http://127.0.0.1:9193 PEP_FEDERATION=http://127.0.0.1:9194 \
  GATEWAY_ENTITY="http://$host:9194" \
  demo-console &
pids="$pids $!"
echo "demo: console on :$port (stubs at http://$host, PEPs on 9192-9194)"

# If any process goes, exit, so the platform restarts the set together.
while :; do
  for pid in $pids; do
    kill -0 "$pid" 2>/dev/null || { echo "demo: process $pid exited; stopping"; exit 1; }
  done
  sleep 2
done

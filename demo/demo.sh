#!/usr/bin/env bash
# Walk through PDP discovery against the three PEPs docker-compose (or run-local.sh)
# stands up. Needs curl; uses jq or python3 to pretty-print.
#
#   STUBS_HOST  how the PEPs reach the stubs (default: stubs — the compose network name)
#   PEP_HOST    how this script reaches the PEPs (default: localhost)
set -euo pipefail

STUBS_HOST="${STUBS_HOST:-stubs}"
PEP_HOST="${PEP_HOST:-localhost}"
STATIC="http://${PEP_HOST}:${PEP_STATIC_PORT:-9192}"
RESOURCE="http://${PEP_HOST}:${PEP_RESOURCE_PORT:-9193}"
FEDERATION="http://${PEP_HOST}:${PEP_FEDERATION_PORT:-9194}"
CHECK_TOKEN="${CHECK_API_TOKEN:-demo}"

S="http://${STUBS_HOST}"
MEMBER="$S:9001"; GOOD="$S:9002"; ROGUE="$S:9003"; PLAIN="$S:9004"; IMPOSTOR="$S:9005"; BROKEN="$S:9006"; STRAY="$S:9007"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
# An UNSIGNED token: coaz-pep decodes without verifying when no JWKS is configured, and
# says so loudly at startup. The demo is about discovery, not token validation.
jwt() { # $1 human, $2 agent
  local h c
  h=$(printf '{"alg":"none","typ":"JWT"}' | b64url)
  c=$(printf '{"sub":"%s","client_id":"%s","act":{"sub":"%s"},"scope":"accounts:read payments:write","aud":"%s"}' "$1" "$2" "$2" "$PLAIN" | b64url)
  printf '%s.%s.' "$h" "$c"
}

pretty() {
  if command -v jq >/dev/null 2>&1; then
    jq -c '{decision, status: .response.status, body: ((.response.body // "") | if . == "" then null else (try fromjson catch .) end)}'
  else python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("response") or {}; b=r.get("body") or None
try: b=json.loads(b) if b else None
except Exception: pass
print(json.dumps({"decision": d.get("decision"), "status": r.get("status"), "body": b}))'; fi
}

# check PEP RESOURCE HUMAN METHOD PATH [BODY]
check() {
  local pep="$1" resource="$2" human="$3" method="$4" path="$5" body="${6:-}"
  local cfg
  if [ -n "$resource" ]; then cfg=$(printf '{"pep_label":"demo","style":"rest","require_token":"true","resource":"%s"}' "$resource")
  else cfg='{"pep_label":"demo","style":"rest","require_token":"true"}'; fi
  local esc_body; esc_body=$(printf '%s' "$body" | sed 's/"/\\"/g')
  curl -sS -X POST "$pep/v1/mcp/check" \
    -H "Authorization: Bearer $CHECK_TOKEN" -H 'Content-Type: application/json' \
    -d "$(printf '{"config":%s,"method":"%s","path":"%s","headers":{"authorization":"Bearer %s","content-type":"application/json"},"body":"%s"}' \
      "$cfg" "$method" "$path" "$(jwt "$human" agent-1)" "$esc_body")" | pretty
}

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '  %-58s ' "$1"; }

say "0. What the metadata says"
echo "  the good PDP's metadata:      $(curl -s "http://${PEP_HOST}:9002/.well-known/authzen-configuration")"
echo "  the rogue PDP's metadata:     $(curl -s "http://${PEP_HOST}:9003/.well-known/authzen-configuration")"
echo "  plain resource (RFC 9728):    $(curl -s "http://${PEP_HOST}:9004/.well-known/oauth-protected-resource")"
echo "  impostor resource (RFC 9728): $(curl -s "http://${PEP_HOST}:9005/.well-known/oauth-protected-resource")"
echo "  member's OWN well-known:      $(curl -s "http://${PEP_HOST}:9001/.well-known/oauth-protected-resource")"
echo "  member's entity configuration is a signed JWT; the anchor's policy for it is:"
echo '      {"oauth_resource":{"authzen_policy_decision_points":{"subset_of":["'"$GOOD"'"],"essential":true}}}'

say "1. pep-static: told where the PDP is, no discovery (today's behaviour)"
step "alice reads a balance"; check "$STATIC" "" alice GET /accounts/a1/balance
step "mallory reads a balance"; check "$STATIC" "" mallory GET /accounts/a1/balance

say "2. pep-resource: each resource's own well-known names its PDP"
step "plain resource -> good PDP: alice"; check "$RESOURCE" "$PLAIN" alice GET /accounts/a1/balance
step "plain resource -> good PDP: mallory"; check "$RESOURCE" "$PLAIN" mallory GET /accounts/a1/balance
step "IMPOSTOR resource -> ROGUE PDP: mallory (!)"; check "$RESOURCE" "$IMPOSTOR" mallory GET /accounts/a1/balance
echo "  ^ a self-asserted document cannot protect the thing it asserts: the resource chose its own judge."

say "3. pep-federation: the federation's word, never the resource's own"
step "impostor is not a member -> static (good) PDP: mallory"; check "$FEDERATION" "$IMPOSTOR" mallory GET /accounts/a1/balance
step "member names [rogue, good]; policy keeps good: mallory"; check "$FEDERATION" "$MEMBER" mallory GET /accounts/a1/balance
step "member: alice"; check "$FEDERATION" "$MEMBER" alice GET /accounts/a1/balance
step "broken chain -> 503, never falls to static"; check "$FEDERATION" "$BROKEN" alice GET /accounts/a1/balance
step "stray (no metadata at all) -> static PDP"; check "$FEDERATION" "$STRAY" alice GET /accounts/a1/balance
echo "  ^ watch the stubs log: rogue-pdp is never consulted by pep-federation."

say "4. The challenge contract survives discovery"
step "alice pays 50"; check "$FEDERATION" "$MEMBER" alice POST /payments '{"from_account":"a1","to_account":"b2","amount":50,"currency":"AUD"}'
step "alice pays 5000 -> step-up challenge"; check "$FEDERATION" "$MEMBER" alice POST /payments '{"from_account":"a1","to_account":"b2","amount":5000,"currency":"AUD"}'

if curl -s -o /dev/null -w '%{http_code}' "http://${PEP_HOST}:8000/bank/accounts/a1/balance" 2>/dev/null | grep -q '^[0-9]'; then
  say "5. Kong, doing the same discovery in Lua (profile kong)"
  step "alice via Kong"; curl -s -H "Authorization: Bearer $(jwt alice agent-1)" "http://${PEP_HOST}:8000/bank/accounts/a1/balance"; echo
  step "mallory via Kong"; curl -s -H "Authorization: Bearer $(jwt mallory agent-1)" "http://${PEP_HOST}:8000/bank/accounts/a1/balance"; echo
fi
echo

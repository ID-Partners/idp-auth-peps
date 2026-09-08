#!/usr/bin/env bash
# Walk through PDP discovery against the three PEPs docker-compose (or run-local.sh)
# stands up. Needs curl; uses jq or python3 to pretty-print.
#
# Nothing here turns on who the customer is: the demo is about which PDP decides, what it
# was given, and what the token carries. One subject, "customer", throughout.
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
MEMBER="$S:9001"; GOOD="$S:9002/tenants/bank-a"; ROGUE="$S:9003"; PLAIN="$S:9004"; IMPOSTOR="$S:9005"; BROKEN="$S:9006"; STRAY="$S:9007"; BANKB="$S:9009"; ESTATE="$S:9098"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
# An UNSIGNED token: coaz-pep decodes without verifying when no JWKS is configured, and
# says so loudly at startup. The demo is about discovery, not token validation.
# Shape it with CLIENT / ACR / SCOPE env: who it was issued to, how the customer
# authenticated, what it carries.
jwt() {
  local h c client="${CLIENT:-agent-1}" acr="${ACR:-urn:idp:loa:password}" scope="${SCOPE:-accounts:read payments:write}"
  h=$(printf '{"alg":"none","typ":"JWT"}' | b64url)
  c=$(printf '{"sub":"customer","client_id":"%s","act":{"sub":"%s"},"scope":"%s","acr":"%s","aud":"%s"}' "$client" "$client" "$scope" "$acr" "$PLAIN" | b64url)
  printf '%s.%s.' "$h" "$c"
}

pretty() {
  if command -v jq >/dev/null 2>&1; then
    jq -c '{decision, status: .response.status, body: ((.response.body // "") | if . == "" then null else (try fromjson catch .) end)} + (if (.response_headers // {})["X-PDP-Fail-Open"] then {failed_open: .response_headers["X-PDP-Fail-Open"]} else {} end)'
  else python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("response") or {}; b=r.get("body") or None
try: b=json.loads(b) if b else None
except Exception: pass
o={"decision": d.get("decision"), "status": r.get("status"), "body": b}
fo=(d.get("response_headers") or {}).get("X-PDP-Fail-Open")
if fo: o["failed_open"]=fo
print(json.dumps(o))'; fi
}

# check PEP RESOURCE METHOD PATH [BODY] — route knobs via FORWARD (yes|no) and LAYERS env
check() {
  local pep="$1" resource="$2" method="$3" path="$4" body="${5:-}"
  local cfg fwd layers
  fwd=$([ "${FORWARD:-yes}" = "yes" ] && printf ',"forward_access_token":"true"' || printf '')
  layers=$([ -n "${LAYERS:-}" ] && printf ',"pdp_layers":"%s"' "$LAYERS" || printf '')
  if [ -n "$resource" ]; then cfg=$(printf '{"pep_label":"demo","style":"rest","require_token":"true","resource":"%s"%s%s}' "$resource" "$fwd" "$layers")
  else cfg=$(printf '{"pep_label":"demo","style":"rest","require_token":"true"%s%s}' "$fwd" "$layers"); fi
  local esc_body; esc_body=$(printf '%s' "$body" | sed 's/"/\\"/g')
  curl -sS -X POST "$pep/v1/mcp/check" \
    -H "Authorization: Bearer $CHECK_TOKEN" -H 'Content-Type: application/json' \
    -d "$(printf '{"config":%s,"method":"%s","path":"%s","headers":{"authorization":"Bearer %s","content-type":"application/json"},"body":"%s"}' \
      "$cfg" "$method" "$path" "$(jwt)" "$esc_body")" | pretty
}

# ctl OP — a lever on the stubs (move_pdp, repoint_plain, estate_down, estate_up, reset)
ctl() {
  curl -sS -o /dev/null -X POST -H 'Content-Type: application/json' -d "{\"op\":\"$1\"}" "http://${PEP_HOST}:${CONTROL_PORT:-9099}/control"
}

PAY50='{"from_account":"a1","to_account":"b2","amount":50,"currency":"AUD"}'
PAY500='{"from_account":"a1","to_account":"b2","amount":500,"currency":"AUD"}'
PAY5000='{"from_account":"a1","to_account":"b2","amount":5000,"currency":"AUD"}'

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '  %-62s ' "$1"; }

say "0. What the metadata says"
echo "  Bank A's PDP:        $(curl -s "http://${PEP_HOST}:9002/.well-known/authzen-configuration/tenants/bank-a")"
echo "  Bank B's PDP:        $(curl -s "http://${PEP_HOST}:9008/.well-known/authzen-configuration/tenants/bank-b")"
echo "  the estate PDP:      $(curl -s "http://${PEP_HOST}:9098/.well-known/authzen-configuration")"
echo "  the rogue PDP:       $(curl -s "http://${PEP_HOST}:9003/.well-known/authzen-configuration")"
echo "  plain (RFC 9728):    $(curl -s "http://${PEP_HOST}:9004/.well-known/oauth-protected-resource")"
echo "  impostor (RFC 9728): $(curl -s "http://${PEP_HOST}:9005/.well-known/oauth-protected-resource")"
echo "  member's OWN doc:    $(curl -s "http://${PEP_HOST}:9001/.well-known/oauth-protected-resource")"
echo "  member's entity configuration is a signed JWT; the anchor's policy for members is:"
echo '      {"oauth_resource":{"authzen_policy_decision_points":{"subset_of":["'"$GOOD"'"]},"acr_values_required":{"value":["urn:idp:loa:mfa"]}}}'

say "1. Where the PDP comes from, and what it was told — a read-only token trying to pay"
step "pep-static: told its PDP, reads no metadata"; SCOPE="accounts:read" check "$STATIC" "$PLAIN" POST /payments "$PAY50"
echo "  ^ permitted: the PDP was told nothing about the resource, so it had nothing to hold the scope to."
step "pep-resource: plain names Bank A's PDP, and its scopes"; SCOPE="accounts:read" check "$RESOURCE" "$PLAIN" POST /payments "$PAY50"
echo "  ^ step-up for payments:write: the PDP read the resource's scopes_supported out of what the PEP forwarded."
step "pep-resource: IMPOSTOR names the rogue PDP (!)"; SCOPE="accounts:read" check "$RESOURCE" "$IMPOSTOR" POST /payments "$PAY50"
echo "  ^ permitted by the rogue. A self-asserted document cannot protect the thing it asserts: the resource chose its own judge."
step "pep-federation: impostor is not a member -> static PDP"; SCOPE="accounts:read" check "$FEDERATION" "$IMPOSTOR" POST /payments "$PAY50"
step "pep-federation: member -> chain -> Bank A's PDP, resolved document"; SCOPE="accounts:read" check "$FEDERATION" "$MEMBER" POST /payments "$PAY50"
echo "  ^ denied on the acr the federation set, before the scope was even considered: the resolved document travelled."
step "pep-federation: broken chain -> 503, never static"; check "$FEDERATION" "$BROKEN" GET /accounts/a1/balance
step "pep-federation: stray (no metadata) -> static PDP"; check "$FEDERATION" "$STRAY" GET /accounts/a1/balance
echo "  ^ watch the stubs log: the rogue PDP is never consulted by pep-federation."

say "2. Two banks, one gateway: the resource decides whose policy applies"
echo "  (an MFA token, so only the threshold differs between the two banks)"
step "pay 500 on plain (Bank A steps up over 1000)"; ACR=urn:idp:loa:mfa check "$RESOURCE" "$PLAIN" POST /payments "$PAY500"
step "pay 500 on bank-b (Bank B steps up over 100)"; ACR=urn:idp:loa:mfa check "$RESOURCE" "$BANKB" POST /payments "$PAY500"
echo "  ^ same request, two answers. The static PEP cannot tell them apart: it has one PDP for everything."

say "3. What the resource requires is the PDP's to enforce — and the federation sets the floor"
step "bank-b requires MFA; a password token"; check "$RESOURCE" "$BANKB" GET /accounts/a1/balance
step "same, with an MFA token"; ACR=urn:idp:loa:mfa check "$RESOURCE" "$BANKB" GET /accounts/a1/balance
step "member's OWN metadata says a password is enough (resource mode)"; check "$RESOURCE" "$MEMBER" GET /accounts/a1/balance
step "the federation raised member's floor to MFA (federation mode)"; check "$FEDERATION" "$MEMBER" GET /accounts/a1/balance
echo "  ^ same PDP, same policy, same token. The PEP forwarded a different document, and said which one."
step "bank-b, MFA required, but the token is NOT forwarded"; FORWARD=no ACR=urn:idp:loa:mfa check "$RESOURCE" "$BANKB" GET /accounts/a1/balance
echo "  ^ the PDP could not examine what it was not given, and says so rather than guessing."

say "4. Layers: a generic PDP for the estate first, the resource's PDP after"
echo "  pdp_layers = $ESTATE, resource. Every layer must permit; the first that does not is the answer."
step "agent-1 pays 50 on plain: estate, then Bank A"; LAYERS="$ESTATE,resource" check "$RESOURCE" "$PLAIN" POST /payments "$PAY50"
step "agent-risky pays 50 on plain: the estate PDP stops it"; LAYERS="$ESTATE,resource" CLIENT=agent-risky check "$RESOURCE" "$PLAIN" POST /payments "$PAY50"
echo "  ^ Bank A's PDP was never asked. The generic layer is a gate; the specific one only sees what gets through."

say "5. Failing open, deliberately: the estate PDP goes down"
echo "  Closed is the default: a layer whose PDP cannot be reached denies. A layer marked fail-open is skipped instead,"
echo "  and the permit says so in X-PDP-Fail-Open. A deny is never skipped, and neither is a refusal."
ctl estate_down
step "estate DOWN, layers as before (fail-closed): 503"; LAYERS="$ESTATE,resource" check "$RESOURCE" "$PLAIN" GET /accounts/a1/balance
step "estate DOWN, estate layer marked fail-open: Bank A decides"; LAYERS="$ESTATE fail-open,resource" check "$RESOURCE" "$PLAIN" GET /accounts/a1/balance
echo "  ^ permitted by Bank A's PDP alone, and marked: failed_open names the layer that was skipped."
ctl estate_up
step "estate back up, same fail-open policy: no marker"; LAYERS="$ESTATE fail-open,resource" check "$RESOURCE" "$PLAIN" GET /accounts/a1/balance

say "6. The challenge contract survives discovery"
step "pay 50 on member (federation mode)"; ACR=urn:idp:loa:mfa check "$FEDERATION" "$MEMBER" POST /payments "$PAY50"
step "pay 5000 -> step-up challenge"; ACR=urn:idp:loa:mfa check "$FEDERATION" "$MEMBER" POST /payments "$PAY5000"

if curl -s -o /dev/null -w '%{http_code}' "http://${PEP_HOST}:8000/bank/accounts/a1/balance" 2>/dev/null | grep -q '^[0-9]'; then
  say "7. Kong, doing the same discovery in Lua (profile kong)"
  step "read a balance via Kong"; curl -s -H "Authorization: Bearer $(jwt)" "http://${PEP_HOST}:8000/bank/accounts/a1/balance"; echo
  step "read-only token pays via Kong"; curl -s -X POST -H "Authorization: Bearer $(SCOPE='accounts:read' jwt)" -H 'Content-Type: application/json' -d "$PAY50" "http://${PEP_HOST}:8000/bank/payments"; echo
fi
echo

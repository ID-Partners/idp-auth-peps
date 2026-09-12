#!/usr/bin/env sh
# The demo's PingAccess configures itself once it is up: a site for the `plain` resource
# stub, the AuthZEN rule with resource discovery, and an API application on the default
# virtual host that runs the rule on every request. Everything is one admin API call
# each, so this file doubles as the worked example of wiring the rule up by hand.
#
# It replaces the stock 81-after-start-process.sh, whose first job (accepting the EULA
# and setting the administrator password) it keeps; the rest of the stock hook is the
# data.json import and cluster set-up this demo does not use.
#
#   AUTHZEN_URL / AUTHZEN_API_KEY  the static PDP, always the fallback  (stubs:9002)
#   RESOURCE                       the identifier discovery starts from (http://stubs:9004)
#   SITE_TARGET                    where a permitted request is proxied (stubs:9004)
#   PEP_LABEL                      how this PEP names itself in challenges
set -u
# shellcheck source=/dev/null
. "${HOOKS_DIR}/pingcommon.lib.sh"

run_hook "83-change-password.sh"

authzen_url="${AUTHZEN_URL:-http://stubs:9002}"
authzen_api_key="${AUTHZEN_API_KEY:-static-pdp-key}"
resource="${RESOURCE:-http://stubs:9004}"
site_target="${SITE_TARGET:-stubs:9004}"
pep_label="${PEP_LABEL:-PingAccess (resource discovery)}"
api="https://localhost:${PA_ADMIN_PORT}/pa-admin-api/v3"
out=$(mktemp)

pa() {
    # $1 method, $2 path, $3 body (optional). Prints the HTTP status; the body is in $out.
    if test -n "${3:-}"; then
        curl --insecure --silent --write-out '%{http_code}' --output "${out}" \
            --user "${ROOT_USER}:${PING_IDENTITY_PASSWORD}" \
            --header "X-Xsrf-Header: PingAccess" --header "Content-Type: application/json" \
            --request "$1" --data "$3" "${api}$2" 2> /dev/null
    else
        curl --insecure --silent --write-out '%{http_code}' --output "${out}" \
            --user "${ROOT_USER}:${PING_IDENTITY_PASSWORD}" \
            --header "X-Xsrf-Header: PingAccess" --request "$1" "${api}$2" 2> /dev/null
    fi
}

must() {
    # $1 expected status, $2 what for; the rest is pa()'s arguments.
    _want="$1"; _what="$2"; shift 2
    _got=$(pa "$@")
    if test "${_got}" != "${_want}"; then
        echo_red "authzen demo: ${_what} failed (HTTP ${_got}):"
        cat "${out}"
        exit 81
    fi
}

# Idempotent: a restarted container keeps its configuration.
must 200 "listing applications" GET "/applications?name=bank"
if test "$(jq -r '.items | length' "${out}")" != "0"; then
    echo "authzen demo: application 'bank' already configured"
    rm -f "${out}"
    exit 0
fi

echo "authzen demo: configuring PingAccess to front ${site_target} with the AuthZEN rule"

# The site: where a permitted request goes.
must 200 "creating the site" POST /sites \
    "{\"name\":\"plain-resource\",\"targets\":[\"${site_target}\"],\"secure\":false,\"availabilityProfileId\":1}"
site_id=$(jq -r .id "${out}")

# The rule: the same knobs as demo/kong/kong.yml, spelled the same.
must 200 "creating the rule" POST /rules "{
  \"name\": \"authzen-pdp\",
  \"className\": \"com.idpartners.pa.authzen.AuthZenRule\",
  \"supportedDestinations\": [\"Site\", \"Agent\"],
  \"configuration\": {
    \"authzen_url\": \"${authzen_url}\",
    \"authzen_api_key\": \"${authzen_api_key}\",
    \"pep_label\": \"${pep_label}\",
    \"style\": \"rest\",
    \"require_token\": true,
    \"pdp_discovery\": \"resource\",
    \"resource\": \"${resource}\",
    \"pdp_discovery_insecure\": true,
    \"resource_metadata_allowlist\": [\"${resource}\"],
    \"forward_access_token\": true
  }
}"
rule_id=$(jq -r .id "${out}")

# The default virtual host `*:3000`, which a fresh PingAccess ships with.
must 200 "listing virtual hosts" GET "/virtualhosts?host=*"
vhost_id=$(jq -r '.items[] | select(.port == 3000) | .id' "${out}" | head -n 1)
if test -z "${vhost_id}"; then
    must 200 "creating the virtual host" POST /virtualhosts '{"host":"*","port":3000}'
    vhost_id=$(jq -r .id "${out}")
fi

# The application: API type, accessValidatorId 0 (PingAccess validates no token itself:
# the demo's tokens are unsigned, and the rule decodes them as Kong does), the rule as
# the whole of its API policy. Enabled explicitly: the API's default is off.
must 200 "creating the application" POST /applications "{
  \"name\": \"bank\",
  \"contextRoot\": \"/\",
  \"applicationType\": \"API\",
  \"defaultAuthType\": \"API\",
  \"destination\": \"Site\",
  \"siteId\": ${site_id},
  \"virtualHostIds\": [${vhost_id}],
  \"accessValidatorId\": 0,
  \"enabled\": true,
  \"policy\": {\"API\": [{\"type\": \"Rule\", \"id\": ${rule_id}}]}
}"
echo_green "authzen demo: PingAccess is fronting ${site_target} on :3000 (site ${site_id}, rule ${rule_id}, virtual host ${vhost_id})"
rm -f "${out}"
exit 0

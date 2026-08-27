#!/bin/sh
# Render the agentgateway config from its template (substituting upstream
# host:port pairs that differ between docker-compose and Railway), then start
# the gateway.
set -e

: "${BANK_MCP_HOST:=bank-mcp:8090}"
: "${BANK_API_HOST:=bank-api:8070}"
: "${EXTAUTHZ_HOST:=coaz-pep:9191}"

sed -e "s|__BANK_MCP_HOST__|${BANK_MCP_HOST}|g" \
    -e "s|__BANK_API_HOST__|${BANK_API_HOST}|g" \
    -e "s|__EXTAUTHZ_HOST__|${EXTAUTHZ_HOST}|g" \
    /etc/agentgateway/config.yaml.template > /etc/agentgateway/config.yaml

exec /app/agentgateway -f /etc/agentgateway/config.yaml

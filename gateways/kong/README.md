# `authzen-pdp` — Kong Gateway plugin

A Policy Enforcement Point for Kong that authorises delegated AI-agent traffic against an
AuthZEN PDP: token and actor-claim extraction (RFC 8693), DPoP sender-constraint checks
(RFC 9449), RFC 9470 step-up challenges, REST and MCP request mapping, and — for MCP tools
declaring `coaz: true` — per-tool-call authorisation under the OpenID AuthZEN MCP profile.

## Install

DB-less: mount the plugin directory and tell Kong about it.

```
# kong.conf / environment
KONG_PLUGINS=bundled,authzen-pdp
KONG_LUA_PACKAGE_PATH=/opt/?.lua;;
```

Mount `authzen-pdp/` at `/opt/kong/plugins/authzen-pdp/` (the module path Kong looks for
is `kong.plugins.authzen-pdp.handler`). Or build the rockspec.

## Configure

```yaml
plugins:
  - name: authzen-pdp
    route: bank-api
    config:
      authzen_url:     "{vault://env/authzen-url}"
      authzen_api_key: "{vault://env/authzen-api-key}"
      pep_label: "PEP#2 (Bank API edge)"
      style: rest              # rest | mcp
      require_token: true
      require_dpop: true       # enforce the cnf.jkt sender-constraint
      require_user_login: false

  - name: authzen-pdp
    route: mcp-edge
    config:
      authzen_url:     "{vault://env/authzen-url}"
      authzen_api_key: "{vault://env/authzen-api-key}"
      pep_label: "PEP#1 (MCP edge)"
      style: mcp
      require_token: true
      require_user_login: true
      # COAZ: tools/call on a coaz:true tool is authorised per its x-coaz-mapping.
      coaz_url: http://coaz-pep:9192
      mcp_upstream_url: http://bank-mcp:8090/mcp
```

`authzen_url` and `authzen_api_key` are `referenceable`, so they take Kong vault
references rather than literals.

## Why COAZ needs `coaz_url`

`coaz_url` points at the HTTP check API of the Go `coaz-pep` service in
[`../../core`](../../core). Set it together with `mcp_upstream_url` and the plugin
delegates `tools/call` to that engine, relaying its verdict — JSON-RPC error bodies
included — verbatim.

That indirection is deliberate. The profile compiles `x-coaz-mapping` leaves as CEL, and
there is no credible CEL evaluator in Lua. Reimplementing the mapping rules here would
give two implementations of one spec and a guarantee that they drift. Everything else —
claims, DPoP, challenges, REST mapping — is native Lua in `handler.lua`.

Without `coaz_url`, `style: mcp` still works: it authorises access to the MCP service on
the `initialize` handshake and lets authenticated JSON-RPC through. Per-tool-call
authorisation is what needs the engine.

## Upstream headers

On permit the plugin sets `X-Auth-Principal`, `X-Auth-Agent`, `X-Auth-Scope` and
`X-Auth-Acr` on the proxied request, so a resource server can record the delegation chain
and read the authentication context the AS asserted — rather than inferring a channel from
a username, which is how a self-registered user ends up inheriting staff authority.

## Where this came from

The current handler is the one from `idp-agentic-demo` — it moved the step-up decision
into the PDP (the policy compares the payment amount to the threshold and returns
`step_up_required` advice) instead of an amount-blind gateway rule, and it forwards `acr`.
The rockspec came from `idp-authzen-adapter-go`.

Not to be confused with `ID-Partners-AU/kong-plugin-ping-auth` — our fork of Ping's
official Kong plugin, which predates AuthZEN and MCP and is unrelated to this.

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

## `subject.identity` -> `subject.id`

AuthZEN names the subject identifier `id`; this plugin historically sent `identity`, which
no version of the spec defines. It now sends **both**, so upgrading the gateway alone
cannot break a policy still reading the old field. Once your policies read `subject.id`,
set `legacy_subject_identity: false` per route and the non-standard field goes away.

The full sequence is in [`core/README.md`](../../core/README.md#migrating-subjectidentity---subjectid).
The Go PEP moves in lockstep — two gateways sending different subject shapes to one PDP
would be worse than either shape.

## DPoP is delegated

`require_dpop` sends the proof to `coaz-pep`'s `POST /v1/dpop/verify`, which checks the
JWS **signature**, `iat` freshness and `jti` replay as well as the `cnf.jkt` / `htm` /
`ath` binding.

The plugin does not do this itself and should not: there is no usable JOSE verifier
available to it — the same reason COAZ mapping is delegated — and a local thumbprint
comparison proves nothing, because the proof carries the very JWK being compared. Anyone
who has seen one proof could mint another with the same thumbprint. That was the old
behaviour, and it made `require_dpop` look like a sender-constraint without being one.

So `coaz_url` is **required** whenever `require_dpop` is set. The schema enforces it, so
the mistake is a config-load failure rather than a per-request surprise:

```
require_dpop needs coaz_url: this plugin cannot verify a DPoP proof signature
itself, so verification is delegated to coaz-pep
```

Everything fails closed. An unreachable verifier, a non-200, an unusable body, or a
`coaz_url` that is somehow empty all deny — a route that demands sender-constrained
tokens and cannot verify them must refuse, never silently fall back to the weaker check.

Set `CHECK_API_TOKEN` on `coaz-pep` and `coaz_api_key` here; the verification endpoint is
authenticated exactly like the COAZ check endpoint.

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

## Tests

```sh
cd gateways/kong
busted --lpath="./?.lua;./?/init.lua" spec/
```

16 behavioural tests against a mocked Kong — no gateway, no database, no network. They
cover the pure helpers, the request mapping both gateways must agree on, and the decision
paths: no token, permit, deny, and PDP-unreachable (which must fail closed). See
[`spec/README.md`](../spec/README.md).

## Where this came from

The current handler is the one from `idp-agentic-demo` — it moved the step-up decision
into the PDP (the policy compares the payment amount to the threshold and returns
`step_up_required` advice) instead of an amount-blind gateway rule, and it forwards `acr`.
The rockspec came from `idp-authzen-adapter-go`.

Not to be confused with `ID-Partners-AU/kong-plugin-ping-auth` — our fork of Ping's
official Kong plugin, which predates AuthZEN and MCP and is unrelated to this.

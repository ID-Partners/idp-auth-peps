-- Config schema for the authzen-pdp Kong plugin.
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "authzen-pdp",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Base URL of the Go authzen-adapter (AuthZEN PDP in front of Ping Authorize).
          -- referenceable so it can be supplied via a {vault://env/...} reference.
          { authzen_url = { type = "string", required = true, referenceable = true } },
          -- Bearer key the adapter expects (its API_KEY env var).
          { authzen_api_key = { type = "string", required = true, referenceable = true } },
          -- Label shown in denials and the X-PDP-PEP response header, e.g. "PEP#2 (Bank API edge)".
          { pep_label = { type = "string", default = "kong-pep" } },
          -- Request-mapping style: "rest" (Resource Server) or "mcp" (MCP edge).
          { style = { type = "string", default = "rest",
                      one_of = { "rest", "mcp" } } },
          -- Reject requests that carry no readable access token.
          { require_token = { type = "boolean", default = true } },
          -- Enforce the DPoP sender-constraint binding (cnf.jkt) on the token.
          { require_dpop = { type = "boolean", default = false } },
          -- Require a logged-in end user (X-User-Token). If absent, return a
          -- 401 login-required challenge (RFC 9470 step-up) so the app logs in.
          { require_user_login = { type = "boolean", default = false } },
          -- Step-up scope: for `stepup_action`, the user's token (X-User-Token)
          -- must carry this scope; if not, return 401 insufficient_scope.
          { stepup_scope = { type = "string" } },
          { stepup_action = { type = "string", default = "make_payment" } },
          -- COAZ (OpenID AuthZEN MCP profile): base URL of the coaz-pep
          -- engine's HTTP check API. When set on an "mcp"-style route,
          -- tools/call requests are authorized per the tool's x-coaz-mapping
          -- (discovery from tools/list, CEL evaluation, JSON-RPC errors) by
          -- the shared engine — one spec implementation for every gateway.
          { coaz_url = { type = "string" } },
          -- Shared secret for the engine's HTTP check API (its CHECK_API_TOKEN).
          { coaz_api_key = { type = "string", referenceable = true } },
          -- The MCP server whose tools/list declares the x-coaz-mapping
          -- objects (reached directly by the engine for discovery).
          { mcp_upstream_url = { type = "string" } },
          -- TLS verification on the PDP and engine calls. Defaults to ON: a PEP that
          -- silently accepts any certificate has no integrity on the decision it is
          -- enforcing. Set false only for local development against self-signed certs.
          { pdp_ssl_verify = { type = "boolean", default = true } },
          -- Authorize tools that declare no x-authzen-mapping against the COAZ-MCP
          -- binding's default tools/call mapping, as it requires. Off keeps the
          -- pass-through deployed routes expect — which is NOT conformant.
          { coaz_defaults = { type = "boolean", default = false } },
          -- Also send the non-standard `subject.identity` alongside AuthZEN's
          -- `subject.id`. On by default so upgrading the gateway alone cannot break a
          -- policy still reading the old field. Set false once policies read
          -- subject.id; the field is removed in a later release.
          { legacy_subject_identity = { type = "boolean", default = true } },
        },
        -- require_dpop needs somewhere to verify the proof. This plugin cannot: there
        -- is no JOSE verifier available to it, so on its own it can compare the proof's
        -- JWK thumbprint to cnf.jkt without ever checking the proof's signature — and
        -- the proof carries that JWK, so the comparison proves nothing. Verification is
        -- delegated to coaz-pep, which means a route demanding sender-constrained
        -- tokens with no coaz_url is misconfigured. Failing at config load is far
        -- better than discovering it per request.
        entity_checks = {
          { conditional = {
              if_field = "require_dpop", if_match = { eq = true },
              then_field = "coaz_url",
              then_match = { required = true },
              then_err = "require_dpop needs coaz_url: this plugin cannot verify a DPoP proof signature itself, so verification is delegated to coaz-pep",
          } },
        },
      },
    },
  },
}

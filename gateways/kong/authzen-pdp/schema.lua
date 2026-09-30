-- Config schema for the authzen-pdp Kong plugin.
local typedefs = require "kong.db.schema.typedefs"

local function set(v) return type(v) == "string" and v ~= "" end

-- The cross-field rules. Each is a configuration a route must not run with: failing at
-- config load is far better than discovering it per request. See ../README.md.
local function validate(config)
  local delegated = set(config.coaz_url)

  -- An MCP route is decided by coaz-pep, every request of it: the JSON-RPC is parsed
  -- strictly there, and a tool call is authorised per its mapping, which needs CEL.
  if config.style == "mcp" and not delegated then
    return nil, "style=mcp needs coaz_url: every request on an MCP route is decided by coaz-pep"
  end
  -- require_dpop needs somewhere to verify the proof. This plugin cannot: there is no
  -- JOSE verifier available to it, so on its own it could only compare the proof's JWK
  -- thumbprint to cnf.jkt without checking the proof's signature — and the proof carries
  -- that JWK, so the comparison proves nothing.
  if config.require_dpop == true and not delegated then
    return nil, "require_dpop needs coaz_url: this plugin cannot verify a DPoP proof signature itself, so verification is delegated to coaz-pep"
  end
  -- The same for the user's token: its claims drive consent and step-up, so a forged one
  -- is a bypass of both.
  if config.require_user_login == true and not delegated then
    return nil, "require_user_login needs coaz_url: this plugin cannot verify X-User-Token's signature, so the route is decided by coaz-pep"
  end
  if config.user_token_subject == "pdp" and not delegated then
    return nil, "user_token_subject=pdp needs coaz_url: X-User-Token is only read, and judged, by coaz-pep"
  end
  -- What follows is a missing or weakened security setting. allow_insecure is the one
  -- explicit way past each, logged when the configuration loads.
  if config.allow_insecure == true then return true end

  -- Decided here, the route reads the access token's claims without verifying its
  -- signature. That is safe only when something in front of it did.
  if not delegated and config.access_token_verified_upstream ~= true then
    return nil, "without coaz_url this plugin reads the access token's claims unverified: set access_token_verified_upstream when an openid-connect or jwt plugin validates Authorization first, or set coaz_url so coaz-pep verifies it"
  end
  -- coaz-pep's check API relays a caller-supplied Authorization header, so it
  -- authenticates its callers (CHECK_API_TOKEN).
  if delegated and not set(config.coaz_api_key) then
    return nil, "coaz_url needs coaz_api_key: coaz-pep's check API authenticates its callers with CHECK_API_TOKEN"
  end
  -- An empty allowlist is any https PDP a resource names. With coaz_url set, discovery
  -- is coaz-pep's, under its own PDP_ALLOWLIST.
  if not delegated and (config.pdp_discovery or "off") ~= "off"
    and not (type(config.pdp_allowlist) == "table" and #config.pdp_allowlist > 0) then
    return nil, "pdp_discovery needs pdp_allowlist: without one, any https PDP a resource names would be asked"
  end
  if config.pdp_discovery_insecure == true then
    return nil, "pdp_discovery_insecure needs allow_insecure: it lets a discovered URL be plain http"
  end
  if config.pdp_ssl_verify == false then
    return nil, "pdp_ssl_verify=false needs allow_insecure: a PEP that accepts any certificate has no integrity on its decisions"
  end
  return true
end

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
          -- Bearer key the adapter expects (its API_KEY env var). Encrypted at rest where
          -- Kong has a keyring; a vault reference keeps it out of the configuration.
          { authzen_api_key = { type = "string", required = true, referenceable = true, encrypted = true } },
          -- Label shown in denials and the X-PDP-PEP response header, e.g. "PEP#2 (Bank API edge)".
          { pep_label = { type = "string", default = "kong-pep" } },
          -- Request-mapping style: "rest" (Resource Server) or "mcp" (MCP edge, which
          -- needs coaz_url).
          { style = { type = "string", default = "rest",
                      one_of = { "rest", "mcp" } } },
          -- Reject requests that carry no readable access token.
          { require_token = { type = "boolean", default = true } },
          -- Enforce the DPoP sender constraint (RFC 9449). Needs coaz_url.
          { require_dpop = { type = "boolean", default = false } },
          -- Require a logged-in end user (X-User-Token), verified by coaz-pep. Needs coaz_url.
          { require_user_login = { type = "boolean", default = false } },
          -- Step-up scope: for `stepup_action`, the user's token (X-User-Token)
          -- must carry this scope; if not, return 401 insufficient_scope.
          { stepup_scope = { type = "string" } },
          { stepup_action = { type = "string", default = "make_payment" } },
          -- coaz-pep's HTTP check API. Set, coaz-pep decides the whole request on this
          -- route — verifying the access token, X-User-Token and the DPoP proof, mapping
          -- it, finding the PDPs — and this plugin enforces the answer. Required for an
          -- mcp route, require_dpop and require_user_login.
          { coaz_url = { type = "string" } },
          -- coaz-pep's HTTP base when this route is the resource's federation face: the
          -- plugin relays the resource's entity configuration and RFC 9728 document from
          -- it, since it cannot sign either itself.
          { federation_entity_url = { type = "string" } },
          -- Shared secret for the engine's HTTP check API (its CHECK_API_TOKEN). Required
          -- with coaz_url.
          { coaz_api_key = { type = "string", referenceable = true, encrypted = true } },
          -- The MCP server whose tools/list declares the x-coaz-mapping
          -- objects (reached directly by the engine for discovery).
          { mcp_upstream_url = { type = "string" } },
          -- TLS verification on the PDP and engine calls. Defaults to ON: a PEP that
          -- silently accepts any certificate has no integrity on the decision it is
          -- enforcing. Off needs allow_insecure; against a self-signed PDP, trust its
          -- certificate with lua_ssl_trusted_certificate instead.
          { pdp_ssl_verify = { type = "boolean", default = true } },
          -- Govern every MCP method by the COAZ-MCP binding's default mappings: tools
          -- that declare no mapping, and every method that is not a tools/call. On by
          -- default; false keeps the old pass-through for methods other than tools/call,
          -- which is NOT conformant.
          { coaz_defaults = { type = "boolean", default = true } },
          -- Also send the non-standard `subject.identity` alongside AuthZEN's
          -- `subject.id`. On by default so upgrading the gateway alone cannot break a
          -- policy still reading the old field. Set false once policies read
          -- subject.id; the field is removed in a later release.
          { legacy_subject_identity = { type = "boolean", default = true } },
          -- Whose X-User-Token counts, forwarded to coaz-pep: "principal" (the default)
          -- counts only the access token's own subject's login; "pdp" also counts someone
          -- else's — a staff member approving for a customer — and the PDP, which gets
          -- user_sub, decides whether they may. Needs coaz_url.
          { user_token_subject = { type = "string", default = "principal", one_of = { "principal", "pdp" } } },
          -- Without coaz_url, the route is decided here on the access token's claims,
          -- which this plugin does not verify. Set true when an openid-connect or jwt
          -- plugin on the route validates Authorization first (it runs before this one);
          -- without it, or coaz_url, or allow_insecure, the configuration is refused.
          { access_token_verified_upstream = { type = "boolean", default = false } },
          -- The escape hatch: lets the route run with what would otherwise refuse it —
          -- unverified claims, no pdp_allowlist, no coaz_api_key, plain-http discovery,
          -- TLS verification off. For development and demos only; logged when the
          -- configuration loads.
          { allow_insecure = { type = "boolean", default = false } },
          -- The largest request body, in bytes, the plugin reads to authorise a request.
          -- A body Kong buffered to disk is read back up to this (Kong 3.9+); a larger one
          -- is refused with a 413, never authorised unread.
          { max_request_body_size = { type = "integer", default = 1048576, gt = 0 } },
          -- Timeouts, in milliseconds, on each call the plugin makes: coaz-pep's check
          -- API, each PDP layer, and each metadata document fetched or relayed. A call
          -- that times out finds its PDP unavailable, and the layer's fail_mode decides.
          { coaz_timeout_ms = { type = "integer", default = 15000, gt = 0 } },
          { pdp_timeout_ms = { type = "integer", default = 10000, gt = 0 } },
          { discovery_timeout_ms = { type = "integer", default = 5000, gt = 0 } },
          -- What one decision may take, in milliseconds, counted from when the request
          -- has been read: discovery and every layer. Each call gets its own timeout or
          -- what is left of this, whichever is less; a layer with nothing left is
          -- unavailable, and its fail_mode decides.
          { decision_deadline_ms = { type = "integer", default = 20000, gt = 0 } },
          -- PDP discovery (see ../README.md#pdp-discovery). "off" is the static PDP
          -- with the AuthZEN default paths and no metadata fetch; "authzen" reads
          -- authzen_url's .well-known/authzen-configuration; "resource" reads the
          -- route's resource's RFC 9728 metadata for the PDP that decides for it,
          -- then that PDP's metadata, falling back to authzen_url. No federation
          -- mode here: a Trust Chain cannot be validated without a JOSE verifier.
          { pdp_discovery = { type = "string", default = "off",
                              one_of = { "off", "authzen", "resource" } } },
          -- The protected resource's identifier (RFC 8707), the key discovery starts
          -- from. An mcp route without one uses mcp_upstream_url; a rest route
          -- without one uses the static PDP.
          { resource = { type = "string" } },
          -- Cache TTL, seconds, for resource and PDP metadata.
          { pdp_metadata_ttl = { type = "number", default = 300, gt = 0 } },
          -- Permitted discovered-PDP prefixes; authzen_url is always permitted. Required
          -- when pdp_discovery is on (empty would mean any https PDP a resource names).
          { pdp_allowlist = { type = "array", elements = { type = "string" } } },
          -- Permitted `resource` prefixes for metadata fetches. Empty means any.
          { resource_metadata_allowlist = { type = "array", elements = { type = "string" } } },
          -- Allow http for discovered URLs (dev only, and only with allow_insecure;
          -- authzen_url's own origin is always trusted over http).
          { pdp_discovery_insecure = { type = "boolean", default = false } },
          -- Forward the raw access token to the PDP as context.access_token, so the
          -- PDP can examine it itself: verify the signature, read cnf, score the client.
          -- Off by default: the PDP call must be TLS + authenticated before a bearer
          -- token travels over it, and that is the operator's call to make.
          { forward_access_token = { type = "boolean", default = false } },
          -- The ordered PDPs to ask, every one of which must permit: "static" (the
          -- configured authzen_url, regardless of discovery — the slot for an
          -- estate-wide PDP that judges the token and the client), "resource" (what
          -- discovery finds for this route's resource), or a PDP identifier. The first
          -- that does not permit is the answer. Default: the resource's PDP alone.
          -- Each entry may carry its own failure mode: "http://estate.example fail-open".
          { pdp_layers = { type = "array", elements = { type = "string" }, default = { "resource" } } },
          -- What a layer does when its PDP cannot be reached, unless the layer says for
          -- itself. "closed" denies the request. "open" skips the layer; if every layer
          -- was skipped the request is permitted, with X-PDP-Fail-Open naming what was
          -- skipped. A refusal (allowlist, invalid chain) never opens, and a deny is a
          -- decision, not a failure.
          { fail_mode = { type = "string", default = "closed", one_of = { "closed", "open" } } },
        },
        custom_validator = validate,
      },
    },
  },
}

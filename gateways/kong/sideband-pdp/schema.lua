-- Config schema for the sideband-pdp Kong plugin.
--
-- The first block is Ping's ping-auth plugin's configuration, same names and defaults,
-- so a route configured for that plugin ports over by changing the plugin name. What
-- follows is this repo's: PDP discovery, layers and their failure modes, and the
-- credentials a discovered PDP is called with.
local typedefs = require "kong.db.schema.typedefs"

local function set(v) return type(v) == "string" and v ~= "" end

-- A Kong vault reference ({vault://env/paz-url}): what a referenceable field holds when
-- the validator sees it, dereferenced only when the plugin runs.
local function reference(raw)
  return type(raw) == "string" and raw:match("^{vault://.+}$") ~= nil
end

local function scheme_of(raw)
  return tostring(raw or ""):lower():match("^(%a+)://[^/?#]+")
end

local function url_ok(raw)
  if reference(raw) then return true end
  local scheme = scheme_of(raw)
  return scheme == "http" or scheme == "https"
end

-- The cross-field rules. A missing or weakened security setting is a configuration
-- error; allow_insecure is the one explicit way past it, logged when the configuration
-- loads.
local function validate(config)
  if not url_ok(config.service_url) then
    return nil, "service_url must be an http or https URL with a host"
  end
  local switch = config.pdp_discovery == "federation-resolver"
  if switch and not set(config.federation_resolve_url) then
    return nil, "pdp_discovery=federation-resolver needs federation_resolve_url: the resolve endpoint whose word is taken for the resource"
  end
  if switch and not set(config.federation_trust_anchor) then
    return nil, "pdp_discovery=federation-resolver needs federation_trust_anchor: the anchor the resolver resolves under"
  end
  if config.allow_insecure == true then return true end

  if (config.pdp_discovery or "off") ~= "off"
    and not (type(config.pdp_allowlist) == "table" and #config.pdp_allowlist > 0) then
    return nil, "pdp_discovery needs pdp_allowlist: without one, any https PDP a resource or the federation names would be asked"
  end
  if config.pdp_discovery_insecure == true then
    return nil, "pdp_discovery_insecure needs allow_insecure: it lets a discovered URL be plain http"
  end
  if config.verify_service_certificate == false then
    return nil, "verify_service_certificate=false needs allow_insecure: a PEP that accepts any certificate has no integrity on its decisions"
  end
  -- The resolver's answer is taken on transport, so the transport has to be worth
  -- something.
  if switch and not reference(config.federation_resolve_url) and scheme_of(config.federation_resolve_url) ~= "https" then
    return nil, "pdp_discovery=federation-resolver needs an https federation_resolve_url: its answer is trusted on TLS alone"
  end
  return true
end

return {
  name = "sideband-pdp",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- The static PDP: PingAuthorize's base URL, without "/sideband..." in the path.
          -- With discovery on, the PDP for a resource that publishes nothing, and the one
          -- PDP that is called with shared_secret.
          { service_url = { type = "string", required = true, referenceable = true } },
          -- The Sideband API shared secret PingAuthorize expects from this PEP, and the
          -- header it expects it in. Sent to service_url only: a discovered PDP is called
          -- with what pdp_credentials names for it, or with nothing.
          { shared_secret = { type = "string", required = true, referenceable = true, encrypted = true } },
          { secret_header_name = { type = "string", required = true } },
          { connection_timeout_ms = { type = "integer", default = 10000, gt = 0 } },
          -- Timeout, in milliseconds, on each metadata document discovery fetches.
          { discovery_timeout_ms = { type = "integer", default = 5000, gt = 0 } },
          { connection_keepAlive_ms = { type = "integer", default = 60000, gt = 0 } },
          -- TLS verification on every sideband and metadata call. A PEP that accepts any
          -- certificate has no integrity on the decision it enforces. Off needs
          -- allow_insecure; PingAuthorize ships a self-signed certificate, which Kong is
          -- told to trust with lua_ssl_trusted_certificate instead.
          { verify_service_certificate = { type = "boolean", default = true } },
          { enable_debug_logging = { type = "boolean", default = false } },
          -- Forward the client's TLS certificate, as a JWK with x5c, in
          -- client_certificate — what PingAuthorize policy reads for a certificate-bound
          -- client.
          { forward_client_certificate = { type = "boolean", default = true } },
          -- Make the /sideband/response call, so policy can filter and rewrite the
          -- upstream's response. Off, the response phase does nothing. Kong buffers the
          -- whole upstream response on any route this plugin is on, on or off: that is
          -- what a response phase costs, and why this plugin is for REST routes.
          { filter_response = { type = "boolean", default = true } },
          -- The largest upstream response body, in bytes, sent to the policy provider. A
          -- larger one is withheld with a 502 rather than filtered in part or passed
          -- unfiltered. Kong has buffered it whole by then; this bounds what is re-sent.
          { max_response_body_size = { type = "integer", default = 1048576, gt = 0 } },
          -- The largest request body, in bytes, sent to the policy provider. A body Kong
          -- buffered to disk is read back up to this (Kong 3.9+); a larger one is refused
          -- with a 413, never sent without its body.
          { max_request_body_size = { type = "integer", default = 1048576, gt = 0 } },
          -- Names this PEP in its own denials and in the X-PDP-PEP response header.
          { pep_label = { type = "string", default = "kong-sideband-pep" } },
          -- PDP discovery (see ../README.md). "off" is service_url. "resource" reads the
          -- route's resource's RFC 9728 document for the PDPs that decide for it and the
          -- layers it publishes in front of them, falling back to service_url.
          -- "federation-resolver" asks a federation resolve endpoint for the resource's
          -- Resolved Metadata instead, and never the resource's own document. Its answer
          -- is taken on TLS, unverified — named apart from coaz-pep's "federation",
          -- which verifies the Trust Chain.
          { pdp_discovery = { type = "string", default = "off",
                              one_of = { "off", "resource", "federation-resolver" } } },
          -- The protected resource's identifier (RFC 8707), the key discovery starts
          -- from. A route without one uses service_url.
          { resource = { type = "string" } },
          { pdp_metadata_ttl = { type = "number", default = 300, gt = 0 } },
          -- Permitted discovered-PDP prefixes; service_url is always permitted. Required
          -- when pdp_discovery is on (empty would mean any https PDP a resource, or the
          -- federation, names).
          { pdp_allowlist = { type = "array", elements = { type = "string" } } },
          -- Permitted `resource` prefixes for metadata lookups. Empty means any.
          { resource_metadata_allowlist = { type = "array", elements = { type = "string" } } },
          -- Allow http for discovered URLs (dev only, and only with allow_insecure;
          -- service_url's own origin is always trusted over http).
          { pdp_discovery_insecure = { type = "boolean", default = false } },
          -- The escape hatch: lets the route run without a pdp_allowlist, with plain-http
          -- discovery or a plain-http resolver, or with TLS verification off. For
          -- development and demos only; logged when the configuration loads.
          { allow_insecure = { type = "boolean", default = false } },
          -- The switch to the federation's resolver: its resolve endpoint (OpenID
          -- Federation 1.0 §8.3, usually the trust anchor's; https unless allow_insecure)
          -- and the trust anchor to resolve under. The resolver's answer is taken on
          -- transport — see the README for what that means.
          { federation_resolve_url = { type = "string" } },
          { federation_trust_anchor = { type = "string" } },
          -- The ordered PDPs to ask, every one of which must permit: "static"
          -- (service_url, regardless of discovery), "resource" (what discovery finds for
          -- the route's resource, behind whatever layers its document publishes), or a
          -- PDP identifier. Each entry may carry its rules: "fail-open" or "fail-closed"
          -- for when it cannot be reached, and "request-only" to skip its
          -- /sideband/response call. The first that does not permit is the answer.
          { pdp_layers = { type = "array", elements = { type = "string" }, default = { "resource" } } },
          -- What a layer does when its PDP cannot be reached, unless the layer says for
          -- itself. "closed" denies. "open" skips the layer; if every layer was skipped
          -- the request is permitted, marked X-PDP-Fail-Open. A deny is a decision, not a
          -- failure, and never opens; nor does a refusal.
          { fail_mode = { type = "string", default = "closed", one_of = { "closed", "open" } } },
          -- The credentials a discovered PDP is called with, by identifier. PingAuthorize
          -- refuses a sideband request without its shared secret, so a discovered PDP
          -- with no entry here fails the layer — closed unless the layer opens. The header
          -- name defaults to secret_header_name.
          { pdp_credentials = { type = "array", elements = { type = "record", fields = {
              { pdp = { type = "string", required = true } },
              { shared_secret = { type = "string", required = true, referenceable = true, encrypted = true } },
              { secret_header_name = { type = "string" } },
          } } } },
        },
        custom_validator = validate,
      },
    },
  },
}

-- PDP discovery for the Kong plugins: resource -> PDP identifier -> PDP metadata ->
-- endpoints. A Lua port of core/authzen/discovery, shared by authzen-pdp and sideband-pdp
-- (which requires it under this module name, so there is one copy of these rules in Lua).
--
--   resource identifier (conf.resource, or mcp_upstream_url on an mcp route)
--     ├─ federation-resolver: what a federation resolve endpoint resolves for it — the resolver's word
--     ├─ resource:   {resource}/.well-known/oauth-protected-resource (RFC 9728) — self-asserted
--     └─ static:     conf.authzen_url                  — when the resource publishes nothing
--   PDP identifier
--     ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9)
--     └─ 404 -> {pdp}/access/v1/evaluation, the spec's default paths
--        (or no probe at all, for a caller whose protocol has no PDP metadata to read)
--
-- Two parameters are minted by this repo, in a shape valid both in an RFC 9728 document
-- and under metadata.oauth_resource in an Entity Statement, and shared with the Go PEP
-- byte for byte: `authzen_policy_decision_points`, the PDPs that decide for a resource
-- (candidates for ONE decision, first preferred), and `authzen_policy_layers`, the PDPs
-- to ask in FRONT of it, every one of which must permit.
--
-- There is no federation mode here in the Go PEP's sense: it walks the Trust Chain and
-- verifies every signature to an anchor key it holds, and a Kong plugin has no JOSE
-- verifier to do that with. The federation-resolver mode asks a federation resolve
-- endpoint (OpenID Federation 1.0 §8.3) — typically the trust anchor's — and takes the
-- resolver's answer on transport: TLS to a URL the operator configured, the resolve
-- response's signature NOT verified. That is the trust the plugin already places in its
-- static PDP, and a weaker claim, so it is named apart: the mode, and the source a PDP
-- is told the metadata came from, say federation-resolver and never federation. A route
-- that needs the stronger claim belongs behind coaz-pep.
--
-- Two rules are never relaxed: a URL outside an allowlist fails closed rather than
-- falling to a weaker source, and a discovered PDP never receives the static API key.
-- And the static PDP is where a resource that publishes nothing lands (a 404, a document
-- naming no PDP, a subject the resolver does not know), not where an outage or a document
-- that does not validate lands: those serve the last good answer for up to one more TTL,
-- and then the layer is unavailable and fails by its mode.

local http = require "resty.http"
local contract = require "kong.plugins.authzen-pdp.contract"
local cjson = contract.json

local D = {}

D.PARAM = "authzen_policy_decision_points"
D.PARAM_LAYERS = "authzen_policy_layers"
-- The source of a PDP a resource's document named in front of its own, as opposed to
-- "layer" for one the operator configured and the metadata sources for the resource's own.
D.SOURCE_PUBLISHED = "published"
D.RESOLVE_RESPONSE_TYP = "resolve-response+jwt"
-- The resolve-endpoint mode, and the source of metadata it found.
D.RESOLVER = "federation-resolver"
D.MAX_BODY = 1048576
D.MIN_REFRESH = 30

-- Error kinds. `not_allowed` is the one the chain never swallows.
local NOT_ALLOWED, INVALID, NO_METADATA, TRANSIENT = "not_allowed", "invalid", "no_metadata", "transient"

local function fail(kind, msg) return nil, { kind = kind, msg = msg } end

-- ---------- URLs ----------

local function parse_url(raw)
  if type(raw) ~= "string" then return nil end
  local scheme, host, rest = raw:match("^(%a[%w+.-]*)://([^/?#]+)(.*)$")
  if not scheme or host == "" then return nil end
  local path, query, fragment = rest, nil, nil
  local f = path:find("#", 1, true)
  if f then fragment = path:sub(f + 1); path = path:sub(1, f - 1) end
  local q = path:find("?", 1, true)
  if q then query = path:sub(q + 1); path = path:sub(1, q - 1) end
  return { scheme = scheme:lower(), host = host:lower(), path = path, query = query, fragment = fragment }
end

--- RFC 8414 / RFC 9728 / AuthZEN rule: insert /.well-known/<suffix> after the host.
function D.well_known_url(identifier, suffix)
  local u = parse_url(identifier)
  if not u then return nil, tostring(identifier) .. " is not an absolute URL" end
  if u.query or u.fragment then return nil, identifier .. " must not have a query or fragment" end
  local path = u.path:gsub("/+$", "")
  return u.scheme .. "://" .. u.host .. "/.well-known/" .. suffix .. path
end

--- Prefix allowlist that only matches at a path boundary (the same rule as the Go
--- PEP's upstreamAllowed): "https://a.example/mcp" permits ".../mcp" and ".../mcp/x",
--- never ".../mcpx".
function D.allowed(list, raw)
  if not list or #list == 0 then return true end
  local u = parse_url(raw)
  if not u then return false end
  local target = u.scheme .. "://" .. u.host .. u.path
  for _, entry in ipairs(list) do
    local e = parse_url(entry)
    if e then
      local prefix = (e.scheme .. "://" .. e.host .. e.path):gsub("/+$", "")
      if target == prefix or target:sub(1, #prefix + 1) == prefix .. "/" then return true end
    end
  end
  return false
end

local function same_origin(u, trusted)
  local t = parse_url(trusted)
  return t ~= nil and u.scheme == t.scheme and u.host == t.host
end

--- Policy check: https unless insecure or same-origin as the trusted (static) PDP,
--- then the allowlist. Returns ok, err.
function D.check_url(raw, opts)
  local u = parse_url(raw)
  if not u then return false, tostring(raw) .. " is not an absolute URL" end
  if u.scheme == "http" then
    if not (opts.insecure or same_origin(u, opts.trusted_origin)) then
      return false, raw .. " is not https"
    end
  elseif u.scheme ~= "https" then
    return false, raw .. " has scheme " .. u.scheme
  end
  if not D.allowed(opts.allowlist, raw) then return false, raw .. " is outside the allowlist" end
  return true
end

-- ---------- fetch ----------

--- GET under the policy. Returns the response (any status) | nil, err{kind,msg}.
local function do_get(url, opts, accept)
  local ok, why = D.check_url(url, opts)
  if not ok then return fail(NOT_ALLOWED, why) end
  local httpc = http.new()
  httpc:set_timeout(opts.timeout_ms or 5000)
  local res, err = httpc:request_uri(url, {
    method = "GET",
    headers = { ["Accept"] = accept },
    ssl_verify = opts.ssl_verify ~= false,
  })
  if not res then return fail(TRANSIENT, "GET " .. url .. ": " .. tostring(err)) end
  return res
end

--- GET a JSON document under the policy. Returns table | nil, err{kind,msg}.
local function get_json(url, opts)
  local res, err = do_get(url, opts, "application/json")
  if not res then return nil, err end
  if res.status == 404 then return fail(NO_METADATA, url .. " returned 404") end
  -- resty.http does not follow redirects, so a 3xx lands here: a document that tries
  -- to send the PEP elsewhere is a failure, never a hop.
  if res.status < 200 or res.status >= 300 then return fail(TRANSIENT, "GET " .. url .. " returned " .. tostring(res.status)) end
  if type(res.body) ~= "string" or #res.body > D.MAX_BODY then return fail(TRANSIENT, url .. " body is missing or too large") end
  local doc = cjson.decode(res.body)
  if type(doc) ~= "table" then return fail(INVALID, url .. " is not JSON") end
  return doc
end

-- ---------- cache ----------
-- Per worker, keyed by identifier: the documents are public, so no credential in the
-- key. Serves the last good value while a refresh fails — an outage is not a reason to
-- trust something else — throttles retries, and negatively caches a transient failure
-- so a down resource does not put a fetch in every request's path. Three things end the
-- stale value: a refusal (the resolver now says the chain is invalid, say), the value's
-- own expiry (a resolve response's exp), and one whole TTL past its own of failed
-- refreshes. Past any of them it is never served, and the layer is unavailable.

local caches = { resources = {}, federation = {}, pdps = {} }

function D._reset_cache() caches = { resources = {}, federation = {}, pdps = {} } end
function D._cache() return caches end

local function now() return ngx.now() end

local function cache_get(store, key, ttl, negative_ttl, fetch)
  local e = store[key]
  if not e then e = {}; store[key] = e end
  local t = now()
  if e.ok and ((e.hard_expiry and t >= e.hard_expiry) or (e.stale_until and t >= e.stale_until)) then
    e.ok, e.val, e.hard_expiry, e.stale_until = false, nil, nil, nil
  end
  if e.ok and t < e.expires then return e.val end
  if not e.ok and e.err and e.neg_until and t < e.neg_until then return nil, e.err end
  if e.ok and e.err and (t - (e.last_attempt or 0)) < D.MIN_REFRESH then return e.val end
  e.last_attempt = t
  local val, err = fetch(key)
  if not val then
    e.err = err
    local refused = type(err) == "table" and err.kind == NOT_ALLOWED
    if refused then
      -- A refusal is an answer, not an outage: what was trusted is trusted no longer.
      e.ok, e.val, e.neg_until = false, nil, nil
      return nil, err
    end
    if e.ok then return e.val end -- the last good value beats failing every request
    if negative_ttl and negative_ttl > 0 then e.neg_until = t + negative_ttl end
    return nil, err
  end
  e.val, e.ok, e.expires, e.err, e.neg_until = val, true, t + ttl, nil, nil
  e.stale_until = t + 2 * ttl
  e.hard_expiry = type(val) == "table" and tonumber(val.expires_at) or nil
  return val
end

-- ---------- sources ----------

local function trim_slash(s) return (s:gsub("/+$", "")) end

-- identifiers reads an array of PDP identifiers. An entry that is not one makes the
-- document invalid.
local function identifiers(raw, from)
  local out = {}
  for _, v in ipairs(raw) do
    local u = type(v) == "string" and parse_url(v) or nil
    if not u or u.query or u.fragment then
      return fail(INVALID, from .. " lists " .. tostring(v) .. ", which is not a PDP identifier")
    end
    out[#out + 1] = trim_slash(v)
  end
  return out
end

local function pdp_list(raw, from)
  if type(raw) ~= "table" then return fail(NO_METADATA, from .. " names no PDP") end
  local out, err = identifiers(raw, from)
  if not out then return nil, err end
  if #out == 0 then return fail(NO_METADATA, from .. " names no PDP") end
  return out
end

-- layer_list reads authzen_policy_layers out of a document: absent (or null) is no
-- layers; anything else that is not an array of PDP identifiers makes the document
-- invalid — a policy the PEP cannot read is not one it may quietly narrow.
local function layer_list(doc, from)
  local raw = doc[D.PARAM_LAYERS]
  if raw == nil or raw == contract.null then return {} end
  if type(raw) ~= "table" then return fail(INVALID, from .. " " .. D.PARAM_LAYERS .. " is not an array") end
  return identifiers(raw, from)
end

--- RFC 9728: the resource's own protected resource metadata. Returns
--- {pdps, layers, document, source}: the PDP list and the published layers are what this
--- module uses; the document is what the plugin forwards to the PDP verbatim. Nothing
--- here interprets scopes_supported or an acr requirement — what a resource requires is
--- policy input, and policy is the PDP's.
local function rfc9728_lookup(resource, opts)
  local wk, err = D.well_known_url(resource, "oauth-protected-resource")
  if not wk then return fail(INVALID, err) end
  -- The allowlist bounds the resource identifier, checked before this is called. The
  -- well-known URL is that identifier's own, on its origin, with the segment inserted
  -- after the host, so it would never sit under a path-bearing entry: fetch it under the
  -- rest of the policy (https unless insecure), not the allowlist again.
  local p = opts.resource_policy
  local doc, ferr = get_json(wk, { insecure = p.insecure, ssl_verify = p.ssl_verify, timeout_ms = p.timeout_ms })
  if not doc then return nil, ferr end
  -- §3.3: the echoed identifier MUST be identical, or whoever answers at that path has
  -- just named a PDP for someone else's resource.
  if doc.resource ~= resource then
    return fail(INVALID, wk .. " says resource is " .. tostring(doc.resource) .. ", expected " .. resource)
  end
  local pdps, perr = pdp_list(doc[D.PARAM], wk)
  if not pdps then return nil, perr end
  local layers, lerr = layer_list(doc, wk)
  if not layers then return nil, lerr end
  return { pdps = pdps, layers = layers, document = doc, source = "rfc9728" }
end

local function b64url_decode(s)
  s = s:gsub("-", "+"):gsub("_", "/")
  local pad = #s % 4
  if pad > 0 then s = s .. string.rep("=", 4 - pad) end
  return ngx.decode_base64(s)
end

--- jws_parts decodes a compact JWS's header and payload. It verifies nothing — see the
--- module comment for what that means and why it is acceptable here.
local function jws_parts(tok)
  if type(tok) ~= "string" then return nil end
  local h, p = tok:match("^%s*([%w%-_]+)%.([%w%-_]+)%.[%w%-_]*%s*$")
  if not h then return nil end
  local hdr = cjson.decode(b64url_decode(h) or "")
  local claims = cjson.decode(b64url_decode(p) or "")
  if type(hdr) ~= "table" or type(claims) ~= "table" then return nil end
  return hdr, claims
end

-- What a resolver's error codes (OpenID Federation 1.0 §8.9) mean to discovery. A
-- subject the resolver does not know is no metadata — the static PDP decides, as for a
-- resource outside the federation. A chain it could not validate, or a request it will
-- not take, is a refusal: a resource that claims membership and fails validation is a
-- signal, not an outage, and a misconfigured resolver is not a reason to take the
-- resource's own word instead. The resolver's own trouble is transient.
local RESOLVE_ERRORS = {
  not_found = NO_METADATA,
  invalid_trust_chain = NOT_ALLOWED, invalid_metadata = NOT_ALLOWED, invalid_subject = NOT_ALLOWED,
  invalid_trust_anchor = NOT_ALLOWED, invalid_issuer = NOT_ALLOWED, invalid_client = NOT_ALLOWED,
  invalid_request = NOT_ALLOWED, unsupported_parameter = NOT_ALLOWED,
  server_error = TRANSIENT, temporarily_unavailable = TRANSIENT,
}

--- OpenID Federation 1.0 §8.3: ask a resolve endpoint for the resource's Resolved
--- Metadata — what survived every superior's metadata_policy, signed back to the trust
--- anchor — and read the PDP parameters out of its oauth_resource metadata. The response
--- is a JWT the plugin cannot verify; what it does check is what it can: the media type's
--- typ, that the subject is the resource asked about, and that the answer has not expired.
local function federation_lookup(resource, opts)
  local f = opts.federation
  if not f.resolve_url or f.resolve_url == "" or not f.anchor or f.anchor == "" then
    return fail(NOT_ALLOWED, "federation-resolver mode needs federation_resolve_url and federation_trust_anchor")
  end
  local url = f.resolve_url .. (f.resolve_url:find("?", 1, true) and "&" or "?")
    .. "sub=" .. ngx.escape_uri(resource) .. "&anchor=" .. ngx.escape_uri(f.anchor)
  local res, err = do_get(url, opts.federation_policy, "application/resolve-response+jwt")
  if not res then return nil, err end
  local from = "resolve " .. resource
  if res.status < 200 or res.status >= 300 then
    local body = type(res.body) == "string" and cjson.decode(res.body) or nil
    local code = type(body) == "table" and type(body.error) == "string" and body.error or nil
    local desc = type(body) == "table" and type(body.error_description) == "string" and (": " .. body.error_description) or ""
    local kind = RESOLVE_ERRORS[code] or (res.status == 404 and NO_METADATA) or (res.status >= 500 and TRANSIENT) or NOT_ALLOWED
    return fail(kind, from .. ": resolver returned " .. tostring(res.status) .. (code and (" " .. code) or "") .. desc)
  end
  if type(res.body) ~= "string" or #res.body > D.MAX_BODY then return fail(TRANSIENT, from .. ": body is missing or too large") end
  local hdr, claims = jws_parts(res.body)
  if not hdr then return fail(INVALID, from .. ": response is not a compact JWS") end
  if hdr.typ ~= D.RESOLVE_RESPONSE_TYP then
    return fail(INVALID, from .. ": response typ is " .. tostring(hdr.typ) .. ", not " .. D.RESOLVE_RESPONSE_TYP)
  end
  if claims.sub ~= resource then
    return fail(NOT_ALLOWED, from .. ": resolver answered about " .. tostring(claims.sub))
  end
  if type(claims.exp) == "number" and claims.exp <= now() then
    return fail(INVALID, from .. ": resolve response expired")
  end
  local meta = type(claims.metadata) == "table" and claims.metadata.oauth_resource or nil
  if type(meta) ~= "table" then return fail(NO_METADATA, from .. ": no oauth_resource metadata") end
  from = "resolved metadata of " .. resource
  local pdps, perr = pdp_list(meta[D.PARAM], from)
  if not pdps then return nil, perr end
  local layers, lerr = layer_list(meta, from)
  if not layers then return nil, lerr end
  -- What travels to the PDP is the RESOLVED metadata: what survived every superior's
  -- policy, not what the resource wrote. It is good until the answer's exp and no
  -- longer, however long the cache TTL.
  return { pdps = pdps, layers = layers, document = meta, source = D.RESOLVER,
    expires_at = type(claims.exp) == "number" and claims.exp or nil }
end

--- AuthZEN 1.0 §9: the PDP's own metadata, or the default paths when it has none (a
--- 404). A PDP whose metadata cannot be fetched is not one without metadata: the caller's
--- cache serves the last good answer, and with none the layer is unavailable — the
--- defaults would send the evaluation somewhere the PDP may no longer answer.
local function fetch_config(pdp, opts)
  local ok, why = D.check_url(pdp, opts.pdp_policy)
  if not ok then return fail(NOT_ALLOWED, why) end
  local wk, err = D.well_known_url(pdp, "authzen-configuration")
  if not wk then return fail(INVALID, err) end
  -- The identifier has passed the allowlist; its own metadata, on its origin with the
  -- segment inserted after the host, is fetched under the rest of the policy. What the
  -- metadata advertises is checked against the allowlist below.
  local p = opts.pdp_policy
  local doc, ferr = get_json(wk, { insecure = p.insecure, trusted_origin = p.trusted_origin, ssl_verify = p.ssl_verify, timeout_ms = p.timeout_ms })
  if not doc then
    if ferr.kind == NO_METADATA then return D.default_endpoints(pdp) end
    return nil, ferr
  end
  local declared = contract.str(doc.policy_decision_point)
  if trim_slash(declared or "") ~= trim_slash(pdp) then
    return fail(INVALID, wk .. " says policy_decision_point is " .. tostring(declared) .. ", expected " .. pdp)
  end
  local evaluation = contract.str(doc.access_evaluation_endpoint)
  if not evaluation or evaluation == "" then
    return fail(INVALID, wk .. " has no access_evaluation_endpoint")
  end
  -- A null is absent: the PDP has no batch endpoint.
  local evaluations = contract.str(doc.access_evaluations_endpoint)
  for _, u in ipairs({ evaluation, evaluations }) do
    local eok, ewhy = D.check_url(u, opts.pdp_policy)
    if not eok then return fail(NOT_ALLOWED, ewhy) end
  end
  return {
    identifier = trim_slash(pdp),
    evaluation = evaluation,
    evaluations = evaluations,
    capabilities = contract.is_array(doc.capabilities) and doc.capabilities or nil,
  }
end

function D.default_endpoints(pdp)
  pdp = trim_slash(pdp)
  return { identifier = pdp, evaluation = pdp .. "/access/v1/evaluation", evaluations = pdp .. "/access/v1/evaluations" }
end

-- ---------- resolve ----------

--- The identifier discovery starts from for this route.
function D.resource_id(conf)
  if conf.resource and conf.resource ~= "" then return trim_slash(conf.resource) end
  if conf.style == "mcp" and conf.mcp_upstream_url and conf.mcp_upstream_url ~= "" then
    return conf.mcp_upstream_url
  end
  return ""
end

-- Per-call options a plugin may pass beside its configuration:
--   probe      false skips the PDP metadata probe: the identifier is the endpoint's base.
--              For a protocol that has no PDP metadata (the sideband plugin).
--   modifiers  extra layer-entry modifiers the caller understands, as
--              { ["request-only"] = "request_only" }: modifier -> the field set on the
--              layer's endpoints. Anything else unknown is still an error.
local function options(conf, opts)
  opts = opts or {}
  local static = trim_slash(conf.authzen_url or "")
  local insecure = conf.pdp_discovery_insecure == true
  local timeout = tonumber(conf.discovery_timeout_ms) or 5000
  return {
    mode = conf.pdp_discovery or "off",
    static = static,
    ttl = tonumber(conf.pdp_metadata_ttl) or 300,
    probe = opts.probe ~= false,
    modifiers = opts.modifiers,
    resource_policy = {
      insecure = insecure, trusted_origin = nil, allowlist = conf.resource_metadata_allowlist,
      ssl_verify = conf.pdp_ssl_verify, timeout_ms = timeout,
    },
    pdp_policy = {
      -- The static PDP's own origin is trusted over http; the allowlist bounds what a
      -- resource may add to it, and the static PDP is always on it.
      insecure = insecure, trusted_origin = static,
      allowlist = (conf.pdp_allowlist and #conf.pdp_allowlist > 0) and (function()
        local l = { static }
        for _, e in ipairs(conf.pdp_allowlist) do l[#l + 1] = e end
        return l
      end)() or nil,
      ssl_verify = conf.pdp_ssl_verify, timeout_ms = timeout,
    },
    federation = { resolve_url = conf.federation_resolve_url, anchor = conf.federation_trust_anchor },
    -- The resolve endpoint is configuration, not something discovered, so no allowlist
    -- bounds it; the URL policy still applies.
    federation_policy = { insecure = insecure, ssl_verify = conf.pdp_ssl_verify, timeout_ms = timeout },
  }
end

-- endpoints_of resolves one PDP identifier to its endpoints under the options: the
-- metadata probe, cached, or the defaults with no HTTP when the caller asked for none.
local function endpoints_of(pdp, o)
  local pok, pwhy = D.check_url(pdp, o.pdp_policy)
  if not pok then return fail(NOT_ALLOWED, pwhy) end
  if not o.probe then return D.default_endpoints(pdp) end
  local ep, err = cache_get(caches.pdps, pdp, o.ttl, D.MIN_REFRESH, function(key) return fetch_config(key, o) end)
  if not ep then return nil, err end
  for _, u in ipairs({ ep.evaluation, ep.evaluations }) do
    local eok, ewhy = D.check_url(u, o.pdp_policy)
    if not eok then return fail(NOT_ALLOWED, ewhy) end
  end
  -- Copy: the cached table must not carry a key, a source or a failure mode.
  return { identifier = ep.identifier, evaluation = ep.evaluation, evaluations = ep.evaluations, capabilities = ep.capabilities }
end

--- Resolve an explicitly named PDP — an operator-configured layer, or one a document
--- published. The PDP allowlist applies: a layer URL in route config is as caller-supplied
--- as anything else there, and a document is as caller-supplied as a route.
function D.resolve_pdp(conf, pdp, opts)
  local o = options(conf, opts)
  pdp = trim_slash(pdp)
  if o.mode == "off" then
    local ep = D.default_endpoints(pdp)
    ep.api_key = (pdp == o.static and conf.authzen_api_key ~= "" and conf.authzen_api_key) or nil
    ep.source = "layer"
    return ep
  end
  local ep, err = endpoints_of(pdp, o)
  if not ep then return nil, err end
  ep.source = "layer"
  ep.api_key = (ep.identifier == o.static and conf.authzen_api_key ~= "" and conf.authzen_api_key) or nil
  return ep
end

--- Parse one layer entry: a name, optionally followed by "fail-open" or "fail-closed",
--- and by any modifier the caller declared. Returns {name, fail_open = true|false|nil,
--- ...} or nil, err. An unknown modifier is an error: a policy that cannot be read must
--- not be silently narrowed.
function D.parse_layer(entry, modifiers)
  local fields = {}
  for f in tostring(entry):gmatch("%S+") do fields[#fields + 1] = f end
  if #fields == 0 then return nil, "empty layer" end
  local spec = { name = trim_slash(fields[1]) }
  if spec.name ~= "resource" and spec.name ~= "static" and not spec.name:find("://", 1, true) then
    return nil, "layer " .. spec.name .. " is neither static, resource nor a PDP identifier"
  end
  for i = 2, #fields do
    local m = fields[i]:lower()
    if m == "fail-open" then spec.fail_open = true
    elseif m == "fail-closed" then spec.fail_open = false
    elseif modifiers and modifiers[m] then spec[modifiers[m]] = true
    else return nil, "layer " .. spec.name .. ": unknown modifier " .. fields[i] end
  end
  return spec
end

--- Resolve every layer of a route's policy, in order, duplicates collapsed. Returns
--- {pdps, skipped, meta} or nil, err. A port of the Go engine's ResolveLayers: layering
--- is what lets a generic PDP that judges the token and the client sit in front of the
--- resource's own. default_open is the route's fail_mode; a layer's own setting wins.
---
--- The stack need not be configured on the route at all. When the resource layer's
--- document carries authzen_policy_layers, each PDP named there is asked, in that order,
--- in front of the resource's own: the published layers are what "resource" means. They
--- pass the same PDP allowlist as a configured entry, and they take the resource entry's
--- failure mode, never one of their own — a document may say who decides, not what
--- happens when they cannot. A configured entry and a published one that name the same
--- PDP are one call, and the configured entry's own failure mode, if it set one, wins.
---
--- A layer that cannot be resolved fails the request unless it is fail-open, in which
--- case it is skipped and named. A refusal is never skipped.
function D.resolve_layers(conf, resource, layers, default_open, opts)
  if not layers or #layers == 0 then layers = { "resource" } end
  local o = options(conf, opts)
  local out, seen, explicit, skipped = {}, {}, {}, {}
  local function add(ep, spec, open, own)
    ep.fail_open = open
    if o.modifiers then
      for _, field in pairs(o.modifiers) do ep[field] = spec[field] or nil end
    end
    local at = seen[ep.identifier]
    if at then
      -- The same PDP twice is one call. Keep the resource metadata if this occurrence
      -- carried it and the earlier one did not. On the failure mode, an entry's own
      -- setting beats an inherited default; between two of a kind the stricter wins.
      local have = out[at]
      if not have.resource and ep.resource then have.resource = ep.resource end
      local had_own = explicit[ep.identifier] or false
      if own and not had_own then have.fail_open = open
      elseif own == had_own then have.fail_open = have.fail_open and open end
      explicit[ep.identifier] = had_own or own
      if o.modifiers then
        for _, field in pairs(o.modifiers) do have[field] = have[field] or ep[field] end
      end
      return
    end
    seen[ep.identifier] = #out + 1
    explicit[ep.identifier] = own
    out[#out + 1] = ep
  end
  for _, entry in ipairs(layers) do
    local spec, perr = D.parse_layer(entry, o.modifiers)
    if not spec then return fail(INVALID, perr) end
    local open, own = default_open == true, spec.fail_open ~= nil
    if own then open = spec.fail_open end
    local ep, err
    if spec.name == "resource" then ep, err = D.resolve(conf, resource, opts)
    elseif spec.name == "static" then ep, err = D.resolve(conf, "", opts)
    else ep, err = D.resolve_pdp(conf, spec.name, opts) end
    if not ep then
      if err.kind == NOT_ALLOWED or not open then
        return nil, { kind = err.kind, msg = "layer " .. spec.name .. ": " .. err.msg }
      end
      -- The skipped list is what a client is shown (X-PDP-Fail-Open): identifiers only.
      -- Why a layer was skipped is for the log.
      kong.log.warn("pdp discovery: layer ", spec.name, " could not be resolved (", err.msg, "); skipped (fail-open)")
      skipped[#skipped + 1] = spec.name
    else
      if spec.name == "resource" and ep.resource and ep.resource.layers then
        -- What the document put in front of its PDP, in the document's order.
        for _, pdp in ipairs(ep.resource.layers) do
          local gate, gerr = D.resolve_pdp(conf, pdp, opts)
          if not gate then
            if gerr.kind == NOT_ALLOWED or not open then
              return nil, { kind = gerr.kind, msg = "layer resource: " .. resource .. " published layer " .. pdp .. ": " .. gerr.msg }
            end
            kong.log.warn("pdp discovery: layer ", pdp, " published by ", resource, " could not be resolved (", gerr.msg, "); skipped (fail-open)")
            skipped[#skipped + 1] = pdp
          else
            gate.source = D.SOURCE_PUBLISHED
            add(gate, {}, open, false)
          end
        end
      end
      add(ep, spec, open, own)
    end
  end
  local meta
  for _, ep in ipairs(out) do
    if ep.resource then meta = ep.resource; break end
  end
  return { pdps = out, skipped = skipped, meta = meta }
end

--- Resolve the PDP endpoints for `resource` under `conf`. Returns
--- ep{identifier, evaluation, evaluations, api_key, source, resource} | nil, err{kind,msg}.
--- ep.resource is {source, document, layers}: the resource's metadata as published, when a
--- document named the PDP. The plugin forwards it to the PDP and reads nothing from it
--- but the two PDP parameters.
function D.resolve(conf, resource, opts)
  local o = options(conf, opts)
  local mode = o.mode
  local function with_key(ep, source)
    ep.api_key = (ep.identifier == o.static and conf.authzen_api_key ~= "" and conf.authzen_api_key) or nil
    ep.source = ep.source or source
    return ep
  end

  if mode == "off" then
    if o.static == "" then return fail(TRANSIENT, "no PDP configured") end
    return with_key(D.default_endpoints(o.static), "static")
  end

  local candidates
  local from -- the resource's metadata, when a document named the PDP
  if resource == nil or resource == "" or mode == "authzen" then
    if o.static == "" then return fail(TRANSIENT, "no PDP configured") end
    candidates = { o.static }
  else
    -- Checked here as well as at fetch time: a cached list may have been fetched under
    -- another route's allowlist.
    local rok, rwhy = D.check_url(resource, o.resource_policy)
    if not rok then return fail(NOT_ALLOWED, rwhy) end
    -- One store per source: a route trusting the federation and one trusting the
    -- resource's own word must not share an answer.
    local store = mode == D.RESOLVER and caches.federation or caches.resources
    local meta, err = cache_get(store, resource, o.ttl, D.MIN_REFRESH, function()
      local found, perr
      if mode == D.RESOLVER then found, perr = federation_lookup(resource, o)
      else found, perr = rfc9728_lookup(resource, o) end
      if found then return found end
      -- Only "publishes nothing" is an answer the static PDP takes. An outage or a
      -- document that does not validate stays a failure, so the last good answer is
      -- served or, with none, the layer fails under its own rule.
      if perr.kind ~= NO_METADATA or o.static == "" then return nil, perr end
      return { pdps = { o.static } }
    end)
    if not meta then
      if err.kind == NOT_ALLOWED then return nil, err end
      if err.kind == NO_METADATA then
        return fail(TRANSIENT, "no PDP could be resolved for " .. resource .. ": " .. err.msg)
      end
      -- Nothing cached to serve. Standing the static PDP in here would let whoever can
      -- take a resource's metadata down choose its judge, and quietly drop whatever the
      -- resource puts in front of its own.
      return fail(TRANSIENT, "the metadata for " .. resource .. " is unavailable and none is cached: " .. err.msg)
    end
    candidates = meta.pdps
    if meta.document then from = { source = meta.source, document = meta.document, layers = meta.layers } end
  end

  local last
  for _, pdp in ipairs(candidates) do
    local ep, err = endpoints_of(pdp, o)
    if ep then
      ep.resource = from
      return with_key(ep, (pdp == o.static and "static") or (from and from.source) or "static")
    end
    if err.kind == NOT_ALLOWED then return nil, err end
    kong.log.warn("pdp discovery: ", pdp, ": ", err.msg)
    last = err
  end
  return fail(TRANSIENT, "no PDP could be resolved" .. (last and (": " .. last.msg) or ""))
end

D._TEST = { parse_url = parse_url, get_json = get_json, cache_get = cache_get, fetch_config = fetch_config,
  rfc9728_lookup = rfc9728_lookup, federation_lookup = federation_lookup, jws_parts = jws_parts,
  layer_list = layer_list, options = options }

return D

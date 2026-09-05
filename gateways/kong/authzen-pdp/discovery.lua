-- PDP discovery for the authzen-pdp Kong plugin: resource -> PDP identifier -> PDP
-- metadata -> evaluation endpoint. A Lua port of core/authzen/discovery, minus the
-- federation branch: there is no JOSE verifier available to a Kong plugin, so a Trust
-- Chain cannot be validated here. Routes that need federation delegate to coaz-pep.
--
--   resource identifier (conf.resource, or mcp_upstream_url on an mcp route)
--     ├─ resource: {resource}/.well-known/oauth-protected-resource (RFC 9728) — self-asserted
--     └─ static:   conf.authzen_url                                          — the fallback
--   PDP identifier
--     ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9)
--     └─ 404 / unreachable -> {pdp}/access/v1/evaluation, the spec's default paths
--
-- The parameter naming the PDPs, `authzen_policy_decision_points`, is minted by this
-- repo (no spec defines one) and shared with the Go PEP byte for byte.
--
-- Two rules are never relaxed: a URL outside an allowlist fails closed rather than
-- falling to a weaker source, and a discovered PDP never receives the static API key.

local http = require "resty.http"
local cjson = require "cjson.safe"

local D = {}

D.PARAM = "authzen_policy_decision_points"
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

--- GET a JSON document under the policy. Returns table | nil, err{kind,msg}.
local function get_json(url, opts)
  local ok, why = D.check_url(url, opts)
  if not ok then return fail(NOT_ALLOWED, why) end
  local httpc = http.new()
  httpc:set_timeout(opts.timeout_ms or 5000)
  local res, err = httpc:request_uri(url, {
    method = "GET",
    headers = { ["Accept"] = "application/json" },
    ssl_verify = opts.ssl_verify ~= false,
  })
  if not res then return fail(TRANSIENT, "GET " .. url .. ": " .. tostring(err)) end
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
-- key. Serves stale while a refresh fails, throttles retries, and negatively caches a
-- transient failure so a down resource does not put a fetch in every request's path.

local caches = { resources = {}, pdps = {} }

function D._reset_cache() caches = { resources = {}, pdps = {} } end
function D._cache() return caches end

local function now() return ngx.now() end

local function cache_get(store, key, ttl, negative_ttl, fetch)
  local e = store[key]
  if not e then e = {}; store[key] = e end
  local t = now()
  if e.ok and t < e.expires then return e.val end
  if not e.ok and e.err and e.neg_until and t < e.neg_until then return nil, e.err end
  if e.ok and e.err and (t - (e.last_attempt or 0)) < D.MIN_REFRESH then return e.val end
  e.last_attempt = t
  local val, err = fetch(key)
  if not val then
    e.err = err
    if e.ok then return e.val end -- stale beats failing every request
    -- A policy refusal cost no fetch and belongs to one route's allowlist; another
    -- route sharing this worker must not inherit it.
    if negative_ttl and negative_ttl > 0 and not (type(err) == "table" and err.kind == NOT_ALLOWED) then
      e.neg_until = t + negative_ttl
    end
    return nil, err
  end
  e.val, e.ok, e.expires, e.err, e.neg_until = val, true, t + ttl, nil, nil
  return val
end

-- ---------- sources ----------

local function trim_slash(s) return (s:gsub("/+$", "")) end

local function pdp_list(raw, from)
  if type(raw) ~= "table" then return fail(NO_METADATA, from .. " names no PDP") end
  local out = {}
  for _, v in ipairs(raw) do
    local u = type(v) == "string" and parse_url(v) or nil
    if not u or u.query or u.fragment then
      return fail(INVALID, from .. " lists " .. tostring(v) .. ", which is not a PDP identifier")
    end
    out[#out + 1] = trim_slash(v)
  end
  if #out == 0 then return fail(NO_METADATA, from .. " names no PDP") end
  return out
end

--- RFC 9728: the resource's own protected resource metadata.
local function rfc9728_pdps(resource, opts)
  local wk, err = D.well_known_url(resource, "oauth-protected-resource")
  if not wk then return fail(INVALID, err) end
  local doc, ferr = get_json(wk, opts.resource_policy)
  if not doc then return nil, ferr end
  -- §3.3: the echoed identifier MUST be identical, or whoever answers at that path has
  -- just named a PDP for someone else's resource.
  if doc.resource ~= resource then
    return fail(INVALID, wk .. " says resource is " .. tostring(doc.resource) .. ", expected " .. resource)
  end
  return pdp_list(doc[D.PARAM], wk)
end

--- AuthZEN 1.0 §9: the PDP's own metadata, or the default paths when it has none.
local function fetch_config(pdp, opts)
  local ok, why = D.check_url(pdp, opts.pdp_policy)
  if not ok then return fail(NOT_ALLOWED, why) end
  local wk, err = D.well_known_url(pdp, "authzen-configuration")
  if not wk then return fail(INVALID, err) end
  local doc, ferr = get_json(wk, opts.pdp_policy)
  if not doc then
    if ferr.kind == NOT_ALLOWED or ferr.kind == INVALID then return nil, ferr end
    if ferr.kind ~= NO_METADATA then kong.log.warn("pdp discovery: ", ferr.msg, "; using default AuthZEN paths") end
    return D.default_endpoints(pdp)
  end
  if trim_slash(tostring(doc.policy_decision_point or "")) ~= trim_slash(pdp) then
    return fail(INVALID, wk .. " says policy_decision_point is " .. tostring(doc.policy_decision_point) .. ", expected " .. pdp)
  end
  if type(doc.access_evaluation_endpoint) ~= "string" or doc.access_evaluation_endpoint == "" then
    return fail(INVALID, wk .. " has no access_evaluation_endpoint")
  end
  for _, u in ipairs({ doc.access_evaluation_endpoint, doc.access_evaluations_endpoint }) do
    local eok, ewhy = D.check_url(u, opts.pdp_policy)
    if not eok then return fail(NOT_ALLOWED, ewhy) end
  end
  return {
    identifier = trim_slash(pdp),
    evaluation = doc.access_evaluation_endpoint,
    evaluations = doc.access_evaluations_endpoint,
    capabilities = doc.capabilities,
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

local function options(conf)
  local static = trim_slash(conf.authzen_url or "")
  local insecure = conf.pdp_discovery_insecure == true
  return {
    static = static,
    ttl = tonumber(conf.pdp_metadata_ttl) or 300,
    resource_policy = {
      insecure = insecure, trusted_origin = nil, allowlist = conf.resource_metadata_allowlist,
      ssl_verify = conf.pdp_ssl_verify, timeout_ms = 5000,
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
      ssl_verify = conf.pdp_ssl_verify, timeout_ms = 5000,
    },
  }
end

--- Resolve the PDP endpoints for `resource` under `conf`. Returns
--- ep{identifier, evaluation, evaluations, api_key, source} | nil, err{kind,msg}.
function D.resolve(conf, resource)
  local mode = conf.pdp_discovery or "off"
  local o = options(conf)
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
  if resource == nil or resource == "" or mode == "authzen" then
    if o.static == "" then return fail(TRANSIENT, "no PDP configured") end
    candidates = { o.static }
  else
    -- Checked here as well as at fetch time: a cached list may have been fetched under
    -- another route's allowlist.
    local rok, rwhy = D.check_url(resource, o.resource_policy)
    if not rok then return fail(NOT_ALLOWED, rwhy) end
    local list, err = cache_get(caches.resources, resource, o.ttl, D.MIN_REFRESH, function(key)
      local pdps, perr = rfc9728_pdps(key, o)
      if pdps then return pdps end
      if perr.kind == NOT_ALLOWED or perr.kind == TRANSIENT then return nil, perr end
      if perr.kind == INVALID then kong.log.warn("pdp discovery: ", perr.msg) end
      if o.static == "" then return nil, perr end
      return { o.static }
    end)
    if not list then
      if err.kind == NOT_ALLOWED then return nil, err end
      if o.static == "" then return fail(TRANSIENT, "no PDP could be resolved for " .. resource .. ": " .. err.msg) end
      kong.log.warn("pdp discovery: ", err.msg, "; using the static PDP")
      list = { o.static }
    end
    candidates = list
  end

  local last
  for _, pdp in ipairs(candidates) do
    local pok, pwhy = D.check_url(pdp, o.pdp_policy)
    if not pok then return fail(NOT_ALLOWED, pwhy) end
    local ep, err = cache_get(caches.pdps, pdp, o.ttl, nil, function(key) return fetch_config(key, o) end)
    if ep then
      for _, u in ipairs({ ep.evaluation, ep.evaluations }) do
        local eok, ewhy = D.check_url(u, o.pdp_policy)
        if not eok then return fail(NOT_ALLOWED, ewhy) end
      end
      -- Copy: the cached table must not carry a key or a source.
      return with_key({ identifier = ep.identifier, evaluation = ep.evaluation, evaluations = ep.evaluations,
        capabilities = ep.capabilities }, pdp == o.static and "static" or "rfc9728")
    end
    if err.kind == NOT_ALLOWED then return nil, err end
    kong.log.warn("pdp discovery: ", pdp, ": ", err.msg)
    last = err
  end
  return fail(TRANSIENT, "no PDP could be resolved" .. (last and (": " .. last.msg) or ""))
end

D._TEST = { parse_url = parse_url, get_json = get_json, cache_get = cache_get, fetch_config = fetch_config, rfc9728_pdps = rfc9728_pdps, options = options }

return D

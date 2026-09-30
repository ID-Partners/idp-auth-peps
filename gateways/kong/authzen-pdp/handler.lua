-- authzen-pdp: a Kong Policy Enforcement Point (PEP) that calls the AuthZEN PDP.
--
-- A route is decided one of two ways.
--
-- With coaz_url set, coaz-pep decides the whole request. The plugin sends it the
-- request (method, path, the headers it verifies, the body) and the route's knobs over
-- coaz-pep's check API (POST /v1/mcp/check) and enforces the answer: a permit sets the
-- upstream identity headers coaz-pep returns, a deny is relayed verbatim. coaz-pep
-- verifies the access token, X-User-Token and the DPoP proof, maps the request, finds
-- the PDPs and asks them. This plugin cannot do the first three itself — there is no
-- usable JOSE verifier available to a Kong plugin — so require_dpop, require_user_login
-- and every MCP route need coaz_url, and the schema says so. On an MCP route every
-- request goes, whatever its JSON-RPC method, after the body has been read in full and
-- parsed strictly here: a body this plugin cannot read, or one that is not exactly one
-- JSON-RPC object, is refused before anything is asked.
--
-- Without coaz_url the route is decided here, natively, for REST:
--   1. read the access token's claims (sub = principal, act.sub = acting agent, scope,
--      acr). The plugin does not verify the token's signature, so it reads the claims
--      only when the route declares access_token_verified_upstream — an openid-connect or
--      jwt plugin validated Authorization first — or allow_insecure. X-User-Token is
--      never read here;
--   2. map the request to an AuthZEN evaluation (subject = the agent on behalf of the
--      principal, action + resource + context from the HTTP request);
--   3. find the PDPs (discovery.lua) and ask each layer in order;
--   4. PERMIT -> forward, with X-Auth-Principal / X-Auth-Agent / X-Auth-Scope /
--      X-Auth-Acr for the resource server's audit trail;
--      DENY   -> 403 with the policy reason, or the challenge the policy's advice asks for.

local http = require "resty.http"
local discovery = require "kong.plugins.authzen-pdp.discovery"
local contract = require "kong.plugins.authzen-pdp.contract"
local cjson = contract.json

local AuthzenPDP = {
  PRIORITY = 1000,  -- after Kong's authentication plugins; see ../README.md#plugin-order
  -- 0.4.0: coaz-pep decides the whole request when coaz_url is set; strict MCP parsing;
  -- fail-open on unavailability only. 0.3.0: PDP discovery. 0.2.0: COAZ via coaz-pep.
  VERSION = "0.4.1",
}

-- The identity headers this plugin asserts to the upstream. Whatever a client sent under
-- these names is removed before anything else happens.
local AUTH_HEADERS = { "X-Auth-Principal", "X-Auth-Agent", "X-Auth-Scope", "X-Auth-Acr" }

-- What coaz-pep is given of the request's headers: the two tokens and the proof it
-- verifies, and what the body is. Each must arrive at most once — a repeated one would
-- be read one way here and perhaps another upstream.
local FORWARDED = { "authorization", "x-user-token", "dpop", "content-type", "content-encoding" }
local MAX_HEADERS = 1000

local function set(v) return type(v) == "string" and v ~= "" end

-- ---------- helpers ----------

local function b64url_decode(str)
  if not str or str == "" then return nil end
  str = str:gsub("-", "+"):gsub("_", "/")
  local pad = #str % 4
  if pad > 0 then str = str .. string.rep("=", 4 - pad) end
  return ngx.decode_base64(str)
end

-- decode the payload (claims) of a compact JWT; returns a table or nil
local function jwt_claims(token)
  if not token then return nil end
  local dot1 = token:find("%.")
  if not dot1 then return nil end
  local dot2 = token:find("%.", dot1 + 1)
  if not dot2 then return nil end
  local payload = b64url_decode(token:sub(dot1 + 1, dot2 - 1))
  if not payload then return nil end
  local claims = cjson.decode(payload)
  if not contract.is_object(claims) then return nil end
  return claims
end

-- extract the access token from Authorization: "DPoP <t>" or "Bearer <t>"
local function extract_token(auth_header)
  if not auth_header then return nil, nil end
  local scheme, token = auth_header:match("^(%a+)%s+(.+)$")
  if not scheme then return nil, nil end
  return token, scheme:lower()
end

-- Every denial this plugin makes is marked as one (header_filter adds X-PDP-*).
local function deny(pep, status, reason, headers)
  kong.ctx.plugin.pep, kong.ctx.plugin.decision = pep, "DENY"
  local h = { ["Content-Type"] = "application/json" }
  for k, v in pairs(headers or {}) do h[k] = v end
  return kong.response.exit(status, {
    error = "authorization_failed",
    pep = pep,
    reason = reason,
  }, h)
end

-- The request's headers, capped, with the ones this plugin reads checked for repeats.
-- Returns the headers or nil, a status and a reason.
local function request_headers()
  local headers, err = kong.request.get_headers(MAX_HEADERS)
  if err == "truncated" then
    return nil, 431, "The request carries more headers than the gateway will authorise."
  end
  for _, name in ipairs(FORWARDED) do
    if type(headers[name]) == "table" then
      return nil, 400, "The request repeats its " .. name .. " header."
    end
  end
  return headers
end

-- ---------- MCP: one JSON-RPC object, positively understood ----------

-- A JSON-RPC error for a body this plugin will not pass on (contract section 1).
local function rpc_refusal(pep, status, code, message, id)
  kong.ctx.plugin.pep, kong.ctx.plugin.decision = pep, "DENY"
  return kong.response.exit(status, {
    jsonrpc = "2.0",
    id = id == nil and cjson.null or id,
    error = { code = code, message = message },
  }, { ["Content-Type"] = "application/json", ["X-PDP-Decision"] = "DENY" })
end

-- Two members whose names differ only in case: the one a case-insensitive parser reads
-- is not necessarily the one an exact one does, so a PDP could be asked about one tool
-- while another runs.
local function case_collision(obj)
  local seen = {}
  for k in pairs(obj) do
    if type(k) == "string" then
      local lower = k:lower()
      if seen[lower] then return true end
      seen[lower] = true
    end
  end
  return false
end

--- Why an MCP POST body is not one JSON-RPC object this plugin understands, or nil.
--- Returns status, JSON-RPC code, message, id.
local function mcp_body_refusal(body)
  if body:sub(1, 3) == "\239\187\191" or not contract.valid_utf8(body) then
    return 400, -32700, "Parse error"
  end
  local rpc = cjson.decode(body)
  if rpc == nil then return 400, -32700, "Parse error" end
  if contract.is_array(rpc) or body:match("^%s*%[") then
    return 400, -32600, "Invalid Request: batch requests are not supported"
  end
  if not contract.is_object(rpc) then
    return 400, -32600, "Invalid Request: the body is not a JSON-RPC object"
  end
  -- The id is echoed in a refusal only when it can be: a string, or a finite number
  -- (1e999 decodes to infinity, which no JSON encoder will write back).
  local id = rpc.id
  if type(id) == "number" and (id ~= id or id == math.huge or id == -math.huge) then id = nil end
  if type(id) ~= "string" and type(id) ~= "number" then id = nil end
  local params = rpc.params
  if case_collision(rpc) or (contract.is_object(params) and case_collision(params)) then
    return 400, -32600, "Invalid Request: member names differ only in case", id
  end
  if rpc.method == nil then
    -- A client's answer to a server-initiated request: an id, and exactly one of
    -- result and error.
    if rpc.id ~= nil and ((rpc.result ~= nil) ~= (rpc.error ~= nil)) then return nil end
    return 400, -32600, "Invalid Request: neither a request nor a response", id
  end
  if type(rpc.method) ~= "string" then
    return 400, -32600, "Invalid Request: method is not a string", id
  end
  if rpc.method == "tools/call" then
    local name = contract.is_object(params) and params.name or nil
    if not set(name) then
      return 400, -32600, "Invalid Request: tools/call without a tool name", id
    end
  end
  return nil
end

-- ---------- delegation to coaz-pep ----------

local function flag(v) return v == true and "true" or "false" end

-- The route's knobs, as coaz-pep's check API reads them: strings, as ext_authz
-- context_extensions carry them.
local function check_config(conf, pep)
  return {
    pep_label = pep,
    style = conf.style or "rest",
    require_token = flag(conf.require_token),
    require_dpop = flag(conf.require_dpop),
    require_user_login = flag(conf.require_user_login),
    stepup_scope = contract.str(conf.stepup_scope),
    stepup_action = contract.str(conf.stepup_action),
    mcp_upstream_url = set(conf.mcp_upstream_url) and conf.mcp_upstream_url or nil,
    -- Default mappings are on: only an explicit false opts out.
    coaz_defaults = conf.coaz_defaults == false and "false" or "true",
    legacy_subject_identity = conf.legacy_subject_identity == false and "false" or "true",
    user_token_subject = conf.user_token_subject == "pdp" and "pdp" or "principal",
    -- coaz-pep runs its own PDP discovery (federation included); an explicit resource is
    -- passed so both PEPs key off the same identifier.
    resource = set(conf.resource) and (conf.resource:gsub("/+$", "")) or nil,
    forward_access_token = flag(conf.forward_access_token),
    pdp_layers = type(conf.pdp_layers) == "table" and #conf.pdp_layers > 0 and table.concat(conf.pdp_layers, ",") or nil,
    -- Always sent: a route that says nothing is closed, whatever coaz-pep's own default.
    fail_mode = contract.str(conf.fail_mode) or "closed",
  }
end

local function delegate(conf, pep)
  local c = kong.ctx.plugin
  c.pep = pep
  local headers, hstatus, hreason = request_headers()
  if not headers then
    return deny(pep, hstatus, hreason)
  end
  local method = kong.request.get_method()
  local mcp = conf.style == "mcp"

  if mcp then
    local enc = headers["content-encoding"]
    if enc ~= nil and not enc:lower():match("^%s*identity%s*$") then
      return rpc_refusal(pep, 415, -32600, "Invalid Request: Content-Encoding not supported by the PEP")
    end
  end
  local body, berr = contract.read_body(conf.max_request_body_size)
  if not body then
    kong.log.err("the request body could not be read in full (", berr, "); refusing it")
    if mcp then
      return rpc_refusal(pep, 413, -32600, "Invalid Request: request body too large for the PEP to authorise")
    end
    return deny(pep, 413, "The request body is too large for the gateway to authorise.")
  end
  if mcp then
    if method == "POST" then
      local status, code, message, id = mcp_body_refusal(body)
      if status then return rpc_refusal(pep, status, code, message, id) end
    elseif body ~= "" then
      return rpc_refusal(pep, 400, -32600, "Invalid Request: a body on a " .. method .. " request")
    end
  end

  local fwd = {}
  for _, name in ipairs(FORWARDED) do fwd[name] = headers[name] end
  -- Strings and flags only, so this always encodes.
  local payload = cjson.encode({
    config = check_config(conf, pep),
    method = method,
    path = kong.request.get_path(),
    headers = fwd,
    body = body,
  })

  local httpc = http.new()
  httpc:set_timeout(15000)
  local res, err = httpc:request_uri(conf.coaz_url:gsub("/+$", "") .. "/v1/mcp/check", {
    method = "POST",
    body = payload,
    headers = {
      ["Content-Type"] = "application/json",
      -- Matches CHECK_API_TOKEN on the coaz-pep side: that endpoint relays a
      -- caller-supplied Authorization header, so it authenticates its callers.
      ["Authorization"] = set(conf.coaz_api_key) and ("Bearer " .. conf.coaz_api_key) or nil,
    },
    ssl_verify = conf.pdp_ssl_verify ~= false,
  })
  local kind, detail = contract.classify(res, err)
  local verdict
  if kind == "answer" then
    verdict = cjson.decode(res.body)
    if not contract.is_object(verdict) or type(verdict.decision) ~= "boolean" then
      kind, detail = "refusal", "answered " .. tostring(res.status) .. " with no boolean decision"
    end
  end
  if kind ~= "answer" then
    if kind == "unavailable" then
      kong.log.err("coaz-pep unavailable (", detail, "); denying (fail-closed)")
      return deny(pep, 503, "Authorization service unavailable; denying (fail-closed).")
    end
    kong.log.err("coaz-pep refused the check (", detail, "); denying (fail-closed)")
    return deny(pep, 503, "Authorization service refused the request; denying (fail-closed).")
  end

  if verdict.decision == true then
    c.decision = "PERMIT"
    for k, v in pairs(contract.is_object(verdict.upstream_headers) and verdict.upstream_headers or {}) do
      local value = type(k) == "string" and contract.header_value(v) or nil
      if value == "" then
        kong.service.request.clear_header(k)
      elseif value then
        kong.service.request.set_header(k, value)
      end
    end
    c.engine_headers = contract.is_object(verdict.response_headers) and verdict.response_headers or nil
    return
  end

  -- A deny: coaz-pep's rendering of it, relayed verbatim — a JSON-RPC error on an MCP
  -- route, a challenge or a 403 on a REST one. Two renderings of one decision would drift.
  c.decision = "DENY"
  local resp = contract.is_object(verdict.response) and verdict.response or {}
  local status = tonumber(resp.status)
  if not status or status % 1 ~= 0 or status < 100 or status > 599 then
    kong.log.err("coaz-pep denied without a usable response; answering 403")
    return deny(pep, 403, "Denied by policy.")
  end
  local h = {}
  for k, v in pairs(contract.is_object(resp.headers) and resp.headers or {}) do
    local value = type(k) == "string" and contract.header_value(v) or nil
    if value then h[k] = value end
  end
  return kong.response.exit(status, contract.str(resp.body) or "", h)
end

-- ---------- native: REST, decided here ----------

-- The path the route delegates to its service, which is what the mapping describes:
-- normalised (kong.request.get_path is RFC 3986-normalised on Kong 3.x, the path its
-- router matched and the upstream receives), with the route's matched prefix removed
-- when the route strips it, as Kong does. A regex route path is not stripped.
local function routed_path()
  local path = kong.request.get_path()
  local route = kong.router.get_route()
  if not contract.is_object(route) or route.strip_path == false then return path end
  local prefix
  for _, p in ipairs(contract.is_array(route.paths) and route.paths or {}) do
    if type(p) == "string" and p:sub(1, 1) == "/" and path:sub(1, #p) == p and (not prefix or #p > #prefix) then
      prefix = p
    end
  end
  if not prefix then return path end
  local rest = path:sub(#prefix + 1)
  if rest:sub(1, 1) ~= "/" then rest = "/" .. rest end
  return rest
end

local function present(v) return v ~= nil and v ~= cjson.null end
local function finite(v) return type(v) == "number" and v == v and v ~= math.huge and v ~= -math.huge end

-- The body of a request whose mapping needs it, as one JSON object; or nil, a status and
-- a reason. A body that cannot be read in full, or parsed, is never mapped as empty.
local function json_body(conf)
  local raw, err = contract.read_body(conf.max_request_body_size)
  if not raw then
    kong.log.err("the request body could not be read in full (", err, "); refusing it")
    return nil, 413, "The request body is too large for the gateway to authorise."
  end
  local body = cjson.decode(raw)
  if not contract.is_object(body) then
    return nil, 400, "The request body is not a JSON object the gateway can read."
  end
  return body
end

-- Map the HTTP request to an AuthZEN (action, resource, context, resource properties).
-- Resource Server semantics: fine-grained, e.g. the payment amount. Every pattern is
-- anchored to the whole routed path. Returns the mapping, or nil, a status and a reason
-- when the request cannot be mapped faithfully.
local function map_request(conf)
  local method = kong.request.get_method()
  local path = routed_path()
  local m = { ctx = { channel = "ai-agent" }, rprops = {} }

  local cust = path:match("^/customers/([^/]+)/accounts/?$")
  local acct = path:match("^/accounts/([^/]+)/balance/?$")
  if cust then
    m.action, m.rtype, m.rid = "list_accounts", "customer", cust
  elseif acct then
    m.action, m.rtype, m.rid = "get_balance", "account", acct
  elseif method == "POST" and path:match("^/accounts/?$") then
    local body, status, reason = json_body(conf)
    if not body then return nil, status, reason end
    local account_type = body.account_type
    if present(account_type) and not set(account_type) then
      return nil, 400, "account_type must be a non-empty string."
    end
    account_type = present(account_type) and account_type or nil
    m.action, m.rtype, m.rid = "open_account", "account", "new:" .. (account_type or "savings")
    m.rprops.account_type = account_type
  elseif method == "POST" and path:match("^/payments/?$") then
    -- What the PDP is asked about must be what the upstream will do: an amount it cannot
    -- read is not an amount of nothing.
    local body, status, reason = json_body(conf)
    if not body then return nil, status, reason end
    if not set(body.from_account) then return nil, 400, "from_account must be a non-empty string." end
    if not finite(body.amount) then return nil, 400, "amount must be a number." end
    for _, f in ipairs({ "to_account", "currency", "description" }) do
      if present(body[f]) and type(body[f]) ~= "string" then return nil, 400, f .. " must be a string." end
    end
    if present(body.internal_transfer) and type(body.internal_transfer) ~= "boolean" then
      return nil, 400, "internal_transfer must be true or false."
    end
    m.action, m.rtype, m.rid = "make_payment", "account", body.from_account
    m.rprops.from_account = body.from_account
    m.rprops.to_account = contract.str(body.to_account)
    m.ctx.amount = body.amount
    m.ctx.currency = set(body.currency) and body.currency or "AUD"
    m.ctx.description = contract.str(body.description)
    if type(body.internal_transfer) == "boolean" then m.ctx.internal_transfer = body.internal_transfer end
  else
    m.action, m.rtype, m.rid = "http:" .. method:lower(), "endpoint", kong.request.get_path()
  end
  return m
end

-- has_obligation reports whether a folded context already carries a challenge.
local function has_obligation(ctx)
  return ctx ~= nil and (ctx.identity_proofing_required == true or ctx.step_up_required == true)
end

-- merge_permit folds a permitting layer's context into the running one.
--
-- Only the DECISION is a single answer; the OBLIGATIONS are cumulative. Replacing the
-- context wholesale let a later layer's plain permit erase an earlier layer's step-up or
-- identity-proofing requirement, and the request was then forwarded with no challenge
-- issued at all -- which defeats the point of putting a generic PDP in front of the
-- resource's own. The first layer to require something owns its parameter.
local function merge_permit(acc, layer)
  local out = {}
  for k, v in pairs(layer) do out[k] = v end
  if acc then
    if acc.identity_proofing_required == true then
      out.identity_proofing_required = true
      out.identity_proofing_doctype = acc.identity_proofing_doctype or out.identity_proofing_doctype
    end
    if acc.step_up_required == true then
      out.step_up_required = true
      out.step_up_scope = acc.step_up_scope or out.step_up_scope
    end
  end
  return out
end

local function native(conf, pep)
  local c = kong.ctx.plugin
  c.pep = pep

  -- The schema refuses each of these; a route that got here anyway fails closed rather
  -- than decide on something it cannot check.
  local misconfigured
  if conf.style == "mcp" then
    misconfigured = "style=mcp without coaz_url"
  elseif conf.require_dpop or conf.require_user_login then
    misconfigured = "require_dpop or require_user_login without coaz_url"
  elseif conf.access_token_verified_upstream ~= true and conf.allow_insecure ~= true then
    misconfigured = "unverified access token claims (neither access_token_verified_upstream nor allow_insecure)"
  end
  if misconfigured then
    kong.log.err("route misconfigured: ", misconfigured, "; denying (fail-closed)")
    return deny(pep, 503, "Authorization is not configured correctly on this route; denying (fail-closed).")
  end

  local headers, hstatus, hreason = request_headers()
  if not headers then
    return deny(pep, hstatus, hreason)
  end

  -- 1) token + claims
  local token = extract_token(headers["authorization"])
  if not token and conf.require_token then
    return deny(pep, 401, "No access token presented to the gateway.")
  end

  -- Unverified here: read only because the configuration says who verified them (or,
  -- with allow_insecure, that nobody need have).
  local claims = token and jwt_claims(token) or {}
  local sub = contract.str(claims.sub)
  -- `act` (RFC 8693) may be a nested object (self-issued tokens) OR a JSON string
  -- (PingFederate's JWT ATM emits object-valued claims as strings) — handle both.
  local act_claim = claims.act
  if type(act_claim) == "string" then act_claim = cjson.decode(act_claim) end
  local act = contract.is_object(act_claim) and contract.str(act_claim.sub) or nil
  -- A claim that is a string, or a list of strings joined by spaces; anything else is absent.
  local function words(v)
    if not contract.is_array(v) then return contract.str(v) end
    for _, item in ipairs(v) do
      if type(item) ~= "string" then return nil end
    end
    return table.concat(v, " ")
  end
  local scope = words(claims.scope or claims.scp)
  local client_id = contract.str(claims.client_id) or contract.str(claims.azp)
  -- The authentication context the AS asserted. Forwarded downstream so a resource server can
  -- decide "is this a staff channel?" from a CLAIM the OP made, instead of comparing the
  -- principal against a hardcoded username list (a self-registered user called `the approver` used to
  -- inherit staff authority over every customer that way).
  local acr = words(claims.acr)

  if conf.require_token and not sub then
    return deny(pep, 401, "Access token missing or unreadable (no subject claim).")
  end

  -- 2) build the AuthZEN evaluation request
  local m, mstatus, mreason = map_request(conf)
  if not m then return deny(pep, mstatus, mreason) end
  local ctx = m.ctx

  -- AuthZEN 1.0 names the subject identifier `id`. This plugin historically sent
  -- `identity`, which no version of the spec defines, so a policy reading it is reading
  -- a field we invented. Both are sent while legacy_subject_identity is on (the
  -- default), so upgrading the gateway alone cannot break such a policy; turn it off
  -- once the policies read subject.id. Kept in lockstep with the Go PEP — the two
  -- sending different subject shapes would be worse than either shape.
  local agent_id = act or client_id or "unknown-agent"
  local subject = {
    type = "agent",
    id = agent_id,
    properties = {
      on_behalf_of = sub,
      agent_type = "ai_assistant",
      scope = scope,
      client_id = client_id,
    },
  }
  if conf.legacy_subject_identity ~= false then
    subject.identity = agent_id
  end

  local authzen_req = {
    subject = subject,
    action = { name = m.action },
    resource = { type = m.rtype, id = m.rid, properties = m.rprops },
    context = ctx,
  }

  -- 3) which PDP, and where. Off by default (authzen_url + the AuthZEN paths, no
  --    fetch). A discovery failure is a 503, like an unreachable PDP: a request whose
  --    decider cannot be found is not one to let through.
  local layers, derr = discovery.resolve_layers(conf, discovery.resource_id(conf), conf.pdp_layers, conf.fail_mode == "open")
  if not layers then
    kong.log.err("PDP discovery failed: ", derr.msg)
    return deny(pep, 503, "Authorization service could not be resolved; denying (fail-closed).")
  end
  local eps, meta, skipped = layers.pdps, layers.meta, layers.skipped

  -- What the PDP gets to reason with, beyond the mapped action and resource:
  --   resource_metadata   the resource's declared posture (scopes, acr, sender-constraint
  --                       requirements — whatever it published), verbatim, with its
  --                       source so the PDP knows whether the federation vouched for it.
  --   request             the endpoint actually hit, so the PDP can match requirements
  --                       to endpoints itself.
  --   access_token        the raw token, when the route allows it, so the PDP can verify
  --                       and inspect it rather than trusting what this plugin decoded.
  -- The plugin enforces none of these. Comparing a token's scope or acr to what a
  -- resource requires is a policy decision, and policy is offloaded to the PDP, where it
  -- can weigh them alongside things a gateway never sees.
  if meta then
    ctx.resource_metadata = meta.document
    ctx.resource_metadata_source = meta.source
  end
  ctx.request = { method = kong.request.get_method(), path = kong.request.get_path() }
  if conf.forward_access_token and token then
    ctx.access_token = token
  end

  -- 4) ask each layer in order. Every layer must permit; the first that does not is
  --    the answer, advice and all, and later layers are not consulted — a generic
  --    layer is a gate in front of a specific one. A layer whose PDP is unavailable (no
  --    answer, a 5xx, a 429) fails closed unless it is fail-open, in which case it is
  --    skipped and named; if every layer was skipped the request is permitted and
  --    marked. A deny is never skipped, and nor is a refusal: a PDP that answered a 3xx
  --    or 4xx, or with no boolean decision, or a request that could not be encoded.
  local body = cjson.encode(authzen_req)
  if not body then
    kong.log.err("the evaluation request could not be encoded (a value JSON cannot carry); refused, denying (fail-closed)")
    return deny(pep, 503, "Authorization service refused the request; denying (fail-closed).")
  end
  local decision, reason
  local dctx = {}
  local decided = false
  for _, ep in ipairs(eps) do
    local httpc = http.new()
    httpc:set_timeout(10000)
    local res, err = httpc:request_uri(ep.evaluation, {
      method = "POST",
      body = body,
      headers = {
        ["Content-Type"] = "application/json",
        -- Bound to the PDP it was configured for; a discovered PDP gets no key.
        ["Authorization"] = ep.api_key and ("Bearer " .. ep.api_key) or nil,
      },
      ssl_verify = conf.pdp_ssl_verify ~= false,
    })
    local kind, detail = contract.classify(res, err)
    local data
    if kind == "answer" then
      data = cjson.decode(res.body)
      if not contract.is_object(data) or type(data.decision) ~= "boolean" then
        kind, detail = "refusal", "answered " .. tostring(res.status) .. " with no boolean decision"
      end
    end
    if kind == "refusal" then
      kong.log.err("PDP ", ep.identifier, " refused the evaluation (", detail, "); denying (fail-closed)")
      return deny(pep, 503, "Authorization service refused the request; denying (fail-closed).")
    elseif kind == "unavailable" then
      if not ep.fail_open then
        kong.log.err("PDP ", ep.identifier, " unavailable (", detail, "); denying (fail-closed)")
        return deny(pep, 503, "Authorization service unavailable; denying (fail-closed).")
      end
      kong.log.warn("PDP layer ", ep.identifier, " unavailable (", detail, "); skipped (fail-open)")
      skipped[#skipped + 1] = ep.identifier
    else
      decided = true
      decision = data.decision == true
      local lctx = (contract.is_object(data.context) and data.context) or {}
      local lreason = contract.str(lctx.reason) or (decision and "Permitted by policy." or "Denied by policy.")
      if not decision then
        -- A deny is reported with its own advice, and later layers are not consulted.
        dctx, reason = lctx, lreason
        break
      end
      -- A permit: obligations accumulate. See merge_permit.
      if not has_obligation(dctx) then reason = lreason end
      dctx = merge_permit(dctx, lctx)
    end
  end
  if not decided then
    -- Which layers were skipped goes in X-PDP-Fail-Open; why is in the log.
    decision, dctx = true, {}
    reason = "fail-open: no policy layer could be reached"
  end
  if #skipped > 0 then
    kong.log.warn("permit failed open past: ", table.concat(skipped, ", "))
    c.fail_open = table.concat(skipped, ", ")
  end

  -- surface the decision on the response for the demo transcript
  c.decision = decision and "PERMIT" or "DENY"
  c.reason = reason
  c.action = m.action

  -- Identity-proofing advice: the customer has no verified proofing activity yet.
  -- Challenge for a credential presentation rather than a flat deny, so the client
  -- knows what would resolve it. Ordered before step-up because identity is the more
  -- fundamental gate: resolve it first and let the retry surface any step-up.
  --
  -- This mirrors the Go PEP exactly (core/coaz/engine.go). Without it, the same policy
  -- decision produced a resolvable challenge behind Envoy and an unexplained 403 behind
  -- Kong, which defeats the point of sharing one decision contract.
  if dctx.identity_proofing_required == true then
    local doctype = contract.str(dctx.identity_proofing_doctype) or "org.iso.18013.5.1.mDL"
    return kong.response.exit(401, {
      error = "identity_verification_required",
      doctype = doctype,
      pep = pep,
      reason = reason,
      authz_challenge = { type = "identity_proofing", doctype = doctype, reason = reason, pep = pep },
    }, {
      ["Content-Type"] = "application/json",
      ["WWW-Authenticate"] = 'Bearer error="identity_verification_required", doctype="' .. contract.quoted(doctype) .. '"',
    })
  end

  -- Step-up advice from the policy: this payment is over the threshold and the user
  -- hasn't approved it yet. Challenge for the step-up scope (RFC 9470) so the app can
  -- step the customer up, rather than a flat 403.
  if dctx.step_up_required == true then
    local scope_req = contract.str(dctx.step_up_scope) or contract.str(conf.stepup_scope) or ""
    return kong.response.exit(401, {
      error = "insufficient_scope",
      scope = scope_req,
      pep = pep,
      reason = reason,
      authz_challenge = { type = "resource_authorisation", scope = scope_req, reason = reason, pep = pep },
    }, {
      ["Content-Type"] = "application/json",
      ["WWW-Authenticate"] = 'Bearer error="insufficient_scope", scope="' .. contract.quoted(scope_req) .. '"',
    })
  end

  if not decision then
    return deny(pep, 403, reason)
  end

  -- PERMIT: pass the delegation identity to the upstream for its audit trail. What the
  -- token does not assert stays absent (the client's copy was removed on the way in).
  for name, value in pairs({ ["X-Auth-Principal"] = sub, ["X-Auth-Agent"] = act, ["X-Auth-Scope"] = scope, ["X-Auth-Acr"] = acr }) do
    value = contract.header_value(value)
    if value and value ~= "" then kong.service.request.set_header(name, value) end
  end
end

-- ---------- the phases ----------

-- The resource's two well-known documents: OpenID Federation appends its segment to the
-- identifier's path, RFC 9728 inserts its own after the host.
local FED_WK, RES_WK = "/.well-known/openid-federation", "/.well-known/oauth-protected-resource"
local function is_well_known(path)
  return path == FED_WK or path == RES_WK
    or path:sub(-#FED_WK) == FED_WK
    or path:sub(1, #RES_WK + 1) == RES_WK .. "/"
end

-- relay_well_known serves the resource's federation face from coaz-pep, which holds the
-- key: the entity configuration a trust controller onboards, and the RFC 9728 document
-- that republishes what the federation resolved. Kong cannot sign, so it relays.
local function relay_well_known(conf, path)
  local httpc = http.new()
  httpc:set_timeout(5000)
  local res, err = httpc:request_uri(conf.federation_entity_url .. path, {
    method = "GET", ssl_verify = conf.pdp_ssl_verify ~= false,
  })
  if not res then
    kong.log.err("federation entity relay failed: ", err)
    return kong.response.exit(503, { error = "federation_entity_unavailable" }, { ["Content-Type"] = "application/json" })
  end
  local ct = res.headers and (res.headers["Content-Type"] or res.headers["content-type"]) or "application/json"
  return kong.response.exit(res.status, res.body, { ["Content-Type"] = ct, ["Cache-Control"] = "no-cache" })
end

-- What allow_insecure lets a route run with, that the schema would otherwise refuse.
local function relaxations(conf)
  local out, delegated = {}, set(conf.coaz_url)
  if not delegated and conf.access_token_verified_upstream ~= true then
    out[#out + 1] = "access token claims are read unverified"
  end
  if delegated and not set(conf.coaz_api_key) then
    out[#out + 1] = "coaz-pep is called without coaz_api_key"
  end
  if not delegated and (conf.pdp_discovery or "off") ~= "off"
    and not (type(conf.pdp_allowlist) == "table" and #conf.pdp_allowlist > 0) then
    out[#out + 1] = "any PDP a resource names may be asked (no pdp_allowlist)"
  end
  if conf.pdp_discovery_insecure == true then out[#out + 1] = "discovered URLs may be plain http" end
  if conf.pdp_ssl_verify == false then out[#out + 1] = "TLS verification is off" end
  return out
end

-- Kong calls configure with every configuration of this plugin at worker start and on
-- every change: where an escape hatch in use is said out loud.
function AuthzenPDP:configure(configs)
  for _, conf in ipairs(configs or {}) do
    if conf.allow_insecure == true then
      local relaxed = relaxations(conf)
      kong.log.warn("allow_insecure on route ", tostring(conf.pep_label), ": ",
        #relaxed > 0 and table.concat(relaxed, "; ") or "nothing relaxed", " (development only)")
    end
  end
end

function AuthzenPDP:access(conf)
  local pep = conf.pep_label or "kong-pep"

  -- The identity headers are this plugin's to assert. A client's own copies go first,
  -- before anything else, so no path through here can forward one.
  for _, name in ipairs(AUTH_HEADERS) do kong.service.request.clear_header(name) end

  -- The resource's federation face, before any token is looked at: these documents
  -- are public by definition.
  if set(conf.federation_entity_url) then
    local path = kong.request.get_path()
    if is_well_known(path) then return relay_well_known(conf, path) end
  end

  if set(conf.coaz_url) then return delegate(conf, pep) end
  return native(conf, pep)
end

-- The decision on the response, for the demo transcript and anyone reading a trace. Every
-- value is header-safe: a policy's reason is PDP data, and a line break in it would
-- otherwise start a header of the policy's choosing.
function AuthzenPDP:header_filter(conf)
  local c = kong.ctx.plugin
  if not (c and c.decision) then return end
  local function put(name, value)
    value = contract.header_value(value)
    if value then kong.response.set_header(name, value) end
  end
  for k, v in pairs(c.engine_headers or {}) do
    if type(k) == "string" then put(k, v) end
  end
  put("X-PDP-PEP", c.pep or "")
  put("X-PDP-Decision", c.decision)
  put("X-PDP-Fail-Open", c.fail_open)
  put("X-PDP-Action", c.action)
  put("X-PDP-Reason", c.reason)
end

-- Internals exposed for unit tests. Kong never reads this; it exists so the pure
-- helpers and the request mapping can be exercised without a running gateway
-- (see ../spec). Keeping them `local` above means the plugin itself is unaffected.
AuthzenPDP._TEST = {
  b64url_decode = b64url_decode,
  jwt_claims = jwt_claims,
  extract_token = extract_token,
  map_request = map_request,
  merge_permit = merge_permit,
  has_obligation = has_obligation,
  mcp_body_refusal = mcp_body_refusal,
  check_config = check_config,
}

return AuthzenPDP

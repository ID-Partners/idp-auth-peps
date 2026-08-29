-- authzen-pdp: a Kong Policy Enforcement Point (PEP) that calls the AuthZEN PDP.
--
-- For every proxied request this plugin:
--   1. extracts the delegated access token (DPoP or Bearer) and reads its claims
--      (sub = principal, act.sub = acting agent, scope, cnf.jkt);
--   2. if DPoP is required, checks the sender-constraint binding: the SHA-256
--      JWK thumbprint of the DPoP proof header key must equal the access token's
--      cnf.jkt (RFC 9449), htm must match the method, and ath must equal
--      base64url(SHA-256(access token)) so a proof cannot replay against a
--      different token. SEE THE DPoP LIMITATION NOTE BELOW;
--   3. builds an AuthZEN evaluation request (subject=agent on behalf of principal,
--      action+resource+context derived from the HTTP request) and POSTs it to the
--      Go authzen-adapter, which asks Ping Authorize;
--   4. PERMIT -> forwards the request, injecting X-Auth-Principal / X-Auth-Agent /
--      X-Auth-Scope for the Resource Server's audit trail;
--      DENY   -> returns 403 with the policy reason.
--
-- DPoP LIMITATION — READ THIS BEFORE RELYING ON require_dpop.
-- This plugin does NOT verify the DPoP proof's own JWS signature, because there is no
-- usable JOSE verifier in Lua here (the same reason COAZ mapping is delegated to
-- coaz-pep). The proof's public JWK travels inside the proof, so an attacker who has
-- observed one proof can mint another that thumbprints to the same cnf.jkt. The jkt
-- comparison below therefore does NOT by itself prove possession of the private key.
-- What IS enforced: the jkt/cnf match, htm, and the ath token binding — enough to stop
-- a proof being reused against a different token, not enough to stop forgery.
-- For a real sender-constraint put the Envoy/agentgateway PEP (core/, which verifies
-- the proof signature, iat freshness and jti replay) in front of this route, or
-- validate DPoP in Kong's own auth layer before this plugin runs.
--
-- NOTE (demo honesty): this plugin reads the JWT claims and enforces the DPoP
-- key binding, but does not itself verify the access-token JWS signature. In a
-- hardened deployment pair this with Kong's bundled `openid-connect`/`jwt` plugin
-- (or set verify against the AS JWKS) so the token signature is validated before
-- these claims are trusted. The authorization decision itself is always made by
-- Ping Authorize via the PDP.

local http = require "resty.http"
local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"

local AuthzenPDP = {
  PRIORITY = 1000,  -- run before upstream proxying; after auth plugins if present
  VERSION = "0.2.0", -- 0.2.0: COAZ (OpenID AuthZEN MCP profile) via coaz-pep
}

-- ---------- helpers ----------

local function b64url_decode(str)
  if not str or str == "" then return nil end
  str = str:gsub("-", "+"):gsub("_", "/")
  local pad = #str % 4
  if pad > 0 then str = str .. string.rep("=", 4 - pad) end
  return ngx.decode_base64(str)
end

local function b64url_encode(bytes)
  return (ngx.encode_base64(bytes):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
end

-- decode the payload (claims) of a compact JWT; returns table or nil
local function jwt_claims(token)
  if not token then return nil end
  local dot1 = token:find("%.")
  if not dot1 then return nil end
  local dot2 = token:find("%.", dot1 + 1)
  if not dot2 then return nil end
  local payload = b64url_decode(token:sub(dot1 + 1, dot2 - 1))
  if not payload then return nil end
  return cjson.decode(payload)
end

-- decode the protected header of a compact JWT; returns table or nil
local function jwt_header(token)
  if not token then return nil end
  local dot1 = token:find("%.")
  if not dot1 then return nil end
  local header = b64url_decode(token:sub(1, dot1 - 1))
  if not header then return nil end
  return cjson.decode(header)
end

-- RFC 7638 JWK thumbprint (SHA-256, base64url) for EC / RSA / OKP keys
local function jwk_thumbprint(jwk)
  if type(jwk) ~= "table" or not jwk.kty then return nil end
  local canon
  if jwk.kty == "EC" then
    canon = string.format('{"crv":"%s","kty":"EC","x":"%s","y":"%s"}', jwk.crv, jwk.x, jwk.y)
  elseif jwk.kty == "RSA" then
    canon = string.format('{"e":"%s","kty":"RSA","n":"%s"}', jwk.e, jwk.n)
  elseif jwk.kty == "OKP" then
    canon = string.format('{"crv":"%s","kty":"OKP","x":"%s"}', jwk.crv, jwk.x)
  else
    return nil
  end
  local sha = resty_sha256:new()
  sha:update(canon)
  return b64url_encode(sha:final())
end

-- RFC 9449 `ath`: base64url(SHA-256(access token)). Binds a proof to THIS token.
local function access_token_hash(token)
  local sha = resty_sha256:new()
  sha:update(token)
  return b64url_encode(sha:final())
end

-- extract the access token from Authorization: "DPoP <t>" or "Bearer <t>"
local function extract_token(auth_header)
  if not auth_header then return nil, nil end
  local scheme, token = auth_header:match("^(%a+)%s+(.+)$")
  if not scheme then return nil, nil end
  return token, scheme:lower()
end

local function deny(pep, status, reason)
  return kong.response.exit(status, {
    error = "authorization_failed",
    pep = pep,
    reason = reason,
  }, { ["Content-Type"] = "application/json" })
end

-- Map the HTTP request to an AuthZEN (action, resource, context, resource_props).
-- style="rest": Resource Server semantics (fine-grained, e.g. payment amount).
-- style="mcp" : MCP edge (coarse; refine to the tool name if the JSON-RPC body
--               is a tools/call, otherwise authorize the rpc method generically).
local function map_request(conf)
  local method = kong.request.get_method()
  local path = kong.request.get_path()
  local ctx = { channel = "ai-agent" }
  local action, rtype, rid = nil, nil, nil
  local rprops = {}

  if conf.style == "mcp" then
    -- PEP #1 authorizes the agent's ACCESS TO THE MCP SERVICE, evaluated once on
    -- the MCP `initialize` handshake (action=access_mcp). All other MCP traffic
    -- (tools/list, tools/call, notifications, ping, SSE GET) is allowed through
    -- on a valid token so the JSON-RPC session isn't broken by a mid-stream 403;
    -- fine-grained per-operation policy is enforced at PEP #2 (the Bank API edge).
    rtype, rid, action = "mcp-service", "northwind-bank", "__allow__"
    local ok, body = pcall(function() return kong.request.get_raw_body() end)
    if ok and body then
      local rpc = cjson.decode(body)
      if type(rpc) == "table" and rpc.method == "initialize" then
        action = "access_mcp"
      end
    end
    return action, rtype, rid, rprops, ctx
  end

  -- style == "rest"
  -- Patterns are prefix-tolerant: Kong strips the route prefix (/bank) but the
  -- plugin sees the original request path, so we match without anchoring at ^.
  local cust = path:match("/customers/([^/]+)/accounts")
  local acct = path:match("/accounts/([^/]+)/balance")
  if cust then
    action, rtype, rid = "list_accounts", "customer", cust
  elseif acct then
    action, rtype, rid = "get_balance", "account", acct
  elseif path:match("/accounts") and method == "POST" then
    action, rtype = "open_account", "account"
    local ok, body = pcall(function() return kong.request.get_body() end)
    if ok and type(body) == "table" then
      rid = "new:" .. tostring(body.account_type or "savings")
      rprops.account_type = body.account_type
    else
      rid = "new:savings"
    end
  elseif path:match("/payments") and method == "POST" then
    action, rtype = "make_payment", "account"
    local ok, body = pcall(function() return kong.request.get_body() end)
    if ok and type(body) == "table" then
      rid = tostring(body.from_account or "")
      rprops.from_account = body.from_account
      rprops.to_account = body.to_account
      ctx.amount = tonumber(body.amount)
      ctx.currency = body.currency or "AUD"
      ctx.description = body.description
      if body.internal_transfer ~= nil then
        ctx.internal_transfer = body.internal_transfer
      end
    end
  else
    action, rtype, rid = "http:" .. method:lower(), "endpoint", path
  end
  return action, rtype, rid, rprops, ctx
end

-- ---------- main phase ----------

function AuthzenPDP:access(conf)
  local pep = conf.pep_label or "kong-pep"

  -- 0) Step-up: require a logged-in END USER (RFC 9470 step-up challenge). The
  --    principal (the customer) authenticates at PingFederate; the app forwards their PF
  --    token down the agent chain as X-User-Token. Without a valid one, the
  --    gateway pushes back a login challenge so the app sends them to log in.
  if conf.require_user_login then
    local ut = kong.request.get_header("x-user-token")
    local uclaims = ut and jwt_claims(ut) or nil
    if not uclaims or not uclaims.sub then
      return kong.response.exit(401, {
        error = "login_required",
        pep = pep,
        reason = "The gateway requires an authenticated user (no valid X-User-Token).",
        acr_values = "urn:pingidentity:loa:password",
      }, {
        ["Content-Type"] = "application/json",
        ["WWW-Authenticate"] = 'Bearer error="insufficient_user_authentication", '
          .. 'error_description="Login required", acr_values="urn:pingidentity:loa:password"',
      })
    end
  end

  -- 1) token + claims
  local token, scheme = extract_token(kong.request.get_header("authorization"))
  if not token then
    if conf.require_token then
      return deny(pep, 401, "No access token presented to the gateway.")
    end
  end

  local claims = token and jwt_claims(token) or {}
  claims = claims or {}
  local sub = claims.sub
  -- `act` (RFC 8693) may be a nested object (self-issued tokens) OR a JSON string
  -- (PingFederate's JWT ATM emits object-valued claims as strings) — handle both.
  local act_claim = claims.act
  if type(act_claim) == "string" then
    local ok, decoded = pcall(cjson.decode, act_claim)
    if ok then act_claim = decoded end
  end
  local act = type(act_claim) == "table" and act_claim.sub or nil
  local scope = claims.scope or claims.scp
  if type(scope) == "table" then scope = table.concat(scope, " ") end
  local client_id = claims.client_id or claims.azp
  -- The authentication context the AS asserted. Forwarded downstream so a resource server can
  -- decide "is this a staff channel?" from a CLAIM the OP made, instead of comparing the
  -- principal against a hardcoded username list (a self-registered user called `the approver` used to
  -- inherit staff authority over every customer that way).
  local acr = claims.acr
  if type(acr) == "table" then acr = table.concat(acr, " ") end

  if conf.require_token and not sub then
    return deny(pep, 401, "Access token missing or unreadable (no subject claim).")
  end

  -- 2) DPoP sender-constraint binding
  if conf.require_dpop then
    if scheme ~= "dpop" then
      return deny(pep, 401, "DPoP-bound token required but Authorization scheme was not DPoP.")
    end
    local proof = kong.request.get_header("dpop")
    if not proof then
      return deny(pep, 401, "Missing DPoP proof header.")
    end
    local phdr = jwt_header(proof)
    local pclaims = jwt_claims(proof)
    local jkt = phdr and jwk_thumbprint(phdr.jwk)
    local cnf_jkt = type(claims.cnf) == "table" and claims.cnf.jkt or nil
    if not jkt or not cnf_jkt or jkt ~= cnf_jkt then
      return deny(pep, 401, "DPoP proof key does not match the token's cnf.jkt binding.")
    end
    if not pclaims or pclaims.htm ~= kong.request.get_method() then
      return deny(pep, 401, "DPoP proof htm does not match the request method.")
    end
    -- ath binds this proof to THIS access token. Presence alone is worthless: a proof
    -- minted for any token would otherwise replay against any other.
    if not pclaims.ath then
      return deny(pep, 401, "DPoP proof missing ath (access-token hash).")
    end
    if pclaims.ath ~= access_token_hash(token) then
      return deny(pep, 401, "DPoP proof ath does not match the presented access token.")
    end
    -- htu is validated best-effort: hosts get rewritten behind the platform proxy,
    -- so a mismatch is logged rather than fatal for the demo.
    if pclaims.htu and not tostring(pclaims.htu):find(kong.request.get_path(), 1, true) then
      kong.log.warn("DPoP htu path mismatch: ", tostring(pclaims.htu))
    end
  end

  -- 2b) COAZ (OpenID AuthZEN MCP profile): tools/call on an MCP route is
  --     delegated to the coaz-pep engine, which discovers the tool's
  --     x-coaz-mapping from the MCP server's tools/list, evaluates the CEL
  --     mapping against the call arguments + token claims, asks the AuthZEN
  --     PDP, and returns either a permit (with identity/audit headers) or the
  --     profile's JSON-RPC error response to relay verbatim.
  if conf.style == "mcp" and conf.coaz_url and conf.coaz_url ~= "" then
    local ok_body, raw_body = pcall(function() return kong.request.get_raw_body() end)
    local rpc = ok_body and raw_body and cjson.decode(raw_body) or nil
    if type(rpc) == "table" and rpc.method == "tools/call" then
      local coaz_httpc = http.new()
      coaz_httpc:set_timeout(15000)
      local cres, cerr = coaz_httpc:request_uri(conf.coaz_url .. "/v1/mcp/check", {
        method = "POST",
        body = cjson.encode({
          config = {
            pep_label = pep,
            style = "mcp",
            mcp_upstream_url = conf.mcp_upstream_url,
            coaz_defaults = conf.coaz_defaults and "true" or "false",
          },
          method = kong.request.get_method(),
          path = kong.request.get_path(),
          headers = {
            authorization = kong.request.get_header("authorization"),
            ["x-user-token"] = kong.request.get_header("x-user-token"),
          },
          body = raw_body,
        }),
        headers = {
          ["Content-Type"] = "application/json",
          -- Matches CHECK_API_TOKEN on the coaz-pep side. That endpoint takes a
          -- caller-supplied upstream URL and relays a caller-supplied Authorization
          -- header, so it authenticates its callers.
          ["Authorization"] = conf.coaz_api_key and ("Bearer " .. conf.coaz_api_key) or nil,
        },
      })
      if not cres or cres.status ~= 200 then
        kong.log.err("coaz-pep engine call failed: ", cerr or (cres and cres.status))
        return deny(pep, 503, "COAZ authorization engine unreachable; denying (fail-closed).")
      end
      local verdict = cjson.decode(cres.body) or {}
      local c = kong.ctx.plugin
      if verdict.decision and verdict.decision == true then
        for k, v in pairs(verdict.upstream_headers or {}) do
          kong.service.request.set_header(k, v)
        end
        local rh = verdict.response_headers or {}
        c.pep, c.decision = pep, "PERMIT"
        c.action = rh["X-PDP-Action"] or ("tools/call:" .. tostring(rpc.params and rpc.params.name or "?"))
        c.reason = rh["X-PDP-Reason"]
        return
      end
      local resp = verdict.response or {}
      local rh = resp.headers or {}
      c.pep, c.decision = pep, "DENY"
      c.action = rh["X-PDP-Action"] or ("tools/call:" .. tostring(rpc.params and rpc.params.name or "?"))
      c.reason = rh["X-PDP-Reason"]
      return kong.response.exit(resp.status or 200, resp.body or "", rh)
    end
  end

  -- 3) build AuthZEN evaluation request
  local action, rtype, rid, rprops, ctx = map_request(conf)

  -- MCP handshake / non-tool traffic: allow on a valid token, skip the PDP.
  if action == "__allow__" then
    kong.service.request.set_header("X-Auth-Principal", sub or "")
    kong.service.request.set_header("X-Auth-Agent", act or "")
    kong.service.request.set_header("X-Auth-Scope", scope or "")
    kong.service.request.set_header("X-Auth-Acr", acr or "")
    local c = kong.ctx.plugin
    c.pep, c.decision, c.action = pep, "PERMIT", "mcp-handshake"
    c.reason = "MCP handshake allowed (authenticated); policy applies to tool calls."
    return
  end

  -- 3b) Carry the USER's (the customer's) consented scope into the PDP context. The step-up
  --     decision is now the PDP's (see the advice handling after the decision), not a
  --     hardcoded amount-blind gateway rule: the banking policy compares the payment
  --     amount to the step-up threshold and checks whether this scope already satisfies
  --     it, then returns a step_up_required advice the gateway honours below. Small
  --     payments below the threshold flow without any step-up.
  do
    local ut = kong.request.get_header("x-user-token")
    local uclaims = ut and jwt_claims(ut) or nil
    local uscope = uclaims and (uclaims.scope or uclaims.scp) or ""
    if type(uscope) == "table" then uscope = table.concat(uscope, " ") end
    ctx.user_scope = uscope
  end

  local authzen_req = {
    subject = {
      type = "agent",
      identity = act or client_id or "unknown-agent",
      properties = {
        on_behalf_of = sub,
        agent_type = "ai_assistant",
        scope = scope,
        client_id = client_id,
      },
    },
    action = { name = action },
    resource = { type = rtype, id = rid, properties = rprops },
    context = ctx,
  }

  local httpc = http.new()
  httpc:set_timeout(10000)
  local res, err = httpc:request_uri(conf.authzen_url .. "/access/v1/evaluation", {
    method = "POST",
    body = cjson.encode(authzen_req),
    headers = {
      ["Content-Type"] = "application/json",
      ["Authorization"] = "Bearer " .. (conf.authzen_api_key or ""),
    },
    ssl_verify = conf.pdp_ssl_verify ~= false,
  })

  -- 4) enforce (fail closed on PDP error)
  if not res then
    kong.log.err("PDP call failed: ", err)
    return deny(pep, 503, "Authorization service unreachable; denying (fail-closed).")
  end
  local data = cjson.decode(res.body) or {}
  local decision = data.decision == true
  local dctx = (type(data.context) == "table" and data.context) or {}
  local reason = dctx.reason or (decision and "Permitted by policy." or "Denied by policy.")

  -- surface the decision on the response for the demo transcript
  local pdp_ctx = kong.ctx.plugin
  pdp_ctx.pep = pep
  pdp_ctx.decision = decision and "PERMIT" or "DENY"
  pdp_ctx.reason = reason
  pdp_ctx.action = action

  -- Identity-proofing advice: the customer has no verified proofing activity yet.
  -- Challenge for a credential presentation rather than a flat deny, so the client
  -- knows what would resolve it. Ordered before step-up because identity is the more
  -- fundamental gate: resolve it first and let the retry surface any step-up.
  --
  -- This mirrors the Go PEP exactly (core/coaz/engine.go). Without it, the same policy
  -- decision produced a resolvable challenge behind Envoy and an unexplained 403 behind
  -- Kong, which defeats the point of sharing one decision contract.
  if dctx.identity_proofing_required then
    local doctype = dctx.identity_proofing_doctype or "org.iso.18013.5.1.mDL"
    return kong.response.exit(401, {
      error = "identity_verification_required",
      doctype = doctype,
      pep = pep,
      reason = reason,
      authz_challenge = { type = "identity_proofing", doctype = doctype, reason = reason, pep = pep },
    }, {
      ["Content-Type"] = "application/json",
      ["WWW-Authenticate"] = 'Bearer error="identity_verification_required", doctype="' .. doctype .. '"',
    })
  end

  -- Step-up advice from the policy: this payment is over the threshold and the user
  -- hasn't approved it yet. Challenge for the step-up scope (RFC 9470) so the app can
  -- step the customer up, rather than a flat 403.
  if dctx.step_up_required then
    local scope_req = dctx.step_up_scope or conf.stepup_scope or ""
    return kong.response.exit(401, {
      error = "insufficient_scope",
      scope = scope_req,
      pep = pep,
      reason = reason,
      authz_challenge = { type = "resource_authorisation", scope = scope_req, reason = reason, pep = pep },
    }, {
      ["Content-Type"] = "application/json",
      ["WWW-Authenticate"] = 'Bearer error="insufficient_scope", scope="' .. scope_req .. '"',
    })
  end

  if not decision then
    return deny(pep, 403, reason)
  end

  -- PERMIT: pass the delegation identity to the upstream for its audit trail
  kong.service.request.set_header("X-Auth-Principal", sub or "")
  kong.service.request.set_header("X-Auth-Agent", act or "")
  kong.service.request.set_header("X-Auth-Scope", scope or "")
  kong.service.request.set_header("X-Auth-Acr", acr or "")
end

function AuthzenPDP:header_filter(conf)
  local c = kong.ctx.plugin
  if c and c.decision then
    kong.response.set_header("X-PDP-PEP", c.pep or "")
    kong.response.set_header("X-PDP-Decision", c.decision)
    kong.response.set_header("X-PDP-Action", c.action or "")
    if c.reason then kong.response.set_header("X-PDP-Reason", c.reason) end
  end
end

-- Internals exposed for unit tests. Kong never reads this; it exists so the pure
-- helpers and the request mapping can be exercised without a running gateway
-- (see ../spec). Keeping them `local` above means the plugin itself is unaffected.
AuthzenPDP._TEST = {
  b64url_decode = b64url_decode,
  b64url_encode = b64url_encode,
  jwt_claims = jwt_claims,
  jwt_header = jwt_header,
  jwk_thumbprint = jwk_thumbprint,
  access_token_hash = access_token_hash,
  extract_token = extract_token,
  map_request = map_request,
}

return AuthzenPDP

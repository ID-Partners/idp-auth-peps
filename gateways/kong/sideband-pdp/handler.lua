-- sideband-pdp: a Kong Policy Enforcement Point that enforces through PingAuthorize's
-- Sideband API and finds the PDPs it calls from the resource it protects.
--
-- For every proxied request:
--   1. resolve the PDPs: service_url as configured, or — with discovery on — what the
--      resource's RFC 9728 metadata (or, with the switch, a federation resolve endpoint)
--      names in authzen_policy_decision_points, behind whatever it publishes in
--      authzen_policy_layers, behind whatever pdp_layers configures. One ordered list,
--      each entry with its rules;
--   2. POST the whole request to each layer's /sideband/request, in order, each layer
--      seeing the request as the previous one rewrote it. The first layer whose answer is
--      a response ends the request: that response goes to the client, verbatim. A layer
--      that cannot be reached follows its rule — fail-closed denies, fail-open skips it;
--   3. forward the request as the layers rewrote it;
--   4. in the response phase, POST the upstream's response to each permitting layer's
--      /sideband/response, in reverse order, skipping request-only layers, and send the
--      client what comes back.
--
-- What the plugin does NOT do: decide anything, map the request to an action, or shape
-- a challenge. The sideband API's contract is that PingAuthorize's policy does all three
-- and hands back the HTTP to send, so the WWW-Authenticate a denied agent gets is the
-- policy's to write. The challenge contract the other PEPs render in code is, on this
-- route, a contract the policy honours.
--
-- The sideband half descends from Ping's ping-auth plugin (the ID-Partners-AU fork of
-- pingidentity/kong-plugin-ping-auth); the discovery half is the module shared with
-- authzen-pdp, so both plugins find PDPs by the same rules.

local discovery = require "kong.plugins.authzen-pdp.discovery"
local contract = require "kong.plugins.authzen-pdp.contract"
local sideband = require "kong.plugins.sideband-pdp.sideband"

local SidebandPDP = {
  PRIORITY = 999, -- as ping-auth: after Kong's own authentication plugins; see ../README.md#plugin-order
  VERSION = "0.4.0",
}

-- The modifiers a layer entry may carry beyond the shared fail-open / fail-closed.
local MODIFIERS = { ["request-only"] = "request_only" }

local function trim_slash(s) return (tostring(s or ""):gsub("/+$", "")) end

-- The response headers that say what happened, for the demo transcript and for anyone
-- reading a trace. They ride on every exit this plugin makes: Kong will not load a plugin
-- that has both a response phase and a header_filter, so there is no later phase to set
-- them in. Header-safe, every one: identifiers and labels are configuration and PDP data.
local function pdp_headers(c)
  local h = { ["X-PDP-PEP"] = c.pep, ["X-PDP-Decision"] = c.decision }
  local names = {}
  for _, a in ipairs(c.asked or {}) do names[#names + 1] = a.ep.identifier end
  if #names > 0 then h["X-PDP-Layers"] = table.concat(names, ", ") end
  h["X-PDP-Layer"] = c.layer
  h["X-PDP-Source"] = c.source
  h["X-PDP-Fail-Open"] = c.fail_open
  for k, v in pairs(h) do h[k] = contract.header_value(v) end
  return h
end

-- The plugin's own denials: the same shape as authzen-pdp's, because they are the same
-- events — a PDP that could not be found or reached. A policy deny never comes through
-- here; that is the policy provider's response, relayed as it is.
local function deny(c, status, reason, headers)
  local h = pdp_headers(c)
  h["Content-Type"] = "application/json"
  for k, v in pairs(headers or {}) do h[k] = v end
  return kong.response.exit(status, { error = "authorization_failed", pep = c.pep, reason = reason }, h)
end

-- The configuration the shared discovery module reads. service_url is the static PDP.
-- No API key goes through discovery: a sideband secret is bound to an identifier below.
local function discovery_conf(conf)
  return {
    authzen_url = conf.service_url,
    authzen_api_key = "",
    pdp_discovery = conf.pdp_discovery,
    resource = conf.resource,
    pdp_metadata_ttl = conf.pdp_metadata_ttl,
    pdp_allowlist = conf.pdp_allowlist,
    resource_metadata_allowlist = conf.resource_metadata_allowlist,
    pdp_discovery_insecure = conf.pdp_discovery_insecure,
    pdp_ssl_verify = conf.verify_service_certificate,
    federation_resolve_url = conf.federation_resolve_url,
    federation_trust_anchor = conf.federation_trust_anchor,
  }
end

-- What a PDP is called with. The static secret is bound to service_url; a discovered
-- PDP gets what pdp_credentials names for it, or nothing — PingAuthorize then refuses
-- the call, and the layer's rule decides what that costs.
local function credential_for(conf, identifier)
  if identifier == trim_slash(conf.service_url) then
    return { header = conf.secret_header_name, secret = conf.shared_secret }
  end
  for _, c in ipairs(conf.pdp_credentials or {}) do
    if trim_slash(c.pdp) == identifier then
      return { header = c.secret_header_name or conf.secret_header_name, secret = c.shared_secret }
    end
  end
  return nil
end

local function debug(conf, ...)
  if conf.enable_debug_logging then kong.log.debug(...) end
end

-- One layer that could not be reached, under its rule: fail-open skips the layer and
-- names it; fail-closed denies, with the reason a client can act on when there is one.
-- A 429 answers this request only: the next is asked afresh.
local function fail_layer(c, ep, detail, skipped, phase)
  if ep.fail_open then
    -- The client is told which layer was skipped (X-PDP-Fail-Open); why is for the log.
    kong.log.warn("PDP layer ", ep.identifier, " unavailable (", phase, "): ", detail.msg, "; skipped (fail-open)")
    skipped[#skipped + 1] = ep.identifier
    return
  end
  kong.log.err("PDP layer ", ep.identifier, " unavailable (", phase, "): ", detail.msg, "; denying (fail-closed)")
  c.decision, c.layer = "DENY", ep.identifier
  if detail.retry_after then
    return deny(c, 429, "Authorization service is rate-limiting this gateway; denying (fail-closed).",
      { ["Retry-After"] = tostring(detail.retry_after) })
  end
  return deny(c, 503, "Authorization service unavailable; denying (fail-closed).")
end

-- One layer that answered and refused (a 3xx or 4xx, an answer it cannot read, a call it
-- could not make): closed, whatever the layer's rule. A refusal is not an outage.
local function refuse(c, ep, detail, phase)
  kong.log.err("PDP layer ", ep.identifier, " refused the ", phase, " call: ", detail.msg, "; denying (fail-closed)")
  c.decision, c.layer = "DENY", ep.identifier
  return deny(c, 503, "Authorization service refused the request; denying (fail-closed).")
end

-- ask posts one payload to one layer and classifies the answer with `classify`.
local function ask(conf, ep, path, payload, classify)
  local who = ep.identifier
  debug(conf, "sideband ", path, " to ", who, " (", ep.source, ")")
  local res, err, unencodable = sideband.post(who .. path, payload, conf, credential_for(conf, who))
  return classify(res, err, who, unencodable)
end

-- What allow_insecure lets a route run with, that the schema would otherwise refuse.
local function relaxations(conf)
  local out = {}
  if (conf.pdp_discovery or "off") ~= "off"
    and not (type(conf.pdp_allowlist) == "table" and #conf.pdp_allowlist > 0) then
    out[#out + 1] = "any PDP a resource or the federation names may be asked (no pdp_allowlist)"
  end
  if conf.pdp_discovery_insecure == true then out[#out + 1] = "discovered URLs may be plain http" end
  if conf.verify_service_certificate == false then out[#out + 1] = "TLS verification is off" end
  if conf.pdp_discovery == "federation" and tostring(conf.federation_resolve_url or ""):lower():match("^http://") then
    out[#out + 1] = "the federation resolver is plain http"
  end
  return out
end

-- Kong calls configure with every configuration of this plugin at worker start and on
-- every change: where an escape hatch in use is said out loud.
function SidebandPDP:configure(configs)
  for _, conf in ipairs(configs or {}) do
    if conf.allow_insecure == true then
      local relaxed = relaxations(conf)
      kong.log.warn("allow_insecure on route ", tostring(conf.pep_label), ": ",
        #relaxed > 0 and table.concat(relaxed, "; ") or "nothing relaxed", " (development only)")
    end
  end
end

function SidebandPDP:access(conf)
  local c = kong.ctx.plugin
  c.pep = conf.pep_label or "kong-sideband-pep"

  -- 0) A client's identity headers go before anything else: the policy provider is not
  --    shown them as if a PEP had asserted them, and the upstream receives only what a
  --    layer adds.
  for _, name in ipairs(sideband.AUTH_HEADERS) do kong.service.request.clear_header(name) end

  -- 1) which PDPs, in what order, under what rules. A discovery failure is a 503, like an
  --    unreachable PDP: a request whose decider cannot be found is not one to let through.
  local dconf = discovery_conf(conf)
  local layers, derr = discovery.resolve_layers(dconf, discovery.resource_id(dconf), conf.pdp_layers,
    conf.fail_mode == "open", { probe = false, modifiers = MODIFIERS })
  if not layers then
    kong.log.err("PDP discovery failed: ", derr.msg)
    c.decision = "DENY"
    return deny(c, 503, "Authorization service could not be resolved; denying (fail-closed).")
  end
  local eps, skipped = layers.pdps, layers.skipped
  c.source = layers.meta and layers.meta.source or "static"

  -- 2) the request as the client sent it, through every layer in order
  local original, perr = sideband.request_payload(conf)
  if not original then
    kong.log.err("the sideband request could not be built: ", perr.detail)
    c.decision = "DENY"
    return deny(c, perr.status, perr.reason)
  end
  local current, asked = original, {}
  for _, ep in ipairs(eps) do
    local verdict, detail = ask(conf, ep, sideband.REQUEST_PATH, current, sideband.classify)
    if verdict == "unavailable" then
      fail_layer(c, ep, detail, skipped, "request")
    elseif verdict == "refusal" then
      return refuse(c, ep, detail, "request")
    elseif verdict == "deny" then
      -- The policy's answer is the HTTP to send. Verbatim: what the client needs to
      -- resolve this — a WWW-Authenticate challenge, a body it can read — is the
      -- policy's to write, and this plugin does not second-guess it.
      c.decision, c.layer, c.asked = "DENY", ep.identifier, asked
      debug(conf, "denied by ", ep.identifier, " with ", detail.status)
      local h = sideband.client_headers(detail.headers)
      for k, v in pairs(pdp_headers(c)) do h[k] = v end
      return kong.response.exit(detail.status, detail.body or "", h)
    else
      asked[#asked + 1] = { ep = ep, state = detail.state, request = current }
      current = sideband.rewritten(current, detail)
    end
  end

  -- 3) permitted: forward the request as the layers rewrote it
  c.decision, c.asked, c.skipped = "PERMIT", asked, skipped
  if #skipped > 0 then
    kong.log.warn("permit failed open past: ", table.concat(skipped, ", "))
    c.fail_open = table.concat(skipped, ", ")
  end
  sideband.apply_request(original, current, function(...) kong.log.warn(...) end)
end

-- 4) the upstream's response, back through every layer that permitted, in reverse. Kong
--    runs this phase only after a permit, with the whole response buffered.
function SidebandPDP:response(conf)
  local c = kong.ctx.plugin
  if not c or c.decision ~= "PERMIT" or conf.filter_response == false then return end
  local asked, skipped = c.asked or {}, c.skipped or {}
  local current = {
    status = kong.response.get_status(),
    headers = sideband.format_headers(kong.response.get_headers()),
    body = kong.service.response.get_raw_body(),
  }
  local filtered = 0
  for i = #asked, 1, -1 do
    local a = asked[i]
    if not a.ep.request_only then
      local verdict, detail = ask(conf, a.ep, sideband.RESPONSE_PATH, sideband.response_payload(current, a), sideband.classify_response)
      if verdict == "unavailable" then
        fail_layer(c, a.ep, detail, skipped, "response")
      elseif verdict == "refusal" then
        return refuse(c, a.ep, detail, "response")
      else
        current, filtered = detail, filtered + 1
      end
    end
  end
  if #skipped > 0 then c.fail_open = table.concat(skipped, ", ") end
  -- Nothing filtered it: the upstream's response goes as it is, marked.
  if filtered == 0 then
    for k, v in pairs(pdp_headers(c)) do kong.response.set_header(k, v) end
    return
  end
  return sideband.apply_response(current, pdp_headers(c))
end

-- Internals exposed for unit tests; Kong never reads this.
SidebandPDP._TEST = { credential_for = credential_for, discovery_conf = discovery_conf, pdp_headers = pdp_headers }

return SidebandPDP

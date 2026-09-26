-- The wire half of the sideband-pdp plugin: PingAuthorize's Sideband API as Ping's
-- ping-auth plugin speaks it, reshaped so one request can pass through more than one PDP.
--
--   POST {pdp}/sideband/request   the whole HTTP request. Back comes either the request
--                                 to forward — possibly rewritten, with a `state` for the
--                                 second call — or, under `response`, the HTTP response
--                                 to send the client instead.
--   POST {pdp}/sideband/response  the upstream's response, with that `state`. Back comes
--                                 the response to send.
--
-- Nothing here decides anything. What goes out is the request as the client sent it, or
-- as the previous layer rewrote it; what comes back is applied.

local http = require "resty.http"
local contract = require "kong.plugins.authzen-pdp.contract"
local cjson = contract.json

local S = {}

S.REQUEST_PATH = "/sideband/request"
S.RESPONSE_PATH = "/sideband/response"
S.VERSION = "0.1.0"

-- Response headers kept even when the policy provider leaves them out of its answer.
local KEEP = { ["content-length"] = true, date = true, connection = true, vary = true }

-- ---------- headers ----------

--- Kong's name -> value | {values} into the sideband API's list of single-pair objects,
--- one per value, names lower-cased, in a stable order. Returns nil, err for a nested
--- value, which the API has no shape for.
function S.format_headers(headers)
  local out, names = {}, {}
  for k in pairs(headers or {}) do names[#names + 1] = k end
  table.sort(names)
  for _, k in ipairs(names) do
    local v, name = headers[k], k:lower()
    if type(v) ~= "table" then
      out[#out + 1] = { [name] = v }
    else
      for _, item in ipairs(v) do
        if type(item) == "table" then return nil, "header " .. name .. " has a nested value" end
        out[#out + 1] = { [name] = item }
      end
    end
  end
  return out
end

--- The reverse: a list of single-pair objects into name -> {values}, names lower-cased.
function S.flatten_headers(list)
  local out = {}
  for _, pair in ipairs(list or {}) do
    if type(pair) == "table" then
      for k, v in pairs(pair) do
        local name = k:lower()
        out[name] = out[name] or {}
        out[name][#out[name] + 1] = v
      end
    end
  end
  return out
end

local function same_values(a, b)
  if #a ~= #b then return false end
  for i = 1, #a do
    if tostring(a[i]) ~= tostring(b[i]) then return false end
  end
  return true
end

-- ---------- URLs ----------

function S.parse_url(raw)
  local scheme, host, port, rest = tostring(raw or ""):match("^(%a[%w+.-]*)://([^/:?#]+):?(%d*)(.*)$")
  if not scheme then return nil end
  local path, query = rest, nil
  local q = path:find("?", 1, true)
  if q then query = path:sub(q + 1); path = path:sub(1, q - 1) end
  if path == "" then path = "/" end
  return { scheme = scheme:lower(), host = host:lower(), port = port ~= "" and port or nil, path = path, query = query }
end

-- ---------- the client's request ----------

--- The client certificate as the sideband API wants it: the certificate's public key as a
--- JWK, the certificate itself in x5c. Nil when the client presented none. Ping's
--- plugin, unchanged.
local function client_certificate()
  local pem = kong.client.tls.get_full_client_certificate_chain()
  if not pem then return nil end
  local x509 = require "resty.openssl.x509"
  local cert, err = x509.new(pem, "*")
  if not cert then return nil, "client certificate could not be parsed: " .. tostring(err) end
  local key, kerr = cert:get_pubkey()
  if not key then return nil, "client certificate public key could not be read: " .. tostring(kerr) end
  local jwk = cjson.decode(key:tostring("public", "JWK") or "")
  if type(jwk) ~= "table" then return nil, "client certificate public key is not a JWK" end
  jwk.x5c = { ngx.encode_base64(cert:tostring("DER")) }
  return jwk
end

--- The request as the client sent it, in the sideband API's shape. A permit comes back in
--- the same shape, so this is also what travels from one layer to the next.
function S.request_payload(conf)
  local p = {
    source_ip = ngx.var.remote_addr,
    source_port = tonumber(ngx.var.remote_port),
    method = kong.request.get_method(),
    http_version = tostring(ngx.req.http_version()),
    body = kong.request.get_raw_body(),
  }
  local url = kong.request.get_forwarded_scheme() .. "://" .. kong.request.get_forwarded_host() .. ":"
    .. tostring(kong.request.get_forwarded_port()) .. kong.request.get_forwarded_path()
  -- decode_args returns (args, err); the query is normalised through both, as Ping did.
  local args = ngx.decode_args(kong.request.get_raw_query() or "", 100)
  local query = ngx.encode_args(args)
  if query ~= "" then url = url .. "?" .. query end
  p.url = url
  local headers, herr = S.format_headers(kong.request.get_headers())
  if not headers then return nil, herr end
  p.headers = headers
  if conf.forward_client_certificate ~= false then
    local cert, cerr = client_certificate()
    if cerr then return nil, cerr end
    p.client_certificate = cert
  end
  return p
end

--- The next layer's, and the upstream's, request: a permit laid over the request it
--- answered. A field the answer leaves out is unchanged — except the body, which the
--- answer clears by leaving out, as Ping's plugin reads it.
function S.rewritten(current, answer)
  return {
    source_ip = answer.source_ip or current.source_ip,
    source_port = answer.source_port or current.source_port,
    http_version = current.http_version,
    client_certificate = answer.client_certificate or current.client_certificate,
    method = answer.method or current.method,
    url = answer.url or current.url,
    headers = answer.headers or current.headers,
    body = answer.body,
  }
end

-- ---------- the call ----------

--- POST a sideband payload to url. cred is {header, secret} or nil. Returns the
--- resty.http response | nil, err, and true as a third value when the payload could not
--- be encoded at all — a refusal, never an outage a fail-open layer may skip.
function S.post(url, payload, conf, cred)
  local body = cjson.encode(payload)
  if not body then return nil, "the sideband request could not be encoded", true end
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json",
    ["User-Agent"] = "Kong/sideband-pdp " .. S.VERSION,
  }
  if cred then headers[cred.header] = cred.secret end
  local httpc = http.new()
  httpc:set_timeout(conf.connection_timeout_ms or 10000)
  return httpc:request_uri(url, {
    method = "POST",
    body = body,
    headers = headers,
    ssl_verify = conf.verify_service_certificate ~= false,
    keepalive_timeout = conf.connection_keepAlive_ms or 60000,
  })
end

-- The Retry-After a 429 carried, as whole seconds; 1 when it carried none we can read.
local function retry_after(res)
  local hdrs = type(res.headers) == "table" and res.headers or {}
  local after = tonumber(hdrs["Retry-After"] or hdrs["retry-after"])
  if not after or after ~= after or after < 0 or after == math.huge then return 1 end
  return math.floor(after)
end

--- What a sideband call's outcome is, under the contract's rules: "answer" (a 2xx, still
--- to be read), "too_large" (413, an answer about this request), "unavailable" (no
--- answer, a 5xx or a 429 — the only thing a fail-open layer may skip) or "refusal"
--- (any other 3xx or 4xx, or a payload that could not be encoded — closed whatever the
--- layer's rule). The detail is for the log, never for the client.
local function outcome(res, err, who, unencodable)
  if unencodable then return "refusal", { msg = who .. ": " .. tostring(err) } end
  local kind, detail = contract.classify(res, err)
  if kind == "answer" then return "answer" end
  local status = res and tonumber(res.status)
  if kind == "unavailable" then
    if status == 429 then
      local after = retry_after(res)
      return "unavailable", { msg = who .. " rate-limited this PEP (retry after " .. after .. "s)", retry_after = after }
    end
    return "unavailable", { msg = who .. " " .. detail }
  end
  if status == 413 then return "too_large" end
  local msg = who .. " " .. detail
  local body = type(res.body) == "string" and cjson.decode(res.body) or nil
  if contract.is_object(body) and contract.str(body.message) then msg = msg .. ": " .. body.message end
  if status == 401 or status == 403 then msg = msg .. " (is a shared secret configured for it?)" end
  return "refusal", { msg = msg }
end

-- 413 from the API is an answer about this request — too large for it — not an outage.
-- Ping's plugin relays it to the client; so does this one.
local function too_large(res)
  return { status = 413, headers = { { ["content-type"] = "application/json" } }, body = contract.str(res.body) or "" }
end

--- What a /sideband/request answer means. Returns one of
---   "permit",      request  the request to forward, as the policy provider returned it
---   "deny",        response {status, headers (a list), body} to send the client instead
---   "unavailable", {msg, retry_after} for the layer's rule
---   "refusal",     {msg} closed, whatever the layer's rule
function S.classify(res, err, who, unencodable)
  local kind, detail = outcome(res, err, who, unencodable)
  if kind == "too_large" then return "deny", too_large(res) end
  if kind ~= "answer" then return kind, detail end
  local body = type(res.body) == "string" and cjson.decode(res.body) or nil
  if not contract.is_object(body) then
    return "refusal", { msg = who .. " returned an unreadable body" }
  end
  if contract.is_object(body.response) then
    local r = body.response
    return "deny", { status = tonumber(r.response_code) or 403, headers = r.headers or {}, body = r.body }
  end
  return "permit", body
end

--- What a /sideband/response answer means: "response", {status, headers (a list), body}
--- to send the client, or "unavailable" / "refusal", {...}.
function S.classify_response(res, err, who, unencodable)
  local kind, detail = outcome(res, err, who, unencodable)
  if kind == "too_large" then return "response", too_large(res) end
  if kind ~= "answer" then return kind, detail end
  local body = type(res.body) == "string" and cjson.decode(res.body) or nil
  if not contract.is_object(body) or not tonumber(body.response_code) then
    return "refusal", { msg = who .. " returned an unreadable body" }
  end
  return "response", { status = tonumber(body.response_code), headers = body.headers or {}, body = body.body }
end

--- The status strings the sideband API expects beside a code (Ping's table).
local STATUS = {
  [200] = "OK", [201] = "CREATED", [204] = "NO CONTENT", [400] = "BAD REQUEST", [401] = "UNAUTHORIZED",
  [403] = "FORBIDDEN", [404] = "NOT FOUND", [413] = "PAYLOAD TOO LARGE", [429] = "TOO MANY REQUESTS",
  [500] = "INTERNAL SERVER ERROR", [502] = "BAD GATEWAY", [503] = "SERVICE UNAVAILABLE",
}
function S.status_string(code) return STATUS[tonumber(code)] or "" end

--- The upstream's response in the sideband API's shape, for one layer: correlated by the
--- state that layer returned, or by the request it saw when it returned none.
function S.response_payload(resp, layer)
  local p = {
    method = layer.request.method,
    url = layer.request.url,
    http_version = layer.request.http_version,
    response_code = tostring(resp.status),
    response_status = S.status_string(resp.status),
    headers = resp.headers,
    body = resp.body,
  }
  if layer.state ~= nil then p.state = layer.state else p.request = layer.request end
  return p
end

-- ---------- applying answers ----------

--- Apply the difference between the request the client sent and the one the layers agreed
--- on to the request Kong will proxy. Ping's update_request, against a final state rather
--- than one answer. logf receives what could not be applied.
function S.apply_request(original, final, logf)
  local before, after = S.flatten_headers(original.headers), S.flatten_headers(final.headers)
  for name, vals in pairs(before) do
    local new = after[name]
    if not new then
      kong.service.request.clear_header(name)
    elseif not same_values(vals, new) then
      kong.service.request.set_headers({ [name] = new })
    end
  end
  for name, vals in pairs(after) do
    if not before[name] then kong.service.request.set_headers({ [name] = vals }) end
  end
  -- The response phase reads the upstream's body; a compressed one would reach the policy
  -- provider as bytes it cannot read. Ping's plugin, unchanged.
  kong.service.request.clear_header("Accept-Encoding")
  if final.method ~= original.method then kong.service.request.set_method(final.method) end
  if final.url ~= original.url then
    local o, n = S.parse_url(original.url), S.parse_url(final.url)
    if o and n then
      if n.host ~= o.host or n.port ~= o.port then
        kong.service.request.set_header("host", n.host .. (n.port and (":" .. n.port) or ""))
      end
      if n.path ~= o.path then kong.service.request.set_path(n.path) end
      if (n.query or "") ~= (o.query or "") then kong.service.request.set_raw_query(n.query or "") end
      if n.scheme ~= o.scheme then
        logf("the policy provider changed the request scheme (", o.scheme, " -> ", n.scheme, "), which cannot be applied here")
      end
    end
  end
  if final.body ~= original.body and not ((original.body == nil or original.body == "") and final.body == nil) then
    kong.service.request.set_raw_body(final.body or "")
  end
  for _, f in ipairs({ "source_ip", "source_port" }) do
    if tostring(final[f]) ~= tostring(original[f]) then
      logf("the policy provider changed ", f, " (", tostring(original[f]), " -> ", tostring(final[f]), "), which cannot be applied here")
    end
  end
end

--- Send the client the response the layers agreed on, and nothing the upstream said that
--- they did not: a header the policy provider left out is removed (Ping's plugin,
--- unchanged). extra is set on top — the plugin's own X-PDP-* headers.
function S.apply_response(final, extra)
  local keep = S.flatten_headers(final.headers)
  for name in pairs(kong.response.get_headers()) do
    local n = name:lower()
    if not keep[n] and not KEEP[n] then kong.response.clear_header(name) end
  end
  for k, v in pairs(extra or {}) do keep[k] = v end
  return kong.response.exit(final.status, final.body or "", keep)
end

return S

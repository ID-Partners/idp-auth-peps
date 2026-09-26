-- A mocked OpenResty/Kong environment, enough to load and exercise the plugins
-- outside a running gateway.
--
-- The plugins reach for things that only exist inside Kong: the `ngx` and `kong`
-- globals, `cjson.safe`, `resty.http`, `resty.sha256` and `resty.openssl.x509`. Each is
-- stubbed here with the behaviour the plugins rely on, including the parts of the PDK
-- contract that are easy to forget and cost a bypass when forgotten:
--
--   * get_raw_body returns nil and an error for a body larger than
--     client_body_buffer_size (8 KiB by default), unless Kong is 3.9 or later and is
--     given a max the body fits under. An absent body is "", never nil;
--   * get_headers, kong.response.get_headers and ngx.decode_args stop at a cap (100
--     unless told otherwise) and say "truncated";
--   * get_forwarded_* read X-Forwarded-* when the client is a trusted proxy. get_path
--     is the normalised path, get_raw_path the one the client sent;
--   * cjson.safe's encode returns nil for inf and NaN; decode rejects trailing data and
--     decodes a JSON null to cjson.null, which is truthy and is not a table;
--   * kong.response.exit and set_header refuse a value Kong would refuse (a JSON null in
--     a header, a status outside 100-599), by raising, as Kong does;
--   * Kong runs a plugin's response phase only under buffered proxying, which it turns
--     off for an Upgrade request and, before 3.9, for HTTP/2. `M.proxy` models that.

local M = {}

-- ---------- base64 (pure Lua, replaces ngx.encode_base64/decode_base64) ----------

local B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

-- Straightforward byte-wise base64. The clever one-liner versions drop the tail when
-- the input length is not a multiple of three, which silently corrupts every JWT whose
-- payload happens not to divide evenly.
local function encode_base64(data)
  if not data then return nil end
  local out = {}
  for i = 1, #data, 3 do
    local a, b, c = data:byte(i, i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    local c1 = math.floor(n / 262144) % 64
    local c2 = math.floor(n / 4096) % 64
    local c3 = math.floor(n / 64) % 64
    local c4 = n % 64
    out[#out + 1] = B64:sub(c1 + 1, c1 + 1) .. B64:sub(c2 + 1, c2 + 1) ..
      (b and B64:sub(c3 + 1, c3 + 1) or '=') ..
      (c and B64:sub(c4 + 1, c4 + 1) or '=')
  end
  return table.concat(out)
end

local function decode_base64(data)
  if not data then return nil end
  data = data:gsub('[^' .. B64:gsub('%p', '%%%0') .. '=]', '')
  local out = {}
  for i = 1, #data, 4 do
    local chunk = data:sub(i, i + 3)
    local vals = {}
    for j = 1, 4 do
      local ch = chunk:sub(j, j)
      vals[j] = (ch == '' or ch == '=') and 0 or (B64:find(ch, 1, true) - 1)
    end
    local n = vals[1] * 262144 + vals[2] * 4096 + vals[3] * 64 + vals[4]
    local pad = select(2, chunk:gsub('=', '')) + (4 - #chunk)
    out[#out + 1] = string.char(math.floor(n / 65536) % 256)
    if pad < 2 then out[#out + 1] = string.char(math.floor(n / 256) % 256) end
    if pad < 1 then out[#out + 1] = string.char(n % 256) end
  end
  return table.concat(out)
end

function M.b64url(s)
  return (encode_base64(s):gsub('%+', '-'):gsub('/', '_'):gsub('=', ''))
end

-- ---------- a JSON encoder/decoder standing in for cjson.safe ----------

-- cjson.null is a lightuserdata: truthy, not a table, not indexable. A function is the
-- closest thing plain Lua has — `type(x) == "table"` is false for it, as it is in Kong,
-- so code that forgets a null is caught here rather than in production.
local NULL = function() end
M.null = NULL

-- The metatable cjson gives a decoded array when decode_array_with_array_mt is on, and
-- honours on encode, so [] and {} stay apart.
local ARRAY_MT = { __name = 'cjson.array' }

local function skip_ws(s, i)
  return select(2, s:find('^[ \t\r\n]*', i)) + 1
end

local function utf8_char(cp)
  if cp < 0x80 then return string.char(cp) end
  if cp < 0x800 then return string.char(0xC0 + math.floor(cp / 64), 0x80 + cp % 64) end
  if cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 4096), 0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
  end
  return string.char(0xF0 + math.floor(cp / 262144), 0x80 + math.floor(cp / 4096) % 64,
    0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
end

local decode_value

local function decode_string(s, i)
  local out, j = {}, i + 1
  while j <= #s do
    local c = s:sub(j, j)
    if c == '"' then return table.concat(out), j + 1 end
    if c == '\\' then
      local esc = s:sub(j + 1, j + 1)
      local map = { n = '\n', t = '\t', r = '\r', b = '\b', f = '\f', ['"'] = '"', ['\\'] = '\\', ['/'] = '/' }
      if esc == 'u' then
        local cp = tonumber(s:sub(j + 2, j + 5), 16)
        assert(cp, 'bad \\u escape')
        j = j + 6
        if cp >= 0xD800 and cp <= 0xDBFF and s:sub(j, j + 1) == '\\u' then
          local lo = tonumber(s:sub(j + 2, j + 5), 16)
          if lo and lo >= 0xDC00 and lo <= 0xDFFF then
            cp = 0x10000 + (cp - 0xD800) * 1024 + (lo - 0xDC00)
            j = j + 6
          end
        end
        out[#out + 1] = utf8_char(cp)
      else
        assert(map[esc], 'bad escape')
        out[#out + 1] = map[esc]
        j = j + 2
      end
    else
      out[#out + 1] = c
      j = j + 1
    end
  end
  error('unterminated string')
end

local function decode_object(s, i, arrays)
  local obj, j = {}, skip_ws(s, i + 1)
  if s:sub(j, j) == '}' then return obj, j + 1 end
  while true do
    assert(s:sub(j, j) == '"', 'expected a key')
    local key
    key, j = decode_string(s, j)
    j = skip_ws(s, j)
    assert(s:sub(j, j) == ':', 'expected :')
    local val
    val, j = decode_value(s, skip_ws(s, j + 1), arrays)
    obj[key] = val -- a repeated key: the last wins, as in cjson
    j = skip_ws(s, j)
    local c = s:sub(j, j)
    if c == '}' then return obj, j + 1 end
    assert(c == ',', 'expected , or }')
    j = skip_ws(s, j + 1)
  end
end

local function decode_array(s, i, arrays)
  local arr, j = {}, skip_ws(s, i + 1)
  if arrays then setmetatable(arr, ARRAY_MT) end
  if s:sub(j, j) == ']' then return arr, j + 1 end
  while true do
    local val
    val, j = decode_value(s, j, arrays)
    arr[#arr + 1] = val
    j = skip_ws(s, j)
    local c = s:sub(j, j)
    if c == ']' then return arr, j + 1 end
    assert(c == ',', 'expected , or ]')
    j = skip_ws(s, j + 1)
  end
end

decode_value = function(s, i, arrays)
  i = skip_ws(s, i)
  local c = s:sub(i, i)
  if c == '{' then return decode_object(s, i, arrays) end
  if c == '[' then return decode_array(s, i, arrays) end
  if c == '"' then return decode_string(s, i) end
  if s:sub(i, i + 3) == 'true' then return true, i + 4 end
  if s:sub(i, i + 4) == 'false' then return false, i + 5 end
  if s:sub(i, i + 3) == 'null' then return NULL, i + 4 end
  -- A JSON number. 1e999 is valid JSON and decodes to inf, as strtod gives it.
  local num = s:match('^-?%d+%.?%d*[eE]?[-+]?%d*', i)
  if num and num ~= '' then return tonumber(num), i + #num end
  error('unexpected character at ' .. i .. ': ' .. c)
end

local function encode_string(v)
  return '"' .. v:gsub('[%c"\\]', function(ch)
    local named = { ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }
    return named[ch] or string.format('\\u%04x', ch:byte())
  end) .. '"'
end

local function is_sequence(t)
  local n = 0
  for k in pairs(t) do
    if type(k) ~= 'number' or k < 1 or k % 1 ~= 0 then return false end
    n = n + 1
  end
  return n > 0 and n == #t
end

local function json_encode(v, seen)
  if v == nil or v == NULL then return 'null' end
  local t = type(v)
  if t == 'boolean' then return tostring(v) end
  if t == 'number' then
    if v ~= v or v == math.huge or v == -math.huge then
      error('Cannot serialise number: must not be NaN or Infinity', 0)
    end
    if math.type and math.type(v) == 'integer' then return tostring(v) end
    return string.format('%.14g', v)
  end
  if t == 'string' then return encode_string(v) end
  if t == 'table' then
    seen = seen or {}
    if seen[v] then error('Cannot serialise, excessive nesting', 0) end
    seen[v] = true
    local out
    if getmetatable(v) == ARRAY_MT or is_sequence(v) then
      local parts = {}
      for _, item in ipairs(v) do parts[#parts + 1] = json_encode(item, seen) end
      out = '[' .. table.concat(parts, ',') .. ']'
    else
      local keys = {}
      for k in pairs(v) do keys[#keys + 1] = tostring(k) end
      table.sort(keys)
      local parts = {}
      for _, k in ipairs(keys) do
        local val = v[k]
        if val == nil then val = v[tonumber(k)] end
        parts[#parts + 1] = encode_string(k) .. ':' .. json_encode(val, seen)
      end
      out = '{' .. table.concat(parts, ',') .. '}'
    end
    seen[v] = nil
    return out
  end
  error('Cannot serialise ' .. t, 0)
end

-- A cjson.safe module (or an instance from .new()): its own decode_array_with_array_mt
-- setting, nil and an error where cjson would raise.
local function new_cjson()
  local arrays = false
  local inst = { null = NULL, array_mt = ARRAY_MT, empty_array_mt = ARRAY_MT }
  function inst.decode_array_with_array_mt(on) arrays = on and true or false end
  function inst.decode_invalid_numbers() end -- this decoder never accepts them
  function inst.decode(s)
    if type(s) ~= 'string' then return nil, 'bad argument: expected string' end
    local ok, v, pos = pcall(decode_value, s, 1, arrays)
    if not ok then return nil, v end
    pos = skip_ws(s, pos)
    if pos <= #s then return nil, 'Expected the end but found invalid token at character ' .. pos end
    return v
  end
  function inst.encode(v)
    local ok, out = pcall(json_encode, v)
    if not ok then return nil, out end
    return out
  end
  inst.new = new_cjson
  return inst
end

-- ---------- what Kong refuses ----------

local function check_header_value(name, value)
  local t = type(value)
  if t == 'string' or t == 'number' or t == 'boolean' then return end
  if t == 'table' then
    for _, v in ipairs(value) do
      if type(v) ~= 'string' then error(('invalid header value in array %q: got %s, expected string'):format(name, type(v)), 3) end
    end
    return
  end
  error(('invalid header value for %q: got %s, expected array of string, string, number or boolean'):format(name, t), 3)
end

-- ---------- the mock environment ----------

local current -- the state of the last install, for M.proxy

--- install stubs and return a handle for driving and inspecting one request.
-- opts:
--   method, path (normalised, as kong.request.get_path returns it), raw_path, query,
--   headers, body, scheme, host, port, http_version, remote_addr, remote_port
--   trusted_proxy            the client is in trusted_ips: get_forwarded_* read X-Forwarded-*
--   client_body_buffer_size  default 8192; a larger body is "on disk"
--   kong_version_num         default 3009003 (3.9.3); below 3009000 get_raw_body takes no
--                            max and HTTP/2 turns response buffering off
--   route, service           what kong.router returns
--   pdp                      the PDP / coaz-pep responder: a table (JSON), false (connection
--                            refused) or function(url, req)
--   upstream                 {status, headers, body}: the response the response phase sees
--   x509, client_cert_pem    the client certificate parser and chain
function M.install(opts)
  opts = opts or {}
  local state = {
    -- what the plugin did
    exited = nil,          -- { status, body, headers } if kong.response.exit was called
    upstream_headers = {}, -- headers injected for the proxied request
    pdp_requests = {},     -- every request body sent to the PDP or coaz-pep
    logs = {},
  }
  current = state

  local headers = {}
  for k, v in pairs(opts.headers or {}) do headers[k:lower()] = v end
  local version_num = opts.kong_version_num or 3009003

  -- A header table capped the way ngx.req.get_headers caps it: max values (100 unless
  -- told), then "truncated".
  local function capped(t, max)
    max = max or 100
    local names, count = {}, 0
    for k, v in pairs(t) do
      names[#names + 1] = k
      count = count + (type(v) == 'table' and #v or 1)
    end
    if max == 0 or count <= max then return t end
    table.sort(names)
    local out, n = {}, 0
    for _, k in ipairs(names) do
      local v = t[k]
      if type(v) == 'table' then
        local kept = {}
        for _, item in ipairs(v) do
          if n < max then kept[#kept + 1] = item; n = n + 1 end
        end
        if #kept > 0 then out[k] = kept end
      elseif n < max then
        out[k] = v; n = n + 1
      end
    end
    return out, 'truncated'
  end

  -- The pieces of the nginx API the sideband plugin reaches for beyond the PDK: the
  -- client's address, the raw request line, and the query-string helpers.
  -- Two return values, as OpenResty's: a caller that feeds the result straight into
  -- another one-argument function gets the same error it would get in Kong. And the cap:
  -- 100 arguments unless told otherwise, 0 for none, "truncated" past it.
  local function decode_args(str, max)
    local out, n, truncated = {}, 0, false
    max = max or 100
    for pair in (str or ''):gmatch('[^&]+') do
      local k, v = pair:match('^([^=]*)=?(.*)$')
      if k and k ~= '' then
        if max > 0 and n >= max then truncated = true; break end
        n = n + 1
        out[k] = v
      end
    end
    if truncated then return out, 'truncated' end
    return out, nil
  end
  local function encode_args(t, extra)
    assert(extra == nil, 'expecting 1 argument but seen 2')
    local keys = {}
    for k in pairs(t or {}) do keys[#keys + 1] = k end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
      parts[#parts + 1] = (t[k] == true or t[k] == '') and k or (k .. '=' .. tostring(t[k]))
    end
    return table.concat(parts, '&')
  end
  _G.ngx = {
    encode_base64 = encode_base64,
    decode_base64 = decode_base64,
    null = NULL,
    -- A settable clock, so cache expiry can be driven without sleeping.
    now = function() return state.now end,
    var = { remote_addr = opts.remote_addr or '203.0.113.7', remote_port = opts.remote_port or 51234 },
    req = {
      get_method = function() return opts.method or 'GET' end,
      get_headers = function(max) return capped(headers, max) end,
      http_version = function() return opts.http_version or 1.1 end,
    },
    decode_args = decode_args,
    encode_args = encode_args,
    escape_uri = function(v)
      return (tostring(v):gsub('[^%w%-_.~]', function(c) return string.format('%%%02X', c:byte()) end))
    end,
  }
  state.now = opts.now or 1700000000

  -- The handler requires its siblings by module name; outside Kong that name resolves
  -- to nothing, so point it at the file. Reloaded per install: the modules hold
  -- per-worker state that must not leak between tests.
  local siblings = {
    ['kong.plugins.authzen-pdp.discovery'] = 'authzen-pdp/discovery.lua',
    ['kong.plugins.authzen-pdp.contract'] = 'authzen-pdp/contract.lua',
    ['kong.plugins.sideband-pdp.sideband'] = 'sideband-pdp/sideband.lua',
  }
  for name, file in pairs(siblings) do
    package.loaded[name] = nil
    package.preload[name] = function() return assert(loadfile(file))() end
  end
  -- The client certificate parser. A test that forwards a certificate supplies its own
  -- (opts.x509); by default nothing presents one, so nothing parses one.
  package.loaded['resty.openssl.x509'] = opts.x509 or {
    new = function() error('no client certificate in this test') end,
  }

  package.loaded['cjson.safe'] = new_cjson()
  package.loaded['cjson'] = package.loaded['cjson.safe']

  -- A deterministic stand-in for SHA-256. The digest value is irrelevant to the
  -- plugin's logic; what matters is the CANONICAL JSON fed to it (RFC 7638 member
  -- ordering), so the input is captured for assertions instead.
  package.loaded['resty.sha256'] = {
    new = function()
      return {
        _buf = '',
        update = function(self, s) self._buf = self._buf .. s; state.last_sha_input = s; return true end,
        final = function(self) return 'digest:' .. self._buf end,
      }
    end,
  }

  package.loaded['resty.http'] = {
    new = function()
      return {
        set_timeout = function() end,
        request_uri = function(_, url, req)
          state.pdp_requests[#state.pdp_requests + 1] = { url = url, body = req.body, headers = req.headers, ssl_verify = req.ssl_verify }
          local responder = opts.pdp
          if type(responder) == 'function' then return responder(url, req) end
          if responder == false then return nil, 'connection refused' end
          return { status = 200, body = json_encode(responder or { decision = true }) }
        end,
      }
    end,
  }

  -- The upstream's answer, for the response phase: what the plugin sees as the
  -- proxied response before it is filtered.
  local upstream = opts.upstream or {}
  state.response_status = upstream.status or 200
  state.response_hdrs = {}
  for k, v in pairs(upstream.headers or {}) do state.response_hdrs[k:lower()] = v end

  local path = opts.path or '/'
  local function forwarded(name, real)
    if opts.trusted_proxy and headers['x-forwarded-' .. name] then
      local v = headers['x-forwarded-' .. name]
      return type(v) == 'table' and v[1] or v
    end
    return real
  end

  _G.kong = {
    version = '3.9.3',
    version_num = version_num,
    request = {
      get_method = function() return opts.method or 'GET' end,
      get_path = function() return path end,
      get_raw_path = function() return opts.raw_path or path end,
      get_scheme = function() return opts.scheme or 'https' end,
      get_host = function() return opts.host or 'api.example' end,
      get_port = function() return opts.port or 443 end,
      get_http_version = function() return opts.http_version or 1.1 end,
      get_header = function(name)
        local v = headers[name:lower()]
        if type(v) == 'table' then return v[1] end
        return v
      end,
      get_headers = function(max)
        if max ~= nil and (max < 1 or max > 1000) then error('max_headers must be >= 1 and <= 1000', 2) end
        return capped(headers, max)
      end,
      get_raw_body = function(max)
        local body = opts.body
        if body == nil then return '' end
        if #body <= (opts.client_body_buffer_size or 8192) then return body end
        -- On disk. Before 3.9 the PDK took no argument and gave up here.
        if version_num < 3009000 then max = nil end
        if not max or max < 0 then
          return nil, "request body did not fit into client body buffer, consider raising 'client_body_buffer_size'"
        end
        if max > 0 and #body > max then
          return nil, ('request body file too big: %d > %d'):format(#body, max)
        end
        return body
      end,
      get_body = function()
        if not opts.body then return nil end
        return (package.loaded['cjson.safe'].decode(opts.body))
      end,
      get_raw_query = function() return opts.query or '' end,
      get_query = function(max) return decode_args(opts.query or '', max) end,
      get_forwarded_scheme = function() return forwarded('proto', opts.scheme or 'https') end,
      get_forwarded_host = function() return forwarded('host', opts.host or 'api.example') end,
      get_forwarded_port = function() return tonumber(forwarded('port', opts.port or 443)) end,
      get_forwarded_path = function() return forwarded('path', path) end,
      get_forwarded_prefix = function() return forwarded('prefix', opts.stripped_prefix) end,
    },
    router = {
      get_route = function() return opts.route end,
      get_service = function() return opts.service end,
    },
    response = {
      exit = function(status, body, hdrs)
        if type(status) ~= 'number' or status < 100 or status > 599 then
          error('code must be a number between 100 and 599', 2)
        end
        if body ~= nil and type(body) ~= 'string' and type(body) ~= 'table' then
          error('body must be a nil, string or table', 2)
        end
        for k, v in pairs(hdrs or {}) do check_header_value(k, v) end
        state.exited = { status = status, body = body, headers = hdrs }
        error({ __kong_exit = true }, 0) -- Kong's exit is non-local; unwind like it does
      end,
      set_header = function(k, v)
        check_header_value(k, v)
        state.response_headers = state.response_headers or {}
        state.response_headers[k] = v
      end,
      get_status = function() return state.response_status end,
      get_headers = function(max) return capped(state.response_hdrs, max) end,
      get_header = function(k) return state.response_hdrs[k:lower()] end,
      clear_header = function(k)
        state.response_hdrs[k:lower()] = nil
        state.cleared_response_headers = state.cleared_response_headers or {}
        state.cleared_response_headers[#state.cleared_response_headers + 1] = k:lower()
      end,
    },
    service = {
      request = {
        set_header = function(k, v)
          check_header_value(k, v)
          state.upstream_headers[k] = v
        end,
        set_headers = function(t)
          for k, v in pairs(t) do check_header_value(k, v); state.upstream_headers[k] = v end
        end,
        clear_header = function(k)
          state.upstream_headers[k] = nil
          state.cleared_upstream_headers = state.cleared_upstream_headers or {}
          state.cleared_upstream_headers[#state.cleared_upstream_headers + 1] = k
        end,
        set_method = function(m) state.upstream_method = m end,
        set_path = function(p) state.upstream_path = p end,
        set_raw_query = function(q) state.upstream_query = q end,
        set_raw_body = function(b) state.upstream_body = b end,
      },
      response = {
        get_raw_body = function() return upstream.body end,
      },
    },
    client = {
      tls = {
        get_full_client_certificate_chain = function() return opts.client_cert_pem end,
      },
    },
    log = setmetatable({}, {
      __index = function(_, level)
        return function(...)
          local parts = {}
          for i = 1, select('#', ...) do parts[#parts + 1] = tostring((select(i, ...))) end
          state.logs[#state.logs + 1] = table.concat(parts, ' ')
          state.log_levels = state.log_levels or {}
          state.log_levels[#state.logs] = level
        end
      end,
    }),
    ctx = { plugin = {} },
  }

  state.kong = _G.kong
  return state
end

--- run the plugin's access phase, absorbing Kong's non-local exit.
function M.run_access(handler, conf)
  local ok, err = pcall(handler.access, handler, conf)
  if not ok and not (type(err) == 'table' and err.__kong_exit) then
    error(err, 0)
  end
end

--- run the plugin's response phase the same way. Kong runs it only when access did not
--- exit; a test that calls it after a deny is asking the wrong question.
function M.run_response(handler, conf)
  local ok, err = pcall(handler.response, handler, conf)
  if not ok and not (type(err) == 'table' and err.__kong_exit) then
    error(err, 0)
  end
end

--- one request through Kong as Kong runs it: access; then, when access let it through
--- and the plugin has a response phase, that phase only under buffered proxying — which
--- Kong turns off for an Upgrade request and, before 3.9, for HTTP/2; then header_filter
--- on whatever is sent. state.response_ran says whether the response phase ran.
function M.proxy(handler, conf)
  local state = current
  M.run_access(handler, conf)
  state.response_ran = false
  if not state.exited and handler.response then
    local kong_ = state.kong
    local upgrade = kong_.request.get_header('upgrade')
    local http2 = (kong_.request.get_http_version() or 1.1) >= 2
    local buffered = not (upgrade and upgrade:lower() == 'websocket')
      and not (http2 and kong_.version_num < 3009000)
    if buffered then
      state.response_ran = true
      M.run_response(handler, conf)
    end
  end
  if handler.header_filter then handler:header_filter(conf) end
  return state
end

--- build a compact JWT with the given header and claims (signature is not checked).
function M.jwt(claims, header)
  local h = M.b64url(json_encode(header or { alg = 'ES256', typ = 'JWT' }))
  local c = M.b64url(json_encode(claims))
  return h .. '.' .. c .. '.sig'
end

M.json_encode = json_encode
M.json_decode = function(s) return (decode_value(s, 1, true)) end
M.array_mt = ARRAY_MT
function M.array(t) return setmetatable(t or {}, ARRAY_MT) end

return M

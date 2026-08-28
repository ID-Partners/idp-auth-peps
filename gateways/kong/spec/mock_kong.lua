-- A mocked OpenResty/Kong environment, enough to load and exercise the plugin
-- outside a running gateway.
--
-- The plugin reaches for four things that only exist inside Kong: the `ngx` and `kong`
-- globals, `cjson.safe`, `resty.http` and `resty.sha256`. Each is stubbed here with the
-- smallest behaviour the plugin actually relies on, so a test can drive a request
-- through `access()` and inspect what came out.

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

-- ---------- a minimal JSON encoder/decoder standing in for cjson.safe ----------

local function skip_ws(s, i)
  return select(2, s:find('^[ \t\r\n]*', i)) + 1
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
        out[#out + 1] = '?' -- the plugin never inspects escaped unicode
        j = j + 6
      else
        out[#out + 1] = map[esc] or esc
        j = j + 2
      end
    else
      out[#out + 1] = c
      j = j + 1
    end
  end
  error('unterminated string')
end

local function decode_object(s, i)
  local obj, j = {}, skip_ws(s, i + 1)
  if s:sub(j, j) == '}' then return obj, j + 1 end
  while true do
    local key
    key, j = decode_string(s, skip_ws(s, j))
    j = skip_ws(s, j)
    assert(s:sub(j, j) == ':', 'expected :')
    local val
    val, j = decode_value(s, skip_ws(s, j + 1))
    obj[key] = val
    j = skip_ws(s, j)
    local c = s:sub(j, j)
    if c == '}' then return obj, j + 1 end
    assert(c == ',', 'expected , or }')
    j = skip_ws(s, j + 1)
  end
end

local function decode_array(s, i)
  local arr, j = {}, skip_ws(s, i + 1)
  if s:sub(j, j) == ']' then return arr, j + 1 end
  while true do
    local val
    val, j = decode_value(s, j)
    arr[#arr + 1] = val
    j = skip_ws(s, j)
    local c = s:sub(j, j)
    if c == ']' then return arr, j + 1 end
    assert(c == ',', 'expected , or ]')
    j = skip_ws(s, j + 1)
  end
end

decode_value = function(s, i)
  i = skip_ws(s, i)
  local c = s:sub(i, i)
  if c == '{' then return decode_object(s, i) end
  if c == '[' then return decode_array(s, i) end
  if c == '"' then return decode_string(s, i) end
  if s:sub(i, i + 3) == 'true' then return true, i + 4 end
  if s:sub(i, i + 4) == 'false' then return false, i + 5 end
  if s:sub(i, i + 3) == 'null' then return nil, i + 4 end
  local num = s:match('^-?%d+%.?%d*[eE]?[-+]?%d*', i)
  if num and num ~= '' then return tonumber(num), i + #num end
  error('unexpected character at ' .. i .. ': ' .. c)
end

local function json_encode(v, seen)
  local t = type(v)
  if v == nil then return 'null' end
  if t == 'boolean' or t == 'number' then return tostring(v) end
  if t == 'string' then return '"' .. v:gsub('[\\"]', '\\%0'):gsub('\n', '\\n') .. '"' end
  if t == 'table' then
    seen = seen or {}
    if seen[v] then return 'null' end
    seen[v] = true
    if #v > 0 then
      local parts = {}
      for _, item in ipairs(v) do parts[#parts + 1] = json_encode(item, seen) end
      return '[' .. table.concat(parts, ',') .. ']'
    end
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = k end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
      parts[#parts + 1] = '"' .. k .. '":' .. json_encode(v[k], seen)
    end
    return '{' .. table.concat(parts, ',') .. '}'
  end
  return 'null'
end

-- ---------- the mock environment ----------

--- install stubs and return a handle for driving and inspecting one request.
-- @param opts method, path, headers, body, pdp (the PDP response table or a function)
function M.install(opts)
  opts = opts or {}
  local state = {
    -- what the plugin did
    exited = nil,          -- { status, body, headers } if kong.response.exit was called
    upstream_headers = {}, -- headers injected for the proxied request
    pdp_requests = {},     -- every request body sent to the PDP or coaz-pep
    logs = {},
  }

  _G.ngx = {
    encode_base64 = encode_base64,
    decode_base64 = decode_base64,
    null = setmetatable({}, { __tostring = function() return 'null' end }),
  }

  package.loaded['cjson.safe'] = {
    decode = function(s)
      if type(s) ~= 'string' or s == '' then return nil, 'not a string' end
      local ok, v = pcall(function() return (decode_value(s, 1)) end)
      if not ok then return nil, v end
      return v
    end,
    encode = function(v) return json_encode(v) end,
  }
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

  local headers = {}
  for k, v in pairs(opts.headers or {}) do headers[k:lower()] = v end

  _G.kong = {
    request = {
      get_method = function() return opts.method or 'GET' end,
      get_path = function() return opts.path or '/' end,
      get_header = function(name) return headers[name:lower()] end,
      get_raw_body = function() return opts.body end,
      get_body = function()
        if not opts.body then return nil end
        return (package.loaded['cjson.safe'].decode(opts.body))
      end,
    },
    response = {
      exit = function(status, body, hdrs)
        state.exited = { status = status, body = body, headers = hdrs }
        error({ __kong_exit = true }, 0) -- Kong's exit is non-local; unwind like it does
      end,
      set_header = function(k, v) state.response_headers = state.response_headers or {}; state.response_headers[k] = v end,
    },
    service = {
      request = {
        set_header = function(k, v) state.upstream_headers[k] = v end,
      },
    },
    log = setmetatable({}, {
      __index = function() return function(...) state.logs[#state.logs + 1] = table.concat({ ... }, ' ') end end,
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

--- build a compact JWT with the given header and claims (signature is not checked).
function M.jwt(claims, header)
  local h = M.b64url(json_encode(header or { alg = 'ES256', typ = 'JWT' }))
  local c = M.b64url(json_encode(claims))
  return h .. '.' .. c .. '.sig'
end

M.json_encode = json_encode
M.json_decode = function(s) return (decode_value(s, 1)) end

return M

-- The rules both Kong plugins share with every other PEP in this repository: what counts
-- as a PDP being unavailable rather than refusing, how a request body is read, what a
-- header built from PDP data may carry, and how a JSON null reads. sideband-pdp requires
-- this module by name, as it does discovery.lua, so there is one copy of each rule in Lua.

local cjson_safe = require "cjson.safe"

local C = {}

-- A private cjson instance. The shared cjson.safe belongs to Kong and to every other
-- plugin in the worker, and its settings are not ours to change. This one marks decoded
-- arrays, so `[]` and `{}` stay apart, and refuses the non-JSON numbers (hex, NaN,
-- Infinity) that cjson otherwise accepts and no other PEP here does.
local cjson = cjson_safe.new()
cjson.decode_array_with_array_mt(true)
cjson.decode_invalid_numbers(false)
C.json = cjson
C.null = cjson.null

C.MAX_BODY = 1048576

-- ---------- JSON ----------

--- v if it is a string, else nil. A JSON null is truthy in Lua (cjson.null), so a field
--- read straight out of a document would pass an `or` default and break a header.
function C.str(v)
  if type(v) == "string" then return v end
  return nil
end

function C.is_array(v)
  if type(v) ~= "table" then return false end
  if getmetatable(v) == cjson.array_mt then return true end
  local n = 0
  for k in pairs(v) do
    if type(k) ~= "number" then return false end
    n = n + 1
  end
  return n > 0 and n == #v
end

function C.is_object(v)
  return type(v) == "table" and not C.is_array(v)
end

-- ---------- outcomes ----------

--- What an HTTP answer from a PDP, a resolver or coaz-pep is, under the contract's
--- outcomes:
---   "unavailable"  a transport error, a timeout, a 5xx or a 429: the only thing a
---                  fail-open layer may skip
---   "refusal"      a 3xx or a 4xx: closed whatever the layer's rule, and logged as such
---   "answer"       a 2xx, still to be read (and an unreadable one is a refusal too)
--- The second value is detail for the log, never for the client.
function C.classify(res, err)
  if not res then return "unavailable", "no answer: " .. tostring(err) end
  local status = tonumber(res.status) or 0
  if status >= 500 or status == 429 then return "unavailable", "answered " .. status end
  if status >= 200 and status < 300 then return "answer" end
  return "refusal", "answered " .. status
end

-- ---------- the request ----------

--- The request body, whole and no larger than max, or nil and why. Kong keeps a body
--- larger than client_body_buffer_size on disk; from 3.9 it reads it back up to `max`
--- bytes, and before that the argument is ignored and the body is out of reach. A body
--- held in memory comes back whatever max is asked for, so the limit is checked here as
--- well. Either way nil means "cannot authorise", never "no body": an absent body is "".
function C.read_body(max)
  max = max or C.MAX_BODY
  local ok, body, err = pcall(kong.request.get_raw_body, max)
  if not ok then return nil, tostring(body) end
  if body == nil then return nil, err or "the request body could not be read" end
  if #body > max then return nil, "the request body is " .. #body .. " bytes, over the limit of " .. max end
  return body
end

--- Whether s is well-formed UTF-8 (RFC 3629): no stray continuation bytes, no overlong
--- forms, no surrogates, nothing past U+10FFFF.
function C.valid_utf8(s)
  local i, n = 1, #s
  while i <= n do
    local j = s:find("[\128-\255]", i)
    if not j then return true end
    local c, len = s:byte(j), 0
    if c >= 0xC2 and c <= 0xDF then len = 2
    elseif c >= 0xE0 and c <= 0xEF then len = 3
    elseif c >= 0xF0 and c <= 0xF4 then len = 4
    else return false end
    if j + len - 1 > n then return false end
    local c2 = s:byte(j + 1)
    if (c == 0xE0 and c2 < 0xA0) or (c == 0xED and c2 > 0x9F)
      or (c == 0xF0 and c2 < 0x90) or (c == 0xF4 and c2 > 0x8F) then
      return false
    end
    for k = j + 1, j + len - 1 do
      local b = s:byte(k)
      if b < 0x80 or b > 0xBF then return false end
    end
    i = j + len
  end
  return true
end

-- ---------- what a client is sent ----------

--- A header value built from PDP data: printable ASCII only. CR, LF and tab become a
--- space (a line break would end the header), other control characters and every byte
--- outside ASCII are dropped: Kong writes bytes, a client reads Latin-1, and a
--- multi-byte UTF-8 character would reach it as something else. Nil for a value that is
--- not a string, a number or a boolean — a JSON null included.
function C.header_value(v)
  local t = type(v)
  if t == "number" or t == "boolean" then return tostring(v) end
  if t ~= "string" then return nil end
  v = v:gsub("[\r\n\t]", " ")
  v = v:gsub("%c", "")
  v = v:gsub("[\128-\255]", "")
  return v
end

--- The inside of an RFC 9110 quoted-string, for a WWW-Authenticate parameter: the
--- header-safe value with \ and " escaped.
function C.quoted(v)
  return ((C.header_value(v) or ""):gsub('[\\"]', "\\%0"))
end

return C

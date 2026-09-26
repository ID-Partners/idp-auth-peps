-- The mock's own contract: the PDK behaviours that hid bypasses in these plugins, pinned
-- so the mock cannot quietly drift back to a friendlier Kong than the real one.

local mock = require 'spec.mock_kong'

describe('the mocked PDK', function()
  it('gives up on a body larger than client_body_buffer_size unless Kong 3.9+ is given a max', function()
    local big = string.rep('x', 9 * 1024)
    mock.install({ body = big })
    local body, err = kong.request.get_raw_body()
    assert.is_nil(body)
    assert.matches('did not fit into client body buffer', err)
    assert.equal(big, kong.request.get_raw_body(16384))
    local none, too_big = kong.request.get_raw_body(4096)
    assert.is_nil(none)
    assert.matches('too big', too_big)
    -- Before 3.9 the argument is ignored.
    mock.install({ body = big, kong_version_num = 3007001 })
    assert.is_nil((kong.request.get_raw_body(16384)))
    -- An absent body is "", never nil.
    mock.install({})
    assert.equal('', kong.request.get_raw_body())
  end)

  it('caps headers and query arguments, and says so', function()
    local headers = {}
    for i = 1, 150 do headers['x-h' .. i] = 'v' end
    mock.install({ headers = headers, query = string.rep('a=1&', 150) })
    local h, herr = kong.request.get_headers()
    assert.equal('truncated', herr)
    local n = 0
    for _ in pairs(h) do n = n + 1 end
    assert.equal(100, n)
    local all, none = kong.request.get_headers(1000)
    assert.is_nil(none)
    assert.equal('v', all['x-h150'])
    local _, aerr = ngx.decode_args(kong.request.get_raw_query())
    assert.equal('truncated', aerr)
  end)

  it('reads X-Forwarded-* only for a trusted proxy', function()
    local fwd = { ['x-forwarded-path'] = '/public/status', ['x-forwarded-host'] = 'public.example' }
    mock.install({ path = '/admin/users/1', headers = fwd })
    assert.equal('/admin/users/1', kong.request.get_forwarded_path())
    mock.install({ path = '/admin/users/1', headers = fwd, trusted_proxy = true })
    assert.equal('/public/status', kong.request.get_forwarded_path())
    assert.equal('public.example', kong.request.get_forwarded_host())
    assert.equal('/admin/users/1', kong.request.get_path())
  end)

  it('encodes no inf or NaN, rejects trailing data, and decodes null to a truthy non-table', function()
    mock.install({})
    local cjson = require('cjson.safe').new()
    cjson.decode_array_with_array_mt(true)
    assert.is_nil((cjson.encode({ amount = math.huge })))
    assert.is_nil((cjson.encode({ amount = 0 / 0 })))
    assert.is_nil((cjson.decode('{"a":1} x')))
    local v = cjson.decode('{"a":null,"b":1e999,"c":[],"d":{}}')
    assert.is_truthy(v.a)
    assert.equal(cjson.null, v.a)
    assert.is_not.equal('table', type(v.a))
    assert.equal(math.huge, v.b)
    assert.equal(cjson.array_mt, getmetatable(v.c))
    assert.is_nil(getmetatable(v.d))
    assert.equal('[]', cjson.encode(v.c))
    assert.equal('\1', cjson.decode('"\\u0001"'))
    assert.equal('method', cjson.decode('"\\u006dethod"'))
  end)

  it('refuses what Kong refuses: a null header value, a status outside 100-599', function()
    mock.install({})
    assert.has_error(function() kong.response.set_header('X-PDP-Reason', ngx.null) end)
    assert.has_error(function() kong.response.exit(1000, 'x') end)
    assert.has_error(function() kong.service.request.set_header('X-Auth-Principal', ngx.null) end)
  end)

  it('runs the response phase only under buffered proxying', function()
    local ran = 0
    local handler = { access = function() end, response = function() ran = ran + 1 end }
    mock.install({})
    assert.is_true(mock.proxy(handler, {}).response_ran)
    mock.install({ headers = { upgrade = 'websocket', connection = 'Upgrade' } })
    assert.is_false(mock.proxy(handler, {}).response_ran)
    mock.install({ http_version = 2 })
    assert.is_true(mock.proxy(handler, {}).response_ran)
    mock.install({ http_version = 2, kong_version_num = 3007001 })
    assert.is_false(mock.proxy(handler, {}).response_ran)
    assert.equal(2, ran)
  end)
end)

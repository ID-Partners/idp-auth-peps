-- Behavioural tests for the sideband-pdp Kong plugin, against the mocked Kong in
-- mock_kong.lua: no gateway, no PingAuthorize, no network. They cover what the policy
-- provider is sent, how its answers are applied, the layer walk and its rules, the
-- response phase, and discovery through both phases.

local mock = require 'spec.mock_kong'
local json = mock.json_encode

local PAZ = 'https://paz.example'
local ESTATE = 'https://estate.example'
local BANKPDP = 'https://pdp.bank.example/tenants/bank'
local RES = 'https://api.bank.example'
local ANCHOR = 'https://anchor.example'

local function load_plugin(opts)
  local state = mock.install(opts)
  package.loaded['kong.plugins.sideband-pdp.handler'] = nil
  local plugin = assert(loadfile('sideband-pdp/handler.lua'))()
  package.loaded['kong.plugins.sideband-pdp.sideband']._reset()
  return plugin, state
end

local function conf(over)
  local c = {
    service_url = PAZ, shared_secret = 'static-secret', secret_header_name = 'CLIENT-TOKEN',
    connection_timeout_ms = 1000, connection_keepAlive_ms = 1000, verify_service_certificate = true,
    enable_debug_logging = false, forward_client_certificate = true, filter_response = true,
    pep_label = 'test-pep', pdp_discovery = 'off', pdp_metadata_ttl = 300,
    pdp_layers = { 'resource' }, fail_mode = 'closed',
  }
  for k, v in pairs(over or {}) do c[k] = v end
  return c
end

-- A responder that routes by URL prefix, longest first. A table is JSON, a string a raw
-- body, a number a status, false a connection failure, a function decides for itself.
local function router(routes)
  local hits = {}
  local fn = function(url, req)
    hits[#hits + 1] = { url = url, method = req.method, headers = req.headers, body = req.body }
    local keys = {}
    for k in pairs(routes) do keys[#keys + 1] = k end
    table.sort(keys, function(a, b) return #a > #b end)
    for _, prefix in ipairs(keys) do
      local r = routes[prefix]
      if url == prefix or url:sub(1, #prefix) == prefix then
        if type(r) == 'function' then return r(url, req) end
        if r == false then return nil, 'connection refused' end
        if type(r) == 'number' then return { status = r, body = '' } end
        if type(r) == 'string' then return { status = 200, body = r } end
        return { status = 200, body = json(r) }
      end
    end
    return { status = 404, body = '' }
  end
  return fn, hits
end

local function urls(hits, needle)
  local out = {}
  for _, h in ipairs(hits) do if h.url:find(needle, 1, true) then out[#out + 1] = h.url end end
  return out
end

-- A policy provider that permits: echoes the request, optionally rewritten, with a state.
local function permit(rewrite, state)
  return function(url, req)
    local body = mock.json_decode(req.body)
    local out = { method = body.method, url = body.url, headers = body.headers, body = body.body, state = state }
    if rewrite then rewrite(out, body, req) end
    return { status = 200, body = json(out) }
  end
end

-- A policy provider that denies with the HTTP it wants sent.
local function policy_deny(status, headers, body)
  return function()
    return { status = 200, body = json({ response = { response_code = tostring(status), response_status = 'x', headers = headers, body = body } }) }
  end
end

local function header_value(list, name)
  for _, pair in ipairs(list or {}) do
    for k, v in pairs(pair) do if k == name then return v end end
  end
end

local function drive(over, opts)
  local plugin, state = load_plugin(opts)
  local c = conf(over)
  mock.run_access(plugin, c)
  return plugin, state, c
end

-- A /sideband/response that hands the response back as it is.
local function echo_response(_, req)
  local sent = mock.json_decode(req.body)
  return { status = 200, body = json({ response_code = sent.response_code, headers = sent.headers, body = sent.body }) }
end

describe('what the policy provider is sent', function()
  it('is the whole request, in the sideband API shape, with the static secret', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit() })
    local _, state = drive({}, {
      method = 'GET', path = '/accounts/a1/balance', query = 'x=1&y=2',
      headers = { authorization = 'Bearer tok', ['x-custom'] = 'v', accept = { 'a', 'b' } }, pdp = fn,
    })
    assert.is_nil(state.exited)
    assert.equal(1, #hits)
    assert.equal(PAZ .. '/sideband/request', hits[1].url)
    assert.equal('static-secret', hits[1].headers['CLIENT-TOKEN'])
    assert.equal('application/json', hits[1].headers['Content-Type'])
    local sent = mock.json_decode(hits[1].body)
    assert.equal('203.0.113.7', sent.source_ip)
    assert.equal(51234, sent.source_port)
    assert.equal('GET', sent.method)
    assert.equal('https://api.example:443/accounts/a1/balance?x=1&y=2', sent.url)
    assert.equal('1.1', sent.http_version)
    assert.is_nil(sent.body)
    assert.is_nil(sent.client_certificate)
    assert.equal('Bearer tok', header_value(sent.headers, 'authorization'))
    assert.equal('v', header_value(sent.headers, 'x-custom'))
    -- a multi-valued header is one pair per value
    local n = 0
    for _, pair in ipairs(sent.headers) do if pair.accept then n = n + 1 end end
    assert.equal(2, n)
  end)

  it('carries the body and the client certificate as a JWK with x5c', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit() })
    local x509 = { new = function(pem) assert.equal('PEM', pem); return {
      get_pubkey = function() return { tostring = function() return '{"kty":"EC","crv":"P-256","x":"1","y":"2"}' end } end,
      tostring = function() return 'DER-BYTES' end,
    } end }
    local _, state = drive({}, { method = 'POST', path = '/payments', body = '{"amount":5}', pdp = fn, client_cert_pem = 'PEM', x509 = x509 })
    assert.is_nil(state.exited)
    local sent = mock.json_decode(hits[1].body)
    assert.equal('{"amount":5}', sent.body)
    assert.equal('EC', sent.client_certificate.kty)
    assert.equal(mock.json_decode('["' .. _G.ngx.encode_base64('DER-BYTES') .. '"]')[1], sent.client_certificate.x5c[1])
  end)

  it('leaves the certificate out when told to', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit() })
    drive({ forward_client_certificate = false }, { pdp = fn, client_cert_pem = 'PEM', x509 = { new = function() error('must not parse') end } })
    assert.is_nil(mock.json_decode(hits[1].body).client_certificate)
  end)

  it('denies with a 400 when the certificate cannot be parsed, as ping-auth does', function()
    local fn = router({ [PAZ .. '/sideband/request'] = permit() })
    local _, state = drive({}, { pdp = fn, client_cert_pem = 'PEM', x509 = { new = function() return nil, 'garbage' end } })
    assert.equal(400, state.exited.status)
    assert.matches('could not be parsed', state.exited.body.reason)
  end)
end)

describe('a permit', function()
  it('applies the rewritten request to the upstream and marks the response', function()
    local fn = router({ [PAZ .. '/sideband/response'] = echo_response, [PAZ .. '/sideband/request'] = permit(function(out)
      -- add, change, remove; new method, path, query and body
      local kept = {}
      for _, pair in ipairs(out.headers) do
        if pair['x-remove'] == nil then
          if pair['x-change'] then pair['x-change'] = 'after' end
          kept[#kept + 1] = pair
        end
      end
      kept[#kept + 1] = { ['x-policy'] = 'applied' }
      out.headers = kept
      out.method = 'POST'
      out.url = 'https://api.example:443/v2/accounts/a1/balance?y=2'
      out.body = 'new-body'
    end, 'st-1') })
    local plugin, state, c = drive({}, { method = 'GET', path = '/accounts/a1/balance', query = 'x=1', body = 'old-body',
      headers = { ['x-remove'] = '1', ['x-change'] = 'before', ['x-keep'] = 'same' }, pdp = fn })
    assert.is_nil(state.exited)
    assert.same({ 'applied' }, state.upstream_headers['x-policy'])
    assert.same({ 'after' }, state.upstream_headers['x-change'])
    assert.is_nil(state.upstream_headers['x-keep'])
    assert.is_true(#state.cleared_upstream_headers >= 2)
    local cleared = table.concat(state.cleared_upstream_headers, ' ')
    assert.matches('x%-remove', cleared)
    assert.matches('Accept%-Encoding', cleared)
    assert.equal('POST', state.upstream_method)
    assert.equal('/v2/accounts/a1/balance', state.upstream_path)
    assert.equal('y=2', state.upstream_query)
    assert.equal('new-body', state.upstream_body)
    mock.run_response(plugin, c)
    local h = state.exited.headers
    assert.equal('PERMIT', h['X-PDP-Decision'])
    assert.equal('test-pep', h['X-PDP-PEP'])
    assert.equal(PAZ, h['X-PDP-Layers'])
    assert.equal('static', h['X-PDP-Source'])
    assert.is_nil(h['X-PDP-Fail-Open'])
  end)

  it('applies a new host, and says what it cannot apply', function()
    local fn = router({ [PAZ .. '/sideband/request'] = permit(function(out)
      out.url = 'http://other.example:8443/accounts/a1/balance?x=1'
      out.source_ip = '10.0.0.1'
    end) })
    local _, state = drive({}, { method = 'GET', path = '/accounts/a1/balance', query = 'x=1', pdp = fn })
    assert.is_nil(state.exited)
    assert.equal('other.example:8443', state.upstream_headers.host)
    assert.is_nil(state.upstream_path)
    local logs = table.concat(state.logs, '\n')
    assert.matches('changed the request scheme', logs)
    assert.matches('changed%s+source_ip', logs)
  end)

  it('clears a body the policy provider left out, and leaves an empty one alone', function()
    local fn = router({ [PAZ .. '/sideband/request'] = permit(function(out) out.body = nil end) })
    local _, state = drive({}, { method = 'POST', path = '/payments', body = '{"amount":5}', pdp = fn })
    assert.equal('', state.upstream_body)
    local _, state2 = drive({}, { method = 'GET', path = '/accounts', pdp = fn })
    assert.is_nil(state2.upstream_body)
  end)
end)

describe('a policy deny', function()
  it('is relayed verbatim: the policy wrote the challenge, the plugin sends it', function()
    local fn = router({ [PAZ .. '/sideband/request'] = policy_deny(401,
      { { ['www-authenticate'] = 'Bearer error="insufficient_scope", scope="payments:write"' }, { ['content-type'] = 'application/json' } },
      '{"error":"insufficient_scope","scope":"payments:write"}') })
    local _, state = drive({}, { method = 'POST', path = '/payments', body = '{}', pdp = fn })
    assert.equal(401, state.exited.status)
    assert.equal('{"error":"insufficient_scope","scope":"payments:write"}', state.exited.body)
    assert.same({ 'Bearer error="insufficient_scope", scope="payments:write"' }, state.exited.headers['www-authenticate'])
    assert.equal('DENY', state.exited.headers['X-PDP-Decision'])
    assert.equal(PAZ, state.exited.headers['X-PDP-Layer'])
    assert.is_nil(state.upstream_headers['x-anything'])
  end)

  it('relays a 413 from the sideband API as the answer about this request', function()
    local fn = router({ [PAZ .. '/sideband/request'] = function() return { status = 413, body = '{"message":"too big"}' } end })
    local _, state = drive({}, { pdp = fn })
    assert.equal(413, state.exited.status)
    assert.equal('{"message":"too big"}', state.exited.body)
  end)
end)

describe('fail rules in the request phase', function()
  it('FAILS CLOSED with a 503 when the policy provider is unreachable or errors', function()
    for _, answer in ipairs({ false, 500, 502 }) do
      local fn = router({ [PAZ .. '/sideband/request'] = answer })
      local _, state = drive({}, { pdp = fn })
      assert.equal(503, state.exited.status, tostring(answer))
      assert.equal('authorization_failed', state.exited.body.error)
      assert.equal('DENY', state.exited.headers['X-PDP-Decision'])
    end
  end)

  it('treats a 401 from the API as a failure and says what it probably is', function()
    local fn = router({ [PAZ .. '/sideband/request'] = function() return { status = 401, body = '{"message":"no secret"}' } end })
    local _, state = drive({}, { pdp = fn })
    assert.equal(503, state.exited.status)
    assert.matches('shared secret', table.concat(state.logs, '\n'))
  end)

  it('fails closed on an unreadable answer', function()
    local fn = router({ [PAZ .. '/sideband/request'] = 'not json' })
    local _, state = drive({}, { pdp = fn })
    assert.equal(503, state.exited.status)
  end)

  it('open on the route: the layer is skipped and the permit says so', function()
    local fn = router({ [PAZ .. '/sideband/request'] = false })
    local plugin, state, c = drive({ fail_mode = 'open' }, { pdp = fn })
    assert.is_nil(state.exited)
    -- nothing permitted it, so nothing filters the response either; it goes out marked
    mock.run_response(plugin, c)
    assert.is_nil(state.exited)
    assert.equal('PERMIT', state.response_headers['X-PDP-Decision'])
    assert.matches('^' .. PAZ:gsub('%p', '%%%0'), state.response_headers['X-PDP-Fail-Open'])
  end)

  it('a rate-limiting PDP is not asked again until Retry-After has passed', function()
    local calls = 0
    local fn = router({ [PAZ .. '/sideband/request'] = function()
      calls = calls + 1
      return { status = 429, headers = { ['Retry-After'] = '7' }, body = '' }
    end })
    local plugin, state, c = drive({}, { pdp = fn })
    assert.equal(429, state.exited.status)
    assert.equal('7', state.exited.headers['Retry-After'])
    assert.equal(1, calls)
    -- Within the window: denied without a call.
    _G.kong.ctx.plugin = {}
    mock.run_access(plugin, c)
    assert.equal(429, state.exited.status)
    assert.equal(1, calls)
    -- After it: asked again.
    state.now = state.now + 8
    _G.kong.ctx.plugin = {}
    mock.run_access(plugin, c)
    assert.equal(2, calls)
  end)

  it('a rate-limited fail-open layer is skipped', function()
    local fn = router({ [PAZ .. '/sideband/request'] = function() return { status = 429, headers = { ['Retry-After'] = '3' }, body = '' } end })
    local plugin, state, c = drive({ pdp_layers = { 'resource fail-open' } }, { pdp = fn })
    assert.is_nil(state.exited)
    mock.run_response(plugin, c)
    assert.matches('rate%-limited', state.response_headers['X-PDP-Fail-Open'])
  end)
end)

describe('layers', function()
  local function two_layers(estate_fn, paz_fn)
    return router({ [ESTATE .. '/sideband/request'] = estate_fn, [PAZ .. '/sideband/request'] = paz_fn,
      [ESTATE .. '/sideband/response'] = echo_response, [PAZ .. '/sideband/response'] = echo_response })
  end

  it('are asked in order, each seeing the request as the previous one rewrote it', function()
    local fn, hits = two_layers(permit(function(out) out.headers[#out.headers + 1] = { ['x-estate'] = 'seen' } end, 'est-1'), permit(nil, 'paz-1'))
    local plugin, state, c = drive({ pdp_layers = { ESTATE .. ' request-only', 'resource' }, pdp_credentials = { { pdp = ESTATE, shared_secret = 'estate-secret', secret_header_name = 'X-Estate' } } }, { pdp = fn })
    assert.is_nil(state.exited)
    assert.same({ ESTATE .. '/sideband/request', PAZ .. '/sideband/request' }, { hits[1].url, hits[2].url })
    assert.equal('estate-secret', hits[1].headers['X-Estate'])
    assert.is_nil(hits[1].headers['CLIENT-TOKEN'])
    assert.equal('static-secret', hits[2].headers['CLIENT-TOKEN'])
    assert.equal('seen', header_value(mock.json_decode(hits[2].body).headers, 'x-estate'))
    assert.same({ 'seen' }, state.upstream_headers['x-estate'])
    mock.run_response(plugin, c)
    assert.equal(ESTATE .. ', ' .. PAZ, state.exited.headers['X-PDP-Layers'])
  end)

  it('the first deny is the answer and later layers are not asked', function()
    local paz_called = false
    local fn = two_layers(policy_deny(403, { { ['content-type'] = 'text/plain' } }, 'no'), function() paz_called = true; return { status = 200, body = json({}) } end)
    local _, state = drive({ pdp_layers = { ESTATE, 'resource' } }, { pdp = fn })
    assert.equal(403, state.exited.status)
    assert.equal('no', state.exited.body)
    assert.is_false(paz_called)
    assert.equal(ESTATE, state.exited.headers['X-PDP-Layer'])
    assert.is_nil(state.exited.headers['X-PDP-Layers'])
  end)

  it('a discovered or configured PDP never gets the static secret, and no credential is a failure under its rule', function()
    local fn = two_layers(function(_, req)
      if not req.headers['X-Estate'] then return { status = 401, body = '{"message":"unauthorized"}' } end
      return permit()(_, req)
    end, permit())
    local _, state = drive({ pdp_layers = { ESTATE, 'resource' } }, { pdp = fn })
    assert.equal(503, state.exited.status)
    local plugin2, open, c2 = drive({ pdp_layers = { ESTATE .. ' fail-open', 'resource' } }, { pdp = fn })
    assert.is_nil(open.exited)
    mock.run_response(plugin2, c2)
    assert.matches('401', open.exited.headers['X-PDP-Fail-Open'])
    local _, with = drive({ pdp_layers = { ESTATE, 'resource' }, pdp_credentials = { { pdp = ESTATE .. '/', shared_secret = 's', secret_header_name = 'X-Estate' } } }, { pdp = fn })
    assert.is_nil(with.exited)
  end)

  it('a layer entry with an unknown modifier fails the route closed', function()
    local fn = two_layers(permit(), permit())
    local _, state = drive({ pdp_layers = { ESTATE .. ' sometimes', 'resource' } }, { pdp = fn })
    assert.equal(503, state.exited.status)
    assert.matches('could not be resolved', state.exited.body.reason)
  end)
end)

describe('the response phase', function()
  local upstream = { status = 200, headers = { ['content-type'] = 'application/json', ['x-upstream-only'] = '1', date = 'D' }, body = '{"balance":100}' }

  local function filtered(rc, extra_headers, body)
    return function(_, req)
      local sent = mock.json_decode(req.body)
      local headers = { { ['content-type'] = 'application/json' } }
      for _, h in ipairs(extra_headers or {}) do headers[#headers + 1] = h end
      return { status = 200, body = json({ response_code = tostring(rc or sent.response_code), headers = headers, body = body or sent.body }) }
    end
  end

  it('sends the client what the policy provider returned and drops what it left out', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit(nil, 'st-1'), [PAZ .. '/sideband/response'] = filtered(200, { { ['x-filtered'] = 'yes' } }, '{"balance":"***"}') })
    local plugin, state, c = drive({}, { pdp = fn, upstream = upstream })
    assert.is_nil(state.exited)
    mock.run_response(plugin, c)
    assert.equal(200, state.exited.status)
    assert.equal('{"balance":"***"}', state.exited.body)
    assert.same({ 'yes' }, state.exited.headers['x-filtered'])
    assert.equal('PERMIT', state.exited.headers['X-PDP-Decision'])
    local cleared = table.concat(state.cleared_response_headers, ' ')
    assert.matches('x%-upstream%-only', cleared)
    assert.is_nil(cleared:find('date', 1, true))
    -- what was sent: the upstream's response, correlated by the state from the request call
    local sent = mock.json_decode(hits[2].body)
    assert.equal('200', sent.response_code)
    assert.equal('OK', sent.response_status)
    assert.equal('{"balance":100}', sent.body)
    assert.equal('st-1', sent.state)
    assert.is_nil(sent.request)
    assert.equal('1', header_value(sent.headers, 'x-upstream-only'))
  end)

  it('sends the request instead when the policy provider returned no state', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit(), [PAZ .. '/sideband/response'] = filtered() })
    local plugin, _, c = drive({}, { method = 'GET', path = '/accounts', pdp = fn, upstream = upstream })
    mock.run_response(plugin, c)
    local sent = mock.json_decode(hits[2].body)
    assert.is_nil(sent.state)
    assert.equal('GET', sent.request.method)
    assert.equal('https://api.example:443/accounts', sent.request.url)
  end)

  it('walks the permitting layers in reverse and skips request-only ones', function()
    local order = {}
    local fn = router({
      [ESTATE .. '/sideband/request'] = permit(nil, 'e'), [ESTATE .. '/sideband/response'] = function(...) order[#order + 1] = 'estate'; return filtered()(...) end,
      [BANKPDP .. '/sideband/request'] = permit(nil, 'b'), [BANKPDP .. '/sideband/response'] = function(...) order[#order + 1] = 'bank'; return filtered()(...) end,
      [PAZ .. '/sideband/request'] = permit(nil, 'p'), [PAZ .. '/sideband/response'] = function(...) order[#order + 1] = 'paz'; return filtered()(...) end,
    })
    local plugin, state, c = drive({ pdp_layers = { ESTATE .. ' request-only', BANKPDP, 'resource' } }, { pdp = fn, upstream = upstream })
    mock.run_response(plugin, c)
    assert.same({ 'paz', 'bank' }, order)
    assert.equal(200, state.exited.status)
  end)

  it('does nothing when filtering is off', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit(), [PAZ .. '/sideband/response'] = filtered() })
    local plugin, state, c = drive({ filter_response = false }, { pdp = fn, upstream = upstream })
    mock.run_response(plugin, c)
    assert.is_nil(state.exited)
    assert.equal(1, #hits)
  end)

  it('treats an unreadable response-phase answer as a failure', function()
    local fn = router({ [PAZ .. '/sideband/request'] = permit(), [PAZ .. '/sideband/response'] = 'not json' })
    local plugin, state, c = drive({}, { pdp = fn, upstream = upstream })
    mock.run_response(plugin, c)
    assert.equal(503, state.exited.status)
  end)

  it('applies the layer rule to a failure here too', function()
    local fn = router({ [PAZ .. '/sideband/request'] = permit(), [PAZ .. '/sideband/response'] = false })
    local plugin, state, c = drive({}, { pdp = fn, upstream = upstream })
    mock.run_response(plugin, c)
    assert.equal(503, state.exited.status)
    local plugin2, state2, c2 = drive({ fail_mode = 'open' }, { pdp = fn, upstream = upstream })
    mock.run_response(plugin2, c2)
    assert.is_nil(state2.exited)
    assert.matches('^' .. PAZ:gsub('%p', '%%%0'), state2.response_headers['X-PDP-Fail-Open'])
  end)
end)

describe('discovery through the plugin', function()
  local function bank_routes(over)
    local r = {
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { BANKPDP }, authzen_policy_layers = { ESTATE } },
      [ESTATE .. '/sideband/request'] = permit(nil, 'e'),
      [BANKPDP .. '/sideband/request'] = permit(nil, 'b'),
      [ESTATE .. '/sideband/response'] = function(_, req) return { status = 200, body = json({ response_code = '200', headers = {}, body = mock.json_decode(req.body).body }) } end,
      [BANKPDP .. '/sideband/response'] = function(_, req) return { status = 200, body = json({ response_code = '200', headers = {}, body = mock.json_decode(req.body).body }) } end,
    }
    for k, v in pairs(over or {}) do r[k] = v end
    return r
  end
  local function resource_conf(over)
    local c = { pdp_discovery = 'resource', resource = RES, resource_metadata_allowlist = { RES } }
    for k, v in pairs(over or {}) do c[k] = v end
    return c
  end

  it('asks the PDPs the resource names, its published layer first, and probes no PDP metadata', function()
    local fn, hits = router(bank_routes())
    local plugin, state, c = drive(resource_conf(), { pdp = fn })
    assert.is_nil(state.exited)
    assert.same({ ESTATE .. '/sideband/request', BANKPDP .. '/sideband/request' }, urls(hits, '/sideband/request'))
    assert.equal(0, #urls(hits, 'authzen-configuration'))
    -- neither discovered PDP was given the static secret
    for _, h in ipairs(hits) do assert.is_nil(h.headers and h.headers['CLIENT-TOKEN']) end
    mock.run_response(plugin, c)
    assert.same({ BANKPDP .. '/sideband/response', ESTATE .. '/sideband/response' }, urls(hits, '/sideband/response'))
    assert.equal('rfc9728', state.exited.headers['X-PDP-Source'])
    assert.equal(ESTATE .. ', ' .. BANKPDP, state.exited.headers['X-PDP-Layers'])
  end)

  it('calls a discovered PDP with the credential configured for it', function()
    local fn, hits = router(bank_routes())
    drive(resource_conf({ pdp_credentials = { { pdp = BANKPDP, shared_secret = 'bank-secret' } } }), { pdp = fn })
    local calls = {}
    for _, h in ipairs(hits) do calls[h.url] = h.headers end
    assert.equal('bank-secret', calls[BANKPDP .. '/sideband/request']['CLIENT-TOKEN'])
    assert.is_nil(calls[ESTATE .. '/sideband/request']['CLIENT-TOKEN'])
  end)

  it('falls back to service_url when the resource has no metadata, and refuses one outside the allowlist', function()
    local fn, hits = router({ [PAZ .. '/sideband/request'] = permit() })
    local _, state = drive(resource_conf(), { pdp = fn })
    assert.is_nil(state.exited)
    assert.same({ PAZ .. '/sideband/request' }, urls(hits, '/sideband/request'))
    local _, refused = drive(resource_conf({ resource_metadata_allowlist = { 'https://other.example' } }), { pdp = fn })
    assert.equal(503, refused.exited.status)
  end)

  it('the switch: takes the federation resolver\'s word and never reads the resource\'s own document', function()
    local resolved = mock.jwt({ iss = ANCHOR, sub = RES, iat = 1700000000, exp = 1700003600,
      metadata = { oauth_resource = { authzen_policy_decision_points = { BANKPDP }, authzen_policy_layers = { ESTATE } } } },
      { alg = 'ES256', typ = 'resolve-response+jwt' })
    local fn, hits = router(bank_routes({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { 'https://rogue.example' } },
      [ANCHOR .. '/resolve'] = resolved,
    }))
    local plugin, state, c = drive({ pdp_discovery = 'federation', resource = RES, federation_resolve_url = ANCHOR .. '/resolve', federation_trust_anchor = ANCHOR }, { pdp = fn })
    assert.is_nil(state.exited)
    assert.equal(1, #urls(hits, ANCHOR .. '/resolve'))
    assert.matches('sub=https%%3A%%2F%%2Fapi%.bank%.example', urls(hits, '/resolve')[1])
    assert.matches('anchor=https%%3A%%2F%%2Fanchor%.example', urls(hits, '/resolve')[1])
    assert.equal(0, #urls(hits, 'oauth-protected-resource'))
    assert.same({ ESTATE .. '/sideband/request', BANKPDP .. '/sideband/request' }, urls(hits, '/sideband/request'))
    mock.run_response(plugin, c)
    assert.equal('federation', state.exited.headers['X-PDP-Source'])
  end)

  it('the switch: a subject the resolver does not know falls to service_url; an invalid chain fails closed even when open', function()
    local base = { pdp_discovery = 'federation', resource = RES, federation_resolve_url = ANCHOR .. '/resolve', federation_trust_anchor = ANCHOR }
    local fn, hits = router(bank_routes({ [ANCHOR .. '/resolve'] = function() return { status = 404, body = json({ error = 'not_found' }) } end, [PAZ .. '/sideband/request'] = permit() }))
    local _, state = drive(base, { pdp = fn })
    assert.is_nil(state.exited)
    assert.same({ PAZ .. '/sideband/request' }, urls(hits, '/sideband/request'))
    local bad = router(bank_routes({ [ANCHOR .. '/resolve'] = function() return { status = 400, body = json({ error = 'invalid_trust_chain', error_description = 'no path to the anchor' }) } end }))
    local over = {}
    for k, v in pairs(base) do over[k] = v end
    over.fail_mode = 'open'
    local _, refused = drive(over, { pdp = bad })
    assert.equal(503, refused.exited.status)
  end)
end)

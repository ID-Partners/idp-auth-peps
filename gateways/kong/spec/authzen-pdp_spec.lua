-- Behavioural tests for the authzen-pdp Kong plugin.
--
-- Kong is mocked (see mock_kong.lua), so these run anywhere Lua does — no gateway, no
-- database, no network. They cover the pure helpers, the request mapping, the two ways a
-- route is decided (natively, on claims an auth plugin verified; or by coaz-pep, which
-- verifies them itself) and the access() paths that matter: fail closed on a PDP error,
-- honour a deny, forward identity on a permit, refuse an MCP body it cannot read.

local mock = require 'spec.mock_kong'

--- load a fresh copy of the plugin against a freshly installed mock environment
local function load_plugin(opts)
  local state = mock.install(opts)
  package.loaded['kong.plugins.authzen-pdp.handler'] = nil
  local chunk = assert(loadfile('authzen-pdp/handler.lua'))
  return chunk(), state
end

-- A native route: decided here, on claims an openid-connect or jwt plugin verified.
local function base_conf(over)
  local conf = {
    authzen_url = 'http://pdp:8080',
    authzen_api_key = 'k',
    pep_label = 'test-pep',
    style = 'rest',
    require_token = true,
    require_dpop = false,
    require_user_login = false,
    stepup_action = 'make_payment',
    pdp_ssl_verify = true,
    access_token_verified_upstream = true,
    fail_mode = 'closed',
  }
  for k, v in pairs(over or {}) do conf[k] = v end
  return conf
end

local COAZ = 'http://coaz-pep:9192'

-- A delegated route: coaz-pep decides the whole request.
local function coaz_conf(over)
  return base_conf((function()
    local o = { coaz_url = COAZ, coaz_api_key = 'check-token', access_token_verified_upstream = false }
    for k, v in pairs(over or {}) do o[k] = v end
    return o
  end)())
end

local function mcp_conf(over)
  return coaz_conf((function()
    local o = { style = 'mcp', mcp_upstream_url = 'http://mcp:8090/mcp' }
    for k, v in pairs(over or {}) do o[k] = v end
    return o
  end)())
end

local function token(claims)
  return 'Bearer ' .. mock.jwt(claims or { sub = 'alice', act = { sub = 'agent-1' } })
end

-- The engine's side of a check, as a responder: `engine` is a table (the JSON answer),
-- false (connection refused), a number (that status, empty body) or a function.
local function engine_route(engine, opts)
  local calls = {}
  opts = opts or {}
  opts.pdp = function(url, req)
    calls[#calls + 1] = { url = url, body = req.body, headers = req.headers, ssl_verify = req.ssl_verify }
    if url:find('/v1/mcp/check', 1, true) then
      if type(engine) == 'function' then return engine(url, req) end
      if engine == false then return nil, 'connection refused' end
      if type(engine) == 'number' then return { status = engine, body = '' } end
      return { status = 200, body = mock.json_encode(engine or { decision = true, upstream_headers = {} }) }
    end
    return { status = 200, body = mock.json_encode({ decision = true }) }
  end
  local plugin, state = load_plugin(opts)
  return plugin, state, calls
end

local function checks(calls)
  local out = {}
  for _, c in ipairs(calls) do
    if c.url:find('/v1/mcp/check', 1, true) then out[#out + 1] = mock.json_decode(c.body) end
  end
  return out
end

local TOOLS_CALL = '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_customer","arguments":{"id":"c1"}}}'

describe('pure helpers', function()
  -- Each test loads its own plugin: load_plugin reinstalls the globals, so a handle
  -- captured once at describe time would outlive the environment it was built against.
  local function helpers()
    return (load_plugin({}))._TEST
  end

  it('round-trips base64url without padding', function()
    for _, s in ipairs({ 'a', 'ab', 'abc', 'abcd', 'hello world' }) do
      local T = helpers()
      assert.equal(s, T.b64url_decode(mock.b64url(s)))
    end
  end)

  it('decodes JWT claims and header, and refuses malformed tokens', function()
    local T = helpers()
    local tok = mock.jwt({ sub = 'alice@example.com', scope = 'a b' }, { alg = 'ES256', kid = 'k1' })
    assert.equal('alice@example.com', T.jwt_claims(tok).sub)

    for _, bad in ipairs({ 'nodots', 'only.one' }) do
      assert.is_nil(T.jwt_claims(bad))
    end
    assert.is_nil(T.jwt_claims(nil))
    -- A payload that is JSON but not an object is no claims at all.
    assert.is_nil(T.jwt_claims('h.' .. mock.b64url('"a string"') .. '.s'))
  end)

  it('extracts the token and lower-cases the scheme', function()
    local T = helpers()
    local t, s = T.extract_token('Bearer abc.def.ghi')
    assert.equal('abc.def.ghi', t)
    assert.equal('bearer', s)

    t, s = T.extract_token('DPoP xyz')
    assert.equal('dpop', s)

    assert.is_nil((T.extract_token(nil)))
    assert.is_nil((T.extract_token('Malformed')))
  end)
end)

describe('request mapping', function()
  it('maps REST banking routes to actions and resources', function()
    local cases = {
      { method = 'GET', path = '/customers/cust-1/accounts', action = 'list_accounts', rtype = 'customer', rid = 'cust-1' },
      { method = 'GET', path = '/accounts/acc-9/balance', action = 'get_balance', rtype = 'account', rid = 'acc-9' },
    }
    for _, c in ipairs(cases) do
      local plugin = load_plugin({ method = c.method, path = c.path })
      local m = plugin._TEST.map_request(base_conf())
      assert.equal(c.action, m.action, c.path)
      assert.equal(c.rtype, m.rtype, c.path)
      assert.equal(c.rid, m.rid, c.path)
    end
  end)

  it('always tags the channel so policy can see it is agent traffic', function()
    local plugin = load_plugin({ method = 'GET', path = '/anything' })
    local m = plugin._TEST.map_request(base_conf())
    assert.equal('ai-agent', m.ctx.channel)
  end)

  local function mapped(opts)
    local plugin = load_plugin(opts)
    return plugin._TEST.map_request(base_conf())
  end

  it('matches the path the route delegates to its service: its prefix stripped as Kong strips it', function()
    local route = { paths = { '/bank' }, strip_path = true }
    local m = mapped({ method = 'GET', path = '/bank/accounts/acc-9/balance', route = route })
    assert.equal('get_balance', m.action); assert.equal('acc-9', m.rid)
    -- A route that does not strip forwards the whole path, and that is what is matched.
    m = mapped({ method = 'GET', path = '/bank/accounts/acc-9/balance', route = { paths = { '/bank' }, strip_path = false } })
    assert.equal('http:get', m.action)
    -- The longest matching prefix is the one Kong matched; a regex path is not stripped.
    m = mapped({ method = 'GET', path = '/bank/v2/accounts/a/balance', route = { paths = { '/bank', '/bank/v2' } } })
    assert.equal('get_balance', m.action)
    m = mapped({ method = 'GET', path = '/bank/accounts/a/balance', route = { paths = { '~/bank' } } })
    assert.equal('http:get', m.action)
  end)

  it('anchors every pattern: a mapped path inside another is not that operation', function()
    for _, c in ipairs({
      { 'GET', '/admin/accounts/a1/balance' },     -- used to map to get_balance(a1)
      { 'GET', '/customers/c1/accounts/a1/balance' }, -- used to map to list_accounts(c1)
      { 'POST', '/accounts/a1/close' },            -- used to map to open_account
      { 'POST', '/refunds/payments' },             -- used to map to make_payment
    }) do
      local m = mapped({ method = c[1], path = c[2], body = '{"from_account":"a","amount":1}' })
      assert.equal('http:' .. c[1]:lower(), m.action, c[2])
      assert.equal(c[2], m.rid)
    end
    assert.equal('get_balance', mapped({ method = 'GET', path = '/accounts/a1/balance/' }).action)
  end)

  it('matches the normalised path, never the one the client wrote', function()
    -- Kong's router and upstream both work from the normalised path; the raw one could
    -- name an account's balance while /admin/users is what runs.
    local m = mapped({ method = 'GET', raw_path = '/accounts/a1/balance/../../../admin/users', path = '/admin/users' })
    assert.equal('http:get', m.action)
    assert.equal('/admin/users', m.rid)
  end)
end)

describe('a payment or account the plugin cannot read is refused, never sent without its amount', function()
  local function post(path, body, over, extra)
    local opts = { method = 'POST', path = path, body = body, headers = { authorization = token({ sub = 'alice' }) }, pdp = { decision = true } }
    for k, v in pairs(extra or {}) do opts[k] = v end
    local plugin, state = load_plugin(opts)
    mock.run_access(plugin, base_conf(over))
    return state
  end

  it('a body it cannot read in full is a 413', function()
    local state = post('/payments', '{"from_account":"a","amount":5,"pad":"' .. string.rep('x', 9000) .. '"}', nil, { kong_version_num = 3007001 })
    assert.equal(413, state.exited.status)
    assert.equal(0, #state.pdp_requests)
  end)

  it('a body that is not one JSON object, or a payment without a readable account and amount, is a 400', function()
    for _, body in ipairs({ '', 'not json', '[{"amount":5}]', '"x"', '{"amount":5}', '{"from_account":7,"amount":5}',
      '{"from_account":"a"}', '{"from_account":"a","amount":"50"}', '{"from_account":"a","amount":1e999}',
      '{"from_account":"a","amount":5,"to_account":7}', '{"from_account":"a","amount":5,"internal_transfer":"yes"}',
      '{"from_account":"a","amount":5,"currency":["AUD"]}' }) do
      local state = post('/payments', body)
      assert.equal(400, state.exited.status, body)
      assert.equal(0, #state.pdp_requests, body)
    end
    for _, body in ipairs({ 'not json', '{"account_type":7}', '{"account_type":""}' }) do
      local state = post('/accounts', body)
      assert.equal(400, state.exited.status, body)
    end
  end)

  it('a readable payment reaches the PDP with its amount and account; a null optional field is absent', function()
    local state = post('/payments', '{"from_account":"a1","to_account":"b2","amount":50,"currency":null,"description":"rent"}')
    assert.is_nil(state.exited)
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.equal(50, sent.context.amount)
    assert.equal('AUD', sent.context.currency)
    assert.equal('rent', sent.context.description)
    assert.equal('a1', sent.resource.id)
    assert.equal('b2', sent.resource.properties.to_account)
  end)
end)

describe('access(): the decision path', function()
  it('denies a request with no token when one is required', function()
    local plugin, state = load_plugin({ method = 'GET', path = '/accounts/a/balance' })
    mock.run_access(plugin, base_conf())
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.equal(0, #state.pdp_requests) -- never reached the PDP
  end)

  it('forwards the delegation chain upstream on a permit', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice', act = { sub = 'agent-7' }, scope = 'accounts:read', acr = 'urn:mfa' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.is_nil(state.exited)
    assert.equal('alice', state.upstream_headers['X-Auth-Principal'])
    assert.equal('agent-7', state.upstream_headers['X-Auth-Agent'])
    assert.equal('accounts:read', state.upstream_headers['X-Auth-Scope'])
    -- acr comes from the token, not from a username comparison
    assert.equal('urn:mfa', state.upstream_headers['X-Auth-Acr'])
  end)

  it('honours a PDP deny', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = false, context = { reason = 'not your account' } },
    })
    mock.run_access(plugin, base_conf())
    assert.is_truthy(state.exited)
    assert.equal(403, state.exited.status)
    assert.matches('not your account', state.exited.body.reason)
  end)

  it('FAILS CLOSED when the PDP is unreachable', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = false, -- connection refused
    })
    mock.run_access(plugin, base_conf())
    assert.is_truthy(state.exited)
    assert.equal(503, state.exited.status)
  end)

  it('verifies TLS to the PDP by default', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.equal(1, #state.pdp_requests)
    assert.is_true(state.pdp_requests[1].ssl_verify)
  end)

  it('allows TLS verification to be turned off only explicitly', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ pdp_ssl_verify = false, allow_insecure = true }))
    assert.is_false(state.pdp_requests[1].ssl_verify)
  end)

  it('sends the PDP a subject built from the token, not from the request', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/customers/cust-1/accounts',
      headers = { authorization = token({ sub = 'alice', act = { sub = 'agent-7' }, client_id = 'c1' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.equal('list_accounts', sent.action.name)
    assert.equal('customer', sent.resource.type)
    assert.equal('cust-1', sent.resource.id)
  end)
end)

describe('a native route trusts only verified claims', function()
  -- Without coaz_url the plugin reads the access token's claims itself, and it has no
  -- JOSE verifier. That is safe only when an auth plugin validated Authorization first,
  -- and the route has to say so; X-User-Token is never read here at all.
  it('never reads X-User-Token: no user_scope reaches the PDP', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = {
        authorization = token({ sub = 'alice' }),
        ['x-user-token'] = mock.jwt({ sub = 'mallory', scope = 'payments:approve' }),
      },
      body = '{"from_account":"a","amount":50}',
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.is_nil(state.exited)
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.is_nil(sent.context.user_scope)
    assert.is_nil(state.pdp_requests[1].body:find('mallory', 1, true))
  end)

  it('refuses to decide on unverified claims when the route has not said who verified them', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ access_token_verified_upstream = false }))
    assert.equal(503, state.exited.status)
    assert.equal(0, #state.pdp_requests)
    -- The escape hatch, and only the escape hatch, lets the claims through unverified.
    local plugin2, state2 = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin2, base_conf({ access_token_verified_upstream = false, allow_insecure = true }))
    assert.is_nil(state2.exited)
  end)

  it('fails closed on an MCP route with nowhere to send it', function()
    -- The schema requires coaz_url for style=mcp; a route that got here anyway must not
    -- be decided by REST mapping of JSON-RPC.
    local plugin, state = load_plugin({
      method = 'POST', path = '/mcp', headers = { authorization = token() },
      body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}',
    })
    mock.run_access(plugin, base_conf({ style = 'mcp' }))
    assert.equal(503, state.exited.status)
    assert.equal(0, #state.pdp_requests)
  end)

  it('fails closed on require_dpop or require_user_login without coaz-pep to verify them', function()
    for _, over in ipairs({ { require_dpop = true }, { require_user_login = true } }) do
      local plugin, state = load_plugin({
        method = 'GET', path = '/accounts/a/balance', headers = { authorization = token() },
      })
      mock.run_access(plugin, base_conf(over))
      assert.equal(503, state.exited.status)
      assert.equal(0, #state.pdp_requests)
    end
  end)
end)

describe('step-up and PDP advice', function()
  local function permit_token()
    return token({ sub = 'alice', scope = 'accounts:read' })
  end

  it('relays a step-up challenge rather than a flat deny', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = permit_token() },
      body = '{"from_account":"a","to_account":"b","amount":9000}',
      pdp = {
        decision = false,
        context = { reason = 'over threshold', step_up_required = true, step_up_scope = 'payments:approve' },
      },
    })
    mock.run_access(plugin, base_conf())
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    -- The client needs to know WHICH scope to go and get.
    local body = state.exited.body
    assert.matches('payments:approve', mock.json_encode(body))
  end)

  it('relays an identity-proofing requirement with its doctype', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/accounts',
      headers = { authorization = permit_token() },
      body = '{"account_type":"savings"}',
      pdp = {
        decision = false,
        context = { identity_proofing_required = true, identity_proofing_doctype = 'org.iso.18013.5.1.mDL' },
      },
    })
    mock.run_access(plugin, base_conf())
    assert.is_truthy(state.exited)
    assert.matches('mDL', mock.json_encode(state.exited.body))
  end)
end)

describe('the identity headers are the PEP\'s, and what a client reads is generic and header-safe', function()
  local FORGED = { ['x-auth-principal'] = 'mallory', ['x-auth-agent'] = 'evil-agent', ['x-auth-scope'] = 'admin', ['x-auth-acr'] = 'urn:staff' }
  local function with_forged(h)
    for k, v in pairs(FORGED) do h[k] = v end
    return h
  end
  local function cleared(state)
    local out = {}
    for _, name in ipairs(state.cleared_upstream_headers or {}) do out[name:lower()] = true end
    return out
  end

  it('removes a client\'s X-Auth-* before anything else, and sets only what it asserts', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = with_forged({ authorization = token({ sub = 'alice' }) }), -- no act, scope or acr
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.is_nil(state.exited)
    local gone = cleared(state)
    for name in pairs(FORGED) do assert.is_true(gone[name], name) end
    assert.equal('alice', state.upstream_headers['X-Auth-Principal'])
    -- Nothing asserted, nothing set: not the client's value, and not an empty one.
    assert.is_nil(state.upstream_headers['X-Auth-Agent'])
    assert.is_nil(state.upstream_headers['X-Auth-Scope'])
    assert.is_nil(state.upstream_headers['X-Auth-Acr'])
  end)

  it('removes them on a delegated route too, whatever coaz-pep asserts', function()
    local plugin, state = engine_route({ decision = true, upstream_headers = { ['X-Auth-Principal'] = 'alice' } },
      { method = 'POST', path = '/mcp', body = TOOLS_CALL, headers = with_forged({ authorization = token() }) })
    mock.run_access(plugin, mcp_conf())
    assert.is_nil(state.exited)
    local gone = cleared(state)
    for name in pairs(FORGED) do assert.is_true(gone[name], name) end
    assert.equal('alice', state.upstream_headers['X-Auth-Principal'])
    assert.is_nil(state.upstream_headers['X-Auth-Agent'])
  end)

  it('removes them before relaying the federation face, too', function()
    local plugin, state = load_plugin({ method = 'GET', path = '/.well-known/openid-federation', headers = with_forged({}),
      pdp = function() return { status = 200, body = 'eyJ.a.b' } end })
    mock.run_access(plugin, base_conf({ federation_entity_url = 'http://coaz-pep:9192' }))
    assert.equal(200, state.exited.status)
    assert.is_true(cleared(state)['x-auth-principal'])
  end)

  it('keeps line breaks and non-ASCII out of every header built from PDP data', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = false, context = { reason = 'no\r\nSet-Cookie: pwned=1 caf\195\169' } },
    })
    mock.proxy(plugin, base_conf())
    assert.equal(403, state.exited.status)
    local reason = state.response_headers['X-PDP-Reason']
    assert.is_nil(reason:find('[\r\n]'))
    assert.is_nil(reason:find('[\128-\255]'))
    assert.equal('no  Set-Cookie: pwned=1 caf', reason)
    -- The JSON body keeps the policy's words as written.
    assert.equal('no\r\nSet-Cookie: pwned=1 caf\195\169', state.exited.body.reason)
  end)

  it('escapes a WWW-Authenticate parameter as a quoted-string', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments', body = '{"from_account":"a","amount":9000}',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = false, context = { step_up_required = true, step_up_scope = 'pay"x\\y\r\nz' } },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('Bearer error="insufficient_scope", scope="pay\\"x\\\\y  z"', state.exited.headers['WWW-Authenticate'])
  end)

  it('sanitises what coaz-pep asks it to set, too', function()
    local plugin, state = engine_route({ decision = true, upstream_headers = { ['X-Auth-Principal'] = 'alice\r\nX-Evil: 1' },
      response_headers = { ['X-PDP-Reason'] = 'ok\nX-Evil: 1' } },
      { method = 'POST', path = '/mcp', body = TOOLS_CALL, headers = { authorization = token() } })
    mock.proxy(plugin, mcp_conf())
    assert.equal('alice  X-Evil: 1', state.upstream_headers['X-Auth-Principal'])
    assert.equal('ok X-Evil: 1', state.response_headers['X-PDP-Reason'])
  end)
end)

describe('a JSON null from the PDP reads as absent', function()
  -- cjson decodes null to cjson.null, which is truthy: read straight, a null reason
  -- became a header value Kong refuses (a 500 from header_filter), and a null
  -- step_up_required became a challenge.
  local function answer(body, method, path, request_body)
    local plugin, state = load_plugin({
      method = method or 'GET', path = path or '/accounts/a/balance', body = request_body,
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = function() return { status = 200, body = body } end,
    })
    mock.proxy(plugin, base_conf())
    return state
  end

  it('a null reason is the default reason, and header_filter does not raise', function()
    local state = answer('{"decision":true,"context":{"reason":null,"step_up_required":null,"identity_proofing_required":null}}')
    assert.is_nil(state.exited)
    assert.equal('Permitted by policy.', state.response_headers['X-PDP-Reason'])
    local denied = answer('{"decision":false,"context":{"reason":null}}')
    assert.equal(403, denied.exited.status)
    assert.equal('Denied by policy.', denied.response_headers['X-PDP-Reason'])
  end)

  it('a null context is no context', function()
    local state = answer('{"decision":true,"context":null}')
    assert.is_nil(state.exited)
  end)

  it('a challenge whose parameters are null still renders', function()
    local state = answer('{"decision":false,"context":{"step_up_required":true,"step_up_scope":null}}',
      'POST', '/payments', '{"from_account":"a","amount":9000}')
    assert.equal(401, state.exited.status)
    assert.equal('Bearer error="insufficient_scope", scope=""', state.exited.headers['WWW-Authenticate'])
  end)
end)

describe('challenge parity with the other PEPs', function()
  -- The repo's central claim is that a client gets the same challenge whichever PEP
  -- denies it. These pin the wire shape so a change to one PEP cannot silently drift.
  it('renders a step-up identically to the Go PEP', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = token({ sub = 'alice' }) },
      body = '{"from_account":"a","amount":9000}',
      pdp = { decision = false, context = { reason = 'approve it', step_up_required = true, step_up_scope = 'pay:approve' } },
    })
    mock.run_access(plugin, base_conf())
    local body = state.exited.body
    assert.equal(401, state.exited.status)
    assert.equal('insufficient_scope', body.error)
    assert.equal('resource_authorisation', body.authz_challenge.type)
    assert.equal('pay:approve', body.authz_challenge.scope)
    assert.matches('insufficient_scope', state.exited.headers['WWW-Authenticate'])
  end)

  it('renders identity proofing identically to the Go PEP', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/accounts',
      headers = { authorization = token({ sub = 'alice' }) },
      body = '{}',
      pdp = { decision = false, context = { identity_proofing_required = true, identity_proofing_doctype = 'org.iso.18013.5.1.mDL' } },
    })
    mock.run_access(plugin, base_conf())
    local body = state.exited.body
    assert.equal(401, state.exited.status)
    assert.equal('identity_verification_required', body.error)
    assert.equal('identity_proofing', body.authz_challenge.type)
    assert.equal('org.iso.18013.5.1.mDL', body.authz_challenge.doctype)
  end)

  it('defaults the doctype when the policy names none', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/accounts',
      headers = { authorization = token({ sub = 'alice' }) },
      body = '{}',
      pdp = { decision = false, context = { identity_proofing_required = true } },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('org.iso.18013.5.1.mDL', state.exited.body.doctype)
  end)

  it('resolves identity before step-up when a policy asks for both', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = token({ sub = 'alice' }) },
      body = '{"from_account":"a","amount":9000}',
      pdp = { decision = false, context = {
        identity_proofing_required = true, step_up_required = true, step_up_scope = 's' } },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('identity_verification_required', state.exited.body.error)
  end)
end)

describe('an MCP route: every request goes to coaz-pep', function()
  local function mcp(method, body, over, engine, extra)
    local opts = { method = method, path = '/mcp', body = body,
      headers = { authorization = token(), ['content-type'] = 'application/json' } }
    for k, v in pairs(extra or {}) do opts[k] = v end
    local plugin, state, calls = engine_route(engine, opts)
    mock.run_access(plugin, mcp_conf(over))
    return state, calls
  end

  it('sends every method and every JSON-RPC message, not only tools/call', function()
    local cases = {
      { 'POST', TOOLS_CALL },
      { 'POST', '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' },
      { 'POST', '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' },
      { 'POST', '{"jsonrpc":"2.0","method":"notifications/initialized"}' },
      { 'POST', '{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"x"}}' },
      { 'POST', '{"jsonrpc":"2.0","id":3,"result":{}}' }, -- a client's answer to a server request
      { 'GET', nil },
      { 'DELETE', nil },
    }
    for _, c in ipairs(cases) do
      local state, calls = mcp(c[1], c[2])
      assert.is_nil(state.exited, c[1] .. ' ' .. tostring(c[2]))
      local sent = checks(calls)
      assert.equal(1, #sent, c[1] .. ' ' .. tostring(c[2]))
      assert.equal(c[1], sent[1].method)
      assert.equal(c[2] or '', sent[1].body)
      assert.equal(1, #calls, 'nothing but the check is called')
    end
  end)

  it('sends the route\'s knobs and the five headers coaz-pep verifies', function()
    local state, calls = mcp('POST', TOOLS_CALL, { require_user_login = true, pdp_layers = { 'static', 'resource' }, resource = 'https://mcp.example/' }, nil, {
      headers = { authorization = token(), ['x-user-token'] = 'user.jwt.sig', dpop = 'proof', ['content-type'] = 'application/json',
        ['content-encoding'] = 'identity', ['x-other'] = 'not forwarded' },
    })
    assert.is_nil(state.exited)
    local sent = checks(calls)[1]
    assert.equal('mcp', sent.config.style)
    assert.equal('test-pep', sent.config.pep_label)
    assert.equal('true', sent.config.coaz_defaults, 'default mappings are on unless the route turns them off')
    assert.equal('true', sent.config.require_user_login)
    assert.equal('true', sent.config.require_token)
    assert.equal('http://mcp:8090/mcp', sent.config.mcp_upstream_url)
    assert.equal('static,resource', sent.config.pdp_layers)
    assert.equal('closed', sent.config.fail_mode)
    assert.equal('https://mcp.example', sent.config.resource)
    assert.equal('/mcp', sent.path)
    assert.same({ authorization = token(), ['x-user-token'] = 'user.jwt.sig', dpop = 'proof',
      ['content-type'] = 'application/json', ['content-encoding'] = 'identity' }, sent.headers)
    assert.equal('Bearer check-token', calls[1].headers['Authorization'])
    -- Only an explicit false opts out of the default mappings.
    local _, calls2 = mcp('POST', TOOLS_CALL, { coaz_defaults = false })
    assert.equal('false', checks(calls2)[1].config.coaz_defaults)
  end)

  it('applies the engine\'s upstream headers on a permit, an empty value clearing one', function()
    local state = mcp('POST', TOOLS_CALL, nil, {
      decision = true,
      upstream_headers = { ['X-Auth-Principal'] = 'alice', ['X-Auth-Agent'] = 'agent-1', ['X-Auth-Scope'] = '', ['X-Auth-Acr'] = '' },
      response_headers = { ['X-PDP-Action'] = 'tools/call:get_customer', ['X-PDP-Reason'] = 'ok' },
    })
    assert.is_nil(state.exited)
    assert.equal('alice', state.upstream_headers['X-Auth-Principal'])
    assert.equal('agent-1', state.upstream_headers['X-Auth-Agent'])
    assert.is_nil(state.upstream_headers['X-Auth-Scope'])
    assert.is_nil(state.upstream_headers['X-Auth-Acr'])
  end)

  it('relays the engine\'s deny verbatim', function()
    local rpc_error = '{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"denied by policy"}}'
    local state = mcp('POST', TOOLS_CALL, nil, {
      decision = false,
      response = { status = 200, headers = { ['Content-Type'] = 'application/json', ['X-PDP-Decision'] = 'DENY' }, body = rpc_error },
    })
    -- Relayed as-is: two renderings of one decision would drift.
    assert.equal(200, state.exited.status)
    assert.equal(rpc_error, state.exited.body)
    assert.equal('application/json', state.exited.headers['Content-Type'])
  end)

  it('permits only on a JSON true: anything else from the engine is a refusal, closed', function()
    for _, answer in ipairs({ { decision = 'true' }, { decision = 1 }, {}, '"yes"', 'not json' }) do
      local engine = type(answer) == 'string'
        and function() return { status = 200, body = answer } end or answer
      local state = mcp('POST', TOOLS_CALL, nil, engine)
      assert.equal(503, state.exited.status, mock.json_encode(answer))
      assert.is_nil(state.upstream_headers['X-Auth-Principal'])
    end
  end)

  it('FAILS CLOSED when the engine is unreachable, erroring or refusing the call', function()
    for _, engine in ipairs({ false, 500, 429, 401, 400, 302 }) do
      local state = mcp('POST', TOOLS_CALL, nil, engine)
      assert.equal(503, state.exited.status, tostring(engine))
      assert.equal('authorization_failed', state.exited.body.error)
    end
  end)

  it('a deny without a usable response is still a deny', function()
    local state = mcp('POST', TOOLS_CALL, nil, { decision = false, response = { status = 'teapot' } })
    assert.equal(403, state.exited.status)
  end)

  it('carries the engine\'s response headers to the client on a permit', function()
    local plugin, _, _ = engine_route({
      decision = true, upstream_headers = {},
      response_headers = { ['X-PDP-Action'] = 'tools/call:get_customer', ['X-PDP-Reason'] = 'Permitted by policy.' },
    }, { method = 'POST', path = '/mcp', body = TOOLS_CALL, headers = { authorization = token() } })
    local state = mock.proxy(plugin, mcp_conf())
    assert.equal('tools/call:get_customer', state.response_headers['X-PDP-Action'])
    assert.equal('Permitted by policy.', state.response_headers['X-PDP-Reason'])
    assert.equal('PERMIT', state.response_headers['X-PDP-Decision'])
    assert.equal('test-pep', state.response_headers['X-PDP-PEP'])
  end)

  it('passes a body in well-formed UTF-8, multi-byte characters and all', function()
    local body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"caf\195\169","arguments":{"note":"\240\159\152\128 \226\130\172"}}}'
    local state, calls = mcp('POST', body)
    assert.is_nil(state.exited)
    assert.equal(body, checks(calls)[1].body)
  end)

  it('refuses more headers than it will read, rather than miss a repeated one', function()
    local headers = { authorization = token() }
    for i = 1, 1001 do headers['x-pad-' .. i] = 'v' end
    for _, conf in ipairs({ mcp_conf(), base_conf() }) do
      local plugin, state, calls = engine_route(nil, { method = 'POST', path = '/mcp', body = TOOLS_CALL, headers = headers })
      mock.run_access(plugin, conf)
      assert.equal(431, state.exited.status)
      assert.equal(0, #calls)
    end
  end)
end)

describe('an MCP route refuses a body it cannot read in full or parse strictly', function()
  -- Contract section 1: a POST body must be exactly one JSON object the PEP positively
  -- understands. Anything else is refused here, with no call to coaz-pep.
  local function refused(body, over, extra)
    local opts = { method = 'POST', path = '/mcp', body = body,
      headers = { authorization = token(), ['content-type'] = 'application/json' } }
    for k, v in pairs(extra or {}) do opts[k] = v end
    if opts.headers_extra then
      for k, v in pairs(opts.headers_extra) do opts.headers[k] = v end
      opts.headers_extra = nil
    end
    local plugin, state, calls = engine_route(nil, opts)
    mock.run_access(plugin, mcp_conf(over))
    assert.is_truthy(state.exited, 'expected a refusal for ' .. tostring(body))
    assert.equal(0, #calls, 'nothing may reach coaz-pep')
    assert.equal('application/json', state.exited.headers['Content-Type'])
    assert.equal('DENY', state.exited.headers['X-PDP-Decision'])
    local rpc = state.exited.body
    assert.equal('2.0', rpc.jsonrpc)
    return state.exited.status, rpc.error.code, rpc.error.message, rpc.id
  end

  it('a body larger than the gateway will read is a 413, never an empty or partial body', function()
    local big = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"pad":"'
      .. string.rep('x', 9 * 1024) .. '"}}}'
    -- On Kong before 3.9 anything past client_body_buffer_size is out of reach.
    local status, code, message = refused(big, nil, { kong_version_num = 3007001 })
    assert.equal(413, status); assert.equal(-32600, code)
    assert.equal('Invalid Request: request body too large for the PEP to authorise', message)
    -- On 3.9+ it is read back from disk up to max_request_body_size, and beyond it refused.
    status = refused(big, { max_request_body_size = 4096 })
    assert.equal(413, status)
    -- The limit is the body's, wherever Kong buffered it: a body held in memory (a larger
    -- client_body_buffer_size) comes back whatever max is asked for. Found in the live run.
    status = refused(big, { max_request_body_size = 4096 }, { client_body_buffer_size = 65536 })
    assert.equal(413, status)
    -- Within the max, it is read whole and sent.
    local plugin, state, calls = engine_route(nil, { method = 'POST', path = '/mcp', body = big, headers = { authorization = token() } })
    mock.run_access(plugin, mcp_conf())
    assert.is_nil(state.exited)
    assert.equal(big, checks(calls)[1].body)
  end)

  it('a batch is refused, empty or not', function()
    for _, body in ipairs({ '[' .. TOOLS_CALL .. ']', '[]', '  [ ]' }) do
      local status, code, message = refused(body)
      assert.equal(400, status); assert.equal(-32600, code)
      assert.matches('^Invalid Request: ', message)
    end
  end)

  it('a Content-Encoding other than identity is a 415', function()
    for _, enc in ipairs({ 'gzip', 'br', 'identity, gzip' }) do
      local status, code, message = refused(TOOLS_CALL, nil, { headers_extra = { ['content-encoding'] = enc } })
      assert.equal(415, status); assert.equal(-32600, code)
      assert.equal('Invalid Request: Content-Encoding not supported by the PEP', message)
    end
  end)

  it('a BOM, invalid UTF-8, trailing data or anything not JSON is a parse error', function()
    for _, body in ipairs({ '\239\187\191' .. TOOLS_CALL, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\255"}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\237\160\128"}}',
      TOOLS_CALL .. ' {}', 'not json', '' }) do
      local status, code, message, id = refused(body)
      assert.equal(400, status, body); assert.equal(-32700, code, body)
      assert.equal('Parse error', message)
      assert.equal(mock.null, id)
    end
  end)

  it('anything but one JSON-RPC object is an invalid request', function()
    for _, body in ipairs({ '"tools/call"', '42', 'null', 'true',
      '{"jsonrpc":"2.0","id":1,"method":7}',
      '{"jsonrpc":"2.0","id":1}',
      '{"jsonrpc":"2.0","id":1,"result":{},"error":{}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":{"x":1}}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["get_customer"]}' }) do
      local status, code = refused(body)
      assert.equal(400, status, body); assert.equal(-32600, code, body)
    end
  end)

  it('member names that differ only in case are refused, at the top and in params', function()
    for _, body in ipairs({
      '{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"t"}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"},"Params":{"name":"make_payment"}}',
      '{"jsonrpc":"2.0","id":1,"ID":2,"method":"ping"}',
      '{"jsonrpc":"2.0","JSONRPC":"1.0","id":1,"method":"ping"}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance","Name":"make_payment"}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{},"ARGUMENTS":{"x":1}}}',
      '{"jsonrpc":"2.0","id":1,"\\u004dethod":"tools/call","method":"ping"}' }) do
      local status, code, message, id = refused(body)
      assert.equal(400, status, body); assert.equal(-32600, code, body)
      assert.matches('case', message)
      assert.is_not_nil(id)
    end
  end)

  it('echoes the request id when it could be read', function()
    local _, _, _, id = refused('{"jsonrpc":"2.0","id":"req-9","method":"tools/call","params":{}}')
    assert.equal('req-9', id)
  end)

  it('a body on anything but a POST is refused', function()
    for _, method in ipairs({ 'GET', 'DELETE' }) do
      local plugin, state, calls = engine_route(nil, { method = method, path = '/mcp', body = TOOLS_CALL, headers = { authorization = token() } })
      mock.run_access(plugin, mcp_conf())
      assert.equal(400, state.exited.status)
      assert.equal(-32600, state.exited.body.error.code)
      assert.equal(0, #calls)
    end
  end)

  it('a repeated identity header is refused rather than guessed at', function()
    local plugin, state, calls = engine_route(nil, { method = 'POST', path = '/mcp', body = TOOLS_CALL,
      headers = { authorization = { token({ sub = 'alice' }), token({ sub = 'mallory' }) } } })
    mock.run_access(plugin, mcp_conf())
    assert.equal(400, state.exited.status)
    assert.equal(0, #calls)
  end)
end)

describe('a REST route with coaz_url: coaz-pep decides the whole request', function()
  -- coaz-pep verifies the access token, X-User-Token and the DPoP proof itself, maps the
  -- request, discovers the PDPs and evaluates the layers. The plugin sends it the
  -- request and enforces the answer; it decodes no token and calls no PDP of its own.
  local function rest(method, path, body, over, engine, headers)
    local plugin, state, calls = engine_route(engine, { method = method, path = path, body = body,
      headers = headers or { authorization = token(), ['x-user-token'] = 'user.jwt.sig' } })
    mock.run_access(plugin, coaz_conf(over))
    return state, calls
  end

  it('sends the request and the route\'s knobs, and nothing else is called', function()
    local state, calls = rest('POST', '/payments', '{"from_account":"a","amount":50}',
      { require_dpop = true, require_user_login = true, stepup_scope = 'payments:approve', forward_access_token = true, legacy_subject_identity = false })
    assert.is_nil(state.exited)
    assert.equal(1, #calls)
    local sent = checks(calls)[1]
    assert.equal('rest', sent.config.style)
    assert.equal('true', sent.config.require_dpop)
    assert.equal('true', sent.config.require_user_login)
    assert.equal('payments:approve', sent.config.stepup_scope)
    assert.equal('make_payment', sent.config.stepup_action)
    assert.equal('true', sent.config.forward_access_token)
    assert.equal('false', sent.config.legacy_subject_identity)
    assert.equal('POST', sent.method)
    assert.equal('/payments', sent.path)
    assert.equal('{"from_account":"a","amount":50}', sent.body)
    assert.equal('user.jwt.sig', sent.headers['x-user-token'])
  end)

  it('no longer asks /v1/dpop/verify: the proof travels in the check', function()
    local _, calls = rest('GET', '/accounts/a/balance', nil, { require_dpop = true }, nil,
      { authorization = 'DPoP ' .. mock.jwt({ sub = 'alice', cnf = { jkt = 'T' } }), dpop = 'the.proof.jws' })
    for _, c in ipairs(calls) do assert.is_nil(c.url:find('/v1/dpop/verify', 1, true)) end
    assert.equal('the.proof.jws', checks(calls)[1].headers.dpop)
  end)

  it('leaves login to coaz-pep, which verifies X-User-Token', function()
    local challenge = '{"error":"login_required"}'
    local state = rest('GET', '/accounts/a/balance', nil, { require_user_login = true }, {
      decision = false,
      response = { status = 401, headers = { ['WWW-Authenticate'] = 'Bearer error="insufficient_user_authentication"', ['Content-Type'] = 'application/json' }, body = challenge },
    }, { authorization = token() })
    assert.equal(401, state.exited.status)
    assert.equal(challenge, state.exited.body)
    assert.equal('Bearer error="insufficient_user_authentication"', state.exited.headers['WWW-Authenticate'])
  end)

  it('refuses a body it cannot read in full', function()
    local state, calls = rest('POST', '/payments', '{"pad":"' .. string.rep('x', 9000) .. '"}', { max_request_body_size = 1024 })
    assert.equal(413, state.exited.status)
    assert.equal('authorization_failed', state.exited.body.error)
    assert.equal(0, #calls)
  end)
end)

describe('claim handling and remaining denials', function()
  it('denies a token with no readable subject', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ scope = 'a' }) }, -- no sub
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.matches('no subject claim', state.exited.body.reason)
  end)

  it('decodes an act claim that arrived as a JSON string', function()
    -- PingFederate serialises act as a string; read naively, every delegated call
    -- looks direct and the agent disappears from the audit trail.
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice', act = '{"sub":"agent-9"}' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('agent-9', state.upstream_headers['X-Auth-Agent'])
  end)

  it('carries an internal_transfer flag and a default account type into the request', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = token({ sub = 'alice' }) },
      body = '{"from_account":"a","to_account":"b","amount":5,"internal_transfer":true}',
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.is_true(sent.context.internal_transfer)

    local plugin2, state2 = load_plugin({
      method = 'POST', path = '/accounts',
      headers = { authorization = token({ sub = 'alice' }) },
      body = '{}',
      pdp = { decision = true },
    })
    mock.run_access(plugin2, base_conf())
    local sent2 = mock.json_decode(state2.pdp_requests[1].body)
    assert.equal('new:savings', sent2.resource.id)
  end)
end)

describe('subject.identity -> subject.id migration', function()
  local function sent_subject(over)
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({
        sub = 'alice', act = { sub = 'agent-7' }, client_id = 'c1' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf(over))
    return mock.json_decode(state.pdp_requests[1].body).subject
  end

  it('sends AuthZEN id', function()
    local subject = sent_subject()
    assert.equal('agent-7', subject.id)
    -- The agent is the subject; the human it acts for is a property.
    assert.equal('alice', subject.properties.on_behalf_of)
  end)

  it('still sends the legacy identity by default', function()
    -- Upgrading the gateway alone must not break a policy reading subject.identity.
    assert.equal('agent-7', sent_subject().identity)
  end)

  it('drops the legacy identity when turned off', function()
    local subject = sent_subject({ legacy_subject_identity = false })
    assert.is_nil(subject.identity)
    assert.equal('agent-7', subject.id)
  end)

  it('matches the Go PEP subject shape exactly', function()
    -- The two PEPs sending different subject shapes would be worse than either shape.
    local subject = sent_subject()
    assert.equal('agent', subject.type)
    assert.equal('agent-7', subject.id)
    assert.equal('ai_assistant', subject.properties.agent_type)
    assert.equal('c1', subject.properties.client_id)
  end)

  it('falls back to client_id then a placeholder', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice', client_id = 'c1' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('c1', mock.json_decode(state.pdp_requests[1].body).subject.id)

    local plugin2, state2 = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = token({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin2, base_conf())
    assert.equal('unknown-agent', mock.json_decode(state2.pdp_requests[1].body).subject.id)
  end)
end)

describe('layered fold keeps obligations', function()
  -- A permitting layer's obligation must survive a later layer's plain permit. Replacing
  -- the context wholesale let a generic PDP's "permit, but step up" be erased by the
  -- resource PDP's permit, and the request was then forwarded with no challenge at all.
  local T = (load_plugin({}))._TEST

  it('carries a step-up forward onto a later permit', function()
    local folded = T.merge_permit(
      { step_up_required = true, step_up_scope = 'banking:payments:transfer' },
      { reason = 'resource is fine' })
    assert.is_true(folded.step_up_required)
    assert.equal('banking:payments:transfer', folded.step_up_scope)
  end)

  it('carries identity proofing forward onto a later permit', function()
    local folded = T.merge_permit(
      { identity_proofing_required = true, identity_proofing_doctype = 'org.iso.18013.5.1.mDL' },
      { reason = 'resource is fine' })
    assert.is_true(folded.identity_proofing_required)
    assert.equal('org.iso.18013.5.1.mDL', folded.identity_proofing_doctype)
  end)

  it('lets the requiring layer own the parameter', function()
    local folded = T.merge_permit(
      { step_up_required = true, step_up_scope = 'first' },
      { step_up_required = true, step_up_scope = 'second' })
    assert.equal('first', folded.step_up_scope)
  end)

  it('keeps a later layer members when nothing was carried', function()
    local folded = T.merge_permit({}, { reason = 'resource is fine' })
    assert.equal('resource is fine', folded.reason)
    assert.is_nil(folded.step_up_required)
  end)

  it('recognises a context that already carries a challenge', function()
    assert.is_true(T.has_obligation({ step_up_required = true }))
    assert.is_true(T.has_obligation({ identity_proofing_required = true }))
    assert.is_false(T.has_obligation({ reason = 'nothing to resolve' }))
    assert.is_false(T.has_obligation(nil))
  end)
end)

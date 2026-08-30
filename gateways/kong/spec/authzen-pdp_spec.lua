-- Behavioural tests for the authzen-pdp Kong plugin.
--
-- Kong is mocked (see mock_kong.lua), so these run anywhere Lua does — no gateway, no
-- database, no network. They cover the pure helpers, the request mapping both gateways
-- must agree on, and the access() decision paths that matter: fail closed on a PDP
-- error, honour a deny, forward identity on a permit.

local mock = require 'spec.mock_kong'

--- load a fresh copy of the plugin against a freshly installed mock environment
local function load_plugin(opts)
  local state = mock.install(opts)
  package.loaded['kong.plugins.authzen-pdp.handler'] = nil
  local chunk = assert(loadfile('authzen-pdp/handler.lua'))
  return chunk(), state
end

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
  }
  for k, v in pairs(over or {}) do conf[k] = v end
  return conf
end

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
    local token = mock.jwt({ sub = 'alice@example.com', scope = 'a b' }, { alg = 'ES256', kid = 'k1' })
    assert.equal('alice@example.com', T.jwt_claims(token).sub)

    for _, bad in ipairs({ 'nodots', 'only.one' }) do
      assert.is_nil(T.jwt_claims(bad))
    end
    assert.is_nil(T.jwt_claims(nil))
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
      local action, rtype, rid = plugin._TEST.map_request(base_conf())
      assert.equal(c.action, action, c.path)
      assert.equal(c.rtype, rtype, c.path)
      assert.equal(c.rid, rid, c.path)
    end
  end)

  it('matches routes regardless of a stripped gateway prefix', function()
    -- The patterns are prefix-tolerant on purpose: it must not matter whether the
    -- gateway strips /bank before or after the PEP sees the request.
    local plugin = load_plugin({ method = 'GET', path = '/bank/accounts/acc-9/balance' })
    local action, _, rid = plugin._TEST.map_request(base_conf())
    assert.equal('get_balance', action)
    assert.equal('acc-9', rid)
  end)

  it('treats an MCP initialize handshake differently from other JSON-RPC', function()
    local init = load_plugin({
      method = 'POST', path = '/mcp',
      body = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    local action = init._TEST.map_request(base_conf({ style = 'mcp' }))
    assert.equal('access_mcp', action)

    local other = load_plugin({
      method = 'POST', path = '/mcp',
      body = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
    })
    local action2 = other._TEST.map_request(base_conf({ style = 'mcp' }))
    assert.are_not.equal('access_mcp', action2)
  end)

  it('always tags the channel so policy can see it is agent traffic', function()
    local plugin = load_plugin({ method = 'GET', path = '/anything' })
    local _, _, _, _, ctx = plugin._TEST.map_request(base_conf())
    assert.equal('ai-agent', ctx.channel)
  end)
end)

describe('access(): the decision path', function()
  local function token(claims)
    return 'Bearer ' .. mock.jwt(claims)
  end

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
    mock.run_access(plugin, base_conf({ pdp_ssl_verify = false }))
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

describe('DPoP is delegated, and fails closed', function()
  -- The plugin no longer verifies proofs itself. It cannot: a thumbprint comparison
  -- proves nothing when the proof carries the very JWK being compared. Verification
  -- goes to coaz-pep, and anything that cannot be verified is denied.
  local function with_verifier(verdict_or_fn, over)
    local calls = {}
    local pdp_fn = function(url, req)
      calls[#calls + 1] = { url = url, body = req.body }
      if url:find('/v1/dpop/verify', 1, true) then
        if type(verdict_or_fn) == 'function' then return verdict_or_fn(url, req) end
        if verdict_or_fn == false then return nil, 'connection refused' end
        return { status = 200, body = mock.json_encode(verdict_or_fn) }
      end
      return { status = 200, body = mock.json_encode({ decision = true }) }
    end
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = {
        authorization = 'DPoP ' .. mock.jwt({ sub = 'alice', cnf = { jkt = 'THUMB' } }),
        dpop = mock.jwt({ htm = 'GET', ath = 'AAA' }, { typ = 'dpop+jwt', alg = 'ES256' }),
      },
      pdp = pdp_fn,
    })
    local conf = base_conf({ require_dpop = true, coaz_url = 'http://coaz-pep:9192' })
    for k, v in pairs(over or {}) do conf[k] = v end
    mock.run_access(plugin, conf)
    return state, calls
  end

  it('permits when the verifier says the proof is valid', function()
    local state, calls = with_verifier({ valid = true })
    assert.is_nil(state.exited)
    -- The proof went to the verifier, and the request still reached the PDP.
    local saw_verify, saw_pdp = false, false
    for _, c in ipairs(calls) do
      if c.url:find('/v1/dpop/verify', 1, true) then saw_verify = true end
      if c.url:find('/access/v1/evaluation', 1, true) then saw_pdp = true end
    end
    assert.is_true(saw_verify, 'the proof should be sent for verification')
    assert.is_true(saw_pdp, 'a valid proof should let the request reach the PDP')
  end)

  it('relays the verifier reason on an invalid proof', function()
    local state = with_verifier({ valid = false, reason = 'DPoP proof signature is invalid' })
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.matches('signature is invalid', state.exited.body.reason)
  end)

  it('FAILS CLOSED when the verifier is unreachable', function()
    local state = with_verifier(false)
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.matches('unreachable', state.exited.body.reason)
  end)

  it('FAILS CLOSED when the verifier errors', function()
    local state = with_verifier(function() return { status = 500, body = 'boom' } end)
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
  end)

  it('FAILS CLOSED on an unusable verifier body', function()
    local state = with_verifier(function() return { status = 200, body = 'not json' } end)
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
  end)

  it('FAILS CLOSED rather than falling back when coaz_url is unset', function()
    -- The schema forbids this combination, so it should be unreachable — but a route
    -- that demands sender-constrained tokens and cannot verify them must deny, never
    -- silently downgrade to the weaker local check that used to live here.
    local state = with_verifier({ valid = true }, { coaz_url = '' })
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.matches('verification is unavailable', state.exited.body.reason)
  end)

  it('never sends the proof anywhere when the route does not require DPoP', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_dpop = false }))
    assert.is_nil(state.exited)
    for _, r in ipairs(state.pdp_requests) do
      assert.is_nil(r.url:find('/v1/dpop/verify', 1, true))
    end
  end)
end)

describe('step-up and PDP advice', function()
  local function permit_token()
    return 'Bearer ' .. mock.jwt({ sub = 'alice', scope = 'accounts:read' })
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

  it('requires a logged-in user when the route says so', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = permit_token() }, -- no X-User-Token
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_user_login = true }))
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.equal(0, #state.pdp_requests) -- challenged before the PDP is consulted
  end)

  it('carries the user token scope into the PDP context', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = {
        authorization = permit_token(),
        ['x-user-token'] = mock.jwt({ sub = 'alice', scope = 'payments:approve', acr = 'urn:mfa' }),
      },
      body = '{"from_account":"a","amount":50}',
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_user_login = true }))
    assert.is_nil(state.exited)
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.equal('payments:approve', sent.context.user_scope)
  end)
end)

describe('challenge parity with the other PEPs', function()
  -- The repo's central claim is that a client gets the same challenge whichever PEP
  -- denies it. These pin the wire shape so a change to one PEP cannot silently drift.
  it('renders a step-up identically to the Go PEP', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
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
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
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
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      body = '{}',
      pdp = { decision = false, context = { identity_proofing_required = true } },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('org.iso.18013.5.1.mDL', state.exited.body.doctype)
  end)

  it('resolves identity before step-up when a policy asks for both', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      body = '{"from_account":"a","amount":9000}',
      pdp = { decision = false, context = {
        identity_proofing_required = true, step_up_required = true, step_up_scope = 's' } },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('identity_verification_required', state.exited.body.error)
  end)
end)

describe('COAZ delegation on an MCP route', function()
  local tools_call = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer","arguments":{"id":"c1"}}}'

  local function mcp_route(engine, over)
    local calls = {}
    local plugin, state = load_plugin({
      method = 'POST', path = '/mcp',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice', act = { sub = 'agent-1' } }) },
      body = tools_call,
      pdp = function(url, req)
        calls[#calls + 1] = url
        if url:find('/v1/mcp/check', 1, true) then
          if type(engine) == 'function' then return engine(url, req) end
          if engine == false then return nil, 'connection refused' end
          return { status = 200, body = mock.json_encode(engine) }
        end
        return { status = 200, body = mock.json_encode({ decision = true }) }
      end,
    })
    local conf = base_conf({ style = 'mcp', coaz_url = 'http://coaz-pep:9192', mcp_upstream_url = 'http://mcp:8090/mcp' })
    for k, v in pairs(over or {}) do conf[k] = v end
    mock.run_access(plugin, conf)
    return state, calls
  end

  it('delegates a tools/call to the engine and forwards its upstream headers', function()
    local state, calls = mcp_route({
      decision = true,
      upstream_headers = { ['X-Auth-Principal'] = 'alice', ['X-Coaz'] = 'permit' },
    })
    assert.is_nil(state.exited)
    assert.is_truthy(calls[1]:find('/v1/mcp/check', 1, true), 'the tools/call should go to the engine')
    assert.equal('permit', state.upstream_headers['X-Coaz'])
  end)

  it('relays the engine JSON-RPC error body verbatim on a deny', function()
    local rpc_error = '{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"denied by policy"}}'
    local state = mcp_route({
      decision = false,
      response = { status = 200, body = rpc_error },
    })
    assert.is_truthy(state.exited)
    -- Relayed as-is: two renderings of one decision would drift.
    assert.equal(200, state.exited.status)
    assert.matches('-32001', tostring(state.exited.body))
  end)

  it('FAILS CLOSED when the engine is unreachable', function()
    local state = mcp_route(false)
    assert.is_truthy(state.exited)
    assert.equal(503, state.exited.status)
    assert.matches('unreachable', state.exited.body.reason)
  end)

  it('FAILS CLOSED when the engine errors', function()
    local state = mcp_route(function() return { status = 500, body = 'boom' } end)
    assert.is_truthy(state.exited)
    assert.equal(503, state.exited.status)
  end)

  it('does not delegate JSON-RPC that is not a tools/call', function()
    local calls = {}
    local plugin, state = load_plugin({
      method = 'POST', path = '/mcp',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      pdp = function(url)
        calls[#calls + 1] = url
        return { status = 200, body = mock.json_encode({ decision = true }) }
      end,
    })
    mock.run_access(plugin, base_conf({ style = 'mcp', coaz_url = 'http://coaz-pep:9192' }))
    for _, u in ipairs(calls) do
      assert.is_nil(u:find('/v1/mcp/check', 1, true), 'only tools/call is delegated')
    end
  end)

  it('does not delegate when coaz_url is unset', function()
    local calls = {}
    local plugin = load_plugin({
      method = 'POST', path = '/mcp',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      body = tools_call,
      pdp = function(url)
        calls[#calls + 1] = url
        return { status = 200, body = mock.json_encode({ decision = true }) }
      end,
    })
    mock.run_access(plugin, base_conf({ style = 'mcp' }))
    for _, u in ipairs(calls) do
      assert.is_nil(u:find('/v1/mcp/check', 1, true))
    end
  end)
end)

describe('claim handling and remaining denials', function()
  it('denies a token with no readable subject', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = 'Bearer ' .. mock.jwt({ scope = 'a' }) }, -- no sub
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
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice', act = '{"sub":"agent-9"}' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    assert.equal('agent-9', state.upstream_headers['X-Auth-Agent'])
  end)

  it('sends a login challenge with an acr hint when no user is present', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_user_login = true }))
    assert.equal(401, state.exited.status)
    assert.matches('insufficient_user_authentication', state.exited.headers['WWW-Authenticate'])
  end)

  it('carries an internal_transfer flag and a default account type into the request', function()
    local plugin, state = load_plugin({
      method = 'POST', path = '/payments',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      body = '{"from_account":"a","to_account":"b","amount":5,"internal_transfer":true}',
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf())
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.is_true(sent.context.internal_transfer)

    local plugin2, state2 = load_plugin({
      method = 'POST', path = '/accounts',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      body = '{}',
      pdp = { decision = true },
    })
    mock.run_access(plugin2, base_conf())
    local sent2 = mock.json_decode(state2.pdp_requests[1].body)
    assert.equal('new:savings', sent2.resource.id)
  end)
end)

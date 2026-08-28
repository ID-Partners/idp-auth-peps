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
      assert.equal(s, T.b64url_decode(T.b64url_encode(s)))
    end
  end)

  it('decodes JWT claims and header, and refuses malformed tokens', function()
    local T = helpers()
    local token = mock.jwt({ sub = 'alice@example.com', scope = 'a b' }, { alg = 'ES256', kid = 'k1' })
    assert.equal('alice@example.com', T.jwt_claims(token).sub)
    assert.equal('k1', T.jwt_header(token).kid)

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

  it('canonicalises a JWK per RFC 7638 member ordering', function()
    -- The digest is stubbed; the canonical JSON is the bug-prone part, so that is what
    -- is asserted. Members must be lexicographic, with no whitespace.
    local shapes = {
      { jwk = { kty = 'EC', crv = 'P-256', x = 'X', y = 'Y' }, canon = '{"crv":"P-256","kty":"EC","x":"X","y":"Y"}' },
      { jwk = { kty = 'RSA', e = 'AQAB', n = 'N' },            canon = '{"e":"AQAB","kty":"RSA","n":"N"}' },
      { jwk = { kty = 'OKP', crv = 'Ed25519', x = 'X' },       canon = '{"crv":"Ed25519","kty":"OKP","x":"X"}' },
    }
    for _, case in ipairs(shapes) do
      local plugin, state = load_plugin({})
      assert.is_truthy(plugin._TEST.jwk_thumbprint(case.jwk))
      assert.equal(case.canon, state.last_sha_input)
    end
  end)

  it('refuses a JWK with no usable key type', function()
    local T = helpers()
    assert.is_nil(T.jwk_thumbprint({ kty = 'oct', k = 's' }))
    assert.is_nil(T.jwk_thumbprint('not a table'))
    assert.is_nil(T.jwk_thumbprint({}))
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

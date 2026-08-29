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

describe('DPoP sender-constraint', function()
  -- The mock's SHA-256 is deterministic ("digest:" .. input), so the expected ath can
  -- be computed the same way the plugin does without needing real crypto here.
  local function expected_ath(plugin, token)
    return plugin._TEST.access_token_hash(token)
  end

  local function dpop_request(opts)
    local claims = opts.token_claims or { sub = 'alice', cnf = { jkt = 'THUMB' } }
    local token = mock.jwt(claims)
    local proof_claims = opts.proof_claims or {}
    if proof_claims.ath == nil and not opts.omit_ath then
      proof_claims.ath = '__COMPUTED__'
    end
    local proof = mock.jwt(proof_claims, { typ = 'dpop+jwt', alg = 'ES256', jwk = opts.jwk or { kty = 'EC', crv = 'P-256', x = 'X', y = 'Y' } })
    return token, proof, proof_claims
  end

  it('permits a proof whose key, method and token hash all match', function()
    -- Build in two passes: the first tells us the thumbprint and ath the plugin expects.
    local probe = load_plugin({})
    local jwk = { kty = 'EC', crv = 'P-256', x = 'X', y = 'Y' }
    local thumb = probe._TEST.jwk_thumbprint(jwk)
    local token = mock.jwt({ sub = 'alice', cnf = { jkt = thumb } })
    local ath = probe._TEST.access_token_hash(token)
    local proof = mock.jwt({ htm = 'GET', ath = ath, htu = '/accounts/a/balance' },
      { typ = 'dpop+jwt', alg = 'ES256', jwk = jwk })

    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = 'DPoP ' .. token, dpop = proof },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_dpop = true }))
    assert.is_nil(state.exited)
  end)

  it('REJECTS a proof minted for a different token (ath binding)', function()
    -- The regression: ath used to be checked for presence only, so a proof for one
    -- token replayed against any other.
    local probe = load_plugin({})
    local jwk = { kty = 'EC', crv = 'P-256', x = 'X', y = 'Y' }
    local thumb = probe._TEST.jwk_thumbprint(jwk)
    local token = mock.jwt({ sub = 'alice', cnf = { jkt = thumb } })
    local otherAth = probe._TEST.access_token_hash(mock.jwt({ sub = 'alice', jti = 'other' }))
    local proof = mock.jwt({ htm = 'GET', ath = otherAth }, { typ = 'dpop+jwt', alg = 'ES256', jwk = jwk })

    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = 'DPoP ' .. token, dpop = proof },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_dpop = true }))
    assert.is_truthy(state.exited)
    assert.equal(401, state.exited.status)
    assert.matches('ath does not match', state.exited.body.reason)
  end)

  it('rejects a bearer scheme, a missing proof, a jkt mismatch and a wrong method', function()
    local probe = load_plugin({})
    local jwk = { kty = 'EC', crv = 'P-256', x = 'X', y = 'Y' }
    local thumb = probe._TEST.jwk_thumbprint(jwk)
    local token = mock.jwt({ sub = 'alice', cnf = { jkt = thumb } })
    local ath = probe._TEST.access_token_hash(token)
    local good = mock.jwt({ htm = 'GET', ath = ath }, { typ = 'dpop+jwt', alg = 'ES256', jwk = jwk })

    local cases = {
      { name = 'bearer scheme', auth = 'Bearer ' .. token, proof = good },
      { name = 'no proof header', auth = 'DPoP ' .. token, proof = nil },
      { name = 'jkt bound elsewhere', auth = 'DPoP ' .. mock.jwt({ sub = 'alice', cnf = { jkt = 'SOMEONE-ELSE' } }), proof = good },
      { name = 'no cnf at all', auth = 'DPoP ' .. mock.jwt({ sub = 'alice' }), proof = good },
      { name = 'htm mismatch', auth = 'DPoP ' .. token,
        proof = mock.jwt({ htm = 'POST', ath = ath }, { typ = 'dpop+jwt', alg = 'ES256', jwk = jwk }) },
      { name = 'no ath', auth = 'DPoP ' .. token,
        proof = mock.jwt({ htm = 'GET' }, { typ = 'dpop+jwt', alg = 'ES256', jwk = jwk }) },
    }
    for _, c in ipairs(cases) do
      local headers = { authorization = c.auth }
      if c.proof then headers.dpop = c.proof end
      local plugin, state = load_plugin({
        method = 'GET', path = '/accounts/a/balance', headers = headers, pdp = { decision = true },
      })
      mock.run_access(plugin, base_conf({ require_dpop = true }))
      assert.is_truthy(state.exited, c.name .. ' should be denied')
      assert.equal(401, state.exited.status, c.name)
    end
  end)

  it('does not enforce DPoP when the route does not require it', function()
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a/balance',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) },
      pdp = { decision = true },
    })
    mock.run_access(plugin, base_conf({ require_dpop = false }))
    assert.is_nil(state.exited)
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

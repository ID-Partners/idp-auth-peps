-- PDP discovery for the Kong plugin: resource -> PDP -> endpoints, against the mocked
-- resty.http. Mirrors the Go discovery suite so the two PEPs agree on every rule.

local mock = require 'spec.mock_kong'

local function load(opts)
  local state = mock.install(opts)
  local D = assert(loadfile('authzen-pdp/discovery.lua'))()
  return D, state
end

local function load_plugin(opts)
  local state = mock.install(opts)
  package.loaded['kong.plugins.authzen-pdp.handler'] = nil
  return assert(loadfile('authzen-pdp/handler.lua'))(), state
end

local json = mock.json_encode

-- A responder that routes by URL: well-known documents, evaluation bodies, and
-- everything else 404. `routes` maps a URL (or prefix) to a table (JSON), a string
-- (raw body), a number (status), false (connection refused) or a function.
local function router(routes)
  local hits = {}
  local fn = function(url, req)
    hits[#hits + 1] = { url = url, method = req.method, headers = req.headers }
    -- Longest prefix wins, so an exact well-known route beats a host-wide one.
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

local function count(hits, needle)
  local n = 0
  for _, h in ipairs(hits) do if h.url:find(needle, 1, true) then n = n + 1 end end
  return n
end

local STATIC, GOOD, ROGUE, RES = 'https://static.example', 'https://good.example', 'https://rogue.example', 'https://api.example'

local function pdp_config(self, eval, evals)
  return {
    policy_decision_point = self,
    access_evaluation_endpoint = eval or (self .. '/custom/eval'),
    access_evaluations_endpoint = evals,
    capabilities = { 'urn:x:batch' },
  }
end

local function conf(over)
  local c = { authzen_url = STATIC, authzen_api_key = 'static-key', pdp_discovery = 'resource', pdp_metadata_ttl = 300 }
  for k, v in pairs(over or {}) do c[k] = v end
  return c
end

describe('discovery: URLs', function()
  it('derives well-known URLs with the insertion rule', function()
    local D = load({})
    local cases = {
      ['https://pdp.example'] = 'https://pdp.example/.well-known/authzen-configuration',
      ['https://pdp.example/'] = 'https://pdp.example/.well-known/authzen-configuration',
      ['https://pdp.example/tenant1'] = 'https://pdp.example/.well-known/authzen-configuration/tenant1',
      ['https://pdp.example/t/1/'] = 'https://pdp.example/.well-known/authzen-configuration/t/1',
      ['https://PDP.example:8443/x'] = 'https://pdp.example:8443/.well-known/authzen-configuration/x',
    }
    for input, want in pairs(cases) do
      assert.equal(want, D.well_known_url(input, 'authzen-configuration'))
    end
    for _, bad in ipairs({ 'pdp.example', '/relative', 'https://pdp.example/?x=1', 'https://pdp.example/#f', 'https:///x', 42 }) do
      local got, err = D.well_known_url(bad, 'authzen-configuration')
      assert.is_nil(got, tostring(bad))
      assert.is_string(err)
    end
  end)

  it('matches allowlist prefixes only at a path boundary', function()
    local D = load({})
    local list = { 'https://a.example/mcp', 'https://b.example/' }
    assert.is_true(D.allowed(list, 'https://a.example/mcp'))
    assert.is_true(D.allowed(list, 'https://a.example/mcp/x'))
    assert.is_false(D.allowed(list, 'https://a.example/mcpx'))
    assert.is_false(D.allowed(list, 'https://a.example/'))
    assert.is_true(D.allowed(list, 'https://b.example/anything'))
    assert.is_false(D.allowed(list, 'http://a.example/mcp'))
    assert.is_false(D.allowed(list, 'garbage'))
    assert.is_true(D.allowed(nil, 'https://x'))
    assert.is_true(D.allowed({}, 'https://x'))
    assert.is_false(D.allowed({ 'not a url' }, 'https://x'))
  end)

  it('applies the URL policy', function()
    local D = load({})
    assert.is_true(D.check_url('https://ok.example/x', {}))
    assert.is_false(D.check_url('http://ok.example/x', {}))
    assert.is_true(D.check_url('http://ok.example/x', { insecure = true }))
    assert.is_true(D.check_url('http://pdp:8080/.well-known/x', { trusted_origin = 'http://pdp:8080' }))
    assert.is_false(D.check_url('http://other:8080/x', { trusted_origin = 'http://pdp:8080' }))
    assert.is_false(D.check_url('http://pdp:8080/x', { trusted_origin = '://bad' }))
    assert.is_false(D.check_url('ftp://ok.example/x', {}))
    assert.is_false(D.check_url('/x', {}))
    assert.is_false(D.check_url('https://no.example/x', { allowlist = { 'https://ok.example' } }))
    assert.is_true(D.check_url('https://ok.example/x', { allowlist = { 'https://ok.example' } }))
  end)

  it('picks the resource identifier for a route', function()
    local D = load({})
    assert.equal('https://api.example', D.resource_id({ resource = 'https://api.example/' }))
    assert.equal('http://mcp:8090/mcp', D.resource_id({ style = 'mcp', mcp_upstream_url = 'http://mcp:8090/mcp' }))
    assert.equal('https://r', D.resource_id({ style = 'mcp', mcp_upstream_url = 'http://mcp', resource = 'https://r' }))
    assert.equal('', D.resource_id({ style = 'rest' }))
    assert.equal('', D.resource_id({ style = 'mcp', mcp_upstream_url = '' }))
  end)
end)

describe('discovery: off and authzen modes', function()
  it('off makes no requests and keeps the static key', function()
    local fn, hits = router({})
    local D = load({ pdp = fn })
    local ep = D.resolve(conf({ pdp_discovery = 'off' }), 'https://any')
    assert.same({ identifier = STATIC, evaluation = STATIC .. '/access/v1/evaluation',
      evaluations = STATIC .. '/access/v1/evaluations', api_key = 'static-key', source = 'static' }, ep)
    assert.equal(0, #hits)
    local nothing, err = D.resolve(conf({ pdp_discovery = 'off', authzen_url = '' }), '')
    assert.is_nil(nothing)
    assert.equal('transient', err.kind)
  end)

  it('authzen reads the static PDP metadata once and binds the key', function()
    local fn, hits = router({ [STATIC .. '/.well-known/authzen-configuration'] = pdp_config(STATIC, STATIC .. '/custom/eval', STATIC .. '/custom/evals') })
    local D = load({ pdp = fn })
    for _ = 1, 2 do
      local ep = D.resolve(conf({ pdp_discovery = 'authzen' }), 'https://ignored')
      assert.equal(STATIC .. '/custom/eval', ep.evaluation)
      assert.equal(STATIC .. '/custom/evals', ep.evaluations)
      assert.equal('static-key', ep.api_key)
      assert.same({ 'urn:x:batch' }, ep.capabilities)
    end
    assert.equal(1, #hits)
    assert.equal('application/json', hits[1].headers['Accept'])
    local nothing, err = D.resolve(conf({ pdp_discovery = 'authzen', authzen_url = '' }), '')
    assert.is_nil(nothing)
    assert.equal('transient', err.kind)
  end)

  it('falls back to the default paths on 404, 500 and connection failure', function()
    for _, r in ipairs({ 404, 500, false }) do
      local fn = router({ [STATIC] = r })
      local D = load({ pdp = fn })
      local ep = D.resolve(conf({ pdp_discovery = 'authzen' }), '')
      assert.equal(STATIC .. '/access/v1/evaluation', ep.evaluation, tostring(r))
    end
  end)

  it('rejects a document about another PDP, or without an evaluation endpoint, or not JSON', function()
    local cases = {
      { pdp_config('https://other.example'), 'policy_decision_point' },
      { { policy_decision_point = STATIC }, 'access_evaluation_endpoint' },
      { '<html>', 'not JSON' },
    }
    for _, c in ipairs(cases) do
      local fn = router({ [STATIC .. '/.well-known/authzen-configuration'] = c[1] })
      local D, state = load({ pdp = fn })
      local ep, err = D.resolve(conf({ pdp_discovery = 'authzen' }), '')
      assert.is_nil(ep)
      assert.equal('transient', err.kind)
      assert.matches(c[2], err.msg)
      assert.is_truthy(#state.logs > 0)
    end
  end)

  it('refuses an advertised endpoint outside the allowlist', function()
    local fn = router({ [STATIC .. '/.well-known/authzen-configuration'] = pdp_config(STATIC, STATIC .. '/eval', 'https://elsewhere.example/evals') })
    local D = load({ pdp = fn })
    local ep, err = D.resolve(conf({ pdp_discovery = 'authzen', pdp_allowlist = { 'https://pdp.example' } }), '')
    assert.is_nil(ep)
    assert.equal('not_allowed', err.kind)
  end)

  it('trusts the static PDP over http on its own origin, and nothing else', function()
    local fn = router({ ['http://pdp:8080/.well-known/authzen-configuration'] = pdp_config('http://pdp:8080', 'http://pdp:8080/eval', 'http://other:8080/evals') })
    local D = load({ pdp = fn })
    local ep, err = D.resolve(conf({ pdp_discovery = 'authzen', authzen_url = 'http://pdp:8080/' }), '')
    assert.is_nil(ep)
    assert.equal('not_allowed', err.kind)
    local ok = D.resolve(conf({ pdp_discovery = 'authzen', authzen_url = 'http://pdp:8080/', pdp_discovery_insecure = true }), '')
    assert.equal('http://other:8080/evals', ok.evaluations)
  end)

  it('treats a redirect or an oversized body as a transport failure', function()
    local big = string.rep('x', 1048577)
    for _, r in ipairs({ 302, function() return { status = 200, body = big } end, function() return { status = 200 } end }) do
      local fn = router({ [STATIC] = r })
      local D = load({ pdp = fn })
      local ep = D.resolve(conf({ pdp_discovery = 'authzen' }), '')
      assert.equal(STATIC .. '/access/v1/evaluation', ep.evaluation)
    end
  end)
end)

describe('discovery: resource mode', function()
  local function routes(over)
    local r = {
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD .. '/' }, ignored = true },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [ROGUE .. '/.well-known/authzen-configuration'] = pdp_config(ROGUE),
    }
    for k, v in pairs(over or {}) do r[k] = v end
    return r
  end

  it('follows the resource to its PDP and never relays the static key', function()
    local fn, hits = router(routes())
    local D = load({ pdp = fn })
    local ep = D.resolve(conf(), RES)
    assert.equal(GOOD, ep.identifier)
    assert.equal(GOOD .. '/custom/eval', ep.evaluation)
    assert.is_nil(ep.api_key)
    assert.equal('rfc9728', ep.source)
    -- The whole document rides along, verbatim, tagged with where it came from.
    assert.equal('rfc9728', ep.resource.source)
    assert.equal(RES, ep.resource.document.resource)
    assert.is_true(ep.resource.document.ignored)
    assert.equal(0, count(hits, STATIC))
    D.resolve(conf(), RES)
    assert.equal(1, count(hits, RES), 'resource metadata is cached')
    assert.equal(1, count(hits, GOOD), 'pdp metadata is cached')
  end)

  it('uses the static PDP for an empty resource, and keeps its key', function()
    local fn, hits = router(routes())
    local D = load({ pdp = fn })
    local ep = D.resolve(conf(), '')
    assert.equal(STATIC, ep.identifier)
    assert.equal('static-key', ep.api_key)
    assert.is_nil(ep.resource, 'nothing was read, so nothing is forwarded')
    assert.equal(0, count(hits, RES))
  end)

  it('falls to the static PDP when the resource has no usable metadata', function()
    local cases = {
      ['404'] = 404,
      ['no parameter'] = { resource = RES },
      ['echo mismatch'] = { resource = 'https://impostor.example', authzen_policy_decision_points = { GOOD } },
      ['bad entries'] = { resource = RES, authzen_policy_decision_points = { 'not a url', 1 } },
      ['entry with query'] = { resource = RES, authzen_policy_decision_points = { GOOD .. '/?x' } },
      ['empty list'] = { resource = RES, authzen_policy_decision_points = {} },
      ['not JSON'] = '<html>',
    }
    for name, doc in pairs(cases) do
      local fn = router(routes({ [RES .. '/.well-known/oauth-protected-resource'] = doc }))
      local D = load({ pdp = fn })
      local ep = D.resolve(conf(), RES)
      assert.equal(STATIC, ep.identifier, name)
      assert.equal('static-key', ep.api_key, name)
      assert.is_nil(ep.resource, name .. ': falling to static forwards no document')
    end
    -- An identifier that cannot have metadata at all.
    local D = load({ pdp = router(routes()) })
    assert.equal(STATIC, D.resolve(conf(), 'https://r.example/?x').identifier)
  end)

  it('falls to the static PDP on a transient failure without caching it as the answer', function()
    local down = router(routes({ [RES .. '/.well-known/oauth-protected-resource'] = 500 }))
    local D, state = load({ pdp = down })
    assert.equal(STATIC, D.resolve(conf(), RES).identifier)
    local e = D._cache().resources[RES]
    assert.is_falsy(e.ok)
    assert.is_truthy(e.neg_until)
    -- Within the negative window the resource is not re-fetched.
    local before = #state.pdp_requests
    D.resolve(conf(), RES)
    assert.equal(before, #state.pdp_requests)
    -- Past it, it is.
    state.now = state.now + 31
    D.resolve(conf(), RES)
    assert.is_true(#state.pdp_requests > before)
  end)

  it('serves the stale list while the resource is down after the TTL', function()
    local r = routes()
    local fn = router(r)
    local D, state = load({ pdp = fn })
    assert.equal(GOOD, D.resolve(conf(), RES).identifier)
    r[RES .. '/.well-known/oauth-protected-resource'] = 500
    state.now = state.now + 301
    assert.equal(GOOD, D.resolve(conf(), RES).identifier)
    -- Throttled: a second attempt inside MIN_REFRESH does not refetch.
    local before = #state.pdp_requests
    D.resolve(conf(), RES)
    assert.equal(before, #state.pdp_requests)
    -- Recovery clears the error.
    r[RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD } }
    state.now = state.now + 31
    assert.equal(GOOD, D.resolve(conf(), RES).identifier)
    assert.is_nil(D._cache().resources[RES].err)
  end)

  it('fails closed on a disallowed resource without fetching it', function()
    local fn, hits = router(routes())
    local D = load({ pdp = fn })
    local ep, err = D.resolve(conf({ resource_metadata_allowlist = { 'https://only.example' } }), RES)
    assert.is_nil(ep)
    assert.equal('not_allowed', err.kind)
    assert.equal(0, #hits)
  end)

  it('fails closed when the named PDP is outside the allowlist, even from another route\'s cache', function()
    local fn, hits = router(routes())
    local D = load({ pdp = fn })
    assert.equal(GOOD, D.resolve(conf(), RES).identifier) -- a permissive route fills the cache
    local ep, err = D.resolve(conf({ pdp_allowlist = { 'https://pdp.example' } }), RES)
    assert.is_nil(ep)
    assert.equal('not_allowed', err.kind)
    assert.equal(1, count(hits, GOOD), 'the strict route must not fetch the PDP again either')
    -- The static PDP is always permitted.
    assert.equal(STATIC, D.resolve(conf({ pdp_allowlist = { 'https://pdp.example' } }), '').identifier)
  end)

  it('re-checks cached endpoints against the calling route\'s allowlist', function()
    local fn = router(routes({ [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD, GOOD .. '/eval', 'https://batch.example/evals') }))
    local D = load({ pdp = fn })
    assert.equal(GOOD .. '/eval', D.resolve(conf(), RES).evaluation)
    local ep, err = D.resolve(conf({ pdp_allowlist = { GOOD } }), RES)
    assert.is_nil(ep)
    assert.equal('not_allowed', err.kind)
  end)

  it('refuses http for a discovered resource unless insecure', function()
    local fn = router({ ['http://r.example/.well-known/oauth-protected-resource'] = { resource = 'http://r.example', authzen_policy_decision_points = { GOOD } },
      [GOOD] = pdp_config(GOOD) })
    local D = load({ pdp = fn })
    local ep, err = D.resolve(conf(), 'http://r.example')
    assert.is_nil(ep)
    assert.equal('not_allowed', err.kind)
    assert.equal(GOOD, D.resolve(conf({ pdp_discovery_insecure = true }), 'http://r.example').identifier)
  end)

  it('tries the next candidate when the first PDP is unusable', function()
    local fn = router(routes({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { ROGUE, GOOD } },
      [ROGUE .. '/.well-known/authzen-configuration'] = pdp_config('https://x.example'),
    }))
    local D = load({ pdp = fn })
    assert.equal(GOOD, D.resolve(conf(), RES).identifier)
  end)

  it('reports no PDP when every candidate fails and there is no static one', function()
    local fn = router({ [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { ROGUE } },
      [ROGUE .. '/.well-known/authzen-configuration'] = pdp_config('https://x.example') })
    local D = load({ pdp = fn })
    local ep, err = D.resolve(conf({ authzen_url = '' }), RES)
    assert.is_nil(ep)
    assert.equal('transient', err.kind)
    assert.matches('no PDP could be resolved', err.msg)
    -- No metadata and no static PDP either.
    local D2 = load({ pdp = router({}) })
    local ep2, err2 = D2.resolve(conf({ authzen_url = '' }), RES)
    assert.is_nil(ep2)
    assert.equal('transient', err2.kind)
    -- Transient failure and no static PDP.
    local D3 = load({ pdp = router({ [RES] = 500 }) })
    local ep3, err3 = D3.resolve(conf({ authzen_url = '' }), RES)
    assert.is_nil(ep3)
    assert.equal('transient', err3.kind)
  end)

  it('caps the cache-serving of a pdp entry that failed transiently', function()
    -- A PDP whose metadata fetch is refused after a good first read keeps serving.
    local r = routes()
    local fn = router(r)
    local D, state = load({ pdp = fn })
    assert.equal(GOOD .. '/custom/eval', D.resolve(conf(), RES).evaluation)
    r[GOOD .. '/.well-known/authzen-configuration'] = pdp_config('https://x.example')
    state.now = state.now + 301
    assert.equal(GOOD .. '/custom/eval', D.resolve(conf(), RES).evaluation)
  end)
end)

describe('discovery: layers', function()
  local ESTATE = 'https://estate.example'
  local function routes(over)
    local r = {
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [ESTATE .. '/.well-known/authzen-configuration'] = pdp_config(ESTATE),
    }
    for k, v in pairs(over or {}) do r[k] = v end
    return r
  end

  it('resolves every layer in order, duplicates collapsed, with the resource document', function()
    local D = load({ pdp = router(routes()) })
    local r, err = D.resolve_layers(conf(), RES, { ESTATE, 'static', 'resource' })
    assert.is_nil(err)
    local eps, meta = r.pdps, r.meta
    assert.equal(3, #eps)
    assert.equal(ESTATE, eps[1].identifier); assert.equal('layer', eps[1].source); assert.is_nil(eps[1].api_key)
    assert.equal(STATIC, eps[2].identifier); assert.equal('static-key', eps[2].api_key)
    assert.equal(GOOD, eps[3].identifier)
    assert.equal('rfc9728', meta.source)
    assert.same({}, r.skipped)
    assert.is_false(eps[1].fail_open)
    local one = D.resolve_layers(conf(), RES, nil)
    assert.equal(1, #one.pdps); assert.equal(GOOD, one.pdps[1].identifier)
    local dup = D.resolve_layers(conf(), RES, { GOOD, 'resource' })
    assert.equal(1, #dup.pdps)
  end)

  it('parses a layer entry with its failure mode, and refuses what it cannot read', function()
    local D = load({ pdp = router({}) })
    assert.same({ name = ESTATE, fail_open = true }, D.parse_layer(ESTATE .. '/ fail-open'))
    assert.same({ name = 'resource', fail_open = false }, D.parse_layer('resource FAIL-CLOSED'))
    assert.same({ name = 'static' }, D.parse_layer(' static '))
    for _, bad in ipairs({ 'resource maybe', 'bogus', '' }) do
      local spec, err = D.parse_layer(bad)
      assert.is_nil(spec, bad); assert.is_string(err)
    end
    local r, err = D.resolve_layers(conf(), RES, { 'resource maybe' })
    assert.is_nil(r); assert.equal('invalid', err.kind)
  end)

  it('a fail-open layer that cannot be resolved is skipped; a refusal never is', function()
    local D = load({ pdp = router(routes()) })
    local bad = 'https://p.example/?x=1' -- invalid identifier: fails at resolution
    local r, err = D.resolve_layers(conf(), RES, { bad, 'resource' })
    assert.is_nil(r); assert.matches('layer', err.msg)
    r, err = D.resolve_layers(conf(), RES, { bad .. ' fail-open', 'resource' })
    assert.is_nil(err)
    assert.equal(1, #r.pdps); assert.equal(GOOD, r.pdps[1].identifier); assert.is_false(r.pdps[1].fail_open)
    assert.equal(1, #r.skipped); assert.matches('^' .. bad:gsub('%p', '%%%0'), r.skipped[1])
    -- The route default applies to layers that say nothing; the layer's own word wins.
    r, err = D.resolve_layers(conf(), RES, { bad, 'resource fail-closed' }, true)
    assert.is_nil(err); assert.equal(1, #r.skipped); assert.is_false(r.pdps[1].fail_open)
    r, err = D.resolve_layers(conf(), RES, { bad .. ' fail-closed' }, true)
    assert.is_nil(r); assert.is_table(err)
    -- Everything skipped is still a resolution, with nothing to ask.
    r = D.resolve_layers(conf(), RES, { bad }, true)
    assert.same({}, r.pdps); assert.equal(1, #r.skipped)
    -- A duplicate takes the stricter mode.
    r = D.resolve_layers(conf(), RES, { GOOD .. ' fail-open', 'resource fail-closed' })
    assert.equal(1, #r.pdps); assert.is_false(r.pdps[1].fail_open)
    -- The allowlist is a refusal, not an outage.
    r, err = D.resolve_layers(conf({ pdp_allowlist = { 'https://pdp.example' } }), RES, { ESTATE .. ' fail-open' }, true)
    assert.is_nil(r); assert.equal('not_allowed', err.kind)
  end)

  it('an explicit layer obeys the allowlist, names itself on failure, and reads nothing in off mode', function()
    local D = load({ pdp = router(routes()) })
    local eps, err = D.resolve_layers(conf({ pdp_allowlist = { 'https://pdp.example' } }), RES, { ESTATE })
    assert.is_nil(eps); assert.equal('not_allowed', err.kind); assert.matches('layer', err.msg)
    local D2 = load({ pdp = router({}) })
    local ep = D2.resolve_pdp(conf({ pdp_discovery = 'off' }), ESTATE .. '/')
    assert.equal(ESTATE .. '/access/v1/evaluation', ep.evaluation); assert.equal('layer', ep.source)
    local sk = D2.resolve_pdp(conf({ pdp_discovery = 'off' }), STATIC)
    assert.equal('static-key', sk.api_key)
  end)

  it('through access(): every layer is asked in order and the first deny is the answer', function()
    local calls = {}
    local fn = router({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [ESTATE .. '/.well-known/authzen-configuration'] = pdp_config(ESTATE),
      [ESTATE .. '/custom/eval'] = function(url, req)
        calls[#calls + 1] = 'estate'
        local body = mock.json_decode(req.body)
        if body.subject.properties.client_id == 'risky' then
          return { status = 200, body = json({ decision = false, context = { reason = 'client on the watch list' } }) }
        end
        return { status = 200, body = json({ decision = true }) }
      end,
      [GOOD .. '/custom/eval'] = function() calls[#calls + 1] = 'resource'; return { status = 200, body = json({ decision = true }) } end,
    })
    local drive = function(claims)
      local plugin, state = load_plugin({
        method = 'GET', path = '/accounts/a1/balance',
        headers = { authorization = 'Bearer ' .. mock.jwt(claims) }, pdp = fn,
      })
      mock.run_access(plugin, { authzen_url = STATIC, authzen_api_key = 'k', pep_label = 'test-pep', style = 'rest', require_token = true,
        pdp_ssl_verify = true, stepup_action = 'make_payment', pdp_discovery = 'resource', resource = RES, pdp_layers = { ESTATE, 'resource' } })
      return state
    end
    local state = drive({ sub = 'alice', client_id = 'good-client' })
    assert.is_nil(state.exited)
    assert.same({ 'estate', 'resource' }, calls)
    calls = {}
    local denied = drive({ sub = 'alice', client_id = 'risky' })
    assert.equal(403, denied.exited.status)
    assert.matches('watch list', denied.exited.body.reason)
    assert.same({ 'estate' }, calls)
  end)
end)

describe('discovery: fail-open through access()', function()
  local DOWN = 'https://down.example'
  local function drive(over, pdp_fn)
    local plugin, state = load_plugin({
      method = 'GET', path = '/accounts/a1/balance',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }) }, pdp = pdp_fn,
    })
    local c = { authzen_url = STATIC, authzen_api_key = 'k', pep_label = 'test-pep', style = 'rest',
      require_token = true, pdp_ssl_verify = true, stepup_action = 'make_payment', pdp_discovery = 'resource', resource = RES }
    for k, v in pairs(over or {}) do c[k] = v end
    mock.run_access(plugin, c)
    plugin:header_filter(c)
    return state
  end
  local function fn()
    return router({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [GOOD .. '/custom/eval'] = { decision = true },
      [DOWN .. '/.well-known/authzen-configuration'] = 404,
      [DOWN .. '/access/v1/evaluation'] = 503,
    })
  end

  it('closed by default: a failing layer is a 503', function()
    local state = drive({ pdp_layers = { DOWN, 'resource' } }, fn())
    assert.equal(503, state.exited.status)
  end)

  it('open on the layer: skipped, the rest decides, and the permit is marked', function()
    local state = drive({ pdp_layers = { DOWN .. ' fail-open', 'resource' } }, fn())
    assert.is_nil(state.exited)
    assert.equal(GOOD .. '/custom/eval', state.pdp_requests[#state.pdp_requests].url)
    assert.matches('^' .. DOWN:gsub('%p', '%%%0'), state.response_headers['X-PDP-Fail-Open'])
    assert.equal('PERMIT', state.response_headers['X-PDP-Decision'])
    -- Nothing skipped, no marker.
    local clean = drive({ pdp_layers = { 'resource' } }, fn())
    assert.is_nil(clean.exited); assert.is_nil(clean.response_headers['X-PDP-Fail-Open'])
  end)

  it('fail_mode on the route is the default; the layer\'s own word wins; everything skipped is a marked permit', function()
    local state = drive({ fail_mode = 'open', pdp_layers = { DOWN, 'resource' } }, fn())
    assert.is_nil(state.exited); assert.is_string(state.response_headers['X-PDP-Fail-Open'])
    local strict = drive({ fail_mode = 'open', pdp_layers = { DOWN .. ' fail-closed', 'resource' } }, fn())
    assert.equal(503, strict.exited.status)
    local all = drive({ fail_mode = 'open', pdp_layers = { DOWN } }, fn())
    assert.is_nil(all.exited); assert.matches('fail%-open', all.response_headers['X-PDP-Reason'])
  end)

  it('a deny is a decision, never skipped; an unreadable policy fails closed', function()
    local f = fn()
    local denying = router({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [GOOD .. '/custom/eval'] = { decision = false, context = { reason = 'no' } },
    })
    local state = drive({ fail_mode = 'open', pdp_layers = { 'resource fail-open' } }, denying)
    assert.equal(403, state.exited.status); assert.equal('no', state.exited.body.reason)
    local bad = drive({ fail_mode = 'open', pdp_layers = { 'resource maybe' } }, f)
    assert.equal(503, bad.exited.status)
  end)

  it('passes the policy and fail mode to the COAZ engine on MCP routes', function()
    local sent
    local f = router({ ['http://coaz-pep:9192/v1/mcp/check'] = function(_, req) sent = mock.json_decode(req.body); return { status = 200, body = json({ decision = true, upstream_headers = {} }) } end })
    local plugin, state = load_plugin({
      method = 'POST', path = '/mcp', body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}',
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }), ['content-type'] = 'application/json' }, pdp = f,
    })
    mock.run_access(plugin, { authzen_url = STATIC, pep_label = 'test-pep', style = 'mcp', require_token = true, pdp_ssl_verify = true,
      coaz_url = 'http://coaz-pep:9192', mcp_upstream_url = 'http://mcp:8090/mcp', pdp_layers = { DOWN .. ' fail-open', 'resource' }, fail_mode = 'open' })
    assert.is_nil(state.exited)
    assert.equal(DOWN .. ' fail-open,resource', sent.config.pdp_layers)
    assert.equal('open', sent.config.fail_mode)
  end)
end)

describe('federation entity relay', function()
  it('serves the two well-known documents from coaz-pep, and nothing else', function()
    local fn = router({
      ['http://coaz-pep:9192/.well-known/openid-federation'] = function()
        return { status = 200, body = 'eyJ.a.b', headers = { ['Content-Type'] = 'application/entity-statement+jwt' } }
      end,
      ['http://coaz-pep:9192/.well-known/oauth-protected-resource/bank'] = function()
        return { status = 200, body = '{"resource":"x"}', headers = { ['content-type'] = 'application/json' } }
      end,
      ['http://coaz-pep:9192/.well-known/oauth-protected-resource'] = false,
    })
    local drive = function(path, over)
      local plugin, state = load_plugin({ method = 'GET', path = path, headers = {}, pdp = fn })
      local c = { authzen_url = STATIC, pep_label = 'test-pep', style = 'rest', require_token = true, pdp_ssl_verify = true,
        federation_entity_url = 'http://coaz-pep:9192' }
      for k, v in pairs(over or {}) do c[k] = v end
      mock.run_access(plugin, c)
      return state
    end
    local ec = drive('/.well-known/openid-federation')
    assert.equal(200, ec.exited.status); assert.equal('eyJ.a.b', ec.exited.body)
    assert.equal('application/entity-statement+jwt', ec.exited.headers['Content-Type'])
    local doc = drive('/.well-known/oauth-protected-resource/bank')
    assert.equal(200, doc.exited.status); assert.equal('{"resource":"x"}', doc.exited.body)
    assert.equal('application/json', doc.exited.headers['Content-Type'])
    local down = drive('/.well-known/oauth-protected-resource')
    assert.equal(503, down.exited.status)
    -- Any other path is the plugin's ordinary business: no token, so a 401.
    assert.equal(401, drive('/accounts/a1/balance').exited.status)
    -- And so is a well-known path on a route that is nobody's federation face.
    assert.equal(401, drive('/.well-known/openid-federation', { federation_entity_url = ngx.null }).exited.status)
  end)
end)

describe('discovery: through access()', function()
  local function drive(over, pdp_fn, body, method, path)
    local plugin, state = load_plugin({
      method = method or 'GET', path = path or '/accounts/a1/balance', body = body,
      headers = { authorization = 'Bearer ' .. mock.jwt({ sub = 'alice' }), ['content-type'] = 'application/json' },
      pdp = pdp_fn,
    })
    local c = { authzen_url = STATIC, authzen_api_key = 'k', pep_label = 'test-pep', style = 'rest',
      require_token = true, pdp_ssl_verify = true, stepup_action = 'make_payment' }
    for k, v in pairs(over or {}) do c[k] = v end
    mock.run_access(plugin, c)
    return state
  end

  it('a REST route with a resource is decided by the resource\'s PDP, without the static key', function()
    local fn, hits = router({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [GOOD .. '/custom/eval'] = { decision = true },
    })
    local state = drive({ pdp_discovery = 'resource', resource = RES }, fn)
    assert.is_nil(state.exited)
    local eval = state.pdp_requests[#state.pdp_requests]
    assert.equal(GOOD .. '/custom/eval', eval.url)
    assert.is_nil(eval.headers['Authorization'])
    assert.equal(0, count(hits, STATIC))
    assert.equal('alice', state.upstream_headers['X-Auth-Principal'])
  end)

  it('forwards the resource document, the endpoint and (only when told) the token', function()
    local fn = router({
      [RES .. '/.well-known/oauth-protected-resource'] = { resource = RES, authzen_policy_decision_points = { GOOD }, scopes_supported = { 'accounts:read' } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [GOOD .. '/custom/eval'] = { decision = true },
    })
    local state = drive({ pdp_discovery = 'resource', resource = RES }, fn)
    assert.is_nil(state.exited)
    local sent = mock.json_decode(state.pdp_requests[#state.pdp_requests].body)
    assert.equal('rfc9728', sent.context.resource_metadata_source)
    assert.same({ 'accounts:read' }, sent.context.resource_metadata.scopes_supported)
    assert.equal(RES, sent.context.resource_metadata.resource)
    assert.same({ method = 'GET', path = '/accounts/a1/balance' }, sent.context.request)
    assert.is_nil(sent.context.access_token, 'the raw token is not forwarded unless the route says so')

    local fn2 = router({ [STATIC .. '/access/v1/evaluation'] = { decision = true } })
    local state2 = drive({ forward_access_token = true }, fn2)
    local sent2 = mock.json_decode(state2.pdp_requests[#state2.pdp_requests].body)
    assert.is_string(sent2.context.access_token)
    assert.is_nil(sent2.context.resource_metadata, 'static mode read no document')
  end)

  it('tells the COAZ engine to forward the token when the route says so', function()
    local fn = router({ ['http://coaz-pep:9192/v1/mcp/check'] = { decision = true, upstream_headers = {} } })
    local state = drive({ style = 'mcp', coaz_url = 'http://coaz-pep:9192', mcp_upstream_url = 'http://mcp:8090/mcp', forward_access_token = true }, fn,
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}', 'POST', '/mcp')
    assert.is_nil(state.exited)
    assert.equal('true', mock.json_decode(state.pdp_requests[1].body).config.forward_access_token)
  end)

  it('a REST route without a resource keeps the static PDP and its key', function()
    local fn = router({ [STATIC .. '/access/v1/evaluation'] = { decision = true } })
    local state = drive({ pdp_discovery = 'resource' }, fn)
    assert.is_nil(state.exited)
    local eval = state.pdp_requests[#state.pdp_requests]
    assert.equal(STATIC .. '/access/v1/evaluation', eval.url)
    assert.equal('Bearer k', eval.headers['Authorization'])
  end)

  it('FAILS CLOSED with a 503 when discovery refuses the resource', function()
    local fn, hits = router({})
    local state = drive({ pdp_discovery = 'resource', resource = RES, resource_metadata_allowlist = { 'https://only.example' } }, fn)
    assert.equal(503, state.exited.status)
    assert.matches('could not be resolved', state.exited.body.reason)
    assert.equal(0, #hits)
  end)

  it('an MCP route is keyed by its upstream', function()
    local mcp = 'https://mcp.example/mcp'
    local fn = router({
      [mcp .. '/.well-known/oauth-protected-resource'] = 404,
      ['https://mcp.example/.well-known/oauth-protected-resource/mcp'] = { resource = mcp, authzen_policy_decision_points = { GOOD } },
      [GOOD .. '/.well-known/authzen-configuration'] = pdp_config(GOOD),
      [GOOD .. '/custom/eval'] = { decision = true },
    })
    local state = drive({ pdp_discovery = 'resource', style = 'mcp', mcp_upstream_url = mcp }, fn,
      '{"jsonrpc":"2.0","id":1,"method":"initialize"}', 'POST', '/mcp')
    assert.is_nil(state.exited)
    assert.equal(GOOD .. '/custom/eval', state.pdp_requests[#state.pdp_requests].url)
  end)

  it('passes an explicit resource to the COAZ engine', function()
    local fn = router({ ['http://coaz-pep:9192/v1/mcp/check'] = { decision = true, upstream_headers = {} } })
    local state = drive({ style = 'mcp', coaz_url = 'http://coaz-pep:9192', mcp_upstream_url = 'http://mcp:8090/mcp', resource = RES }, fn,
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}', 'POST', '/mcp')
    assert.is_nil(state.exited)
    local sent = mock.json_decode(state.pdp_requests[1].body)
    assert.equal(RES, sent.config.resource)
    -- And is absent when the route has none.
    local fn2 = router({ ['http://coaz-pep:9192/v1/mcp/check'] = { decision = true, upstream_headers = {} } })
    local state2 = drive({ style = 'mcp', coaz_url = 'http://coaz-pep:9192', mcp_upstream_url = 'http://mcp:8090/mcp' }, fn2,
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}', 'POST', '/mcp')
    assert.is_nil(mock.json_decode(state2.pdp_requests[1].body).config.resource)
  end)
end)

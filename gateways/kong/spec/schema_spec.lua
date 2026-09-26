-- Both plugins' configuration schemas, loaded as Kong loads them, so the coverage gate
-- counts them and a validation rule is tested rather than read.

local mock = require 'spec.mock_kong'

local function load_schema(path)
  mock.install({})
  package.loaded['kong.db.schema.typedefs'] = {
    protocols_http = { type = 'set', elements = { type = 'string', one_of = { 'grpc', 'grpcs', 'http', 'https' } },
      default = { 'grpc', 'grpcs', 'http', 'https' } },
  }
  return assert(loadfile(path))()
end

-- The `config` record of a plugin schema.
local function config_of(schema)
  for _, f in ipairs(schema.fields) do
    if f.config then return f.config end
  end
end

-- The named field of a record, or nil.
local function field(record, name)
  for _, f in ipairs(record.fields) do
    if f[name] then return f[name] end
  end
end

-- A configuration as Kong would hand it to the validator: every default filled in.
local function defaults_of(config, over)
  local c = {}
  for _, f in ipairs(config.fields) do
    for name, def in pairs(f) do
      if def.default ~= nil then c[name] = def.default end
    end
  end
  for k, v in pairs(over or {}) do c[k] = v end
  return c
end

describe('the authzen-pdp schema', function()
  local config
  before_each(function() config = config_of(load_schema('authzen-pdp/schema.lua')) end)

  local function check(over)
    return config.custom_validator(defaults_of(config, over))
  end

  it('loads, with its name and the fields the handler reads', function()
    local schema = load_schema('authzen-pdp/schema.lua')
    assert.equal('authzen-pdp', schema.name)
    for _, name in ipairs({ 'authzen_url', 'authzen_api_key', 'style', 'coaz_url', 'pdp_layers', 'fail_mode',
      'access_token_verified_upstream', 'allow_insecure', 'max_request_body_size' }) do
      assert.is_table(field(config_of(schema), name), name)
    end
  end)

  it('governs every MCP method by default', function()
    assert.is_true(field(config, 'coaz_defaults').default)
  end)

  it('refuses an MCP route, DPoP or a user login without coaz-pep to decide it', function()
    local base = { authzen_url = 'https://pdp', authzen_api_key = 'k', access_token_verified_upstream = true }
    local function with(over) local o = {}; for k, v in pairs(base) do o[k] = v end; for k, v in pairs(over) do o[k] = v end; return o end
    for _, case in ipairs({
      { { style = 'mcp' }, 'style=mcp needs coaz_url' },
      { { require_dpop = true }, 'require_dpop needs coaz_url' },
      { { require_user_login = true }, 'require_user_login needs coaz_url' },
    }) do
      local ok, err = check(with(case[1]))
      assert.is_nil(ok)
      assert.matches(case[2], err, 1, true)
      assert.is_true(check(with((function() local o = { coaz_url = 'https://coaz', coaz_api_key = 'c' }; for k, v in pairs(case[1]) do o[k] = v end; return o end)())))
    end
  end)

  it('refuses a native route that reads unverified claims, unless it says who verified them', function()
    local ok, err = check({ authzen_url = 'https://pdp', authzen_api_key = 'k' })
    assert.is_nil(ok)
    assert.matches('access_token_verified_upstream', err)
    assert.is_true(check({ authzen_url = 'https://pdp', authzen_api_key = 'k', access_token_verified_upstream = true }))
    assert.is_true(check({ authzen_url = 'https://pdp', authzen_api_key = 'k', allow_insecure = true }))
    -- A null from Kong for an unset field is not a coaz_url.
    assert.is_nil((check({ authzen_url = 'https://pdp', authzen_api_key = 'k', coaz_url = ngx.null })))
  end)

  -- Contract section 5: a missing security setting is a configuration error, and
  -- allow_insecure is the one, explicit, way past it.
  local native = { authzen_url = 'https://pdp', authzen_api_key = 'k', access_token_verified_upstream = true }
  local function over(base, o)
    local c = {}
    for k, v in pairs(base) do c[k] = v end
    for k, v in pairs(o) do c[k] = v end
    return c
  end

  it('refuses discovery with no pdp_allowlist, since an empty one is any https PDP a resource names', function()
    for _, mode in ipairs({ 'authzen', 'resource' }) do
      local ok, err = check(over(native, { pdp_discovery = mode }))
      assert.is_nil(ok)
      assert.matches('pdp_allowlist', err)
      assert.is_true(check(over(native, { pdp_discovery = mode, pdp_allowlist = { 'https://pdp.example' } })))
      assert.is_true(check(over(native, { pdp_discovery = mode, allow_insecure = true })))
    end
    assert.is_true(check(native)) -- off discovers nothing
    -- With coaz_url, discovery is coaz-pep's, under its own PDP_ALLOWLIST.
    assert.is_true(check({ authzen_url = 'https://pdp', authzen_api_key = 'k', coaz_url = 'https://coaz', coaz_api_key = 'c', pdp_discovery = 'resource' }))
  end)

  it('refuses coaz_url without coaz_api_key: the check API authenticates its callers', function()
    local delegated = { authzen_url = 'https://pdp', authzen_api_key = 'k', coaz_url = 'https://coaz' }
    local ok, err = check(delegated)
    assert.is_nil(ok)
    assert.matches('coaz_api_key', err)
    assert.is_true(check(over(delegated, { coaz_api_key = '{vault://env/coaz-key}' })))
    assert.is_true(check(over(delegated, { allow_insecure = true })))
  end)

  it('refuses the weakening flags unless allow_insecure', function()
    for _, flag in ipairs({ { pdp_discovery_insecure = true }, { pdp_ssl_verify = false } }) do
      local ok, err = check(over(native, flag))
      assert.is_nil(ok)
      assert.matches('allow_insecure', err)
      assert.is_true(check(over(over(native, flag), { allow_insecure = true })))
    end
  end)

  it('marks both secrets encrypted and referenceable', function()
    for _, name in ipairs({ 'authzen_api_key', 'coaz_api_key' }) do
      assert.is_true(field(config, name).encrypted, name)
      assert.is_true(field(config, name).referenceable, name)
    end
    assert.is_false(field(config, 'allow_insecure').default)
  end)
end)

describe('allow_insecure is logged when the configuration loads', function()
  -- Kong calls a plugin's configure() with every configuration it holds, at worker start
  -- and on every change: the startup log contract section 5 asks for.
  local function configure(file, configs)
    local state = mock.install({})
    local plugin = assert(loadfile(file))()
    plugin:configure(configs)
    return table.concat(state.logs, '\n'), state
  end

  it('names each relaxation on an authzen-pdp route', function()
    local logs = configure('authzen-pdp/handler.lua', { {
      pep_label = 'demo', allow_insecure = true, pdp_discovery = 'resource', pdp_discovery_insecure = true, pdp_ssl_verify = false,
    }, {
      pep_label = 'mcp', allow_insecure = true, coaz_url = 'http://coaz-pep:9192', style = 'mcp',
    }, {
      pep_label = 'strict', access_token_verified_upstream = true,
    } })
    assert.matches('demo', logs)
    assert.matches('unverified', logs)
    assert.matches('pdp_allowlist', logs)
    assert.matches('plain http', logs)
    assert.matches('TLS verification', logs)
    assert.matches('coaz_api_key', logs)
    assert.is_nil(logs:find('strict', 1, true))
  end)

  it('names each relaxation on a sideband-pdp route', function()
    local logs = configure('sideband-pdp/handler.lua', { {
      pep_label = 'demo', allow_insecure = true, pdp_discovery = 'federation', verify_service_certificate = false,
      federation_resolve_url = 'http://anchor/resolve',
    } })
    assert.matches('pdp_allowlist', logs)
    assert.matches('TLS verification', logs)
    assert.matches('resolver', logs)
  end)

  it('says nothing, and does not fail, with nothing to configure', function()
    local logs = configure('authzen-pdp/handler.lua', nil)
    assert.equal('', logs)
    logs = configure('sideband-pdp/handler.lua', { { pep_label = 'x' } })
    assert.equal('', logs)
  end)
end)

describe('the sideband-pdp schema', function()
  local config
  before_each(function() config = config_of(load_schema('sideband-pdp/schema.lua')) end)
  local base = { service_url = 'https://paz.example', shared_secret = 's', secret_header_name = 'CLIENT-TOKEN' }
  local function check(o)
    local c = {}
    for k, v in pairs(base) do c[k] = v end
    for k, v in pairs(o or {}) do c[k] = v end
    return config.custom_validator(defaults_of(config, c))
  end

  it('loads, with its name and the fields the handler reads', function()
    local schema = load_schema('sideband-pdp/schema.lua')
    assert.equal('sideband-pdp', schema.name)
    for _, name in ipairs({ 'service_url', 'shared_secret', 'secret_header_name', 'pdp_layers', 'pdp_credentials', 'allow_insecure' }) do
      assert.is_table(field(config_of(schema), name), name)
    end
  end)

  it('refuses a service_url that is not an http or https URL with a host, and takes a vault reference', function()
    assert.is_true(check())
    local ok, err = check({ service_url = 'paz.example' })
    assert.is_nil(ok)
    assert.matches('service_url', err)
    -- service_url is referenceable; the validator sees the reference, not the URL.
    assert.is_true(check({ service_url = '{vault://env/paz-url}' }))
  end)

  it('refuses discovery with no pdp_allowlist, and the weakening flags, unless allow_insecure', function()
    local ok, err = check({ pdp_discovery = 'resource' })
    assert.is_nil(ok); assert.matches('pdp_allowlist', err)
    assert.is_true(check({ pdp_discovery = 'resource', pdp_allowlist = { 'https://pdp.example' } }))
    for _, flag in ipairs({ { pdp_discovery_insecure = true }, { verify_service_certificate = false } }) do
      local nok, ferr = check(flag)
      assert.is_nil(nok); assert.matches('allow_insecure', ferr)
      local o = { allow_insecure = true }
      for k, v in pairs(flag) do o[k] = v end
      assert.is_true(check(o))
    end
  end)

  it('refuses the resolver switch without its settings, or over plain http', function()
    local switch = { pdp_discovery = 'federation', pdp_allowlist = { 'https://pdp.example' },
      federation_resolve_url = 'https://anchor.example/resolve', federation_trust_anchor = 'https://anchor.example' }
    assert.is_true(check(switch))
    for _, missing in ipairs({ 'federation_resolve_url', 'federation_trust_anchor' }) do
      local o = {}
      for k, v in pairs(switch) do o[k] = v end
      o[missing] = ngx.null
      local ok, err = check(o)
      assert.is_nil(ok); assert.matches(missing, err)
    end
    local o = {}
    for k, v in pairs(switch) do o[k] = v end
    o.federation_resolve_url = 'http://anchor.example/resolve'
    local ok, err = check(o)
    assert.is_nil(ok); assert.matches('https', err)
    o.allow_insecure = true
    assert.is_true(check(o))
  end)

  it('marks every shared secret encrypted and referenceable', function()
    assert.is_true(field(config, 'shared_secret').encrypted)
    local creds = field(config, 'pdp_credentials').elements
    local secret = field(creds, 'shared_secret')
    assert.is_true(secret.encrypted)
    assert.is_true(secret.referenceable)
  end)
end)

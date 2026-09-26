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
end)

describe('the sideband-pdp schema', function()
  it('loads, with its name and the fields the handler reads', function()
    local schema = load_schema('sideband-pdp/schema.lua')
    assert.equal('sideband-pdp', schema.name)
    local config = config_of(schema)
    for _, name in ipairs({ 'service_url', 'shared_secret', 'secret_header_name', 'pdp_layers', 'pdp_credentials' }) do
      assert.is_table(field(config, name), name)
    end
  end)

  it('refuses a service_url that is not an http or https URL with a host', function()
    local config = config_of(load_schema('sideband-pdp/schema.lua'))
    assert.is_true(config.custom_validator({ service_url = 'https://paz.example' }))
    local ok, err = config.custom_validator({ service_url = 'paz.example' })
    assert.is_nil(ok)
    assert.matches('service_url', err)
  end)
end)

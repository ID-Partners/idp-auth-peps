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

describe('the authzen-pdp schema', function()
  it('loads, with its name and the fields the handler reads', function()
    local schema = load_schema('authzen-pdp/schema.lua')
    assert.equal('authzen-pdp', schema.name)
    local config = config_of(schema)
    for _, name in ipairs({ 'authzen_url', 'authzen_api_key', 'style', 'coaz_url', 'pdp_layers', 'fail_mode' }) do
      assert.is_table(field(config, name), name)
    end
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

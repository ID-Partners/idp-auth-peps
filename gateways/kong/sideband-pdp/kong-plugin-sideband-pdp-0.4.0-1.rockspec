package = "kong-plugin-sideband-pdp"
version = "0.4.0-1"

source = {
  url = "git+https://github.com/ID-Partners/idp-auth-peps.git",
  tag = "v0.4.0",
}

description = {
  summary = "Kong PEP for PingAuthorize's Sideband API, with PDP discovery from the resource's metadata or a federation resolver",
  detailed = [[
    A Kong Policy Enforcement Point that authorises every request through
    PingAuthorize's Sideband API - /sideband/request in the access phase,
    /sideband/response in the response phase - and finds the PDPs it calls from
    the protected resource's RFC 9728 metadata (authzen_policy_decision_points
    and the layers it publishes in authzen_policy_layers) or from an OpenID
    Federation resolve endpoint, with per-layer failure rules and per-PDP
    credentials. The sideband half descends from Ping's ping-auth plugin; the
    discovery and contract modules come from the authzen-pdp rock, which this
    one depends on. Kong Gateway 3.4 or later; 3.9 or later recommended.
  ]],
  homepage = "https://github.com/ID-Partners/idp-auth-peps",
  license = "Apache-2.0",
}

dependencies = {
  "lua >= 5.1",
  -- kong.plugins.authzen-pdp.discovery and .contract, required by name: one copy of
  -- each rule in Lua, owned by one rock.
  "kong-plugin-authzen-pdp == 0.4.0",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.sideband-pdp.handler"] = "gateways/kong/sideband-pdp/handler.lua",
    ["kong.plugins.sideband-pdp.schema"] = "gateways/kong/sideband-pdp/schema.lua",
    ["kong.plugins.sideband-pdp.sideband"] = "gateways/kong/sideband-pdp/sideband.lua",
  },
}

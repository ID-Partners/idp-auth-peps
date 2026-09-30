package = "kong-plugin-authzen-pdp"
version = "0.4.1-1"

source = {
  url = "git+https://github.com/ID-Partners/idp-auth-peps.git",
  tag = "v0.4.1",
}

description = {
  summary = "Kong PEP for AuthZEN PDPs with OpenID AuthZEN MCP profile (COAZ) support",
  detailed = [[
    A Kong Policy Enforcement Point that authorizes delegated AI-agent traffic
    against an AuthZEN Policy Decision Point (e.g. Ping Authorize via the
    authzen-adapter). With coaz_url set, the whole decision is delegated to the
    coaz-pep engine, which verifies the access token, X-User-Token and DPoP
    proof (RFC 9449), maps the request, and authorizes every MCP request -
    tools/call per the OpenID AuthZEN MCP profile - with JSON-RPC parsed
    strictly first. Without it, REST routes are decided natively on claims an
    auth plugin verified: RFC 8693 delegation, RFC 9470 step-up challenges,
    PDP discovery via RFC 9728 protected resource metadata and the AuthZEN
    .well-known/authzen-configuration document, with ordered policy layers.
    Also provides the discovery and contract modules sideband-pdp requires.
    Kong Gateway 3.4 or later; 3.9 or later recommended.
  ]],
  homepage = "https://github.com/ID-Partners/idp-auth-peps",
  license = "Apache-2.0",
}

dependencies = {
  "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.authzen-pdp.handler"] = "gateways/kong/authzen-pdp/handler.lua",
    ["kong.plugins.authzen-pdp.schema"] = "gateways/kong/authzen-pdp/schema.lua",
    ["kong.plugins.authzen-pdp.discovery"] = "gateways/kong/authzen-pdp/discovery.lua",
    ["kong.plugins.authzen-pdp.contract"] = "gateways/kong/authzen-pdp/contract.lua",
  },
}

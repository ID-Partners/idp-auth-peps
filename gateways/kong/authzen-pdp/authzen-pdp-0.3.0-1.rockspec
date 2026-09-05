package = "kong-plugin-authzen-pdp"
version = "0.3.0-1"

source = {
  url = "git+https://github.com/ID-Partners/idp-auth-peps.git",
  tag = "v0.3.0",
}

description = {
  summary = "Kong PEP for AuthZEN PDPs with OpenID AuthZEN MCP profile (COAZ) support",
  detailed = [[
    A Kong Policy Enforcement Point that authorizes delegated AI-agent traffic
    against an AuthZEN Policy Decision Point (e.g. Ping Authorize via the
    authzen-adapter): token/actor-claim extraction (RFC 8693 delegation),
    DPoP sender-constraint checks (RFC 9449), RFC 9470 step-up challenges,
    REST and MCP request mapping, and — for MCP tools declaring coaz:true —
    per-tool-call authorization per the OpenID AuthZEN MCP profile, delegated
    to the shared coaz-pep engine (discovery, CEL mapping, JSON-RPC errors).
    PDP discovery via RFC 9728 protected resource metadata and the AuthZEN
    .well-known/authzen-configuration document.
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
  },
}

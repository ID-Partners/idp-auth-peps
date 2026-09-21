# Kong plugin tests

Behavioural tests for `authzen-pdp` and `sideband-pdp`, run against a **mocked Kong** — no
gateway, no database, no network. Anywhere Lua and [busted](https://lunarmodules.github.io/busted/)
are installed:

```sh
cd gateways/kong
busted --lpath="./?.lua;./?/init.lua" spec/
```

## What is mocked, and why that is enough

[`mock_kong.lua`](mock_kong.lua) stubs the four things that only exist inside a running
gateway — the `ngx` and `kong` globals, `cjson.safe`, `resty.http` and `resty.sha256` —
with the smallest behaviour the plugin actually uses. A test then drives a request
through `access()` and inspects what came out: whether `kong.response.exit` fired and
with what status, which headers were set for the upstream, and exactly what body reached
the PDP.

Two deliberate choices:

- **`kong.response.exit` raises.** In Kong it is a non-local exit that never returns; a
  stub that simply recorded the call would let execution continue past a deny and every
  test would pass for the wrong reason. `run_access` unwinds it the way Kong does.
- **SHA-256 is a stub, and the canonical JSON is what gets asserted.** The digest is not
  where RFC 7638 goes wrong — member ordering is. The stub captures its input so the
  canonicalisation can be checked directly, which is a stronger test than comparing a
  hash.

`handler.lua` exposes its `local` helpers through an `AuthzenPDP._TEST` table at the
bottom of the file. Kong never reads it; it exists so the pure helpers and the request
mapping can be exercised without restructuring the plugin.

`sideband-pdp_spec.lua` drives the second plugin through both of its phases: `run_response`
absorbs Kong's exit the same way, `opts.upstream` is the buffered response the phase sees,
and the mock's `ngx.decode_args` returns two values as OpenResty's does — a plugin that
feeds it straight into a one-argument function fails here as it would in Kong. The mock
stops short of what only Kong can check: it will not refuse a plugin that has both a
`response` and a `header_filter`, so a handler change deserves one pass through a real
Kong as well.

## Coverage

The decision paths that matter: no token (denied before the PDP is ever called), permit
(delegation chain forwarded as `X-Auth-*`), deny (403 with the policy reason), and PDP
unreachable — which **must** fail closed with a 503, and is asserted as such.

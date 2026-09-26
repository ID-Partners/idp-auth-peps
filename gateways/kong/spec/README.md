# Kong plugin tests

Behavioural tests for `authzen-pdp` and `sideband-pdp`, run against a **mocked Kong** — no
gateway, no database, no network. Anywhere Lua and [busted](https://lunarmodules.github.io/busted/)
are installed:

```sh
cd gateways/kong
busted --lpath="./?.lua;./?/init.lua" spec/
../../scripts/lua-coverage-gate.sh
```

## What is mocked, and why that is enough

[`mock_kong.lua`](mock_kong.lua) stubs what only exists inside a running gateway — the `ngx`
and `kong` globals, `cjson.safe`, `resty.http`, `resty.sha256` and `resty.openssl.x509` —
with the behaviour the plugins rely on. A test then drives a request through `access()`
(and, for `sideband-pdp`, `response()`) and inspects what came out: whether
`kong.response.exit` fired and with what status, which headers were set or cleared for the
upstream, and exactly what reached the PDP or `coaz-pep`.

The mock is deliberately unfriendly where Kong is. Each of these hid a bypass while the
mock was kinder than the real thing, and [`mock_kong_spec.lua`](mock_kong_spec.lua) pins
them so it cannot drift back:

- **`get_raw_body` gives up past the buffer.** A body larger than `client_body_buffer_size`
  (8 KiB) is nil and an error unless Kong is 3.9 or later and asked for a max the body fits
  under. An absent body is `""`.
- **Headers, response headers and query arguments are capped** at 100 unless a caller asks
  for more, and say `"truncated"`.
- **`get_forwarded_*` read `X-Forwarded-*`** when the client is a trusted proxy;
  `get_path` is the normalised path and `get_raw_path` the one the client sent.
- **`cjson` behaves like `cjson`.** `encode` returns nil for inf and NaN; `decode` rejects
  trailing data, decodes `1e999` to inf, and decodes `null` to `cjson.null`, which is truthy
  and not a table. `decode_array_with_array_mt` marks arrays, so `[]` and `{}` differ.
- **`kong.response.exit` and `set_header` refuse what Kong refuses** — a status outside
  100-599, a JSON null as a header value — by raising, as Kong does.
- **`mock.proxy` runs a request as Kong does**: access; the response phase only under
  buffered proxying, which Kong turns off for an `Upgrade` request and, before 3.9, for
  HTTP/2; then `header_filter`.

Two deliberate choices beyond that:

- **`kong.response.exit` raises.** In Kong it is a non-local exit that never returns; a
  stub that simply recorded the call would let execution continue past a deny and every
  test would pass for the wrong reason. `run_access` unwinds it the way Kong does.
- **SHA-256 is a stub, and the canonical JSON is what gets asserted.** The digest is not
  where RFC 7638 goes wrong — member ordering is. The stub captures its input so the
  canonicalisation can be checked directly.

`handler.lua` exposes its `local` helpers through an `AuthzenPDP._TEST` table at the
bottom of the file. Kong never reads it; it exists so the pure helpers and the request
mapping can be exercised without restructuring the plugin. [`schema_spec.lua`](schema_spec.lua)
loads both plugins' schemas and calls their validators directly, so the configuration
refusals are tested rather than read, along with the `configure` phase that logs what
`allow_insecure` relaxes.

The mock stops short of what only Kong can check: it will not refuse a plugin that has
both a `response` and a `header_filter`, it runs on Lua 5.4 where Kong runs LuaJIT, and a
PDK change in a new release reaches it only when someone reads the source. So a handler
change deserves one pass through a real Kong as well — see the plugins' READMEs.

## Coverage

The decision paths that matter: no token (denied before the PDP is ever called), permit
(delegation chain forwarded as `X-Auth-*`, the client's own copies removed), deny (403 with
the policy reason), a PDP that is unavailable (fail-closed 503, or skipped and marked when
the layer is fail-open) and one that refuses (closed whatever the layer says), every MCP
body the contract refuses, and the sideband response phase Kong would skip.
`scripts/lua-coverage-gate.sh` holds the floor.

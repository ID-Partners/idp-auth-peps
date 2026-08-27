# core — the COAZ engine and the `coaz-pep` service

The shared decision logic behind every PEP in this repo. Go, one binary, two front doors.

```
coaz/            the OpenID AuthZEN MCP profile ("COAZ")
  discovery.go     tools/list over MCP streamable HTTP (JSON + SSE), TTL-cached
  build.go         x-coaz-mapping validation, compilation, and the processing rules
  cel.go           CEL compilation of mapping leaves (cel-go)
  engine.go        the flow: discover -> build -> ask the PDP -> JSON-RPC semantics
  types.go         mapping/verdict types, JSON-RPC error codes, AuthzChallenge
cmd/coaz-pep/    the service
  pep.go           Envoy ext_authz Check + the gateway-edge enforcement
  httpcheck.go     POST /v1/mcp/check — the same check over HTTP
  jwt.go           JWT decode + RFC 7638 thumbprints
  mapping.go       HTTP request -> AuthZEN action/resource/context
```

## Two front doors, one implementation

- **`:9191` — Envoy `ext_authz` gRPC.** agentgateway, Istio and Envoy attach here.
- **`:9192` — HTTP check API** (`POST /v1/mcp/check`). The Kong plugin calls this, and so
  can the Node SDK in `delegate` mode.

Kong has no credible CEL evaluator in Lua, and neither does Node. Rather than reimplement
`x-coaz-mapping` twice more and let three copies drift, both delegate the COAZ part here.

## What it enforces

`coaz/` implements the profile:

- **Discovery** — `tools/list` over streamable HTTP, stateless or with a session
  handshake, cached per upstream.
- **Mapping** — `x-coaz-mapping` validated and CEL-compiled, with `params` and `token` as
  input variables and the profile's rule that at least one subject or context field must
  derive from `token`. Without it, a mapping could authorise a request nobody authenticated.
- **Processing rules** — all fields single-element → the `evaluation` API; any field
  multi-element → `evaluations` (boxcar), single-element fields sitting at the top level as
  defaults and multi-element fields zipped.
- **Error semantics** — deny → `-32401` (with `data.authz_challenge` when the policy offers
  a remedy), mapping or CEL failure → `-32602`, discovery or PDP failure → `-32603`,
  fail-closed. Tools without `coaz: true` fall through to the host PEP's behaviour.
- **Claims normalisation** — object-valued claims serialised as JSON strings (PingFederate's
  `act`) are decoded, so `token.act.sub` resolves instead of silently reading nothing.

`cmd/coaz-pep/` wraps that with classic gateway-edge enforcement: delegated-token claims,
RFC 9449 DPoP binding, RFC 9470 step-up challenges, REST request mapping, fail-closed PDP
calls.

## Build and run

```sh
go build ./...
go test ./...          # the profile's worked examples

docker build -t coaz-pep .
docker run -p 9191:9191 -p 9192:9192 \
  -e AUTHZEN_URL=http://authzen-adapter:8080 \
  -e AUTHZEN_API_KEY=… coaz-pep
```

| Env | Meaning | Default |
| --- | --- | --- |
| `AUTHZEN_URL` | AuthZEN PDP base URL | required |
| `AUTHZEN_API_KEY` | Bearer key for the PDP | — |
| `PORT` | ext_authz gRPC port | 9191 |
| `HTTP_PORT` | HTTP check API port | 9192 |
| `COAZ_DISCOVERY_TTL` | `tools/list` cache TTL | 60s |
| `PDP_TLS_INSECURE` | skip PDP TLS verification (dev only) | false |

Per-route knobs are not env — they arrive as ext_authz `context_extensions` or in the
`config` object of an HTTP check. See [`../gateways/envoy/README.md`](../gateways/envoy/README.md).

## A note on `mapping.go`

The REST mapping is a direct port of `map_request` in the Kong plugin, so both gateways
send the PDP identical requests. Its route patterns are a specific banking API's
(`/customers/:id/accounts`, `/accounts/:id/balance`, …). Treat them as a worked example:
for your own API, either extend the switch or run the Node SDK, whose mapping you supply.

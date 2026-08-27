# idp-auth-peps

Policy Enforcement Points that speak **[OpenID AuthZEN 1.0](https://openid.net/wg/authzen/)**
to a PDP — in our deployments, **Ping Authorize** — and enforce the answer at whatever
sits in front of your traffic.

Three enforcement surfaces, one decision contract:

| | Where it runs | What it guards |
| --- | --- | --- |
| [`gateways/kong`](gateways/kong) | Kong Gateway, as a Lua plugin | REST + MCP |
| [`gateways/envoy`](gateways/envoy) | agentgateway (solo.io), Istio, plain Envoy — via `ext_authz` | REST + MCP |
| [`sdk/node`](sdk/node) | In your Node process, as Express middleware or an MCP guard | REST + MCP |

They share [`core/`](core) — the Go COAZ engine and the `coaz-pep` service that both
gateway surfaces call. That is the point: **a client gets the same challenge whichever
PEP denies it**, because there is one implementation of the decision and one of the
challenge, not three.

## Why a PEP at all

An MCP tool call from an AI agent is not a session. It is one agent, acting for one
human, touching one resource, right now — and whether it is allowed depends on all
three. That decision belongs in policy, not in tool code, which is what AuthZEN is for
and what these PEPs enforce.

The interesting part is the **deny**. A flat 403 tells an agent nothing it can act on,
so every PEP here returns a *resolvable* challenge when the policy offers one:

```
identity_proofing        present a verified credential (an mDL)   -> then retry
resource_authorisation   get the user to approve this scope       -> RFC 9470 step-up
authn                    there is no authenticated user yet       -> log in
```

Same three words in an HTTP `WWW-Authenticate` header, in a JSON body, and in an MCP
JSON-RPC error's `data.authz_challenge`. An agent can resolve a challenge without a
human reading prose.

## Layout

```
core/                        Go: the COAZ engine + the coaz-pep service
  coaz/                        AuthZEN MCP profile — discovery, CEL, processing rules
  cmd/coaz-pep/                ext_authz gRPC (:9191) + HTTP check API (:9192)
gateways/
  kong/authzen-pdp/            Kong Lua plugin
  envoy/agentgateway/          agentgateway (solo.io) attachment
  envoy/istio/                 Istio CUSTOM AuthorizationPolicy + EnvoyFilter
sdk/node/                    @id-partners/authzen-pep — TypeScript
```

### `core/` — the engine

One binary, two front doors, because Lua has no credible CEL evaluator and duplicating
the spec in it would guarantee drift:

- **`:9191` Envoy `ext_authz` gRPC** — what agentgateway, Istio and Envoy attach to.
- **`:9192` HTTP check API** (`POST /v1/mcp/check`) — what the Kong plugin calls, and
  what the Node SDK can delegate to.

```sh
cd core
go build ./... && go test ./...
docker build -t coaz-pep .
docker run -e AUTHZEN_URL=http://authzen-adapter:8080 -e AUTHZEN_API_KEY=… coaz-pep
```

| Env | Meaning | Default |
| --- | --- | --- |
| `AUTHZEN_URL` | AuthZEN PDP base URL | required |
| `AUTHZEN_API_KEY` | Bearer key for the PDP | — |
| `PORT` | ext_authz gRPC port | 9191 |
| `HTTP_PORT` | HTTP check API port | 9192 |
| `COAZ_DISCOVERY_TTL` | `tools/list` cache TTL | 60s |
| `PDP_TLS_INSECURE` | skip PDP TLS verification (dev only) | false |

Everything else — `style`, `require_token`, `require_dpop`, `mcp_upstream_url` — is
**per route**, and arrives as ext_authz `context_extensions` or the Kong plugin's config.

### `sdk/node/` — when there is no gateway

```ts
import { authzenMiddleware, pathMapper } from '@id-partners/authzen-pep/express';

app.use(authzenMiddleware({
  client: { url: process.env.AUTHZEN_URL!, apiKey: process.env.AUTHZEN_API_KEY },
  verifyToken: async (t) => (await jwtVerify(t, jwks)).payload,   // verify before you trust
  map: pathMapper([
    { method: 'GET',  pattern: '/accounts/:id/balance', action: 'get_balance',  resourceType: 'account', resourceId: p => p.id },
    { method: 'POST', pattern: '/payments',             action: 'make_payment', resourceType: 'payment' },
  ]),
}));
```

See [`sdk/node/README.md`](sdk/node/README.md) for the MCP guard, and for the one place
the SDK deliberately does less than the Go engine (CEL).

## The AuthZEN PDP

These are PEPs. They need a PDP to ask, exposing AuthZEN 1.0's
`/access/v1/evaluation(s)`. Ours are:

- **[dphhyland/idp-authzen-adapter-go](https://github.com/dphhyland/idp-authzen-adapter-go)** —
  a Go proxy that fronts Ping Authorize with the AuthZEN API, plus subject/resource
  search and an SSF receiver feed.
- **[dphhyland/idp-pingauthorize](https://github.com/dphhyland/idp-pingauthorize)**
  (`authzen-servlet/`) — the same API served **in-process** by PingAuthorize as a Server
  SDK `HTTPServletExtension`. No proxy hop.

Any conformant AuthZEN PDP works. The `step_up_required` / `identity_proofing_required`
decision-context keys are our convention, not AuthZEN's; a PDP that does not emit them
still gets clean permits and denies, just without resolvable challenges.

## Provenance

Assembled from work that was scattered across four repos. Fresh history; the components
came from:

| Here | Came from |
| --- | --- |
| `core/coaz`, `core/cmd/coaz-pep` | `idp-authzen-adapter-go/coaz-pep`, with the newer engine, `types.go` and `pep.go` from `idp-agentic-demo/coaz-pep` (which had drifted ahead of the package repo) |
| `core/go.mod`, `go.sum` | `idp-authzen-adapter-go` — it carried the Dependabot CVE bumps (grpc 1.79.3, x/net 0.55.0) the demo copy did not |
| `gateways/kong/authzen-pdp` | `idp-agentic-demo/kong/plugins/authzen-pdp` (PDP-driven step-up, `acr` forwarding), plus the rockspec from `idp-authzen-adapter-go` |
| `gateways/envoy/agentgateway` | `idp-agentic-demo/agentgateway` |
| `sdk/node` | New, seeded by the fail-closed `AuthzenPdpPlugin` in `mcp-interop/packages/shared` |

Earlier ancestors: `ID-Partners/idp-paz-authzen-adapter` (archived), the standalone
`authzen-coaz-pep`, and `ID-Partners-AU/kong-plugin-ping-auth` — Ping's official Kong
plugin, which predates AuthZEN and MCP entirely and is not carried forward here.

The demo that exercises all of this end to end is
[dphhyland/idp-agentic-demo](https://github.com/dphhyland/idp-agentic-demo).

## Licence

Apache-2.0.

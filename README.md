# idp-auth-peps

Policy Enforcement Points that speak **[OpenID AuthZEN 1.0](https://openid.net/wg/authzen/)**
to a PDP — in our deployments, **Ping Authorize** — and enforce the answer at whatever
sits in front of your traffic.

Four enforcement surfaces, one decision contract:

| | Where it runs | What it guards |
| --- | --- | --- |
| [`gateways/kong`](gateways/kong) | Kong Gateway, as a Lua plugin | REST + MCP |
| [`gateways/envoy`](gateways/envoy) | agentgateway (solo.io), Istio, plain Envoy — via `ext_authz` | REST + MCP |
| [`gateways/pingaccess`](gateways/pingaccess) | PingAccess, as an Add-on SDK rule (Java) | REST + MCP |
| [`sdk/node`](sdk/node) | In your Node process, as Express middleware or an MCP guard | REST + MCP |

A fifth surface, [`gateways/kong/sideband-pdp`](gateways/kong/sideband-pdp), is the Kong
plugin's discovery in front of PingAuthorize's Sideband API instead of AuthZEN: the same PDP
resolution and the same layers, but a deny — and so a challenge — is the policy's HTTP, not
this contract's.

The site, **[federated-enforcement.idpartners.global](https://federated-enforcement.idpartners.global)**,
is the way in: what this is, the one-page overview and the configuration reference.

They share [`core/`](core) — the Go COAZ engine and the `coaz-pep` service that the
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

**Start with [docs/architecture.md](docs/architecture.md)** (or the one-page
[overview](docs/overview.html), open it in a browser) for the map: what each piece
does, the decision contract, and how a PEP finds its PDP. **[docs/pingaccess.md](docs/pingaccess.md)**
is the explainer for the PingAccess rule, for administrators who know PingAccess but
not AuthZEN and the other way round. **Then [`demo/`](demo)** stands
the whole thing up — a stub federation, a good PDP and a rogue one — with one
`docker compose up`, and shows why the federation's word beats a resource's own: as a
scripted walkthrough, or a console on :8088 that runs one request through the three
`coaz-pep` modes and traces what each of them fetched. Profiles add Kong and PingAccess
doing the same discovery in front of the same resource.

The **[reference site](docs/reference/index.html)** documents every configurable item
of every component — coaz-pep, the Envoy family, the Kong plugin, the PingAccess rule, the
Node SDK and the demo — with complete configurations and, where a component has a
screen, screenshots of it. It lives at
[federated-enforcement.idpartners.global/docs/](https://federated-enforcement.idpartners.global/docs/),
and the hosted demo serves the same pages at
[demo-production-6ee6.up.railway.app/docs/](https://demo-production-6ee6.up.railway.app/docs/).

## Layout

```
docs/                        architecture.md — the explainer
site/                        the site: federated-enforcement.idpartners.global
demo/                        docker compose + scripts + a console: see discovery work
core/                        Go: the COAZ engine + the coaz-pep service
  coaz/                        COAZ — discovery, CEL, envelopes, trust anchoring
  authzen/discovery/           resource -> PDPs (and the layers in front of them) -> endpoints (RFC 9728, AuthZEN well-known, federation)
  federation/                  OpenID Federation 1.0 trust chain resolver
  jose/                        JWS verification shared by tokens, DPoP and federation
  cmd/coaz-pep/                ext_authz gRPC (:9191) + HTTP check API (:9192)
  cmd/demo-stubs/              the demo's stub federation and PDPs
  cmd/demo-console/            the demo's clickable walkthrough
gateways/
  kong/authzen-pdp/            Kong Lua plugin
  kong/sideband-pdp/           Kong Lua plugin: PingAuthorize's Sideband API, the same discovery
  envoy/agentgateway/          agentgateway (solo.io) attachment
  envoy/istio/                 Istio CUSTOM AuthorizationPolicy + EnvoyFilter
  pingaccess/authzen-pdp/      PingAccess Add-on SDK rule (Java, Maven)
sdk/node/                    @id-partners/authzen-pep — TypeScript
```

### `core/` — the engine

One binary, two front doors, because Lua has no credible CEL evaluator and duplicating
the spec in it would guarantee drift:

- **`:9191` Envoy `ext_authz` gRPC** — what agentgateway, Istio and Envoy attach to.
- **`:9192` HTTP check API** (`POST /v1/mcp/check`) — what the Kong plugin and the
  PingAccess rule call, and what the Node SDK can delegate to.

```sh
cd core
go build ./... && go test -race ./...
docker build -t coaz-pep .
docker run -e AUTHZEN_URL=http://authzen-adapter:8080 -e AUTHZEN_API_KEY=… \
  -e CHECK_API_TOKEN=… -e MCP_UPSTREAM_ALLOWLIST=… \
  -e ACCESS_TOKEN_JWKS_URL=… -e ACCESS_TOKEN_ISSUER=… -e ACCESS_TOKEN_AUDIENCE=… coaz-pep
```

It will not start without its security settings — the check API token, the upstream
allowlist, and the JWKS, issuer and audience to verify tokens against (plus the discovery
allowlists when discovery is on) — and says which are missing, all at once.
`PEP_ALLOW_INSECURE=true` starts it anyway for development, logging each gap. The full
environment reference, and how to operate it (readiness, the SIGTERM drain, audit logs,
metrics), is in [`core/README.md`](core/README.md#build-and-run).

Everything else — `style`, `require_token`, `require_dpop`, `mcp_upstream_url`,
`coaz_defaults` — is **per route**, and arrives as ext_authz `context_extensions` or the Kong
plugin's config.

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

### COAZ dialects

`authzen-mcp-profile-1_0` was superseded on 2026-02-13 by the
[COAZ Framework](https://openid.github.io/authzen/authzen-coaz-framework-1_0.html) and the
[COAZ-MCP binding](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html).
Every PEP here speaks both and picks per tool: `x-authzen-mapping` in a tool's
`inputSchema` is v2, `coaz: true` is the superseded v1. New tools should be v2 — among
other things it replaces the non-conformant `-32401` denial code with `-32001`, and it
verifies `subject.id` against the token so an MCP server cannot assert someone else's
identity. See [`core/README.md`](core/README.md#coaz-dialects) for the full table.

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
| `gateways/kong/sideband-pdp` | `ID-Partners-AU/kong-plugin-ping-auth` — Ping's `ping-auth` plugin, the sideband half; the discovery half is `authzen-pdp`'s module |
| `gateways/envoy/agentgateway` | `idp-agentic-demo/agentgateway` |
| `sdk/node` | New, seeded by the fail-closed `AuthzenPdpPlugin` in `mcp-interop/packages/shared` |

Earlier ancestors: `ID-Partners/idp-paz-authzen-adapter` (archived) and the standalone
`authzen-coaz-pep`.

The demo that exercises all of this end to end is
[dphhyland/idp-agentic-demo](https://github.com/dphhyland/idp-agentic-demo).

## Tests

```sh
cd core       && go test -race ./...
cd sdk/node   && npm ci && npm test
cd gateways/kong && busted --lpath="./?.lua;./?/init.lua" spec/
cd gateways/pingaccess/authzen-pdp && mvn verify   # needs the SDK jar: scripts/pingaccess-sdk.sh
demo/run-local.sh                                  # the whole walkthrough, no Docker
```

All four suites run offline. CI also runs govulncheck and `npm audit`, builds the image
and checks it refuses to start without its security settings, and runs the demo
walkthrough end to end. CI enforces a coverage **ratchet** — floors set just under the
current numbers, so a change that drops coverage fails while one that raises it does not
need the gate touched. Raise a floor when coverage rises; never lower one to make CI pass.

| | Coverage | Floor set in |
| --- | --- | --- |
| `core/coaz` | 96.0% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `core/cmd/coaz-pep` | 96.1% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `core/federation` | 98.8% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `core/jose` | 98.2% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `core/authzen/discovery` | 98.5% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `core/internal/ttlcache` | 100% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `core/internal/metafetch` | 97.1% | [`scripts/coverage-gate.sh`](scripts/coverage-gate.sh) |
| `sdk/node` | 99.8% stmts / 96.3% branches / 100% funcs | [`vitest.config.ts`](sdk/node/vitest.config.ts) |
| `gateways/kong` | 100% | [`scripts/lua-coverage-gate.sh`](scripts/lua-coverage-gate.sh) |
| `gateways/pingaccess` | 99.6% lines / 96.1% branches | [`pom.xml`](gateways/pingaccess/authzen-pdp/pom.xml) (JaCoCo) |

The target is **100% of what can be meaningfully tested, with the rest named** — not a
coverage-number fetish. Two things are deliberately excluded from the Go gate, and only
these two (the PingAccess gate excludes one class, `PaResponses`, for the same reason: it
needs the running engine, and the demo exercises it):

- **`main()` itself.** Its configuration is `buildServer` and `grpcServerOptions`, tested
  across the configuration matrix, and serving and draining is `run`, tested with a real
  listener and a signal; `main()` only binds the socket and wires the signal, so a test
  would be exercising the standard library. It is a thin, documented shell.
- **Defensive `err != nil` / type-guard branches that cannot fire on validated input** —
  a `json.Marshal` of a struct that always marshals, an AST fall-through the CEL compiler
  rules out, an object-claim that has already been type-checked. Forcing these with
  contrived inputs would test the test, not the code.

Everything else is covered, including — aggressively — COAZ discovery over SSE: split
data frames, CRLF, keepalive comments, oversized frames, the session handshake, and
content-type confusion, each driven end to end so a framing bug surfaces as a wrong
authorization decision rather than a parser detail. See `core/coaz/sse_torture_test.go`
and the matching SDK suite.

## Releases

A `v*` tag releases every component at one version: the `coaz-pep` image on
`ghcr.io/id-partners/coaz-pep` (amd64 and arm64, signed with cosign, with an SBOM and build
provenance), both Kong rocks (install authzen-pdp's first), the PingAccess rule's jar, and
the Node SDK as an npm package - `npm install ./id-partners-authzen-pep-<version>.tgz`.
Publishing `@id-partners/authzen-pep` to npm, with provenance, is opt-in: a release does
it while the repository variable `NPM_PUBLISH` is `true`, and `scripts/release.sh npm
vX.Y.Z` publishes an earlier release's SDK. A tag like `v0.4.0-rc1` is a candidate for
that version: the same jobs, the image pushed under the candidate's tag only, a prerelease
on GitHub, and npm only as a dry run, since an npm version cannot be taken back.
[`scripts/release.sh`](scripts/release.sh) cuts them: `bump X.Y.Z` moves every component
to a version, `rc` tags the next candidate, and `final` tags the release on the commit a
passing candidate was cut from. What changed, and what to do about it when
upgrading, is in [CHANGELOG.md](CHANGELOG.md). To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Licence

Apache-2.0.

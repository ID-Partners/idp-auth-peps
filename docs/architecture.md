# Architecture

What is in this repository, how the pieces fit, and the decisions behind them. The
per-component READMEs cover installation and every knob; this page is the map.

## The problem, in one paragraph

An AI agent calling a tool is one agent, acting for one human, touching one resource,
right now. Whether that is allowed depends on all three, and it belongs in policy, not
in tool code. OpenID AuthZEN gives a Policy Enforcement Point (PEP) a standard way to ask
a Policy Decision Point (PDP) that question. This repository is the enforcement side:
three PEPs for three places traffic already flows through, with one decision contract
between them so a client sees the same answer, and the same *resolvable* challenge on a
deny, whichever one said no.

## The pieces

```
                      agent / MCP client
                             │
        ┌────────────────────┼─────────────────────┐
        ▼                    ▼                     ▼
   Kong Gateway       Envoy / Istio /         Node process
   (Lua plugin)       agentgateway            (Express middleware
        │             (ext_authz gRPC)         or McpGuard)
        │                    │                     │
        │  /v1/mcp/check     │                     │  delegate (optional)
        └─────────►  coaz-pep (Go)  ◄──────────────┘
                     ├─ COAZ engine: tools/list discovery, CEL mapping, JSON-RPC errors
                     ├─ token + DPoP verification
                     ├─ PDP discovery: RFC 9728 / AuthZEN well-known / OpenID Federation
                     └─ challenge rendering
                             │  AuthZEN 1.0  POST access/v1/evaluation(s)
                             ▼
                        the PDP (Ping Authorize via its adapter, or any conformant PDP)
```

| Component | Where | What it does |
| --- | --- | --- |
| [`core/`](../core) | Go module | `coaz-pep`, the shared engine. Two front doors: Envoy `ext_authz` gRPC on :9191 and an HTTP check API on :9192. Everything with a spec behind it lives here once. |
| [`gateways/kong/`](../gateways/kong) | Lua plugin | A Kong PEP. Native Lua for claims, REST mapping, challenges and PDP discovery; delegates DPoP verification and COAZ tool-call checks to `coaz-pep`, because a Kong plugin has no JOSE verifier and no CEL. |
| [`gateways/envoy/`](../gateways/envoy) | YAML | How agentgateway, Istio and plain Envoy attach to `coaz-pep`. No code: the gateway only points at the engine. |
| [`sdk/node/`](../sdk/node) | TypeScript | `@id-partners/authzen-pep`: an AuthZEN client, Express middleware, and an MCP guard for a process that is its own PEP. Evaluates a CEL subset itself; can delegate to `coaz-pep` for the rest. |
| [`demo/`](../demo) | Compose + scripts | A stub federation, a good PDP and a rogue one, and three `coaz-pep` instances in three discovery modes. Stands up with `docker compose up` or with `run-local.sh`. |

Inside `core/`:

| Package | Role |
| --- | --- |
| `cmd/coaz-pep` | The service: request mapping, token and DPoP checks, the two front doors, config from the environment. |
| `coaz` | The COAZ engine: `tools/list` discovery, the v1 and v2 mapping dialects, CEL evaluation, PDP calls, JSON-RPC error semantics. |
| `authzen/discovery` | Resource → PDP identifier → PDP metadata → endpoints. Four modes; see below. |
| `federation` | An OpenID Federation 1.0 Trust Chain resolver: fetching, the §3.2 validation rules, the §4 invariants, §6.1 metadata policy, §6.2 constraints. |
| `jose` | Compact JWS verification for the ES/RS/PS families, JWK parsing, RFC 7638 thumbprints. Shared by token validation, DPoP and federation. |
| `internal/ttlcache`, `internal/metafetch` | The one cache shape and the one bounded, policy-checked GET that every metadata fetch uses. |
| `cmd/demo-stubs` | The demo's cast of stub services. Not for production. |

## The decision contract

Every PEP sends the PDP an AuthZEN request shaped the same way: the *agent* is the
subject (`subject.id` from the token's `act.sub`, falling back to `client_id`), the human
it acts for is `subject.properties.on_behalf_of`, and the request context carries what the
policy needs to reason about the delegation: the user token's scope, `acr`, any RFC 9396
`authorization_details`, and the token audience.

The interesting part is the deny. A flat 403 tells an agent nothing it can act on, so a
policy that says *how* to resolve a deny gets that rendered three consistent ways:

| The policy says | HTTP | `WWW-Authenticate` | JSON-RPC `data.authz_challenge.type` |
| --- | --- | --- | --- |
| `identity_proofing_required` | 401 | `identity_verification_required` | `identity_proofing` |
| `step_up_required` (RFC 9470) | 401 | `insufficient_scope` | `resource_authorisation` |
| no authenticated user | 401 | `login_required` | `authn` |

The same three words in a header, in a JSON body and in an MCP error, from all three
PEPs. That is why there is one engine and not three: two renderings of one decision would
drift.

## Three surfaces, one implementation

The rule for what lives where: **anything with a spec behind it is implemented once, in
Go, and the other surfaces either reuse it natively when that is safe or delegate to it
when it is not.**

- The Kong plugin can decode a JWT, map a REST request, render a challenge and fetch a
  JSON document. It cannot verify a signature (no JOSE library is available to a plugin)
  or evaluate CEL. So it does the first list in Lua and delegates DPoP and COAZ tool calls
  to `coaz-pep` over the HTTP check API.
- The Node SDK can do more in-process, and does: a deliberately narrow CEL subset, so a
  mapping that needs more raises a mapping error rather than guessing. Anything past the
  subset is delegated, exactly as Kong does.
- Envoy-family gateways never see any of this. They attach `ext_authz` to `coaz-pep` and
  carry per-route knobs in `context_extensions`.

The per-route knobs are the same map everywhere (`style`, `require_token`,
`require_dpop`, `mcp_upstream_url`, `resource`, …): Kong plugin config, ext_authz
context extensions, or the `config` object of an HTTP check.

## COAZ: authorising a tool call

For MCP, the PEP does not authorise "POST /mcp". It reads the JSON-RPC body, finds the
tool, and authorises *that call* under the OpenID AuthZEN MCP profile (COAZ): the MCP
server's `tools/list` declares, per tool, how to map the call's arguments and the token's
claims into an AuthZEN request. The engine caches `tools/list`, compiles the mapping, and
evaluates it per call. Two dialects are supported; the v2 one has a trust anchor worth
understanding: where a mapping sets `subject.id` from `$token.sub`, the PEP verifies that
its resolved value equals that claim, so an MCP server cannot name a different subject.
Deny and error semantics are JSON-RPC errors over HTTP 200, as the profile requires.

## Finding the PDP

Until recently every PEP was *told* where the PDP is (`AUTHZEN_URL`) and assumed the
AuthZEN paths under it. Discovery replaces both assumptions with metadata:

```
resource identifier (the route's `resource`; an MCP route's upstream URL)
  ├─ federation   resolved oauth_resource metadata from a Trust Chain     ← authoritative
  ├─ resource     {resource}/.well-known/oauth-protected-resource (RFC 9728) ← self-asserted
  └─ static       AUTHZEN_URL                                             ← always the fallback
PDP identifier
  ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9)
  └─ 404 → {pdp}/access/v1/evaluation, the spec's default paths
```

No standard names a PDP from a protected resource: not RFC 9728, not AuthZEN 1.0, not the
MCP profile, not OpenID Federation 1.0. So this repository mints one parameter and uses it
everywhere:

```json
"authzen_policy_decision_points": ["https://pdp.example"]
```

An array of PDP *identifiers*, first preferred, and the same bytes whether it sits in an
RFC 9728 document or under `metadata.oauth_resource` in a federation Entity Statement.

### Why the federation's word beats the resource's own

The value being discovered is "who may decide access to this resource". A document the
resource publishes about itself cannot protect the thing it asserts: a compromised or
careless resource can name a PDP that permits everything, and a PEP that trusted the
document would enforce nothing. That is what the demo's *impostor* resource does.

In a federation, the resource's Entity Configuration is only the starting point. What the
PEP uses is the *Resolved Metadata*: what survives every Superior's `metadata_policy`,
signed back to a Trust Anchor whose keys the operator configured out of band. A
federation operator can therefore pin, per resource, which PDPs may decide for it, with
`subset_of` and `essential`; a resource that names anything else has an invalid chain.
The two documents can legitimately differ, and when they do the PEP never merges them:
`federation` mode does not consult the resource's own well-known at all.

### The rules that never relax

- A URL outside an allowlist, or a chain that fails validation, **fails closed**. It never
  falls through to a weaker source. Everything else degrades: a stale cache, then the
  operator's own static PDP, and only when nothing is left is the request a 503.
- A discovered PDP never receives the static API key. The key is bound to `AUTHZEN_URL`.
- A batch is never sent to a guessed path: a boxcar mapping needs the PDP to advertise
  `access_evaluations_endpoint`.
- Metadata is cached per identifier with stale-while-failing, refresh throttling and
  negative caching, so a metadata outage is not an authorisation outage and a down
  resource does not put a fetch in every request's path.
- Allowlists are re-applied on every call, not only when a document is fetched, because a
  cache is shared and a policy is per route.

Federation resolution lives only in Go. The Kong plugin and the Node SDK implement the
`resource` and `authzen` modes natively (there is no JOSE verifier in Kong; the SDK leaves
a `sources` seam) and get federation by delegating to `coaz-pep`.

## What is deliberately not here

- **A PDP.** These are enforcement points. The PDP is Ping Authorize behind its AuthZEN
  adapter in our deployments, and any conformant AuthZEN PDP otherwise.
- **A general REST-path-to-resource mapper in the SDK.** The Go and Kong PEPs carry one
  for a specific banking API, as a worked example. Guessing a resource from a URL is how
  a PEP authorises the wrong thing, so the SDK makes you write the mapping.
- **Trust Marks, the federation resolve endpoint, historical keys, client authentication
  at federation endpoints, and the PEP as a Federation Entity.** Chain resolution and
  metadata policy are enough to answer "which PDP decides for this resource"; the rest is
  a later phase if a deployment needs it.
- **An AuthZEN entity type for the PDP.** No spec defines one. The PDP's own metadata is
  fetched directly and bound by its `policy_decision_point` echo; if the AuthZEN WG
  defines an entity type, the PDP-metadata step gains a federation branch symmetrical to
  the resource step.

## Seeing it work

`demo/` stands up a stub Trust Anchor, resources that are and are not members, a
well-behaved PDP and a rogue one that permits everything, and `coaz-pep` three times in
three discovery modes. `demo.sh` walks through the cases: the impostor resource choosing
its own judge under `resource` mode, the federation's policy stripping the rogue PDP
under `federation` mode, a broken chain failing closed, and a step-up challenge surviving
discovery. See [`demo/README.md`](../demo/README.md).

## Standards

AuthZEN Authorization API 1.0 · OpenID AuthZEN MCP profile (COAZ) · RFC 9728 OAuth 2.0
Protected Resource Metadata · OpenID Federation 1.0 · RFC 9449 DPoP · RFC 9470 step-up ·
RFC 8693 token exchange (`act`) · RFC 9396 RAR · RFC 8707 resource indicators.

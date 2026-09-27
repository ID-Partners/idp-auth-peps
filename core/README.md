# core — the COAZ engine and the `coaz-pep` service

The shared decision logic behind every PEP in this repo. Go, one binary, two front doors.

```
coaz/            the OpenID AuthZEN MCP profile ("COAZ")
  jsonrpc.go       strict JSON-RPC parsing: one reading of a body, or a refusal
  discovery.go     tools/list over MCP streamable HTTP (JSON + SSE), paginated, TTL-cached
  build.go         x-coaz-mapping validation, compilation, and the processing rules
  cel.go           CEL compilation and bounded evaluation of mapping leaves (cel-go)
  engine.go        the flow: parse -> discover -> build -> ask the PDP -> JSON-RPC semantics
  types.go         mapping/verdict types, JSON-RPC error codes, AuthzChallenge
cmd/coaz-pep/    the service
  main.go          configuration, and the refusal to start without security settings
  pep.go           Envoy ext_authz Check + the gateway-edge enforcement
  httpcheck.go     POST /v1/mcp/check — the same check over HTTP
  tokens.go        access-token and X-User-Token validation, the JWKS cache
  dpop.go          RFC 9449 proof verification and the replay cache
  ops.go           gRPC hardening, readiness, logs, the decision audit, metrics
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
- **One reading of every message** — a body is parsed strictly or refused: a batch, bytes
  after the object, a BOM, invalid UTF-8, and any object holding two member names that a
  case-insensitive parser would treat as one (`"params"` beside `"Params"`) are all
  refused, because a PEP that reads a body one way while the upstream reads it another
  has authorised nothing. See [MCP bodies the PEP will not read](#mcp-bodies-the-pep-will-not-read).
- **Every method decided** — a tool's declared mapping, otherwise the binding's default
  mapping for the method; `ping`, notifications and a client's responses pass; an unknown
  method is denied. See [Default mappings](#default-mappings).
- **Error semantics** — deny → `-32001` (`-32401` for v1 tools), with
  `data.authz_challenge` when the policy offers a remedy; mapping or CEL failure →
  `-32602`; discovery or PDP failure → `-32603`, fail-closed; a body the PEP will not read
  → `-32700` or `-32600`.
- **Claims normalisation** — object-valued claims serialised as JSON strings (PingFederate's
  `act`) are decoded, so `token.act.sub` resolves instead of silently reading nothing.

`cmd/coaz-pep/` wraps that with classic gateway-edge enforcement: verified delegated-token
claims, RFC 9449 DPoP binding, RFC 9470 step-up challenges, REST request mapping, fail-closed
PDP calls.

## Build and run

```sh
go build ./...
go test -race ./...    # the profile's worked examples, and everything else

docker build --build-arg VERSION=0.4.0 -t coaz-pep .
docker run -p 9191:9191 -p 9192:9192 \
  -e AUTHZEN_URL=http://authzen-adapter:8080 -e AUTHZEN_API_KEY=… \
  -e CHECK_API_TOKEN=… -e MCP_UPSTREAM_ALLOWLIST=http://bank-mcp:8090 \
  -e ACCESS_TOKEN_JWKS_URL=https://as.example.com/jwks \
  -e ACCESS_TOKEN_ISSUER=https://as.example.com -e ACCESS_TOKEN_AUDIENCE=https://api.example.com \
  coaz-pep
```

The image is distroless and runs as `nonroot`. Released images are on
`ghcr.io/id-partners/coaz-pep`, signed with cosign (keyless) and carrying an SBOM and build
provenance.

### It refuses to start without its security settings

A PEP that comes up with an open check API or unverified tokens is worse than one that
does not come up, so a missing security setting stops startup — every one of them named in
the error, so one restart fixes the lot:

```
refusing to start with insecure settings:
  - CHECK_API_TOKEN is unset: the HTTP check API on :9192 is unauthenticated
  - MCP_UPSTREAM_ALLOWLIST is unset: any caller-supplied mcp_upstream_url is fetched server-side
  - ACCESS_TOKEN_JWKS_URL is unset: access tokens and X-User-Token are decoded, not verified
```

`PEP_ALLOW_INSECURE=true` starts it anyway and logs each gap as a warning. That is for
development and the demo — never for anything a real client reaches.

| Env | Meaning | Default |
| --- | --- | --- |
| `AUTHZEN_URL` | AuthZEN PDP base URL, absolute http(s) | required |
| `AUTHZEN_API_KEY` | Bearer key for the PDP | — |
| `CHECK_API_TOKEN` | shared secret required on the HTTP check API | **required** |
| `MCP_UPSTREAM_ALLOWLIST` | permitted `mcp_upstream_url` prefixes, comma-separated | **required** |
| `ACCESS_TOKEN_JWKS_URL` | JWKS for validating the access token | **required** |
| `ACCESS_TOKEN_ISSUER` / `_AUDIENCE` | expected `iss` / `aud` | **required** with a JWKS |
| `USER_TOKEN_JWKS_URL` | JWKS for `X-User-Token` | the access-token JWKS |
| `USER_TOKEN_ISSUER` | expected `iss` for `X-User-Token` | the access-token issuer |
| `USER_TOKEN_AUDIENCE` | expected `aud` for `X-User-Token`; without it `X-User-Token` is ignored, and `require_user_login` routes deny | — |
| `PEP_ALLOW_INSECURE` | start despite missing security settings, logging each (dev only) | false |
| `PORT` | ext_authz gRPC port | 9191 |
| `HTTP_PORT` | HTTP check API port | 9192 |
| `HTTP_ADDR` | bind address for the check API | all interfaces |
| `GRPC_TLS_CERT_FILE` / `_KEY_FILE` | serve ext_authz over TLS | plaintext (use mesh mTLS) |
| `GRPC_TLS_CLIENT_CA_FILE` | require and verify client certificates (mTLS) | — |
| `DPOP_HTU_BASE` | the external origin clients make DPoP proofs for, e.g. `https://api.example.com` | the path alone is compared |
| `COAZ_DISCOVERY_TTL` | `tools/list` cache TTL | 60s |
| `LOG_FORMAT` | `json` or `text` | json |
| `PDP_TLS_INSECURE` | skip PDP TLS verification — needs `PEP_ALLOW_INSECURE` | false |
| `PDP_DISCOVERY` | `off`, `authzen`, `resource` or `federation` — see [PDP discovery](#pdp-discovery) | `off` |
| `PDP_METADATA_TTL` | cache TTL for resource and PDP metadata | 5m |
| `PDP_ALLOWLIST` | permitted discovered-PDP prefixes; `AUTHZEN_URL` is always permitted | **required** in `resource` and `federation` modes |
| `RESOURCE_METADATA_ALLOWLIST` | permitted `resource` prefixes for metadata fetches | **required** in `resource` and `federation` modes |
| `PDP_DISCOVERY_INSECURE` | allow `http` for discovered URLs — needs `PEP_ALLOW_INSECURE` | false |
| `FEDERATION_TRUST_ANCHORS_FILE` | JSON `{"<entity id>": {"keys": [JWK…]}}` — required in `federation` mode | — |
| `FEDERATION_FETCH_ALLOWLIST` | permitted prefixes for the climb to the anchor (Superiors' Entity Configurations and fetch endpoints); the resource's own is governed by `RESOURCE_METADATA_ALLOWLIST` | **required** in `federation` mode |
| `FEDERATION_MAX_PATH_LENGTH` | intermediates allowed between a resource and its anchor | 4 |
| `PDP_LAYERS` | ordered PDPs every route asks unless it names its own: `static`, `resource`, or a PDP identifier, each optionally suffixed ` fail-open` / ` fail-closed`; every layer must permit. `resource` is the resource's PDP behind any layers its metadata publishes in `authzen_policy_layers` | `resource` |
| `PDP_FAIL_MODE` | what a layer does when its PDP is unavailable, unless the layer says for itself: `closed` denies, `open` skips it and marks the permit with `X-PDP-Fail-Open` | `closed` |
| `FEDERATION_ENTITY_ID` | make this PEP the federation entity for the resource it fronts: a minimal Entity Configuration at `{id}/.well-known/openid-federation` for the controller to onboard, and RFC 9728 metadata at `/.well-known/oauth-protected-resource{path}` republishing what the federation resolved (self-asserted until onboarded) | — |
| `FEDERATION_ENTITY_KEY_FILE` | the private JWK the entity signs with; `FEDERATION_ENTITY_KEY_GENERATE=true` mints a P-256 key into it when absent | — |
| `FEDERATION_AUTHORITY_HINTS` | comma-separated superiors the trust controller is reached through | — |

A duration or a knob that does not parse is refused too, rather than replaced by a default.

Per-route knobs are not env — they arrive as ext_authz `context_extensions` or in the
`config` object of an HTTP check. See [`../gateways/envoy/README.md`](../gateways/envoy/README.md).
A knob that is neither `true` nor `false`, or a style that is neither `rest` nor `mcp`,
fails that route closed rather than reading as off.

### Operating it

- **`/healthz`** is liveness. **`/readyz`** is readiness: false while draining, and false
  until the access-token JWKS has loaded once. A replica whose PDP is down stays ready —
  it answers with a fail-closed deny, which beats no answer.
- **SIGTERM drains.** Readiness drops, gRPC health reports `NOT_SERVING`, in-flight checks
  finish (up to 25 s), then the listeners close. Give the pod a 30 s grace period.
- **Logs are JSON**, one audit record per decision (`"msg":"decision"`): the route, the
  outcome and status, the action, the client-facing reason, any fail-open layers, the
  request id and whether the PEP started insecure. Never a token.
- **`/metrics`** is Prometheus text: decisions by outcome, style and fail-open, and PDP
  calls by result with a latency histogram.
- **The gRPC server** recovers a panic into an error (which Envoy fails closed on), bounds
  messages at 4 MiB and recycles connections every five minutes, so a new replica gets its
  share of an Envoy's long-lived streams.

## PDP discovery

By default the PEP is told where the PDP is (`AUTHZEN_URL`) and assumes the AuthZEN
paths under it. `PDP_DISCOVERY` replaces both assumptions with metadata, in four steps:

```
resource identifier (the route's `resource`, or `mcp_upstream_url` on an MCP route)
  ├─ federation  resolved oauth_resource metadata from a Trust Chain     ← authoritative
  ├─ resource    {resource}/.well-known/oauth-protected-resource (RFC 9728) ← self-asserted
  └─ static      AUTHZEN_URL                                              ← when the resource publishes nothing
PDP identifier
  ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9): access_evaluation_endpoint, …
  └─ 404 → {pdp}/access/v1/evaluation, the spec's default paths
```

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| `off` | nothing — static PDP, default paths, no HTTP | — |
| `authzen` | `AUTHZEN_URL`'s `authzen-configuration` | default paths |
| `resource` | the resource's RFC 9728 document, then the named PDP's metadata | static PDP when the resource publishes none (404) |
| `federation` | the resource's **resolved** `oauth_resource` metadata, then the named PDP's metadata | static PDP when the resource is not a member — never the resource's own document |

The parameter that names the PDP is not standardised anywhere (not in RFC 9728, AuthZEN
1.0, the MCP profile, or OpenID Federation 1.0), so this PEP mints one and uses it in
both places:

```json
"authzen_policy_decision_points": ["https://pdp.example"]
```

An array of PDP *identifiers* (the AuthZEN `policy_decision_point` value, not an
endpoint), first preferred. It is the same bytes in an RFC 9728 document and under
`metadata.oauth_resource` in an Entity Statement — which is the point. A resource's own
well-known is a self-assertion over TLS; a federation's Resolved Metadata is what survives
every Superior's `metadata_policy`, signed back to a Trust Anchor you configured. So a
federation operator can pin, per resource, which PDPs may decide for it:

```json
"metadata_policy": { "oauth_resource": { "authzen_policy_decision_points": {
  "subset_of": ["https://pdp.bank-a.example"], "essential": true } } }
```

and a resource the PEP cannot then use — its PDP list stripped to nothing, an entry it
cannot read — is refused. An invalid chain, like a URL outside an allowlist, fails closed
and never falls through to a weaker source.

Everything else degrades within bounds. A 404 means the resource publishes nothing, and
the static PDP decides. An outage or a document that does not validate is not a 404: the
last good copy is served for up to one more TTL (`PDP_METADATA_MAX_STALE`) and never past
its own expiry — a chain's expiry included — and after that the `resource` layer is
unavailable, failing closed with a 503 unless it is marked fail-open. A refusal evicts,
so a chain the anchor stops vouching for stops being honoured at the next refresh, not at
restart. A PDP whose own metadata blips keeps its last good endpoints rather than
reverting to the default paths.

Two things a discovered PDP never gets: the static `AUTHZEN_API_KEY` (it is bound to
`AUTHZEN_URL` alone), and a guessed batch path (a boxcar mapping needs the PDP to
advertise `access_evaluations_endpoint`).

Per route, `resource` is the RFC 8707 identifier the chain starts from. An MCP route
without one uses its `mcp_upstream_url`; a REST route without one uses the static PDP.

Whatever document named the PDP travels to the PDP as well, verbatim, as
`context.resource_metadata` with `context.resource_metadata_source` saying whether it is
the resource's own RFC 9728 document or the federation-resolved one. The endpoint hit goes
as `context.request`, and the raw token as `context.access_token` when the route sets
`forward_access_token`. The PEP reads only the PDP list out of the document; what a
resource requires — `scopes_supported`, an acr, sender-constrained tokens — is policy
input, and matching a token to it is the PDP's decision. The reasoning is in
[docs/architecture.md](../docs/architecture.md#what-the-pep-forwards-and-what-it-does-not-decide).

A route may ask more than one PDP: `pdp_layers` (or the service's `PDP_LAYERS`) is an
ordered list of `static`, `resource` or PDP identifiers, every one of which must permit,
the first deny being the answer. That is how a generic estate PDP that judges the token
and the client sits in front of the one that knows the resource. The resource can publish
that stack itself — `authzen_policy_layers` in its metadata names the PDPs to ask in front
of its own, and a federation can `add` one for every member — in which case the `resource`
layer runs them with nothing configured on the PEP; see
[docs/architecture.md](../docs/architecture.md#layers-the-resource-publishes).

The PEP can be the federation face of the resource it fronts. With `FEDERATION_ENTITY_ID`
set it holds a key and publishes a minimal entity configuration — keys, `authority_hints`,
the entity type, no policy — for a trust controller to onboard, and republishes what the
federation resolved for it as the resource's RFC 9728 document, `signed_metadata`
included. The controller maintains the resource's metadata; the PEP maintains a key. Route
the two well-known paths to the PEP's HTTP port; see
[docs/architecture.md](../docs/architecture.md#the-pep-as-the-resources-federation-face).

A layer whose PDP is unavailable fails closed unless it says otherwise: suffix the entry
with ` fail-open` (`http://estate:9098 fail-open, resource`) and it is skipped instead,
with the permit marked `X-PDP-Fail-Open` — which names the layer, never the error.
`PDP_FAIL_MODE=open` (or a route's `fail_mode`) makes that the default for layers that say
nothing.

*Unavailable* is narrow on purpose: a transport error, a timeout, a 5xx or a 429. A PDP
that answers a 3xx or 4xx, or a 2xx that is not a decision, has refused the request, and a
refusal fails closed on every layer — otherwise a rotated key's 401, or a 413 a client
provoked with an oversized argument, would switch an advisory layer off on demand. A deny
is never skipped either, and a policy the PEP cannot read fails the route closed; see
[docs/architecture.md](../docs/architecture.md#failing-open-deliberately).

## A note on `mapping.go`

The REST mapping is a direct port of `map_request` in the Kong plugin, so both gateways
send the PDP identical requests. Its route patterns are a specific banking API's
(`/customers/:id/accounts`, `/accounts/:id/balance`, …). Treat them as a worked example:
for your own API, either extend the switch or run the Node SDK, whose mapping you supply.

## Migrating `subject.identity` -> `subject.id`

AuthZEN 1.0 names the subject identifier **`id`**. Both gateway PEPs historically sent
**`identity`**, which no version of the spec defines — so a policy reading it is reading a
field we invented, and a conformant PDP would find no subject identifier at all.

The Node SDK was written against `subject.id` and is unaffected.

This cannot be a flag day: the PEPs and the policies deploy separately, and swapping the
field in one release would break every policy the moment the gateway rolled. So both PEPs
now send **`id` always**, and `identity` **as well** while `legacy_subject_identity` is on
— which it is by default. Upgrading a gateway on its own changes nothing a policy can see.

The sequence:

1. **Deploy this version.** Requests now carry both `subject.id` and `subject.identity`
   with the same value. Nothing breaks; nothing needs coordinating.
2. **Update the policies** to read `subject.id`. Verify against the doubled traffic — both
   fields are present, so a policy can be switched and tested without a rollback window.
3. **Turn the legacy field off**, per route: `legacy_subject_identity: false` (Kong) or
   `legacy_subject_identity: "false"` (ext_authz `context_extensions`). Requests are now
   AuthZEN-conformant.
4. **A later release removes the field entirely**, at which point step 3 becomes a no-op.

Only an explicit `false` (case-insensitive) removes it — an empty value, a typo, or `no`
all leave it in place, because silently dropping a field a live policy depends on is the
one failure mode this ordering exists to prevent.

The two PEPs move in lockstep on purpose. Two gateways sending different subject shapes
to the same PDP would be worse than either shape on its own.

## `POST /v1/dpop/verify`

A single-purpose sender-constraint check, for gateways that cannot do it themselves:

```jsonc
// request
{ "method": "POST", "path": "/payments", "pep_label": "kong",
  "headers": { "authorization": "DPoP <token>", "dpop": "<proof>" } }

// response
{ "valid": true }
{ "valid": false, "reason": "DPoP proof signature is invalid: …", "status": 401 }
```

It validates the access token first (when `ACCESS_TOKEN_JWKS_URL` is set — a proof is
only as good as the `cnf.jkt` it is compared with), then the proof's JWS signature, `iat`
freshness, `jti` replay and the `cnf.jkt`/`htm`/`htu`/`ath` binding — the full
`checkDpop`, without the rest of the pipeline.

Deliberately **not** `/v1/mcp/check`: that runs everything including the PDP evaluation,
so a caller wanting only the sender-constraint checked would get a second, independent
authorization decision as a side effect — one that could disagree with its own.

Authenticated by `CHECK_API_TOKEN`, like the check API.

## Securing the HTTP check API

The gRPC port takes its per-route config from the gateway's own configuration. The HTTP
check API is different: the **caller** supplies `config.mcp_upstream_url` *and* the
`authorization` header, and the PEP then fetches that URL with that header. Unbounded,
that is a server-side request forgery and credential-relay primitive.

So both guards are required, and the PEP will not start without them:

```sh
CHECK_API_TOKEN=…                                     # callers must present it as a bearer
MCP_UPSTREAM_ALLOWLIST=http://bank-mcp:8090/mcp,…     # prefixes that may be fetched
```

Allowlist entries match on scheme + host + path prefix, compared against the *parsed*
URL, so `https://mcp.example.com` does not admit `https://mcp.example.com.evil.test` or
`https://mcp.example.com@evil.test`. Callers configure the secret with `coaz_api_key`
(Kong), `coaz_api_key` (PingAccess) or `delegate.apiKey` (Node SDK). A check request is
capped at just over 1 MiB.

The gRPC port has no token of its own: whatever can reach it can choose a route's knobs.
Keep it reachable only by the gateways — a mesh sidecar's mTLS, `GRPC_TLS_*` with a client
CA, or a NetworkPolicy (the Istio sample has one).

## Bounding what discovery will fetch

Discovery follows URLs out of documents the PEP did not write: a resource's RFC 9728
metadata, an Entity Configuration, a Superior's `federation_fetch_endpoint`. Every one of
them goes through a single bounded GET — https only, hop-by-hop redirect re-checks capped
at three, a 1 MiB body cap, and a per-resolution fetch budget — so a hostile document
cannot turn the PEP into an open proxy or a memory sink.

*Which hosts* may be reached is bounded by the allowlists, and in `resource` and
`federation` mode those are required: `RESOURCE_METADATA_ALLOWLIST` for the resources
whose metadata is fetched, `PDP_ALLOWLIST` for the PDPs a document may name, and in
`federation` mode `FEDERATION_FETCH_ALLOWLIST` for the climb to the anchor. Keep
`PDP_DISCOVERY_INSECURE` off outside development — it permits `http` both in an Entity
Identifier and on the wire.

The PDP and `tools/list` clients never follow redirects: a PDP is asked, not followed, and
a redirect would carry the request — and a forwarded access token — somewhere the
allowlist never approved.

## DPoP

The `cnf.jkt` comparison is only meaningful once the proof's **signature** verifies under
the JWK the proof carries — that JWK is public in every proof, so on its own the
thumbprint proves nothing. `checkDpop` compares the thumbprint first (it is cheap, and a
proof header can carry a key big enough to make verification expensive), then verifies
the JWS (ES256/384/512, RS/PS256/384/512), matches `htm` and `htu`, compares `ath` against
SHA-256 of the presented access token, enforces an `iat` window (300 s back, 60 s of clock
skew forward) and rejects a reused `jti`.

- **`htu`** is compared as RFC 9449 §4.3 says, ignoring query and fragment. Behind a
  gateway the PEP does not see the origin the client used, so set `DPOP_HTU_BASE` to it;
  without it only the path is compared — exactly, never as a substring.
- **A DPoP-bound token presented as a bearer token is rejected** on every route, not only
  those with `require_dpop` (§7.2) — otherwise a stolen bound token is as good as a bearer
  one wherever the route forgot to ask.
- **The replay cache** holds each proof until its `iat` plus the window, keyed by key and
  `jti`. One key is held to a quota, and at the global cap the entries nearest expiry make
  way — so a flood of fresh `jti`s refuses the flooder, not everyone. It is per replica: a
  proof replayed to a different replica within its window is not caught.

## Token validation

The COAZ-MCP binding: "The access token ... MUST be validated by the PEP before its
claims are used. The PEP MUST verify the token signature, issuer, audience, and
expiration." Decoding is not validating, and the PEP will not start without the JWKS,
issuer and audience to validate against.

That bites twice. The access token is the obvious case. The sharper one is
**`X-User-Token`** — its claims feed `user_scope`, `user_acr`, `authorization_details`
and the consented-amount cap, which are exactly the inputs the step-up and consent gates
turn on. Unverified, a forged one walks through both. And a *genuine* one is only the
user's login if it is this principal's:

- its `sub` must be the access token's `sub` — customer B's consent does not authorise
  customer A's payment. A route where someone else may approve — a staff member for a
  customer — says `user_token_subject: "pdp"`: there another subject's verified login
  counts, and the PDP, which always receives `user_sub` and `user_iss`, decides whether
  that person may approve for this principal;
- it must not be delegated (no `act`) or be the access token itself — an agent's own
  token is not a user having logged in;
- its audience must be `USER_TOKEN_AUDIENCE`. Without that setting `X-User-Token` is
  ignored altogether, because the agent's own token comes from the same issuer and
  verifies against the same keys.

```sh
ACCESS_TOKEN_JWKS_URL=https://as.example.com/jwks
ACCESS_TOKEN_ISSUER=https://as.example.com
ACCESS_TOKEN_AUDIENCE=https://api.example.com
USER_TOKEN_AUDIENCE=banking-app   # the aud the user's own login token carries
USER_TOKEN_JWKS_URL=…             # defaults to the access-token JWKS
```

A token that fails verification is a 401 (`invalid_token`); an `X-User-Token` that fails
yields **no** claims, so the gates it feeds close rather than open.

Verification covers signature (ES256/384/512, RS/PS256/384/512), `exp`, `nbf`, `iss` and
`aud`, rejects `alg: none`, and refuses a token whose `kid` is not in the JWKS. The JWKS is
refreshed in the background every 10 minutes, one fetch shared by every request that
needs it, with backoff when it fails. Stale keys keep verifying for up to an hour of
failed refreshes — a JWKS outage costs freshness, not availability — and then stop,
because a key the issuer withdrew must stop working. An unknown `kid` fetches at most once
every 30 s, so made-up kids cannot be used to push traffic at the AS.

## MCP bodies the PEP will not read

A POST to an MCP route must be one JSON-RPC message that every parser reads the same way.
Anything else is refused before any PDP is asked:

| Body | Status | JSON-RPC error |
| --- | --- | --- |
| not JSON, invalid UTF-8, a BOM, anything after the object | 400 | `-32700` |
| a batch, not an object, two members equal under case folding at any depth, a non-string `method`, a `tools/call` with no string `params.name`, `jsonrpc` not `"2.0"` | 400 | `-32600` |
| truncated by the gateway (`x-envoy-auth-partial-body: true`) | 413 | `-32600` |
| a `Content-Encoding` other than `identity` | 415 | `-32600` |

Each of these used to be treated as "not a tool call" and let through, while the upstream
read the full, decoded or differently-parsed body and ran the call. GET (the server's SSE
stream) and DELETE (ending a session) carry no message and pass on the token checks; any
other method is a 405.

REST routes get the same treatment for the bodies and paths the mapping reads: a payment
or account body that is not one clean JSON object, and a path with a matrix parameter
(`;`), a dot segment, an empty segment or an encoded slash, dot or backslash, is a 400
rather than a PDP request with the fields missing.

## COAZ dialects

`authzen-mcp-profile-1_0` was superseded on 2026-02-13 by the
[COAZ Framework](https://openid.github.io/authzen/authzen-coaz-framework-1_0.html) and
the [COAZ-MCP binding](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html).
Both dialects are supported; v2 is selected automatically.

| | v1 (superseded) | v2 (current) |
| --- | --- | --- |
| declaration | `coaz: true` + `x-coaz-mapping` | `x-authzen-mapping` in `inputSchema` |
| shape | flat subject/action/resource/context arrays, zipped by length | an **envelope**: exactly one of `evaluation` or `evaluations` |
| expressions | every string is CEL (`'customer'` is a literal) | only `$`-prefixed strings are CEL; `$$` escapes; the rest are literals |
| denial code | `-32401` | `-32001` |
| subject | ≥1 subject/context field from the token | `subject.id` anchored to the token claim and **verified** against it |

A tool carrying `x-authzen-mapping` is v2 whatever else it says; `coaz: true` selects v1
only for tools that have not migrated. v1 tools keep getting `-32401`, because a client
that string-matches on it should not break on upgrade.

The v2 trust anchor is the one to understand: where `subject.id` is `$token.sub`, the PEP
verifies the resolved value equals that claim, so an MCP server — the party being
authorized — cannot assert a different subject. A mapping that sets `subject.id` from
somewhere else is permitted but logged, because the identity is then asserted by the
mapping author rather than anchored to the token.

### Deliberate deviations

Two places where this implementation is **stricter** than the drafts. Both are choices,
not oversights.

**Per-entry `subject` in an `evaluations` envelope is rejected outright.** AuthZEN's
generic override semantics would let an entry set its own `subject`; the COAZ-MCP binding
forbids it ("MUST NOT set `subject` within any entry"), and we enforce that as a compile
error rather than dropping the field. A mapping that tried is malformed, and telling its
author so beats silently authorizing a different question.

**A declared `resource.id` that resolves absent is a mapping error**, not a dropped key.
AuthZEN allows a type-only resource, so a mapping that never mentions `resource.id` is
fine. But one that *declares* `"id": "$params.arguments.id"` and gets absent has just
turned "this customer" into *every* customer — the request silently broadens, and the PDP
answers a question nobody asked. Absence is only pruned from `context`, which is optional
by definition.

### Default mappings

The binding: "A PEP MUST apply the default mapping for a method unless a declared mapping
applies to the specific operation." So every method is decided: a tool with no
`x-authzen-mapping` is authorised against the default `tools/call` mapping, not waved
through, and so is every other method — `resources/read`, `prompts/get`, `tools/list`,
`initialize` — against its own. A `tools/call` on a route with no `mcp_upstream_url` gets
the default mapping too, since there is no `tools/list` to read a declaration from.

This is on by default. `coaz_defaults: "false"` (per route), `ApplyDefaultMappings: false`
(Go API) or `applyDefaultMappings: false` (Node SDK) turns it off and brings back the old
behaviour: declared tools are decided, everything else passes on a valid token, and the
handshake gets the coarse `access_mcp` check. **Pass-through is not conformant**; the
switch exists for a route whose policies are not ready yet.

`coaz_v2_only: "true"` goes the other way: a tool declaring only the superseded
`coaz: true` mapping is refused, since a v1 mapping can take the subject from the caller's
params.

### Default mappings — the full table

With default mappings on, every MCP method is governed:

| Method(s) | `resource` |
| --- | --- |
| `tools/call` | `{type: tool, id: $params.name}` |
| `tools/list`, `resources/list`, `prompts/list`, `tasks/list` | `{type: mcp_server, id: $token.aud}` |
| `resources/read`, `resources/subscribe`, `resources/unsubscribe` | `{type: resource, id: $params.uri}` |
| `prompts/get` | `{type: prompt, id: $params.name}` |
| `completion/complete` | prompt or resource, by `$params.ref.type` |
| `logging/setLevel` | `{type: mcp_server, id: $token.aud}`, `level` in context |
| `tasks/get`, `tasks/result`, `tasks/cancel` | `{type: task, id: $params.taskId}` |
| `initialize` | `{type: mcp_server, id: $token.aud}` — see below |

`ping`, `notifications/*` and a client's JSON-RPC responses (to a server's sampling or
elicitation request) are pass-through: the PEP must not call the PDP for them.
Server-initiated requests (`sampling/createMessage`, `elicitation/create`, `roots/list`)
are out of scope for the binding — authorizing them with the *client's* token would ask
about the wrong identity — so they pass through too.

Anything else is **denied**, so a method from a future MCP version fails closed rather
than slipping past authorization.

### Two problems found in the binding

Both are handled here and worth raising with the working group.

**`initialize` is unreachable.** It appears nowhere in the binding — not in the
default-mapping table, not in the pass-through list. By the Unknown Methods rule it
therefore MUST be denied, which denies every MCP handshake and makes the protocol
unusable. That reads as an omission, not a decision. Denying it breaks everything and
passing it through leaves the handshake ungoverned, so it gets a default mapping shaped
like the other server-scoped methods: the PDP is asked, policy decides, nothing bypasses
authorization.

**The `completion/complete` default does not compile.** The binding prints it as

```
"id": "$params.ref.type == 'ref/prompt' ? $params.ref.name : $params.ref.uri"
```

with a `$` on every reference. But the framework says only the *leading* `$` marks a
value as an expression — "the text following the `$` is the expression itself" — and "a
`$` anywhere else in a string has no special meaning". Stripping only the leading one
leaves stray `$` in the CEL source, which is a syntax error. It is written here the way
the framework's own rule requires: leading `$` to mark the expression, plain CEL inside.

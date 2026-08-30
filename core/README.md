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
| `CHECK_API_TOKEN` | shared secret required on the HTTP check API | unset — **warns**, endpoint open |
| `MCP_UPSTREAM_ALLOWLIST` | permitted `mcp_upstream_url` prefixes, comma-separated | unset — **warns**, any upstream fetched |
| `HTTP_ADDR` | bind address for the check API | all interfaces |
| `ACCESS_TOKEN_JWKS_URL` | JWKS for validating the access token | unset — **warns**, token decoded not verified |
| `ACCESS_TOKEN_ISSUER` / `_AUDIENCE` | expected `iss` / `aud` | — |
| `USER_TOKEN_JWKS_URL` | JWKS for `X-User-Token` | falls back to the access-token JWKS |
| `USER_TOKEN_ISSUER` / `_AUDIENCE` | expected `iss` / `aud` for `X-User-Token` | issuer falls back to the access-token issuer |

Per-route knobs are not env — they arrive as ext_authz `context_extensions` or in the
`config` object of an HTTP check. See [`../gateways/envoy/README.md`](../gateways/envoy/README.md).

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

It verifies the proof's JWS signature, `iat` freshness, `jti` replay and the
`cnf.jkt`/`htm`/`ath` binding — the full `checkDpop`, without the rest of the pipeline.

Deliberately **not** `/v1/mcp/check`: that runs everything including the PDP evaluation,
so a caller wanting only the sender-constraint checked would get a second, independent
authorization decision as a side effect — one that could disagree with its own.

Authenticated by `CHECK_API_TOKEN`, like the check API.

## Securing the HTTP check API

The gRPC port takes its per-route config from the gateway's own configuration, which no
external caller can influence. The HTTP check API is different: the **caller** supplies
`config.mcp_upstream_url` *and* the `authorization` header, and the PEP then fetches that
URL with that header. Unbounded, that is a server-side request forgery and
credential-relay primitive.

Two guards, both off by default so no existing deployment breaks silently — each logs a
warning at startup when unset:

```sh
CHECK_API_TOKEN=…                                     # callers must present it as a bearer
MCP_UPSTREAM_ALLOWLIST=http://bank-mcp:8090/mcp,…     # prefixes that may be fetched
```

Allowlist entries match on scheme + host + path prefix, compared against the *parsed*
URL, so `https://mcp.example.com` does not admit `https://mcp.example.com.evil.test` or
`https://mcp.example.com@evil.test`. Callers configure the secret with
`coaz_api_key` (Kong) or `delegate.apiKey` (Node SDK).

Set both in any environment where the port is reachable by anything you do not control.

## DPoP

The `cnf.jkt` comparison is only meaningful once the proof's **signature** verifies under
the JWK the proof carries — that JWK is public in every proof, so on its own the
thumbprint proves nothing. `checkDpop` verifies the JWS (ES256/384/512, RS/PS256/384/512),
compares `ath` against SHA-256 of the presented access token, enforces an `iat` freshness
window, and rejects a reused `jti`. See `dpop.go` and its tests.

## Token validation

The COAZ-MCP binding: "The access token ... MUST be validated by the PEP before its
claims are used. The PEP MUST verify the token signature, issuer, audience, and
expiration." Decoding is not validating.

That bites twice. The access token is the obvious case. The sharper one is
**`X-User-Token`** — its claims feed `user_scope`, `user_acr`, `authorization_details`
and the consented-amount cap, which are exactly the inputs the step-up and consent gates
turn on. Unverified, a forged one walks through both.

```sh
ACCESS_TOKEN_JWKS_URL=https://as.example.com/jwks
ACCESS_TOKEN_ISSUER=https://as.example.com
ACCESS_TOKEN_AUDIENCE=https://api.example.com
USER_TOKEN_JWKS_URL=…      # defaults to the access-token JWKS
```

Configured, a token that fails verification is a 401 (`invalid_token`) and an
`X-User-Token` that fails yields **no** claims, so the gates it feeds close rather than
open. Unconfigured, tokens are decoded as before and startup warns — which keeps an
existing deployment running without silently shipping the bypass.

Verification covers signature (ES256/384/512, RS/PS256/384/512), `exp`, `nbf`, `iss` and
`aud`, rejects `alg: none`, and refuses a token whose `kid` is not in the JWKS. The JWKS
is cached for 10 minutes and refreshed on an unknown `kid`, rate-limited to once every
30s so bogus kids cannot be used to force traffic at the AS.

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
applies to the specific operation." A tool with no `x-authzen-mapping` should therefore be
authorized against the default `tools/call` mapping, not waved through.

That is off by default here, because turning it on makes every previously-unGoverned tool
call require a PDP decision — a change deployed routes should opt into rather than
discover. Set `coaz_defaults` (per route) or `ApplyDefaultMappings` (Go API) /
`applyDefaultMappings` (Node SDK) to enable it. **Pass-through is not conformant**; the
switch exists so the migration is yours to time.

### Default mappings — the full table

Enabled per route (`coaz_defaults`), every MCP method is governed:

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

`ping` and `notifications/*` are pass-through: the PEP must not call the PDP for them.
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

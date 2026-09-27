# @id-partners/authzen-pep

An [AuthZEN 1.0](https://openid.net/wg/authzen/) Policy Enforcement Point for Node —
Express/Connect middleware for REST APIs, and a COAZ guard for every MCP method.

Node 22 or later. ESM only — there is no CommonJS build. No runtime dependencies.

```sh
npm install @id-partners/authzen-pep
```

Until a version is on npm, install the package attached to its
[GitHub release](https://github.com/ID-Partners/idp-auth-peps/releases):
`npm install ./id-partners-authzen-pep-<version>.tgz`.

Reach for this when the traffic cannot sit behind the Kong or Envoy PEPs in this repo,
or when the decision needs request context only the application has. Everything fails
closed: a timeout, a 500, an unparseable body and a mapping it cannot evaluate all deny,
and a configuration that would trust something nobody checked refuses to start.

## Upgrading to 0.4.0

0.4.0 closes every way this SDK had of letting a request through that no PDP judged.
Most of it is invisible, but these change what you write or what you get back:

- **Node 22 or later**, and ESM only. Node 20 is end of life.
- **`verifyToken` is required.** `authzenMiddleware` throws at construction without it.
  `allowInsecure: true` is the escape hatch for demos — it decodes without verifying and
  says so once at startup. A `verifyToken` that throws is now a 401, not a 502.
- **`map()` opts out only with `null`.** `undefined` — a mapper that forgot a `return` —
  is now a mapping error and a 400, not a free pass.
- **`X-Auth-*` go on the request.** `forwardHeaders` sets `X-Auth-Principal`, `-Agent`,
  `-Scope` and `-Acr` on `req.headers` for your handler and whatever it proxies to; they
  used to go on the response. Client copies are stripped from every request the
  middleware lets through, whether or not `forwardHeaders` is set.
- **`applyDefaultMappings` defaults to `true`.** Every MCP method is governed by the
  binding's default mapping unless a tool declares its own. Pass `false` to keep the old
  pass-through.
- **Delegate mode needs `upstreamUrl` and `delegate.apiKey`**, and sends every MCP
  request to coaz-pep — `ping`, notifications and responses included. Before, it never
  told coaz-pep which server to read `tools/list` from, so coaz-pep never ran COAZ and
  permitted every `tools/call`.
- **Resource-mode discovery needs `pdpAllowlist` and `resourceAllowlist`.** Without them
  any resource could name any PDP. `allowInsecure` starts it anyway, loudly.
- **A resource whose metadata cannot be read is not the static PDP.** Only a resource
  that publishes nothing (404) falls back to it; an outage or an invalid document fails
  that layer by its own mode.
- **A PDP whose metadata cannot be read is unavailable**, not called at guessed default
  paths; those are for a PDP that publishes no metadata (404). The last good copy of
  either document is served for up to one more TTL.
- **Fail-open covers an unavailable PDP only** — a network error, a timeout, a 5xx, a
  429, or a PDP with no batch endpoint asked for a boxcar. A 3xx or 4xx, an answer that
  is not a decision and a request that cannot be encoded never open.
- **A permit is the JSON boolean `true`.** `"true"`, `1` and `{}` used to permit. A boxcar
  answer needs exactly one decision per evaluation sent.
- **`reason` is for the caller, `detail` is for your logs.** A PDP failure's `reason` is
  now a fixed phrase; which PDP, which status and which error moved to `verdict.detail`.
  `failedOpen` and `X-PDP-Fail-Open` carry layer identifiers only.
- **`pathMapper` matches the way Express routes** — decoded, case-insensitive, HEAD as
  GET. A route that only matched raw or by case before may now match, and be asked about.
- **`McpVerdict` says what to send.** `response` is the HTTP response for a deny,
  `upstreamHeaders` and `responseHeaders` what to apply on a permit, and `wrap()` hands
  its handler `(rpc, verdict)`.

## REST

```ts
import { authzenMiddleware, pathMapper } from '@id-partners/authzen-pep/express';
import { jwtVerify, createRemoteJWKSet } from 'jose';

const jwks = createRemoteJWKSet(new URL('https://as.example.com/jwks'));

app.use(authzenMiddleware({
  client: { url: process.env.AUTHZEN_URL!, apiKey: process.env.AUTHZEN_API_KEY },
  pep: 'api-edge',

  // Required. An unverified `sub` is an attacker-chosen `sub`.
  verifyToken: async (token) => (await jwtVerify(token, jwks, { audience: 'https://api.example.com' })).payload,

  map: pathMapper([
    { method: 'GET',  pattern: '/accounts/:id/balance', action: 'get_balance',  resourceType: 'account', resourceId: p => p.id },
    { method: 'POST', pattern: '/payments',             action: 'make_payment', resourceType: 'payment',
      resourceProperties: (_p, req) => ({ amount: (req.body as any)?.amount }) },
  ]),

  forwardHeaders: true,                    // X-Auth-* on req.headers, for the handler
  onDecision: ({ verdict }) => audit.log(verdict),
}));
```

On permit the request continues and `req.authz` carries `{ claims, verdict, request }`.
On deny nothing downstream runs, and the response is the challenge — see below. An error
your handler throws after a permit is the router's to handle, not a PEP failure.

`verifyToken` returns the claims, or `null` (or throws) to reject — both are a 401.
Without it the middleware will not build; `allowInsecure: true` builds it anyway, decodes
tokens without checking a signature, and warns once. Keep that for demos.

`map` returns an evaluation, or exactly `null` to let the request through without the
PDP — for health checks, never for "I couldn't work out the resource", which should
throw. Anything else, `undefined` included, is a mapping error.

`pathMapper` is a convenience, not the contract: **an unmatched route is a deny.** A route
you forgot to describe is not a route you meant to leave open. Pass `fallthrough: 'allow'`
only for paths that genuinely carry no policy. It matches the path the way Express routes
it, so the PDP is asked about the request the handler will serve: segment by segment,
each percent-decoded after the split (a captured `%31%32%33` is `123`, as in
`req.params`, and an encoded slash stays inside its segment), case-insensitively unless
you pass `caseSensitive: true` because your router is, with one trailing slash tolerated
and the query ignored. A `GET` rule also answers `HEAD`, which Express routes to the GET
handler. For anything real, write `map` yourself — it can be async, so it may look up an
account's owner or a tenant before deciding what the resource even is.

There is deliberately no built-in URL→resource guesser. Inferring a resource type from a
path is how a PEP ends up confidently authorising the wrong thing.

## MCP

Under [COAZ](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html) a tool
declares how its call becomes an authorisation question, in its `inputSchema`:

```jsonc
{
  "name": "make_payment",
  "inputSchema": {
    "type": "object",
    "properties": { "payment_id": { "type": "string" } },
    "x-authzen-mapping": {
      "evaluation": {
        "subject":  { "type": "identity", "id": "$token.sub" },
        "resource": { "type": "payment",  "id": "$params.arguments.payment_id" },
        "context":  { "agent": "$token.?client_id" }
      }
    }
  }
}
```

Three things to get right:

- The **envelope** — exactly one of `evaluation` or `evaluations` — decides single vs
  boxcar. A list value never causes a fan-out.
- Only strings starting with **`$`** are expressions; everything else is a literal.
  `"identity"` is the string `identity`; `$$` escapes a leading `$`.
- `params` binds to the whole JSON-RPC `params` member, so arguments are at
  `params.arguments.x`.

`subject.id` is **trust-anchored**: where it resolves from `$token.sub`, the SDK verifies
the resolved value equals that claim and raises a mapping error otherwise — an MCP server
must not be able to name a subject other than the one the token authenticated. Omit
`subject` and the default anchored subject is supplied for you.

> **v1 tools still work.** A tool declaring the superseded `coaz: true` +
> `x-coaz-mapping` is handled in the old dialect (every string is CEL, fields zip by
> length) and keeps its `-32401` denial code. `x-authzen-mapping` wins wherever both
> appear.

```ts
import { McpGuard } from '@id-partners/authzen-pep/mcp';

const guard = new McpGuard({
  client: { url: process.env.AUTHZEN_URL!, apiKey: process.env.AUTHZEN_API_KEY },
  tools,                       // this process IS the MCP server — no discovery round trip
  pep: 'mcp-edge',
});

// claims: from a token YOU verified — the guard never decodes one.
const verdict = await guard.checkToolCall({ rpc, claims, extraContext: { channel: 'ai-agent' } });
if (!verdict.allow) {
  const { status, headers, body } = verdict.response!;   // 200 for a policy deny, 400/415 for a refusal
  return res.status(status).set(headers).send(body);
}
```

Or wrap a handler, which runs only when `allow` is exactly `true`:

```ts
const handle = guard.wrap(async (rpc, verdict) => runTool(rpc));
const result = await handle(rpc, claims);          // the JSON-RPC error on deny
```

### What the guard reads

The guard reads each message the way every PEP in this repo agrees to, and refuses what
it cannot positively read rather than waving it through as handshake traffic. The PDP is
never asked about a refusal.

| The message | Answer |
| --- | --- |
| a request or notification with a string `method` | judged, below |
| a JSON-RPC response (`id`, and one of `result` / `error`) | passed through — it answers the server |
| a batch (a top-level array) | 400, `-32600` |
| not one object, a `method` or `id` of the wrong type, `params` that is not an object | 400, `-32600` |
| an object, at any depth, with two member names a case-insensitive parser reads as one (`Params` beside `params`, `Amount` beside `amount` in the arguments) | 400, `-32600` |
| nesting deeper than 64 | 400, `-32600` |
| a `tools/call` without a non-empty string `params.name` | 400, `-32600` |

"Reads as one" is Go's rule, the one its `encoding/json` matches a key to a struct field
by: Unicode simple case folding, so the long s beside `s` and the Kelvin sign beside `k`
count too. A Go MCP server behind a gateway would act on whichever came last, so the
guard refuses both, in the arguments as much as at the top level, exactly as coaz-pep
does.

Pass the untouched request as `raw: { headers, body }` and the guard judges the bytes
rather than your parse of them: a `Content-Encoding` other than identity is a 415, a
byte-order mark, invalid UTF-8 (pass the body as bytes to have that checked), trailing
data or anything that is not JSON is `-32700`, and a member named twice at any depth is
`-32600` — a parser that keeps the first and one that keeps the last would disagree
about what was asked. An `rpc` passed alongside must match the body. A gateway that
forwards the raw body upstream should always pass it.

**Every MCP method is governed.** `applyDefaultMappings` defaults to `true`: the SDK
applies the binding's default mapping for `tools/list`, `resources/*`, `prompts/*`,
`completion/complete`, `logging/setLevel`, `tasks/*`, `initialize` and any tool that
declares no mapping of its own; `ping`, `notifications/*` and server-initiated methods
pass through; anything unknown is denied so future MCP methods fail closed. See
[`core/README.md`](../../core/README.md#default-mappings--the-full-table) for the table
and for two problems we found in the binding along the way. `applyDefaultMappings: false`
restores the old pass-through for undeclared tools and non-`tools/call` methods — not
conformant, so time it rather than discover it.

The server-scoped defaults (`tools/list`, `initialize` and friends) name this server
from the token's `aud`. Where `aud` is an array the guard picks this server's own
identifier out of it (`resource`, or `upstreamUrl`) or its only entry; a token it cannot
choose from, or one with no `aud` at all, is a mapping error.

Two places the SDK is deliberately **stricter** than the drafts: a `subject` inside an
`evaluations` entry is rejected (identity smuggling), and a *declared* `resource.id` or a
`subject.id` that resolves absent is a mapping error rather than a dropped key — in both
dialects — because dropping it would silently turn "this customer" into every customer.
Absence is pruned only from `context`.

When a declared mapping sets `subject.id` from something other than the token claim, the
SDK warns: that identity is asserted by whoever wrote the mapping, which for a gateway is
the MCP server being authorised. Pass `onWarning` to route it somewhere useful.

### What a verdict tells you to do

| Field | When | What |
| --- | --- | --- |
| `allow` | always | only `true` means go |
| `response` | deny | the HTTP response to send as is: status, headers (`X-PDP-Decision: DENY`) and body |
| `jsonRpcError` | deny | the JSON-RPC error — the body of `response` |
| `upstreamHeaders` | permit | the `X-Auth-*` identity to set on what you forward; an empty value means remove the client's copy |
| `responseHeaders` | permit | headers to add to the client's response, `X-PDP-Fail-Open` among them |
| `message` | always, once read | the JSON-RPC message that was judged |

Error codes are the profile's and JSON-RPC's:

| Code | When |
| --- | --- |
| `-32001` | the PDP denied — `error.data.authz_challenge` carries the remedy when there is one |
| `-32602` | the mapping could not be evaluated |
| `-32603` | the PDP could not be reached — fail closed |
| `-32600` | the message is not one the PEP will read (HTTP 400, or 415 for an encoding) |
| `-32700` | the body is not JSON (HTTP 400) |

`-32001` is v2. Tools still declared against v1 get `-32401`, which the current binding
calls out as non-conformant with JSON-RPC — kept only so a client that string-matches on
it does not break on upgrade.

### Acting as a gateway

In front of someone else's MCP server, give the guard `upstreamUrl` and it discovers
`tools/list` over streamable HTTP (JSON or SSE), the way the Go engine does: a bare
request first, and if the server wants a session, the initialize handshake and the list
again inside it. It follows `nextCursor` up to 32 pages — a tool declared on page two
must be judged by its own declaration, not the default — and a list it cannot read to the
end fails closed. One deadline covers the whole discovery (`discoveryTimeoutMs`, default
10s), concurrent calls share one discovery, answers over 4 MiB are refused, and
redirects are not followed. The result is reused for `discoveryTtlMs`.

### The CEL caveat

COAZ compiles mapping leaves as CEL. There is no credible CEL evaluator for Node, so this
SDK implements a **documented subset** and refuses anything outside it with a `-32602`
rather than guessing:

```
'literal'  "literal"        string literals
123  1.5  true  false  null
params.a.b   params["a"]    tool call params
token.sub    token.act.sub  token claims
token.?client_id            optional selection — the key is omitted when absent
string(x)  int(x)  double(x)
a + b + 'c'                 concatenation / addition
```

Conditionals are supported with `==` and `!=` only — the binding's own
`completion/complete` default needs one, so a required default mapping could not be
evaluated without them. Ordering (`>`), boolean operators and macros like
`exists(r, ...)` are still outside the subset and raise `-32602`. Delegate those.

### Delegating to coaz-pep

For full CEL, hand the check to the Go engine in [`../../core`](../../core), which is
exactly what the Kong plugin does and for the same reason:

```ts
const guard = new McpGuard({
  client: { url: process.env.AUTHZEN_URL! },
  upstreamUrl: 'https://mcp.bank.example/mcp',     // the server coaz-pep reads tools/list from
  delegate: {
    url: 'http://coaz-pep:9192',
    apiKey: process.env.CHECK_API_TOKEN,           // coaz-pep's CHECK_API_TOKEN
    config: { require_token: 'true' },
  },
});
const v = await guard.checkToolCall({ raw: { method: 'POST', path: '/mcp', headers: req.headers, body: rawBody } });
```

Every MCP request goes to coaz-pep's `POST /v1/mcp/check` — whatever its method, `GET`
and `DELETE` on the MCP endpoint too — and nothing is decided here. The guard sends
`mcp_upstream_url` from `upstreamUrl` and `coaz_defaults` from `applyDefaultMappings`, so
both PEPs govern the same methods against the same declarations; a `delegate.config`
that says otherwise about `style`, `mcp_upstream_url` or `coaz_defaults` will not build.
Only the headers coaz-pep reads travel with the body: `authorization`, `x-user-token`,
`dpop`, `content-type` and `content-encoding`.

Only `decision === true` permits. A permit carries coaz-pep's `upstream_headers` as
`upstreamHeaders` (with a removal for any `X-Auth-*` it did not name) and its
`response_headers` as `responseHeaders`, so `X-PDP-Fail-Open` survives. A deny relays
the response coaz-pep rendered verbatim — a 401 challenge keeps its status and
`WWW-Authenticate` — so there is one rendering of one decision. `upstreamUrl` and
`delegate.apiKey` are required; `allowInsecure: true` lets the latter go, for
development.

## PDP discovery

By default the client is told where the PDP is (`url`) and assumes the AuthZEN paths
under it. `discovery` replaces both assumptions with metadata — the same chain the Go
PEP and the Kong plugin walk (see [`core/README.md`](../../core/README.md#pdp-discovery)):

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| off (default) | nothing — static PDP, default paths, no fetch | — |
| `authzen` | `url`'s `/.well-known/authzen-configuration` | default paths |
| `resource` | the call's resource's RFC 9728 document (`authzen_policy_decision_points`), then that PDP's metadata | `url`, when the resource publishes nothing |

```ts
const client = new AuthzenClient({
  url: process.env.AUTHZEN_URL!,            // the static PDP, always permitted
  apiKey: process.env.AUTHZEN_API_KEY,      // bound to `url`; a discovered PDP never receives it
  discovery: {
    mode: 'resource',
    pdpAllowlist: ['https://pdp.bank.example'],        // what a resource may name — required
    resourceAllowlist: ['https://api.bank.example'],   // whose documents are read — required
  },
});

// The resource is per call: a string or a function of the request on the middleware,
// `resource` (defaulting to `upstreamUrl`) on the guard.
app.use(authzenMiddleware({ client, verifyToken, map, resource: 'https://api.bank.example' }));
await client.evaluate(request, { resource: 'https://api.bank.example' });
```

Resource mode will not start without both allowlists: the PDP a call goes to comes from
a document the resource publishes, so without a PDP allowlist any resource could name any
PDP. Allowlist entries are prefixes matched at a path boundary, and an entry with a path
(`https://pdp.example/tenant1`) permits its own well-known. `allowInsecure: true` starts
without them, and allows http, for development — it says so once at construction.

The rules are the Go PEP's: the resource's echoed `resource` must be byte-identical
(RFC 9728 §3.3), the PDP's `policy_decision_point` must equal the identifier it was
fetched from, a PDP without metadata gets the spec's default paths, a batch is never sent
to a PDP that does not advertise `access_evaluations_endpoint`, and a URL outside an
allowlist never falls through to a weaker source — the verdict is a `pdp_error`.

A resource that publishes nothing — a 404, or a document that names no PDP — is decided
by the static PDP, by design. A resource whose document cannot be read is not the same
thing: an outage, or a document that is invalid (the wrong `resource`, entries that are
not PDP identifiers, not JSON), makes the resource layer unavailable, and it fails by its
own mode — closed unless you said otherwise, and marked when skipped. An outage of either
document serves the last good copy for up to one more TTL, and a refusal ends it at once;
after that, or with no good copy yet, the layer is unavailable. A PDP's metadata falls
back to the default paths only when the PDP publishes none (404), never as a guess while
it cannot be read. Failures are remembered for `minRefreshMs` rather than retried in every request, and warned about
once per window.

Whatever document named the PDP is forwarded to it verbatim as `context.resource_metadata`
(with `context.resource_metadata_source`). The middleware forwards the endpoint hit as
`context.request`, and the raw token as `context.access_token` when `forwardAccessToken`
is set; on the guard, set `forwardAccessToken` and pass `accessToken` per call. The client
itself takes `accessToken` and `request` in `EvaluateOptions`. Those four keys are the
PEP's: a mapping or a caller that puts them in `context` — at the top level or in a
boxcar entry — has them removed, and only what the PEP forwards is sent. The SDK enforces
none of it: what a resource requires is the PDP's to match. See
[docs/architecture.md](../../docs/architecture.md#what-the-pep-forwards-and-what-it-does-not-decide).

`layers` on the client (or per call) is the ordered list of PDPs to ask — `'static'`,
`'resource'`, or a PDP identifier — every one of which must permit; the first deny is the
verdict. A generic estate PDP that judges the token and the client goes first; the
resource's own PDP after. Default `['resource']`. Identifiers named in `layers` are held
to the PDP allowlist too.

An entry may carry its own failure mode (`'https://estate.example fail-open'`, or
`{ name, failOpen }` where `failOpen` is a boolean — `'false'` is refused, not read as
true); `failMode: 'open'` on the client, the middleware, the guard or a call is the
default for entries that say nothing. A PDP exchange ends one of four ways, and only one
of them can be skipped:

| Outcome | What | A fail-open layer |
| --- | --- | --- |
| permit | the decision is the JSON boolean `true` (every one, for a boxcar) | — |
| deny | the decision is `false` | never skips it — a deny is a decision |
| unavailable | a network error, a timeout, a 5xx, a 429; a PDP with no batch endpoint asked a boxcar | skips it, and says so |
| refusal | a 3xx or 4xx, a 2xx that is not a decision, an answer over 1 MiB, a request that cannot be encoded (`Infinity`, `NaN`, a cycle), an unusable URL, an allowlist miss | never skips it |

A skipped layer is named in the verdict's `failedOpen`, and the middleware sets
`X-PDP-Fail-Open`. If every layer was skipped the verdict is a permit that says so. The
PDP POST never follows a redirect, so a forwarded token cannot be steered off the
allowlist. `onTrace` receives each exchange with its `outcome`, so a refusal and an outage
are logged apart. The guard passes `fail_mode` to coaz-pep in delegate mode.

### The resource's federation face

`FederationEntity` holds a private key and serves the two documents a federated resource
publishes: a minimal entity configuration (keys, `authority_hints`, the entity type — no
policy, the controller maintains that) for a trust controller to onboard, and RFC 9728
metadata with `signed_metadata`.

```ts
import { FederationEntity } from '@id-partners/authzen-pep';

const entity = new FederationEntity({
  entityId: 'https://api.bank.example',
  key: privateJwk,                                  // or a KeyObject: EC, or RSA of 2048 bits or more
  authorityHints: ['https://federation.example'],
  asserted: { authzen_policy_decision_points: ['https://pdp.bank.example'] },
});
app.use(entity.handler());   // serves the two well-known paths, passes everything else on
```

The entity id and every authority hint must be https (`allowInsecure` relaxes that for
development), and both lifetimes must be positive. `signed_metadata` is a JWT of the
document's members with the entity as `iss`, an `iat` and an `exp`
(`metadataLifetimeSeconds`, default 3600); JWT-registered claims in `asserted` are
dropped, since they are the entity's to set. Both documents are signed once and served
until half their lifetime has gone.

The SDK has no chain resolver, so its RFC 9728 document is self-asserted from `asserted`.
`coaz-pep` walks its own chain and republishes what the federation resolved; put it in
front when the public document must be the controller's word.

There is no federation mode in the SDK; `sources` is the seam for one, and `discovery`
also accepts a resolver of your own (`{ resolve(resource) }`). In `delegate` mode the
Go engine runs its own discovery, federation included, and an explicit `resource` is
passed to it so both PEPs key off one identifier.

## Challenges

A deny an agent can resolve beats a deny it cannot. When the PDP's decision context says
how, the SDK renders it three consistent ways:

| Verdict kind | HTTP | `WWW-Authenticate` | `authz_challenge.type` |
| --- | --- | --- | --- |
| `identity_proofing_required` | 401 | `identity_verification_required` | `identity_proofing` |
| `step_up_required` | 401 | `insufficient_scope` (RFC 9470) | `resource_authorisation` |
| `unauthenticated` | 401 | `login_required` | `authn` |
| `denied` | 403 | — | — |
| `mapping_error` | 400 | — | — |
| `pdp_error` | 502 | — | — |

`pdp_error` is 502 on purpose: the PDP being down is our problem, and a 403 would send
the caller chasing permissions they already have.

These come from `context.step_up_required` / `identity_proofing_required` and friends —
our convention, shared with the Kong and Envoy PEPs here. A PDP that does not emit them
still yields clean permits and denies.

What reaches the caller is generic where it has to be. A policy deny carries the PDP's
own reason; a PDP failure or a mapper that threw says so in a fixed phrase, and the
detail — which PDP, which status, which error — is in `verdict.detail` for your logs and
`onDecision`, never in a response. Header values built from PDP data lose CR, LF and
anything outside printable Latin-1, and are quoted-string escaped inside
`WWW-Authenticate`, so no reason can forge a header or make Node refuse one.

## Also exported

`AuthzenClient` on its own, when you want the decision without the middleware —
`evaluate`, `evaluateAll` (boxcar, folded to one verdict, first deny wins so its advice
survives), `evaluations`, `searchSubject`, `searchResource`.

`extractClaims` / `claimsFromToken` normalise the things that bite: `scope` vs `scp`,
string vs array, and `act`/`cnf` arriving as JSON *strings* rather than objects —
PingFederate does this, and a naive `claims.act.sub` silently reads `undefined`, making
every delegated call look direct. They decode; they do not verify. `jwkThumbprint`
computes RFC 7638 for a DPoP check.

## Develop

```sh
npm ci
npm test                # 460 tests, no network beyond localhost
npm run test:coverage   # same, with the ratchet enforced
npm run build
```

`npm pack` runs a clean build first. The package ships `dist`, the `src` its source maps
point at, this README and the licence.

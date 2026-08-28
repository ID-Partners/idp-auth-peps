# @id-partners/authzen-pep

An [AuthZEN 1.0](https://openid.net/wg/authzen/) Policy Enforcement Point for Node —
Express/Connect middleware for REST APIs, and a COAZ guard for MCP `tools/call`.

Node 20+. No runtime dependencies.

```sh
npm install @id-partners/authzen-pep
```

Reach for this when the traffic cannot sit behind the Kong or Envoy PEPs in this repo,
or when the decision needs request context only the application has. Everything fails
closed: a timeout, a 500, an unparseable body and a mapping it cannot evaluate all deny.

## REST

```ts
import { authzenMiddleware, pathMapper } from '@id-partners/authzen-pep/express';
import { jwtVerify, createRemoteJWKSet } from 'jose';

const jwks = createRemoteJWKSet(new URL('https://as.example.com/jwks'));

app.use(authzenMiddleware({
  client: { url: process.env.AUTHZEN_URL!, apiKey: process.env.AUTHZEN_API_KEY },
  pep: 'api-edge',

  // Verify BEFORE you trust. Without this the middleware only decodes, and an
  // unverified `sub` is an attacker-chosen `sub`.
  verifyToken: async (token) => (await jwtVerify(token, jwks)).payload,

  map: pathMapper([
    { method: 'GET',  pattern: '/accounts/:id/balance', action: 'get_balance',  resourceType: 'account', resourceId: p => p.id },
    { method: 'POST', pattern: '/payments',             action: 'make_payment', resourceType: 'payment',
      resourceProperties: (_p, req) => ({ amount: (req.body as any)?.amount }) },
  ]),

  forwardHeaders: true,                    // X-Auth-Principal / -Agent / -Scope / -Acr
  onDecision: ({ verdict }) => audit.log(verdict),
}));
```

On permit the request continues and `req.authz` carries `{ claims, verdict, request }`.
On deny nothing downstream runs, and the response is the challenge — see below.

`pathMapper` is a convenience, not the contract: **an unmatched route is a deny.** A route
you forgot to describe is not a route you meant to leave open. Pass `fallthrough: 'allow'`
only for paths that genuinely carry no policy. For anything real, write `map` yourself —
it can be async, so it may look up an account's owner or a tenant before deciding what
the resource even is.

There is deliberately no built-in URL→resource guesser. Inferring a resource type from a
path is how a PEP ends up confidently authorising the wrong thing.

## MCP

Under [COAZ](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html) a tool
declares how its call becomes an authorization question, in its `inputSchema`:

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

const verdict = await guard.checkToolCall({ rpc, claims, extraContext: { channel: 'ai-agent' } });
if (!verdict.allow) return verdict.jsonRpcError;   // send with HTTP 200
```

Or wrap a handler:

```ts
const handle = guard.wrap(async (rpc) => runTool(rpc));
const result = await handle(rpc, claims);          // returns the JSON-RPC error on deny
```

Acting as a **gateway** in front of someone else's MCP server instead? Give it
`upstreamUrl` and it discovers `tools/list` over streamable HTTP (JSON or SSE),
cached for `discoveryTtlMs`.

Error codes are the profile's:

| Code | When |
| --- | --- |
| `-32001` | the PDP denied — `error.data.authz_challenge` carries the remedy when there is one |
| `-32602` | the mapping could not be evaluated |
| `-32603` | the PDP could not be reached — fail closed |

`-32001` is v2. Tools still declared against v1 get `-32401`, which the current binding
calls out as non-conformant with JSON-RPC — kept only so a client that string-matches on
it does not break on upgrade.

A tool that declares no mapping in either dialect passes straight through by default.
That is **not conformant** — the binding says the default `tools/call` mapping applies
instead — so set `applyDefaultMappings: true` to authorize undeclared tools against it.
It is opt-in because turning it on makes every previously-unGoverned call require a PDP
decision, which is a change you should time rather than discover.

Two places the SDK is deliberately **stricter** than the drafts: a `subject` inside an
`evaluations` entry is rejected (identity smuggling), and a *declared* `resource.id` that
resolves absent is a mapping error rather than a dropped key — dropping it would silently
turn "this customer" into every customer. Absence is pruned only from `context`.

When a declared mapping sets `subject.id` from something other than the token claim, the
SDK warns: that identity is asserted by whoever wrote the mapping, which for a gateway is
the MCP server being authorized. Pass `onWarning` to route it somewhere useful.

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

Conditionals (`$token.roles.exists(r, r == 'treasury') ? 'a' : 'b'`), which the binding's
own examples use, are outside the subset and raise `-32602`. Delegate those.

For full CEL, hand the check to the Go engine in [`../../core`](../../core), which is
exactly what the Kong plugin does and for the same reason:

```ts
const guard = new McpGuard({
  client: { url: process.env.AUTHZEN_URL! },
  delegate: { url: 'http://coaz-pep:9192', config: { style: 'mcp', require_token: 'true' } },
});
await guard.checkToolCall({ rpc, claims, raw: { headers, body: rawBody } });
```

The engine renders the JSON-RPC error and the SDK relays it verbatim — two renderings of
one decision would drift.

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

## Also exported

`AuthzenClient` on its own, when you want the decision without the middleware —
`evaluate`, `evaluateAll` (boxcar, folded to one verdict, first deny wins so its advice
survives), `evaluations`, `searchSubject`, `searchResource`.

`extractClaims` / `claimsFromToken` normalise the things that bite: `scope` vs `scp`,
string vs array, and `act`/`cnf` arriving as JSON *strings* rather than objects —
PingFederate does this, and a naive `claims.act.sub` silently reads `undefined`, making
every delegated call look direct. `jwkThumbprint` computes RFC 7638 for a DPoP check.

## Develop

```sh
npm install
npm test        # 40 tests, no network
npm run test:coverage   # same, with the ratchet enforced
npm run build
```

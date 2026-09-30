# `authzen-pdp` — Kong Gateway plugin

A Policy Enforcement Point for Kong that authorises delegated AI-agent traffic against an
AuthZEN PDP: token and actor-claim extraction (RFC 8693), DPoP sender constraints
(RFC 9449), RFC 9470 step-up challenges, REST and MCP request mapping, PDP discovery, and
per-tool-call authorisation under the OpenID AuthZEN MCP profile (COAZ).

Its sibling, [`sideband-pdp`](sideband-pdp/README.md), is the same discovery — and the same
layers, rules and allowlists, from the modules the two share — in front of PingAuthorize's
Sideband API instead of AuthZEN: for a REST route where the policy, not the gateway, should
own the request mapping and the shape of a deny.

## Kong versions

Kong Gateway **3.4 or later**, open source or Enterprise. Both plugins have been run
through 3.7 (open source), 3.9 (open source) and 3.15 (Enterprise).

**3.9 or later is recommended.** Two things these plugins lean on changed between 3.7 and
3.9 — read from the Kong source of 3.4, 3.7, 3.9 and 3.15, and seen in the live runs; 3.8
was not checked, so the plugins treat it as the older behaviour:

- `kong.request.get_raw_body` reads back a body Kong buffered to disk. Before 3.9 it
  cannot, so a request body larger than `client_body_buffer_size` (8 KiB by default) is
  out of reach and the request is refused with a 413 — never authorised unread. On those
  releases, raise `nginx_http_client_body_buffer_size` to cover the bodies you expect.
- Kong keeps buffering the upstream's response for HTTP/2. Before 3.9 it turns buffering
  off, a plugin's response phase does not run, and `sideband-pdp` refuses HTTP/2 on a route
  that filters responses.

## Install

DB-less: mount the plugin directory and tell Kong about it.

```
# kong.conf / environment
KONG_PLUGINS=bundled,authzen-pdp
KONG_LUA_PACKAGE_PATH=/opt/?.lua;;
```

Mount `authzen-pdp/` at `/opt/kong/plugins/authzen-pdp/` (the module path Kong looks for
is `kong.plugins.authzen-pdp.handler`). Or install the rock from the `v0.4.1` release,
`luarocks install kong-plugin-authzen-pdp-0.4.1-1.all.rock` - the plugin alone, nothing
fetched. It also carries the `discovery` and `contract` modules `sideband-pdp` requires.

## How a route is decided

There are two ways, and `coaz_url` chooses between them.

| | With `coaz_url` | Without it |
| --- | --- | --- |
| Who decides | `coaz-pep`, the whole request, over its check API | this plugin |
| The access token | verified by `coaz-pep` | read here, trusted because something in front verified it |
| `X-User-Token`, DPoP | verified by `coaz-pep` | not available: `require_user_login` and `require_dpop` need `coaz_url` |
| Routes | REST and MCP | REST only: `style: mcp` needs `coaz_url` |
| PDP discovery | `coaz-pep`'s, federation included | this plugin's, `off`, `authzen` or `resource` |

### With `coaz_url`: coaz-pep decides the whole request

The plugin sends `coaz-pep` the request — method, path, the `authorization`,
`x-user-token`, `dpop`, `content-type` and `content-encoding` headers, the body — and the
route's knobs, over `POST {coaz_url}/v1/mcp/check`, and enforces what comes back. Only
`"decision": true` permits. A permit sets every `upstream_headers` entry on the request to
the upstream (an empty value removes that header) and carries `response_headers` to the
client; a deny is relayed exactly as `coaz-pep` rendered it — a JSON-RPC error on an MCP
route, a challenge or a 403 on a REST one — because two renderings of one decision would
drift.

`coaz-pep` verifies the access token and `X-User-Token` against its own JWKS
configuration, checks the DPoP proof, maps the request, finds the PDPs and asks them. A
Kong plugin has no usable JOSE verifier, so this is the only way a route here gets
verified tokens without an auth plugin in front, and the only way it gets DPoP, user login
or COAZ at all.

The knobs sent: `style`, `require_token`, `require_dpop`, `require_user_login`,
`stepup_scope`, `stepup_action`, `mcp_upstream_url`, `resource`, `pdp_layers`, `fail_mode`
(always sent, so a route that says nothing is closed whatever `coaz-pep`'s own default),
`forward_access_token`, `legacy_subject_identity`, `coaz_defaults`, `user_token_subject`
and `pep_label`. The route's own discovery fields (`pdp_discovery`, the allowlists,
`authzen_url`) play no part: `coaz-pep` discovers under its own settings.

`user_token_subject` says whose `X-User-Token` counts. `principal`, the default, counts
only the access token's own subject's login — customer B's consent never authorises
customer A's payment. `pdp` also counts someone else's verified login, for a route where a
staff member approves for a customer; the PDP receives `user_sub` and decides whether that
person may. It needs `coaz_url`, since only `coaz-pep` reads the user's token.

`coaz_api_key` is required with `coaz_url`: the check API relays a caller-supplied
`Authorization` header, so it authenticates its callers (`CHECK_API_TOKEN`). `coaz-pep`
unavailable (no answer, a 5xx, a 429) is a 503; `coaz-pep` refusing the call (a 3xx or
4xx) or answering something that is not a decision is a 503 as well, logged as a refusal.

### Without it: decided here, on claims something else verified

The plugin reads the access token's claims — `sub` the principal, `act.sub` the agent,
`scope`, `acr`, `client_id` — maps the request, finds the PDPs and asks them. It does not
verify the token's signature. So it reads the claims only when the route says who did:

- `access_token_verified_upstream: true` — an `openid-connect` or `jwt` plugin on the same
  route validates `Authorization` first. Both run before this one (see
  [plugin order](#plugin-order)). Do not give that plugin an `anonymous` consumer: a
  request it could not authenticate would then reach this one with its token unverified.
- or `allow_insecure: true`, for development and demos.

Without either, or `coaz_url`, the configuration is refused. `X-User-Token` is never read
on such a route — its claims drive consent and step-up, and a forged one would be a
bypass of both.

## MCP routes

`style: mcp` needs `coaz_url`, and **every** request on the route goes to `coaz-pep` —
`initialize`, `tools/list`, `resources/read`, notifications, a client's answer to a
server-initiated request, the SSE `GET`, the session `DELETE` — not only `tools/call`. The
old behaviour, asking about `tools/call` and letting everything else through on a valid
token, let a body the plugin could not classify run with no PDP call.

Before anything is sent, the body is read whole and parsed strictly. A POST body must be
exactly one JSON-RPC object this plugin positively understands, or it is refused here:

| The request | Answer | JSON-RPC error |
| --- | --- | --- |
| a body larger than `max_request_body_size` (1 MiB by default), or one Kong cannot read back | 413 | `-32600` Invalid Request: request body too large for the PEP to authorise |
| `Content-Encoding` other than `identity` | 415 | `-32600` Invalid Request: Content-Encoding not supported by the PEP |
| a byte-order mark, invalid UTF-8, trailing data, not JSON | 400 | `-32700` Parse error |
| a batch (a top-level array), anything but one object, member names that differ only in case (`"Params"` beside `"params"`, `"Name"` beside `"name"`), a method that is not a string, neither a request nor a response, a `tools/call` without a string `params.name` | 400 | `-32600` Invalid Request: … |
| a body on a request other than a POST | 400 | `-32600` |

Every refusal is JSON with `X-PDP-Decision: DENY`, and carries the request's `id` when it
could be read. `cjson` keeps the last of two members with exactly the same name; `coaz-pep`
parses the body again and refuses an exact duplicate.

`coaz_defaults` now defaults to **true**: with it, every MCP method is governed by the
COAZ-MCP binding's default mappings, `ping`, notifications and responses pass, and anything
unknown is denied. Only an explicit `false` keeps the old pass-through for methods other
than `tools/call`, which is not conformant.

## Configure

A REST route decided natively, behind Kong's own `jwt` plugin:

```yaml
plugins:
  - name: jwt
    route: bank-api
    config:
      claims_to_verify: ["exp"]
  - name: authzen-pdp
    route: bank-api
    config:
      authzen_url:     "{vault://env/authzen-url}"
      authzen_api_key: "{vault://env/authzen-api-key}"
      pep_label: "PEP#2 (Bank API edge)"
      style: rest
      require_token: true
      access_token_verified_upstream: true   # the jwt plugin validated Authorization
```

A REST route `coaz-pep` decides, with DPoP and a logged-in user:

```yaml
  - name: authzen-pdp
    route: bank-api
    config:
      authzen_url:     "{vault://env/authzen-url}"
      authzen_api_key: "{vault://env/authzen-api-key}"
      pep_label: "PEP#2 (Bank API edge)"
      style: rest
      require_token: true
      require_dpop: true
      require_user_login: true
      coaz_url: https://coaz-pep.internal:9192
      coaz_api_key: "{vault://env/coaz-api-key}"
```

An MCP edge:

```yaml
  - name: authzen-pdp
    route: mcp-edge
    config:
      authzen_url:     "{vault://env/authzen-url}"
      authzen_api_key: "{vault://env/authzen-api-key}"
      pep_label: "PEP#1 (MCP edge)"
      style: mcp
      require_token: true
      require_user_login: true
      coaz_url: https://coaz-pep.internal:9192
      coaz_api_key: "{vault://env/coaz-api-key}"
      mcp_upstream_url: http://bank-mcp:8090/mcp
```

`authzen_url`, `authzen_api_key` and `coaz_api_key` are `referenceable`, so they take Kong
vault references rather than literals, and the two keys are `encrypted` where Kong has a
keyring.

## Plugin order

`authzen-pdp` runs at priority 1000, `sideband-pdp` at 999 — Kong runs a higher number
first. So Kong's authentication plugins run before them, which is what
`access_token_verified_upstream` relies on, and several traffic plugins run after them:

| Plugin | Priority | Runs |
| --- | --- | --- |
| `jwt` | 1450 | before |
| `oauth2` | 1400 | before |
| `key-auth` | 1250 | before |
| `openid-connect` (Enterprise) | 1050 | before |
| **`authzen-pdp`** | 1000 | |
| **`sideband-pdp`** | 999 | |
| `ip-restriction` | 990 | after |
| `request-size-limiting` | 951 | after |
| `acl` | 950 | after |
| `rate-limiting` | 910 | after |
| `request-transformer` | 801 | after |

The ones after matter. A request `ip-restriction` or `acl` would refuse still costs a PDP
call first, and `rate-limiting` does not protect the PDP from a burst: every request
reaches it before the limit is counted. A `request-transformer` that rewrites the path or
body changes the request after the PDP judged it. On Kong Enterprise, dynamic plugin
ordering puts a plugin in front:

```yaml
  - name: rate-limiting
    route: bank-api
    config: { minute: 600, policy: local }
    ordering:
      before:
        access: ["authzen-pdp"]
```

On open-source Kong the priorities are fixed; put the limit in front of Kong, or accept
that the PDP sees every request.

## PDP discovery

On a route decided here, the plugin is told where the PDP is (`authzen_url`) and assumes
the AuthZEN paths under it, unless `pdp_discovery` replaces both assumptions with metadata
— the same chain the Go PEP walks (see [`core/README.md`](../../core/README.md#pdp-discovery)),
minus one branch:

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| `off` | nothing — static PDP, default paths, no fetch | — |
| `authzen` | `authzen_url`'s `/.well-known/authzen-configuration` | default paths, when the PDP has no metadata (a 404) |
| `resource` | the route's resource's RFC 9728 document (`authzen_policy_decision_points`), then that PDP's metadata | `authzen_url`, when the resource publishes nothing (a 404) |

There is **no `federation` mode in this plugin**. Resolving an OpenID Federation Trust Chain
means verifying Entity Statement signatures, and no JOSE verifier is available to a Kong
plugin. A route that must take the federation's word belongs behind `coaz-pep`, which
walks and verifies the chain — set `coaz_url` and it does. (`sideband-pdp` has a weaker
alternative, a resolve endpoint's answer taken on transport, named `federation-resolver`
so it is never mistaken for a verified chain; see
[its README](sideband-pdp/README.md#the-switch-resolving-through-the-federation).)

```yaml
config:
  authzen_url: "{vault://env/authzen-url}"        # the static PDP, always permitted
  pdp_discovery: resource
  resource: https://api.bank.example              # RFC 8707 identifier
  pdp_allowlist: ["https://pdp.bank.example"]     # required with discovery on
  resource_metadata_allowlist: ["https://api.bank.example"]
  pdp_metadata_ttl: 300
```

`pdp_allowlist` is required whenever discovery is on: an empty one used to mean any https
PDP a resource named. An entry may carry a path — a tenant's PDP, a resource under a
prefix — and the identifier's own well-known document is still fetched on its origin;
the endpoints a PDP's metadata advertises must fall inside the allowlist too.

Metadata is cached per identifier. A fetch that fails — no answer, a 5xx, a redirect, a
body that is missing or too large — or a document that does not validate serves the last
good document for up to one more TTL; after that, or with none cached, the layer is
unavailable and its failure rule decides, and the failure is not retried for 30
seconds. A 404 is different: the resource publishes nothing, or the PDP has no metadata,
and the static PDP or the default paths are what the design says. An outage used to be
read as a 404, which cached the default endpoints for a whole TTL, or fell to the static
PDP and quietly dropped whatever the resource put in front of its own. A JSON `null`
(`"authzen_policy_layers": null`, `"access_evaluations_endpoint": null`) reads as absent.

Whatever document named the PDP is forwarded to it verbatim as `context.resource_metadata`
(with `context.resource_metadata_source`), the endpoint hit as `context.request`, and the
raw token as `context.access_token` when the route sets `forward_access_token`. The plugin
enforces none of it: what a resource requires is the PDP's to match, next to everything
else the PDP knows. See [docs/architecture.md](../../docs/architecture.md#what-the-pep-forwards-and-what-it-does-not-decide).

`federation_entity_url` makes the route the resource's federation face: the plugin relays
`/.well-known/openid-federation` and `/.well-known/oauth-protected-resource` (with any
identifier path) from `coaz-pep` at that URL, which holds the key and signs both. Kong
cannot sign, so it relays; everything else on the route is untouched.

The rules are the Go PEP's: the resource's echoed `resource` must be byte-identical
(RFC 9728 §3.3), the PDP's `policy_decision_point` must equal the identifier it was
fetched from, and a URL outside an allowlist never falls through to a weaker source — the
request is a 503. A discovered PDP never receives `authzen_api_key`; that key is bound to
`authzen_url` alone.

## Layers, and what fail-open covers

`pdp_layers` is the ordered list of PDPs to ask — `static`, `resource`, or a PDP identifier
— every one of which must permit; the first deny is the answer. Default `["resource"]`:
the resource's PDP behind whatever its document publishes in `authzen_policy_layers`.
An entry may carry its own failure mode (`"https://estate.example fail-open"`); `fail_mode`
(`closed`, the default, or `open`) is the route's default for entries that say nothing.

A PDP call has four outcomes, and fail-open covers only one of them:

- **permit** — the answer's `decision` is the JSON boolean `true`;
- **deny** — `false`. A decision, never skipped;
- **unavailable** — no answer (DNS, connect, TLS, reset, timeout), a 5xx or a 429. A
  fail-open layer is skipped and named in `X-PDP-Fail-Open`; a closed one is a 503;
- **refusal** — a 3xx or 4xx, a 2xx whose body is not a readable decision (`"true"`, `1`,
  `{}`), a request that could not be encoded, an allowlist miss. Closed whatever the layer
  says, and logged as a refusal.

Before, every non-2xx was "unavailable", so a 401 from a rotated key, or a 400 the client
provoked, skipped a fail-open layer — and a client could provoke one: a `1e999` in the
body decodes to infinity, which JSON cannot carry back out, so the evaluation went as an
empty POST. A payment's `amount` must now be a finite number, and an evaluation that
cannot be encoded is a refusal.

## REST mapping

The mapping (`list_accounts`, `get_balance`, `open_account`, `make_payment`, and
`http:<method>` for anything else) matches the whole of the path the route delegates to its
service: Kong's normalised path — `kong.request.get_path`, RFC 3986-normalised on every
Kong 3.x release checked, the path Kong's router matched and the upstream receives — with
the matched route prefix removed when the route strips it, as Kong does. So
`/bank/accounts/a1/balance` on a `/bank` route with `strip_path` is `get_balance(a1)`,
`/admin/accounts/a1/balance` is not, and neither is a raw path with dot segments that only
names a balance before it is normalised.

A payment or account POST is read whole. A body that cannot be read in full is a 413; one
that is not a JSON object, or a payment without a string `from_account` and a numeric
`amount`, is a 400. Nothing goes to the PDP without the amount it is being asked about.

## What the upstream and the client see

The upstream gets `X-Auth-Principal`, `X-Auth-Agent`, `X-Auth-Scope` and `X-Auth-Acr` on a
permit, so a resource server can record the delegation chain and read the authentication
context the AS asserted rather than inferring a channel from a username. A client's own
copies of those four are removed before anything else happens, on every path, and a claim
the token does not carry stays absent rather than arriving empty.

The client gets `X-PDP-PEP`, `X-PDP-Decision`, `X-PDP-Action` and `X-PDP-Reason`, and
`X-PDP-Fail-Open` on a permit that skipped a layer — naming the layers' identifiers, never
the error; why a layer was skipped is in Kong's log. Every header built from PDP or engine
data is reduced to printable ASCII, a line break becoming a space, and a
`WWW-Authenticate` parameter is escaped as a quoted-string, so a policy's reason cannot
start a header of its own. The JSON body keeps the policy's words as written. The plugin's
own reasons are generic: no internal URL, no upstream error text.

## TLS to the PDP and coaz-pep

`pdp_ssl_verify` is on by default and turning it off needs `allow_insecure`. A PDP with a
private or self-signed certificate — PingAuthorize ships one — is trusted by adding its
certificate, or its CA's, to Kong's trust store, not by turning verification off:

```
KONG_LUA_SSL_TRUSTED_CERTIFICATE=system,/etc/kong/pdp-ca.pem
KONG_LUA_SSL_VERIFY_DEPTH=2
```

## `allow_insecure`

Missing security settings are configuration errors, and Kong refuses the configuration:

- a route decided here with neither `access_token_verified_upstream` nor `coaz_url`;
- `coaz_url` without `coaz_api_key`;
- `pdp_discovery` on without `pdp_allowlist`;
- `pdp_discovery_insecure: true`, or `pdp_ssl_verify: false`.

`allow_insecure: true` is the one way past them, for development and demos. Kong logs what
it relaxes, per route, when the configuration loads (the plugin's `configure` phase). Three
refusals it does not relax: `style: mcp`, `require_dpop` and `require_user_login` without
`coaz_url` — there is nothing insecure to allow, the plugin simply cannot do them.

## `subject.identity` -> `subject.id`

AuthZEN names the subject identifier `id`; this plugin historically sent `identity`, which
no version of the spec defines. It now sends **both**, so upgrading the gateway alone
cannot break a policy still reading the old field. Once your policies read `subject.id`,
set `legacy_subject_identity: false` per route and the non-standard field goes away.

The full sequence is in [`core/README.md`](../../core/README.md#migrating-subjectidentity---subjectid).
The Go PEP moves in lockstep — two gateways sending different subject shapes to one PDP
would be worse than either shape.

## Why coaz-pep, and not Lua

Three things need `coaz-pep`, and all for the same reason: there is no credible JOSE
verifier or CEL evaluator in Lua.

- **Token verification.** Reading a JWT's claims without checking its signature proves
  nothing about who sent it.
- **DPoP.** A local thumbprint comparison proves nothing either: the proof carries the very
  JWK being compared, so anyone who has seen one proof could mint another. The proof now
  travels in the check request; the separate `/v1/dpop/verify` call is gone.
- **COAZ.** The profile compiles `x-coaz-mapping` leaves as CEL. Reimplementing the mapping
  rules here would give two implementations of one spec and a guarantee that they drift.

## Upgrading from 0.3

- **MCP routes need `coaz_url`**, and every request on them now goes to `coaz-pep`, not only
  `tools/call`. Update `coaz-pep` with the plugin: it must govern non-`tools/call` methods.
- **`coaz_defaults` defaults to true.** Set it `false` to keep the old pass-through.
- **With `coaz_url` set, `coaz-pep` decides the whole request**, REST routes included, and
  verifies the tokens and the DPoP proof. The route's own discovery settings no longer
  apply there.
- **Without `coaz_url`, declare who verified the token**: `access_token_verified_upstream`
  with an `openid-connect` or `jwt` plugin in front, or `allow_insecure` for a demo.
  `X-User-Token` is no longer read on such a route, so `context.user_scope` is no longer
  sent, and `require_user_login` needs `coaz_url`.
- **`coaz_url` needs `coaz_api_key`**; **discovery needs `pdp_allowlist`**;
  `pdp_discovery_insecure` and `pdp_ssl_verify: false` need `allow_insecure`.
- **A 3xx or 4xx from a PDP is a refusal**, closed even on a fail-open layer.
- **A PDP-metadata or resource-metadata outage** serves the last good document for up to
  one more TTL, then fails the layer under its rule — never the defaults or the static
  PDP. So does a resource document that does not validate.
- **REST patterns are anchored**, and a payment or account body that cannot be read is
  refused.
- **`X-PDP-Fail-Open` names identifiers only**; the error detail is in the log.
- **The rock is `kong-plugin-authzen-pdp-0.4.1-1`**, built from `v0.4.1`.

## Tests

```sh
cd gateways/kong
busted --lpath="./?.lua;./?/init.lua" spec/
../../scripts/lua-coverage-gate.sh
```

The behavioural tests run against a mocked Kong — no gateway, no database, no network — that
models the parts of the PDK these bugs hid in: a body past the buffer, header and argument
caps, forwarded headers from a trusted proxy, `cjson`'s nulls and non-finite numbers, and a
response phase Kong skips. See [`spec/README.md`](spec/README.md). A handler change also
deserves a pass through a real Kong: mount both plugin directories into `kong:3.9` or
`kong/kong-gateway:3.15` DB-less (on 3.15 give each route `protocols: ["http","https"]`,
since its DB-less routes default to https), in front of a stub that plays the PDP and
`coaz-pep`.

## Where this came from

The handler began as the one in `idp-agentic-demo` — it moved the step-up decision into
the PDP (the policy compares the payment amount to the threshold and returns
`step_up_required` advice) instead of an amount-blind gateway rule, and it forwards `acr`.
The rockspec came from `idp-authzen-adapter-go`.

Not to be confused with `ID-Partners-AU/kong-plugin-ping-auth` — our fork of Ping's
official Kong plugin, which predates AuthZEN and MCP. That one lives on as the sideband
half of [`sideband-pdp`](sideband-pdp/README.md), which shares this plugin's discovery
and contract modules.

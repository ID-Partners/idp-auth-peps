# `authzen-pdp` — PingAccess rule

A Policy Enforcement Point for PingAccess, as an Add-on SDK rule: the PingAccess
counterpart of the [Kong plugin](../kong), sending the PDP the same AuthZEN evaluation
request and rendering the same challenges, so a client cannot tell from the deny which
gateway said no. Token and actor-claim extraction (RFC 8693), RFC 9470 step-up
challenges, REST request mapping, RFC 9728 and AuthZEN metadata discovery, and policy
layers are native Java in [`authzen-pdp/`](authzen-pdp); DPoP verification and every
decision on an MCP route are delegated to `coaz-pep`, exactly as Kong does.

Two things it does natively that a Kong plugin cannot: it reads the identity PingAccess
itself validated, and it verifies `X-User-Token` (jose4j is on PingAccess's classpath).

This file is the reference card. **[docs/pingaccess.md](../../docs/pingaccess.md)** is
the explainer: where the rule sits in PingAccess's object model and request order, one
request end to end, what PingAccess validates and what the rule reads, the deny on the
wire, three worked configurations, production posture and troubleshooting.

Not to be confused with PingAccess's built-in *PingAuthorize Policy Decision Access
Control* and *PingAuthorize Access Control* rules. Those speak PingAuthorize's own
sideband and policy-decision APIs to PingAuthorize alone. This one speaks AuthZEN 1.0
to any conformant PDP, discovers which PDP decides for a resource, and returns
resolvable challenges.

## Upgrading to 0.4.0

0.4.0 is the production-readiness release, and it refuses things 0.3 let through. A
rule configured under 0.3 may fail to configure under 0.4.0 - PingAccess reports it as
**Invalid plugin configuration;** and every request through the rule is then a 500 deny
until it is fixed. Check each rule before you deploy the jar:

- **`style: mcp` needs `coaz_url`.** Every request on an MCP route now goes to
  `coaz-pep`, not only `tools/call`: the handshake, `tools/list`, notifications, the SSE
  `GET`. Nothing on an MCP route passes on a token alone any more, and the rule no longer
  asks the PDP about `initialize` itself.
- **`coaz_defaults` is on by default.** Every MCP method is governed by the COAZ binding's
  default table. Untick it only if you need the old pass-through for methods other than
  `tools/call`, and know that it is not conformant.
- **An MCP body the rule cannot read one way only is refused** - a batch, invalid UTF-8,
  a BOM, trailing data, a case-variant member, a compressed or partial body - with the
  JSON-RPC errors listed [below](#mcp-routes).
- **An access token PingAccess did not validate is a 401.** On an unprotected application
  PingAccess establishes no identity, and 0.3 took the token's own claims as the subject.
  Protect the application with an access token validator, or, for development only, tick
  `allow_insecure`.
- **`X-User-Token` needs a JWKS.** Without `user_token_jwks_url` the token is ignored:
  it opens no login gate and carries no `user_scope`. `require_user_login` without a JWKS
  is refused. With one, `user_token_audience` is required, and the token must carry
  `exp`, `sub` and that audience.
- **`X-User-Token` counts only as the principal's own login.** Its `sub` must be the
  access token's subject (PingAccess's identity's, on a protected application), and it
  must not be the access token itself or a delegated token (`act`). A route where
  someone else approves - staff approving for a customer - sets
  `user_token_subject: pdp`, and the PDP judges whose login it is from `user_sub`.
- **The PDP gets the user context coaz-pep sends**: `user_scope`, `token_aud`,
  `user_acr`, `user_sub` and `user_iss`, and `authorization_details` with the consented
  amount and creditor, so a payment approved at the MCP edge is not challenged again
  here.
- **Missing security settings are refused**, not warned about: an API key or a forwarded
  token over plain http, `coaz_url` without `coaz_api_key`, discovery without
  `pdp_allowlist`, `pdp_discovery_insecure`, `pdp_ssl_verify` off. `allow_insecure` lets
  a development rule start with them and logs each one.
- **Every URL must be one the rule can call**: absolute http or https, with a host.
  `http://authzen_pdp:8080` is refused at save time - an underscore is not legal in a
  host name, so the JDK has no host to connect to.
- **A fail-open layer opens on an outage only.** A 4xx, a redirect or an answer that is
  not a decision is a refusal, and closed.
- **A payment or a new account needs a readable body.** A `POST /payments` with no
  `from_account` or no numeric amount is a 400 before any PDP is asked.

## Build

The PingAccess Add-on SDK is on no public Maven repository. Take it from a PingAccess
install (`<PA_HOME>/lib/pingaccess-sdk-<version>.jar`) or, without an install, from the
public Docker image, which needs no licence to pull:

```sh
cd gateways/pingaccess/authzen-pdp
id=$(docker create pingidentity/pingaccess:9.1.0-latest)
mkdir -p .pa/lib && docker cp "$id:/opt/server/lib/pingaccess-sdk-9.1.0.1.jar" .pa/lib/ && docker rm "$id"
mvn verify                                    # tests, the coverage ratchet, the jar
# or, against an install:
mvn -Dpa.server.root=/opt/pingaccess -Dpa.sdk.version=9.1.0.1 verify
```

`.pa/` is git-ignored. The jar is `target/authzen-pdp-pingaccess-<version>.jar`; nothing
from the SDK, Jackson, jose4j or slf4j is bundled, PingAccess supplies them all. The
bytecode is Java 17, so it needs a Java 17 or later runtime. It has been tested on
PingAccess 9.1.0.1 (Java 21) and on nothing earlier.

## Install

Copy the jar to `<PA_HOME>/deploy/` and restart PingAccess; the DevOps image's local
server profile is `/opt/in/instance/deploy/`, which it merges into the instance at boot
([the demo's Dockerfile](../../demo/pingaccess/Dockerfile) does that). The rule then
appears as **AuthZEN PDP** (`AuthZenPdpRule`, class
`com.idpartners.pa.authzen.AuthZenRule`) in the rule descriptors and the admin console,
for Site and Agent destinations.

## Configure

Attach it to an application's or a resource's **API policy**. The rule's configuration
is the same map of knobs every PEP in this repository takes, spelled identically:

```sh
curl -sk -u administrator:$PA_PASSWORD -H 'X-Xsrf-Header: PingAccess' -H 'Content-Type: application/json' \
  https://pa-admin:9000/pa-admin-api/v3/rules -d '{
  "name": "authzen-pdp",
  "className": "com.idpartners.pa.authzen.AuthZenRule",
  "supportedDestinations": ["Site", "Agent"],
  "configuration": {
    "authzen_url": "https://pdp.bank.example",
    "authzen_api_key": "...",
    "pep_label": "PEP#2 (Bank API edge)",
    "style": "rest",
    "require_token": true,
    "pdp_discovery": "resource",
    "resource": "https://api.bank.example",
    "resource_metadata_allowlist": ["https://api.bank.example"],
    "pdp_allowlist": ["https://pdp.bank.example"],
    "pdp_layers": ["https://estate-pdp.example fail-open", "resource"],
    "user_token_jwks_url": "https://as.bank.example/jwks",
    "user_token_audience": "https://api.bank.example"
  }
}'
```

Then `POST /applications` with `"policy": {"API": [{"type": "Rule", "id": <rule id>}]}`.
[`demo/pingaccess/hooks/81-after-start-process.sh`](../../demo/pingaccess/hooks/81-after-start-process.sh)
is the whole sequence, site and application included, as a script.

| Knob | Default | Meaning |
| --- | --- | --- |
| `authzen_url` | required | The static PDP: always the fallback, always permitted |
| `authzen_api_key` | — | Bearer key for `authzen_url`, sent over https only. A discovered PDP never receives it |
| `pep_label` | `pingaccess-pep` | Names this PEP in challenges and the `X-PDP-PEP` header |
| `style` | `rest` | `rest` (resource server) or `mcp` (MCP edge: every request goes to `coaz-pep`; needs `coaz_url`) |
| `require_token` | `true` | Deny without a readable access token |
| `require_dpop` | `false` | Delegate the RFC 9449 sender-constraint check to `coaz-pep`; needs `coaz_url` |
| `require_user_login` | `false` | Deny without a verified `X-User-Token`, with a login challenge; needs `user_token_jwks_url` |
| `stepup_scope` | — | Scope named in a step-up challenge when the PDP's advice names none |
| `coaz_url` / `coaz_api_key` | — | `coaz-pep`'s HTTP check API and its `CHECK_API_TOKEN`; the key is required with the URL, and https with the key |
| `mcp_upstream_url` | — | Where `tools/list` lives; `coaz-pep` reads each tool's mapping from it |
| `federation_entity_url` | — | Relay the resource's two well-known documents from `coaz-pep` at this URL |
| `pdp_discovery` | `off` | `off`, `authzen` or `resource`; see [PDP discovery](#pdp-discovery) |
| `resource` | — | The protected resource's identifier (RFC 8707), the key discovery starts from |
| `pdp_metadata_ttl` | `300` | Cache TTL, seconds, for resource and PDP metadata |
| `pdp_allowlist` | — | Permitted discovered-PDP prefixes; required when `pdp_discovery` is on. `authzen_url` is always permitted |
| `resource_metadata_allowlist` | any | Permitted `resource` prefixes for metadata fetches |
| `pdp_discovery_insecure` | `false` | Allow http for discovered URLs; needs `allow_insecure` |
| `forward_access_token` | `false` | Send the raw token to the PDP as `context.access_token`; https only |
| `pdp_layers` | `["resource"]` | Ordered PDPs, every one of which must permit; ` fail-open` / ` fail-closed` per entry |
| `fail_mode` | `closed` | What a layer does when its PDP is unavailable, unless it says for itself |
| `coaz_defaults` | `true` | Govern every MCP method by the COAZ-MCP binding's default table; `false` keeps the old pass-through |
| `legacy_subject_identity` | `true` | Also send the non-standard `subject.identity` beside `subject.id` |
| `pdp_ssl_verify` | `true` | Certificate verification on every outbound call. Off trusts any chain but still checks the host name; needs `allow_insecure` |
| `user_token_jwks_url` | — | Verify `X-User-Token` against this JWKS (https). Unset, the token is ignored |
| `user_token_issuer` / `user_token_audience` | — | Expected `iss` / `aud`; the audience is required with the JWKS |
| `user_token_subject` | `principal` | Whose login counts: `principal`, only the access token's subject; `pdp`, another person's verified login too, for the PDP to judge from `user_sub` |
| `pdp_timeout_ms` / `coaz_timeout_ms` | `10000` / `15000` | Deadline on each call, the whole exchange included |
| `allow_insecure` | `false` | Development only: start with what the rule otherwise refuses, logging each relaxation |

The semantics are the Kong plugin's, knob for knob; its [README](../kong/README.md) has
the long form of each, and [docs/pingaccess-console.md](../../docs/pingaccess-console.md)
documents the same knobs as the console form: widgets, defaults, help text, what is
behind Show Advanced Settings, and how a bad value is reported.

The rule checks its configuration when it is saved, and refuses rather than warns.
Always refused: a URL that is not absolute http or https with a host (or, for an
identifier - `authzen_url`, `resource`, an allowlist entry, a layer - one with a query or
fragment), a JSON `null` for `style`, `pdp_discovery` or `fail_mode`, `style: mcp`
without `coaz_url`, and `require_dpop` without `coaz_url`, because this rule cannot
verify a DPoP proof signature itself and a thumbprint comparison proves nothing when the
proof carries the very JWK being compared. Refused unless `allow_insecure` is set:
`require_user_login` without a JWKS, a JWKS without an audience or over http, an API key
or a forwarded access token over http, `coaz_url` without `coaz_api_key`, discovery
without `pdp_allowlist`, `pdp_discovery_insecure`, and `pdp_ssl_verify` off.

## What PingAccess does, and what the rule does

**The access token.** When the application is protected (an access token validator, or
`accessValidatorId` 1 for the token provider), PingAccess validates the bearer token
before any rule runs: signature or introspection, expiry, audience. The rule then reads
what PingAccess established, from `Exchange.getIdentity()`: the validated attributes,
the subject, the client and scopes. Those win over the token's own payload, which is
also read when the token is a JWT, so `act`, `cnf` and `acr` are available whether
PingAccess exposes them or not. When the application is **unprotected**
(`accessValidatorId` 0) PingAccess establishes no identity and the token's claims are the
client's own word, so a request that carries a token is a 401 - unless `allow_insecure`
is set, which is how the demo runs its unsigned tokens. A route with `require_token` off
still lets a request with no token at all through to the PDP, as `unknown-agent`.

**DPoP.** PingAccess enforces DPoP natively when it validates the token (the
application's `dpopSettings`); that is the place for it. `require_dpop` is for the
unprotected case and for parity with Kong: the proof goes to `coaz-pep`'s
`/v1/dpop/verify`, which checks the JWS signature, `iat` freshness, `jti` replay and the
`cnf.jkt`/`htm`/`ath` binding, and anything that cannot be verified is denied.

**`X-User-Token`.** The one token PingAccess has no native way to validate, and the one
whose claims feed the step-up and login gates. It is verified against
`user_token_jwks_url` (ES/RS/PS families, `alg: none` refused), and it must carry `exp`,
`sub` and `user_token_audience`, and `iss` when `user_token_issuer` is set. A token that
fails yields no claims, so the gates close rather than open, and the log says why without
quoting the token. Without a JWKS the token is ignored; under `allow_insecure` it is
decoded instead, and `configure` says so. The key set is fetched through the rule's own
transport - a 3 second deadline, a 256 KiB cap - kept for five minutes unless the server
says otherwise, kept for fifteen more while a refresh fails, and refetched for an unknown
`kid` at most every 30 seconds.

A verified token still counts only as the principal's own login, by the same rules as
`coaz-pep`: it is not the access token presented a second time, it carries no `act` (an
agent's token is not a user having logged in), it has a `sub`, and that `sub` is the
principal's - the subject of the identity PingAccess established, or of the token under
`allow_insecure`. Someone else's genuine login is as much a bypass as a forged one:
customer B's consent must not approve customer A's payment. The one exception
is deliberate. On a route with `user_token_subject: pdp`, someone else's verified login
counts - a staff member approving for a customer - and the PDP decides whether that
person may approve for this principal. It can, because whenever a login counts the PDP
is told whose it is: `user_sub` and `user_iss`, beside `user_scope`, `user_acr`,
`token_aud` and the `authorization_details` with the consented amount and creditor,
exactly the context `coaz-pep` sends. On an MCP route the setting is passed to
`coaz-pep`, which reads the token itself.

**How a deny is written.** PingAccess's contract for a rule is that `Outcome.RETURN`
means "this rule rejects the request; call its error handling callback for the
response". The rule parks the verdict on the exchange and the callback renders it:
status, `WWW-Authenticate`, the JSON body and the `X-PDP-*` headers. Worth knowing if
you port another rule: setting a response and returning `RETURN` gets you the callback's
output, not yours.

**What a permit puts on the request.** Every `X-Auth-*` header the client sent is
removed first, in whatever case it was spelled, and then the ones the PEP asserts are
set: `X-Auth-Principal`, `X-Auth-Agent`, `X-Auth-Scope`, `X-Auth-Acr`. One it has no value
for stays off. A principal that could not be carried in a header intact - a character
past Latin-1, a control character - is refused rather than forwarded mangled. The
`X-PDP-*` headers go on the response, replacing any the upstream set. Every value built
from a PDP's or `coaz-pep`'s answer is cleaned for a header: no CR, no LF, nothing past
Latin-1, and quoted-string escaping inside `WWW-Authenticate`.

**Threads.** Every decision runs on a bounded pool of daemon workers that belongs to the
rule instance, so a slow PDP never holds one of the engine's I/O threads and one rule's
stuck dependency cannot starve another rule. Every outbound call has one deadline over
the whole exchange and a 1 MiB cap on the answer, so no worker is held past a timeout.
Saturation is a 503 deny, not a queue that grows without end;
`-Dauthzen.pdp.threads=N` sets the size per rule (64 by default). An error anywhere in
the pipeline is a 500 deny, never a request left hanging.

## MCP routes

On a route with `style: mcp` the rule decides nothing itself. It checks the token (and
DPoP, when required), then sends every request - whatever its method - to `coaz-pep`'s
`POST /v1/mcp/check` with the `authorization`, `x-user-token`, `dpop`, `content-type`
and `content-encoding` headers and the raw body, and enforces the answer: a permit is the
boolean `true` alone, its `upstream_headers` go on the request (an empty value means the
header stays off) and its `response_headers` on the response; a deny is `coaz-pep`'s
rendering relayed as it is, which for a `tools/call` is the COAZ JSON-RPC error at HTTP
200.

Before that, a body is judged only when it is exactly one JSON-RPC message the rule has
read in full and in one way. Anything else is refused here, and neither `coaz-pep` nor
the upstream sees it:

| What | HTTP | JSON-RPC error |
| --- | --- | --- |
| not JSON, invalid UTF-8, a BOM, anything after the value | 400 | `-32700` Parse error |
| a batch (an array), not an object, a member whose name matches another ignoring case, a case variant of a JSON-RPC member or of `params.name`, `arguments` or `uri`, a method that is not a string, a `tools/call` without a string `params.name` | 400 | `-32600` Invalid Request: ... |
| a body PingAccess could not hand over whole, or over 1 MiB | 413 | `-32600` Invalid Request: request body too large for the PEP to authorise |
| a `Content-Encoding` other than identity, on any of its values | 415 | `-32600` Invalid Request: Content-Encoding not supported by the PEP |

The body is `{"jsonrpc":"2.0","id":...,"error":{"code":...,"message":"..."}}` with the
request's `id` when it could be read, `Content-Type: application/json` and
`X-PDP-Decision: DENY`.

## PDP discovery

The same chain the Kong plugin walks, minus the federation branch, for the same reason:
a Trust Chain cannot be validated without the resolver in `coaz-pep`, and duplicating it
would guarantee drift.

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| `off` | nothing — static PDP, default paths, no fetch | — |
| `authzen` | `authzen_url`'s `/.well-known/authzen-configuration` | default paths, when the PDP publishes none (a 404) |
| `resource` | the route's resource's RFC 9728 document (`authzen_policy_decision_points`), then that PDP's metadata | `authzen_url` |

Whatever document named the PDP is forwarded verbatim as `context.resource_metadata`
(with `context.resource_metadata_source`), the endpoint hit as `context.request`, and
the raw token as `context.access_token` when the route sets `forward_access_token`. The
rule enforces none of it; see
[docs/architecture.md](../../docs/architecture.md#what-the-pep-forwards-and-what-it-does-not-decide).
A URL outside an allowlist never falls through to a weaker source, and a discovered PDP
never receives `authzen_api_key`. On mcp routes the layers and failure mode are passed
through to `coaz-pep`.

`pdp_layers` and `fail_mode` are the ordered layers and their failure modes. A PDP call
ends one of four ways: permit, deny, refusal, or unavailable. Only unavailable - a
connection or TLS failure, a timeout, a 5xx, a 429 - lets a fail-open layer be skipped,
and a permit that skipped one carries `X-PDP-Fail-Open` with the layer's identifier. A
refusal - a 3xx or another 4xx, an answer that is not a boolean decision, an answer over
the cap, a call that could not be made - is a 503 deny whatever the layer's mode, and is
logged as a refusal, so a rotated key or a client-padded request cannot switch a layer
off. Metadata is cached per identifier: while a refresh fails the last good entry is
served, and a PDP's metadata falls back to AuthZEN's default paths only when the PDP
publishes none, never because it could not be fetched.

`federation_entity_url` makes the route the resource's federation face: the two
well-known documents are relayed from `coaz-pep`, which holds the key and signs them.
PingAccess cannot sign, so it relays; everything else on the route is untouched.

## REST mapping

A request is mapped as the upstream will route it: path parameters (`;jsessionid=...`)
stripped from every segment, percent-decoding undone, empty and dot segments resolved.
Routes match whole segments at the end of the path, so a context root in front still
maps. A read (`list_accounts`, `get_balance`) is only ever a `GET` or `HEAD`, and a
`POST` that names `payments` anywhere in its path is judged as a payment. A payment must
carry a readable `from_account` and a finite amount, and a body that is not one JSON
object - read with the same strictness as an MCP body - is a 400. So is a path that could
route more than one way: an encoded slash or backslash, a control character, a bad
escape.

## Tests

```sh
cd gateways/pingaccess/authzen-pdp && mvn verify
```

JUnit 5 against a scripted transport and a mocked `Exchange`: no PingAccess, no PDP, no
network except loopback servers for the real transport, the JWKS and a TLS peer. The
suites are the Kong specs ported case for case (the request mapping both gateways must
agree on, the decision paths, DPoP and COAZ delegation, the challenge shapes, discovery,
layers and failing open), plus what is PingAccess's alone: the identity merge, the
exchange plumbing, the error callback, the worker pool. `ReviewProbesTest` is the 0.4.0
review's probes, one per finding, each of which failed against 0.3.

JaCoCo enforces a coverage ratchet in [`pom.xml`](authzen-pdp/pom.xml), a floor set just
under the current number. One class is excluded, because it needs a running PingAccess
rather than because it is hard: `PaResponses`, which builds a response through the SDK's
`ResponseBuilder` (its implementation is registered by the engine at boot). Every deny
the demo shows is written by it. The trust-all TLS client behind `pdp_ssl_verify=false`
is not excluded: the suite runs it against a loopback TLS server with a self-signed
certificate, and checks that the host name is still verified.

## The demo

```sh
cd demo
printf 'PING_IDENTITY_DEVOPS_USER=...\nPING_IDENTITY_DEVOPS_KEY=...\n' > .env   # git-ignored
docker compose --profile pingaccess up --build -d && ./demo.sh
```

The `pingaccess` profile builds the rule inside a PingAccess image (taking the SDK from
the image itself), and a hook configures the running server over its admin API: a site
for the `plain` resource stub, the rule with resource discovery, and an API application
on `*:3000`. The demo's tokens are unsigned, its application is unprotected and its
stubs speak plain http, so the rule is configured with `allow_insecure` - the one place
it belongs. `demo.sh` notices it and adds a section; the same three requests it sends
Kong come back with the same answers and the same challenges. The admin console is at
`https://localhost:9443` (administrator / 2FederateM0re), and the requests themselves
are plain:

```sh
curl -sk -H "Authorization: Bearer $JWT" https://localhost:3000/accounts/a1/balance
```

The image pulls an evaluation licence with the DevOps credentials; without them it stops
at boot and says so. That is also why the single-container Railway image does not
include PingAccess.

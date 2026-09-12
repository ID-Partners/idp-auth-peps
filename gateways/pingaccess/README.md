# `authzen-pdp` — PingAccess rule

A Policy Enforcement Point for PingAccess, as an Add-on SDK rule: the PingAccess
counterpart of the [Kong plugin](../kong), sending the PDP the same AuthZEN evaluation
request and rendering the same challenges, so a client cannot tell from the deny which
gateway said no. Token and actor-claim extraction (RFC 8693), RFC 9470 step-up
challenges, REST and MCP request mapping, RFC 9728 and AuthZEN metadata discovery, and
policy layers are native Java in [`authzen-pdp/`](authzen-pdp); DPoP verification and
per-tool-call COAZ authorisation are delegated to `coaz-pep`, exactly as Kong does.

Two things it does natively that a Kong plugin cannot: it reads the identity PingAccess
itself validated, and it verifies `X-User-Token` (jose4j is on PingAccess's classpath).

Not to be confused with PingAccess's built-in *PingAuthorize Policy Decision Access
Control* and *PingAuthorize Access Control* rules. Those speak PingAuthorize's own
sideband and policy-decision APIs to PingAuthorize alone. This one speaks AuthZEN 1.0
to any conformant PDP, discovers which PDP decides for a resource, and returns
resolvable challenges.

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
from the SDK, Jackson, jose4j or slf4j is bundled, PingAccess supplies them all. Built
for Java 17 bytecode, so it loads on PingAccess 8.x (Java 17) and 9.x (Java 21).

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
    "user_token_jwks_url": "https://as.bank.example/jwks"
  }
}'
```

Then `POST /applications` with `"policy": {"API": [{"type": "Rule", "id": <rule id>}]}`.
[`demo/pingaccess/hooks/81-after-start-process.sh`](../../demo/pingaccess/hooks/81-after-start-process.sh)
is the whole sequence, site and application included, as a script.

| Knob | Default | Meaning |
| --- | --- | --- |
| `authzen_url` | required | The static PDP: always the fallback, always permitted |
| `authzen_api_key` | — | Bearer key for `authzen_url`. A discovered PDP never receives it |
| `pep_label` | `pingaccess-pep` | Names this PEP in challenges and the `X-PDP-PEP` header |
| `style` | `rest` | `rest` (resource server) or `mcp` (MCP edge) |
| `require_token` | `true` | Deny without a readable access token |
| `require_dpop` | `false` | Delegate the RFC 9449 sender-constraint check to `coaz-pep`; needs `coaz_url` |
| `require_user_login` | `false` | Deny without a valid `X-User-Token`, with a login challenge |
| `stepup_scope` | — | Scope named in a step-up challenge when the PDP's advice names none |
| `coaz_url` / `coaz_api_key` | — | `coaz-pep`'s HTTP check API and its `CHECK_API_TOKEN` |
| `mcp_upstream_url` | — | Where `tools/list` lives; with `coaz_url`, enables per-tool-call COAZ on mcp routes |
| `federation_entity_url` | — | Relay the resource's two well-known documents from `coaz-pep` at this URL |
| `pdp_discovery` | `off` | `off`, `authzen` or `resource`; see [PDP discovery](#pdp-discovery) |
| `resource` | — | The protected resource's identifier (RFC 8707), the key discovery starts from |
| `pdp_metadata_ttl` | `300` | Cache TTL, seconds, for resource and PDP metadata |
| `pdp_allowlist` | any https | Permitted discovered-PDP prefixes; `authzen_url` is always permitted |
| `resource_metadata_allowlist` | any | Permitted `resource` prefixes for metadata fetches |
| `pdp_discovery_insecure` | `false` | Allow http for discovered URLs (dev only) |
| `forward_access_token` | `false` | Send the raw token to the PDP as `context.access_token` |
| `pdp_layers` | `["resource"]` | Ordered PDPs, every one of which must permit; ` fail-open` / ` fail-closed` per entry |
| `fail_mode` | `closed` | What a layer does when its PDP cannot be reached, unless it says for itself |
| `coaz_defaults` | `false` | Apply the COAZ-MCP binding's default mappings to undeclared tools |
| `legacy_subject_identity` | `true` | Also send the non-standard `subject.identity` beside `subject.id` |
| `pdp_ssl_verify` | `true` | TLS verification on every outbound call. Off is process-wide for JDK clients built afterwards: dev only |
| `user_token_jwks_url` | — | Verify `X-User-Token` against this JWKS; unset, it is decoded only and `configure` warns |
| `user_token_issuer` / `user_token_audience` | — | Expected `iss` / `aud` when verifying |
| `pdp_timeout_ms` / `coaz_timeout_ms` | `10000` / `15000` | Call timeouts |

The semantics are the Kong plugin's, knob for knob; its [README](../kong/README.md) has
the long form of each. The validation is the same too: `require_dpop` without `coaz_url`
is refused at configuration time, because this rule cannot verify a DPoP proof
signature itself and a thumbprint comparison proves nothing when the proof carries the
very JWK being compared.

## What PingAccess does, and what the rule does

**The access token.** When the application is protected (an access token validator, or
`accessValidatorId` 1 for the token provider), PingAccess validates the bearer token
before any rule runs: signature or introspection, expiry, audience. The rule then reads
what PingAccess established, from `Exchange.getIdentity()`: the validated attributes,
the subject, the client and scopes. Those win over the token's own payload, which is
also read when the token is a JWT, so `act`, `cnf` and `acr` are available whether
PingAccess exposes them or not. When the application is **unprotected**
(`accessValidatorId` 0, what the demo uses because its tokens are unsigned) there is only
the payload, decoded and not verified, with the same caveat the Kong plugin carries: the
authorization decision is still the PDP's, but the claims it is given are the client's
word.

**DPoP.** PingAccess enforces DPoP natively when it validates the token (the
application's `dpopSettings`); that is the place for it. `require_dpop` is for the
unprotected case and for parity with Kong: the proof goes to `coaz-pep`'s
`/v1/dpop/verify`, which checks the JWS signature, `iat` freshness, `jti` replay and the
`cnf.jkt`/`htm`/`ath` binding, and anything that cannot be verified is denied.

**`X-User-Token`.** The one token PingAccess has no native way to validate, and the one
whose claims feed the step-up and login gates. With `user_token_jwks_url` set it is
verified (ES/RS/PS families, `exp`, `nbf`, `iss`, `aud`; `alg: none` refused) and a token
that fails yields no claims, so the gates close rather than open. Unset, it is decoded,
and `configure` logs a warning per rule instance.

**How a deny is written.** PingAccess's contract for a rule is that `Outcome.RETURN`
means "this rule rejects the request; call its error handling callback for the
response". The rule parks the verdict on the exchange and the callback renders it:
status, `WWW-Authenticate`, the JSON body and the `X-PDP-*` headers. Worth knowing if
you port another rule: setting a response and returning `RETURN` gets you the callback's
output, not yours. On a permit the `X-Auth-*` headers go on the request and `X-PDP-*` on
the response.

**Threads.** Every decision runs on the rule's own bounded pool of daemon workers, so a
slow PDP never holds one of the engine's I/O threads. Saturation is a 503 deny, not a
queue that grows without end; `-Dauthzen.pdp.threads=N` sets the size (64 by default).

## PDP discovery

The same chain the Kong plugin walks, minus the federation branch, for the same reason:
a Trust Chain cannot be validated without the resolver in `coaz-pep`, and duplicating it
would guarantee drift.

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| `off` | nothing — static PDP, default paths, no fetch | — |
| `authzen` | `authzen_url`'s `/.well-known/authzen-configuration` | default paths |
| `resource` | the route's resource's RFC 9728 document (`authzen_policy_decision_points`), then that PDP's metadata | `authzen_url` |

Whatever document named the PDP is forwarded verbatim as `context.resource_metadata`
(with `context.resource_metadata_source`), the endpoint hit as `context.request`, and
the raw token as `context.access_token` when the route sets `forward_access_token`. The
rule enforces none of it; see
[docs/architecture.md](../../docs/architecture.md#what-the-pep-forwards-and-what-it-does-not-decide).
`pdp_layers` and `fail_mode` are the ordered layers and their failure modes; a permit
that skipped a fail-open layer carries `X-PDP-Fail-Open`. A URL outside an allowlist
never falls through to a weaker source, and a discovered PDP never receives
`authzen_api_key`. On mcp routes both settings are passed through to `coaz-pep`.

`federation_entity_url` makes the route the resource's federation face: the two
well-known documents are relayed from `coaz-pep`, which holds the key and signs them.
PingAccess cannot sign, so it relays; everything else on the route is untouched.

## Tests

```sh
cd gateways/pingaccess/authzen-pdp && mvn verify
```

JUnit 5 against a scripted transport and a mocked `Exchange`: no PingAccess, no PDP, no
network except a loopback server for the real transport and the JWKS. The suites are
the Kong specs ported case for case (the request mapping both gateways must agree on,
the decision paths, DPoP and COAZ delegation, the challenge shapes, discovery, layers
and failing open), plus what is PingAccess's alone: the identity merge, the exchange
plumbing, the error callback, the worker pool.

JaCoCo enforces a coverage ratchet in [`pom.xml`](authzen-pdp/pom.xml), a floor set just
under the current number. Two classes are excluded, each because it needs a running
PingAccess or a TLS peer rather than because it is hard: `PaResponses`, which builds a
response through the SDK's `ResponseBuilder` (its implementation is registered by the
engine at boot), and the trust-all TLS context behind `pdp_ssl_verify=false`. Both are
exercised by the live run below.

## The demo

```sh
cd demo
printf 'PING_IDENTITY_DEVOPS_USER=...\nPING_IDENTITY_DEVOPS_KEY=...\n' > .env   # git-ignored
docker compose --profile pingaccess up --build -d && ./demo.sh
```

The `pingaccess` profile builds the rule inside a PingAccess image (taking the SDK from
the image itself), and a hook configures the running server over its admin API: a site
for the `plain` resource stub, the rule with resource discovery, and an API application
on `*:3000`. `demo.sh` notices it and adds a section; the same three requests it sends
Kong come back with the same answers and the same challenges. The admin console is at
`https://localhost:9443` (administrator / 2FederateM0re), and the requests themselves
are plain:

```sh
curl -sk -H "Authorization: Bearer $JWT" https://localhost:3000/accounts/a1/balance
```

The image pulls an evaluation licence with the DevOps credentials; without them it stops
at boot and says so. That is also why the single-container Railway image does not
include PingAccess.

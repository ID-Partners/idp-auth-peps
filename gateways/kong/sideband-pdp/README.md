# `sideband-pdp` — Kong Gateway plugin for PingAuthorize's Sideband API

A Policy Enforcement Point for Kong that authorises every request through PingAuthorize's
**Sideband API** and finds the PDPs it calls from the resource it protects. The resource's
RFC 9728 metadata names its PDP and the layers to run in front of it, or — with the switch —
a federation resolve endpoint says what the federation resolved for it. Every layer must
permit, each under its own failure rule, and what a denied client gets is the HTTP the
policy wrote.

It is the sibling of [`authzen-pdp`](../README.md): the same discovery module, the same
layers and the same failure rules, in front of a different PDP protocol. Where `authzen-pdp`
maps a request to an AuthZEN evaluation and renders the PDP's advice as a challenge, this
plugin ships the whole HTTP request to PingAuthorize and applies whatever comes back.

## Where it came from

The sideband half is Ping's [`kong-plugin-ping-auth`](https://github.com/pingidentity/kong-plugin-ping-auth),
by way of the ID Partners fork, and its seven configuration fields keep their names and
defaults, so a `ping-auth` route ports over by changing the plugin name. What changed:

- **Discovery.** `service_url` was the only PDP; it is now the static one, for a
  resource that publishes nothing, and the one the configured secret is bound to. The PDPs actually asked come from the
  resource's metadata or the federation's resolver, in layers.
- **One request, several PDPs.** The request and response walks are generalised to an
  ordered list, each layer seeing the request as the previous one rewrote it, each with
  its own rule for when it cannot be reached.
- **The request PingAuthorize judges is the one Kong forwards.** Ping's plugin built the URL
  from `X-Forwarded-*`, which Kong reads for any client in `trusted_ips`, and sent a body
  past `client_body_buffer_size` as nothing. See [below](#what-pingauthorize-is-sent).
- **Failures are this repository's.** A PDP that cannot be reached is a 503 with the
  `authorization_failed` body `authzen-pdp` sends, not Ping's bare 502, so a client sees
  one shape from every PEP here. A PDP that answers and refuses is never skipped.
- **No globals.** Ping's plugin kept its modules in `_G`, which a second plugin in the same
  worker would clobber. Everything here is a local.
- **HTTP/2 is refused only where it has to be.** Ping's plugin answered every HTTP/2 client
  with a 400. Kong 3.9 and later buffer an HTTP/2 response like any other, so the response
  phase runs and the request is served; before 3.9, on a route that filters responses, it
  is refused. See [below](#responses-kong-would-not-show-it).

The client certificate goes exactly as Ping sent it: the certificate's public key as a JWK,
the certificate in `x5c`, under `client_certificate`.

## Install

DB-less: mount **both** plugin directories and enable this one. The discovery and contract
modules are `authzen-pdp`'s, required by name, so that directory must be on the package
path whether or not `authzen-pdp` itself is enabled.

```
# kong.conf / environment
KONG_PLUGINS=bundled,sideband-pdp
KONG_LUA_PACKAGE_PATH=/opt/?.lua;;
```

```yaml
volumes:
  - ../gateways/kong/authzen-pdp:/opt/kong/plugins/authzen-pdp:ro     # discovery.lua, contract.lua
  - ../gateways/kong/sideband-pdp:/opt/kong/plugins/sideband-pdp:ro
```

Or install the rocks from the `v0.4.1` release, authzen-pdp's first:
`luarocks install kong-plugin-authzen-pdp-0.4.1-1.all.rock`, then
`kong-plugin-sideband-pdp-0.4.1-1.all.rock`. This one depends on
`kong-plugin-authzen-pdp` 0.4.1, which brings the shared modules; neither rock ships the
other's. Kong Gateway 3.4 or later, 3.9 or later recommended — see
[Kong versions](../README.md#kong-versions).

## Configure

```yaml
plugins:
  - name: sideband-pdp
    route: bank-api
    config:
      service_url:        "{vault://env/paz-url}"          # PingAuthorize, no /sideband in the path; the static PDP
      shared_secret:      "{vault://env/paz-secret}"       # bound to service_url alone
      secret_header_name: CLIENT-TOKEN
      pep_label: "PEP#2 (Bank API edge)"
      pdp_discovery: resource
      resource: https://api.bank.example                    # RFC 8707 identifier; discovery starts here
      pdp_allowlist: ["https://pdp.bank.example", "https://pdp.estate.example"]   # required with discovery on
      resource_metadata_allowlist: ["https://api.bank.example"]
      pdp_credentials:                                      # what a discovered PDP is called with
        - pdp: https://pdp.bank.example/tenants/bank
          shared_secret: "{vault://env/bank-pdp-secret}"
        - pdp: https://pdp.estate.example
          shared_secret: "{vault://env/estate-pdp-secret}"
          secret_header_name: X-Estate-Token
      pdp_layers: ["resource"]                              # the default: what the resource publishes, then its own PDP
      fail_mode: closed
```

The switch, on a route whose resource is a federation member:

```yaml
      pdp_discovery: federation-resolver
      federation_resolve_url: https://anchor.bank-federation.example/resolve
      federation_trust_anchor: https://anchor.bank-federation.example
```

`service_url`, `shared_secret` and every `pdp_credentials[].shared_secret` are
`referenceable`, so they take Kong vault references rather than literals, and the secrets
are `encrypted` where Kong has a keyring.

## How a request flows

1. **Which PDPs.** `pdp_layers` is resolved into an ordered list — configured entries, the
   layers the resource's document publishes, the resource's own PDP — duplicates collapsed,
   each with its rule.
2. **`POST {pdp}/sideband/request`, per layer, in order.** The payload is the whole HTTP
   request as Kong will forward it: source address, method, URL, version, headers, body,
   client certificate. Back comes either the request to forward — possibly rewritten, with
   a `state` — or, under `response`, the HTTP response to send instead. The next layer sees
   the request as this one rewrote it.
3. **The first response is the answer.** It goes to the client verbatim: status, headers,
   body. Nothing is added but the `X-PDP-*` headers.
4. **Permitted: the request goes upstream** as the layers rewrote it — headers added,
   changed and removed, a new method, path, query or body applied. `Accept-Encoding` is
   dropped so the response phase reads a body the policy provider can read.
5. **`POST {pdp}/sideband/response`, in reverse order**, skipping `request-only` layers:
   the upstream's status, headers and body, correlated by each layer's `state`. Back
   comes the response to send; the last layer's answer is what the client gets, and a
   header the policy provider left out is gone.

The plugin decides nothing. It does not map the request to an action, and it does not
shape a challenge. That is the sideband contract: the PDP's policy turns the HTTP request
into a policy request, and on a deny it writes the HTTP response — so the
`WWW-Authenticate` an agent needs to resolve a step-up is the policy's to write, and the
[challenge contract](../../../docs/architecture.md) the other PEPs render in code is, on
this route, a contract the policy honours. Whether that is better than the gateway
knowing the resource's URLs is the trade this plugin makes: `authzen-pdp`'s request mapping
is a table of one API's paths; this plugin has no such table.

**REST routes only.** A plugin with a response phase makes Kong buffer the whole upstream
response on every route it is on, `filter_response` on or off. That is incompatible with
SSE, so an MCP route belongs behind `authzen-pdp` and `coaz-pep`.

## What PingAuthorize is sent

It has to be the request Kong forwards, or the policy judges one request and the upstream
runs another:

- **The URL is the one Kong routed on** — its scheme, the `Host`, its own port, and the
  normalised path its router matched (`kong.request.get_path`), escaped for the wire — and
  the query, normalised through `decode_args`/`encode_args` as Ping did. Never
  `X-Forwarded-*`: Kong honours those from any client in `trusted_ips`, and a client there
  could have `DELETE /admin/users/1` judged as `/public/status`. The path is the one the
  client asked for, route prefix included, as Ping's plugin sent it; PingAuthorize's API
  endpoints are configured against the public paths.
- **The body is read whole**, up to `max_request_body_size` (1 MiB by default), or the
  request is refused with a 413. Kong keeps a body past `client_body_buffer_size` on disk;
  3.9 and later read it back, and before 3.9 such a request is refused.
- **Every header and query argument is sent**, up to 1,000 of each, or the request is
  refused (431 for headers, 414 for arguments). Ping's plugin read the first hundred and
  dropped the rest.
- **A client's `X-Auth-Principal`, `X-Auth-Agent`, `X-Auth-Scope` and `X-Auth-Acr` are not
  sent**, and are removed from the request to the upstream: those are what a PEP asserts.
  A layer's rewrite may add them.

A permit must have the permit's shape — the request echoed, `method` and `url` as strings,
`headers` a list of single-pair objects, `body` a string when present. A 2xx `{}` used to
permit. Anything that is neither that nor a relayable `response` is a refusal.

## Responses Kong would not show it

Kong runs a plugin's response phase only under buffered proxying, and turns buffering off
for a websocket upgrade on every release, and for HTTP/2 before 3.9. The upstream's
response would then go to the client with no `/sideband/response` call — unfiltered — and
no `X-PDP-*` markers. So where any layer filters responses (`filter_response` on and a layer
that is not `request-only`), an `Upgrade` request, and before Kong 3.9 an HTTP/2 one, is
refused with a 400 before any PDP is asked. A route that filters nothing lets them through.

Every permit is marked in the access phase, so a permit is marked whether or not the
response phase runs — a fail-open permit with `filter_response: false` included, which used
to go out unmarked.

## A failure after the upstream ran

The response phase runs after the upstream has done what it was asked. A layer that cannot
be reached there under a closed rule, or that refuses, cannot undo the request — so the
plugin withholds what came back: it clears every upstream header (a `Set-Cookie`, a
`Location`, the lot) and answers **502**, saying the upstream processed the request and its
response could not be authorised. It used to answer 503 "unreachable", which invites a
retry of a request that may not be safe to repeat, and left the upstream's headers on the
way out. A 429 there is the same 502.

An upstream response larger than `max_response_body_size` (1 MiB by default) is withheld
the same way rather than re-sent to the policy provider. Kong has buffered it whole by
then; the limit bounds what the plugin sends on.

## PDP discovery

By default the plugin is told where PingAuthorize is (`service_url`). `pdp_discovery`
replaces that with metadata — the chain the Go PEP and `authzen-pdp` walk, minus the
metadata probe, because a sideband endpoint has none: a PDP identifier is the base its
`/sideband/request` and `/sideband/response` hang off.

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| `off` | nothing — `service_url`, no fetch | — |
| `resource` | the resource's RFC 9728 document: `authzen_policy_decision_points` and `authzen_policy_layers` | `service_url`, when the resource publishes nothing (a 404) |
| `federation-resolver` | the resource's **resolved** `oauth_resource` metadata, from a federation resolve endpoint | `service_url`, when the resolver does not know the resource — never the resource's own document |

`pdp_allowlist` is required whenever discovery is on; an empty one used to mean any https
PDP a resource, or the federation, named. A document that cannot be fetched serves the last
good one; with none cached, the `resource` layer is unavailable and its rule decides — it no
longer falls to `service_url`, which quietly dropped whatever the resource put in front of
its own PDP.

The two parameters are the ones this repository mints for every PEP, byte for byte
(see [`core/README.md`](../../../core/README.md#pdp-discovery)):
`authzen_policy_decision_points` names the PDP that decides for the resource (candidates for
one decision, the first this route may call wins), and `authzen_policy_layers` names the
PDPs to ask in front of it, every one of which must permit. Whether the same PingAuthorize
answers AuthZEN there and sideband here is the deployment's business; the identifier is
the PDP, the plugin chooses the protocol it speaks to it.

A published layer takes the `resource` entry's failure rule — a document may say who
decides, not what happens when they cannot — and passes the same `pdp_allowlist` as a
configured entry. A configured entry and a published one naming the same PDP are one call,
and the configured entry's own rule wins. A document whose layers cannot be read is
invalid, and `service_url` decides. The rules are `coaz-pep`'s; see
[Layers the resource publishes](../../../docs/architecture.md#layers-the-resource-publishes).

### The switch: resolving through the federation

`pdp_discovery: federation-resolver` asks a federation resolve endpoint (OpenID Federation
1.0 §8.3, usually the trust anchor's) for the resource's Resolved Metadata:

```
GET {federation_resolve_url}?sub={resource}&anchor={federation_trust_anchor}
Accept: application/resolve-response+jwt
```

and reads the two parameters out of `metadata.oauth_resource` in the answer — what
survived every superior's `metadata_policy`, which is how an anchor puts its estate PDP in
front of every member's and a member cannot take it out. The resource's own document is
never read in this mode.

What that is, and is not: **the resolver's word, taken on transport.** The resolve
response is a JWT this plugin cannot verify — there is no JOSE verifier available to a Kong
plugin — so it is decoded, not verified. The plugin checks what it can: the response's
`typ` is `resolve-response+jwt`, its `sub` is the resource asked about, and it has not
expired. The trust is TLS to a URL the operator configured, exactly the trust placed in
`service_url` — so the resolve URL must be https, and TLS verification on, unless
`allow_insecure` says otherwise.

That is a weaker claim than `coaz-pep`'s federation mode, which walks the chain and verifies
every signature to an anchor key it holds, and the mode is named apart for that reason.
It was `federation`, and so was the source it reported, which is the word `coaz-pep` uses
for a chain it verified. It is now `federation-resolver` — the mode, `X-PDP-Source`, and the
`context.resource_metadata_source` a PDP is sent — and the old name is refused rather than
kept as an alias. A route that needs the stronger claim belongs behind `coaz-pep`.

The resolver's errors (§8.9) mean what they would to the Go PEP:

| The resolver says | Discovery does |
| --- | --- |
| `not_found`, or 404 | no metadata — `service_url` decides, as for a resource outside the federation |
| `invalid_trust_chain`, `invalid_metadata`, `invalid_subject`, `invalid_trust_anchor`, `invalid_request`, any other 4xx | a **refusal** — the request fails, whatever the failure rule says, and a cached answer is dropped: revocation at the anchor reaches a running gateway |
| `server_error`, `temporarily_unavailable`, 5xx, unreachable | transient — the cached answer while there is one and it has not expired, then the layer's rule |

A resolved answer is cached for `pdp_metadata_ttl` but never served past its own `exp`. A
resolve response that is not a JWS, has the wrong `typ`, has expired, or lists something
that is not a PDP identifier is an invalid document: logged, not used, `service_url` decides.

## Layers and their rules

`pdp_layers` is the ordered list of PDPs to ask, every one of which must permit; the first
that does not is the answer. Default `["resource"]`. Each entry is a name and its rules:

```
<static | resource | PDP identifier> [fail-open | fail-closed] [request-only]
```

- `static` is `service_url`, asked regardless of discovery — the slot for an estate PDP
  that judges the token and the client. `resource` is what discovery finds, behind what
  the document publishes. A PDP identifier is a PDP.
- `fail-open` / `fail-closed` is what the layer does when its PDP is **unavailable** — no
  answer, a 5xx, a 429. Closed denies the request with a 503 (a 429 with the PDP's
  `Retry-After`, when that is what it said). Open skips the layer, names it in
  `X-PDP-Fail-Open`, and lets the rest decide; if every layer was skipped the request is
  permitted, marked. `fail_mode` is the route's default for entries that say nothing.
- A 429 answers the request that received it and no other. The plugin used to block the
  PDP for the whole worker until `Retry-After` had passed, which let one client's burst
  deny everyone.
- `request-only` skips the layer's `/sideband/response` call. An estate PDP that judges
  the token has nothing to say about the response, and a PingAuthorize endpoint with no
  response-phase policy would otherwise be a failure in that phase.
- A **deny is a decision, not a failure**, and never opens. A **refusal** fails the
  request whatever the rule says: a 3xx or 4xx from the Sideband API (a 413 aside, which is
  relayed as the answer about this request), an answer the plugin cannot read or apply, a
  payload it could not encode, a PDP outside `pdp_allowlist`, an invalid chain, a rule it
  cannot read. Fail-open is about availability, and a refusal is not an outage.

```yaml
pdp_layers: ["static fail-open request-only", "resource"]
fail_mode: closed
```

asks `service_url` first as a request-only gate the route can live without, then whatever
the resource publishes and names, each of which must be reached and must permit.

## Credentials

PingAuthorize refuses a sideband call without its shared secret, and which secret is a
fact about which PDP. `shared_secret` is bound to `service_url` and goes nowhere else; a
discovered or configured PDP is called with the `pdp_credentials` entry whose `pdp` is its
identifier, or with nothing. Called with nothing, PingAuthorize answers 401 — a refusal,
closed whatever the layer's rule (it used to be skipped by a fail-open layer), and logged
with a hint that the secret is probably missing. A resource that names a PDP this gateway
holds no secret for is a resource this gateway cannot serve, and says so.
`secret_header_name` in an entry defaults to the top-level one.

PingAuthorize ships a self-signed certificate. Trust it — or the CA that issued yours —
in Kong's trust store; do not turn `verify_service_certificate` off:

```
KONG_LUA_SSL_TRUSTED_CERTIFICATE=system,/etc/kong/pingauthorize.pem
```

## What comes back on the response

| Header | Meaning |
| --- | --- |
| `X-PDP-PEP` | `pep_label` |
| `X-PDP-Decision` | `PERMIT` or `DENY` |
| `X-PDP-Layers` | the PDPs that permitted, in order |
| `X-PDP-Layer` | on a deny, the PDP whose answer it was |
| `X-PDP-Source` | where the resource's PDP came from: `static`, `rfc9728` or `federation-resolver` |
| `X-PDP-Fail-Open` | the layers that were skipped — their identifiers; why is in Kong's log |

They ride on every response the plugin sends, and on every permit from the access phase.
Kong will not load a plugin that has both a response phase and a header filter, so they are
set on the exits and in access rather than in a later phase. Every value, and every header
a policy's response carries to the client, is reduced to printable ASCII with a line break
becoming a space. The plugin's own denials give generic reasons; the detail is logged.

## `allow_insecure`

Missing security settings are configuration errors: discovery on without `pdp_allowlist`,
`pdp_discovery_insecure: true`, `verify_service_certificate: false`, or the resolver switch
over plain http. `allow_insecure: true` is the one way past them, for development and
demos, and Kong logs what it relaxes, per route, when the configuration loads.

## What it does not do

- **Shape a challenge.** A deny is the policy's HTTP. If the policy answers a flat 403, the
  client gets a flat 403.
- **Verify a token, a DPoP proof, or a chain.** No JOSE. The token reaches PingAuthorize
  in the `authorization` header, where policy can validate it; DPoP and COAZ are what
  `authzen-pdp` delegates to `coaz-pep`, and an MCP route belongs there.
- **Read `signed_metadata`** in an RFC 9728 document; the Go PEP does.
- **Serve the resource's federation face.** `authzen-pdp`'s `federation_entity_url` relays
  the two well-known documents from `coaz-pep`; put that plugin on the route for them.

It runs at priority 999, after Kong's authentication plugins and before `ip-restriction`,
`acl` and `rate-limiting`; see [plugin order](../README.md#plugin-order).

## Upgrading from 0.1

- **`pdp_discovery: federation` is now `federation-resolver`**, and `X-PDP-Source` and
  `context.resource_metadata_source` say so. The old name is refused.
- **Discovery needs `pdp_allowlist`**; `pdp_discovery_insecure`, `verify_service_certificate:
  false` and an http resolver need `allow_insecure`.
- **A 401 or 403 from PingAuthorize is a refusal**, closed even on a fail-open layer, and a
  429 no longer blocks the PDP for the worker.
- **The URL sent is the one Kong routed on**, not `X-Forwarded-*`. A policy written against
  a load balancer's forwarded host or path sees Kong's instead.
- **Oversized bodies, over 1,000 headers or 1,000 query arguments, and HTTP/2 or `Upgrade`
  on a filtering route before Kong 3.9 (`Upgrade` on any release)** are refused rather than
  judged in part or filtered not at all.
- **A response-phase failure is a 502 with the upstream's headers withheld**, not a 503.
- **The rock is `kong-plugin-sideband-pdp-0.4.1-1`**, and it depends on
  `kong-plugin-authzen-pdp` 0.4.1 instead of shipping the discovery module itself.

## Tests

```sh
cd gateways/kong
busted --lpath="./?.lua;./?/init.lua" spec/
```

`spec/sideband-pdp_spec.lua` runs against the mocked Kong in `spec/mock_kong.lua` — no
gateway, no PingAuthorize, no network: what the policy provider is sent, how a permit's
rewrites and a deny's response are applied, the layer walk under each rule, the response
phase and when Kong would skip it, and discovery through both phases including the
resolver switch. The discovery rules themselves are covered in `spec/discovery_spec.lua`,
alongside `authzen-pdp`'s.

For a run through real Kong, mount both plugin directories into `kong:3.9` DB-less with a
route on a stub that answers `/.well-known/oauth-protected-resource` and
`/sideband/request` — the response headers above say what happened. `curl --http2` needs
Kong's TLS listener (`KONG_PROXY_LISTEN="0.0.0.0:8000, 0.0.0.0:8443 http2 ssl"`).

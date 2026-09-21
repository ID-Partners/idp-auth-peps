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

- **Discovery.** `service_url` was the only PDP; it is now the static one, the fallback,
  and the one the configured secret is bound to. The PDPs actually asked come from the
  resource's metadata or the federation, in layers.
- **One request, several PDPs.** The request and response walks are generalised to an
  ordered list, each layer seeing the request as the previous one rewrote it, each with
  its own rule for when it cannot be reached.
- **Failures are this repository's.** A PDP that cannot be reached is a 503 with the
  `authorization_failed` body `authzen-pdp` sends, not Ping's bare 502, so a client sees
  one shape from every PEP here. A 429 from a PDP backs that PDP off for its
  `Retry-After`, per PDP, where Ping's plugin tripped one circuit for its single PDP.
- **No globals.** Ping's plugin kept its modules in `_G`, which a second plugin in the same
  worker would clobber. Everything here is a local.
- **HTTP/2 clients are not refused.** Ping's plugin answered them with a 400;
  `http_version` is sent as the client spoke it.

The client certificate goes exactly as Ping sent it: the certificate's public key as a JWK,
the certificate in `x5c`, under `client_certificate`.

## Install

DB-less: mount **both** plugin directories and enable this one. The discovery module is
`authzen-pdp`'s, required by name, so that directory must be on the package path whether or
not `authzen-pdp` itself is enabled.

```
# kong.conf / environment
KONG_PLUGINS=bundled,sideband-pdp
KONG_LUA_PACKAGE_PATH=/opt/?.lua;;
```

```yaml
volumes:
  - ../gateways/kong/authzen-pdp:/opt/kong/plugins/authzen-pdp:ro     # for discovery.lua
  - ../gateways/kong/sideband-pdp:/opt/kong/plugins/sideband-pdp:ro
```

Or build the rockspec, which lists the shared module.

## Configure

```yaml
plugins:
  - name: sideband-pdp
    route: bank-api
    config:
      service_url:        "{vault://env/paz-url}"          # PingAuthorize, no /sideband in the path; the fallback
      shared_secret:      "{vault://env/paz-secret}"       # bound to service_url alone
      secret_header_name: CLIENT-TOKEN
      pep_label: "PEP#2 (Bank API edge)"
      pdp_discovery: resource
      resource: https://api.bank.example                    # RFC 8707 identifier; discovery starts here
      pdp_allowlist: ["https://pdp.bank.example", "https://pdp.estate.example"]
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
      pdp_discovery: federation
      federation_resolve_url: https://anchor.bank-federation.example/resolve
      federation_trust_anchor: https://anchor.bank-federation.example
```

`service_url`, `shared_secret` and every `pdp_credentials[].shared_secret` are `referenceable`,
so they take Kong vault references rather than literals.

## How a request flows

1. **Which PDPs.** `pdp_layers` is resolved into an ordered list — configured entries, the
   layers the resource's document publishes, the resource's own PDP — duplicates collapsed,
   each with its rule.
2. **`POST {pdp}/sideband/request`, per layer, in order.** The payload is the whole HTTP
   request: source address, method, URL, version, headers, body, client certificate. Back
   comes either the request to forward — possibly rewritten, with a `state` — or, under
   `response`, the HTTP response to send instead. The next layer sees the request as this
   one rewrote it.
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

## PDP discovery

By default the plugin is told where PingAuthorize is (`service_url`). `pdp_discovery`
replaces that with metadata — the chain the Go PEP and `authzen-pdp` walk, minus the
metadata probe, because a sideband endpoint has none: a PDP identifier is the base its
`/sideband/request` and `/sideband/response` hang off.

| Mode | What it reads | Falls back to |
| --- | --- | --- |
| `off` | nothing — `service_url`, no fetch | — |
| `resource` | the resource's RFC 9728 document: `authzen_policy_decision_points` and `authzen_policy_layers` | `service_url` |
| `federation` | the resource's **resolved** `oauth_resource` metadata, from a federation resolve endpoint | `service_url` — never the resource's own document |

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

`pdp_discovery: federation` asks a federation resolve endpoint (OpenID Federation 1.0 §8.3,
usually the trust anchor's) for the resource's Resolved Metadata:

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
plugin, the same reason `authzen-pdp` delegates DPoP and COAZ to `coaz-pep` — so it is
decoded, not verified. The plugin checks what it can: the response's `typ` is
`resolve-response+jwt`, its `sub` is the resource asked about, and it has not expired. The
trust is TLS to a URL the operator configured, exactly the trust placed in `service_url`.
That is a weaker claim than `coaz-pep`'s federation mode, which walks the chain and
verifies every signature to an anchor key it holds. A route that needs the stronger claim
belongs behind `coaz-pep`; a route that trusts its federation's resolver gets the
federation's answer here with nothing else deployed.

The resolver's errors (§8.9) mean what they would to the Go PEP:

| The resolver says | Discovery does |
| --- | --- |
| `not_found`, or 404 | no metadata — `service_url` decides, as for a resource outside the federation |
| `invalid_trust_chain`, `invalid_metadata`, `invalid_subject`, `invalid_trust_anchor`, `invalid_request`, any other 4xx | a **refusal** — the request fails, whatever the failure rule says; a resource that claims membership and fails validation is a signal, not an outage |
| `server_error`, `temporarily_unavailable`, 5xx, unreachable | transient — the cached answer while there is one, then `service_url` |

A resolve response that is not a JWS, has the wrong `typ`, has expired, or lists something
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
- `fail-open` / `fail-closed` is what the layer does when its PDP **cannot be reached** —
  unreachable, erroring, rate-limiting, answering nonsense, refusing the call for want of a
  credential. Closed denies the request with a 503 (a 429 with `Retry-After`, when that is
  what the PDP said). Open skips the layer, names it in `X-PDP-Fail-Open`, and lets the rest
  decide; if every layer was skipped the request is permitted, marked. `fail_mode` is the
  route's default for entries that say nothing.
- `request-only` skips the layer's `/sideband/response` call. An estate PDP that judges
  the token has nothing to say about the response, and a PingAuthorize endpoint with no
  response-phase policy would otherwise be a failure in that phase.
- A **deny is a decision, not a failure**, and never opens. A **refusal** — a PDP outside
  `pdp_allowlist`, an invalid chain, a rule the plugin cannot read — fails the request
  whatever the rule says: fail-open is about availability, and a refusal is not an outage.

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
identifier, or with nothing. Called with nothing, PingAuthorize answers 401, which is a
failure under that layer's rule — closed by default, so a resource that names a PDP this
gateway holds no secret for is a resource this gateway cannot serve, and says so.
`secret_header_name` in an entry defaults to the top-level one.

## What comes back on the response

| Header | Meaning |
| --- | --- |
| `X-PDP-PEP` | `pep_label` |
| `X-PDP-Decision` | `PERMIT` or `DENY` |
| `X-PDP-Layers` | the PDPs that permitted, in order |
| `X-PDP-Layer` | on a deny, the PDP whose answer it was |
| `X-PDP-Source` | where the resource's PDP came from: `static`, `rfc9728` or `federation` |
| `X-PDP-Fail-Open` | the layers that were skipped, and why |

They ride on every response the plugin sends. Kong will not load a plugin that has both a
response phase and a header filter, so they are set on the exits themselves.

## What it does not do

- **Shape a challenge.** A deny is the policy's HTTP. If the policy answers a flat 403, the
  client gets a flat 403.
- **Verify a token, a DPoP proof, or a chain.** No JOSE. The token reaches PingAuthorize
  in the `authorization` header, where policy can validate it; DPoP and COAZ are what
  `authzen-pdp` delegates to `coaz-pep`, and an MCP route belongs there.
- **Read `signed_metadata`** in an RFC 9728 document; the Go PEP does.
- **Serve the resource's federation face.** `authzen-pdp`'s `federation_entity_url` relays
  the two well-known documents from `coaz-pep`; put that plugin on the route for them.

## Tests

```sh
cd gateways/kong
busted --lpath="./?.lua;./?/init.lua" spec/
```

`spec/sideband-pdp_spec.lua` runs against the mocked Kong in `spec/mock_kong.lua` — no
gateway, no PingAuthorize, no network: what the policy provider is sent, how a permit's
rewrites and a deny's response are applied, the layer walk under each rule, the response
phase, and discovery through both phases including the federation switch. The discovery
rules themselves are covered in `spec/discovery_spec.lua`, alongside `authzen-pdp`'s.

For a run through real Kong, mount both plugin directories into `kong:3.9` DB-less with a
route on a stub that answers `/.well-known/oauth-protected-resource` and
`/sideband/request` — the response headers above say what happened.

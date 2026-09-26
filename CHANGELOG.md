# Changelog

Every component — the `coaz-pep` image, the two Kong plugins, the PingAccess rule and the
Node SDK — shares one version line from 0.4.0 on. A `v*` tag releases them all; a
`-rcN` tag is a candidate for that version and publishes nothing final.

## [0.4.0] - 2026-09-26

The production-readiness release. A review found that every enforcement point had at
least one way to get a request permitted that no PDP had judged, and that the trust
packages would keep honouring a chain after the anchor stopped vouching for it. This
release closes those, makes the PEPs refuse to run insecurely by accident, and adds what
operating them in production needs.

### Upgrading from 0.3 — read this first

These change behaviour on purpose. Each is a secure default with an explicit way out.

- **Insecure configuration refuses to start.** `coaz-pep` will not start without
  `CHECK_API_TOKEN`, `MCP_UPSTREAM_ALLOWLIST`, and `ACCESS_TOKEN_JWKS_URL` with
  `ACCESS_TOKEN_ISSUER` and `ACCESS_TOKEN_AUDIENCE` — plus `PDP_ALLOWLIST` and
  `RESOURCE_METADATA_ALLOWLIST` in `resource` and `federation` mode, and
  `FEDERATION_FETCH_ALLOWLIST` in `federation` mode — and names every missing one. The
  Kong plugins and the PingAccess rule refuse the equivalent configuration; the Node SDK
  refuses to construct. The escape hatch, logged every time, is `PEP_ALLOW_INSECURE=true`
  (coaz-pep), `allow_insecure` (Kong, PingAccess) or `allowInsecure` (Node). It is for
  development and demos only.
- **Every MCP method is decided.** `coaz_defaults` (`applyDefaultMappings` in the SDK) is
  now on: `tools/list`, `resources/read`, `prompts/get`, `initialize` and the rest go to
  the PDP with the binding's default mappings, a tool with no declared mapping gets the
  default `tools/call` one, and an unknown method is denied. Policies must answer those
  actions. `coaz_defaults: false` brings back the old pass-through for a route whose
  policies are not ready — non-conformant, and an explicit choice.
- **MCP bodies the PEP cannot read unambiguously are refused**: batches, truncated or
  encoded bodies, bytes after the object, and member names equal under case folding at
  any depth. Set Envoy's `allow_partial_message: false` with a `max_request_bytes` above
  your largest request (the samples now do).
- **`X-User-Token` counts only when it is the principal's own verified login**, with an
  audience: set `USER_TOKEN_AUDIENCE` (coaz-pep) or `user_token_audience` (PingAccess), or
  it is ignored and `require_user_login` routes deny. A staff member approving for a
  customer needs `user_token_subject: pdp` on that route, and a policy that checks the
  forwarded `user_sub`.
- **Fail-open covers unavailability only.** A PDP that answers a 3xx or 4xx, or something
  that is not a decision, now fails closed on every layer, fail-open or not.
- **Resource metadata that cannot be fetched, or does not validate, no longer falls back
  to the static PDP.** The last good copy is served for up to one more TTL; after that
  the `resource` layer is unavailable and fails closed unless marked fail-open. A 404, or
  a document naming no PDP, still means "this resource publishes nothing". Likewise a PDP
  whose metadata cannot be read is unavailable, not called at the default paths.
- **Kong:** `style: mcp` requires `coaz_url`; with `coaz_url` set the plugin hands the
  whole decision to coaz-pep, REST included. A route without `coaz_url` must declare
  `access_token_verified_upstream` (an auth plugin validated the token) or it is refused.
  sideband-pdp's `pdp_discovery: federation` is renamed `federation-resolver`. The
  sideband rock now depends on the authzen-pdp rock instead of shipping its module.
- **PingAccess:** `style: mcp` requires `coaz_url`; a token PingAccess did not validate is
  a 401; `require_user_login` needs a JWKS and an audience.
- **Node SDK:** Node 22 or later. The middleware requires `verifyToken`; the delegate
  guard requires `upstreamUrl` and `apiKey`; `map()` returning `undefined` is a mapping
  error (only `null` opts out); `X-Auth-*` are set on the request, not the response.
- **Images** run as non-root on distroless, and the demo's stubs as an unprivileged user:
  a demo volume left from an older run needs `docker compose down -v`.

### Security

- MCP routes on every surface permitted anything they could not parse as one `tools/call`
  — a body over the gateway's buffer (64 KiB for Envoy's samples, 8 KiB for Kong), a
  batch, a gzip body, an empty body — without a PDP call, while the upstream ran it.
- coaz-pep read JSON-RPC into Go structs, which match keys case-insensitively:
  `"params"` beside `"Params"` had the PDP judge one tool while a lenient upstream ran
  another.
- `coaz_defaults` never reached anything but `tools/call` through coaz-pep or Kong.
- Kong decoded `X-User-Token` and the access token without verifying either; the Node
  middleware trusted an unsigned token when no verifier was given; `/v1/dpop/verify`
  never validated the token it checked a proof against; a genuine `X-User-Token` from
  another customer could carry their consent to this one's payment.
- The federation cache served an invalid or expired chain indefinitely whenever a
  refresh failed, so revocation never reached a running PEP; a federation-vouched
  document the PEP could not use fell back to the static PDP and dropped the layers the
  anchor mandated.
- sideband-pdp built the URL PingAuthorize judges from `X-Forwarded-*`, sent it no body
  past Kong's buffer, dropped headers and query arguments past 100, and treated a `{}`
  answer as a permit.
- Fail-open layers could be switched off by a client provoking a 400 or 413, and by a
  rotated key's 401.
- A boxcar answer with fewer decisions than questions permitted the unanswered ones; the
  Node SDK permitted on `"false"`, `1` or `{}`.
- The PDP and discovery clients followed redirects past the allowlists; `X-PDP-Reason`
  carried internal URLs and upstream error bodies to clients.
- No RSA key size ceiling (a CPU denial of service through a DPoP proof), ES algorithms
  not bound to their curves, JWS `crit` ignored, non-canonical base64url accepted.
- The DPoP replay cache refused every proof once full; a DPoP-bound token was accepted as
  a bearer token where `require_dpop` was off; `htu` was only logged.
- The public demo console's `/api/fetch` could be made to fetch any URL.
- grpc 1.83.2 (three advisories, including a server panic), cel-go 0.31, and a pinned Go
  toolchain; govulncheck is clean and runs in CI.

### coaz-pep and the COAZ engine

- Strict JSON-RPC parsing (`coaz.ParseRequest`); every MCP message decided
  (`Engine.CheckMCP`); refusals as JSON-RPC errors with 400, 413, 415 or 405.
- Startup refuses insecure settings; `PEP_ALLOW_INSECURE`, `DPOP_HTU_BASE`,
  `GRPC_TLS_CERT_FILE`/`_KEY_FILE`/`_CLIENT_CA_FILE`, `LOG_FORMAT`,
  `PDP_METADATA_MAX_STALE`, `PDP_METADATA_FETCH_TIMEOUT`,
  `FEDERATION_ENTITY_METADATA_LIFETIME` are new.
- Route knobs `coaz_v2_only` and `user_token_subject` are new; a knob that is neither
  true nor false, or an unknown style, fails the route closed.
- DPoP: binding compared before the signature, `htu` enforced, a keyed replay cache with a
  per-key quota, §7.2 bound-token-as-bearer rejected on every route.
- The JWKS refreshes in the background with one shared fetch; stale keys are trusted for
  up to an hour of failed refreshes.
- CEL evaluates under a deadline, with a cap on expressions per mapping; `tools/list` is
  read across pages; context the PEP asserts wins over a mapping's.
- `X-Auth-*` are overwritten or removed, never left as the client sent them;
  `X-Auth-Acr` is new.
- Operations: `/readyz`, `/metrics`, JSON logs with one audit record per decision, a
  graceful drain on SIGTERM, a panic-recovering, bounded gRPC server.
- REST mapping anchored to the end of the path; non-canonical paths and ambiguous bodies
  refused.

### Trust packages (federation, JOSE, discovery)

- Cached trust has a hard expiry and bounded staleness; refusals evict; a cancelled
  request no longer pins a resource to the static PDP.
- A refused authority hint is a path not taken; offboarding (every statement a 404) is
  "not a member".
- Naming constraints follow OpenID Federation §6.2.2 (RFC 5280 host and domain forms).
- The entity signs its metadata only, dates it, marks its source inside the signature,
  and publishes its key set at its `jwks_uri`; its key file cannot be minted twice.
- Layer lists parse strictly; statements must be served as
  `application/entity-statement+jwt`; anchor keys are checked at startup; allowlists never
  see dot segments or credentials.

### Kong plugins

- authzen-pdp: every MCP request to coaz-pep; the body read in full or refused;
  identity headers owned by the PEP; generic client reasons; REST mapping anchored;
  secrets `encrypted` and vault-referenceable; the last good PDP metadata served through
  a blip.
- sideband-pdp: PingAuthorize judges the request Kong routes — its real URL, its whole
  body, all its headers and arguments; a permit must have a permit's shape; HTTP/2 and
  upgrade requests are refused where a layer filters responses; a response-phase failure
  says the upstream already ran; a response buffering cap.

### PingAccess rule

- Every MCP request to coaz-pep, strict JSON, unreadable bodies refused; a bounded pool
  per rule and deadlines on every outbound call; `X-User-Token` verified, bound and
  audienced; configuration validated (absolute URLs, https where a secret travels);
  REST mapping on the normalised routed path; tested on PingAccess 9.1.0.1 and Java 17+.

### Node SDK

- A strict local guard, the same Unicode folding as Go at every depth; delegate mode
  forwards everything to coaz-pep; `evaluateAll` strict; redirects refused; paginated,
  bounded gateway discovery; a hardened `FederationEntity`. ESM only, Node 22+, published
  with provenance.

### Delivery

- Images: distroless, non-root, pinned by digest, signed with cosign, with an SBOM and
  build provenance, for amd64 and arm64.
- CI: read-only permissions, SHA-pinned actions, the race detector, govulncheck,
  `npm audit`, both Kong plugins parsed, Java 17 and 21, an image boot check and the
  demo walkthrough end to end. Dependabot for every ecosystem.
- `SECURITY.md`, `CODEOWNERS`, and this file.

## [0.3.0] and earlier

Unreleased builds from source. See the git history.

# Demo: what PDP discovery is for

Two different arguments get made here, and it is worth keeping them apart.

**Is it safe?** A resource that names its own PDP can name a permissive one. A federation
stops it. That is the rogue PDP running through the cast below, and what `demo.sh` walks.

**Is it worth turning on?** A PDP moves and no PEP is touched. Two business units answer
to two PDPs through one gateway. A PEP batches only against a PDP that says it can. Those
are the levers and the MCP request in the console.

**Who enforces what a resource requires?** Not the gateway. Each resource publishes the
scopes it uses and the acr it expects; the PEP forwards that document to the PDP verbatim,
with the endpoint hit and the raw token, and the PDP does the matching. That is the
token, scope and acr pickers in the console, and section 3 of `demo.sh`.

**Can policy be layered?** Yes: a route names an ordered list of PDPs, every one of which
must permit. The demo's estate PDP judges the token and the client and knows nothing about
any resource; put first, it gates every request before the resource's own PDP is asked.
That is the layers picker, and section 4.

Nothing here turns on who the customer is. The variables are which PDP was consulted,
what document it was given, what the token carries, and which layers ran. One subject,
`customer`, throughout.

## The cast

| Stub | Port | What it is |
| --- | --- | --- |
| `anchor` | 9000 | A federation Trust Anchor. Its policy for members: `authzen_policy_decision_points` must be a subset of `[pdp-a]`, and `acr_values_required` **is** `[MFA]`, whatever the member says. |
| `member` | 9001 | A federated resource. Its **own** RFC 9728 document names Bank A's PDP and says a password is enough; its entity configuration names the rogue PDP first. The anchor's policy strips the rogue **and raises the acr floor to MFA**. |
| `pdp-a` | 9002 | Bank A's PDP, identifier `…:9002/tenants/bank-a`. Holds the token to what the resource published; steps up payments over 1000. Advertises a batch endpoint. |
| `rogue-pdp` | 9003 | Permits everything, logs loudly when asked, and advertises **no** batch endpoint. Bare identifier, no tenant path. |
| `plain` | 9004 | Not federated. RFC 9728 metadata names Bank A's PDP; requires a password. |
| `impostor` | 9005 | Not federated. RFC 9728 metadata names the rogue PDP. |
| `broken` | 9006 | Federated, but signs with a key the anchor never vouched for. |
| `stray` | 9007 | No metadata of any kind. |
| `pdp-b` | 9008 | Bank B's PDP, identifier `…:9008/tenants/bank-b`. Same product, stricter threshold: steps up payments over 100. |
| `pdp-estate` | 9098 | A generic PDP for the whole estate: judges the token and the client (`agent-risky` is on its watch list), knows nothing about any resource. The first layer. |
| `bank-b` | 9009 | Not federated. RFC 9728 metadata names Bank B's PDP; requires MFA. |
| `control` | 9099 | The event feed the console traces, and the levers it pulls. Not part of any spec. |

The three PEPs' allowlists name the estate PDP so a route may add it as a layer.

Every resource also answers MCP `tools/list` at `/mcp` with one tool whose mapping is a
boxcar: a transfer is a debit and a credit, evaluated in one call.

Every resource with metadata publishes what it requires as ordinary members of that
metadata: `scopes_supported` (RFC 9728's own) and `acr_values_required` (no standard home
yet; an example name). No PEP reads either. They reach the PDP as `context.resource_metadata`,
tagged with whether the federation vouched for them, and the two banks' PDPs hold the
token to them.

Then `coaz-pep` three times, one per discovery mode: `pep-static` (:9192, told where its
PDP is), `pep-resource` (:9193, trusts each resource's own well-known) and
`pep-federation` (:9194, trusts the federation's word). The cast is defined in
[`core/cmd/demo-stubs/main.go`](../core/cmd/demo-stubs/main.go).

## Run it

With Docker:

```bash
cd demo && docker compose up --build -d && ./demo.sh
```

Then open **<http://localhost:8088>** for the console.

Without Docker (needs Go 1.25+; builds and runs everything on this machine):

```bash
demo/run-local.sh              # the scripted walkthrough, then exit
demo/run-local.sh --console    # also serve the console on :8088 and stay up
```

Add `--profile kong` to `docker compose up` to also run Kong (:8000) with the Lua plugin
doing the same discovery in front of the `plain` resource; `demo.sh` notices and adds a
section. The Node SDK version is `node demo/node-sdk.mjs` after
`cd sdk/node && npm install && npm run build`.

Watch the stubs while it runs: `docker compose logs -f stubs` (or `stubs.log` under
`$TMPDIR/idp-auth-peps-demo` for the local runner). Every PDP decision and every metadata
fetch is one line, and the rogue PDP announces itself.

## The console

Pick a resource, a request, the route's policy layers, and the shape of the token: who it
was issued to, how the customer authenticated, which scopes it carries, and whether the
route forwards it to the PDP. Press Run. The same check goes to all three
PEPs and you get three columns: the decision, a line saying what that column just proved,
and underneath it every request the stubs saw while that PEP was deciding — which
`.well-known` document it read, whether it climbed a trust chain, and which PDP answered
**on which endpoint**.

Every endpoint in the trace is AuthZEN's own name — `/access/v1/evaluation` and
`/access/v1/evaluations`. Nothing here invents a path, because a demo about a standard
that shows you a made-up verb teaches the wrong thing.

What differs between PDPs is the **base** those endpoints hang off. A PDP identifier may
carry a path, and a multi-tenant deployment is the ordinary reason it does, so Bank A's
PDP is the identifier `http://stubs:9002/tenants/bank-a`. Its metadata sits at
`/.well-known/authzen-configuration/tenants/bank-a` — AuthZEN §9 inserts the well-known
segment after the host and keeps the identifier's path — and it evaluates at
`/tenants/bank-a/access/v1/evaluation`.

Under each PDP's verdict is a **was given** line: the resource's declared requirements and
their source, the endpoint hit, and what the token said — exactly what the PDP had to work
with, and none of it judged by the PEP.

The trace badges each evaluation as **the PDP's own base** or **advertised elsewhere**.
Before anything moves those agree, and that is the honest picture: a correctly configured
static PEP and a discovering one post to the same place. The difference only appears when
something changes, which is the argument.

### The levers

Three buttons change the world while it runs. None restarts a PEP or edits a PEP's
configuration; the PEPs pick the change up on their next metadata refresh.

- **Relocate Bank A's PDP.** Its metadata starts advertising the same AuthZEN endpoints
  under a new base, `/tenants/bank-a-v2`. The identifier does not change: a name and a
  location are different fields for exactly this reason. Re-run and the discovery columns
  follow; the static column carries on posting to the old base, because it was told a URL
  rather than sent to read one. This is the answer to "why not just set `AUTHZEN_URL`" —
  because then this is a deploy.
- **Hand `plain` over to Bank B's PDP.** Re-run a payment of 500: permitted under Bank A's
  threshold, needs a step-up under Bank B's. A resource changed hands between two policy
  owners and no gateway was touched.
- **Put it back.**

### Requests worth trying

- **A read-only token paying 50 on plain, then on impostor.** Static permits: its PDP
  was told nothing about the resource. Resource mode on `plain` comes back as a step-up for
  `payments:write`, decided from the resource's own `scopes_supported`. Resource mode on
  `impostor` permits, because the impostor named the rogue PDP as its judge.
- **member with a read-only token.** Watch the federation column climb
  `member → anchor → fetch` and come back with Bank A's PDP and the resolved document.
- **plain, then bank-b, paying 500.** Same request, two answers, because two resources
  answer to two PDPs with different thresholds. The static column cannot tell them apart:
  it has one PDP for everything.
- **agent-risky with "estate PDP first" on any resource.** The estate PDP denies and the
  resource's PDP is never asked. Switch to agent-1 and both layers permit, in order.
- **member, password token, read a balance — resource mode then federation mode.** The
  resource column permits: the member's own document says a password is enough, and Bank
  A's PDP believes it. The federation column denies, from the *same* PDP with the *same*
  policy and the *same* token, because the document it was given is the resolved one and
  the anchor set the floor at MFA. The PDP's reason names which document it was reading.
- **bank-b with a password token, then with MFA.** Bank B requires MFA; the PDP says so,
  and says what would satisfy it.
- **plain, read-only token, pay 50.** The PDP turns the resource's `scopes_supported` into
  a step-up for `payments:write`. A gateway comparing scopes could only have said 403.
- **Anything acr-gated with "forward the raw token" set to no.** The PDP was not given the
  token, cannot check the acr, and says exactly that rather than guessing.
- **MCP transfer (batch), on plain then on impostor.** One tool call, two evaluations.
  Against Bank A's PDP it goes to the `access_evaluations_endpoint` its metadata
  advertises. Against the rogue PDP, which advertises none, the PEP reads the metadata and
  **refuses** — nothing is sent at all. AuthZEN's default paths are what a PEP assumes
  when there is no metadata; they are not licence to assume an endpoint a PDP declined to
  claim.

The metadata cache TTL is 15 seconds here so the trace shows fetches on every run rather
than an empty list; the shipped default is five minutes, and a repeat run inside the TTL
legitimately shows nothing fetched. The console reads the stubs' event feed at
`:9099/events` — a plain in-memory ring buffer, not part of any spec.

## What `demo.sh` walks

**1. Where the PDP comes from, and what it was told.** A read-only token tries to pay.
The static PEP's PDP permits: it was told nothing about the resource. The resource-mode
PEP on `plain` comes back as a step-up for `payments:write`: the PDP read the resource's
`scopes_supported` out of what the PEP forwarded. On `impostor` the rogue PDP permits — the
resource chose its own judge. The federation-mode PEP never reads a resource's own
document: the impostor gets the static PDP, the `member` gets Bank A's after a validated
chain, `broken` is a **503** and never a fallback, `stray` gets the static PDP.

**2. Two banks, one gateway.** A payment of 500 is permitted on `plain` and step-up
challenged on `bank-b`, because the resource decides whose policy applies.

**3. What the resource requires is the PDP's to enforce, and the federation sets the
floor.** Bank B requires MFA and a password token is denied with the reason. The `member`
says a password is enough about itself and the resource-mode PEP's PDP agrees; the
federation-mode PEP forwards the resolved document, the anchor set MFA, and the same PDP
denies. With the token not forwarded, the PDP says it could not examine it.

**4. Layers.** With `pdp_layers` naming the estate PDP first, `agent-1` is permitted by
both PDPs in order, and `agent-risky` is stopped by the estate PDP before Bank A's is
asked.

**5. Challenges.** A 50 payment is permitted; a 5000 payment comes back as a 401 with
`WWW-Authenticate: Bearer error="insufficient_scope", scope="payments:approve"` and an
`authz_challenge` body. Discovery changed where the decision came from, not what a deny
looks like.

## What is fake

Tokens are unsigned (the PEPs warn about it at boot); everything is plain http on a
private network, hence `PDP_DISCOVERY_INSECURE`; keys are generated when the stubs start;
the "policy" is a handful of ifs; and the control surface on :9099 is a demo affordance,
not part of any specification. None of that is the point. The point is the three columns,
and which PDP's log line appears under each.

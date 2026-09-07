# Demo: what PDP discovery is for

Two different arguments get made here, and it is worth keeping them apart.

**Is it safe?** A resource that names its own PDP can name a permissive one. A federation
stops it. That is the rogue PDP running through the cast below, and what `demo.sh` walks.

**Is it worth turning on?** A PDP moves and no PEP is touched. Two business units answer
to two PDPs through one gateway. A PEP batches only against a PDP that says it can. Those
are the levers and the MCP request in the console.

## The cast

| Stub | Port | What it is |
| --- | --- | --- |
| `anchor` | 9000 | A federation Trust Anchor. Its policy for members: `authzen_policy_decision_points` must be a subset of `[pdp-a]`, and is essential. |
| `member` | 9001 | A federated resource. Its **own** metadata names the rogue PDP first. |
| `pdp-a` | 9002 | Bank A's PDP. Denies *mallory*; steps up payments over 1000. Advertises a batch endpoint. |
| `rogue-pdp` | 9003 | Permits everything, logs loudly when asked, and advertises **no** batch endpoint. |
| `plain` | 9004 | Not federated. RFC 9728 metadata names Bank A's PDP. |
| `impostor` | 9005 | Not federated. RFC 9728 metadata names the rogue PDP. |
| `broken` | 9006 | Federated, but signs with a key the anchor never vouched for. |
| `stray` | 9007 | No metadata of any kind. |
| `pdp-b` | 9008 | Bank B's PDP. Same product, stricter threshold: steps up payments over 100. |
| `bank-b` | 9009 | Not federated. RFC 9728 metadata names Bank B's PDP. |
| `control` | 9099 | The event feed the console traces, and the levers it pulls. |

Every resource also answers MCP `tools/list` at `/mcp` with one tool whose mapping is a
boxcar: a transfer is a debit and a credit, evaluated in one call.

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

Pick a resource, a user and a request, and press Run. The same check goes to all three
PEPs and you get three columns: the decision, a line saying what that column just proved,
and underneath it every request the stubs saw while that PEP was deciding — which
`.well-known` document it read, whether it climbed a trust chain, and which PDP answered
**on which endpoint**.

That last part is the one people miss. `POST /access/v1/evaluation` is the path AuthZEN
tells a PEP to assume when a PDP publishes no metadata. `POST /decide` is the endpoint
this PDP actually advertised, and a PEP only knows it by having read the document. The
trace badges each call so the difference is visible rather than implied.

### The levers

Three buttons change the world while it runs. None restarts a PEP or edits a PEP's
configuration; the PEPs pick the change up on their next metadata refresh.

- **Move Bank A's PDP to `/decide-v2`.** Re-run: the discovery columns follow to the new
  endpoint; the static column carries on posting to the path it assumed. This is the
  answer to "why not just set `AUTHZEN_URL`" — because then this is a deploy.
- **Hand `plain` over to Bank B's PDP.** Re-run a payment of 500: permitted under Bank A's
  threshold, needs a step-up under Bank B's. A resource changed hands between two policy
  owners and no gateway was touched.
- **Put it back.**

### Requests worth trying

- **impostor + mallory + read a balance.** Static denies her, federation denies her, and
  the middle column permits her, because the resource named its own judge.
- **member + mallory.** Watch the federation column climb `member → anchor → fetch` and
  come back with Bank A's PDP, while the resource column takes the member's own word and
  reaches the rogue one.
- **plain, then bank-b, paying 500.** Same request, two answers, because two resources
  answer to two PDPs with different thresholds. The static column cannot tell them apart:
  it has one PDP for everything.
- **MCP transfer (batch), on plain then on impostor.** One tool call, two evaluations.
  Against Bank A's PDP it goes to the advertised batch endpoint. Against the rogue PDP,
  which advertises none, the PEP reads the metadata and **refuses** — nothing is sent at
  all, because guessing a batch path is not something a PEP gets to do.

The metadata cache TTL is 15 seconds here so the trace shows fetches on every run rather
than an empty list; the shipped default is five minutes, and a repeat run inside the TTL
legitimately shows nothing fetched. The console reads the stubs' event feed at
`:9099/events` — a plain in-memory ring buffer, not part of any spec.

## What `demo.sh` walks

**1. Static.** The PEP is told Bank A's PDP is at :9002. Alice is permitted, mallory is
not. The evaluation arrives on the AuthZEN default path — nothing was discovered.

**2. Resource mode.** The `plain` resource's well-known names Bank A's PDP; the PEP reads
that PDP's metadata and calls the endpoint it advertises. Then the `impostor` resource
names the rogue PDP — and **mallory is permitted**. A self-asserted document cannot
protect the thing it asserts. (A `PDP_ALLOWLIST` would have stopped this; `pep-resource`
deliberately has none, and warns about it at boot.)

**3. Federation mode.** The impostor is not a member, so its own document is never read:
it gets the operator's static PDP, and mallory is denied. The `member` names
`[rogue, pdp-a]` in its Entity Configuration, but the anchor's `subset_of` leaves only
`pdp-a` in the resolved metadata — mallory is denied, and the stubs log shows the rogue
PDP was never consulted. The `broken` resource's chain does not validate: **503**, never a
fallback. The `stray` resource has nothing: static PDP.

**4. Two banks, one gateway.** A payment of 500 is permitted on `plain` and step-up
challenged on `bank-b`, because the resource decides whose policy applies.

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

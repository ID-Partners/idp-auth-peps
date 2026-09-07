# Demo: who decides, and how the PEP finds out

A small world in which the answer to "which PDP decides for this resource" matters:

| Stub | Port | What it is |
| --- | --- | --- |
| `anchor` | 9000 | A federation Trust Anchor. Its policy for members: `authzen_policy_decision_points` must be a subset of `[good-pdp]`, and is essential. |
| `member` | 9001 | A federated resource. Its **own** metadata names the rogue PDP first. |
| `good-pdp` | 9002 | Permits, unless the human is *mallory*; asks for a step-up on payments over 1000. |
| `rogue-pdp` | 9003 | Permits everything, and logs loudly whenever anyone asks it. |
| `plain` | 9004 | Not federated. RFC 9728 metadata names the good PDP. |
| `impostor` | 9005 | Not federated. RFC 9728 metadata names the rogue PDP. |
| `broken` | 9006 | Federated, but signs with a key the anchor never vouched for. |
| `stray` | 9007 | No metadata of any kind. |

and `coaz-pep` three times, one per discovery mode: `pep-static` (:9192, told where the
PDP is), `pep-resource` (:9193, trusts each resource's own well-known) and
`pep-federation` (:9194, trusts the federation's word). The cast is in
[`core/cmd/demo-stubs/main.go`](../core/cmd/demo-stubs/main.go).

Two ways to drive it: `demo.sh` walks every case in the terminal, and the **console** on
:8088 is the clickable version for showing a room.

## The console

Pick a resource, a user and a request, and press Run. The same check goes to all three
PEPs and you get three columns: the decision, and underneath it every request the stubs
saw while that PEP was deciding — which `.well-known` document it read, whether it
climbed a trust chain, and which PDP answered. A permit obtained from the rogue PDP is
called out in orange, because that is the failure the modes exist to prevent.

Start with **impostor + mallory**: static denies her, federation denies her, and the
middle column permits her because the resource named its own judge. Then **member +
mallory**: watch the federation column climb `member → anchor → fetch` and come back
with the good PDP, while the resource column takes the member's own word and reaches the
rogue one.

The metadata cache TTL is set to 15 seconds here so the trace shows fetches on every run
rather than an empty list; the shipped default is five minutes, and a repeat run inside
the TTL legitimately shows nothing fetched. The console reads the stubs' event feed at
`:9008/events` — a plain in-memory ring buffer, not part of any spec.

## Run it

With Docker:

```bash
cd demo && docker compose up --build -d && ./demo.sh
```

Then open **<http://localhost:8088>** for the console: pick a resource and a user, and it
runs the identical request against all three PEPs at once, showing each decision beside
the documents that PEP actually fetched and the PDP that actually decided.

Without Docker (needs Go 1.25+; builds and runs everything on this machine):

```bash
demo/run-local.sh              # the scripted walkthrough, then exit
demo/run-local.sh --console    # also serve the console on :8088 and stay up
```

Add `--profile kong` to `docker compose up` to also run Kong (:8000) with the Lua plugin
doing the same discovery in front of the `plain` resource; `demo.sh` notices and adds a
section.
The Node SDK version is `node demo/node-sdk.mjs` after `cd sdk/node && npm install && npm run build`.

Watch the stubs while it runs: `docker compose logs -f stubs` (or `stubs.log` under
`$TMPDIR/idp-auth-peps-demo` for the local runner). Every PDP decision and every metadata
fetch is one line, and the rogue PDP announces itself.

## What to look for

**1. Static.** Both PEPs are told the good PDP is at :9002. Alice is permitted, mallory is
not. The evaluation arrives on the AuthZEN default path — nothing was discovered.

**2. Resource mode.** The `plain` resource's well-known names the good PDP; the PEP reads
the PDP's metadata and calls its custom evaluation path. Then the `impostor` resource
names the rogue PDP — and **mallory is permitted**. The resource chose its own judge. A
self-asserted document cannot protect the thing it asserts. (A `PDP_ALLOWLIST` would have
stopped this; `pep-resource` deliberately has none, and warns about it at boot.)

**3. Federation mode.** The impostor is not a member, so its own document is never read:
it gets the operator's static PDP, and mallory is denied. The `member` names
`[rogue, good]` in its Entity Configuration, but the anchor's `subset_of` leaves only
`good` in the resolved metadata — mallory is denied, and the stubs log shows the rogue PDP
was never consulted. The `broken` resource's chain does not validate: **503**, never a
fallback. The `stray` resource has nothing: static PDP.

**4. Challenges.** A 50 payment is permitted; a 5000 payment comes back as a 401 with
`WWW-Authenticate: Bearer error="insufficient_scope", scope="payments:approve"` and an
`authz_challenge` body. Discovery changed where the decision came from, not what a deny
looks like.

## What is fake

Tokens are unsigned (the PEPs warn about it at boot); everything is plain http on a
private network, hence `PDP_DISCOVERY_INSECURE`; keys are generated when the stubs start;
the "policy" is a handful of ifs. None of that is the point. The point is the four
columns of `demo.sh`'s output, and which PDP's log line appears under each.

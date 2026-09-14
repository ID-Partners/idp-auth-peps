# The AuthZEN PDP rule in the PingAccess console

Everything an administrator sees of the rule is one form, drawn by the console from the
rule's *descriptor*: the list of configuration fields the rule declares, each with a
widget type, a label, a default, a help note, and whether it is required or tucked
behind **Show Advanced Settings**. This page is that form, field by field, with what each
value does, how it is validated, and what the console sends to PingAccess when you save.
[pingaccess.md](pingaccess.md) explains why the rule exists; the
[README](../gateways/pingaccess/README.md) is the quick reference for the same knobs as
JSON.

## Where it appears

- **Access > Rules**, add a rule, type **AuthZEN PDP**. The rule is in the *Access
  Control* category, so the console lists it with the other rules that decide rather
  than modify, and it runs before any processing rule on the same policy.
- **Applications > Applications**, edit an application, the **API Policy** tab. The rule
  is in **Available Rules** for applications and resources whose destination is *Site*
  (which includes sideband deployments) or *Agent*. Drag it onto the policy; drag it
  towards the top, so a deny costs nothing further.
- The same descriptor is what the admin API serves at
  `GET /pa-admin-api/v3/rules/descriptors/AuthZenPdpRule`, and a saved rule is
  `GET /pa-admin-api/v3/rules/{id}` with the form's values under `configuration`, keyed
  by the name shown in brackets after each label.

The descriptor also says `agentCachingDisabled: true`. In an Agent deployment the agent
normally caches a rule's verdict for a resource; this rule's verdict depends on the
token, the body and the PDP's current view, so caching is turned off and every request
is decided afresh.

## How the form behaves

**Widgets.** Five kinds, all standard console controls:

| Widget | What it is | What is saved |
| --- | --- | --- |
| TEXT | a single-line field | a string; the numeric fields (TTL, timeouts) accept digits and are stored as numbers |
| CONCEALED | a masked field for a secret | encrypted; the API returns it as `{"encryptedValue": "OBF:JWE:..."}` and never the plaintext, and a configuration export carries it encrypted under PingAccess's own key |
| CHECKBOX | a tick box | `true` or `false` |
| SELECT | a drop-down with the options listed below | the option's value (the short word before the colon) |
| LIST | a multi-value field, one entry per row, add and remove per row | an array of strings, `[]` when empty |

**Defaults.** Every field with a default arrives pre-filled: the drop-downs at `rest`,
`off` and `closed`, the tick boxes at the values in the tables below, the label at
`pingaccess-pep`, the numbers at their defaults. An empty **Policy layers** list means
`resource`, the single layer that is the whole of the rule's behaviour until you add
another. A blank optional text field means *not set*.

**Basic and advanced.** The fields marked *advanced* below sit behind **Show Advanced
Settings**. Nothing behind it is needed for a first rule; everything behind it is a
tuning, a safety valve or a development-only switch.

**Help.** Each field's help icon shows the title and note reproduced below. There are no
external help links.

**Saving.** The console posts the form as the rule's `configuration` and PingAccess
validates it twice, in this order:

1. *Field constraints*, reported on the field itself under a **Save Failed** banner: the
   PDP URL must not be blank, the drop-downs must hold one of their options, the numbers
   must be at least 1.
2. *The rule's own check*, reported as a banner beginning **Invalid plugin
   configuration;** followed by the reason. This is where the rules that span two fields
   live: *Require DPoP* without a *coaz-pep check API*, or a *Policy layers* entry the
   rule cannot read. The same message comes back to an API caller as HTTP 422 with the
   text in `flash`.

A saved rule takes effect on the engines without a restart. Only a new jar needs one.

## The fields

In the order the form shows them. *Key* is the JSON name and the text in brackets in the
label.

### The PDP

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| PDP URL | `authzen_url` | TEXT | — | required |
| PDP API key | `authzen_api_key` | CONCEALED | — | |
| PEP label | `pep_label` | TEXT | `pingaccess-pep` | |

**PDP URL** is the static PDP: the base URL AuthZEN's evaluation endpoints hang off when
discovery is off, and the fallback whenever discovery finds nothing. It is always
permitted, whatever the allowlists say, and its own origin is trusted over plain http.
Help: *The static PDP. Base URL of the AuthZEN PDP. Always the fallback and always
permitted, whatever discovery finds.*

**PDP API key** is sent as a bearer token to the static PDP and to nothing else. A PDP
found by discovery never receives it, because a key is bound to the PDP it was issued
for. Help: *Bound to the static PDP.*

**PEP label** names this enforcement point in every deny and challenge body (`"pep"`) and
in the `X-PDP-PEP` response header, so a client, or a support ticket, can say which
gateway said no. Help: *Who denied.*

### The route

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| Style | `style` | SELECT: `rest` (resource server), `mcp` (MCP edge) | `rest` | |
| Require an access token | `require_token` | CHECKBOX | ticked | |
| Require DPoP | `require_dpop` | CHECKBOX | unticked | needs *coaz-pep check API* |
| Require a logged-in user | `require_user_login` | CHECKBOX | unticked | |
| Step-up scope | `stepup_scope` | TEXT | — | |
| Step-up action | `stepup_action` | TEXT | `make_payment` | advanced |

**Style** chooses the request mapping. `rest` maps a REST request to an action and a
resource (a balance read is `get_balance` on an account; a payment carries its amount).
`mcp` treats the application as an MCP edge: access to the service is authorised on the
JSON-RPC `initialize` handshake, other traffic passes on a valid token, and a
`tools/call` is handed to coaz-pep when one is configured. Help: *Request mapping.*

**Require an access token** denies a request with no readable `Authorization: Bearer`
or `DPoP` token, or one without a subject, with a 401. Unticked, an anonymous request
still goes to the PDP, as `unknown-agent`, for the policy to decide.

**Require DPoP** sends the request's DPoP proof to coaz-pep for verification: the
proof's signature, freshness, replay and its binding to the token. The rule cannot verify
a proof itself, so this box needs *coaz-pep check API* filled in, and saving without it
is refused with a banner. When PingAccess validates the token itself, prefer the
application's own DPoP settings and leave this unticked. Help: *Delegated to coaz-pep.*

**Require a logged-in user** denies, with an RFC 9470 login challenge, unless the request
carries a valid `X-User-Token` for the person the agent acts for. Help: *RFC 9470 login
challenge.*

**Step-up scope** is the scope named in a step-up challenge when the PDP's advice names
none; leave it blank when the policy always says which scope it wants. Help: *Fallback
scope.* **Step-up action** is the action that fallback applies to, kept for parity with
the other PEPs.

### coaz-pep

The shared engine the rule delegates to for the two things it cannot do alone.

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| coaz-pep check API | `coaz_url` | TEXT | — | |
| coaz-pep API key | `coaz_api_key` | CONCEALED | — | |
| MCP upstream | `mcp_upstream_url` | TEXT | — | |
| Federation entity relay | `federation_entity_url` | TEXT | — | advanced |
| COAZ default mappings | `coaz_defaults` | CHECKBOX | unticked | advanced |

**coaz-pep check API** is the base URL of coaz-pep's HTTP check API. Required by *Require
DPoP*; on an `mcp` route it turns on per-tool-call authorisation. Help: *The shared
engine.* **coaz-pep API key** is the shared secret that API requires (its
`CHECK_API_TOKEN`); set it, because that endpoint fetches a caller-supplied URL with a
caller-supplied header and must know who is asking. Help: *CHECK_API_TOKEN.*

**MCP upstream** is the MCP server whose `tools/list` declares each tool's authorisation
mapping; the engine reads it from there. On an `mcp` route with no *Resource identifier*
this URL is also the identifier discovery starts from. Help: *Where tools/list lives.*

**Federation entity relay** makes the route the resource's federation face: the two
well-known documents, the entity configuration and the RFC 9728 metadata, are relayed
from coaz-pep at this URL, which holds the key and signs them. PingAccess cannot sign,
so it relays; nothing else on the route changes. Help: *The resource's federation face.*

**COAZ default mappings** authorises tools that declare no mapping against the COAZ-MCP
binding's defaults, as the binding requires. Off keeps the pass-through most deployed
tools expect, which is not conformant. Help: *Conformance.*

### Discovery

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| PDP discovery | `pdp_discovery` | SELECT: `off`, `authzen`, `resource` | `off` | |
| Resource identifier | `resource` | TEXT | — | |
| Metadata cache TTL, seconds | `pdp_metadata_ttl` | TEXT (number) | `300` | advanced, at least 1 |
| Permitted PDPs | `pdp_allowlist` | LIST | empty | advanced |
| Permitted resources | `resource_metadata_allowlist` | LIST | empty | advanced |
| Allow http for discovered URLs | `pdp_discovery_insecure` | CHECKBOX | unticked | advanced |
| Forward the raw access token | `forward_access_token` | CHECKBOX | unticked | |

**PDP discovery** is how the rule finds the PDP. `off`: the static PDP at AuthZEN's
default paths, nothing fetched. `authzen`: the static PDP's own
`/.well-known/authzen-configuration`, which says where it evaluates. `resource`: the
resource's `/.well-known/oauth-protected-resource` names the PDP that decides for it,
then that PDP's metadata; the static PDP when the resource names none. There is no
federation option here: validating a Trust Chain is coaz-pep's alone. Help: *Who
decides.*

**Resource identifier** is the protected resource's RFC 8707 identifier, the key
discovery starts from and the `resource` the PDP is told about. An `mcp` route without
one uses the MCP upstream; a `rest` route without one uses the static PDP. Help:
*RFC 8707.*

**Metadata cache TTL** is how long a resource's or a PDP's metadata is believed before
it is re-read. Stale metadata is served while a refresh fails, so a metadata outage is
not an authorization outage.

**Permitted PDPs** bounds what a resource may name: identifier prefixes, matched at a
path boundary, so `https://pdp.example` does not admit `https://pdp.example.evil`. The
static PDP is always permitted. Empty means any https PDP a resource names, which is
the setting to change before going live. Help: *What a resource may name.* **Permitted
resources** does the same for whose metadata the rule will fetch. Help: *Whose metadata
is fetched.*

**Allow http for discovered URLs** lets discovery follow plain-http URLs. For a
development network only; the static PDP's own origin is trusted over http regardless.
Help: *Development only.*

**Forward the raw access token** sends the bearer token to the PDP as
`context.access_token`, so the PDP can verify and inspect it itself rather than trust
what the rule decoded. It puts a bearer token on the wire, so only to a PDP reached over
TLS with a key on it. Help: *context.access_token.*

### Layers

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| Policy layers | `pdp_layers` | LIST | empty, meaning `resource` | |
| Failure mode | `fail_mode` | SELECT: `closed`, `open` | `closed` | |

**Policy layers** is the ordered list of PDPs every request asks, each an entry:
`static` (the PDP URL above), `resource` (whatever discovery finds), or a PDP
identifier, which must be a permitted PDP. Every layer must permit; the first that does
not is the answer. An entry may carry its own failure mode as a suffix,
`https://estate.example fail-open`; an entry the rule cannot read (`resource maybe`) is
refused at save time with a banner. Help: *Ordered PDPs, every one of which must permit.*

**Failure mode** is what a layer does when its PDP cannot be reached, unless the entry
says for itself. `closed` denies with a 503. `open` skips the layer and, if every layer
was skipped, permits, marking the response with `X-PDP-Fail-Open`. A deny is a decision
and a refusal is the rule's own policy; neither ever opens. Help: *Outages only.*

### The user token

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| X-User-Token JWKS | `user_token_jwks_url` | TEXT | — | |
| X-User-Token issuer | `user_token_issuer` | TEXT | — | advanced |
| X-User-Token audience | `user_token_audience` | TEXT | — | advanced |

**X-User-Token JWKS** turns on verification of the user's token: signature against this
JWKS, expiry, not-before, and the issuer and audience below when set; `alg: none` is
refused. A token that fails yields no claims, so *Require a logged-in user* denies and no
user scope reaches the PDP. Left blank, the token is decoded without verification and
the rule writes a warning to the log each time it is configured. Help: *Verify the user
token.*

### Transport and compatibility

| Label | Key | Widget | Default | Flags |
| --- | --- | --- | --- | --- |
| Verify TLS on outbound calls | `pdp_ssl_verify` | CHECKBOX | ticked | advanced |
| PDP timeout, ms | `pdp_timeout_ms` | TEXT (number) | `10000` | advanced, at least 1 |
| coaz-pep timeout, ms | `coaz_timeout_ms` | TEXT (number) | `15000` | advanced, at least 1 |
| Also send subject.identity | `legacy_subject_identity` | CHECKBOX | ticked | advanced |

**Verify TLS on outbound calls** covers every call the rule makes: the PDP, coaz-pep,
metadata. Unticking it trusts any certificate and skips hostname checks, process-wide
for JDK HTTP clients built afterwards, so it is for a developer's laptop and nothing
else; the rule logs a warning when it is off. Help: *Development only when off.*

**PDP timeout** and **coaz-pep timeout** bound one call each. A call that times out
counts as unreachable: a 503, or a skipped layer if that layer fails open.

**Also send subject.identity** keeps the non-standard `subject.identity` beside AuthZEN's
`subject.id` in every evaluation, so a policy written against the old field keeps
working. Untick it once the policies read `subject.id`. Help: *Migration.*

## Error messages

| Where | Message | Cause |
| --- | --- | --- |
| on the field | `must not be blank` | *PDP URL* is empty |
| on the field | `must be rest or mcp`, `must be off, authzen or resource`, `must be closed or open` | a value outside the drop-down's options, only possible through the API |
| on the field | `must be greater than zero` | a TTL or timeout of 0 |
| banner | `Invalid plugin configuration; require_dpop needs coaz_url: this rule cannot verify a DPoP proof signature itself, so verification is delegated to coaz-pep` | *Require DPoP* ticked with no *coaz-pep check API* |
| banner | `Invalid plugin configuration; pdp_layers: layer <x>: unknown modifier <y>` and its siblings | a *Policy layers* entry that is not `static`, `resource` or a URL, or carries a suffix other than `fail-open` / `fail-closed` |
| banner | `Invalid plugin configuration; authzen_url is required` | the same blank-URL check, when the field constraint was bypassed |

None of these reach the log; they are the console's. What the rule logs at runtime is
described in [pingaccess.md](pingaccess.md#running-it).

## For developers: where the form comes from

The form is [`AuthZenRuleConfiguration`](../gateways/pingaccess/authzen-pdp/src/main/java/com/idpartners/pa/authzen/AuthZenRuleConfiguration.java):
one public field per knob, each carrying a `@UIElement` (order, widget type, label,
default, advanced, required, options, help) and, where a value must satisfy something on
its own, a constraint annotation the console reports on the field. The SDK's
`ConfigurationBuilder.from(Class)` turns the annotations into the descriptor; PingAccess
binds the saved JSON back onto the fields by name, which is why the names are the
snake_case knobs every PEP in this repository shares rather than Java's camelCase.

To add a knob: a field with a `@UIElement` whose label ends in the JSON key in brackets
(a test checks that), a constraint if it has one, the cross-field rule in
`AuthZenRule.validate` if it spans fields, and a row in the README's table and here.

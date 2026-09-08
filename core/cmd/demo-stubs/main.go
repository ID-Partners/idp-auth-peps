// demo-stubs stands up everything the PDP discovery demo needs, in one process, on
// consecutive ports: a Trust Anchor, resources that are and are not federation members,
// two well-behaved PDPs belonging to different business units, and a rogue one.
//
// It exists so someone can show, with curl or the console, what discovery buys: a PDP
// that moves without touching a PEP, different resources answering to different PDPs
// through one gateway, a PEP that only batches against a PDP that says it can — and why
// a federation's word should beat a resource's own.
//
// Nothing here is production code: keys are generated at startup, everything is plain
// http, and the "policy" is a handful of ifs.
//
//	:9000  anchor      Trust Anchor: entity configuration + fetch endpoint
//	:9001  member      federated resource; its OWN metadata names the rogue PDP first,
//	                   the anchor's policy allows only Bank A's PDP
//	:9002  pdp-a       Bank A's PDP, at /tenants/bank-a. Denies mallory; steps up over 1000
//	:9003  rogue-pdp   permits everything, advertises no batch endpoint, and says so
//	:9004  plain       not federated; RFC 9728 metadata names Bank A's PDP
//	:9005  impostor    not federated; RFC 9728 metadata names the rogue PDP
//	:9006  broken      federated, but signs with a key the anchor never vouched for
//	:9007  stray       no metadata of any kind
//	:9008  pdp-b       Bank B's PDP, at /tenants/bank-b. Same denials, steps up over 100
//	:9009  bank-b      not federated; RFC 9728 metadata names Bank B's PDP
//	:9098  pdp-estate  a generic PDP for the whole estate: judges the token and the
//	                   client, knows nothing about any resource. The first layer.
//	:9099  control     the event feed the console traces, and the levers it pulls
//	                   (clear of the entity block, and of the ports desktop apps squat on)
//
// Every resource also answers MCP `tools/list` at /mcp, declaring one tool whose
// mapping is a boxcar — two evaluations in one call. That is what exercises a PDP's
// advertised batch endpoint, and what fails closed against a PDP with none.
//
// Nothing here turns on WHO the subject is. The demo is about which PDP decides, what
// it was given, and what the token carries; a named customer would only be noise. One
// subject, "customer", everywhere.
//
// Every resource also publishes what it REQUIRES — the scopes it uses and the acr it
// expects — as ordinary members of its metadata. No PEP here reads them. They travel
// to the PDP verbatim as context.resource_metadata, alongside the endpoint that was
// hit and (when the route allows) the raw token, and the PDP does the matching. That
// is the design choice the demo exists to show: what a resource requires is policy
// input, and policy is the PDP's, where it can be weighed against things a gateway
// never sees. In federation mode the document is the RESOLVED one, so the anchor can
// raise a member's floor and the member cannot lower it.
//
// Every endpoint here is AuthZEN's own: `/access/v1/evaluation` and
// `/access/v1/evaluations`. Nothing invents a path. What differs between PDPs is the
// BASE those endpoints hang off — a PDP identifier may carry a path, and a multi-tenant
// deployment is the ordinary reason it does. So Bank A's PDP is the identifier
// `http://host:9002/tenants/bank-a`, its metadata is at
// `/.well-known/authzen-configuration/tenants/bank-a` (AuthZEN 1.0 §9 inserts the
// well-known segment after the host and keeps the path), and it evaluates at
// `/tenants/bank-a/access/v1/evaluation`.
//
// That separation is what the "move" lever exercises: the identifier is a stable name,
// the endpoint is a location, and they are different fields for a reason. Move the
// endpoint and a PEP that reads metadata follows; one that was told a URL does not.
//
// Environment:
//
//	STUB_HOST     the hostname other containers reach this process by (default localhost)
//	STUB_PORT     the first port (default 9000); entities occupy the next ten
//	STUB_CONTROL_PORT  the control + events port (default 9099)
//	ANCHORS_FILE  where to write the FEDERATION_TRUST_ANCHORS_FILE for coaz-pep
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

const param = "authzen_policy_decision_points"

// The endpoint names AuthZEN 1.0 defines. A PDP that publishes no metadata is assumed
// to serve them directly under its identifier; a PDP that publishes metadata says where
// they actually are. Both are these two names — only the base moves.
const (
	evaluationPath  = "/access/v1/evaluation"
	evaluationsPath = "/access/v1/evaluations"
	// movedSuffix is where Bank A's PDP relocates when the demo's lever is pulled: a
	// new base, the same AuthZEN endpoint names, the same identifier.
	movedBase = "/tenants/bank-a-v2"
)

type entity struct {
	name string
	port int
	// origin is scheme://host:port. id is the entity identifier, which for a PDP may
	// carry a path: a tenant, a product, whatever the deployment is shaped like.
	origin string
	id     string
	base   string
	key    *ecdsa.PrivateKey
	jwk    map[string]any
}

// atBase gives an entity an identifier with a path component. Only PDPs use it; the
// point is that AuthZEN's endpoint names then hang off something other than the root.
func (e *entity) atBase(base string) *entity {
	e.base = base
	e.id = e.origin + base
	return e
}

func newEntity(name string, port int, host string) *entity {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	jwk, _ := jose.PublicJWK(key)
	origin := fmt.Sprintf("http://%s:%d", host, port)
	return &entity{name: name, port: port, origin: origin, id: origin, key: key, jwk: jwk}
}

func (e *entity) sign(claims map[string]any) []byte {
	tok, err := jose.Sign(map[string]any{"alg": "ES256", "typ": "entity-statement+jwt", "kid": e.jwk["kid"]}, claims, e.key)
	if err != nil {
		log.Fatal(err)
	}
	return []byte(tok)
}

func times() (int64, int64) {
	now := time.Now().Unix()
	return now - 10, now + 3600
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeStatement(w http.ResponseWriter, tok []byte) {
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write(tok)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------- what the operator can change while the demo runs ----------

// state is the mutable half of the world: what each PDP advertises as its evaluation
// endpoint, and which PDP each resource names. Discovery's whole claim is that these
// can change without touching a PEP, so the demo has to be able to change them.
type state struct {
	mu sync.Mutex
	// pdpEval maps a PDP's name to the base its metadata currently advertises the
	// AuthZEN endpoints under.
	pdpEval map[string]string
	// resourcePDPs maps a resource's name to the PDP identifiers its metadata names.
	resourcePDPs map[string][]string
	// requires maps a resource's name to what its OWN metadata says it requires.
	requires map[string]requirements
	// home is each PDP's identifier path — where its endpoints sit unless moved. The
	// console compares against it to say whether a call went to the advertised
	// endpoint or to the one a PEP would have assumed.
	home map[string]string
	// down names PDPs whose evaluation endpoints answer 503 — the fail-open lever. The
	// metadata stays up: a PDP that can say where it is but cannot decide.
	down map[string]bool
	// defaults, for reset.
	defEval map[string]string
	defRes  map[string][]string
}

func (s *state) eval(pdp string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pdpEval[pdp]
}

func (s *state) isDown(pdp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down[pdp]
}

// requirements is what a resource declares about itself. scopes_supported is RFC 9728's
// own member; acr_values_required has no standard home yet, so it is published under
// that name as an example — the PEPs neither know nor care, which is the point.
type requirements struct {
	Scopes []string
	ACR    []string
}

func (s *state) requirementsOf(resource string) requirements {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requires[resource]
}

func (s *state) pdps(resource string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.resourcePDPs[resource]))
	copy(out, s.resourcePDPs[resource])
	return out
}

func (s *state) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	eval := map[string]string{}
	for k, v := range s.pdpEval {
		eval[k] = v + evaluationPath
	}
	res := map[string][]string{}
	for k, v := range s.resourcePDPs {
		res[k] = append([]string{}, v...)
	}
	down := []string{}
	for k, v := range s.down {
		if v {
			down = append(down, k)
		}
	}
	return map[string]any{"pdp_evaluation_path": eval, "pdp_home": s.home, "resource_pdps": res, "pdp_down": down}
}

func main() {
	host := env("STUB_HOST", "localhost")
	base, _ := strconv.Atoi(env("STUB_PORT", "9000"))
	rec := &recorder{}

	anchor := newEntity("anchor", base, host)
	member := newEntity("member", base+1, host)
	pdpA := newEntity("pdp-a", base+2, host).atBase("/tenants/bank-a")
	rogue := newEntity("rogue-pdp", base+3, host)
	plain := newEntity("plain", base+4, host)
	impostor := newEntity("impostor", base+5, host)
	broken := newEntity("broken", base+6, host)
	stray := newEntity("stray", base+7, host)
	pdpB := newEntity("pdp-b", base+8, host).atBase("/tenants/bank-b")
	bankB := newEntity("bank-b", base+9, host)
	estate := newEntity("pdp-estate", base+98, host)
	// The key the anchor vouches for `broken` is not the one it signs with.
	brokenAsserted := newEntity("broken-asserted", base+6, host)

	const (
		acrPassword = "urn:idp:loa:password"
		acrMFA      = "urn:idp:loa:mfa"
	)
	allScopes := []string{"accounts:read", "payments:write"}
	st := &state{
		home:    map[string]string{pdpA.name: pdpA.base, pdpB.name: pdpB.base, rogue.name: rogue.base, estate.name: estate.base},
		pdpEval: map[string]string{pdpA.name: pdpA.base, pdpB.name: pdpB.base, rogue.name: rogue.base, estate.name: estate.base},
		down:    map[string]bool{},
		// The member's OWN document names Bank A's PDP and says a password is enough.
		// Its entity configuration (below) names the rogue PDP first. The anchor's
		// policy strips the rogue AND raises the acr floor to MFA — so the same PDP
		// gives different answers depending on which document the PEP forwarded.
		resourcePDPs: map[string][]string{plain.name: {pdpA.id}, impostor.name: {rogue.id}, bankB.name: {pdpB.id}, member.name: {pdpA.id}, broken.name: {rogue.id}},
		// acr_values_required lists every acr the resource ACCEPTS — "one of these" —
		// so a resource content with a password lists MFA as well, and only the strict
		// ones list MFA alone. The demo PDPs check membership, nothing cleverer.
		requires: map[string]requirements{
			plain.name:    {Scopes: allScopes, ACR: []string{acrPassword, acrMFA}},
			bankB.name:    {Scopes: allScopes, ACR: []string{acrMFA}},
			impostor.name: {Scopes: allScopes, ACR: []string{acrPassword, acrMFA}},
			member.name:   {Scopes: allScopes, ACR: []string{acrPassword, acrMFA}},
			broken.name:   {Scopes: allScopes, ACR: []string{acrPassword, acrMFA}},
		},
	}
	st.defEval = map[string]string{}
	for k, v := range st.pdpEval {
		st.defEval[k] = v
	}
	st.defRes = map[string][]string{}
	for k, v := range st.resourcePDPs {
		st.defRes[k] = append([]string{}, v...)
	}

	if path := os.Getenv("ANCHORS_FILE"); path != "" {
		raw, _ := json.MarshalIndent(map[string]any{anchor.id: map[string]any{"keys": []any{anchor.jwk}}}, "", "  ")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			log.Fatalf("writing %s: %v", path, err)
		}
		log.Printf("wrote trust anchors to %s", path)
	}

	var wg sync.WaitGroup
	serve := func(e *entity, mux *http.ServeMux) {
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("%-10s %s", e.name, e.id)
			log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", e.port), logged(e.name, rec, mux)))
		}()
	}

	// ---- anchor -------------------------------------------------------------------
	{
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
			iat, exp := times()
			writeStatement(w, anchor.sign(map[string]any{
				"iss": anchor.id, "sub": anchor.id, "iat": iat, "exp": exp,
				"jwks":     map[string]any{"keys": []any{anchor.jwk}},
				"metadata": map[string]any{"federation_entity": map[string]any{"organization_name": "Demo Federation", "federation_fetch_endpoint": anchor.id + "/fetch"}},
			}))
		})
		// The federation's constraints on every member: only Bank A's PDP may decide,
		// and nothing less than MFA is acceptable — whatever the member says about
		// itself. `value` overrides; the member's own acr_values_required is discarded.
		policy := map[string]any{"oauth_resource": map[string]any{
			param:                 map[string]any{"subset_of": []any{pdpA.id}, "essential": true},
			"acr_values_required": map[string]any{"value": []any{acrMFA}, "essential": true},
		}}
		mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
			sub := r.URL.Query().Get("sub")
			iat, exp := times()
			var keys []any
			switch sub {
			case member.id:
				keys = []any{member.jwk}
			case broken.id:
				keys = []any{brokenAsserted.jwk} // not the key `broken` actually signs with
			default:
				http.NotFound(w, r)
				return
			}
			writeStatement(w, anchor.sign(map[string]any{
				"iss": anchor.id, "sub": sub, "iat": iat, "exp": exp,
				"jwks": map[string]any{"keys": keys}, "metadata_policy": policy,
			}))
		})
		serve(anchor, mux)
	}

	// ---- resources ----------------------------------------------------------------
	// Federated ones publish an Entity Configuration as well as their own RFC 9728
	// document; the two deliberately disagree.
	// document is a resource's metadata: identity, who decides for it, and what it
	// requires. The same members go in its RFC 9728 document and in the oauth_resource
	// block of its entity configuration; only who vouches for them differs.
	document := func(e *entity, pdps []string) map[string]any {
		req := st.requirementsOf(e.name)
		doc := map[string]any{"resource": e.id, param: pdps, "bearer_methods_supported": []string{"header"}}
		if req.Scopes != nil {
			doc["scopes_supported"] = req.Scopes // RFC 9728 §2
		}
		if req.ACR != nil {
			doc["acr_values_required"] = req.ACR // no standard home; an example name
		}
		return doc
	}
	resource := func(e *entity, federated bool, hasMetadata bool, federationPDPs []string) {
		mux := http.NewServeMux()
		if federated {
			mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				iat, exp := times()
				writeStatement(w, e.sign(map[string]any{
					"iss": e.id, "sub": e.id, "iat": iat, "exp": exp,
					"jwks":            map[string]any{"keys": []any{e.jwk}},
					"metadata":        map[string]any{"oauth_resource": document(e, federationPDPs)},
					"authority_hints": []any{anchor.id},
				}))
			})
		}
		if hasMetadata {
			mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, document(e, st.pdps(e.name)))
			})
		}
		mux.HandleFunc("/mcp", mcpUpstream(e))
		mux.HandleFunc("/", upstreamAPI(e))
		serve(e, mux)
	}
	resource(member, true, true, []string{rogue.id, pdpA.id})
	resource(broken, true, true, []string{rogue.id})
	resource(plain, false, true, nil)
	resource(impostor, false, true, nil)
	resource(bankB, false, true, nil)
	resource(stray, false, false, nil)

	// ---- PDPs ----------------------------------------------------------------------
	// Bank A and Bank B run the same product with different thresholds — the ordinary
	// reason two resources in one estate answer to two PDPs.
	// customerPolicy is the whole of a bank's "policy", and the part that matters for
	// this demo is what it reads from context: the resource's declared requirements,
	// the endpoint hit, and the token — none of which the PEP judged. A real PDP would
	// weigh these alongside risk, consent history and velocity; the shape is the same.
	customerPolicy := func(stepUpOver float64) func(authzenRequest) map[string]any {
		return func(req authzenRequest) map[string]any {
			who := fmt.Sprintf("%v", req.Subject.Properties["on_behalf_of"])
			if who == "" || who == "<nil>" {
				who = req.Subject.ID
			}

			// What the resource said it requires, as forwarded. Absent means the PEP
			// resolved the PDP without reading a document (static mode), and this
			// policy has nothing to hold the token to beyond its own rules.
			meta, _ := req.Context["resource_metadata"].(map[string]any)
			source, _ := req.Context["resource_metadata_source"].(string)
			tok := examineToken(req.Context["access_token"])
			scope := tok.scope
			if scope == "" {
				scope, _ = req.Subject.Properties["scope"].(string) // what the PEP decoded, second best
			}

			if required := stringsOf(meta["acr_values_required"]); len(required) > 0 {
				switch {
				case tok.raw == "":
					return deny(fmt.Sprintf("this resource requires acr %v (per its %s metadata) and no token was forwarded for me to examine", required, source))
				case !contains(required, tok.acr):
					return deny(fmt.Sprintf("this resource requires acr %v (per its %s metadata); the token was authenticated at %q", required, source, tok.acr))
				}
			}
			if supported := stringsOf(meta["scopes_supported"]); len(supported) > 0 {
				if need := scopeFor(req.Action.Name); need != "" && contains(supported, need) && !hasScope(scope, need) {
					return map[string]any{"decision": false, "context": map[string]any{
						"reason":           fmt.Sprintf("%s needs scope %s here (the resource's %s metadata lists it) and the token carries %q", req.Action.Name, need, source, scope),
						"step_up_required": true, "step_up_scope": need}}
				}
			}
			if req.Action.Name == "make_payment" {
				if amt, ok := req.Context["amount"].(float64); ok && amt > stepUpOver {
					return map[string]any{"decision": false, "context": map[string]any{
						"reason":           fmt.Sprintf("payments over %.0f need the customer's approval", stepUpOver),
						"step_up_required": true, "step_up_scope": "payments:approve"}}
				}
			}
			examined := ""
			if tok.raw != "" {
				examined = fmt.Sprintf(" (examined the token: client %s, acr %s)", tok.clientID, tok.acr)
			}
			return map[string]any{"decision": true, "context": map[string]any{"reason": fmt.Sprintf("%s may %s%s", who, req.Action.Name, examined)}}
		}
	}
	pdp(pdpA, rec, st, true, serve, customerPolicy(1000))
	pdp(pdpB, rec, st, true, serve, customerPolicy(100))
	// The estate PDP is the generic layer: it judges the token and the client and knows
	// nothing about any resource. Put first in a route's pdp_layers, it gates every
	// request before the resource's own PDP is consulted — which is the point of
	// layering: one PDP for the things every endpoint shares, then the specific one.
	pdp(estate, rec, st, true, serve, func(req authzenRequest) map[string]any {
		tok := examineToken(req.Context["access_token"])
		client := tok.clientID
		if client == "" {
			client, _ = req.Subject.Properties["client_id"].(string) // what the PEP decoded
		}
		if client == "agent-risky" {
			return deny(fmt.Sprintf("estate: client %s is on the watch list; nothing further is asked", client))
		}
		how := "as decoded by the PEP"
		if tok.raw != "" {
			how = "from the token itself"
		}
		return map[string]any{"decision": true, "context": map[string]any{"reason": fmt.Sprintf("estate: client %s is in good standing (%s)", client, how)}}
	})
	// The rogue PDP advertises NO batch endpoint, so a PEP asked to boxcar against it
	// has nothing to send to and must refuse rather than guess a path.
	pdp(rogue, rec, st, false, serve, func(req authzenRequest) map[string]any {
		log.Printf("rogue-pdp  !!! consulted for %s by %v — permitting, as always", req.Action.Name, req.Subject.Properties["on_behalf_of"])
		return map[string]any{"decision": true, "context": map[string]any{"reason": "the rogue PDP permits everything"}}
	})

	// ---- control + events -----------------------------------------------------------
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
			var since int64
			if v := r.URL.Query().Get("since"); v != "" {
				since, _ = strconv.ParseInt(v, 10, 64)
			}
			seq, events := rec.since(since)
			writeJSON(w, map[string]any{"seq": seq, "events": events})
		})
		mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				writeJSON(w, st.snapshot())
				return
			}
			var body struct {
				Op string `json:"op"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			st.mu.Lock()
			switch body.Op {
			case "move_pdp":
				// Bank A's PDP relocates: same identifier, same AuthZEN endpoint names,
				// new base. It still answers on the old base, so nothing breaks
				// mid-flight; the trace is what shows the PEPs following.
				st.pdpEval[pdpA.name] = movedBase
			case "repoint_plain":
				// The plain resource is handed over to Bank B's PDP. No PEP is touched.
				st.resourcePDPs[plain.name] = []string{pdpB.id}
			case "estate_down":
				// The estate PDP stops deciding. A fail-closed layer turns that into a
				// 503; a fail-open one is skipped, and the permit says so.
				st.down[estate.name] = true
			case "estate_up":
				delete(st.down, estate.name)
			case "reset":
				st.down = map[string]bool{}
				for k, v := range st.defEval {
					st.pdpEval[k] = v
				}
				for k, v := range st.defRes {
					st.resourcePDPs[k] = append([]string{}, v...)
				}
			default:
				st.mu.Unlock()
				http.Error(w, `{"error":"unknown op"}`, http.StatusBadRequest)
				return
			}
			st.mu.Unlock()
			log.Printf("control    %s", body.Op)
			rec.add("control", "change", body.Op, "control", "")
			writeJSON(w, st.snapshot())
		})
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		control, _ := strconv.Atoi(env("STUB_CONTROL_PORT", "9099"))
		log.Printf("%-10s http://%s:%d/events", "control", host, control)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", control), mux))
	}()

	wg.Wait()
}

// examinedToken is what a PDP reads off a forwarded token for itself. The demo token
// is unsigned, so this only decodes; a real PDP would verify the signature and the
// sender-constraint binding here, and could introspect or risk-score the client.
type examinedToken struct {
	raw, acr, scope, clientID string
}

func examineToken(v any) examinedToken {
	raw, _ := v.(string)
	out := examinedToken{raw: raw}
	if raw == "" {
		return out
	}
	claims := jose.Claims(raw)
	out.acr, _ = claims["acr"].(string)
	out.scope, _ = claims["scope"].(string)
	out.clientID, _ = claims["client_id"].(string)
	return out
}

func stringsOf(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasScope(scope, need string) bool {
	return contains(strings.Fields(scope), need)
}

// scopeFor is this bank's view of which scope an action needs. It is the PDP's mapping,
// not the resource's and not the PEP's: the resource said which scopes exist, the PEP
// said which action was attempted, and the policy joins the two.
func scopeFor(action string) string {
	switch action {
	case "get_balance", "list_accounts":
		return "accounts:read"
	case "make_payment", "debit", "credit", "open_account":
		return "payments:write"
	}
	return ""
}

func deny(reason string) map[string]any {
	return map[string]any{"decision": false, "context": map[string]any{"reason": reason}}
}

type authzenRequest struct {
	Subject struct {
		Type       string         `json:"type"`
		ID         string         `json:"id"`
		Properties map[string]any `json:"properties"`
	} `json:"subject"`
	Action struct {
		Name string `json:"name"`
	} `json:"action"`
	Resource map[string]any `json:"resource"`
	Context  map[string]any `json:"context"`
}

// pdp serves one PDP stub. It answers on every path it might ever advertise plus the
// AuthZEN defaults, and its metadata says which one it wants used right now.
// pdp serves one PDP stub: its metadata, and AuthZEN's two endpoint names under every
// base it might ever advertise them at. batching says whether it claims to do batch at
// all — a PDP that does not is what makes a PEP refuse rather than guess.
func pdp(e *entity, rec *recorder, st *state, batching bool, serve func(*entity, *http.ServeMux), decide func(authzenRequest) map[string]any) {
	mux := http.NewServeMux()
	// AuthZEN 1.0 §9: the well-known segment goes after the host, and the identifier's
	// own path follows it. For http://host:9002/tenants/bank-a that is
	// /.well-known/authzen-configuration/tenants/bank-a.
	mux.HandleFunc("/.well-known/authzen-configuration"+e.base, func(w http.ResponseWriter, _ *http.Request) {
		at := e.origin + st.eval(e.name)
		doc := map[string]any{
			"policy_decision_point":      e.id,
			"access_evaluation_endpoint": at + evaluationPath,
		}
		if batching {
			doc["access_evaluations_endpoint"] = at + evaluationsPath
		}
		writeJSON(w, doc)
	})

	outage := func(w http.ResponseWriter, r *http.Request) bool {
		if !st.isDown(e.name) {
			return false
		}
		log.Printf("%-10s DOWN — %s answered 503", e.name, r.URL.Path)
		rec.add(e.name, "POST", r.URL.Path, "outage", "503 — the PDP is down")
		http.Error(w, `{"error":"pdp unavailable"}`, http.StatusServiceUnavailable)
		return true
	}
	evaluate := func(w http.ResponseWriter, r *http.Request) {
		if outage(w, r) {
			return
		}
		var req authzenRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		out := decide(req)
		log.Printf("%-10s %s by %s (for %v) -> decision=%v", e.name, req.Action.Name, req.Subject.ID, req.Subject.Properties["on_behalf_of"], out["decision"])
		reason, _ := out["context"].(map[string]any)["reason"].(string)
		rec.add(e.name, "decision", fmt.Sprintf("%s for %v", req.Action.Name, valueOr(req.Subject.Properties["on_behalf_of"], req.Subject.ID)), "verdict",
			fmt.Sprintf("%v — %s", out["decision"], reason))
		rec.add(e.name, "context", describeContext(req.Context), "input", "")
		writeJSON(w, out)
	}
	batch := func(w http.ResponseWriter, r *http.Request) {
		if outage(w, r) {
			return
		}
		var body struct {
			Evaluations []authzenRequest `json:"evaluations"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		out := make([]any, 0, len(body.Evaluations))
		names := make([]string, 0, len(body.Evaluations))
		for _, req := range body.Evaluations {
			out = append(out, decide(req))
			names = append(names, req.Action.Name)
		}
		log.Printf("%-10s batch of %d: %s", e.name, len(out), strings.Join(names, ", "))
		rec.add(e.name, "decision", fmt.Sprintf("batch of %d: %s", len(out), strings.Join(names, ", ")), "verdict",
			fmt.Sprintf("%d evaluations in one call", len(out)))
		writeJSON(w, map[string]any{"evaluations": out})
	}

	// AuthZEN's endpoint names, under this PDP's own base and under any base it may
	// relocate to. A PEP that never read the metadata would post under the identifier's
	// base; one that did follows the move. Both are served, so neither 404s.
	bases := map[string]bool{e.base: true, st.eval(e.name): true, movedBase: true}
	for b := range bases {
		mux.HandleFunc(b+evaluationPath, evaluate)
		if batching {
			mux.HandleFunc(b+evaluationsPath, batch)
		}
	}
	serve(e, mux)
}

// describeContext is one line on what the PDP was given to reason with, for the trace.
func describeContext(c map[string]any) string {
	parts := []string{}
	if meta, ok := c["resource_metadata"].(map[string]any); ok {
		src, _ := c["resource_metadata_source"].(string)
		req := []string{}
		if acr := stringsOf(meta["acr_values_required"]); len(acr) > 0 {
			req = append(req, "acr "+strings.Join(acr, "|"))
		}
		if sc := stringsOf(meta["scopes_supported"]); len(sc) > 0 {
			req = append(req, "scopes "+strings.Join(sc, " "))
		}
		parts = append(parts, fmt.Sprintf("resource (%s) requires %s", src, strings.Join(req, ", ")))
	} else {
		parts = append(parts, "no resource metadata forwarded")
	}
	if r, ok := c["request"].(map[string]any); ok {
		parts = append(parts, fmt.Sprintf("endpoint %v %v", r["method"], r["path"]))
	}
	if tok := examineToken(c["access_token"]); tok.raw != "" {
		parts = append(parts, fmt.Sprintf("token acr=%s scope=%q", tok.acr, tok.scope))
	} else {
		parts = append(parts, "no token forwarded")
	}
	return strings.Join(parts, " · ")
}

func valueOr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

// mcpUpstream answers MCP `tools/list` with one tool whose mapping is a boxcar: a
// transfer is a debit and a credit, and the profile says both are evaluated in one
// call. That is what needs a PDP's advertised batch endpoint.
func mcpUpstream(e *entity) http.HandlerFunc {
	const tools = `{"jsonrpc":"2.0","id":1,"result":{"tools":[
	  {"name":"transfer","description":"move money between two accounts",
	   "inputSchema":{"type":"object","x-authzen-mapping":{"evaluations":{
	     "subject":{"type":"identity","id":"$token.sub"},
	     "context":{"agent":"$token.?client_id"},
	     "evaluations":[
	       {"action":{"name":"debit"},"resource":{"type":"account","id":"$params.arguments.from"}},
	       {"action":{"name":"credit"},"resource":{"type":"account","id":"$params.arguments.to"}}
	     ]}}}}]}}`
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tools))
	}
}

// upstreamAPI is what a permitted request would reach: the protected resource itself.
func upstreamAPI(e *entity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"resource": e.id, "served": r.Method + " " + r.URL.Path, "principal": r.Header.Get("X-Auth-Principal")})
	}
}

// ---------- the event feed the console traces ----------

type recorder struct {
	mu     sync.Mutex
	seq    int64
	events []event
}

type event struct {
	Seq    int64  `json:"seq"`
	At     string `json:"at"`
	Entity string `json:"entity"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Kind   string `json:"kind"` // metadata | decision | verdict | control | other
	Note   string `json:"note,omitempty"`
}

const maxEvents = 4096

func (r *recorder) add(entity, method, path, kind, note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.events = append(r.events, event{Seq: r.seq, At: time.Now().UTC().Format(time.RFC3339Nano),
		Entity: entity, Method: method, Path: path, Kind: kind, Note: note})
	if len(r.events) > maxEvents {
		r.events = r.events[len(r.events)-maxEvents:]
	}
}

func (r *recorder) since(seq int64) (int64, []event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event, 0, 16)
	for _, e := range r.events {
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return r.seq, out
}

// kindOf classifies a request so the console can colour it without parsing paths.
func kindOf(path string) string {
	switch {
	case strings.HasPrefix(path, "/.well-known/"), strings.HasPrefix(path, "/fetch"):
		return "metadata"
	case strings.HasPrefix(path, "/mcp"):
		return "tools"
	case strings.Contains(path, "/access/v1/"):
		return "decision"
	default:
		return "other"
	}
}

func logged(name string, rec *recorder, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			log.Printf("%-10s %s %s", name, r.Method, r.URL.RequestURI())
			rec.add(name, r.Method, r.URL.RequestURI(), kindOf(r.URL.Path), "")
		}
		h.ServeHTTP(w, r)
	})
}

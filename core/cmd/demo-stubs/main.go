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
//	:9002  pdp-a       Bank A's PDP. Denies mallory; steps up payments over 1000
//	:9003  rogue-pdp   permits everything, advertises no batch endpoint, and says so
//	:9004  plain       not federated; RFC 9728 metadata names Bank A's PDP
//	:9005  impostor    not federated; RFC 9728 metadata names the rogue PDP
//	:9006  broken      federated, but signs with a key the anchor never vouched for
//	:9007  stray       no metadata of any kind
//	:9008  pdp-b       Bank B's PDP. Same denials, but steps up payments over 100
//	:9009  bank-b      not federated; RFC 9728 metadata names Bank B's PDP
//	:9099  control     the event feed the console traces, and the levers it pulls
//	                   (clear of the entity block, and of the ports desktop apps squat on)
//
// Every resource also answers MCP `tools/list` at /mcp, declaring one tool whose
// mapping is a boxcar — two evaluations in one call. That is what exercises a PDP's
// advertised batch endpoint, and what fails closed against a PDP with none.
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

// defaultEvalPath is the path AuthZEN 1.0 tells a PEP to assume when a PDP publishes no
// metadata at all. Every PDP here answers on it as well as on the one it advertises, so
// the trace shows plainly which path a PEP chose and why.
const (
	defaultEvalPath  = "/access/v1/evaluation"
	defaultBatchPath = "/access/v1/evaluations"
)

type entity struct {
	name string
	port int
	id   string
	key  *ecdsa.PrivateKey
	jwk  map[string]any
}

func newEntity(name string, port int, host string) *entity {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	jwk, _ := jose.PublicJWK(key)
	return &entity{name: name, port: port, id: fmt.Sprintf("http://%s:%d", host, port), key: key, jwk: jwk}
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
	// pdpEval maps a PDP's name to the path its metadata currently advertises.
	pdpEval map[string]string
	// resourcePDPs maps a resource's name to the PDP identifiers its metadata names.
	resourcePDPs map[string][]string
	// defaults, for reset.
	defEval map[string]string
	defRes  map[string][]string
}

func (s *state) eval(pdp string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pdpEval[pdp]
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
		eval[k] = v
	}
	res := map[string][]string{}
	for k, v := range s.resourcePDPs {
		res[k] = append([]string{}, v...)
	}
	return map[string]any{"pdp_evaluation_path": eval, "resource_pdps": res}
}

func main() {
	host := env("STUB_HOST", "localhost")
	base, _ := strconv.Atoi(env("STUB_PORT", "9000"))
	rec := &recorder{}

	anchor := newEntity("anchor", base, host)
	member := newEntity("member", base+1, host)
	pdpA := newEntity("pdp-a", base+2, host)
	rogue := newEntity("rogue-pdp", base+3, host)
	plain := newEntity("plain", base+4, host)
	impostor := newEntity("impostor", base+5, host)
	broken := newEntity("broken", base+6, host)
	stray := newEntity("stray", base+7, host)
	pdpB := newEntity("pdp-b", base+8, host)
	bankB := newEntity("bank-b", base+9, host)
	// The key the anchor vouches for `broken` is not the one it signs with.
	brokenAsserted := newEntity("broken-asserted", base+6, host)

	st := &state{
		pdpEval:      map[string]string{pdpA.name: "/decide", pdpB.name: "/decide", rogue.name: "/anything-goes"},
		resourcePDPs: map[string][]string{plain.name: {pdpA.id}, impostor.name: {rogue.id}, bankB.name: {pdpB.id}, member.name: {rogue.id, pdpA.id}, broken.name: {rogue.id}},
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
		// The federation's constraint on every member: only Bank A's PDP may decide.
		policy := map[string]any{"oauth_resource": map[string]any{param: map[string]any{"subset_of": []any{pdpA.id}, "essential": true}}}
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
	resource := func(e *entity, federated bool, hasMetadata bool) {
		mux := http.NewServeMux()
		if federated {
			mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				iat, exp := times()
				pdps := make([]any, 0)
				for _, p := range st.pdps(e.name) {
					pdps = append(pdps, p)
				}
				writeStatement(w, e.sign(map[string]any{
					"iss": e.id, "sub": e.id, "iat": iat, "exp": exp,
					"jwks":            map[string]any{"keys": []any{e.jwk}},
					"metadata":        map[string]any{"oauth_resource": map[string]any{"resource": e.id, param: pdps}},
					"authority_hints": []any{anchor.id},
				}))
			})
		}
		if hasMetadata {
			mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, map[string]any{"resource": e.id, param: st.pdps(e.name)})
			})
		}
		mux.HandleFunc("/mcp", mcpUpstream(e))
		mux.HandleFunc("/", upstreamAPI(e))
		serve(e, mux)
	}
	resource(member, true, true)
	resource(broken, true, true)
	resource(plain, false, true)
	resource(impostor, false, true)
	resource(bankB, false, true)
	resource(stray, false, false)

	// ---- PDPs ----------------------------------------------------------------------
	// Bank A and Bank B run the same product with different thresholds — the ordinary
	// reason two resources in one estate answer to two PDPs.
	customerPolicy := func(stepUpOver float64) func(authzenRequest) map[string]any {
		return func(req authzenRequest) map[string]any {
			who := fmt.Sprintf("%v", req.Subject.Properties["on_behalf_of"])
			if who == "" || who == "<nil>" {
				who = req.Subject.ID
			}
			if strings.HasPrefix(strings.ToLower(who), "mallory") {
				return deny(fmt.Sprintf("%s is not a customer of this bank", who))
			}
			if req.Action.Name == "make_payment" {
				if amt, ok := req.Context["amount"].(float64); ok && amt > stepUpOver {
					return map[string]any{"decision": false, "context": map[string]any{
						"reason":           fmt.Sprintf("payments over %.0f need the customer's approval", stepUpOver),
						"step_up_required": true, "step_up_scope": "payments:approve"}}
				}
			}
			return map[string]any{"decision": true, "context": map[string]any{"reason": fmt.Sprintf("%s may %s", who, req.Action.Name)}}
		}
	}
	pdp(pdpA, rec, st, "/decide-batch", serve, customerPolicy(1000))
	pdp(pdpB, rec, st, "/decide-batch", serve, customerPolicy(100))
	// The rogue PDP advertises NO batch endpoint, so a PEP asked to boxcar against it
	// has nothing to send to and must refuse rather than guess a path.
	pdp(rogue, rec, st, "", serve, func(req authzenRequest) map[string]any {
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
				// Bank A's PDP starts advertising a different evaluation endpoint. It
				// still answers on the old one, so nothing breaks mid-flight; the trace
				// is what shows the PEPs following.
				st.pdpEval[pdpA.name] = "/decide-v2"
			case "repoint_plain":
				// The plain resource is handed over to Bank B's PDP. No PEP is touched.
				st.resourcePDPs[plain.name] = []string{pdpB.id}
			case "reset":
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
func pdp(e *entity, rec *recorder, st *state, batchPath string, serve func(*entity, *http.ServeMux), decide func(authzenRequest) map[string]any) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/authzen-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"policy_decision_point":      e.id,
			"access_evaluation_endpoint": e.id + st.eval(e.name),
		}
		if batchPath != "" {
			doc["access_evaluations_endpoint"] = e.id + batchPath
		}
		writeJSON(w, doc)
	})

	evaluate := func(w http.ResponseWriter, r *http.Request) {
		var req authzenRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		out := decide(req)
		log.Printf("%-10s %s by %s (for %v) -> decision=%v", e.name, req.Action.Name, req.Subject.ID, req.Subject.Properties["on_behalf_of"], out["decision"])
		reason, _ := out["context"].(map[string]any)["reason"].(string)
		rec.add(e.name, "decision", fmt.Sprintf("%s for %v", req.Action.Name, valueOr(req.Subject.Properties["on_behalf_of"], req.Subject.ID)), "verdict",
			fmt.Sprintf("%v — %s", out["decision"], reason))
		writeJSON(w, out)
	}
	batch := func(w http.ResponseWriter, r *http.Request) {
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

	// Every evaluation path this PDP might advertise, plus the AuthZEN defaults.
	for _, p := range []string{"/decide", "/decide-v2", "/anything-goes", defaultEvalPath} {
		mux.HandleFunc(p, evaluate)
	}
	if batchPath != "" {
		mux.HandleFunc(batchPath, batch)
		mux.HandleFunc(defaultBatchPath, batch)
	}
	serve(e, mux)
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
	case strings.Contains(path, "decide") || strings.Contains(path, "anything-goes") || strings.Contains(path, "/access/v1/"):
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

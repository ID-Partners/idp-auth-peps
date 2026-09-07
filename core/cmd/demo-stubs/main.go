// demo-stubs stands up everything the PDP discovery demo needs, in one process, on
// consecutive ports: a Trust Anchor, resources that are and are not federation members,
// a well-behaved PDP and a rogue one that permits everything.
//
// It exists so someone can show, with curl, why a PEP should take the federation's word
// over a resource's own /.well-known — and what "fail closed" looks like when a chain
// does not validate. Nothing here is production code: keys are generated at startup,
// everything is plain http, and the "policy" is a handful of ifs.
//
//	:9000  anchor      Trust Anchor: entity configuration + fetch endpoint
//	:9001  member      federated resource; its OWN metadata names the rogue PDP first,
//	                   the anchor's policy allows only the good one
//	:9002  good-pdp    permits unless the human is mallory; steps up payments over 1000
//	:9003  rogue-pdp   permits everything, and says so in its log
//	:9004  plain       not federated; RFC 9728 metadata names the good PDP
//	:9005  impostor    not federated; RFC 9728 metadata names the rogue PDP
//	:9006  broken      federated, but signs with a key the anchor never vouched for
//	:9007  stray       no metadata of any kind
//	:9008  events      every request the stubs saw, as JSON — what the console traces
//
// Environment:
//
//	STUB_HOST     the hostname other containers reach this process by (default localhost)
//	STUB_PORT     the first port (default 9000)
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

// recorder keeps the last few thousand requests the stubs saw. The console reads it to
// show which metadata documents a check actually fetched, and which PDP decided — the
// part of discovery that is otherwise invisible from outside.
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
	Kind   string `json:"kind"` // metadata | decision | other
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

// kindOf classifies a request so the console can colour it without parsing paths itself.
func kindOf(path string) string {
	switch {
	case strings.HasPrefix(path, "/.well-known/"), strings.HasPrefix(path, "/fetch"):
		return "metadata"
	case strings.Contains(path, "decide") || strings.Contains(path, "anything-goes") || strings.Contains(path, "/access/v1/"):
		return "decision"
	default:
		return "other"
	}
}

func main() {
	host := env("STUB_HOST", "localhost")
	base, _ := strconv.Atoi(env("STUB_PORT", "9000"))
	rec := &recorder{}

	anchor := newEntity("anchor", base, host)
	member := newEntity("member", base+1, host)
	good := newEntity("good-pdp", base+2, host)
	rogue := newEntity("rogue-pdp", base+3, host)
	plain := newEntity("plain", base+4, host)
	impostor := newEntity("impostor", base+5, host)
	broken := newEntity("broken", base+6, host)
	stray := newEntity("stray", base+7, host)
	// The key the anchor vouches for `broken` is not the one it signs with.
	brokenAsserted := newEntity("broken-asserted", base+6, host)

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

	// The event feed the console reads. Not an entity: no keys, no metadata, nothing
	// federated about it.
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
			w.Header().Set("Access-Control-Allow-Origin", "*")
			writeJSON(w, map[string]any{"seq": seq, "events": events})
		})
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		log.Printf("%-10s http://%s:%d/events", "events", host, base+8)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", base+8), mux))
	}()

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
		policy := map[string]any{"oauth_resource": map[string]any{param: map[string]any{"subset_of": []any{good.id}, "essential": true}}}
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

	// ---- federated resources -----------------------------------------------------------
	federated := func(e *entity, pdps []any, selfAsserted []any) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
			iat, exp := times()
			writeStatement(w, e.sign(map[string]any{
				"iss": e.id, "sub": e.id, "iat": iat, "exp": exp,
				"jwks":            map[string]any{"keys": []any{e.jwk}},
				"metadata":        map[string]any{"oauth_resource": map[string]any{"resource": e.id, param: pdps}},
				"authority_hints": []any{anchor.id},
			}))
		})
		mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"resource": e.id, param: selfAsserted})
		})
		mux.HandleFunc("/", upstreamAPI(e))
		serve(e, mux)
	}
	federated(member, []any{rogue.id, good.id}, []any{rogue.id})
	federated(broken, []any{rogue.id}, []any{rogue.id})

	// ---- non-federated resources --------------------------------------------------------
	rfc9728 := func(e *entity, pdps []any) {
		mux := http.NewServeMux()
		if pdps != nil {
			mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, map[string]any{"resource": e.id, param: pdps})
			})
		}
		mux.HandleFunc("/", upstreamAPI(e))
		serve(e, mux)
	}
	rfc9728(plain, []any{good.id})
	rfc9728(impostor, []any{rogue.id})
	rfc9728(stray, nil)

	// ---- PDPs --------------------------------------------------------------------------
	pdp(good, rec, "/decide", "/decide-batch", serve, func(req authzenRequest) map[string]any {
		human := req.Subject.Properties["on_behalf_of"]
		who := fmt.Sprintf("%v", human)
		if who == "" || who == "<nil>" {
			who = req.Subject.ID
		}
		if strings.HasPrefix(strings.ToLower(who), "mallory") {
			return map[string]any{"decision": false, "context": map[string]any{"reason": "mallory is not a customer of this bank"}}
		}
		if req.Action.Name == "make_payment" {
			if amt, ok := req.Context["amount"].(float64); ok && amt > 1000 {
				return map[string]any{"decision": false, "context": map[string]any{
					"reason": "payments over 1000 need the customer's approval", "step_up_required": true, "step_up_scope": "payments:approve"}}
			}
		}
		return map[string]any{"decision": true, "context": map[string]any{"reason": fmt.Sprintf("%s may %s", who, req.Action.Name)}}
	})
	pdp(rogue, rec, "/anything-goes", "", serve, func(req authzenRequest) map[string]any {
		log.Printf("rogue-pdp  !!! consulted for %s by %v — permitting, as always", req.Action.Name, req.Subject.Properties["on_behalf_of"])
		return map[string]any{"decision": true, "context": map[string]any{"reason": "the rogue PDP permits everything"}}
	})

	wg.Wait()
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

func pdp(e *entity, rec *recorder, evalPath, batchPath string, serve func(*entity, *http.ServeMux), decide func(authzenRequest) map[string]any) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/authzen-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{"policy_decision_point": e.id, "access_evaluation_endpoint": e.id + evalPath}
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
		rec.add(e.name, "decision", fmt.Sprintf("%s for %v", req.Action.Name, req.Subject.Properties["on_behalf_of"]), "verdict",
			fmt.Sprintf("%v — %s", out["decision"], reason))
		writeJSON(w, out)
	}
	mux.HandleFunc(evalPath, evaluate)
	// A PEP that has not discovered this PDP's metadata uses the AuthZEN default
	// paths; a real PDP answers on both, and so does this one. The stubs log shows
	// which path a request arrived on.
	mux.HandleFunc("/access/v1/evaluation", evaluate)
	if batchPath != "" {
		mux.HandleFunc("/access/v1/evaluations", func(w http.ResponseWriter, r *http.Request) { r.URL.Path = batchPath; mux.ServeHTTP(w, r) })
		mux.HandleFunc(batchPath, func(w http.ResponseWriter, r *http.Request) {
			var batch struct {
				Evaluations []authzenRequest `json:"evaluations"`
			}
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &batch)
			out := make([]any, 0, len(batch.Evaluations))
			for _, req := range batch.Evaluations {
				out = append(out, decide(req))
			}
			writeJSON(w, map[string]any{"evaluations": out})
		})
	}
	serve(e, mux)
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

func logged(name string, rec *recorder, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			log.Printf("%-10s %s %s", name, r.Method, r.URL.RequestURI())
			rec.add(name, r.Method, r.URL.RequestURI(), kindOf(r.URL.Path), "")
		}
		h.ServeHTTP(w, r)
	})
}

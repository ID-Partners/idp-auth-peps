package federation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// An in-process federation: every entity is an httptest server whose URL is its
// Entity Identifier, serving its Entity Configuration and, for superiors, a fetch
// endpoint. Claims are built per request so a test can mutate an entity mid-flight.
type entity struct {
	t        *testing.T
	id       string
	key      *ecdsa.PrivateKey
	jwk      map[string]any
	hints    []string
	metadata map[string]any
	subs     map[string]*subordinate
	srv      *httptest.Server
	hits     int32

	// Knobs for negative tests.
	signWith crypto.Signer                                // key used to sign; default key
	ssSign   crypto.Signer                                // key for subordinate statements; default signWith
	ecHook   func(hdr, claims map[string]any)             // mutate the entity configuration
	ssHook   func(sub string, hdr, claims map[string]any) // mutate a subordinate statement
	ecStatus int                                          // non-zero: reply with this status
	ecBody   string                                       // non-empty: reply with this raw body
}

type subordinate struct {
	policy      map[string]any
	policyCrit  []any
	constraints map[string]any
	metadata    map[string]any
	keys        []map[string]any // default: the child's key
}

func newEntity(t *testing.T) *entity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := jose.PublicJWK(key)
	e := &entity{t: t, key: key, jwk: jwk, subs: map[string]*subordinate{}, metadata: map[string]any{}}
	e.signWith = key
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-federation", e.serveEC)
	mux.HandleFunc("/fetch", e.serveFetch)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	e.id = e.srv.URL
	return e
}

func (e *entity) now() int64 { return time.Now().Unix() }

func (e *entity) sign(hdr, claims map[string]any, key crypto.Signer) string {
	tok, err := jose.Sign(hdr, claims, key)
	if err != nil {
		// An alg the signer refuses (none, HS*): emit it unsigned so the resolver
		// gets to reject it.
		h, _ := json.Marshal(hdr)
		c, _ := json.Marshal(claims)
		return jose.B64URLEncode(h) + "." + jose.B64URLEncode(c) + "."
	}
	return tok
}

func (e *entity) header() map[string]any {
	return map[string]any{"alg": "ES256", "typ": typEntityStatement, "kid": e.jwk["kid"]}
}

func (e *entity) ecClaims() map[string]any {
	c := map[string]any{
		"iss": e.id, "sub": e.id,
		"iat": e.now() - 10, "exp": e.now() + 3600,
		"jwks": map[string]any{"keys": []any{e.jwk}},
	}
	meta := map[string]any{}
	for k, v := range e.metadata {
		meta[k] = v
	}
	if len(e.subs) > 0 {
		meta[entityTypeFedEnt] = map[string]any{"federation_fetch_endpoint": e.id + "/fetch"}
	}
	if len(meta) > 0 {
		c["metadata"] = meta
	}
	if len(e.hints) > 0 {
		hints := make([]any, 0, len(e.hints))
		for _, h := range e.hints {
			hints = append(hints, h)
		}
		c["authority_hints"] = hints
	}
	return c
}

func (e *entity) serveEC(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&e.hits, 1)
	if e.ecStatus != 0 {
		w.WriteHeader(e.ecStatus)
		return
	}
	if e.ecBody != "" {
		w.Write([]byte(e.ecBody))
		return
	}
	hdr, claims := e.header(), e.ecClaims()
	if e.ecHook != nil {
		e.ecHook(hdr, claims)
	}
	w.Header().Set("Content-Type", contentType)
	w.Write([]byte(e.sign(hdr, claims, e.signWith)))
}

func (e *entity) serveFetch(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&e.hits, 1)
	sub := r.URL.Query().Get("sub")
	s, ok := e.subs[sub]
	if !ok {
		w.WriteHeader(404)
		return
	}
	keys := s.keys
	claims := map[string]any{
		"iss": e.id, "sub": sub,
		"iat": e.now() - 10, "exp": e.now() + 1800,
		"jwks": map[string]any{"keys": toAny(keys)},
	}
	if s.policy != nil {
		claims["metadata_policy"] = s.policy
	}
	if s.policyCrit != nil {
		claims["metadata_policy_crit"] = s.policyCrit
	}
	if s.constraints != nil {
		claims["constraints"] = s.constraints
	}
	if s.metadata != nil {
		claims["metadata"] = s.metadata
	}
	hdr := e.header()
	if e.ssHook != nil {
		e.ssHook(sub, hdr, claims)
	}
	key := e.ssSign
	if key == nil {
		key = e.signWith
	}
	w.Header().Set("Content-Type", contentType)
	w.Write([]byte(e.sign(hdr, claims, key)))
}

func toAny(keys []map[string]any) []any {
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, k)
	}
	return out
}

// subordinate registers child under e, with the child's own key by default.
func (e *entity) subordinate(child *entity, s *subordinate) *subordinate {
	if s == nil {
		s = &subordinate{}
	}
	if s.keys == nil {
		s.keys = []map[string]any{child.jwk}
	}
	e.subs[child.id] = s
	child.hints = append(child.hints, e.id)
	return s
}

func (e *entity) anchor() TrustAnchor {
	return TrustAnchor{EntityID: e.id, Keys: []map[string]any{e.jwk}}
}

// A three-level federation: leaf -> intermediate -> anchor, the leaf an oauth_resource
// naming two PDPs.
type fed struct {
	leaf, mid, anchor *entity
}

func threeLevel(t *testing.T) fed {
	t.Helper()
	anchor, mid, leaf := newEntity(t), newEntity(t), newEntity(t)
	leaf.metadata["oauth_resource"] = map[string]any{
		"resource":                       leaf.id,
		"authzen_policy_decision_points": []any{"https://pdp.good.example", "https://pdp.rogue.example"},
	}
	mid.subordinate(leaf, nil)
	anchor.subordinate(mid, nil)
	return fed{leaf: leaf, mid: mid, anchor: anchor}
}

func newResolver(t *testing.T, o Options, anchors ...*entity) *Resolver {
	t.Helper()
	for _, a := range anchors {
		o.TrustAnchors = append(o.TrustAnchors, a.anchor())
	}
	o.AllowInsecure = true
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func pdps(res Resolved) []any {
	v, _ := res.Metadata["oauth_resource"]["authzen_policy_decision_points"].([]any)
	return v
}

func mustContain(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want error containing %q, got %v", want, err)
	}
}

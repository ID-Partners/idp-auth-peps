package federation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

const param = "authzen_policy_decision_points"

// A PEP-held entity under a fixture anchor. The anchor vouches for the entity's key and
// says what the resource requires; the entity itself asserts next to nothing.
func newHeldEntity(t *testing.T, anchor *entity) (*Entity, *httptest.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &Entity{Key: key, Lifetime: time.Hour, Asserted: map[string]any{param: []any{"https://static.example/pdp"}}}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	e.ID = srv.URL
	if anchor != nil {
		e.AuthorityHints = []string{anchor.id}
		e.Resolver = newResolver(t, Options{AllowInsecure: true, TTL: time.Minute, NegativeTTL: time.Millisecond}, anchor)
	}
	fedPath, resPath := e.Paths()
	mux.Handle(fedPath, e.Handler())
	mux.Handle(resPath, e.Handler())
	return e, srv
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestEntityConfigurationIsMinimalAndSelfSigned(t *testing.T) {
	anchor := newEntity(t)
	e, srv := newHeldEntity(t, anchor)
	resp, body := get(t, srv.URL+WellKnown)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != contentType {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	st, err := parseStatement(body, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsEntityConfiguration() || st.Sub != e.ID || len(st.AuthorityHints) != 1 || st.AuthorityHints[0] != anchor.id {
		t.Fatalf("%+v", st)
	}
	if err := st.verifyWith(st.JWKS); err != nil {
		t.Fatalf("self-signed: %v", err)
	}
	pub, _ := e.PublicJWK()
	if st.JWKS[0]["kid"] != pub["kid"] {
		t.Fatal("the published key must be the entity's")
	}
	// Minimal: the entity type and its identifier, nothing the controller maintains.
	meta := st.Metadata[EntityTypeResource]
	if len(meta) != 1 || meta["resource"] != e.ID {
		t.Fatalf("entity configuration metadata must be minimal: %v", meta)
	}
	if _, ok := st.Claims["metadata"].(map[string]any)["federation_entity"]; ok {
		t.Fatal("a leaf publishes no federation_entity metadata")
	}
	// Minted once, reused within the lifetime.
	again, _ := e.Configuration()
	if again != body {
		t.Fatal("the configuration should be cached, not re-minted per request")
	}
}

func TestEntityRepublishesWhatTheControllerResolved(t *testing.T) {
	anchor := newEntity(t)
	e, srv := newHeldEntity(t, anchor)
	_, resPath := e.Paths()

	// Not yet onboarded: self-asserted, and only what the PEP is configured with.
	resp, body := get(t, srv.URL+resPath)
	if resp.StatusCode != 200 || resp.Header.Get("X-Resource-Metadata-Source") != "self" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("X-Resource-Metadata-Source"))
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(body), &doc)
	if doc["resource"] != e.ID || doc["scopes_supported"] != nil {
		t.Fatalf("before onboarding: %v", doc)
	}
	if pd, _ := doc[param].([]any); len(pd) != 1 || pd[0] != "https://static.example/pdp" {
		t.Fatalf("before onboarding the PDP is the configured one: %v", doc[param])
	}
	pub, _ := e.PublicJWK()
	signed, _ := doc["signed_metadata"].(string)
	if err := jose.VerifyJWS(signed, pub, "ES256"); err != nil {
		t.Fatalf("signed_metadata must verify with the entity's key: %v", err)
	}
	if c := jose.Claims(signed); c["iss"] != e.ID || c["resource"] != e.ID || c["signed_metadata"] != nil {
		t.Fatalf("signed_metadata claims: %v", c)
	}

	// The controller onboards the entity: vouches for its key, and says what the
	// resource requires and who decides for it.
	pubKey, _ := e.PublicJWK()
	anchor.subs[e.ID] = &subordinate{
		keys: []map[string]any{pubKey},
		metadata: map[string]any{EntityTypeResource: map[string]any{
			param: []any{"https://pdp.controller.example"}, "scopes_supported": []any{"accounts:read"},
			"acr_values_required": []any{"urn:idp:loa:mfa"}, "resource": "https://not-yours.example",
			"signed_metadata": "nope",
		}},
		policy: map[string]any{EntityTypeResource: map[string]any{param: map[string]any{"subset_of": []any{"https://pdp.controller.example"}}}},
	}
	time.Sleep(5 * time.Millisecond) // past the (1ms) negative cache of the failed chain
	resp, body = get(t, srv.URL+resPath)
	if resp.Header.Get("X-Resource-Metadata-Source") != "federation" {
		t.Fatalf("after onboarding the document is the federation's: %s", body)
	}
	_ = json.Unmarshal([]byte(body), &doc)
	if pd, _ := doc[param].([]any); len(pd) != 1 || pd[0] != "https://pdp.controller.example" {
		t.Fatalf("%v", doc)
	}
	if sc, _ := doc["scopes_supported"].([]any); len(sc) != 1 || doc["resource"] != e.ID {
		t.Fatalf("the controller's metadata is republished, the identifier stays the entity's: %v", doc)
	}
	signed, _ = doc["signed_metadata"].(string)
	if err := jose.VerifyJWS(signed, pub, "ES256"); err != nil || jose.Claims(signed)["signed_metadata"] != nil {
		t.Fatalf("signed_metadata after onboarding: %v", err)
	}
	if c := jose.Claims(signed); c["acr_values_required"] == nil {
		t.Fatalf("signed_metadata carries the resolved parameters: %v", c)
	}
}

func TestEntityWithoutResolverAndWithPathIdentifier(t *testing.T) {
	e, _ := newHeldEntity(t, nil)
	e.ID = "https://api.example/bank/"
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	fedPath, resPath := e.Paths()
	if fedPath != "/bank/.well-known/openid-federation" || resPath != "/.well-known/oauth-protected-resource/bank" {
		t.Fatalf("%s %s", fedPath, resPath)
	}
	doc, source, err := e.ProtectedResourceMetadata(context.Background())
	if err != nil || source != "self" || doc["resource"] != e.ID {
		t.Fatalf("%v %s %v", doc, source, err)
	}
	tok, _ := e.Configuration()
	if c := jose.Claims(tok); c["iat"] != float64(1_700_000_000) || c["exp"] != float64(1_700_000_000+3600) {
		t.Fatalf("lifetime: %v", c)
	}
	// The handler answers only its two paths, and only to GET/HEAD.
	mux := http.NewServeMux()
	mux.Handle(fedPath, e.Handler())
	mux.Handle(resPath, e.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if resp, _ := get(t, srv.URL+fedPath); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := get(t, srv.URL+"/bank/.well-known/other"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	resp, err := http.Post(srv.URL+fedPath, "text/plain", strings.NewReader("x"))
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("%v %v", resp, err)
	}
	resp.Body.Close()
	// A key the JOSE layer cannot use is an error, not a panic.
	bad := &Entity{ID: "https://x.example", Key: nil}
	if _, err := bad.Configuration(); err == nil {
		t.Fatal("nil key must fail")
	}
	if _, _, err := bad.ProtectedResourceMetadata(context.Background()); err == nil {
		t.Fatal("nil key must fail")
	}
	rec := httptest.NewRecorder()
	bad.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-federation", nil))
	rec2 := httptest.NewRecorder()
	bad.Handler().ServeHTTP(rec2, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil))
	if rec.Code != 500 || rec2.Code != 500 {
		t.Fatalf("%d %d", rec.Code, rec2.Code)
	}
}

func TestResolveLeaf(t *testing.T) {
	f := threeLevel(t)
	r := newResolver(t, Options{AllowInsecure: true}, f.anchor)
	// The leaf's own configuration, handed over rather than fetched.
	_, ec := get(t, f.leaf.id+WellKnown)
	before := f.leaf.hits
	res, err := r.ResolveLeaf(context.Background(), ec)
	if err != nil || res.Subject != f.leaf.id || res.TrustAnchor != f.anchor.id {
		t.Fatalf("%+v %v", res, err)
	}
	if f.leaf.hits != before {
		t.Fatal("ResolveLeaf must not fetch the leaf")
	}
	if _, err := r.ResolveLeaf(context.Background(), ec); err != nil {
		t.Fatal(err)
	}
	// Garbage, a subordinate statement, and a forged signature are all invalid chains.
	_, ss := get(t, f.mid.id+"/fetch?sub="+f.leaf.id)
	for name, raw := range map[string]string{"garbage": "not.a.jwt", "subordinate": ss, "forged": ec[:len(ec)-4] + "AAAA"} {
		if _, err := r.ResolveLeaf(context.Background(), raw); !errors.Is(err, ErrInvalidChain) {
			t.Errorf("%s: want ErrInvalidChain, got %v", name, err)
		}
	}
	// A leaf the anchor has not onboarded has no chain: the anchor's fetch endpoint
	// knows nothing about it.
	lone := newEntity(t)
	lone.hints = []string{f.anchor.id}
	_, loneEC := get(t, lone.id+WellKnown)
	if _, err := r.ResolveLeaf(context.Background(), loneEC); err == nil || !strings.Contains(err.Error(), "no trust chain") {
		t.Fatalf("unknown leaf: %v", err)
	}
}

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/federation"
	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

func ctx() context.Context { return context.Background() }

// pdpServer serves an authzen-configuration (or not) and counts hits.
type pdpServer struct {
	*httptest.Server
	hits   int32
	config func(self string) any // nil: 404
	status int
}

func newPDP(t *testing.T, config func(self string) any) *pdpServer {
	t.Helper()
	p := &pdpServer{config: config}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&p.hits, 1)
		if p.status != 0 {
			w.WriteHeader(p.status)
			return
		}
		if r.URL.Path != "/.well-known/authzen-configuration" || p.config == nil {
			w.WriteHeader(404)
			return
		}
		if s, ok := p.config(p.URL).(string); ok {
			w.Write([]byte(s))
			return
		}
		json.NewEncoder(w).Encode(p.config(p.URL))
	}))
	t.Cleanup(p.Close)
	return p
}

func fullConfig(self string) any {
	return map[string]any{
		"policy_decision_point":       self,
		"access_evaluation_endpoint":  self + "/custom/eval",
		"access_evaluations_endpoint": self + "/custom/evals",
		"capabilities":                []string{"urn:x:batch"},
	}
}

// resourceServer serves an RFC 9728 document.
func newResource(t *testing.T, doc func(self string) any) *pdpServer {
	t.Helper()
	p := &pdpServer{config: doc}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&p.hits, 1)
		if p.status != 0 {
			w.WriteHeader(p.status)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") || p.config == nil {
			w.WriteHeader(404)
			return
		}
		if s, ok := p.config(p.URL).(string); ok {
			w.Write([]byte(s))
			return
		}
		json.NewEncoder(w).Encode(p.config(p.URL))
	}))
	t.Cleanup(p.Close)
	return p
}

func quiet(o Options) Options {
	o.AllowInsecure = true
	o.Logf = func(string, ...any) {}
	return o
}

func mustNew(t *testing.T, o Options) *Chain {
	t.Helper()
	c, err := New(quiet(o))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeOff, "off": ModeOff, " AuthZEN ": ModeAuthZEN, "resource": ModeResource, "federation": ModeFederation} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Fatalf("%q -> %q %v", in, got, err)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Fatal("bogus mode accepted")
	}
}

func TestWellKnownURL(t *testing.T) {
	cases := map[string]string{
		"https://pdp.example":         "https://pdp.example/.well-known/authzen-configuration",
		"https://pdp.example/":        "https://pdp.example/.well-known/authzen-configuration",
		"https://pdp.example/tenant1": "https://pdp.example/.well-known/authzen-configuration/tenant1",
		"https://pdp.example/t/1/":    "https://pdp.example/.well-known/authzen-configuration/t/1",
		"https://pdp.example:8443/x":  "https://pdp.example:8443/.well-known/authzen-configuration/x",
	}
	for in, want := range cases {
		got, err := WellKnownURL(in, wellKnownPDP)
		if err != nil || got != want {
			t.Fatalf("%s -> %s (%v), want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"pdp.example", "/relative", "https://pdp.example/?x=1", "https://pdp.example/#f", "https:///x"} {
		if _, err := WellKnownURL(bad, wellKnownPDP); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestOffModeMakesNoRequests(t *testing.T) {
	pdp := newPDP(t, fullConfig)
	c := Static(pdp.URL+"/", "key")
	ep, err := c.Resolve(ctx(), "https://any.example")
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultEndpoints(pdp.URL)
	want.APIKey, want.Source = "key", "static"
	if !reflect.DeepEqual(ep, want) || atomic.LoadInt32(&pdp.hits) != 0 {
		t.Fatalf("ep=%+v hits=%d", ep, pdp.hits)
	}
	if _, err := Static("", "").Resolve(ctx(), ""); !errors.Is(err, ErrNoPDP) {
		t.Fatalf("no static PDP: %v", err)
	}
	if s := c.Status(); s.Mode != ModeOff || len(s.Sources) != 0 {
		t.Fatalf("status %+v", s)
	}
}

func TestAuthZENMode(t *testing.T) {
	pdp := newPDP(t, fullConfig)
	c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL, APIKeys: map[string]string{pdp.URL: "key"}})
	for i := 0; i < 2; i++ {
		ep, err := c.Resolve(ctx(), "https://ignored.example")
		if err != nil {
			t.Fatal(err)
		}
		if ep.Evaluation != pdp.URL+"/custom/eval" || ep.Evaluations != pdp.URL+"/custom/evals" || ep.APIKey != "key" || !reflect.DeepEqual(ep.Capabilities, []string{"urn:x:batch"}) {
			t.Fatalf("ep=%+v", ep)
		}
	}
	if atomic.LoadInt32(&pdp.hits) != 1 {
		t.Fatalf("config should be fetched once: %d", pdp.hits)
	}
	if err := c.Warm(ctx()); err != nil {
		t.Fatal(err)
	}
	if s := c.Status(); !s.PDPs[pdp.URL].Cached {
		t.Fatalf("status %+v", s)
	}
	if _, err := mustNew(t, Options{Mode: ModeAuthZEN}).Resolve(ctx(), ""); !errors.Is(err, ErrNoPDP) {
		t.Fatalf("no static PDP: %v", err)
	}
}

func TestPDPConfigFallbacksAndRejections(t *testing.T) {
	t.Run("404 uses defaults", func(t *testing.T) {
		pdp := newPDP(t, nil)
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL})
		ep, err := c.Resolve(ctx(), "")
		if err != nil || ep.Evaluation != pdp.URL+"/access/v1/evaluation" || ep.Evaluations != pdp.URL+"/access/v1/evaluations" {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("500 uses defaults", func(t *testing.T) {
		pdp := newPDP(t, fullConfig)
		pdp.status = 500
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL})
		if ep, err := c.Resolve(ctx(), ""); err != nil || ep.Evaluation != pdp.URL+"/access/v1/evaluation" {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("unreachable uses defaults", func(t *testing.T) {
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: "http://127.0.0.1:1"})
		if ep, err := c.Resolve(ctx(), ""); err != nil || ep.Evaluation != "http://127.0.0.1:1/access/v1/evaluation" {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("identifier mismatch is invalid", func(t *testing.T) {
		pdp := newPDP(t, func(self string) any {
			m := fullConfig(self).(map[string]any)
			m["policy_decision_point"] = "https://other.example"
			return m
		})
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL})
		_, err := c.Resolve(ctx(), "")
		if !errors.Is(err, ErrNoPDP) || !strings.Contains(err.Error(), "policy_decision_point") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("missing evaluation endpoint is invalid", func(t *testing.T) {
		pdp := newPDP(t, func(self string) any { return map[string]any{"policy_decision_point": self} })
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL})
		if _, err := c.Resolve(ctx(), ""); !errors.Is(err, ErrNoPDP) || !strings.Contains(err.Error(), "access_evaluation_endpoint") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("not JSON is invalid", func(t *testing.T) {
		pdp := newPDP(t, func(string) any { return "<html>" })
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL})
		if _, err := c.Resolve(ctx(), ""); !errors.Is(err, ErrNoPDP) || !strings.Contains(err.Error(), "not JSON") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("endpoint outside the allowlist", func(t *testing.T) {
		pdp := newPDP(t, func(self string) any {
			m := fullConfig(self).(map[string]any)
			m["access_evaluations_endpoint"] = "https://elsewhere.example/evals"
			return m
		})
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL, PDPAllowed: func(u string) bool { return strings.HasPrefix(u, pdp.URL) }})
		if _, err := c.Resolve(ctx(), ""); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("static PDP outside the allowlist", func(t *testing.T) {
		pdp := newPDP(t, fullConfig)
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL, PDPAllowed: func(string) bool { return false }})
		if _, err := c.Resolve(ctx(), ""); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("static PDP with a query is invalid", func(t *testing.T) {
		c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: "http://pdp.example/?x=1"})
		if _, err := c.Resolve(ctx(), ""); !errors.Is(err, ErrNoPDP) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("http static PDP is same-origin trusted without AllowInsecure", func(t *testing.T) {
		pdp := newPDP(t, fullConfig)
		c, err := New(Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL, Logf: func(string, ...any) {}})
		if err != nil {
			t.Fatal(err)
		}
		if ep, err := c.Resolve(ctx(), ""); err != nil || ep.Evaluation != pdp.URL+"/custom/eval" {
			t.Fatalf("%+v %v", ep, err)
		}
	})
}

func TestResourceMode(t *testing.T) {
	good := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	res := newResource(t, func(self string) any {
		return map[string]any{"resource": self, ParamPolicyDecisionPoints: []string{good.URL + "/"}, "ignored": true}
	})
	opts := Options{Mode: ModeResource, StaticPDP: static.URL, APIKeys: map[string]string{static.URL: "static-key"}}

	t.Run("resource names its PDP; static key not relayed", func(t *testing.T) {
		c := mustNew(t, opts)
		ep, err := c.Resolve(ctx(), res.URL)
		if err != nil {
			t.Fatal(err)
		}
		if ep.Identifier != good.URL || ep.Evaluation != good.URL+"/custom/eval" || ep.APIKey != "" {
			t.Fatalf("%+v", ep)
		}
		if atomic.LoadInt32(&static.hits) != 0 {
			t.Fatal("static PDP should not be consulted")
		}
		// Cached per resource.
		c.Resolve(ctx(), res.URL)
		if atomic.LoadInt32(&res.hits) != 1 {
			t.Fatalf("resource metadata fetched %d times", res.hits)
		}
		if s := c.Status(); !s.Resources[res.URL].Cached || !reflect.DeepEqual(s.Sources, []string{"rfc9728"}) {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("empty resource uses static", func(t *testing.T) {
		ep, err := mustNew(t, opts).Resolve(ctx(), "")
		if err != nil || ep.Identifier != static.URL || ep.APIKey != "static-key" {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("no metadata falls to static", func(t *testing.T) {
		plain := newResource(t, nil)
		ep, err := mustNew(t, opts).Resolve(ctx(), plain.URL)
		if err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("metadata without the parameter falls to static", func(t *testing.T) {
		r := newResource(t, func(self string) any { return map[string]any{"resource": self} })
		ep, err := mustNew(t, opts).Resolve(ctx(), r.URL)
		if err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("resource echo mismatch is invalid, falls to static", func(t *testing.T) {
		r := newResource(t, func(self string) any {
			return map[string]any{"resource": "https://impostor.example", ParamPolicyDecisionPoints: []string{good.URL}}
		})
		ep, err := mustNew(t, opts).Resolve(ctx(), r.URL)
		if err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("bad entries are invalid", func(t *testing.T) {
		r := newResource(t, func(self string) any {
			return map[string]any{"resource": self, ParamPolicyDecisionPoints: []any{"not a url", 1}}
		})
		ep, err := mustNew(t, opts).Resolve(ctx(), r.URL)
		if err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("not JSON is invalid", func(t *testing.T) {
		r := newResource(t, func(string) any { return "<html>" })
		if ep, err := mustNew(t, opts).Resolve(ctx(), r.URL); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("transport error falls to static", func(t *testing.T) {
		r := newResource(t, fullConfig)
		r.status = 500
		if ep, err := mustNew(t, opts).Resolve(ctx(), r.URL); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("resource with a query is invalid", func(t *testing.T) {
		if ep, err := mustNew(t, opts).Resolve(ctx(), "http://r.example/?x"); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("first candidate bad, second good", func(t *testing.T) {
		bad := newPDP(t, func(self string) any { return map[string]any{"policy_decision_point": "https://x"} })
		r := newResource(t, func(self string) any {
			return map[string]any{"resource": self, ParamPolicyDecisionPoints: []string{bad.URL, good.URL}}
		})
		ep, err := mustNew(t, opts).Resolve(ctx(), r.URL)
		if err != nil || ep.Identifier != good.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("disallowed resource fails closed with no fetch", func(t *testing.T) {
		o := opts
		o.ResourceAllowed = func(string) bool { return false }
		r := newResource(t, fullConfig)
		if _, err := mustNew(t, o).Resolve(ctx(), r.URL); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
		if atomic.LoadInt32(&r.hits) != 0 {
			t.Fatal("the resource must not be fetched")
		}
	})
	t.Run("discovered PDP outside the allowlist fails closed", func(t *testing.T) {
		o := opts
		o.PDPAllowed = func(u string) bool { return strings.HasPrefix(u, static.URL) }
		if _, err := mustNew(t, o).Resolve(ctx(), res.URL); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("nothing at all", func(t *testing.T) {
		plain := newResource(t, nil)
		c := mustNew(t, Options{Mode: ModeResource})
		if _, err := c.Resolve(ctx(), plain.URL); !errors.Is(err, ErrNoPDP) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("stale served while the resource is down", func(t *testing.T) {
		now := time.Now()
		o := opts
		o.TTL = time.Minute
		o.Now = func() time.Time { return now }
		r := newResource(t, func(self string) any {
			return map[string]any{"resource": self, ParamPolicyDecisionPoints: []string{good.URL}}
		})
		c := mustNew(t, o)
		if ep, err := c.Resolve(ctx(), r.URL); err != nil || ep.Identifier != good.URL {
			t.Fatalf("%+v %v", ep, err)
		}
		r.status = 500
		now = now.Add(2 * time.Minute)
		ep, err := c.Resolve(ctx(), r.URL)
		if err != nil || ep.Identifier != good.URL {
			t.Fatalf("stale list should be served: %+v %v", ep, err)
		}
	})
	t.Run("federation mode without a resolver", func(t *testing.T) {
		if _, err := New(Options{Mode: ModeFederation}); err == nil {
			t.Fatal("want error")
		}
	})
}

// A minimal two-entity federation: anchor -> resource, the resource an oauth_resource.
type miniFed struct {
	anchor, leaf   *httptest.Server
	anchorKey      *ecdsa.PrivateKey
	anchorJWK      map[string]any
	leafKey        *ecdsa.PrivateKey
	leafJWK        map[string]any
	policy         map[string]any
	leafPDPs       []any
	leafStatus     int
	leafNoResource bool
	breakLeafSig   bool
}

func newMiniFed(t *testing.T) *miniFed {
	t.Helper()
	f := &miniFed{}
	f.anchorKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.anchorJWK, _ = jose.PublicJWK(f.anchorKey)
	f.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.leafJWK, _ = jose.PublicJWK(f.leafKey)
	now := time.Now().Unix()
	sign := func(key *ecdsa.PrivateKey, jwk map[string]any, claims map[string]any) string {
		tok, err := jose.Sign(map[string]any{"alg": "ES256", "typ": "entity-statement+jwt", "kid": jwk["kid"]}, claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	f.leaf = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.leafStatus != 0 {
			w.WriteHeader(f.leafStatus)
			return
		}
		meta := map[string]any{}
		if !f.leafNoResource {
			meta["oauth_resource"] = map[string]any{ParamPolicyDecisionPoints: f.leafPDPs}
		}
		key := f.leafKey
		if f.breakLeafSig {
			key = f.anchorKey
		}
		w.Write([]byte(sign(key, f.leafJWK, map[string]any{
			"iss": f.leaf.URL, "sub": f.leaf.URL, "iat": now - 10, "exp": now + 3600,
			"jwks": map[string]any{"keys": []any{f.leafJWK}}, "metadata": meta,
			"authority_hints": []any{f.anchor.URL},
		})))
	}))
	t.Cleanup(f.leaf.Close)
	f.anchor = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" {
			claims := map[string]any{
				"iss": f.anchor.URL, "sub": f.leaf.URL, "iat": now - 10, "exp": now + 3600,
				"jwks": map[string]any{"keys": []any{f.leafJWK}},
			}
			if f.policy != nil {
				claims["metadata_policy"] = f.policy
			}
			w.Write([]byte(sign(f.anchorKey, f.anchorJWK, claims)))
			return
		}
		w.Write([]byte(sign(f.anchorKey, f.anchorJWK, map[string]any{
			"iss": f.anchor.URL, "sub": f.anchor.URL, "iat": now - 10, "exp": now + 3600,
			"jwks":     map[string]any{"keys": []any{f.anchorJWK}},
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": f.anchor.URL + "/fetch"}},
		})))
	}))
	t.Cleanup(f.anchor.Close)
	return f
}

func (f *miniFed) resolver(t *testing.T) *federation.Resolver {
	t.Helper()
	r, err := federation.New(federation.Options{
		TrustAnchors:  []federation.TrustAnchor{{EntityID: f.anchor.URL, Keys: []map[string]any{f.anchorJWK}}},
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFederationMode(t *testing.T) {
	good := newPDP(t, fullConfig)
	rogue := newPDP(t, fullConfig)
	static := newPDP(t, nil)

	t.Run("policy strips the rogue PDP", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafPDPs = []any{rogue.URL, good.URL}
		f.policy = map[string]any{"oauth_resource": map[string]any{ParamPolicyDecisionPoints: map[string]any{"subset_of": []any{good.URL}}}}
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		ep, err := c.Resolve(ctx(), f.leaf.URL)
		if err != nil || ep.Identifier != good.URL || ep.Evaluation != good.URL+"/custom/eval" {
			t.Fatalf("%+v %v", ep, err)
		}
		if atomic.LoadInt32(&rogue.hits) != 0 {
			t.Fatal("the rogue PDP must never be contacted")
		}
		if s := c.Status(); !reflect.DeepEqual(s.Sources, []string{"federation"}) {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("not federated falls to static", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafStatus = 404
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("invalid chain fails closed", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafPDPs = []any{good.URL}
		f.breakLeafSig = true
		static := newPDP(t, nil)
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		if _, err := c.Resolve(ctx(), f.leaf.URL); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
		if atomic.LoadInt32(&static.hits) != 0 {
			t.Fatal("static must not be consulted after an invalid chain")
		}
	})
	t.Run("fetch refused fails closed", func(t *testing.T) {
		f := newMiniFed(t)
		r, _ := federation.New(federation.Options{
			TrustAnchors:  []federation.TrustAnchor{{EntityID: f.anchor.URL, Keys: []map[string]any{f.anchorJWK}}},
			AllowInsecure: true,
			FetchAllowed:  func(string) bool { return false },
		})
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: r})
		if _, err := c.Resolve(ctx(), f.leaf.URL); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the resource allowlist governs federation lookups too", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafPDPs = []any{good.URL}
		calls := 0
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t),
			ResourceAllowed: func(string) bool { calls++; return false }})
		if _, err := c.Resolve(ctx(), f.leaf.URL); !errors.Is(err, ErrNotAllowed) || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	t.Run("federated but no oauth_resource metadata falls to static", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafNoResource = true
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("federated with an empty list falls to static", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafPDPs = []any{}
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("transient federation error falls to static", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafStatus = 500
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != static.URL {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("federation never consults rfc9728", func(t *testing.T) {
		f := newMiniFed(t)
		f.leafStatus = 404
		c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
		for _, s := range c.Status().Sources {
			if s == "rfc9728" {
				t.Fatal("rfc9728 must not be a federation-mode source")
			}
		}
	})
}

func TestSourcesOverride(t *testing.T) {
	pdp := newPDP(t, nil)
	c := mustNew(t, Options{Mode: ModeResource, StaticPDP: "http://static.example", Sources: []MetadataSource{&fakeSource{pdps: []string{pdp.URL}}}})
	if s := c.Status(); !reflect.DeepEqual(s.Sources, []string{"fake"}) {
		t.Fatalf("%+v", s)
	}
	ep, err := c.Resolve(ctx(), "http://r.example")
	if err != nil || ep.Identifier != pdp.URL {
		t.Fatalf("%+v %v", ep, err)
	}
}

type fakeSource struct {
	pdps []string
	err  error
}

func (fakeSource) Name() string                                      { return "fake" }
func (f *fakeSource) PDPs(context.Context, string) ([]string, error) { return f.pdps, f.err }

func TestSourceErrorHandling(t *testing.T) {
	pdp := newPDP(t, fullConfig)
	t.Run("transient error logged, static used, not cached as the answer", func(t *testing.T) {
		var logged []string
		src := &fakeSource{err: fmt.Errorf("boom")}
		o := quiet(Options{Mode: ModeResource, StaticPDP: pdp.URL, MinRefresh: time.Second, Sources: []MetadataSource{src}})
		o.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
		c, _ := New(o)
		if ep, err := c.Resolve(ctx(), "http://r.example"); err != nil || ep.Identifier != pdp.URL {
			t.Fatalf("%+v %v", ep, err)
		}
		if len(logged) != 1 || !strings.Contains(logged[0], "boom") {
			t.Fatalf("logged %v", logged)
		}
		if s := c.Status(); s.Resources["http://r.example"].Cached {
			t.Fatal("a transient failure must not be cached as the resource's answer")
		}
	})
	t.Run("invalid metadata logged, static cached as the answer", func(t *testing.T) {
		var logged []string
		o := quiet(Options{Mode: ModeResource, StaticPDP: pdp.URL, Sources: []MetadataSource{&fakeSource{err: fmt.Errorf("%w: bad", ErrInvalid)}}})
		o.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
		c, _ := New(o)
		if ep, err := c.Resolve(ctx(), "http://r.example"); err != nil || ep.Identifier != pdp.URL {
			t.Fatalf("%+v %v", ep, err)
		}
		if len(logged) != 1 || !strings.Contains(logged[0], "bad") {
			t.Fatalf("logged %v", logged)
		}
		if s := c.Status(); !s.Resources["http://r.example"].Cached {
			t.Fatal("invalid metadata resolves to static and that is cached")
		}
	})
	t.Run("static candidate that resolves to nothing", func(t *testing.T) {
		bad := newPDP(t, func(self string) any { return map[string]any{"policy_decision_point": "https://x"} })
		c := mustNew(t, Options{Mode: ModeResource, StaticPDP: bad.URL, Sources: []MetadataSource{&fakeSource{err: fmt.Errorf("boom")}}})
		if _, err := c.Resolve(ctx(), "http://r.example"); !errors.Is(err, ErrNoPDP) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("last error reported when nothing resolves", func(t *testing.T) {
		c := mustNew(t, Options{Mode: ModeResource, Sources: []MetadataSource{&fakeSource{err: fmt.Errorf("boom")}}})
		_, err := c.Resolve(ctx(), "http://r.example")
		if !errors.Is(err, ErrNoPDP) || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("static source empty", func(t *testing.T) {
		if _, err := (StaticSource{}).PDPs(ctx(), ""); !errors.Is(err, ErrNoMetadata) {
			t.Fatal(err)
		}
	})
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
	"github.com/ID-Partners/idp-auth-peps/core/coaz"
	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// A PDP stub that serves an authzen-configuration and records evaluation paths.
type discoPDP struct {
	*httptest.Server
	paths []string
	hits  int32
}

func newDiscoPDP(t *testing.T, withConfig bool) *discoPDP {
	t.Helper()
	p := &discoPDP{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&p.hits, 1)
		if r.URL.Path == "/.well-known/authzen-configuration" {
			if !withConfig {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"policy_decision_point":      p.URL,
				"access_evaluation_endpoint": p.URL + "/custom/eval",
			})
			return
		}
		p.paths = append(p.paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	t.Cleanup(p.Close)
	return p
}

// A protected resource serving RFC 9728 metadata that names pdp. When asMCP, it also
// answers tools/list so it can stand in as an MCP upstream.
func newDiscoResource(t *testing.T, pdp string, asMCP bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource" {
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL, discovery.ParamPolicyDecisionPoints: []string{pdp}})
			return
		}
		if asMCP {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_customer",
			  "inputSchema":{"x-authzen-mapping":{"evaluation":{
			    "subject":{"type":"identity","id":"$token.sub"},
			    "action":{"name":"get_customer"},
			    "resource":{"type":"customer","id":"$params.arguments.id"}}}}}]}}`))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func resourceChain(t *testing.T, static string, mode discovery.Mode) *discovery.Chain {
	t.Helper()
	c, err := discovery.New(discovery.Options{Mode: mode, StaticPDP: static, AllowInsecure: true, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type errResolver struct{ err error }

func (e errResolver) Resolve(context.Context, string) (discovery.PDPEndpoints, error) {
	return discovery.PDPEndpoints{}, e.err
}

func TestResourceIDFallbacks(t *testing.T) {
	if got := configFrom(map[string]string{"resource": "https://api.example/"}).resourceID(); got != "https://api.example" {
		t.Fatalf("explicit resource (trailing slash trimmed): %q", got)
	}
	if got := configFrom(map[string]string{"style": "mcp", "mcp_upstream_url": "http://mcp:8090/mcp"}).resourceID(); got != "http://mcp:8090/mcp" {
		t.Fatalf("mcp route falls back to the upstream: %q", got)
	}
	if got := configFrom(map[string]string{"style": "mcp", "mcp_upstream_url": "http://mcp:8090/mcp", "resource": "https://r"}).resourceID(); got != "https://r" {
		t.Fatalf("explicit resource wins on mcp routes: %q", got)
	}
	if got := configFrom(map[string]string{"style": "rest"}).resourceID(); got != "" {
		t.Fatalf("rest without resource is static: %q", got)
	}
}

func TestEvaluateUsesTheResolvedEndpoint(t *testing.T) {
	pdp := newDiscoPDP(t, true)
	s := newServer(t, "http://static.invalid")
	s.resolver = resourceChain(t, pdp.URL, discovery.ModeAuthZEN)
	out, err := s.evaluate(context.Background(), "", map[string]any{"subject": map[string]any{}})
	if err != nil || !out.Decision {
		t.Fatalf("%+v %v", out, err)
	}
	if len(pdp.paths) != 1 || pdp.paths[0] != "/custom/eval" {
		t.Fatalf("resolved endpoint not used: %v", pdp.paths)
	}
}

func TestEvaluateWithoutAResolverIsStatic(t *testing.T) {
	pdp := newDiscoPDP(t, true)
	s := newServer(t, pdp.URL)
	s.resolver = nil
	if _, err := s.evaluate(context.Background(), "https://ignored", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if len(pdp.paths) != 1 || pdp.paths[0] != "/access/v1/evaluation" {
		t.Fatalf("nil resolver must mean the default path: %v", pdp.paths)
	}
}

func TestCheckFailsClosedWhenNoPDPResolves(t *testing.T) {
	s := newServer(t, "http://static.invalid")
	s.resolver = errResolver{err: discovery.ErrNoPDP}
	conf := restConf(nil)
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	resp := s.check(context.Background(), conf, "GET", "/accounts/a1/balance", headers, "")
	if deniedStatus(resp) != 503 {
		t.Fatalf("want 503 fail-closed, got %d: %s", deniedStatus(resp), resp.GetDeniedResponse().GetBody())
	}
}

func TestCheckRESTRouteDiscoversItsPDP(t *testing.T) {
	static := newDiscoPDP(t, false)
	discovered := newDiscoPDP(t, true)
	resource := newDiscoResource(t, discovered.URL, false)

	s := newServer(t, static.URL)
	s.resolver = resourceChain(t, static.URL, discovery.ModeResource)
	conf := restConf(map[string]string{"resource": resource.URL})
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}

	resp := s.check(context.Background(), conf, "GET", "/accounts/a1/balance", headers, "")
	if resp.GetDeniedResponse() != nil {
		t.Fatalf("should permit: %s", resp.GetDeniedResponse().GetBody())
	}
	if len(discovered.paths) != 1 || discovered.paths[0] != "/custom/eval" {
		t.Fatalf("the discovered PDP's endpoint should be used: %v", discovered.paths)
	}
	if atomic.LoadInt32(&static.hits) != 0 {
		t.Fatal("the static PDP must not be consulted")
	}
	// A route without `resource` still goes to the static PDP.
	s.check(context.Background(), restConf(nil), "GET", "/accounts/a1/balance", headers, "")
	if len(static.paths) != 1 {
		t.Fatalf("rest route without resource should use the static PDP: %v", static.paths)
	}
}

func TestCheckMCPRouteUsesUpstreamAsResource(t *testing.T) {
	static := newDiscoPDP(t, false)
	discovered := newDiscoPDP(t, true)
	mcp := newDiscoResource(t, discovered.URL, true)

	chain := resourceChain(t, static.URL, discovery.ModeResource)
	s := newServer(t, static.URL)
	s.resolver = chain
	s.coaz = coaz.NewEngine(coaz.Options{Resolver: chain})

	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcp.URL})
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer","arguments":{"id":"c1"}}}`
	resp := s.check(context.Background(), conf, "POST", "/mcp", headers, body)
	if resp.GetDeniedResponse() != nil {
		t.Fatalf("should permit: %s", resp.GetDeniedResponse().GetBody())
	}
	if len(discovered.paths) != 1 || discovered.paths[0] != "/custom/eval" || atomic.LoadInt32(&static.hits) != 0 {
		t.Fatalf("discovered=%v static hits=%d", discovered.paths, static.hits)
	}
}

func TestCheckDeniesAResourceOutsideTheAllowlist(t *testing.T) {
	static := newDiscoPDP(t, false)
	var fetched int32
	resource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { atomic.AddInt32(&fetched, 1) }))
	defer resource.Close()
	c, err := discovery.New(discovery.Options{
		Mode: discovery.ModeResource, StaticPDP: static.URL, AllowInsecure: true, Logf: func(string, ...any) {},
		ResourceAllowed: func(string) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(t, static.URL)
	s.resolver = c
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	resp := s.check(context.Background(), restConf(map[string]string{"resource": resource.URL}), "GET", "/accounts/a1/balance", headers, "")
	if deniedStatus(resp) != 503 || atomic.LoadInt32(&fetched) != 0 || atomic.LoadInt32(&static.hits) != 0 {
		t.Fatalf("status=%d fetched=%d static=%d", deniedStatus(resp), fetched, static.hits)
	}
}

// ---------- federation end to end ----------

// A two-entity federation: anchor -> leaf (an oauth_resource).
type fedFixture struct {
	anchor, leaf *httptest.Server
	anchorKey    *ecdsa.PrivateKey
	anchorJWK    map[string]any
	leafKey      *ecdsa.PrivateKey
	leafJWK      map[string]any
	pdps         []any
	policy       map[string]any
	breakLeaf    bool
}

func newFedFixture(t *testing.T) *fedFixture {
	t.Helper()
	f := &fedFixture{}
	f.anchorKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.anchorJWK, _ = jose.PublicJWK(f.anchorKey)
	f.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.leafJWK, _ = jose.PublicJWK(f.leafKey)
	now := time.Now().Unix()
	sign := func(key *ecdsa.PrivateKey, jwk map[string]any, claims map[string]any) []byte {
		tok, err := jose.Sign(map[string]any{"alg": "ES256", "typ": "entity-statement+jwt", "kid": jwk["kid"]}, claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(tok)
	}
	f.leaf = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := f.leafKey
		if f.breakLeaf {
			key = f.anchorKey
		}
		_, _ = w.Write(sign(key, f.leafJWK, map[string]any{
			"iss": f.leaf.URL, "sub": f.leaf.URL, "iat": now - 10, "exp": now + 3600,
			"jwks":            map[string]any{"keys": []any{f.leafJWK}},
			"metadata":        map[string]any{"oauth_resource": map[string]any{discovery.ParamPolicyDecisionPoints: f.pdps}},
			"authority_hints": []any{f.anchor.URL},
		}))
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
			_, _ = w.Write(sign(f.anchorKey, f.anchorJWK, claims))
			return
		}
		_, _ = w.Write(sign(f.anchorKey, f.anchorJWK, map[string]any{
			"iss": f.anchor.URL, "sub": f.anchor.URL, "iat": now - 10, "exp": now + 3600,
			"jwks":     map[string]any{"keys": []any{f.anchorJWK}},
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": f.anchor.URL + "/fetch"}},
		}))
	}))
	t.Cleanup(f.anchor.Close)
	return f
}

func (f *fedFixture) anchorsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchors.json")
	raw, _ := json.Marshal(map[string]any{f.anchor.URL: map[string]any{"keys": []any{f.anchorJWK}}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fedEnv(f *fedFixture, t *testing.T, static string, extra map[string]string) func(string) string {
	m := map[string]string{
		"AUTHZEN_URL":                   static,
		"PDP_DISCOVERY":                 "federation",
		"PDP_DISCOVERY_INSECURE":        "true",
		"FEDERATION_TRUST_ANCHORS_FILE": f.anchorsFile(t),
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func TestFederationEndToEnd(t *testing.T) {
	static := newDiscoPDP(t, false)
	good := newDiscoPDP(t, true)
	rogue := newDiscoPDP(t, true)
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}

	t.Run("the federation's policy decides which PDP is called", func(t *testing.T) {
		f := newFedFixture(t)
		f.pdps = []any{rogue.URL, good.URL}
		f.policy = map[string]any{"oauth_resource": map[string]any{discovery.ParamPolicyDecisionPoints: map[string]any{"subset_of": []any{good.URL}}}}
		s, _, _, err := buildServer(fedEnv(f, t, static.URL, map[string]string{"FEDERATION_MAX_PATH_LENGTH": "2"}))
		if err != nil {
			t.Fatal(err)
		}
		staticBefore := atomic.LoadInt32(&static.hits) // boot warm-up reads its metadata once
		resp := s.check(context.Background(), restConf(map[string]string{"resource": f.leaf.URL}), "GET", "/accounts/a1/balance", headers, "")
		if resp.GetDeniedResponse() != nil {
			t.Fatalf("should permit: %s", resp.GetDeniedResponse().GetBody())
		}
		if len(good.paths) != 1 || good.paths[0] != "/custom/eval" {
			t.Fatalf("the surviving PDP should be called: %v", good.paths)
		}
		if atomic.LoadInt32(&rogue.hits) != 0 || atomic.LoadInt32(&static.hits) != staticBefore {
			t.Fatalf("rogue=%d static moved=%v: both must be untouched by the request", rogue.hits, atomic.LoadInt32(&static.hits) != staticBefore)
		}
		if st := s.resolver.(*discovery.Chain).Status(); st.Mode != discovery.ModeFederation {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("an invalid chain fails closed and never falls to static", func(t *testing.T) {
		f := newFedFixture(t)
		f.pdps = []any{good.URL}
		f.breakLeaf = true
		s, _, _, err := buildServer(fedEnv(f, t, static.URL, nil))
		if err != nil {
			t.Fatal(err)
		}
		before := atomic.LoadInt32(&static.hits)
		resp := s.check(context.Background(), restConf(map[string]string{"resource": f.leaf.URL}), "GET", "/accounts/a1/balance", headers, "")
		if deniedStatus(resp) != 503 || atomic.LoadInt32(&static.hits) != before {
			t.Fatalf("status=%d static hits moved=%v", deniedStatus(resp), atomic.LoadInt32(&static.hits) != before)
		}
	})
	t.Run("a resource outside the federation gets the static PDP", func(t *testing.T) {
		f := newFedFixture(t)
		plain := httptest.NewServer(http.NotFoundHandler())
		defer plain.Close()
		s, _, _, err := buildServer(fedEnv(f, t, static.URL, nil))
		if err != nil {
			t.Fatal(err)
		}
		before := len(static.paths)
		resp := s.check(context.Background(), restConf(map[string]string{"resource": plain.URL}), "GET", "/accounts/a1/balance", headers, "")
		if resp.GetDeniedResponse() != nil || len(static.paths) != before+1 {
			t.Fatalf("denied=%v static paths=%v", resp.GetDeniedResponse(), static.paths)
		}
	})
	t.Run("the resource allowlist governs the subject, the fetch allowlist the climb", func(t *testing.T) {
		f := newFedFixture(t)
		f.pdps = []any{good.URL}
		// Leaf permitted only by the resource allowlist; the anchor only by the fetch allowlist.
		s, _, _, err := buildServer(fedEnv(f, t, static.URL, map[string]string{
			"RESOURCE_METADATA_ALLOWLIST": f.leaf.URL, "FEDERATION_FETCH_ALLOWLIST": f.anchor.URL}))
		if err != nil {
			t.Fatal(err)
		}
		resp := s.check(context.Background(), restConf(map[string]string{"resource": f.leaf.URL}), "GET", "/accounts/a1/balance", headers, "")
		if resp.GetDeniedResponse() != nil {
			t.Fatalf("should permit: %s", resp.GetDeniedResponse().GetBody())
		}
		// A resource outside the resource allowlist is refused before any fetch.
		resp = s.check(context.Background(), restConf(map[string]string{"resource": "http://127.0.0.1:1"}), "GET", "/accounts/a1/balance", headers, "")
		if deniedStatus(resp) != 503 {
			t.Fatalf("want 503, got %d", deniedStatus(resp))
		}
	})
	t.Run("fetch allowlist is honoured", func(t *testing.T) {
		f := newFedFixture(t)
		f.pdps = []any{good.URL}
		s, _, _, err := buildServer(fedEnv(f, t, static.URL, map[string]string{"FEDERATION_FETCH_ALLOWLIST": "https://nowhere.example"}))
		if err != nil {
			t.Fatal(err)
		}
		resp := s.check(context.Background(), restConf(map[string]string{"resource": f.leaf.URL}), "GET", "/accounts/a1/balance", headers, "")
		if deniedStatus(resp) != 503 {
			t.Fatalf("a chain that cannot be fetched under the allowlist must fail closed: %d", deniedStatus(resp))
		}
	})
}

func TestBuildServerDiscoveryConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	static := newDiscoPDP(t, true)

	t.Run("off by default, no HTTP", func(t *testing.T) {
		srv, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": static.URL}))
		if err != nil {
			t.Fatal(err)
		}
		if st := srv.resolver.(*discovery.Chain).Status(); st.Mode != discovery.ModeOff {
			t.Fatalf("%+v", st)
		}
		if atomic.LoadInt32(&static.hits) != 0 {
			t.Fatal("off mode must make no requests at boot")
		}
	})
	t.Run("authzen mode warms the static PDP", func(t *testing.T) {
		srv, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": static.URL, "PDP_DISCOVERY": "authzen", "PDP_METADATA_TTL": "1m"}))
		if err != nil {
			t.Fatal(err)
		}
		st := srv.resolver.(*discovery.Chain).Status()
		if st.Mode != discovery.ModeAuthZEN || !st.PDPs[static.URL].Cached {
			t.Fatalf("%+v", st)
		}
		ep, err := srv.resolver.Resolve(context.Background(), "")
		if err != nil || ep.Evaluation != static.URL+"/custom/eval" || ep.APIKey != "" {
			t.Fatalf("%+v %v", ep, err)
		}
	})
	t.Run("static API key is bound to the static PDP", func(t *testing.T) {
		srv, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": static.URL, "AUTHZEN_API_KEY": "k", "PDP_DISCOVERY": "resource"}))
		if err != nil {
			t.Fatal(err)
		}
		if ep, _ := srv.resolver.Resolve(context.Background(), ""); ep.APIKey != "k" {
			t.Fatalf("%+v", ep)
		}
	})
	t.Run("resource mode with allowlists", func(t *testing.T) {
		srv, _, _, err := buildServer(env(map[string]string{
			"AUTHZEN_URL": static.URL, "PDP_DISCOVERY": "resource",
			"PDP_ALLOWLIST": "https://pdp.example", "RESOURCE_METADATA_ALLOWLIST": "https://api.example",
		}))
		if err != nil {
			t.Fatal(err)
		}
		// An off-list resource is refused before any fetch.
		if _, err := srv.resolver.Resolve(context.Background(), "https://other.example"); !errors.Is(err, discovery.ErrNotAllowed) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("warm-up failure is not fatal", func(t *testing.T) {
		if _, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": "http://127.0.0.1:1", "PDP_DISCOVERY": "authzen"})); err != nil {
			t.Fatalf("a PDP that is down at boot must not stop the PEP: %v", err)
		}
	})
	t.Run("bad values", func(t *testing.T) {
		f := newFedFixture(t)
		badJSON := filepath.Join(t.TempDir(), "bad.json")
		_ = os.WriteFile(badJSON, []byte("{"), 0o600)
		cases := map[string]map[string]string{
			"unknown mode":            {"PDP_DISCOVERY": "bogus"},
			"federation without file": {"PDP_DISCOVERY": "federation"},
			"federation missing file": {"PDP_DISCOVERY": "federation", "FEDERATION_TRUST_ANCHORS_FILE": "/nonexistent/anchors.json"},
			"federation bad json":     {"PDP_DISCOVERY": "federation", "FEDERATION_TRUST_ANCHORS_FILE": badJSON},
			"federation no anchors":   {"PDP_DISCOVERY": "federation", "FEDERATION_TRUST_ANCHORS_FILE": writeFile(t, "{}")},
			"bad max path length":     {"PDP_DISCOVERY": "federation", "FEDERATION_TRUST_ANCHORS_FILE": f.anchorsFile(t), "FEDERATION_MAX_PATH_LENGTH": "-1"},
		}
		for name, extra := range cases {
			t.Run(name, func(t *testing.T) {
				m := map[string]string{"AUTHZEN_URL": static.URL}
				for k, v := range extra {
					m[k] = v
				}
				if _, _, _, err := buildServer(env(m)); err == nil {
					t.Fatal("expected a startup error")
				}
			})
		}
	})
	t.Run("bad metadata TTL falls back", func(t *testing.T) {
		if _, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": static.URL, "PDP_DISCOVERY": "authzen", "PDP_METADATA_TTL": "soon"})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("insecure flag warns but works", func(t *testing.T) {
		if _, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": static.URL, "PDP_DISCOVERY": "resource", "PDP_DISCOVERY_INSECURE": "true"})); err != nil {
			t.Fatal(err)
		}
	})
	_ = strings.TrimSpace
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

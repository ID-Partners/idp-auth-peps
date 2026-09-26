package metafetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P11: a path-scoped allowlist entry could be escaped with dot segments. The operator's
// matcher compares strings — https://p.example/tenants/a admits
// https://p.example/tenants/a/../b — while the server resolves the dots and serves
// tenant b. The policy refuses such a URL before the matcher is asked.
func TestPolicyRefusesPathsThatResolveElsewhere(t *testing.T) {
	prefix := func(p string) func(string) bool {
		return func(raw string) bool { return raw == p || strings.HasPrefix(raw, p+"/") }
	}
	p := Policy{Allow: prefix("https://p.example/tenants/a")}
	for _, raw := range []string{
		"https://p.example/tenants/a/../b",
		"https://p.example/tenants/a/%2e%2e/b",
		"https://p.example/tenants/a/%2E%2E/b/.well-known/authzen-configuration",
		"https://p.example/tenants/a/..%2Fb",
	} {
		if err := p.Check(raw, ""); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want a refusal, got %v", raw, err)
		}
	}
	if err := p.Check("https://p.example/tenants/a/x", ""); err != nil {
		t.Fatalf("a plain path under the prefix: %v", err)
	}
	// Credentials in a URL someone else's document supplied are never sent.
	if err := (Policy{}).Check("https://user:pw@p.example/x", ""); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("userinfo must be refused: %v", err)
	}
}

// The same holds hop by hop: a redirect to a dot-segment path is refused.
func TestRedirectToATraversalIsRefused(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tenants/a/doc" {
			http.Redirect(w, r, srv.URL+"/tenants/a/%2e%2e/b/doc", http.StatusFound)
			return
		}
		w.Write([]byte("tenant b"))
	}))
	defer srv.Close()
	c := New(srv.Client(), Policy{AllowInsecure: true}, "", 0)
	if _, err := c.Get(context.Background(), srv.URL+"/tenants/a/doc", ""); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("want a refusal, got %v", err)
	}
}

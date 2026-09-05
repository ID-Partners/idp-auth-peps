package metafetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyCheck(t *testing.T) {
	allowExample := func(raw string) bool { return strings.HasPrefix(raw, "https://ok.example") }
	cases := []struct {
		name    string
		p       Policy
		raw     string
		trusted string
		wantErr bool
	}{
		{"https ok", Policy{}, "https://ok.example/x", "", false},
		{"http refused", Policy{}, "http://ok.example/x", "", true},
		{"http insecure", Policy{AllowInsecure: true}, "http://ok.example/x", "", false},
		{"http same origin", Policy{}, "http://pdp:8080/.well-known/x", "http://pdp:8080", false},
		{"http other origin", Policy{}, "http://other:8080/x", "http://pdp:8080", true},
		{"http case-insensitive host", Policy{}, "http://PDP:8080/x", "http://pdp:8080", false},
		{"trusted unparsable", Policy{}, "http://pdp:8080/x", "://bad", true},
		{"relative", Policy{}, "/x", "", true},
		{"no host", Policy{}, "https:///x", "", true},
		{"ftp", Policy{}, "ftp://ok.example/x", "", true},
		{"allowlist pass", Policy{Allow: allowExample}, "https://ok.example/x", "", false},
		{"allowlist fail", Policy{Allow: allowExample}, "https://no.example/x", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Check(tc.raw, tc.trusted)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrNotAllowed) {
				t.Fatalf("policy errors must wrap ErrNotAllowed: %v", err)
			}
		})
	}
}

func TestGet(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"a":1}`))
		case "/missing":
			w.WriteHeader(404)
		case "/boom":
			w.WriteHeader(500)
		case "/big":
			w.Write(make([]byte, 100))
		case "/hop":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/away":
			http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := New(srv.Client(), Policy{AllowInsecure: true}, "", 50)

	body, err := c.Get(context.Background(), srv.URL+"/ok", "application/json")
	if err != nil || string(body) != `{"a":1}` || gotAccept != "application/json" {
		t.Fatalf("ok: %v %q accept=%q", err, body, gotAccept)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/missing", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 should be ErrNotFound: %v", err)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/boom", ""); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500: %v", err)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/big", ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize: %v", err)
	}
	if body, err := c.Get(context.Background(), srv.URL+"/hop", ""); err != nil || string(body) != `{"a":1}` {
		t.Fatalf("one redirect should be followed: %v %q", err, body)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/loop", ""); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("redirect loop should be refused: %v", err)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/away", ""); err == nil {
		t.Fatalf("redirect off-policy should fail")
	}
	// Policy is enforced before any request.
	strict := New(nil, Policy{}, "", 0)
	if _, err := strict.Get(context.Background(), srv.URL+"/ok", ""); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("http refused without AllowInsecure: %v", err)
	}
	if err := strict.Check("https://x.example/"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "http://127.0.0.1:1/", ""); err == nil {
		t.Fatal("connection refused should error")
	}
	if _, err := c.Get(context.Background(), "http://ok.example/\x7f", ""); err == nil {
		t.Fatal("bad URL should error")
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireCheckTokenRejectsWrongOrMissingCredentials(t *testing.T) {
	called := false
	h := requireCheckToken("s3cret", func(http.ResponseWriter, *http.Request) { called = true })

	cases := []struct {
		name       string
		auth       string
		wantStatus int
		wantCalled bool
	}{
		{"correct", "Bearer s3cret", http.StatusOK, true},
		{"missing", "", http.StatusUnauthorized, false},
		{"wrong", "Bearer nope", http.StatusUnauthorized, false},
		{"prefix of the real token", "Bearer s3cre", http.StatusUnauthorized, false},
		{"no scheme", "s3cret", http.StatusUnauthorized, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodPost, "/v1/mcp/check", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if called != tc.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tc.wantCalled)
			}
			if !tc.wantCalled && rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestRequireCheckTokenIsDisabledWhenUnset(t *testing.T) {
	called := false
	h := requireCheckToken("", func(http.ResponseWriter, *http.Request) { called = true })
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/mcp/check", nil))
	if !called {
		t.Fatal("an empty token should leave the endpoint open (and main() warns)")
	}
}

func TestUpstreamAllowlist(t *testing.T) {
	list := parseAllowlist("https://mcp.example.com, http://bank-mcp:8090/mcp")

	allowed := []string{
		"https://mcp.example.com",
		"https://mcp.example.com/",
		"https://mcp.example.com/tools",
		"http://bank-mcp:8090/mcp",
	}
	for _, u := range allowed {
		if !upstreamAllowed(list, u) {
			t.Errorf("expected %q to be allowed", u)
		}
	}

	blocked := []string{
		// The SSRF targets that matter: cloud metadata and loopback services.
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:9192/v1/mcp/check",
		// A neighbouring host that a naive prefix test would admit.
		"https://mcp.example.com.evil.test/mcp",
		// Scheme confusion.
		"file:///etc/passwd",
		"gopher://mcp.example.com",
		// Credentials in the URL must not buy entry.
		"https://mcp.example.com@evil.test/mcp",
		"not a url",
		"",
	}
	for _, u := range blocked {
		if upstreamAllowed(list, u) {
			t.Errorf("expected %q to be blocked", u)
		}
	}
}

func TestEmptyAllowlistPermitsEverything(t *testing.T) {
	// Pre-existing behaviour, retained so no deployment breaks silently; main() warns.
	if !upstreamAllowed(nil, "http://anything.internal/mcp") {
		t.Fatal("an empty allowlist should permit everything")
	}
}

func TestParseAllowlistSplitsOnCommasAndWhitespace(t *testing.T) {
	got := parseAllowlist("https://a.test,  https://b.test\n https://c.test/ ")
	want := []string{"https://a.test", "https://b.test", "https://c.test"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

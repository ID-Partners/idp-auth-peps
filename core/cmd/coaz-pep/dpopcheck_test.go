package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDpopReasonFromNonJSON(t *testing.T) {
	// dpopReasonFrom on a body that is not JSON returns "" — the fallback arm.
	if got := dpopReasonFrom("not json at all"); got != "" {
		t.Fatalf("a non-JSON body should yield no reason, got %q", got)
	}
	if got := dpopReasonFrom(`{"reason":"nope"}`); got != "nope" {
		t.Fatalf("a JSON reason should be extracted, got %q", got)
	}
}

func TestHTTPCheckRelaysADeniedResponse(t *testing.T) {
	// The DeniedResponse arm of handleHTTPCheck: a policy deny relayed as decision:false
	// with the rendered body.
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reason":"not allowed"}}`))
	}))
	defer pdp.Close()
	s := newServer(t, pdp.URL)

	body, _ := json.Marshal(map[string]any{
		"config": map[string]string{"style": "rest", "require_token": "true"},
		"method": "GET", "path": "/accounts/a/balance",
		"headers": map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})},
	})
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", strings.NewReader(string(body))))

	var out struct {
		Decision bool `json:"decision"`
		Response *struct {
			Body string `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Decision {
		t.Fatal("a policy deny should be relayed as decision:false")
	}
	if out.Response == nil || !strings.Contains(out.Response.Body, "not allowed") {
		t.Fatalf("the deny body should carry the reason, got %+v", out.Response)
	}
}

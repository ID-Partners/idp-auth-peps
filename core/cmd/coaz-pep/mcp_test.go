package main

// Regression tests for the production-readiness review's MCP findings: every way a
// tools/call used to reach the upstream without a PDP decision, driven through the
// service's own pipeline and the HTTP check API the Kong plugin calls.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/ID-Partners/idp-auth-peps/core/coaz"
)

const mcpToolsList = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"transfer_funds",
  "inputSchema":{"x-authzen-mapping":{"evaluation":{
    "subject":{"type":"identity","id":"$token.sub"},
    "action":{"name":"transfer_funds"},
    "resource":{"type":"account","id":"$params.arguments.from"}}}}}]}}`

const mcpCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer_funds","arguments":{"from":"acc-victim","amount":100000}}}`

// mcpSetup is a service in front of an MCP server declaring transfer_funds, asking a PDP
// that answers pdpResp.
func mcpSetup(t *testing.T, pdpResp map[string]any, mcpHandler http.HandlerFunc) (*server, *pdpStub, string) {
	t.Helper()
	if mcpHandler == nil {
		mcpHandler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mcpToolsList))
		}
	}
	mcp := httptest.NewServer(mcpHandler)
	t.Cleanup(mcp.Close)
	pdp := newPDPStub(t, pdpResp, 200)
	s := newServer(t, pdp.URL)
	s.coaz = coaz.NewEngine(coaz.Options{PDP: coaz.PDPConfig{URL: pdp.URL}})
	return s, pdp, mcp.URL
}

func mcpHeaders() map[string]string {
	return map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice", "aud": "bank", "acr": "urn:mfa"})}
}

func deniedHeader(resp *authv3.CheckResponse, name string) string {
	for _, h := range resp.GetDeniedResponse().GetHeaders() {
		if h.GetHeader().GetKey() == name {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}

// Every body the upstream could still execute as a tools/call, behind a PDP that denies
// everything. None may be permitted, and none needs the PDP to be refused.
func TestMCPRouteRefusesBodiesItCannotReadUnambiguously(t *testing.T) {
	s, pdp, mcpURL := mcpSetup(t, map[string]any{"decision": false, "context": map[string]any{"reason": "deny all"}}, nil)
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL})
	if resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), mcpCall); resp.GetOkResponse() != nil || len(pdp.requests) != 1 {
		t.Fatal("control: a plain tools/call is decided by the PDP, and denied")
	}

	padded := mcpCall[:len(mcpCall)-1] + strings.Repeat(" ", 70000) + "}"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(mcpCall))
	_ = zw.Close()
	cases := []struct {
		name    string
		body    string
		headers map[string]string
		status  typev3.StatusCode
	}{
		{"truncated at 64 KiB", padded[:65536], nil, typev3.StatusCode_BadRequest},
		{"Envoy marked the body partial", mcpCall, map[string]string{"x-envoy-auth-partial-body": "true"}, typev3.StatusCode_PayloadTooLarge},
		{"JSON-RPC batch", "[" + mcpCall + "]", nil, typev3.StatusCode_BadRequest},
		{"case-variant Method", strings.Replace(mcpCall, `"method":"tools/call",`, `"method":"tools/call","Method":"initialize",`, 1), nil, typev3.StatusCode_BadRequest},
		{"case-variant Params", strings.Replace(mcpCall, `"params":`, `"Params":{"name":"get_balance"},"params":`, 1), nil, typev3.StatusCode_BadRequest},
		{"empty body", "", nil, typev3.StatusCode_BadRequest},
		{"gzip bytes", gz.String(), nil, typev3.StatusCode_BadRequest},
		{"Content-Encoding gzip", mcpCall, map[string]string{"content-encoding": "gzip"}, typev3.StatusCode_UnsupportedMediaType},
		{"trailing object", `{"jsonrpc":"2.0","id":9,"method":"ping"}` + mcpCall, nil, typev3.StatusCode_BadRequest},
		{"byte-order mark", "\xEF\xBB\xBF" + mcpCall, nil, typev3.StatusCode_BadRequest},
		{"nameless tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`, nil, typev3.StatusCode_BadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(pdp.requests)
			h := mcpHeaders()
			for k, v := range c.headers {
				h[k] = v
			}
			resp := s.check(context.Background(), conf, "POST", "/mcp", h, c.body)
			if resp.GetOkResponse() != nil {
				t.Fatal("permitted a body the upstream could run as a tools/call")
			}
			if got := deniedStatus(resp); got != int(c.status) {
				t.Fatalf("status %d, want %d", got, c.status)
			}
			if !strings.Contains(resp.GetDeniedResponse().GetBody(), `"jsonrpc":"2.0"`) {
				t.Fatalf("a refusal on an MCP route is a JSON-RPC error: %s", resp.GetDeniedResponse().GetBody())
			}
			if len(pdp.requests) != before {
				t.Fatal("a refused body must not reach the PDP")
			}
		})
	}
}

// The HTTP check API is the same pipeline: what Kong and PingAccess delegate to.
func TestMCPRefusalsReachTheHTTPCheckAPI(t *testing.T) {
	s, pdp, mcpURL := mcpSetup(t, map[string]any{"decision": true}, nil)
	req, _ := json.Marshal(map[string]any{
		"config":  map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL},
		"method":  "POST",
		"path":    "/mcp",
		"headers": mcpHeaders(),
		"body":    "[" + mcpCall + "]",
	})
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", bytes.NewReader(req)))
	var out checkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Decision || out.Response == nil || out.Response.Status != http.StatusBadRequest || len(pdp.requests) != 0 {
		t.Fatalf("a batch through the check API must be refused with a 400 and no PDP call: %+v", out)
	}
}

func TestHTTPCheckRefusesAnOversizedRequest(t *testing.T) {
	s, _, _ := mcpSetup(t, map[string]any{"decision": true}, nil)
	big := `{"config":{},"body":"` + strings.Repeat("A", maxCheckRequestBytes) + `"}`
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", strings.NewReader(big)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized check request is refused, got %d", rec.Code)
	}
}

// Default mappings are on: every method is decided, and a method the binding does not
// know is denied without a PDP call.
func TestMCPRouteGovernsEveryMethodByDefault(t *testing.T) {
	s, pdp, mcpURL := mcpSetup(t, map[string]any{"decision": false}, nil)
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL})
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"bank://accounts/acc-victim"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"x"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`,
	} {
		before := len(pdp.requests)
		if resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), body); resp.GetOkResponse() != nil || len(pdp.requests) != before+1 {
			t.Fatalf("%s must be decided by the (denying) PDP", body)
		}
	}
	before := len(pdp.requests)
	resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), `{"jsonrpc":"2.0","id":5,"method":"future/method"}`)
	if resp.GetOkResponse() != nil || len(pdp.requests) != before || !strings.Contains(resp.GetDeniedResponse().GetBody(), "-32001") {
		t.Fatalf("an unknown method is denied outright: %s", resp.GetDeniedResponse().GetBody())
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":6,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":7,"result":{"action":"accept"}}`,
	} {
		if resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), body); resp.GetOkResponse() == nil || len(pdp.requests) != before {
			t.Fatalf("%s passes through without the PDP", body)
		}
	}
}

func TestMCPRouteTransportRequests(t *testing.T) {
	s, pdp, mcpURL := mcpSetup(t, map[string]any{"decision": false}, nil)
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL})
	for _, m := range []string{"GET", "DELETE"} {
		if resp := s.check(context.Background(), conf, m, "/mcp", mcpHeaders(), ""); resp.GetOkResponse() == nil {
			t.Fatalf("%s on the MCP endpoint is transport, token-gated", m)
		}
	}
	if resp := s.check(context.Background(), conf, "PUT", "/mcp", mcpHeaders(), mcpCall); deniedStatus(resp) != int(typev3.StatusCode_MethodNotAllowed) {
		t.Fatal("any other method is refused")
	}
	if resp := s.check(context.Background(), conf, "GET", "/mcp", map[string]string{}, ""); resp.GetOkResponse() != nil {
		t.Fatal("require_token still applies to transport requests")
	}
	if len(pdp.requests) != 0 {
		t.Fatalf("transport requests do not reach the PDP, got %d calls", len(pdp.requests))
	}
}

// With no upstream to read declarations from, a tools/call is judged by the default
// mapping — the old code let it through on a valid token.
func TestMCPRouteWithoutAnUpstreamUsesTheDefaultMapping(t *testing.T) {
	s, pdp, _ := mcpSetup(t, map[string]any{"decision": false}, nil)
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true"})
	if resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), mcpCall); resp.GetOkResponse() != nil || len(pdp.requests) != 1 {
		t.Fatal("a tools/call without an upstream must still be decided")
	}
}

// A route that opts out of default mappings keeps the pre-binding coarse check on the
// handshake, and nothing else.
func TestMCPOptOutKeepsTheCoarseHandshakeCheck(t *testing.T) {
	s, pdp, mcpURL := mcpSetup(t, map[string]any{"decision": true}, nil)
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL, "coaz_defaults": "false"})
	s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if len(pdp.requests) != 1 || pdp.requests[0]["action"].(map[string]any)["name"] != "access_mcp" {
		t.Fatalf("initialize is evaluated as access_mcp, got %v", pdp.requests)
	}
	if resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); resp.GetOkResponse() == nil || len(pdp.requests) != 1 {
		t.Fatal("with defaults off, tools/list passes through")
	}
}

// A discovery failure's detail — the internal URL, the upstream's error body — belongs
// in the log. The client is told the check was unavailable.
func TestMCPReasonDoesNotLeakUpstreamDetail(t *testing.T) {
	s, _, mcpURL := mcpSetup(t, map[string]any{"decision": true}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal: db=10.0.3.7:5432 user=svc_bank"))
	})
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL})
	resp := s.check(context.Background(), conf, "POST", "/mcp", mcpHeaders(), mcpCall)
	reason := deniedHeader(resp, "X-PDP-Reason")
	body := resp.GetDeniedResponse().GetBody()
	for _, leak := range []string{"10.0.3.7", "svc_bank", strings.TrimPrefix(mcpURL, "http://")} {
		if strings.Contains(reason, leak) || strings.Contains(body, leak) {
			t.Fatalf("client-facing text leaks %q: reason=%q body=%s", leak, reason, body)
		}
	}
	if reason == "" {
		t.Fatal("the deny should still say why, generically")
	}
}

// The X-Auth-* headers are the PEP's word on who is calling. A value it has is set over
// the client's copy; a value it does not have is removed, never left as the client sent it.
func TestPermitOwnsTheIdentityHeaders(t *testing.T) {
	resp := permit("pep", "a", "ok", identity{sub: "alice", scope: "openid", acr: "urn:mfa"})
	ok := resp.GetOkResponse()
	set := map[string]string{}
	for _, h := range ok.GetHeaders() {
		if h.GetAppendAction().String() != "OVERWRITE_IF_EXISTS_OR_ADD" {
			t.Fatalf("%s must overwrite the client's copy", h.GetHeader().GetKey())
		}
		set[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	if set["X-Auth-Principal"] != "alice" || set["X-Auth-Scope"] != "openid" || set["X-Auth-Acr"] != "urn:mfa" {
		t.Fatalf("asserted identity headers: %v", set)
	}
	if _, present := set["X-Auth-Agent"]; present {
		t.Fatal("an empty value must not be sent as a mutation: Envoy drops it and keeps the client's copy")
	}
	if len(ok.GetHeadersToRemove()) != 1 || ok.GetHeadersToRemove()[0] != "X-Auth-Agent" {
		t.Fatalf("a header the PEP cannot vouch for is removed: %v", ok.GetHeadersToRemove())
	}

	// And the HTTP check API tells its caller to remove it too.
	s, _, mcpURL := mcpSetup(t, map[string]any{"decision": true}, nil)
	req, _ := json.Marshal(map[string]any{
		"config": map[string]string{"style": "mcp", "require_token": "true", "mcp_upstream_url": mcpURL},
		"method": "POST", "path": "/mcp", "headers": mcpHeaders(), "body": mcpCall,
	})
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", bytes.NewReader(req)))
	var out checkResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if v, ok := out.UpstreamHeaders["X-Auth-Agent"]; !out.Decision || !ok || v != "" {
		t.Fatalf("upstream_headers must carry X-Auth-Agent as a removal: %+v", out)
	}
	if out.UpstreamHeaders["X-Auth-Acr"] != "urn:mfa" {
		t.Fatalf("the token's acr travels as X-Auth-Acr: %+v", out.UpstreamHeaders)
	}
}

func TestQuoteParamCannotCloseTheParameter(t *testing.T) {
	got := quoteParam(`pay" resource_metadata="https://evil` + "\r\n" + `\`)
	if got != `"pay\" resource_metadata=\"https://evil\\"` {
		t.Fatalf("quoteParam = %s", got)
	}
	if sanitizeHeader("a\r\nb\x00c\x7fd") != "a  b c d" {
		t.Fatalf("control characters must become spaces: %q", sanitizeHeader("a\r\nb\x00c\x7fd"))
	}
}

// A forged access token with a validator configured must not make /v1/dpop/verify
// vouch for a proof: the proof is only as good as the cnf.jkt it is compared with.
func TestDpopVerifyValidatesTheAccessToken(t *testing.T) {
	asKey := newKey(t)
	jwks := jwksServer(t, asKey, "as-1")
	defer jwks.Close()
	s := &server{accessValidator: newTestValidator(t, jwks.URL)}
	attacker := newKey(t)
	forged := mintUnsigned(map[string]any{"sub": "victim", "cnf": map[string]any{"jkt": jwkThumbprint(publicJWK(attacker))}})
	proof := mintProof(t, attacker, map[string]any{"htm": "POST", "ath": accessTokenHash(forged),
		"iat": float64(time.Now().Unix()), "jti": "forged-verify-1"})
	body, _ := json.Marshal(map[string]any{"method": "POST", "path": "/payments",
		"headers": map[string]string{"authorization": "DPoP " + forged, "dpop": proof}})
	if _, out := postVerify(t, s, string(body)); out.Valid {
		t.Fatal("a proof bound to a forged token must not verify")
	}
}

// The REST mapping refuses what it cannot read the way the upstream will.
func TestRESTRefusesAmbiguousPathsAndBodies(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)
	h := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/payments;/customers/c1/accounts", `{"from_account":"a","amount":1}`},
		{"GET", "/accounts/../admin/balance", ""},
		{"GET", "/accounts/a1%2f..%2fb2/balance", ""},
		{"GET", "//accounts/a1/balance", ""},
		{"POST", "/payments", `{"from_account":"a","amount":1,"Amount":1000000}`},
		{"POST", "/payments", `{"from_account":"a",`},
		{"POST", "/payments", ``},
		{"POST", "/accounts", `[]`},
	} {
		resp := s.check(context.Background(), restConf(nil), c.method, c.path, h, c.body)
		if deniedStatus(resp) != int(typev3.StatusCode_BadRequest) {
			t.Fatalf("%s %s %q must be refused with a 400, got %d", c.method, c.path, c.body, deniedStatus(resp))
		}
	}
	if len(pdp.requests) != 0 {
		t.Fatalf("a refused request never reaches the PDP, got %d calls", len(pdp.requests))
	}
	// The anchored patterns: a longer path is not the short one it contains.
	if m := mapRequest("rest", "POST", "/payments/p1/refunds", `{}`); m.action == "make_payment" {
		t.Fatal("/payments/p1/refunds is not a payment")
	}
	if m := mapRequest("rest", "GET", "/bank/customers/c1/accounts", ""); m.action != "list_accounts" || m.rid != "c1" {
		t.Fatalf("a route prefix still maps: %+v", m)
	}
}

// A PDP that refuses a request (4xx) is not a PDP that is down: a fail-open layer is
// skipped only for the second.
func TestServiceFailOpenSkipsOnlyAnUnavailablePDP(t *testing.T) {
	own := newPDPStub(t, map[string]any{"decision": true}, 200)
	for status, skipped := range map[int]bool{503: true, 429: true, 401: false, 413: false, 400: false} {
		layer := newPDPStub(t, map[string]any{}, status)
		s := newServer(t, own.URL)
		conf := restConf(map[string]string{"pdp_layers": layer.URL + " fail-open, static"})
		resp := s.check(context.Background(), conf, "GET", "/accounts/a1/balance",
			map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}, "")
		if skipped != (resp.GetOkResponse() != nil) {
			t.Fatalf("PDP status %d: skipped=%v, got permit=%v", status, skipped, resp.GetOkResponse() != nil)
		}
	}
}

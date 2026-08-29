package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// pdpStub serves a fixed AuthZEN decision and records what was asked.
type pdpStub struct {
	*httptest.Server
	requests []map[string]any
}

func newPDPStub(t *testing.T, response map[string]any, status int) *pdpStub {
	t.Helper()
	stub := &pdpStub{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		stub.requests = append(stub.requests, body)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(stub.Close)
	return stub
}

func newServer(t *testing.T, pdpURL string) *server {
	t.Helper()
	return &server{
		authzenURL:    pdpURL,
		authzenAPIKey: "test-key",
		httpc:         &http.Client{Timeout: 5 * time.Second},
	}
}

// mintUnsigned builds a decodable (not verifiable) compact JWT, which is what the PEP
// reads when no validator is configured.
func mintUnsigned(claims map[string]any) string {
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return b64urlEncode(raw)
	}
	return enc(map[string]any{"alg": "none", "typ": "JWT"}) + "." + enc(claims) + ".sig"
}

func restConf(over map[string]string) pepConfig {
	base := map[string]string{"pep_label": "test", "style": "rest", "require_token": "true"}
	for k, v := range over {
		base[k] = v
	}
	return configFrom(base)
}

// deniedStatus pulls the HTTP status out of a denied CheckResponse. Read through the
// generated accessors, not a JSON round-trip: the status marshals as its enum NAME, so
// a numeric probe silently reads zero and every assertion on it passes vacuously.
func deniedStatus(resp *authv3.CheckResponse) int {
	return int(resp.GetDeniedResponse().GetStatus().GetCode())
}

// ---------------------------------------------------------------------------

func TestConfigFromReadsEveryKnob(t *testing.T) {
	c := configFrom(map[string]string{
		"pep_label": "edge", "style": "mcp",
		"require_token": "TRUE", "require_dpop": "true", "require_user_login": "true",
		"stepup_scope": "pay:approve", "stepup_action": "transfer",
		"mcp_upstream_url": "http://mcp:8090/mcp", "coaz_defaults": "true",
	})
	if c.pepLabel != "edge" || c.style != "mcp" {
		t.Fatalf("labels/style wrong: %+v", c)
	}
	if !c.requireToken || !c.requireDpop || !c.requireUserLogin || !c.coazDefaults {
		t.Fatalf("booleans should parse case-insensitively: %+v", c)
	}
	if c.stepupScope != "pay:approve" || c.stepupAction != "transfer" {
		t.Fatalf("step-up config wrong: %+v", c)
	}

	// Defaults when nothing is set.
	d := configFrom(map[string]string{})
	if d.pepLabel != "coaz-pep" || d.style != "rest" {
		t.Fatalf("defaults wrong: %+v", d)
	}
	if d.requireToken || d.requireDpop || d.coazDefaults {
		t.Fatalf("booleans should default false: %+v", d)
	}
	if d.stepupAction != "make_payment" {
		t.Fatalf("stepup_action default wrong: %q", d.stepupAction)
	}
	// Anything other than "true" is false — a typo must not enable a control.
	if configFrom(map[string]string{"require_dpop": "yes"}).requireDpop {
		t.Fatal(`only "true" should enable require_dpop`)
	}
}

func TestJWTClaimHelpers(t *testing.T) {
	t.Run("scope from either spelling and either shape", func(t *testing.T) {
		if got := scopeString(map[string]any{"scope": "a b"}); got != "a b" {
			t.Errorf("scope string: %q", got)
		}
		if got := scopeString(map[string]any{"scp": []any{"a", "b"}}); got != "a b" {
			t.Errorf("scp array: %q", got)
		}
		if got := scopeString(map[string]any{"scp": []any{"a", 42}}); got != "a" {
			t.Errorf("non-string members should be dropped: %q", got)
		}
		if scopeString(nil) != "" || scopeString(map[string]any{"scope": 7}) != "" {
			t.Error("absent or non-string scope should be empty")
		}
	})

	t.Run("actor from an object or a JSON string", func(t *testing.T) {
		if got := actorSub(map[string]any{"act": map[string]any{"sub": "agent-1"}}); got != "agent-1" {
			t.Errorf("object act: %q", got)
		}
		// PingFederate serialises act as a JSON string; a naive read yields nothing and
		// every delegated call looks direct.
		if got := actorSub(map[string]any{"act": `{"sub":"agent-2"}`}); got != "agent-2" {
			t.Errorf("string-encoded act: %q", got)
		}
		if actorSub(nil) != "" || actorSub(map[string]any{}) != "" || actorSub(map[string]any{"act": "nonsense"}) != "" {
			t.Error("absent or unparseable act should be empty")
		}
	})

	t.Run("aud as string or array", func(t *testing.T) {
		if got := audString(map[string]any{"aud": "a"}); got != "a" {
			t.Errorf("string aud: %q", got)
		}
		if got := audString(map[string]any{"aud": []any{"a", "b"}}); got != "a,b" {
			t.Errorf("array aud: %q", got)
		}
		if audString(nil) != "" || audString(map[string]any{"aud": 1}) != "" {
			t.Error("absent or non-string aud should be empty")
		}
	})

	t.Run("strClaim and claimString", func(t *testing.T) {
		if got := strClaim(map[string]any{"acr": "urn:x"}, "acr"); got != "urn:x" {
			t.Errorf("strClaim: %q", got)
		}
		if strClaim(nil, "acr") != "" || strClaim(map[string]any{"acr": 1}, "acr") != "" {
			t.Error("absent or non-string should be empty")
		}
		if claimString(map[string]any{"sub": "s"}, "sub") != "s" || claimString(nil, "sub") != "" {
			t.Error("claimString")
		}
	})

	t.Run("claimsForCEL normalises string-encoded objects", func(t *testing.T) {
		got := claimsForCEL(map[string]any{"sub": "u", "act": `{"sub":"agent-3"}`})
		act, ok := got["act"].(map[string]any)
		if !ok || act["sub"] != "agent-3" {
			t.Fatalf("act should be decoded for CEL, got %#v", got["act"])
		}
		if got["sub"] != "u" {
			t.Fatal("other claims should pass through")
		}
	})
}

func TestJWTDecodeRejectsMalformed(t *testing.T) {
	for _, tok := range []string{"", "nodots", "a.b", "!!!.!!!.x"} {
		if jwtClaims(tok) != nil {
			t.Errorf("malformed token %q should decode to nil", tok)
		}
	}
	tok := mintUnsigned(map[string]any{"sub": "alice"})
	if c := jwtClaims(tok); c == nil || c["sub"] != "alice" {
		t.Fatalf("well-formed token should decode, got %v", c)
	}
	if h := jwtHeader(tok); h == nil || h["alg"] != "none" {
		t.Fatal("header should decode")
	}
}

func TestExtractToken(t *testing.T) {
	tok, scheme := extractToken("Bearer abc")
	if tok != "abc" || scheme != "bearer" {
		t.Fatalf("got %q %q", tok, scheme)
	}
	if tok, scheme = extractToken("DPoP xyz"); scheme != "dpop" {
		t.Fatalf("scheme should be lower-cased, got %q", scheme)
	}
	for _, bad := range []string{"", "Bearer", "justatoken"} {
		if tok, _ = extractToken(bad); tok != "" {
			t.Errorf("%q should not yield a token, got %q", bad, tok)
		}
	}
}

func TestIsToolsCallAndToolCallName(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"make_payment"}}`
	if !isToolsCall(body) {
		t.Fatal("should recognise a tools/call")
	}
	if got := toolCallName(body); got != "make_payment" {
		t.Fatalf("tool name: %q", got)
	}
	for _, other := range []string{
		`{"jsonrpc":"2.0","method":"tools/list"}`,
		`not json`,
		``,
	} {
		if isToolsCall(other) {
			t.Errorf("%q is not a tools/call", other)
		}
	}
}

// ---------------------------------------------------------------------------
// mapRequest — the port of the Kong plugin's map_request. Both gateways must send
// the PDP identical evaluation requests, so the shapes are pinned here.

func TestMapRequestREST(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		wantAction, wantType     string
		wantID                   string
	}{
		{"list accounts", "GET", "/customers/cust-1/accounts", "", "list_accounts", "customer", "cust-1"},
		{"balance", "GET", "/accounts/acc-9/balance", "", "get_balance", "account", "acc-9"},
		{"open account", "POST", "/accounts", `{}`, "open_account", "account", ""},
		// Prefix-tolerant: it must not matter whether the gateway strips /bank first.
		{"prefixed balance", "GET", "/bank/accounts/acc-9/balance", "", "get_balance", "account", "acc-9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mapRequest("rest", tc.method, tc.path, tc.body)
			if m.action != tc.wantAction {
				t.Errorf("action = %q, want %q", m.action, tc.wantAction)
			}
			if m.rtype != tc.wantType {
				t.Errorf("resource type = %q, want %q", m.rtype, tc.wantType)
			}
			if tc.wantID != "" && m.rid != tc.wantID {
				t.Errorf("resource id = %q, want %q", m.rid, tc.wantID)
			}
			if m.ctx["channel"] != "ai-agent" {
				t.Errorf("channel should always be tagged, got %v", m.ctx["channel"])
			}
		})
	}
}

func TestMapRequestMCP(t *testing.T) {
	// The MCP edge authorizes ACCESS to the service on the initialize handshake; other
	// JSON-RPC passes on a valid token, with per-tool policy enforced at the next PEP.
	init := mapRequest("mcp", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if init.action != "access_mcp" {
		t.Fatalf("initialize should map to access_mcp, got %q", init.action)
	}
	if init.rtype != "mcp-service" {
		t.Fatalf("resource type = %q", init.rtype)
	}

	other := mapRequest("mcp", "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if other.action != allowAction {
		t.Fatalf("non-initialize JSON-RPC should use the allow sentinel, got %q", other.action)
	}
	// A body that is not JSON at all must not be treated as a handshake.
	if got := mapRequest("mcp", "GET", "/mcp", "").action; got != allowAction {
		t.Fatalf("empty body should not be access_mcp, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// check() — the decision pipeline.

func TestCheckDeniesWithoutAToken(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)

	resp := s.check(context.Background(), restConf(nil), "GET", "/accounts/a/balance",
		map[string]string{}, "")
	if resp == nil {
		t.Fatal("expected a denial")
	}
	if len(pdp.requests) != 0 {
		t.Fatal("the PDP must not be consulted when there is no token")
	}
}

func TestCheckPermitsAndForwardsIdentity(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true, "context": map[string]any{"reason": "ok"}}, 200)
	s := newServer(t, pdp.URL)

	headers := map[string]string{
		"authorization": "Bearer " + mintUnsigned(map[string]any{
			"sub": "alice", "act": map[string]any{"sub": "agent-7"},
			"scope": "accounts:read", "client_id": "c1", "aud": "https://api",
		}),
	}
	resp := s.check(context.Background(), restConf(nil), "GET", "/customers/cust-1/accounts", headers, "")
	if resp == nil {
		t.Fatal("expected a response")
	}
	if len(pdp.requests) != 1 {
		t.Fatalf("expected exactly one PDP call, got %d", len(pdp.requests))
	}

	sent := pdp.requests[0]
	action := sent["action"].(map[string]any)
	if action["name"] != "list_accounts" {
		t.Fatalf("action sent to the PDP: %v", action)
	}
	resource := sent["resource"].(map[string]any)
	if resource["id"] != "cust-1" {
		t.Fatalf("resource sent to the PDP: %v", resource)
	}
	// The delegation chain: the agent acts, the principal is on whose behalf.
	subject := sent["subject"].(map[string]any)
	props := subject["properties"].(map[string]any)
	if props["on_behalf_of"] != "alice" {
		t.Fatalf("principal not forwarded: %v", props)
	}
}

func TestCheckHonoursADeny(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{
		"decision": false,
		"context":  map[string]any{"reason": "not your account"},
	}, 200)
	s := newServer(t, pdp.URL)

	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	resp := s.check(context.Background(), restConf(nil), "GET", "/accounts/a/balance", headers, "")
	if resp == nil {
		t.Fatal("a deny must produce a denied response")
	}
	if got := deniedStatus(resp); got != int(typev3.StatusCode_Forbidden) {
		t.Fatalf("a policy deny should be 403, got %d", got)
	}
	if body := resp.GetDeniedResponse().GetBody(); !strings.Contains(body, "not your account") {
		t.Fatalf("the policy reason should reach the caller, got %s", body)
	}
}

func TestCheckFailsClosedWhenThePDPIsUnreachable(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	url := pdp.URL
	pdp.Close() // gone
	s := newServer(t, url)

	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	resp := s.check(context.Background(), restConf(nil), "GET", "/accounts/a/balance", headers, "")
	if resp == nil {
		t.Fatal("an unreachable PDP must deny, not allow")
	}
}

func TestCheckDeniesAnUpstreamOutsideTheAllowlist(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)
	s.upstreamAllowlist = parseAllowlist("http://trusted-mcp:8090/mcp")

	conf := configFrom(map[string]string{
		"style": "mcp", "require_token": "true",
		"mcp_upstream_url": "http://169.254.169.254/latest/meta-data/",
	})
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`

	resp := s.check(context.Background(), conf, "POST", "/mcp", headers, body)
	if resp == nil {
		t.Fatal("an upstream outside the allowlist must be refused")
	}
}

func TestEvaluateParsesAdvice(t *testing.T) {
	cases := []struct {
		name     string
		response map[string]any
		check    func(t *testing.T, out pepOutcome)
	}{
		{"permit", map[string]any{"decision": true}, func(t *testing.T, o pepOutcome) {
			if !o.Decision {
				t.Fatal("expected permit")
			}
		}},
		{"step-up advice", map[string]any{
			"decision": false,
			"context":  map[string]any{"reason": "over threshold", "step_up_required": true, "step_up_scope": "pay:approve"},
		}, func(t *testing.T, o pepOutcome) {
			if o.Decision || !o.StepUp || o.StepUpScope != "pay:approve" {
				t.Fatalf("step-up advice not parsed: %+v", o)
			}
		}},
		{"identity advice", map[string]any{
			"decision": false,
			"context":  map[string]any{"identity_proofing_required": true, "identity_proofing_doctype": "org.iso.18013.5.1.mDL"},
		}, func(t *testing.T, o pepOutcome) {
			if o.Decision || !o.IdentityReq || o.IdentityDoctype == "" {
				t.Fatalf("identity advice not parsed: %+v", o)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdp := newPDPStub(t, tc.response, 200)
			s := newServer(t, pdp.URL)
			out, err := s.evaluate(context.Background(), map[string]any{"subject": map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, out)
		})
	}
}

func TestEvaluateRejectsAnUnparseableResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	s := newServer(t, srv.URL)
	if _, err := s.evaluate(context.Background(), map[string]any{}); err == nil {
		t.Fatal("an unparseable PDP response must be an error, not a silent permit")
	}
}

// ---------------------------------------------------------------------------
// The HTTP check API.

func TestHandleHTTPCheck(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)

	body, _ := json.Marshal(map[string]any{
		"config": map[string]string{"pep_label": "kong", "style": "rest", "require_token": "true"},
		"method": "GET",
		"path":   "/accounts/a/balance",
		"headers": map[string]string{
			"Authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"}),
		},
		"body": "",
	})
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", strings.NewReader(string(body))))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Decision bool `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Decision {
		t.Fatalf("expected a permit, got %s", rec.Body.String())
	}
}

func TestHandleHTTPCheckRejectsGarbage(t *testing.T) {
	s := newServer(t, "http://unused")
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", strings.NewReader("{{{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a malformed check request should be a 400, got %d", rec.Code)
	}
}

func TestHandleHTTPCheckLowerCasesHeaders(t *testing.T) {
	// Kong may send headers in any case; the pipeline looks them up lower-cased, so a
	// capitalised Authorization must still be found or every request looks unauthenticated.
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)
	body, _ := json.Marshal(map[string]any{
		"config":  map[string]string{"style": "rest", "require_token": "true"},
		"method":  "GET",
		"path":    "/accounts/a/balance",
		"headers": map[string]string{"AUTHORIZATION": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})},
	})
	rec := httptest.NewRecorder()
	s.handleHTTPCheck(rec, httptest.NewRequest(http.MethodPost, "/v1/mcp/check", strings.NewReader(string(body))))
	if len(pdp.requests) != 1 {
		t.Fatalf("the token should have been found regardless of header case; PDP calls = %d, body = %s",
			len(pdp.requests), rec.Body.String())
	}
}

func TestToLowerAndEnvOr(t *testing.T) {
	if toLower("ABC") != "abc" || toLower("aBc") != "abc" || toLower("") != "" {
		t.Fatal("toLower")
	}
	if envOr("DEFINITELY_NOT_SET_XYZ", "fallback") != "fallback" {
		t.Fatal("envOr should fall back")
	}
	t.Setenv("COAZ_TEST_VAR", "value")
	if envOr("COAZ_TEST_VAR", "fallback") != "value" {
		t.Fatal("envOr should prefer the environment")
	}
}

// ---------------------------------------------------------------------------
// Remaining branches.

func TestMapRequestPayments(t *testing.T) {
	body := `{"from_account":"acc-1","to_account":"acc-2","amount":1500.5,"currency":"USD",
	          "description":"rent","internal_transfer":false}`
	m := mapRequest("rest", "POST", "/payments", body)
	if m.action != "make_payment" || m.rtype != "account" || m.rid != "acc-1" {
		t.Fatalf("payment mapping: %+v", m)
	}
	if m.ctx["amount"] != 1500.5 || m.ctx["currency"] != "USD" {
		t.Fatalf("amount/currency must reach the policy: %+v", m.ctx)
	}
	if m.ctx["description"] != "rent" || m.ctx["internal_transfer"] != false {
		t.Fatalf("optional context dropped: %+v", m.ctx)
	}
	if m.rprops["to_account"] != "acc-2" {
		t.Fatalf("destination should be a resource property: %+v", m.rprops)
	}

	// Currency defaults so a policy comparing amounts is never handed a bare number
	// with no unit.
	def := mapRequest("rest", "POST", "/payments", `{"from_account":"a","amount":10}`)
	if def.ctx["currency"] != "AUD" {
		t.Fatalf("currency should default, got %v", def.ctx["currency"])
	}

	// An unparseable body must not invent values.
	bad := mapRequest("rest", "POST", "/payments", `{{{`)
	if bad.action != "make_payment" {
		t.Fatalf("action should still map: %+v", bad)
	}
	if _, present := bad.ctx["amount"]; present {
		t.Fatal("a malformed body must not produce an amount")
	}
}

func TestMapRequestOpenAccountAndFallback(t *testing.T) {
	withType := mapRequest("rest", "POST", "/accounts", `{"account_type":"savings"}`)
	if withType.rid != "new:savings" || withType.rprops["account_type"] != "savings" {
		t.Fatalf("open_account should carry the requested type: %+v", withType)
	}
	bare := mapRequest("rest", "POST", "/accounts", `{}`)
	if bare.rid != "new:savings" {
		t.Fatalf("open_account should default the type, got %q", bare.rid)
	}

	// Anything unrecognised still produces a governable action rather than nothing.
	other := mapRequest("rest", "DELETE", "/admin/thing", "")
	if other.action != "http:delete" || other.rtype != "endpoint" || other.rid != "/admin/thing" {
		t.Fatalf("fallback mapping: %+v", other)
	}
}

func TestConsentedPayment(t *testing.T) {
	ad := []any{
		map[string]any{"type": "account_information"},
		map[string]any{"type": "payment_initiation", "amount": 500.0, "creditorAccount": "acc-9"},
	}
	amt, cred, ok := consentedPayment(ad)
	if !ok || amt != 500.0 || cred != "acc-9" {
		t.Fatalf("RAR payment entry not extracted: %v %v %v", amt, cred, ok)
	}

	for _, no := range []any{
		nil,
		"not an array",
		[]any{"not an object"},
		[]any{map[string]any{"type": "account_information"}}, // no payment entry
	} {
		if _, _, ok := consentedPayment(no); ok {
			t.Errorf("%#v should not yield a consented payment", no)
		}
	}
}

func TestCheckIssuesAStepUpChallenge(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{
		"decision": false,
		"context": map[string]any{
			"reason": "over threshold", "step_up_required": true, "step_up_scope": "pay:approve",
		},
	}, 200)
	s := newServer(t, pdp.URL)

	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	resp := s.check(context.Background(), restConf(nil), "POST", "/payments", headers,
		`{"from_account":"a","amount":9000}`)

	if got := deniedStatus(resp); got != int(typev3.StatusCode_Unauthorized) {
		t.Fatalf("a step-up is a 401 challenge, not a flat 403; got %d", got)
	}
	body := resp.GetDeniedResponse().GetBody()
	if !strings.Contains(body, "insufficient_scope") || !strings.Contains(body, "pay:approve") {
		t.Fatalf("the challenge must name the scope to acquire, got %s", body)
	}
}

func TestCheckIssuesAnIdentityProofingChallenge(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{
		"decision": false,
		"context": map[string]any{
			"identity_proofing_required": true, "identity_proofing_doctype": "org.iso.18013.5.1.mDL",
		},
	}, 200)
	s := newServer(t, pdp.URL)

	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}
	resp := s.check(context.Background(), restConf(nil), "POST", "/accounts", headers, `{}`)

	body := resp.GetDeniedResponse().GetBody()
	if !strings.Contains(body, "identity_verification_required") || !strings.Contains(body, "mDL") {
		t.Fatalf("the challenge must name the document required, got %s", body)
	}
}

func TestCheckRequiresALoggedInUserWhenConfigured(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)

	conf := restConf(map[string]string{"require_user_login": "true"})
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}

	// No X-User-Token at all.
	resp := s.check(context.Background(), conf, "GET", "/accounts/a/balance", headers, "")
	if got := deniedStatus(resp); got != int(typev3.StatusCode_Unauthorized) {
		t.Fatalf("a missing user token should be a login challenge, got %d", got)
	}
	if len(pdp.requests) != 0 {
		t.Fatal("the PDP should not be asked before there is a user")
	}

	// With one, the request proceeds to the PDP.
	headers["x-user-token"] = mintUnsigned(map[string]any{"sub": "alice", "scope": "openid"})
	if resp := s.check(context.Background(), conf, "GET", "/accounts/a/balance", headers, ""); resp == nil {
		t.Fatal("expected a response")
	}
	if len(pdp.requests) != 1 {
		t.Fatalf("expected the PDP to be consulted, got %d calls", len(pdp.requests))
	}
}

func TestCheckAllowsMCPTrafficThatIsNotAHandshake(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)
	conf := configFrom(map[string]string{"style": "mcp", "require_token": "true"})
	headers := map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}

	// The allow sentinel short-circuits: authenticated non-handshake JSON-RPC proceeds
	// without a PDP round trip, because per-tool policy lives at the next PEP.
	resp := s.check(context.Background(), conf, "POST", "/mcp", headers,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp == nil {
		t.Fatal("expected a response")
	}
	if len(pdp.requests) != 0 {
		t.Fatalf("the allow sentinel should skip the PDP, got %d calls", len(pdp.requests))
	}
}

func TestCheckViaGRPC(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/accounts/acc-1/balance?verbose=1",
					Headers: map[string]string{
						"Authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"}),
					},
				},
			},
		},
	}
	// Per-route knobs ride the context extensions, as the gateway sends them.
	req.Attributes.ContextExtensions = map[string]string{"style": "rest", "require_token": "true"}

	resp, err := s.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a CheckResponse")
	}
	if len(pdp.requests) != 1 {
		t.Fatalf("expected one PDP call, got %d", len(pdp.requests))
	}
	// The query string must be stripped before mapping, or the path never matches.
	sent := pdp.requests[0]
	if res := sent["resource"].(map[string]any); res["id"] != "acc-1" {
		t.Fatalf("query string should not leak into the resource id: %v", res)
	}
}

package coaz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
)

func TestCheckStrictJSON(t *testing.T) {
	for _, ok := range []string{`{"amount":1,"to":"b"}`, `[1,2]`, `"s"`, ` {"a":{"b":[{"c":1}]}} `} {
		if err := CheckStrictJSON([]byte(ok)); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"amount":1,"Amount":1000000}`,
		"\xEF\xBB\xBF{}",
		`{"a":"` + "\xff" + `"}`,
		`{"a":1} {"a":2}`,
		`{"a":`,
		`not json`,
		strings.Repeat("[", 70) + strings.Repeat("]", 70),
	} {
		if err := CheckStrictJSON([]byte(bad)); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

func TestParseRequestMalformedInsideContainers(t *testing.T) {
	for _, body := range []string{`{1:2}`, `{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":[1,]}}`} {
		var pe *ParseError
		if _, err := ParseRequest([]byte(body)); !errors.As(err, &pe) || pe.Code != CodeParseError {
			t.Fatalf("%s: want a parse error, got %v", body, err)
		}
	}
	var pe *ParseError
	if _, err := ParseRequest([]byte(`{"jsonrpc":"2.0","id":1e999,"method":"ping"}`)); !errors.As(err, &pe) || pe.Code != CodeInvalidRequest || pe.Error() == "" {
		t.Fatalf("an id no float64 can carry is an invalid request, got %v", err)
	}
}

func TestRefusedWrapsAnyError(t *testing.T) {
	v := Refused(errors.New("anything"))
	if v.Decision || v.HTTPStatus != http.StatusBadRequest || !strings.Contains(string(v.JSONRPCError), "-32600") {
		t.Fatalf("%+v", v)
	}
}

// A declared tool whose discovery fails cannot be vouched for: -32603, not a pass.
func TestCheckMCPDeniesWhenDiscoveryFails(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer mcp.Close()
	v := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}}).CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "a"}, nil, CallOptions{ApplyDefaultMappings: true})
	if v.Decision || !hasCode(v, CodePDPError) || len(*reqs) != 0 {
		t.Fatalf("%+v", v)
	}
	if strings.Contains(v.ClientReason, "down") || strings.Contains(v.ClientReason, mcp.URL) {
		t.Fatalf("the client reason must not carry the upstream's detail: %q", v.ClientReason)
	}
}

func TestDefaultMappingDeniesWhenNoPDPResolves(t *testing.T) {
	e := NewEngine(Options{Resolver: &fakeResolver{err: errors.New("no PDP")}})
	v := e.CheckToolCall(context.Background(), "", "", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`),
		map[string]any{"sub": "a", "aud": "m"}, nil, CallOptions{ApplyDefaultMappings: true})
	if v.Decision || !hasCode(v, CodePDPError) {
		t.Fatalf("%+v", v)
	}
}

// A request the PEP cannot even build is a refusal; an answer cut off mid-read is the
// PDP being unavailable.
func TestEvaluateClassifiesItsOwnFailures(t *testing.T) {
	built := &BuiltRequest{Body: []byte(`{}`), Count: 1}
	e := NewEngine(Options{})
	if _, err := e.evaluate(context.Background(), discovery.PDPEndpoints{Evaluation: "http://[::1"}, built); err == nil || errors.Is(err, ErrPDPUnavailable) {
		t.Fatalf("a bad URL is a refusal, got %v", err)
	}
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"decision":`))
	}))
	defer cut.Close()
	if _, err := e.evaluate(context.Background(), discovery.PDPEndpoints{Evaluation: cut.URL}, built); !errors.Is(err, ErrPDPUnavailable) {
		t.Fatalf("an answer cut off mid-read is unavailability, got %v", err)
	}
}

// The policy's challenges survive the engine with their defaults filled in.
func TestCOAZChallengesFillTheirDefaults(t *testing.T) {
	mcp := mcpServing(t, singleTool)
	for body, want := range map[string]string{
		`{"decision":false,"context":{"identity_proofing_required":true}}`: "org.iso.18013.5.1.mDL",
		`{"decision":false,"context":{"step_up_required":true}}`:           "banking:payments:transfer",
	} {
		pdp := pdpServing(t, body, 200)
		v := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}}).CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
			map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{})
		if v.Decision || !strings.Contains(string(v.JSONRPCError), want) || v.ClientReason == "" {
			t.Fatalf("%s: %+v", body, v)
		}
	}
}

func TestMergePermitKeepsEarlierObligations(t *testing.T) {
	acc := pdpOutcome{Decision: true, IdentityReq: true, IdentityDoctype: "mdl", StepUp: true, StepUpScope: "s", Reason: "first"}
	out := mergePermit(acc, pdpOutcome{Decision: true, Reason: "second"})
	if !out.IdentityReq || out.IdentityDoctype != "mdl" || !out.StepUp || out.StepUpScope != "s" || out.Reason != "first" {
		t.Fatalf("a later plain permit must not erase an earlier obligation: %+v", out)
	}
}

// A PDP that cannot take a batch cannot be asked one: a fail-open layer may be skipped
// for it, a fail-closed one fails.
func TestNoBatchEndpointCountsAsUnavailable(t *testing.T) {
	built := &BuiltRequest{Body: []byte(`{}`), Count: 2, Batch: true}
	_, err := NewEngine(Options{}).evaluate(context.Background(), discovery.PDPEndpoints{Identifier: "p", Evaluation: "http://p/e"}, built)
	if !errors.Is(err, ErrPDPUnavailable) {
		t.Fatalf("got %v", err)
	}
}

// An array audience still names the server: the first one.
func TestDefaultServerResourceTakesAnArrayAudience(t *testing.T) {
	cm, err := CompiledDefault("initialize")
	if err != nil {
		t.Fatal(err)
	}
	for aud, want := range map[string]any{
		"https://mcp.example": "https://mcp.example",
		"list":                []any{"https://mcp.example", "https://api.example"},
	} {
		claim := any(aud)
		if aud == "list" {
			claim = want
			want = "https://mcp.example"
		}
		b, err := cm.Build(map[string]any{}, map[string]any{"sub": "alice", "aud": claim}, nil)
		if err != nil {
			t.Fatalf("aud %v: %v", claim, err)
		}
		if !strings.Contains(string(b.Body), `"id":"`+want.(string)+`"`) {
			t.Fatalf("aud %v: %s", claim, b.Body)
		}
	}
	if _, err := cm.Build(map[string]any{}, map[string]any{"sub": "alice", "aud": []any{}}, nil); err == nil {
		t.Fatal("an empty audience list names no server: a mapping error")
	}
}

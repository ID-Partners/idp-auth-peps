package coaz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
)

// fakeResolver records the resource it was asked about and answers with fixed endpoints.
type fakeResolver struct {
	ep        discovery.PDPEndpoints
	err       error
	resources []string
}

func (f *fakeResolver) Resolve(_ context.Context, resource string) (discovery.PDPEndpoints, error) {
	f.resources = append(f.resources, resource)
	return f.ep, f.err
}

// singleTool is one COAZ v1 tool: a single evaluation, so it takes the evaluation
// endpoint rather than the batch one.
const singleTool = `[{"name": "get_customer", "coaz": true,
  "inputSchema": {"type": "object", "x-coaz-mapping": {
    "resource": [{"id": "params.arguments.id", "type": "'customer'"}],
    "subject":  [{"type": "'user'", "id": "token.sub"}],
    "context":  [{"agent": "token.client_id"}]}}}]`

func singleCall() []byte { return toolsCallBody("get_customer", map[string]any{"id": "c1"}) }

func hasCode(v Verdict, code int) bool {
	return v.JSONRPCError != nil && bytes.Contains(v.JSONRPCError, []byte(fmt.Sprintf(`"code":%d`, code)))
}

func recordingPDP(t *testing.T, body string) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var reqs []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestEngineUsesResolvedEndpoints(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, singleTool)
	fr := &fakeResolver{ep: discovery.PDPEndpoints{Identifier: pdp.URL, Evaluation: pdp.URL + "/custom/eval", APIKey: "resolved-key"}}
	e := NewEngine(Options{Resolver: fr})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{Resource: "https://api.example"})
	if !v.Decision {
		t.Fatalf("expected permit, got %+v", v)
	}
	if len(*reqs) != 1 || (*reqs)[0].URL.Path != "/custom/eval" {
		t.Fatalf("resolved evaluation endpoint not used: %v", *reqs)
	}
	if got := (*reqs)[0].Header.Get("Authorization"); got != "Bearer resolved-key" {
		t.Fatalf("resolved API key not sent: %q", got)
	}
	if len(fr.resources) != 1 || fr.resources[0] != "https://api.example" {
		t.Fatalf("CallOptions.Resource must reach the resolver: %v", fr.resources)
	}
}

func TestEngineSendsNoBearerWithoutAKey(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, singleTool)
	e := NewEngine(Options{Resolver: &fakeResolver{ep: discovery.PDPEndpoints{Identifier: pdp.URL, Evaluation: pdp.URL + "/e"}}})
	e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{})
	if got := (*reqs)[0].Header.Get("Authorization"); got != "" {
		t.Fatalf("no key should mean no Authorization header, got %q", got)
	}
}

func TestEngineBoxcarFailsClosedWithoutAnEvaluationsEndpoint(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"evaluations":[{"decision":true},{"decision":true}]}`)
	mcp := mcpServing(t, boxcarTool)
	e := NewEngine(Options{Resolver: &fakeResolver{ep: discovery.PDPEndpoints{Identifier: pdp.URL, Evaluation: pdp.URL + "/e"}}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", toolsCallBody("transfer",
		map[string]any{"from": "a1", "to": "a2"}), map[string]any{"sub": "alice"}, nil, CallOptions{})
	if v.Decision || !hasCode(v, CodePDPError) {
		t.Fatalf("a batch with no evaluations endpoint must fail closed: %+v", v)
	}
	if !strings.Contains(v.Reason, "access_evaluations_endpoint") {
		t.Fatalf("reason should say why: %q", v.Reason)
	}
	if len(*reqs) != 0 {
		t.Fatal("nothing should be sent to a guessed batch path")
	}
}

func TestEngineResolveErrorFailsClosedOnBothPaths(t *testing.T) {
	fr := &fakeResolver{err: errors.New("no PDP could be resolved")}
	t.Run("declared mapping", func(t *testing.T) {
		mcp := mcpServing(t, singleTool)
		e := NewEngine(Options{Resolver: fr})
		v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
			map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{})
		if v.Decision || !hasCode(v, CodePDPError) || !strings.Contains(v.Reason, "PDP discovery") {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("default mapping", func(t *testing.T) {
		mcp := mcpServing(t, `[{"name":"plain","inputSchema":{"type":"object"}}]`)
		e := NewEngine(Options{Resolver: fr})
		v := e.CheckToolCall(context.Background(), mcp.URL, "", toolsCallBody("plain", nil),
			map[string]any{"sub": "alice", "aud": "https://mcp.example"}, nil, CallOptions{ApplyDefaultMappings: true, Resource: "https://mcp.example"})
		if v.Decision || !hasCode(v, CodePDPError) || !strings.Contains(v.Reason, "PDP discovery") {
			t.Fatalf("%+v", v)
		}
		if fr.resources[len(fr.resources)-1] != "https://mcp.example" {
			t.Fatalf("resource not threaded through the default-mapping path: %v", fr.resources)
		}
	})
}

func TestEngineWithoutAResolverIsStatic(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, singleTool)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL + "/", APIKey: "k"}})
	e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{Resource: "https://ignored.example"})
	if len(*reqs) != 1 || (*reqs)[0].URL.Path != "/access/v1/evaluation" || (*reqs)[0].Header.Get("Authorization") != "Bearer k" {
		t.Fatalf("PDPConfig alone must still mean the default path and key: %v", *reqs)
	}
}

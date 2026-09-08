package coaz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
)

// fakeResolver records the resource it was asked about and answers with fixed endpoints.
type fakeResolver struct {
	ep        discovery.PDPEndpoints
	err       error
	resources []string
	layerEP   func(pdp string) discovery.PDPEndpoints
}

func (f *fakeResolver) Resolve(_ context.Context, resource string) (discovery.PDPEndpoints, error) {
	f.resources = append(f.resources, resource)
	return f.ep, f.err
}

// ResolvePDP answers an explicit layer with a PDP at that identifier; tests that need a
// different endpoint per layer set `layerEP`.
func (f *fakeResolver) ResolvePDP(_ context.Context, pdp string) (discovery.PDPEndpoints, error) {
	f.resources = append(f.resources, "pdp:"+pdp)
	if f.layerEP != nil {
		return f.layerEP(pdp), f.err
	}
	return discovery.PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/access/v1/evaluation", Source: "layer"}, f.err
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

func TestEngineForwardsWhatTheResolverFound(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, singleTool)
	var bodies [][]byte
	pdp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	})
	_ = reqs
	fr := &fakeResolver{ep: discovery.PDPEndpoints{
		Identifier: pdp.URL, Evaluation: pdp.URL + "/e",
		Resource: &discovery.ResourceMetadata{Source: "federation", Document: map[string]any{"scopes_supported": []any{"accounts:read"}, "acr_values_required": []any{"mfa"}}},
	}}
	e := NewEngine(Options{Resolver: fr})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice", "client_id": "c"}, map[string]any{"user_scope": "x", "request": "caller-wins"},
		CallOptions{Resource: "https://api.example", AccessToken: "raw.token.here", Method: "POST", Path: "/mcp"})
	if !v.Decision {
		t.Fatalf("%+v", v)
	}
	var sent struct {
		Context map[string]any `json:"context"`
	}
	if err := json.Unmarshal(bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Context["resource_metadata_source"] != "federation" {
		t.Fatalf("source not forwarded: %v", sent.Context)
	}
	if doc, _ := sent.Context["resource_metadata"].(map[string]any); doc == nil || doc["acr_values_required"] == nil {
		t.Fatalf("document not forwarded verbatim: %v", sent.Context)
	}
	if sent.Context["access_token"] != "raw.token.here" || sent.Context["user_scope"] != "x" {
		t.Fatalf("token or caller context missing: %v", sent.Context)
	}
	if sent.Context["request"] != "caller-wins" {
		t.Fatalf("a caller's explicit context key must not be overwritten: %v", sent.Context["request"])
	}

	// Nothing to forward when the resolver found nothing and the route sends nothing.
	// (A fresh struct each time: json.Unmarshal merges into an existing map.)
	bodies = nil
	e2 := NewEngine(Options{Resolver: &fakeResolver{ep: discovery.PDPEndpoints{Identifier: pdp.URL, Evaluation: pdp.URL + "/e"}}})
	e2.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{})
	var bare struct {
		Context map[string]any `json:"context"`
	}
	_ = json.Unmarshal(bodies[0], &bare)
	for _, k := range []string{"resource_metadata", "resource_metadata_source", "access_token", "request"} {
		if _, present := bare.Context[k]; present {
			t.Fatalf("%s should be absent when there is nothing to forward: %v", k, bare.Context)
		}
	}

	// The default-mapping path forwards the same things.
	bodies = nil
	e3 := NewEngine(Options{Resolver: fr})
	e3.CheckToolCall(context.Background(), mcpServing(t, `[{"name":"plain","inputSchema":{"type":"object"}}]`).URL, "", toolsCallBody("plain", nil),
		map[string]any{"sub": "alice", "aud": "https://mcp.example"}, nil, CallOptions{ApplyDefaultMappings: true, AccessToken: "t2", Method: "POST", Path: "/mcp"})
	var viaDefault struct {
		Context map[string]any `json:"context"`
	}
	_ = json.Unmarshal(bodies[0], &viaDefault)
	if viaDefault.Context["access_token"] != "t2" || viaDefault.Context["resource_metadata_source"] != "federation" {
		t.Fatalf("default-mapping path did not forward: %v", viaDefault.Context)
	}
}

func TestEngineAsksEveryLayerAndStopsAtTheFirstDeny(t *testing.T) {
	// Two PDPs: an estate one that denies a flagged client, and the resource's own.
	var order []string
	estate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "estate")
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(raw), `"agent":"risky"`) {
			_, _ = w.Write([]byte(`{"decision":false,"context":{"reason":"client on the watch list"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	t.Cleanup(estate.Close)
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		order = append(order, "resource")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	t.Cleanup(own.Close)
	mcp := mcpServing(t, singleTool)
	fr := &fakeResolver{
		ep: discovery.PDPEndpoints{Identifier: own.URL, Evaluation: own.URL + "/e", Resource: &discovery.ResourceMetadata{Source: "rfc9728", Document: map[string]any{"x": 1}}},
		layerEP: func(pdp string) discovery.PDPEndpoints {
			return discovery.PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/e", Source: "layer"}
		},
	}
	e := NewEngine(Options{Resolver: fr})
	layers := []discovery.LayerSpec{{Name: estate.URL}, {Name: "resource"}}

	v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{Layers: layers})
	if !v.Decision || !reflect.DeepEqual(order, []string{"estate", "resource"}) {
		t.Fatalf("both layers, in order, should be asked and permit: %+v %v", v, order)
	}
	order = nil
	v = e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "risky"}, nil, CallOptions{Layers: layers})
	if v.Decision || !strings.Contains(v.Reason, "watch list") || !reflect.DeepEqual(order, []string{"estate"}) {
		t.Fatalf("the estate layer's deny must be the answer and stop the chain: %+v %v", v, order)
	}
	// A duplicate layer is one call, and the resource's document still travels.
	order = nil
	v = e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{Layers: []discovery.LayerSpec{{Name: "resource"}, {Name: own.URL}}})
	if !v.Decision || !reflect.DeepEqual(order, []string{"resource"}) {
		t.Fatalf("duplicates collapse: %v", order)
	}
	// A failing layer fails closed.
	fr.err = errors.New("layer down")
	v = e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{Layers: layers})
	if v.Decision || !hasCode(v, CodePDPError) {
		t.Fatalf("resolution failure must fail closed: %+v", v)
	}
	fr.err = nil
	own.Close()
	v = e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{Layers: layers})
	if v.Decision || !hasCode(v, CodePDPError) {
		t.Fatalf("a PDP error in any layer must fail closed: %+v", v)
	}
}

func TestEngineFailsOpenOnlyWhereTold(t *testing.T) {
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reason":"no"}}`))
	}))
	t.Cleanup(deny.Close)
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	t.Cleanup(own.Close)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	t.Cleanup(down.Close)
	mcp := mcpServing(t, singleTool)
	fr := &fakeResolver{
		ep: discovery.PDPEndpoints{Identifier: own.URL, Evaluation: own.URL + "/e"},
		layerEP: func(pdp string) discovery.PDPEndpoints {
			return discovery.PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/e", Source: "layer"}
		},
	}
	e := NewEngine(Options{Resolver: fr})
	claims := map[string]any{"sub": "alice", "client_id": "c"}
	open, closed := true, false
	call := func(opts CallOptions) Verdict {
		return e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), claims, nil, opts)
	}

	// Closed by default: a failing layer is a PDP error.
	if v := call(CallOptions{Layers: []discovery.LayerSpec{{Name: down.URL}, {Name: "resource"}}}); v.Decision || !hasCode(v, CodePDPError) {
		t.Fatalf("%+v", v)
	}
	// Fail-open on the layer: skipped, named, and the rest of the policy decides.
	v := call(CallOptions{Layers: []discovery.LayerSpec{{Name: down.URL, FailOpen: &open}, {Name: "resource"}}})
	if !v.Decision || len(v.FailedOpen) != 1 || !strings.HasPrefix(v.FailedOpen[0], down.URL) {
		t.Fatalf("%+v", v)
	}
	// Fail-open on the call: same, unless the layer says closed for itself.
	if v := call(CallOptions{FailOpen: true, Layers: []discovery.LayerSpec{{Name: down.URL}, {Name: "resource"}}}); !v.Decision || len(v.FailedOpen) != 1 {
		t.Fatalf("%+v", v)
	}
	if v := call(CallOptions{FailOpen: true, Layers: []discovery.LayerSpec{{Name: down.URL, FailOpen: &closed}, {Name: "resource"}}}); v.Decision {
		t.Fatalf("fail-closed on the layer must win: %+v", v)
	}
	// Every layer skipped is a permit that says so.
	v = call(CallOptions{FailOpen: true, Layers: []discovery.LayerSpec{{Name: down.URL}}})
	if !v.Decision || len(v.FailedOpen) != 1 || !strings.HasPrefix(v.Reason, "fail-open:") {
		t.Fatalf("%+v", v)
	}
	// A deny is a decision: never skipped, whatever the mode.
	if v := call(CallOptions{FailOpen: true, Layers: []discovery.LayerSpec{{Name: deny.URL, FailOpen: &open}, {Name: "resource"}}}); v.Decision || !strings.HasSuffix(v.Reason, "no") {
		t.Fatalf("a deny must never fail open: %+v", v)
	}
	// A permit with nothing skipped carries no marker.
	if v := call(CallOptions{FailOpen: true, Layers: []discovery.LayerSpec{{Name: "resource"}}}); !v.Decision || v.FailedOpen != nil {
		t.Fatalf("%+v", v)
	}
	// The default-mapping path folds the same way.
	v = e.CheckToolCall(context.Background(), mcp.URL, "", []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}`),
		map[string]any{"sub": "alice", "aud": "https://m"}, nil,
		CallOptions{ApplyDefaultMappings: true, FailOpen: true, Layers: []discovery.LayerSpec{{Name: down.URL}, {Name: "resource"}}})
	if !v.Decision || len(v.FailedOpen) != 1 {
		t.Fatalf("default mappings: %+v", v)
	}
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

package coaz

// Conformance tests built from the profile's own non-normative examples.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

var specToken = map[string]any{
	"sub":       "demo-user@example.com",
	"client_id": "http://agentprovider.com/agent-app-id",
	"iss":       "https://auth.example.com",
	"exp":       1750000000,
}

func mustMapping(t *testing.T, name, raw string) *CompiledMapping {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	cm, err := CompileMapping(name, m)
	if err != nil {
		t.Fatalf("CompileMapping: %v", err)
	}
	return cm
}

func asJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// Spec §Single-valued Example: get_customer.
func TestSingleValuedExample(t *testing.T) {
	cm := mustMapping(t, "get_customer", `{
	  "resource": [{"id": "params.arguments.id", "type": "'customer'"}],
	  "subject":  [{"type": "'user'", "id": "token.sub"}],
	  "context":  [{"agent": "token.client_id", "case": "params.arguments.case"}]
	}`)
	params := map[string]any{
		"name":      "get_customer",
		"arguments": map[string]any{"id": "cust-12345", "case": "case-67890"},
	}
	built, err := cm.Build(params, specToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if built.Batch {
		t.Fatal("expected single evaluation API")
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	want := map[string]any{
		"subject":  map[string]any{"type": "user", "id": "demo-user@example.com"},
		"action":   map[string]any{"name": "get_customer"}, // default: tool name
		"resource": map[string]any{"type": "customer", "id": "cust-12345"},
		"context":  map[string]any{"agent": "http://agentprovider.com/agent-app-id", "case": "case-67890"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// Spec §Multi-valued Example: copy_object -> evaluations API with defaults.
func TestMultiValuedExample(t *testing.T) {
	cm := mustMapping(t, "copy_object", `{
	  "action":   [{"name": "'read'"}, {"name": "'write'"}],
	  "resource": [{"type": "'storage_object'", "id": "params.arguments.source"},
	               {"type": "'storage_object'", "id": "params.arguments.destination"}],
	  "subject":  [{"type": "'user'", "id": "token.sub"}],
	  "context":  [{"agent": "token.client_id"}]
	}`)
	params := map[string]any{
		"name": "copy_object",
		"arguments": map[string]any{
			"source":      "/bucket/reports/q1.pdf",
			"destination": "/bucket/archive/q1.pdf",
		},
	}
	built, err := cm.Build(params, specToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !built.Batch || built.Count != 2 {
		t.Fatalf("expected evaluations API with 2 items, got batch=%v count=%d", built.Batch, built.Count)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	want := map[string]any{
		"subject": map[string]any{"type": "user", "id": "demo-user@example.com"},
		"context": map[string]any{"agent": "http://agentprovider.com/agent-app-id"},
		"evaluations": []any{
			map[string]any{
				"action":   map[string]any{"name": "read"},
				"resource": map[string]any{"type": "storage_object", "id": "/bucket/reports/q1.pdf"},
			},
			map[string]any{
				"action":   map[string]any{"name": "write"},
				"resource": map[string]any{"type": "storage_object", "id": "/bucket/archive/q1.pdf"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n%v\nwant:\n%v", got, want)
	}
}

// CEL conditionals and numeric passthrough.
func TestCELConditionalsAndTypes(t *testing.T) {
	cm := mustMapping(t, "transfer_funds", `{
	  "resource": [{"type": "'account'", "id": "params.arguments.from_account"}],
	  "subject":  [{"type": "'user'", "id": "token.sub"}],
	  "context":  [{
	     "amount": "params.arguments.amount",
	     "tier": "params.arguments.amount > 1000.0 ? 'high' : 'low'",
	     "agent": "token.client_id"
	  }]
	}`)
	params := map[string]any{
		"name":      "transfer_funds",
		"arguments": map[string]any{"from_account": "acc-1", "amount": 9000.0},
	}
	built, err := cm.Build(params, specToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	ctx := got["context"].(map[string]any)
	if ctx["tier"] != "high" || ctx["amount"] != 9000.0 {
		t.Fatalf("conditional/number mapping failed: %v", ctx)
	}
}

// The profile requires >=1 subject/context field derived from `token`.
func TestTokenDerivationRequired(t *testing.T) {
	var m map[string]any
	_ = json.Unmarshal([]byte(`{
	  "resource": [{"type": "'r'", "id": "params.arguments.id"}],
	  "subject":  [{"type": "'user'", "id": "'static'"}],
	  "context":  [{"channel": "'web'"}]
	}`), &m)
	if _, err := CompileMapping("x", m); err == nil {
		t.Fatal("expected token-derivation validation error")
	}
}

func TestMismatchedMultiLengths(t *testing.T) {
	var m map[string]any
	_ = json.Unmarshal([]byte(`{
	  "action":   [{"name": "'a'"}, {"name": "'b'"}, {"name": "'c'"}],
	  "resource": [{"type": "'r'", "id": "'1'"}, {"type": "'r'", "id": "'2'"}],
	  "subject":  [{"type": "'user'", "id": "token.sub"}],
	  "context":  [{"agent": "token.client_id"}]
	}`), &m)
	if _, err := CompileMapping("x", m); err == nil {
		t.Fatal("expected mismatched-length validation error")
	}
}

// A CEL reference to a missing argument is a per-call mapping error (-32602).
func TestMissingArgumentIsMappingError(t *testing.T) {
	cm := mustMapping(t, "get_customer", `{
	  "resource": [{"id": "params.arguments.region", "type": "'customer'"}],
	  "subject":  [{"type": "'user'", "id": "token.sub"}],
	  "context":  [{"agent": "token.client_id"}]
	}`)
	params := map[string]any{"name": "get_customer", "arguments": map[string]any{"id": "x"}}
	if _, err := cm.Build(params, specToken, nil); err == nil {
		t.Fatal("expected evaluation error for missing argument")
	}
}

// ---------- Engine end-to-end against stub MCP + PDP servers ----------

const toolsListJSON = `{
  "jsonrpc": "2.0", "id": 1,
  "result": {"tools": [
    {"name": "get_customer", "coaz": true,
     "inputSchema": {"type": "object",
       "x-coaz-mapping": {
         "resource": [{"id": "params.arguments.id", "type": "'customer'"}],
         "subject":  [{"type": "'user'", "id": "token.sub"}],
         "context":  [{"agent": "token.client_id"}]}}},
    {"name": "plain_tool", "inputSchema": {"type": "object"}}
  ]}
}`

func newEngineForTest(t *testing.T, sse bool, pdpDecision bool, pdpReason string) (*Engine, *httptest.Server, *httptest.Server, *[]string) {
	t.Helper()
	var pdpBodies []string
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sse {
			// SSE data frames are single-line JSON; compact the fixture.
			var buf map[string]any
			_ = json.Unmarshal([]byte(toolsListJSON), &buf)
			line, _ := json.Marshal(buf)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: " + string(line) + "\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(toolsListJSON))
	}))
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(raw)
		pdpBodies = append(pdpBodies, string(raw))
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"decision": pdpDecision}
		if pdpReason != "" {
			resp["context"] = map[string]any{"reason": pdpReason}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(mcp.Close)
	t.Cleanup(pdp.Close)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL, APIKey: "k"}})
	return e, mcp, pdp, &pdpBodies
}

func toolCall(name string, args map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	return raw
}

func TestEnginePermit(t *testing.T) {
	for _, sse := range []bool{false, true} {
		e, mcp, _, _ := newEngineForTest(t, sse, true, "ok by policy")
		v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok",
			toolCall("get_customer", map[string]any{"id": "cust-1"}), specToken, nil)
		if !v.CoazTool || !v.Decision || v.JSONRPCError != nil {
			t.Fatalf("sse=%v expected permit, got %+v", sse, v)
		}
	}
}

func TestEngineDeny401(t *testing.T) {
	e, mcp, _, _ := newEngineForTest(t, false, false, "insufficient permissions for customer record")
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok",
		toolCall("get_customer", map[string]any{"id": "cust-1"}), specToken, nil)
	if v.Decision || v.JSONRPCError == nil {
		t.Fatalf("expected deny, got %+v", v)
	}
	got := asJSON(t, json.RawMessage(v.JSONRPCError))
	errObj := got["error"].(map[string]any)
	if errObj["code"].(float64) != -32401 {
		t.Fatalf("expected -32401, got %v", errObj)
	}
	if got["id"].(float64) != 7 {
		t.Fatalf("JSON-RPC id not echoed: %v", got)
	}
}

func TestEngineMappingError32602(t *testing.T) {
	e, mcp, _, _ := newEngineForTest(t, false, true, "")
	// `region` is not supplied -> CEL evaluation error -> -32602
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok",
		toolCall("get_customer", nil), specToken, nil)
	if v.Decision || v.JSONRPCError == nil {
		t.Fatalf("expected mapping error, got %+v", v)
	}
	got := asJSON(t, json.RawMessage(v.JSONRPCError))
	if got["error"].(map[string]any)["code"].(float64) != -32602 {
		t.Fatalf("expected -32602, got %v", got)
	}
}

func TestEngineNonCoazPassthrough(t *testing.T) {
	e, mcp, _, bodies := newEngineForTest(t, false, false, "")
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok",
		toolCall("plain_tool", map[string]any{}), specToken, nil)
	if v.CoazTool || !v.Decision {
		t.Fatalf("expected non-COAZ passthrough, got %+v", v)
	}
	if len(*bodies) != 0 {
		t.Fatal("PDP must not be called for non-COAZ tools")
	}
}

func TestEnginePDPUnreachable32603(t *testing.T) {
	e, mcp, pdp, _ := newEngineForTest(t, false, true, "")
	pdp.Close()
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok",
		toolCall("get_customer", map[string]any{"id": "c"}), specToken, nil)
	if v.Decision || v.JSONRPCError == nil {
		t.Fatalf("expected fail-closed, got %+v", v)
	}
	got := asJSON(t, json.RawMessage(v.JSONRPCError))
	if got["error"].(map[string]any)["code"].(float64) != -32603 {
		t.Fatalf("expected -32603, got %v", got)
	}
}

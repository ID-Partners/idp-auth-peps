package coaz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pdpServing answers every evaluation and evaluations call with a fixed body.
func pdpServing(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mcpServing answers tools/list with a fixed tools array.
func mcpServing(t *testing.T, toolsJSON string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":` + toolsJSON + `}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const boxcarTool = `[{
  "name": "transfer",
  "inputSchema": {"x-authzen-mapping": {"evaluations": {
    "subject": {"type": "identity", "id": "$token.sub"},
    "context": {"agent": "$token.?client_id"},
    "evaluations": [
      {"action": {"name": "debit"},  "resource": {"type": "account", "id": "$params.arguments.from"}},
      {"action": {"name": "credit"}, "resource": {"type": "account", "id": "$params.arguments.to"}}
    ]}}}
}]`

func toolsCallBody(name string, args map[string]any) []byte {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	return body
}

// A boxcar mapping must reach the evaluations API, and every decision must permit.
func TestCheckToolCallUsesTheEvaluationsAPI(t *testing.T) {
	var paths []string
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"evaluations":[{"decision":true},{"decision":true}]}`))
	}))
	defer pdp.Close()
	mcp := mcpServing(t, boxcarTool)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", toolsCallBody("transfer",
		map[string]any{"from": "a1", "to": "a2"}), map[string]any{"sub": "alice"}, nil, CallOptions{})

	if !v.Decision {
		t.Fatalf("all-permit boxcar should permit, got %+v", v)
	}
	if len(paths) != 1 || paths[0] != "/access/v1/evaluations" {
		t.Fatalf("a boxcar mapping must hit the evaluations API, got %v", paths)
	}
}

func TestCheckToolCallBoxcarDeniesIfAnyDecisionDoes(t *testing.T) {
	pdp := pdpServing(t, `{"evaluations":[{"decision":true},{"decision":false,"context":{"reason":"second leg"}}]}`, 200)
	mcp := mcpServing(t, boxcarTool)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", toolsCallBody("transfer",
		map[string]any{"from": "a1", "to": "a2"}), map[string]any{"sub": "alice"}, nil, CallOptions{})

	if v.Decision {
		t.Fatal("one deny in a boxcar must deny the whole call")
	}
	if !strings.Contains(v.Reason, "second leg") {
		t.Fatalf("the denying decision's reason should survive, got %q", v.Reason)
	}
}

func TestEvaluateRejectsUnusablePDPResponses(t *testing.T) {
	cases := map[string]struct {
		body   string
		status int
	}{
		"non-2xx":          {`{"decision":true}`, 500},
		"not json":         {`<html>`, 200},
		"empty boxcar":     {`{"evaluations":[]}`, 200},
		"boxcar not array": {`{"evaluations":"nope"}`, 200},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pdp := pdpServing(t, tc.body, tc.status)
			mcp := mcpServing(t, boxcarTool)
			e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
			v := e.CheckToolCall(context.Background(), mcp.URL, "", toolsCallBody("transfer",
				map[string]any{"from": "a", "to": "b"}), map[string]any{"sub": "alice"}, nil, CallOptions{})
			if v.Decision {
				t.Fatalf("%s must fail closed, got %+v", name, v)
			}
			if !strings.Contains(string(v.JSONRPCError), "-32603") {
				t.Fatalf("a PDP failure is -32603, got %s", v.JSONRPCError)
			}
		})
	}
}

func TestCheckToolCallIgnoresNonToolsCallBodies(t *testing.T) {
	pdp := pdpServing(t, `{"decision":false}`, 200)
	mcp := mcpServing(t, `[]`)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})

	// Not JSON at all: nothing to authorize, and not this engine's business.
	v := e.CheckToolCall(context.Background(), mcp.URL, "", []byte("not json"),
		map[string]any{"sub": "a"}, nil, CallOptions{})
	if !v.Decision || v.CoazTool {
		t.Fatalf("a non-JSON body should pass through, got %+v", v)
	}

	// A tools/call with no tool name has nothing to look up.
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{}})
	if v := e.CheckToolCall(context.Background(), mcp.URL, "", body, map[string]any{"sub": "a"}, nil, CallOptions{}); !v.Decision {
		t.Fatalf("a nameless tools/call should pass through, got %+v", v)
	}
}

func TestCheckToolCallSurfacesAPerToolMappingError(t *testing.T) {
	// Declared but broken: the tool is COAZ, so this is a mapping error rather than a
	// pass-through — silently allowing it would be the dangerous reading.
	broken := `[{"name":"bad","inputSchema":{"x-authzen-mapping":{"evaluation":{
	  "subject":{"type":"identity","id":"$token.sub"},
	  "action":{"name":"$("},
	  "resource":{"type":"r","id":"x"}}}}}]`
	pdp := pdpServing(t, `{"decision":true}`, 200)
	mcp := mcpServing(t, broken)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", toolsCallBody("bad", nil),
		map[string]any{"sub": "alice"}, nil, CallOptions{})
	if v.Decision {
		t.Fatal("a broken declared mapping must not permit")
	}
	if !strings.Contains(string(v.JSONRPCError), "-32602") {
		t.Fatalf("a mapping error is -32602, got %s", v.JSONRPCError)
	}
}

func TestDefaultMappingPathHandlesPDPFailureAndDeny(t *testing.T) {
	mcp := mcpServing(t, `[]`)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}`)
	opts := CallOptions{ApplyDefaultMappings: true}
	claims := map[string]any{"sub": "alice", "aud": "srv"}

	t.Run("pdp unreachable", func(t *testing.T) {
		pdp := pdpServing(t, `{}`, 500)
		e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
		v := e.CheckToolCall(context.Background(), mcp.URL, "", body, claims, nil, opts)
		if v.Decision || !strings.Contains(string(v.JSONRPCError), "-32603") {
			t.Fatalf("a default-mapping PDP failure must fail closed with -32603, got %+v", v)
		}
	})

	t.Run("mapping error", func(t *testing.T) {
		pdp := pdpServing(t, `{"decision":true}`, 200)
		e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
		// No aud claim: resource.id for a server-scoped default cannot resolve.
		v := e.CheckToolCall(context.Background(), mcp.URL, "",
			[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`),
			map[string]any{"sub": "alice"}, nil, opts)
		if v.Decision || !strings.Contains(string(v.JSONRPCError), "-32602") {
			t.Fatalf("an unresolvable default mapping is -32602, got %+v", v)
		}
	})

	t.Run("permit carries the reason", func(t *testing.T) {
		pdp := pdpServing(t, `{"decision":true,"context":{"reason":"fine"}}`, 200)
		e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
		v := e.CheckToolCall(context.Background(), mcp.URL, "", body, claims, nil, opts)
		if !v.Decision || v.Reason != "fine" {
			t.Fatalf("permit reason should survive, got %+v", v)
		}
	})
}

func TestEngineDefaultsCanBeEnabledEngineWide(t *testing.T) {
	// The per-call option and the engine-wide setting are both honoured; a deployment
	// that sets it once should not have to thread it through every call.
	pdp := pdpServing(t, `{"decision":false,"context":{"reason":"no"}}`, 200)
	mcp := mcpServing(t, `[]`)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}, ApplyDefaultMappings: true})

	v := e.CheckToolCall(context.Background(), mcp.URL, "",
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{}}`),
		map[string]any{"sub": "alice", "aud": "srv"}, nil, CallOptions{})
	if v.Decision {
		t.Fatal("engine-wide defaults should govern this call")
	}
}

// ---------------------------------------------------------------------------
// v1 dialect: still supported, so still exercised.

func TestV1MappingProcessingRules(t *testing.T) {
	t.Run("multi-element fields zip into a boxcar", func(t *testing.T) {
		cm := mustMapping(t, "t", `{
		  "subject":  [{"type": "'user'", "id": "token.sub"}],
		  "resource": [{"type": "'a'", "id": "'r1'"}, {"type": "'a'", "id": "'r2'"}],
		  "context":  [{"agent": "token.client_id"}]
		}`)
		built, err := cm.Build(map[string]any{}, specToken, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !built.Batch || built.Count != 2 {
			t.Fatalf("v1 zips by length: batch=%v count=%d", built.Batch, built.Count)
		}
	})

	t.Run("mismatched lengths are rejected", func(t *testing.T) {
		var m map[string]any
		_ = json.Unmarshal([]byte(`{
		  "subject":  [{"id": "token.sub"}, {"id": "token.sub"}],
		  "resource": [{"id": "'a'"}, {"id": "'b'"}, {"id": "'c'"}],
		  "context":  [{"agent": "token.client_id"}]
		}`), &m)
		if _, err := CompileMapping("t", m); err == nil {
			t.Fatal("mismatched multi-valued field lengths must be rejected")
		}
	})

	t.Run("required fields", func(t *testing.T) {
		for name, raw := range map[string]string{
			"no subject":  `{"resource": [{"id": "'a'"}], "context": [{"a": "token.sub"}]}`,
			"no resource": `{"subject": [{"id": "token.sub"}], "context": [{"a": "'b'"}]}`,
			"no context":  `{"subject": [{"id": "token.sub"}], "resource": [{"id": "'a'"}]}`,
		} {
			t.Run(name, func(t *testing.T) {
				var m map[string]any
				_ = json.Unmarshal([]byte(raw), &m)
				if _, err := CompileMapping("t", m); err == nil {
					t.Fatalf("%s should be rejected", name)
				}
			})
		}
	})

	t.Run("uncompilable leaf", func(t *testing.T) {
		var m map[string]any
		_ = json.Unmarshal([]byte(`{
		  "subject":  [{"id": "token.sub"}],
		  "resource": [{"id": "this is not ( valid"}],
		  "context":  [{"agent": "token.client_id"}]
		}`), &m)
		if _, err := CompileMapping("t", m); err == nil {
			t.Fatal("a leaf that will not compile must fail at compile time")
		}
	})

	t.Run("token derivation is detected through nesting", func(t *testing.T) {
		// The rule is "at least one subject or context field derived from token"; the
		// walk has to see through lists, maps and function calls to enforce it.
		cm := mustMapping(t, "t", `{
		  "subject":  [{"id": "'static'"}],
		  "resource": [{"id": "'r'"}],
		  "context":  [{"nested": {"deep": ["'a'", "'b'", "string(token.sub)"]}}]
		}`)
		if cm == nil {
			t.Fatal("a token reference nested inside a list inside a map still counts")
		}
	})
}

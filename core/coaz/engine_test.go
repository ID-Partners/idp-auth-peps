package coaz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
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

func TestCheckToolCallRefusesBodiesItCannotRead(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, `[]`)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})

	// A body the engine cannot read is one it cannot vouch for: refused with a 400, and
	// never handed to the PDP — let alone waved through, which is what an upstream that
	// reads the bytes differently would exploit.
	for name, body := range map[string]string{
		"not JSON":        "not json",
		"batch":           `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer"}}]`,
		"nameless call":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
		"folded params":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer"},"Params":{"name":"x"}}`,
		"truncated":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_cust`,
		"trailing object": `{"jsonrpc":"2.0","id":1,"method":"ping"}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_customer"}}`,
	} {
		v := e.CheckToolCall(context.Background(), mcp.URL, "", []byte(body), map[string]any{"sub": "a"}, nil, CallOptions{})
		if v.Decision || v.PassThrough || v.HTTPStatus != http.StatusBadRequest || len(v.JSONRPCError) == 0 {
			t.Fatalf("%s: must be refused with a 400 JSON-RPC error, got %+v", name, v)
		}
	}
	if len(*reqs) != 0 {
		t.Fatalf("a refused body must never reach the PDP, got %d calls", len(*reqs))
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

// Fail-open covers the PDP being unavailable, never the PDP refusing. A 401 from a
// rotated key, or a 413 a client provoked with an oversized argument, must not switch a
// fail-open layer off.
func TestFailOpenSkipsOnlyAnUnavailablePDP(t *testing.T) {
	mcp := mcpServing(t, singleTool)
	own := pdpServing(t, `{"decision":true}`, 200)
	open := true
	cases := map[string]struct {
		status  int
		body    string
		skipped bool
	}{
		"503":          {503, `{}`, true},
		"500":          {500, `{}`, true},
		"429":          {429, `{}`, true},
		"400":          {400, `{}`, false},
		"401":          {401, `{}`, false},
		"403":          {403, `{}`, false},
		"404":          {404, `{}`, false},
		"413":          {413, `{}`, false},
		"302":          {302, `{}`, false},
		"garbage 200":  {200, `<html>`, false},
		"string true":  {200, `{"decision":"true"}`, false},
		"numeric true": {200, `{"decision":1}`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			layer := pdpServing(t, c.body, c.status)
			fr := &fakeResolver{
				ep: discovery.PDPEndpoints{Identifier: own.URL, Evaluation: own.URL + "/e"},
				layerEP: func(pdp string) discovery.PDPEndpoints {
					return discovery.PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/e"}
				},
			}
			e := NewEngine(Options{Resolver: fr})
			v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), map[string]any{"sub": "alice", "client_id": "c"}, nil,
				CallOptions{Layers: []discovery.LayerSpec{{Name: layer.URL, FailOpen: &open}, {Name: "resource"}}})
			if c.skipped {
				if !v.Decision || len(v.FailedOpen) != 1 || v.FailedOpen[0] != layer.URL {
					t.Fatalf("an unavailable fail-open layer is skipped and named, got %+v", v)
				}
				return
			}
			if v.Decision || !hasCode(v, CodePDPError) {
				t.Fatalf("a refusal must fail closed even on a fail-open layer, got %+v", v)
			}
		})
	}
}

func TestFailOpenSkipsAnUnreachablePDPAndNamesItWithoutDetail(t *testing.T) {
	mcp := mcpServing(t, singleTool)
	own := pdpServing(t, `{"decision":true}`, 200)
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // connection refused
	fr := &fakeResolver{
		ep: discovery.PDPEndpoints{Identifier: own.URL, Evaluation: own.URL + "/e"},
		layerEP: func(pdp string) discovery.PDPEndpoints {
			return discovery.PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/e"}
		},
	}
	open := true
	v := NewEngine(Options{Resolver: fr}).CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice", "client_id": "c"}, nil,
		CallOptions{Layers: []discovery.LayerSpec{{Name: gone.URL, FailOpen: &open}, {Name: "resource"}}})
	if !v.Decision || len(v.FailedOpen) != 1 || v.FailedOpen[0] != gone.URL {
		t.Fatalf("an unreachable fail-open layer is skipped and named by identifier only, got %+v", v)
	}
}

func TestLayerNamesDropsTheDetail(t *testing.T) {
	got := LayerNames([]string{"https://pdp.example (dial tcp 10.0.0.9:443: refused)", "static", "https://b.example (published by https://r: x)"})
	want := []string{"https://pdp.example", "static", "https://b.example"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("LayerNames = %v, want %v", got, want)
		}
	}
	if LayerNames(nil) != nil {
		t.Fatal("no skipped layers is nil, so a permit carries no marker")
	}
}

// Every MCP message is decided: with defaults on, methods other than tools/call go to
// the PDP through their default mappings, responses and pings pass, and a method the
// binding does not know is denied.
func TestCheckMCPDecidesEveryMethod(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, singleTool)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	claims := map[string]any{"sub": "alice", "aud": "https://mcp.example", "client_id": "c"}
	on := CallOptions{ApplyDefaultMappings: true}
	check := func(body string, opts CallOptions) Verdict {
		return e.CheckToolCall(context.Background(), mcp.URL, "", []byte(body), claims, nil, opts)
	}

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"action":"accept"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	} {
		if v := check(body, on); !v.Decision || !v.PassThrough {
			t.Fatalf("%s passes through, got %+v", body, v)
		}
	}
	if len(*reqs) != 0 {
		t.Fatalf("pass-through messages never reach the PDP, got %d calls", len(*reqs))
	}

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///x"}}`,
	} {
		before := len(*reqs)
		if v := check(body, on); !v.Decision || v.PassThrough || len(*reqs) != before+1 {
			t.Fatalf("%s must be decided by the PDP, got %+v", body, v)
		}
	}

	if v := check(`{"jsonrpc":"2.0","id":6,"method":"future/method"}`, on); v.Decision || !hasCode(v, CodeDeniedV2) {
		t.Fatalf("an unknown method is denied, got %+v", v)
	}

	// The explicit opt-out keeps the old pass-through for everything but declared tools.
	if v := check(`{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"file:///x"}}`, CallOptions{}); !v.Decision || !v.PassThrough {
		t.Fatalf("defaults off passes resources/read through, got %+v", v)
	}
}

// With no upstream to read declarations from, a tools/call is judged by the default
// mapping rather than waved through.
func TestToolsCallWithoutAnUpstreamUsesTheDefaultMapping(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":false}`)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), "", "", toolsCallBody("pay", map[string]any{"amount": 5}),
		map[string]any{"sub": "alice", "client_id": "c"}, nil, CallOptions{ApplyDefaultMappings: true})
	if v.Decision || len(*reqs) != 1 {
		t.Fatalf("a tools/call with no upstream is asked of the PDP by the default mapping, got %+v (%d calls)", v, len(*reqs))
	}
}

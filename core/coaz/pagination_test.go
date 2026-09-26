package coaz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pagedMCP serves tools/list across pages, following the cursor it hands out.
func pagedMCP(t *testing.T, pages [][]string, forever bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		page := 0
		fmt.Sscanf(req.Params.Cursor, "p%d", &page)
		result := map[string]any{"tools": []any{}}
		if page < len(pages) {
			var tools []any
			for _, raw := range pages[page] {
				var tool any
				_ = json.Unmarshal([]byte(raw), &tool)
				tools = append(tools, tool)
			}
			result["tools"] = tools
		}
		if page+1 < len(pages) || forever {
			result["nextCursor"] = fmt.Sprintf("p%d", page+1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	t.Cleanup(srv.Close)
	return srv
}

const declaredOnPageTwo = `{"name":"get_customer","inputSchema":{"x-authzen-mapping":{"evaluation":{
  "subject":{"type":"identity","id":"$token.sub"},"action":{"name":"read_customer"},
  "resource":{"type":"customer","id":"$params.arguments.id"}}}}}`

// A tool declared on page two is governed by its own mapping, not treated as undeclared.
func TestDiscoveryFollowsTheCursor(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := pagedMCP(t, [][]string{{`{"name":"other","inputSchema":{}}`}, {declaredOnPageTwo}}, false)
	v := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}}).CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice"}, nil, CallOptions{ApplyDefaultMappings: true})
	if !v.Decision || len(*reqs) != 1 || !strings.Contains(string(v.PDPRequest), "read_customer") {
		t.Fatalf("the page-two declaration must govern the call: %+v", v)
	}
}

// A server with more pages than the PEP reads is refused, not half-read.
func TestDiscoveryRefusesEndlessPagination(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := pagedMCP(t, [][]string{{`{"name":"x","inputSchema":{}}`}}, true)
	v := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}}).CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice"}, nil, CallOptions{ApplyDefaultMappings: true})
	if v.Decision || !hasCode(v, CodePDPError) || len(*reqs) != 0 {
		t.Fatalf("%+v", v)
	}
}

// Two declarations of one tool: neither governs, every call is a mapping error.
func TestDiscoveryRefusesADuplicatedTool(t *testing.T) {
	pdp, _ := recordingPDP(t, `{"decision":true}`)
	mcp := pagedMCP(t, [][]string{{declaredOnPageTwo}, {`{"name":"get_customer","inputSchema":{}}`}}, false)
	v := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}}).CheckToolCall(context.Background(), mcp.URL, "", singleCall(),
		map[string]any{"sub": "alice"}, nil, CallOptions{ApplyDefaultMappings: true})
	if v.Decision || !hasCode(v, CodeMappingError) {
		t.Fatalf("%+v", v)
	}
}

func TestRequireV2RefusesASupersededDeclaration(t *testing.T) {
	pdp, reqs := recordingPDP(t, `{"decision":true}`)
	mcp := mcpServing(t, singleTool) // declared with coaz:true
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	claims := map[string]any{"sub": "alice", "client_id": "c"}
	if v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), claims, nil, CallOptions{RequireV2: true}); v.Decision || !hasCode(v, CodeMappingError) || len(*reqs) != 0 {
		t.Fatalf("%+v", v)
	}
	if v := e.CheckToolCall(context.Background(), mcp.URL, "", singleCall(), claims, nil, CallOptions{}); !v.Decision {
		t.Fatalf("without the switch a v1 tool still works: %+v", v)
	}
}

// The upstream writes the mapping; it does not get to write an unbounded one.
func TestMappingLeafCap(t *testing.T) {
	ctx := map[string]any{}
	for i := 0; i <= maxMappingLeaves; i++ {
		ctx[fmt.Sprintf("k%d", i)] = "$token.sub"
	}
	_, err := CompileMappingV2("t", map[string]any{"evaluation": map[string]any{
		"subject": map[string]any{"type": "identity", "id": "$token.sub"}, "action": map[string]any{"name": "t"},
		"resource": map[string]any{"type": "r", "id": "x"}, "context": ctx}})
	if err == nil || !strings.Contains(err.Error(), "expressions") {
		t.Fatalf("a mapping past the leaf cap must be refused: %v", err)
	}
	v1ctx := map[string]any{}
	for k, v := range ctx {
		v1ctx[k] = strings.TrimPrefix(v.(string), "$")
	}
	if _, err := CompileMapping("t", map[string]any{
		"subject": []any{map[string]any{"id": "token.sub"}}, "resource": []any{map[string]any{"id": "'x'"}},
		"context": []any{v1ctx}}); err == nil {
		t.Fatal("the leaf cap applies to v1 mappings too")
	}
}

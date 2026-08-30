package coaz

// COAZ over SSE, aggressively.
//
// MCP streamable HTTP lets a server answer any JSON-RPC request as an SSE stream, so
// every part of the COAZ flow — discovery, the session handshake, and the answers a
// gateway relays — has to survive real-world SSE: keepalive comments, CRLF endings,
// multi-frame streams, split data lines, id/retry fields, and oversized frames. Each
// test drives the FULL engine (discovery -> mapping -> PDP -> verdict), not just the
// frame parser, so a framing bug shows up as the wrong authorization outcome — which is
// what it would be in production.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sseFrame renders one JSON-RPC payload as an SSE frame with configurable quirks.
type sseQuirks struct {
	crlf    bool // CRLF line endings
	noSpace bool // "data:x" instead of "data: x"
	// prettyPrint re-serialises the payload with MarshalIndent and sends each line as
	// its own data line. This is the REALISTIC multi-line frame: a sender can only
	// split where its own serialisation puts newlines — between tokens — because the
	// receiver joins data lines with a newline. Splitting at arbitrary byte offsets
	// lands inside string tokens and correctly fails to parse (covered separately).
	prettyPrint bool
	leadingJunk string // comments/events emitted before the data frame
	trailer     string // emitted after the frame (e.g. a second frame)
	noBlankEnd  bool   // omit the terminating blank line
}

func sseFrame(payload []byte, q sseQuirks) string {
	nl := "\n"
	if q.crlf {
		nl = "\r\n"
	}
	var b strings.Builder
	if q.leadingJunk != "" {
		b.WriteString(strings.ReplaceAll(q.leadingJunk, "\n", nl))
	}
	prefix := "data: "
	if q.noSpace {
		prefix = "data:"
	}
	if q.prettyPrint {
		var v any
		if err := json.Unmarshal(payload, &v); err != nil {
			panic(err)
		}
		pretty, _ := json.MarshalIndent(v, "", "  ")
		for _, line := range strings.Split(string(pretty), "\n") {
			b.WriteString(prefix + line + nl)
		}
	} else {
		b.WriteString(prefix + string(payload) + nl)
	}
	if !q.noBlankEnd {
		b.WriteString(nl)
	}
	if q.trailer != "" {
		b.WriteString(strings.ReplaceAll(q.trailer, "\n", nl))
	}
	return b.String()
}

const tortureTool = `{
  "name": "make_payment",
  "inputSchema": {"x-authzen-mapping": {"evaluation": {
    "subject": {"type": "identity", "id": "$token.sub"},
    "action": {"name": "make_payment"},
    "resource": {"type": "payment", "id": "$params.arguments.payment_id"},
    "context": {"agent": "$token.?client_id"}
  }}}
}`

// sseMCP serves tools/list as SSE with the given quirks, and refuses non-SSE.
func sseMCP(t *testing.T, quirks sseQuirks) *httptest.Server {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"tools": []json.RawMessage{json.RawMessage(tortureTool)}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sseFrame(payload, quirks)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tortureCall() []byte {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": "make_payment", "arguments": map[string]any{"payment_id": "p-1"}},
	})
	return body
}

var tortureToken = map[string]any{"sub": "alice@example.com", "client_id": "agent-1"}

// Every SSE quirk, end to end: the tool must be discovered, mapped, evaluated, and the
// PDP must have been asked about the RIGHT payment.
func TestCoazOverSSEQuirks(t *testing.T) {
	quirks := map[string]sseQuirks{
		"plain":                             {},
		"crlf endings":                      {crlf: true},
		"no space after colon":              {noSpace: true},
		"pretty-printed across data lines":  {prettyPrint: true},
		"pretty-printed with crlf":          {prettyPrint: true, crlf: true},
		"keepalives and event fields first": {leadingJunk: ": keepalive\n: another\nevent: message\nid: 42\nretry: 3000\n"},
		"second frame after the first":      {trailer: "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"tools\":[]}}\n\n"},
		"no terminating blank line":         {noBlankEnd: true},
	}
	for name, q := range quirks {
		t.Run(name, func(t *testing.T) {
			var asked []byte
			pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked = make([]byte, r.ContentLength)
				_, _ = r.Body.Read(asked)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"decision":true}`))
			}))
			defer pdp.Close()
			mcp := sseMCP(t, q)

			e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
			v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer t", tortureCall(), tortureToken, nil, CallOptions{})
			if !v.CoazTool || !v.Decision {
				t.Fatalf("expected a governed permit, got %+v", v)
			}
			if !strings.Contains(string(asked), `"p-1"`) {
				t.Fatalf("the PDP was asked about the wrong thing: %s", asked)
			}
		})
	}
}

// A data line split INSIDE a JSON string must reassemble per the spec (joined with a
// newline). If the split lands inside a string the payload is invalid JSON, and the
// engine must fail closed — never permit on a half-read declaration.
func TestCoazOverSSESplitInsideAStringFailsClosed(t *testing.T) {
	// Craft a payload whose only valid parse requires the two halves to be
	// concatenated WITHOUT a newline — i.e. an SSE server that splits mid-string.
	// Spec framing makes this unparseable, and unparseable must mean deny.
	raw := `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + tortureTool + `]}}`
	cut := strings.Index(raw, "make_payment") + 4 // inside the string "make_payment"
	frame := "data: " + raw[:cut] + "\ndata: " + raw[cut:] + "\n\n"

	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(frame))
	}))
	defer mcp.Close()
	pdp := pdpServing(t, `{"decision":true}`, 200)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", tortureCall(), tortureToken, nil, CallOptions{})
	if v.Decision {
		t.Fatal("a mangled declaration stream must fail closed, not permit")
	}
	if !strings.Contains(string(v.JSONRPCError), "-32603") {
		t.Fatalf("discovery failure is -32603, got %s", v.JSONRPCError)
	}
}

// An SSE line larger than the 4MB scanner buffer must be an error, not a truncated
// frame treated as complete.
func TestCoazOverSSEOversizedLineFailsClosed(t *testing.T) {
	huge := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"pad\":\"" +
		strings.Repeat("x", 5<<20) + "\"}}\n\n"
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(huge))
	}))
	defer mcp.Close()
	pdp := pdpServing(t, `{"decision":true}`, 200)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", tortureCall(), tortureToken, nil, CallOptions{})
	if v.Decision {
		t.Fatal("an oversized SSE line must fail closed")
	}
}

// A JSON-RPC ERROR delivered over SSE must surface as a discovery failure, exactly as
// it would over plain JSON.
func TestCoazOverSSEJSONRPCErrorSurfaces(t *testing.T) {
	frame := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"server exploded\"}}\n\n"
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(frame))
	}))
	defer mcp.Close()
	pdp := pdpServing(t, `{"decision":true}`, 200)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", tortureCall(), tortureToken, nil, CallOptions{})
	if v.Decision {
		t.Fatal("a JSON-RPC error from discovery must fail closed")
	}
	if !strings.Contains(v.Reason, "server exploded") {
		t.Fatalf("the upstream's error should survive into the reason, got %q", v.Reason)
	}
}

// The full session handshake, everything over SSE: initialize answered as an SSE frame
// carrying the session id in the header, notifications as 202, tools/list as SSE — and
// then a real COAZ evaluation through the discovered tool.
func TestCoazOverSSESessionHandshakeEndToEnd(t *testing.T) {
	const session = "sse-sess-1"
	var sequence []string
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 2,
		"result": map[string]any{"tools": []json.RawMessage{json.RawMessage(tortureTool)}},
	})

	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		sequence = append(sequence, req.Method+"/"+r.Header.Get("Mcp-Session-Id"))
		switch req.Method {
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != session {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"session required"}`))
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(sseFrame(payload, sseQuirks{crlf: true, prettyPrint: true,
				leadingJunk: ": ka\n"})))
		case "initialize":
			w.Header().Set("Mcp-Session-Id", session)
			w.Header().Set("Content-Type", "text/event-stream")
			init, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"protocolVersion": mcpProtocolVersion}})
			_, _ = w.Write([]byte(sseFrame(init, sseQuirks{})))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer mcp.Close()

	pdp := pdpServing(t, `{"decision":false,"context":{"reason":"payment over limit","step_up_required":true,"step_up_scope":"payments:approve"}}`, 200)
	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer t", tortureCall(), tortureToken, nil, CallOptions{})

	// The handshake ran in order with the session carried.
	want := []string{"tools/list/", "initialize/", "notifications/initialized/" + session, "tools/list/" + session}
	if strings.Join(sequence, ",") != strings.Join(want, ",") {
		t.Fatalf("handshake sequence = %v, want %v", sequence, want)
	}

	// And the SSE-discovered tool produced a REAL verdict: a step-up challenge with
	// the structured authz_challenge, not a flat deny.
	if v.Decision {
		t.Fatal("the PDP said step up; the verdict must deny")
	}
	var rpcErr struct {
		Error struct {
			Code int `json:"code"`
			Data struct {
				Challenge AuthzChallenge `json:"authz_challenge"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(v.JSONRPCError, &rpcErr); err != nil {
		t.Fatalf("verdict should carry a JSON-RPC error: %v", err)
	}
	if rpcErr.Error.Code != -32001 {
		t.Fatalf("v2 tool denies with -32001, got %d", rpcErr.Error.Code)
	}
	if rpcErr.Error.Data.Challenge.Type != "resource_authorisation" || rpcErr.Error.Data.Challenge.Scope != "payments:approve" {
		t.Fatalf("the step-up challenge must survive the SSE path intact: %+v", rpcErr.Error.Data.Challenge)
	}
}

// The identity-proofing advice branch through an SSE-discovered tool.
func TestCoazOverSSEIdentityChallenge(t *testing.T) {
	mcp := sseMCP(t, sseQuirks{crlf: true})
	pdp := pdpServing(t, `{"decision":false,"context":{"identity_proofing_required":true,"identity_proofing_doctype":"org.iso.18013.5.1.mDL","reason":"no proofing activity"}}`, 200)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
	v := e.CheckToolCall(context.Background(), mcp.URL, "", tortureCall(), tortureToken, nil, CallOptions{})
	if v.Decision {
		t.Fatal("identity advice must deny with a challenge")
	}
	raw := string(v.JSONRPCError)
	for _, want := range []string{"-32001", "identity_proofing", "org.iso.18013.5.1.mDL", "identity_verification_required"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("challenge missing %q: %s", want, raw)
		}
	}
}

// Discovery caching still applies when the transport is SSE: two calls, one fetch.
func TestCoazOverSSEDiscoveryIsCached(t *testing.T) {
	var fetches int
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"tools": []json.RawMessage{json.RawMessage(tortureTool)}},
	})
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sseFrame(payload, sseQuirks{})))
	}))
	defer mcp.Close()
	pdp := pdpServing(t, `{"decision":true}`, 200)

	e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}, DiscoveryTTL: time.Minute})
	for i := 0; i < 3; i++ {
		if v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer same", tortureCall(), tortureToken, nil, CallOptions{}); !v.Decision {
			t.Fatalf("call %d should permit: %+v", i, v)
		}
	}
	if fetches != 1 {
		t.Fatalf("three calls with one credential should discover once, got %d fetches", fetches)
	}
}

// A wrong Content-Type must not be sniffed as SSE: a JSON body labelled event-stream
// has no data frame and is an error, and an SSE body labelled JSON is JSON-parse junk.
// Both fail closed.
func TestCoazOverSSEContentTypeConfusionFailsClosed(t *testing.T) {
	cases := map[string]struct{ contentType, body string }{
		"json labelled as sse": {"text/event-stream", `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`},
		"sse labelled as json": {"application/json", "event: message\ndata: {}\n\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer mcp.Close()
			pdp := pdpServing(t, `{"decision":true}`, 200)
			e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
			v := e.CheckToolCall(context.Background(), mcp.URL, "", tortureCall(), tortureToken, nil, CallOptions{})
			if v.Decision {
				t.Fatalf("%s must fail closed rather than permit on a misread stream", name)
			}
		})
	}
}

// The engine's evaluate() must send the built request over the wire byte-identically
// whether the declaration arrived by JSON or SSE — the transport must not leak into
// the authorization question.
func TestCoazTransportDoesNotChangeTheQuestion(t *testing.T) {
	ask := func(sse bool) string {
		var asked string
		pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			asked = string(b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"decision":true}`))
		}))
		defer pdp.Close()

		payload, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"tools": []json.RawMessage{json.RawMessage(tortureTool)}},
		})
		mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if sse {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(sseFrame(payload, sseQuirks{prettyPrint: true, crlf: true})))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(payload)
		}))
		defer mcp.Close()

		e := NewEngine(Options{PDP: PDPConfig{URL: pdp.URL}})
		if v := e.CheckToolCall(context.Background(), mcp.URL, "", tortureCall(), tortureToken, nil, CallOptions{}); !v.Decision {
			panic(fmt.Sprintf("expected permit: %+v", v))
		}
		return asked
	}
	if json, sse := ask(false), ask(true); json != sse {
		t.Fatalf("the PDP request must not depend on the discovery transport\n json: %s\n  sse: %s", json, sse)
	}
}

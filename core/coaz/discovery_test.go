package coaz

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

// sessionServer behaves like a session-requiring MCP server: a bare tools/list is
// refused, and only the initialize -> notifications/initialized -> tools/list handshake
// succeeds, with the session id carried in Mcp-Session-Id throughout.
type sessionServer struct {
	*httptest.Server
	sse           bool
	sessionID     string
	seenSessions  []string
	sawNotified   bool
	methodsCalled []string
}

func newSessionServer(t *testing.T, sse bool, tools []map[string]any) *sessionServer {
	t.Helper()
	s := &sessionServer{sse: sse, sessionID: "sess-abc123"}

	write := func(w http.ResponseWriter, payload any) {
		raw, _ := json.Marshal(payload)
		if s.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			// Framed the way a real SSE reply arrives: an event line, the data line,
			// then the blank line that terminates the frame.
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", raw)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	}

	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.methodsCalled = append(s.methodsCalled, req.Method)
		s.seenSessions = append(s.seenSessions, r.Header.Get("Mcp-Session-Id"))

		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", s.sessionID)
			write(w, map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"protocolVersion": mcpProtocolVersion}})
		case "notifications/initialized":
			s.sawNotified = true
			w.WriteHeader(http.StatusAccepted) // notifications get 202 with no body
		case "tools/list":
			// Refuse unless the handshake has happened and the session is presented.
			if r.Header.Get("Mcp-Session-Id") != s.sessionID {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"session required"}`))
				return
			}
			write(w, map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"tools": tools}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

var declaredTool = map[string]any{
	"name": "get_customer",
	"inputSchema": map[string]any{
		"x-authzen-mapping": map[string]any{
			"evaluation": map[string]any{
				"subject":  map[string]any{"type": "identity", "id": "$token.sub"},
				"action":   map[string]any{"name": "get_customer"},
				"resource": map[string]any{"type": "customer", "id": "$params.arguments.id"},
			},
		},
	},
}

// The session handshake is the trickiest part of discovery — SSE framing, the session
// id carried across three calls, and a 202 with no body in the middle.
func TestDiscoveryRunsTheSessionHandshake(t *testing.T) {
	for _, sse := range []bool{false, true} {
		name := "json"
		if sse {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) {
			srv := newSessionServer(t, sse, []map[string]any{declaredTool})
			d := newDiscoveryCache(time.Minute, srv.Client())

			tool, err := d.lookup(context.Background(), srv.URL, "Bearer tok", "get_customer")
			if err != nil {
				t.Fatalf("handshake discovery failed: %v", err)
			}
			if tool == nil || !tool.declared() {
				t.Fatal("the declared tool should have been found")
			}

			// The bare attempt is made first, fails, and the handshake follows.
			want := []string{"tools/list", "initialize", "notifications/initialized", "tools/list"}
			if strings.Join(srv.methodsCalled, ",") != strings.Join(want, ",") {
				t.Fatalf("call sequence = %v, want %v", srv.methodsCalled, want)
			}
			if !srv.sawNotified {
				t.Error("notifications/initialized should be sent before tools/list")
			}
			// The session id must be carried on everything after initialize, or the
			// server refuses and discovery loops.
			if got := srv.seenSessions; got[0] != "" || got[1] != "" || got[2] != srv.sessionID || got[3] != srv.sessionID {
				t.Fatalf("session ids per call = %v, want the id carried after initialize", got)
			}
		})
	}
}

func TestDiscoveryFailsWhenTheHandshakeDoes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"nope"}`))
	}))
	defer srv.Close()

	d := newDiscoveryCache(time.Minute, srv.Client())
	if _, err := d.lookup(context.Background(), srv.URL, "", "any"); err == nil {
		t.Fatal("discovery must fail closed when the upstream refuses")
	} else if !strings.Contains(err.Error(), "discovery from") {
		t.Fatalf("the error should name what failed, got %v", err)
	}
}

func TestDiscoveryPropagatesAJSONRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}`))
	}))
	defer srv.Close()

	d := newDiscoveryCache(time.Minute, srv.Client())
	_, err := d.lookup(context.Background(), srv.URL, "", "any")
	if err == nil || !strings.Contains(err.Error(), "no such method") {
		t.Fatalf("a JSON-RPC error should surface, got %v", err)
	}
}

func TestDiscoveryRejectsAMalformedToolsList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"not an object"}`))
	}))
	defer srv.Close()

	d := newDiscoveryCache(time.Minute, srv.Client())
	if _, err := d.lookup(context.Background(), srv.URL, "", "any"); err == nil {
		t.Fatal("a result that is not a tools object must fail rather than yield nothing")
	}
}

func TestDiscoverySkipsUnusableToolEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A nameless entry and a non-object entry sit alongside a good one.
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		  {"description":"no name"},
		  "not an object",
		  {"name":"plain_tool"}
		]}}`))
	}))
	defer srv.Close()

	d := newDiscoveryCache(time.Minute, srv.Client())
	tool, err := d.lookup(context.Background(), srv.URL, "", "plain_tool")
	if err != nil {
		t.Fatalf("unusable entries should be skipped, not fatal: %v", err)
	}
	if tool == nil {
		t.Fatal("the usable tool should still be found")
	}
	if tool.declared() {
		t.Fatal("a tool with no mapping is not declared")
	}
}

func TestDiscoveryServesAStaleEntryWhenARefreshFails(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"plain_tool"}]}}`))
	}))
	defer srv.Close()

	// A TTL short enough that the second lookup refreshes.
	d := newDiscoveryCache(time.Nanosecond, srv.Client())
	if _, err := d.lookup(context.Background(), srv.URL, "", "plain_tool"); err != nil {
		t.Fatal(err)
	}
	fail = true
	// A failed refresh must not throw away a view that still works — otherwise a brief
	// upstream blip turns into a deny for every governed call.
	if _, err := d.lookup(context.Background(), srv.URL, "", "plain_tool"); err != nil {
		t.Fatalf("a failed refresh should keep serving the previous good entry: %v", err)
	}
}

func TestFirstSSEData(t *testing.T) {
	cases := map[string]struct {
		in      string
		want    string
		wantErr bool
	}{
		"single frame":       {"event: message\ndata: {\"a\":1}\n\n", `{"a":1}`, false},
		"no event line":      {"data: {\"a\":1}\n\n", `{"a":1}`, false},
		"unterminated frame": {"data: {\"a\":1}", `{"a":1}`, false},
		"multi-line data":    {"data: {\"a\":\ndata: 1}\n\n", `{"a":1}`, false},
		"comments ignored":   {": keepalive\ndata: {\"a\":1}\n\n", `{"a":1}`, false},
		"no data at all":     {"event: ping\n\n", "", true},
		"empty":              {"", "", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := firstSSEData(strings.NewReader(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiscoveryForwardsTheCallersCredential(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer srv.Close()

	d := newDiscoveryCache(time.Minute, srv.Client())
	_, _ = d.lookup(context.Background(), srv.URL, "Bearer alice-token", "x")
	if seen != "Bearer alice-token" {
		t.Fatalf("the caller's credential should reach the upstream, got %q", seen)
	}
}

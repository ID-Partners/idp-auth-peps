package coaz

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRequestAcceptsTheMessagesMCPSends(t *testing.T) {
	cases := []struct {
		body   string
		kind   Kind
		method string
		tool   string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance","arguments":{"id":"a1"}}}`, KindRequest, "tools/call", "get_balance"},
		{` {"jsonrpc":"2.0","id":"x","method":"initialize","params":{}} ` + "\n", KindRequest, "initialize", ""},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, KindNotification, "notifications/initialized", ""},
		{`{"jsonrpc":"2.0","id":null,"method":"ping"}`, KindRequest, "ping", ""},
		{`{"jsonrpc":"2.0","id":7,"result":{"content":[]}}`, KindResponse, "", ""},
		{`{"jsonrpc":"2.0","id":7,"error":{"code":-1,"message":"declined"}}`, KindResponse, "", ""},
		// Distinct names that merely look alike to a human are fine.
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"id":"1","ids":["2"]}}}`, KindRequest, "tools/call", "t"},
	}
	for _, c := range cases {
		req, err := ParseRequest([]byte(c.body))
		if err != nil {
			t.Fatalf("%s: unexpected refusal: %v", c.body, err)
		}
		if req.Kind != c.kind || req.Method != c.method || req.ToolName != c.tool {
			t.Fatalf("%s: got kind=%d method=%q tool=%q", c.body, req.Kind, req.Method, req.ToolName)
		}
	}
}

func TestParseRequestRefusesWhatTwoParsersCouldReadDifferently(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"pad":"` + strings.Repeat("A", 70000) + `"}}}`
	deep := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":` +
		strings.Repeat(`{"a":`, 80) + `1` + strings.Repeat(`}`, 80) + `}}`
	cases := []struct {
		name string
		body string
		code int
		id   any
	}{
		{"truncated body", big[:65536], CodeParseError, nil},
		{"empty body", ``, CodeInvalidRequest, nil},
		{"whitespace body", " \n", CodeInvalidRequest, nil},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay"}}]`, CodeInvalidRequest, nil},
		{"scalar", `"tools/call"`, CodeInvalidRequest, nil},
		{"not JSON", `method=tools/call`, CodeParseError, nil},
		{"byte-order mark", "\xEF\xBB\xBF" + `{"jsonrpc":"2.0","id":1,"method":"ping"}`, CodeParseError, nil},
		{"invalid UTF-8", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"memo":"` + "\xff" + `"}}}`, CodeParseError, nil},
		{"trailing data", `{"jsonrpc":"2.0","id":1,"method":"ping"}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pay"}}`, CodeParseError, nil},
		{"trailing garbage", `{"jsonrpc":"2.0","id":1,"method":"ping"} x`, CodeParseError, nil},
		{"case-variant method", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"initialize","params":{"name":"pay"}}`, CodeInvalidRequest, nil},
		{"case-variant params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay"},"Params":{"name":"get_balance"}}`, CodeInvalidRequest, nil},
		{"case-variant name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance","NAME":"pay"}}`, CodeInvalidRequest, nil},
		{"case-variant argument", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":1,"Amount":1000000}}}`, CodeInvalidRequest, nil},
		{"exact duplicate", `{"jsonrpc":"2.0","id":1,"method":"initialize","method":"tools/call","params":{"name":"pay"}}`, CodeInvalidRequest, nil},
		{"long s folds to s", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"},"paramſ":{"name":"pay"}}`, CodeInvalidRequest, nil},
		{"Kelvin sign folds to k", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"k":1,"K":2}}}`, CodeInvalidRequest, nil},
		{"nested too deeply", deep, CodeInvalidRequest, nil},
		{"no jsonrpc", `{"id":1,"method":"ping"}`, CodeInvalidRequest, float64(1)},
		{"wrong jsonrpc", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, CodeInvalidRequest, float64(1)},
		{"numeric method", `{"jsonrpc":"2.0","id":1,"method":7}`, CodeInvalidRequest, float64(1)},
		{"empty method", `{"jsonrpc":"2.0","id":"a","method":""}`, CodeInvalidRequest, "a"},
		{"object id", `{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}`, CodeInvalidRequest, nil},
		{"array params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["pay"]}`, CodeInvalidRequest, float64(1)},
		{"null params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`, CodeInvalidRequest, float64(1)},
		{"unreadable number in params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":1e999}}}`, CodeInvalidRequest, float64(1)},
		{"tools/call without params", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, CodeInvalidRequest, float64(1)},
		{"tools/call with a numeric name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}`, CodeInvalidRequest, float64(1)},
		{"tools/call with a list name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["pay"]}}`, CodeInvalidRequest, float64(1)},
		{"tools/call with an empty name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`, CodeInvalidRequest, float64(1)},
		{"neither request nor response", `{"jsonrpc":"2.0","id":1}`, CodeInvalidRequest, float64(1)},
		{"response with both", `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`, CodeInvalidRequest, float64(1)},
		{"response without an id", `{"jsonrpc":"2.0","result":{}}`, CodeInvalidRequest, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseRequest([]byte(c.body))
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("expected a ParseError, got %v", err)
			}
			if pe.Code != c.code {
				t.Fatalf("code %d, want %d (%s)", pe.Code, c.code, pe.Message)
			}
			if pe.ID != c.id {
				t.Fatalf("id %v, want %v", pe.ID, c.id)
			}
			if !strings.Contains(string(pe.JSONRPCError()), `"jsonrpc":"2.0"`) {
				t.Fatalf("the refusal must render as a JSON-RPC error: %s", pe.JSONRPCError())
			}
		})
	}
}

func TestFoldKeyMatchesEqualFold(t *testing.T) {
	pairs := [][2]string{{"params", "PARAMS"}, {"params", "paramſ"}, {"k", "K"}, {"Straße", "STRASSE"}}
	for _, p := range pairs {
		if (foldKey(p[0]) == foldKey(p[1])) != strings.EqualFold(p[0], p[1]) {
			t.Fatalf("foldKey disagrees with strings.EqualFold on %q / %q", p[0], p[1])
		}
	}
}

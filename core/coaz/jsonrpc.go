package coaz

// Strict JSON-RPC parsing for MCP routes.
//
// A PEP that authorises one reading of a body and forwards the bytes to an upstream that
// reads them another way has authorised nothing. Go's encoding/json matches object keys
// to struct fields case-insensitively and lets the last match win, while the JS and
// Python stacks MCP servers run on read exact keys — so `"params"` and `"Params"` in one
// body name two different tools depending on who reads it. A batch, a partial body, a
// BOM or trailing bytes open the same gap from other directions. ParseRequest refuses
// every body two parsers could disagree about instead of guessing which one the upstream
// uses.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind says what sort of JSON-RPC message a body is.
type Kind int

const (
	// KindRequest has a method and an id.
	KindRequest Kind = iota
	// KindNotification has a method and no id.
	KindNotification
	// KindResponse has an id and exactly one of result or error, and no method: a
	// client's answer to a server-initiated request (sampling, elicitation).
	KindResponse
)

// Request is one JSON-RPC message, parsed strictly.
type Request struct {
	Kind   Kind
	ID     any // string, float64 or nil
	Method string
	// Params is the params object, nil when absent.
	Params map[string]any
	// ToolName is params.name on a tools/call, which ParseRequest guarantees is a
	// non-empty string.
	ToolName string
}

// JSON-RPC 2.0 codes for a message the PEP will not authorise.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
)

// ParseError is a body the PEP refuses to authorise.
type ParseError struct {
	// Code is CodeParseError for bytes that are not one clean JSON value, and
	// CodeInvalidRequest for JSON that is not one unambiguous JSON-RPC message.
	Code int
	// Message is safe to return to the client.
	Message string
	// ID is the request's id when it could be read, so the error can answer it.
	ID any
}

func (e *ParseError) Error() string { return e.Message }

// JSONRPCError renders the refusal as a JSON-RPC error response.
func (e *ParseError) JSONRPCError() json.RawMessage { return jsonRPCError(e.ID, e.Code, e.Message) }

// maxJSONDepth bounds nesting. MCP messages are shallow; a deep one is a stack-depth
// attack on some parser along the way, not a tool call.
const maxJSONDepth = 64

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ParseRequest parses one JSON-RPC message. It refuses:
//
//   - bytes that are not valid UTF-8, begin with a BOM, or carry anything after the value;
//   - anything but a single object — a batch array included;
//   - any object, at any depth, holding two member names that are equal under Unicode
//     case folding (which covers exact duplicates);
//   - a missing or non-"2.0" jsonrpc, a non-string method, an id that is not a string,
//     number or null, params that are not an object;
//   - a message with no method that is not a response;
//   - a tools/call without a non-empty string params.name.
func ParseRequest(body []byte) (*Request, error) {
	parseErr := func(msg string) error { return &ParseError{Code: CodeParseError, Message: "Parse error: " + msg} }
	invalid := func(id any, msg string) error {
		return &ParseError{Code: CodeInvalidRequest, Message: "Invalid Request: " + msg, ID: id}
	}

	if !utf8.Valid(body) {
		return nil, parseErr("the body is not valid UTF-8")
	}
	if bytes.HasPrefix(body, utf8BOM) {
		return nil, parseErr("the body begins with a byte-order mark")
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, invalid(nil, "the body is empty")
	}
	switch trimmed[0] {
	case '[':
		return nil, invalid(nil, "batch requests are not accepted")
	case '{':
	default:
		if !json.Valid(body) {
			return nil, parseErr("the body is not JSON")
		}
		return nil, invalid(nil, "the body is not a JSON-RPC object")
	}

	// One pass over the tokens rejects duplicate and case-folded member names at every
	// depth, excess nesting, and trailing data — none of which encoding/json reports.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // a number too big for float64 is still JSON; params decoding refuses it
	if err := walkValue(dec, 0); err != nil {
		var pe *ParseError
		if errors.As(err, &pe) {
			return nil, err
		}
		return nil, parseErr("the body is not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, parseErr("the body carries data after the JSON-RPC object")
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, parseErr("the body is not JSON")
	}

	// The id is read first so every later refusal can answer it.
	var id any
	idRaw, hasID := top["id"]
	if hasID {
		// A number too large for a float64 is JSON, but not an id anyone can echo back.
		if err := json.Unmarshal(idRaw, &id); err != nil {
			return nil, invalid(nil, "the id must be a string, a number or null")
		}
		switch id.(type) {
		case string, float64, nil:
		default:
			return nil, invalid(nil, "the id must be a string, a number or null")
		}
	}

	var version string
	if raw, ok := top["jsonrpc"]; !ok || json.Unmarshal(raw, &version) != nil || version != "2.0" {
		return nil, invalid(id, `jsonrpc must be "2.0"`)
	}

	req := &Request{ID: id}
	methodRaw, hasMethod := top["method"]
	if !hasMethod {
		_, hasResult := top["result"]
		_, hasError := top["error"]
		if !hasID || hasResult == hasError {
			return nil, invalid(id, "a message without a method must be a response with exactly one of result or error")
		}
		req.Kind = KindResponse
		return req, nil
	}
	if err := json.Unmarshal(methodRaw, &req.Method); err != nil {
		return nil, invalid(id, "method must be a string")
	}
	if req.Method == "" {
		return nil, invalid(id, "method is empty")
	}
	req.Kind = KindNotification
	if hasID {
		req.Kind = KindRequest
	}

	if raw, ok := top["params"]; ok {
		// null, an array, a scalar, or an object holding a number no float64 can carry.
		if json.Unmarshal(raw, &req.Params) != nil || req.Params == nil {
			return nil, invalid(id, "params must be an object of readable values")
		}
	}
	if req.Method == "tools/call" {
		name, _ := req.Params["name"].(string)
		if name == "" {
			return nil, invalid(id, "tools/call needs a string params.name")
		}
		req.ToolName = name
	}
	return req, nil
}

// CheckStrictJSON reports whether body is one JSON value that every parser reads the
// same way: valid UTF-8 with no BOM, nothing after the value, no nesting beyond
// maxJSONDepth, and no object holding two member names equal under case folding. It is
// the same check ParseRequest makes, for bodies that are not JSON-RPC — a REST payment,
// whose amount a case-insensitive upstream could read from "Amount" while the PEP read
// "amount".
func CheckStrictJSON(body []byte) error {
	if !utf8.Valid(body) || bytes.HasPrefix(body, utf8BOM) {
		return errors.New("the body is not clean UTF-8 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := walkValue(dec, 0); err != nil {
		var pe *ParseError
		if errors.As(err, &pe) {
			return errors.New(strings.TrimPrefix(pe.Message, "Invalid Request: "))
		}
		return errors.New("the body is not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("the body carries data after the JSON value")
	}
	return nil
}

// walkValue consumes one JSON value from dec, refusing folded-duplicate member names
// and nesting beyond maxJSONDepth.
func walkValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return &ParseError{Code: CodeInvalidRequest, Message: "Invalid Request: the body is nested too deeply"}
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	switch delim {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyTok.(string)
			folded := foldKey(key)
			if prev, dup := seen[folded]; dup {
				return &ParseError{Code: CodeInvalidRequest, Message: fmt.Sprintf(
					"Invalid Request: member names %q and %q are the same name to a case-insensitive parser", prev, key)}
			}
			seen[folded] = key
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// foldKey maps a member name to one representative of its Unicode simple-folding
// class, so two names are the same key exactly when strings.EqualFold says so — which
// is the rule encoding/json uses to match a key to a struct field. Plain lower-casing is
// not enough: U+017F (ſ) folds to s and U+212A (Kelvin) to k.
func foldKey(s string) string {
	var b []rune
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b = append(b, min)
	}
	return string(b)
}

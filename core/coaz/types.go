// Package coaz implements the PEP side of the OpenID AuthZEN MCP profile
// ("COAZ"): discovery of x-coaz-mapping declarations from an MCP server's
// tools/list, CEL evaluation of the mapping against a tools/call request and
// the caller's token claims, construction of AuthZEN evaluation(s) requests
// per the profile's processing rules, and the profile's JSON-RPC error
// semantics.
//
// Spec: https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md
package coaz

import (
	"encoding/json"
	"log"
	"reflect"
)

// JSON-RPC error codes defined (or adopted) by the COAZ profile.
const (
	// CodeMappingError: the PEP could not construct a valid AuthZEN request
	// from the x-coaz-mapping and the tools/call parameters (Invalid params).
	CodeMappingError = -32602
	// CodeDenied: a deny under the SUPERSEDED v1 profile. v2 says of this value:
	// "a code outside that range, such as -32401, is non-conformant with JSON-RPC and
	// MUST NOT be used" — so it is emitted only for tools still declared against v1.
	CodeDenied = -32401
	// CodeDeniedV2: a deny under the current COAZ-MCP binding. Inside the JSON-RPC
	// implementation-defined server-error range.
	CodeDeniedV2 = -32001
	// CodePDPError: the PEP could not complete the check (PDP unreachable /
	// invalid response). Standard JSON-RPC internal error.
	CodePDPError = -32603
)

// Mapping is a parsed x-coaz-mapping object. Field elements are raw AuthZEN
// objects whose string leaves are CEL expressions (static values are CEL
// string literals, e.g. `'customer'`).
type Mapping struct {
	Subject  []map[string]any `json:"subject"`
	Action   []map[string]any `json:"action"`
	Resource []map[string]any `json:"resource"`
	Context  []map[string]any `json:"context"`
}

// Tool is the subset of an MCP tools/list entry the PEP needs.
type Tool struct {
	Name        string         `json:"name"`
	Coaz        bool           `json:"coaz"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Verdict is the outcome of a COAZ check for one MCP message.
type Verdict struct {
	// CoazTool is true when the engine decided the message: a PDP was asked, or it was
	// refused before one could be. False means no PDP was consulted and the message
	// may proceed — see PassThrough.
	CoazTool bool
	// Decision is true when the message may proceed.
	Decision bool
	// PassThrough is true when the message proceeds without a PDP call: ping,
	// notifications, a client's response to a server-initiated request, or — on a
	// route that turned default mappings off — anything the binding would have mapped.
	PassThrough bool
	// JSONRPCError is the JSON-RPC error response body to return to the MCP client
	// when the message must not proceed. Nil on permit.
	JSONRPCError json.RawMessage
	// HTTPStatus is the status that carries JSONRPCError. Zero means 200, which is how
	// the binding returns a policy denial; a body the PEP cannot parse is a 400.
	HTTPStatus int
	// Reason is a summary for logs. It may name internal URLs and upstream errors, so
	// it is not for the client — see ClientReason.
	Reason string
	// ClientReason is what may be told to the client: the JSON-RPC error's message on
	// a deny, the PDP's reason on a permit.
	ClientReason string
	// PDPRequest is the AuthZEN request that was sent (for transcripts/tests).
	PDPRequest json.RawMessage
	// FailedOpen names the policy layers that failed and were skipped because they
	// were allowed to. Non-empty on a permit means fewer PDPs judged this call than
	// the policy asked for.
	FailedOpen []string
}

// jsonRPCError renders a JSON-RPC 2.0 error response with the request's id.
func jsonRPCError(id any, code int, message string) json.RawMessage {
	return jsonRPCErrorData(id, code, message, nil)
}

// AuthzChallenge is the STRUCTURED form of a policy challenge, carried as the JSON-RPC
// error's `data` member (JSON-RPC 2.0 §5.1) alongside the prose `message`. The prose is
// what MCP clients string-matched before this existed ("insufficient_scope scope=…",
// "identity_verification_required doctype=…"); the data member is what a client SDK
// parses. Type values are this repo's authorisation taxonomy, shared with the Kong
// plugin and the Node SDK — so a challenge, the ceremony that resolves it, and the
// record it leaves behind all agree on the word.
//
//	resource_authorisation  RFC 9470 scope step-up (a specific payment)      -> Scope set
//	identity_proofing       verified-credential presentation (mDL)           -> Doctype set
//	authn                   no authenticated user at all                     -> AcrValues set
//	consent / intent        reserved (no PDP signal yet)
type AuthzChallenge struct {
	Type      string `json:"type"`
	Scope     string `json:"scope,omitempty"`
	Doctype   string `json:"doctype,omitempty"`
	AcrValues string `json:"acr_values,omitempty"`
	Reason    string `json:"reason,omitempty"`
	PEP       string `json:"pep,omitempty"`
}

// jsonRPCErrorData is jsonRPCError with an optional structured `data` member.
func jsonRPCErrorData(id any, code int, message string, data any) json.RawMessage {
	errObj := map[string]any{"code": code, "message": message}
	if data != nil {
		errObj["data"] = data
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   errObj,
	}
	raw, _ := json.Marshal(resp)
	return raw
}

// assertContext writes the context the PEP asserts over what a mapping produced. The
// mapping is authored by the MCP server and can draw values from the caller's params —
// `"context": "$params.arguments.meta"` hands the caller every key — so a mapping key
// must never stand in for the verified user's scope or consent, the resource's metadata,
// or the endpoint hit. An override that changes a value is logged: it means a mapping is
// trying to say something the PEP already knows.
func assertContext(ctx, asserted map[string]any, tool string) {
	for k, v := range asserted {
		if prev, set := ctx[k]; set && !reflect.DeepEqual(prev, v) {
			log.Printf("coaz: tool %q's mapping set context.%s; the PEP's value replaces it", tool, k)
		}
		ctx[k] = v
	}
}

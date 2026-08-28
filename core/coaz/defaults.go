package coaz

// The COAZ-MCP binding's default mappings.
//
// "A PEP MUST apply the default mapping for a method unless a declared mapping applies
// to the specific operation." Only `ping` and `notifications/*` are pass-through, and
// "a request whose method has neither a default mapping ... nor an applicable declared
// mapping, and that is not in the pass-through set ... MUST be denied", so methods from
// future MCP versions fail closed rather than slipping past authorization.
//
// Every default uses the `evaluation` envelope and shares the same subject and agent
// context; they differ only in action.name and resource.

import (
	"fmt"
	"strings"
	"sync"
)

// defaultEnvelope builds one default mapping from the parts that vary.
func defaultEnvelope(action string, resource map[string]any, extraContext map[string]any) map[string]any {
	context := map[string]any{"agent": "$token.?client_id"}
	for k, v := range extraContext {
		context[k] = v
	}
	return map[string]any{
		"evaluation": map[string]any{
			"subject":  map[string]any{"type": "identity", "id": "$token.sub"},
			"context":  context,
			"action":   map[string]any{"name": action},
			"resource": resource,
		},
	}
}

// serverResource identifies this MCP server. The binding derives it from `aud`, since
// MCP requires tokens to be audience-bound to the target server (RFC 8707).
func serverResource() map[string]any {
	return map[string]any{"type": "mcp_server", "id": "$token.aud"}
}

// DefaultMappings returns the binding's default mapping for an MCP method, and whether
// one is defined.
func DefaultMappings(method string) (map[string]any, bool) {
	switch method {
	case "tools/call":
		return defaultEnvelope(method, map[string]any{"type": "tool", "id": "$params.name"}, nil), true
	case "tools/list", "resources/list", "prompts/list", "tasks/list":
		return defaultEnvelope(method, serverResource(), nil), true
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		return defaultEnvelope(method, map[string]any{"type": "resource", "id": "$params.uri"}, nil), true
	case "prompts/get":
		return defaultEnvelope(method, map[string]any{"type": "prompt", "id": "$params.name"}, nil), true
	case "completion/complete":
		// SPEC INCONSISTENCY, reported upstream. The binding prints this default as
		//   "$params.ref.type == 'ref/prompt' ? $params.ref.name : $params.ref.uri"
		// with a `$` on every reference. The framework says only the LEADING `$` marks
		// the value as an expression — "the text following the `$` is the expression
		// itself" — and "a `$` anywhere else in a string has no special meaning". Taken
		// together the printed form leaves stray `$` in the CEL source and does not
		// compile. Written here the way the framework's own rule requires: leading `$`
		// to mark the expression, plain CEL inside.
		return defaultEnvelope(method, map[string]any{
			"type": "$params.ref.type == 'ref/prompt' ? 'prompt' : 'resource'",
			"id":   "$params.ref.type == 'ref/prompt' ? params.ref.name : params.ref.uri",
		}, nil), true
	case "logging/setLevel":
		return defaultEnvelope(method, serverResource(), map[string]any{"level": "$params.level"}), true
	case "tasks/get", "tasks/result", "tasks/cancel":
		return defaultEnvelope(method, map[string]any{"type": "task", "id": "$params.taskId"}, nil), true

	case "initialize":
		// DELIBERATE DEVIATION. `initialize` appears nowhere in the binding — not in the
		// default-mapping table and not in the pass-through set — so by the Unknown
		// Methods rule it MUST be denied. That would deny every MCP handshake and make
		// the protocol unusable, which cannot be the intent; it reads as a gap in the
		// draft rather than a decision.
		//
		// Denying it breaks everything and passing it through leaves the session
		// handshake ungoverned, so we do neither: it gets a default mapping shaped like
		// the other server-scoped methods. The PDP is asked, policy decides, and nothing
		// bypasses authorization. Raised with the WG.
		return defaultEnvelope(method, serverResource(), nil), true
	}
	return nil, false
}

// IsPassThrough reports the methods the binding exempts: "the PEP MUST NOT call the PDP
// for them and MUST allow them to proceed. They are listed explicitly so that the
// absence of a mapping is never interpreted as a deny."
func IsPassThrough(method string) bool {
	return method == "ping" || strings.HasPrefix(method, "notifications/")
}

// IsServerInitiated reports requests the server makes toward the client. The binding puts
// them out of scope: they are authorized with the client's access token, "which is not
// the appropriate identity for server-initiated requests". Treated as pass-through here
// rather than denied, since denying them would break capabilities this PEP does not model.
func IsServerInitiated(method string) bool {
	switch method {
	case "sampling/createMessage", "elicitation/create", "roots/list":
		return true
	}
	return false
}

// defaultCache compiles each default mapping once. They are constant, so compiling per
// request would burn CEL planning on every call.
var (
	defaultCacheMu sync.Mutex
	defaultCache   = map[string]*CompiledMappingV2{}
)

// CompiledDefault returns the compiled default mapping for a method.
func CompiledDefault(method string) (*CompiledMappingV2, error) {
	defaultCacheMu.Lock()
	defer defaultCacheMu.Unlock()
	if cm, ok := defaultCache[method]; ok {
		return cm, nil
	}
	raw, ok := DefaultMappings(method)
	if !ok {
		return nil, fmt.Errorf("no default mapping is defined for %q", method)
	}
	cm, err := CompileMappingV2(method, raw)
	if err != nil {
		return nil, fmt.Errorf("default mapping for %q failed to compile: %w", method, err)
	}
	defaultCache[method] = cm
	return cm, nil
}

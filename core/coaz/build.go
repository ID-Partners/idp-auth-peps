package coaz

// Mapping compilation and the profile's processing rules: which AuthZEN API
// to call (evaluation vs evaluations) and how to assemble the request.

import (
	"encoding/json"
	"fmt"
)

// CompiledMapping is a validated, CEL-compiled x-coaz-mapping for one tool.
type CompiledMapping struct {
	ToolName string
	subject  []*compiledNode
	action   []*compiledNode // nil => default {"name": "<tool name>"}
	resource []*compiledNode
	context  []*compiledNode
}

// CompileMapping validates and compiles a tool's x-coaz-mapping.
func CompileMapping(toolName string, raw map[string]any) (*CompiledMapping, error) {
	var m Mapping
	rawJSON, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("x-coaz-mapping is not valid JSON: %w", err)
	}
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("x-coaz-mapping is malformed: %w", err)
	}
	if len(m.Subject) == 0 {
		return nil, fmt.Errorf("x-coaz-mapping.subject is required")
	}
	if len(m.Resource) == 0 {
		return nil, fmt.Errorf("x-coaz-mapping.resource is required")
	}
	if len(m.Context) == 0 {
		return nil, fmt.Errorf("x-coaz-mapping.context is required")
	}

	cm := &CompiledMapping{ToolName: toolName}
	compileAll := func(elems []map[string]any, field string) ([]*compiledNode, error) {
		nodes := make([]*compiledNode, len(elems))
		for i, el := range elems {
			n, err := compileNode(any(el))
			if err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
			}
			nodes[i] = n
		}
		return nodes, nil
	}
	if cm.subject, err = compileAll(m.Subject, "subject"); err != nil {
		return nil, err
	}
	if cm.resource, err = compileAll(m.Resource, "resource"); err != nil {
		return nil, err
	}
	if cm.context, err = compileAll(m.Context, "context"); err != nil {
		return nil, err
	}
	if len(m.Action) > 0 {
		if cm.action, err = compileAll(m.Action, "action"); err != nil {
			return nil, err
		}
	}

	// "At least one field across the subject and context parameters MUST be
	// derived from the token input variable."
	derived := false
	for _, n := range append(append([]*compiledNode{}, cm.subject...), cm.context...) {
		if n.usesToken() {
			derived = true
			break
		}
	}
	if !derived {
		return nil, fmt.Errorf("no subject or context field is derived from the token input variable")
	}

	// Multi-valued fields must agree in length (checked once here; lengths
	// are static properties of the mapping).
	multi := 0
	for _, f := range [][]*compiledNode{cm.subject, cm.actionOrDefaultLen(), cm.resource, cm.context} {
		if len(f) > 1 {
			if multi != 0 && len(f) != multi {
				return nil, fmt.Errorf("multi-valued mapping fields have mismatched element counts")
			}
			multi = len(f)
		}
	}
	return cm, nil
}

// actionOrDefaultLen lets length validation treat a missing action as the
// single-element default without materialising it.
func (cm *CompiledMapping) actionOrDefaultLen() []*compiledNode {
	if cm.action == nil {
		return make([]*compiledNode, 1)
	}
	return cm.action
}

// BuiltRequest is the AuthZEN request produced by the processing rules.
type BuiltRequest struct {
	// Batch is true when the Evaluations (boxcar) API must be used.
	Batch bool
	// Body is the JSON request payload for /access/v1/evaluation or
	// /access/v1/evaluations.
	Body json.RawMessage
	// Count is the number of decisions expected back (1 unless Batch).
	Count int
}

// Build evaluates the mapping against a tools/call and assembles the AuthZEN
// request per the profile's processing rules:
//   - all fields single-element  -> evaluation API, fields at top level;
//   - any field multi-element    -> evaluations API: single-element fields sit
//     at top level as defaults, multi-element fields are zipped element-wise
//     into the evaluations array.
func (cm *CompiledMapping) Build(params, token map[string]any, extraContext map[string]any) (*BuiltRequest, error) {
	evalField := func(nodes []*compiledNode) ([]any, error) {
		out := make([]any, len(nodes))
		for i, n := range nodes {
			v, err := n.eval(params, token)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}

	subject, err := evalField(cm.subject)
	if err != nil {
		return nil, err
	}
	resource, err := evalField(cm.resource)
	if err != nil {
		return nil, err
	}
	context, err := evalField(cm.context)
	if err != nil {
		return nil, err
	}
	// Merge gateway-supplied context the mapping can't derive itself (e.g. user_scope
	// from the logged-in user's X-User-Token, needed by amount/step-up policies). Only
	// fills keys the mapping didn't set, so declared mappings always win.
	if len(extraContext) > 0 {
		for _, cv := range context {
			m, ok := cv.(map[string]any)
			if !ok {
				continue
			}
			for k, v := range extraContext {
				if _, exists := m[k]; !exists {
					m[k] = v
				}
			}
		}
	}
	var action []any
	if cm.action != nil {
		if action, err = evalField(cm.action); err != nil {
			return nil, err
		}
	} else {
		// "If the action field is missing, it is assumed to be a
		// single-element array containing {"name": "<tool name>"}."
		action = []any{map[string]any{"name": cm.ToolName}}
	}

	fields := []struct {
		name   string
		values []any
	}{
		{"subject", subject},
		{"action", action},
		{"resource", resource},
		{"context", context},
	}

	batchLen := 1
	for _, f := range fields {
		if len(f.values) > 1 {
			if batchLen != 1 && len(f.values) != batchLen {
				return nil, fmt.Errorf("multi-valued mapping fields have mismatched element counts")
			}
			batchLen = len(f.values)
		}
	}

	req := map[string]any{}
	if batchLen == 1 {
		for _, f := range fields {
			req[f.name] = f.values[0]
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		return &BuiltRequest{Batch: false, Body: body, Count: 1}, nil
	}

	// Evaluations API: singles become top-level defaults, multis zip into
	// the evaluations array.
	evaluations := make([]map[string]any, batchLen)
	for i := range evaluations {
		evaluations[i] = map[string]any{}
	}
	for _, f := range fields {
		if len(f.values) == 1 {
			req[f.name] = f.values[0]
		} else {
			for i, v := range f.values {
				evaluations[i][f.name] = v
			}
		}
	}
	req["evaluations"] = evaluations
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return &BuiltRequest{Batch: true, Body: body, Count: batchLen}, nil
}

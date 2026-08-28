package coaz

// COAZ v2 — the current drafts:
//
//	COAZ Framework      https://openid.github.io/authzen/authzen-coaz-framework-1_0.html
//	COAZ-MCP binding    https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html
//
// These replaced authzen-mcp-profile-1_0, which now carries only a "no longer
// maintained" notice. v1 lives on in build.go so tools declared against the old draft
// keep working; everything new should be v2. What actually changed:
//
//	                v1 (superseded)                     v2 (current)
//	declaration     tool.coaz + x-coaz-mapping          x-authzen-mapping in inputSchema
//	shape           flat subject/action/resource/       an ENVELOPE: exactly one of
//	                context arrays, zipped by length    `evaluation` or `evaluations`
//	expressions     every string is CEL                 only `$`-prefixed strings are CEL;
//	                ('customer' is a literal)           `$$` escapes; the rest are literals
//	denial code     -32401                              -32001 (-32401 is explicitly
//	                                                    non-conformant with JSON-RPC)
//	subject         >=1 subject/context field from      subject.id anchored to the token
//	                the token                           claim and VERIFIED against it

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Dialect selects which COAZ draft a mapping is written against.
type Dialect int

const (
	// DialectV2 is the current COAZ Framework + COAZ-MCP binding.
	DialectV2 Dialect = iota
	// DialectV1 is the superseded authzen-mcp-profile-1_0.
	DialectV1
)

func (d Dialect) String() string {
	if d == DialectV1 {
		return "coaz/v1"
	}
	return "coaz/v2"
}

// DeniedCode is the JSON-RPC error code for a policy denial in this dialect.
//
// v2 says of -32401: "a code outside that range ... is non-conformant with JSON-RPC and
// MUST NOT be used". v1 mandated it, so a v1-declared tool still gets it — changing the
// code under a client that string-matches on it would be its own kind of break.
func (d Dialect) DeniedCode() int {
	if d == DialectV1 {
		return CodeDenied
	}
	return CodeDeniedV2
}

// subjectIdentityClaim is the token claim subject.id anchors to. The binding allows a
// deployment to designate another on-behalf-of claim; `sub` is the default.
const subjectIdentityClaim = "sub"

// defaultSubjectExpr is what a declared mapping gets when it omits subject or subject.id:
// "the PEP MUST supply the default subject identifier ... so that every request still
// carries a token-anchored subject."
const defaultSubjectExpr = "$token." + subjectIdentityClaim

// CompiledMappingV2 is a validated, compiled x-authzen-mapping.
type CompiledMappingV2 struct {
	ToolName string
	// Batch is true for the `evaluations` envelope. The ENVELOPE decides this — unlike
	// v1, no amount of list-valued content causes a request to fan out.
	Batch bool
	body  *compiledNode
	// anchored records that subject.id is the token's subject-identity claim, so the
	// resolved value must equal that claim. False means the mapping author asserted an
	// identity the PEP cannot verify — allowed, but warned about.
	anchored bool
}

// Anchored reports whether subject.id is trust-anchored to the token.
func (cm *CompiledMappingV2) Anchored() bool { return cm.anchored }

// CompileMappingV2 validates and compiles a v2 mapping.
func CompileMappingV2(toolName string, raw map[string]any) (*CompiledMappingV2, error) {
	envelope, inner, err := parseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	batch := envelope == "evaluations"

	// Identity smuggling: with the evaluations envelope the single top-level subject
	// governs every entry, so an entry that sets its own subject is rejected outright.
	if batch {
		if entries, ok := inner["evaluations"].([]any); ok {
			for i, e := range entries {
				entry, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if _, present := entry["subject"]; present {
					return nil, fmt.Errorf("evaluations[%d] sets subject; only the top-level subject may do so", i)
				}
			}
		}
	}

	anchored, err := normaliseSubject(inner)
	if err != nil {
		return nil, err
	}

	body, err := compileNodeV2(inner)
	if err != nil {
		return nil, err
	}
	return &CompiledMappingV2{ToolName: toolName, Batch: batch, body: body, anchored: anchored}, nil
}

// parseEnvelope enforces "a JSON object with a single top-level member".
func parseEnvelope(raw map[string]any) (string, map[string]any, error) {
	if len(raw) != 1 {
		return "", nil, fmt.Errorf(
			"mapping must have exactly one top-level member (`evaluation` or `evaluations`), found %d", len(raw))
	}
	for k, v := range raw {
		if k != "evaluation" && k != "evaluations" {
			return "", nil, fmt.Errorf("unknown mapping envelope %q; expected `evaluation` or `evaluations`", k)
		}
		inner, ok := v.(map[string]any)
		if !ok {
			return "", nil, fmt.Errorf("mapping envelope %q must contain an object", k)
		}
		return k, inner, nil
	}
	return "", nil, fmt.Errorf("mapping is empty")
}

// normaliseSubject supplies the default subject identifier where the mapping omits one,
// and reports whether subject.id ends up anchored to the token's subject claim.
// It mutates inner, which is a private copy of the declaration.
func normaliseSubject(inner map[string]any) (bool, error) {
	subject, ok := inner["subject"].(map[string]any)
	if !ok {
		if _, present := inner["subject"]; present {
			return false, fmt.Errorf("subject must be an object")
		}
		subject = map[string]any{}
		inner["subject"] = subject
	}
	id, present := subject["id"]
	if !present || id == nil || id == "" {
		subject["id"] = defaultSubjectExpr
		return true, nil
	}
	idStr, ok := id.(string)
	if !ok {
		return false, fmt.Errorf("subject.id must be a string")
	}
	// Anchored only when it IS the subject-identity claim. `$token.sub + '-x'` is an
	// override, not an anchor, and must not be verified as though it were one.
	return strings.TrimSpace(idStr) == defaultSubjectExpr, nil
}

// Build resolves the mapping against one operation and returns the AuthZEN request.
//
// The envelope alone decides evaluation vs evaluations. extraContext fills only context
// keys the mapping did not set, so a declared mapping always wins.
func (cm *CompiledMappingV2) Build(params, token map[string]any, extraContext map[string]any) (*BuiltRequest, error) {
	resolved, err := cm.body.eval(params, token)
	if err != nil {
		return nil, err
	}
	req, ok := resolved.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("mapping did not resolve to an object")
	}

	// Trust anchoring: "the PEP MUST verify that its resolved value equals that claim in
	// the validated access token, treating a mismatch as a mapping error". This is what
	// stops an MCP server — the party being authorized — asserting another subject.
	if cm.anchored {
		want, _ := token[subjectIdentityClaim].(string)
		subject, _ := req["subject"].(map[string]any)
		got, _ := subject["id"].(string)
		if want == "" {
			return nil, fmt.Errorf("access token carries no %s claim to anchor subject.id to", subjectIdentityClaim)
		}
		if got != want {
			return nil, fmt.Errorf("subject.id %q does not match the validated token's %s claim", got, subjectIdentityClaim)
		}
	}

	// Absent optionals in CONTEXT are pruned: context is optional, and sending
	// `"agent": null` would invite a policy to match on null as a value. Absence in a
	// required field is a mapping error instead — see requireFields below.
	pruneNilContext(req)
	if cm.Batch {
		if entries, ok := req["evaluations"].([]any); ok {
			for _, e := range entries {
				if entry, ok := e.(map[string]any); ok {
					pruneNilContext(entry)
				}
			}
		}
	}

	// Required fields. The framework: "If an expression yields absent or null for a
	// required field, the PEP cannot construct a valid request; this is a mapping
	// error." Without this check an absent resource.id reaches the PDP as a malformed
	// request and surfaces as whatever the PDP happens to say, instead of a -32602.
	if err := requireFields(req, cm.Batch); err != nil {
		return nil, err
	}

	if len(extraContext) > 0 {
		ctx, _ := req["context"].(map[string]any)
		if ctx == nil {
			ctx = map[string]any{}
			req["context"] = ctx
		}
		for k, v := range extraContext {
			if _, exists := ctx[k]; !exists {
				ctx[k] = v
			}
		}
	}

	count := 1
	if cm.Batch {
		entries, _ := req["evaluations"].([]any)
		count = len(entries)
		if count == 0 {
			return nil, fmt.Errorf("evaluations envelope resolved to an empty evaluations array")
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return &BuiltRequest{Batch: cm.Batch, Body: body, Count: count}, nil
}

// compileNodeV2 mirrors compileNode but applies the v2 literal/expression rule: only a
// string whose first character is `$` is an expression. Getting this backwards is not a
// syntax error — it silently sends the PDP the literal text "$token.sub" as a subject —
// so the discriminator is the whole game.
func compileNodeV2(v any) (*compiledNode, error) {
	switch t := v.(type) {
	case string:
		src, isExpr := v2Expression(t)
		if !isExpr {
			return &compiledNode{literal: src}, nil
		}
		e, err := compileExpr(src)
		if err != nil {
			return nil, err
		}
		return &compiledNode{expr: e}, nil
	case map[string]any:
		obj := make(map[string]*compiledNode, len(t))
		for k, vv := range t {
			n, err := compileNodeV2(vv)
			if err != nil {
				return nil, err
			}
			obj[k] = n
		}
		return &compiledNode{object: obj}, nil
	case []any:
		arr := make([]*compiledNode, len(t))
		for i, vv := range t {
			n, err := compileNodeV2(vv)
			if err != nil {
				return nil, err
			}
			arr[i] = n
		}
		return &compiledNode{array: arr}, nil
	default:
		return &compiledNode{literal: t}, nil
	}
}

// v2Expression applies the leading-`$` discriminator. Returns the CEL source and true
// for an expression, or the literal text and false.
//
//	"$token.sub"  -> expression `token.sub`
//	"$$5.00"      -> literal `$5.00`   (doubling applies only to a LEADING $)
//	"customer"    -> literal `customer`
//	"a$b"         -> literal `a$b`     (a $ elsewhere has no special meaning)
func v2Expression(s string) (string, bool) {
	if !strings.HasPrefix(s, "$") {
		return s, false
	}
	if strings.HasPrefix(s, "$$") {
		return s[1:], false
	}
	return s[1:], true
}

// requireFields checks that AuthZEN's mandatory members resolved to something usable.
//
// For the evaluations envelope a member may sit at the top level as a default or inside
// each entry, so each entry is checked against the merge of the two.
func requireFields(req map[string]any, batch bool) error {
	if !batch {
		return checkOne(req, "")
	}
	entries, _ := req["evaluations"].([]any)
	for i, e := range entries {
		entry, _ := e.(map[string]any)
		merged := map[string]any{}
		for k, v := range req {
			if k != "evaluations" {
				merged[k] = v
			}
		}
		for k, v := range entry {
			merged[k] = v
		}
		if err := checkOne(merged, fmt.Sprintf("evaluations[%d].", i)); err != nil {
			return err
		}
	}
	return nil
}

// checkOne enforces subject.id, action.name and resource.type on one evaluation.
// resource.id is deliberately NOT required: AuthZEN allows a type-only resource, and the
// binding's own tools/list default maps a whole server that way.
func checkOne(req map[string]any, prefix string) error {
	subject, ok := req["subject"].(map[string]any)
	if !ok {
		return fmt.Errorf("%ssubject is missing", prefix)
	}
	if !nonEmptyString(subject["id"]) {
		return fmt.Errorf("%ssubject.id resolved to absent or null", prefix)
	}
	action, ok := req["action"].(map[string]any)
	if !ok {
		return fmt.Errorf("%saction is missing", prefix)
	}
	if !nonEmptyString(action["name"]) {
		return fmt.Errorf("%saction.name resolved to absent or null", prefix)
	}
	resource, ok := req["resource"].(map[string]any)
	if !ok {
		return fmt.Errorf("%sresource is missing", prefix)
	}
	if !nonEmptyString(resource["type"]) {
		return fmt.Errorf("%sresource.type resolved to absent or null", prefix)
	}
	if id, present := resource["id"]; present && !nonEmptyString(id) {
		return fmt.Errorf("%sresource.id resolved to absent or null", prefix)
	}
	return nil
}

func nonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// DefaultToolsCallMapping is the binding's default mapping for tools/call, which applies
// to a tool that declares none: "A PEP MUST apply the default mapping for a method unless
// a declared mapping applies to the specific operation."
func DefaultToolsCallMapping() map[string]any {
	return map[string]any{
		"evaluation": map[string]any{
			"subject":  map[string]any{"type": "identity", "id": "$token.sub"},
			"context":  map[string]any{"agent": "$token.?client_id"},
			"action":   map[string]any{"name": "tools/call"},
			"resource": map[string]any{"type": "tool", "id": "$params.name"},
		},
	}
}

// pruneNilContext removes context keys whose expression resolved to absent.
func pruneNilContext(req map[string]any) {
	ctx, ok := req["context"].(map[string]any)
	if !ok {
		return
	}
	for k, v := range ctx {
		if v == nil {
			delete(ctx, k)
		}
	}
}

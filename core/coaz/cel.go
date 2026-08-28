package coaz

// CEL evaluation of x-coaz-mapping fields, per the profile:
//   - every string value in the mapping is a CEL expression (static strings
//     are CEL string literals: 'customer');
//   - expressions are evaluated with two input variables: `params` (the
//     tools/call params object) and `token` (the decoded access-token claims);
//   - at least one field across subject+context MUST derive from `token`.

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"google.golang.org/protobuf/types/known/structpb"
)

var celEnv = mustEnv()

// Bounds on evaluating one mapping leaf. The limit is generous for the field access and
// concatenation real mappings use, and far below anything that could stall a request.
const (
	celCostLimit               = 1_000_000
	celInterruptCheckFrequency = 1_000
)

func mustEnv() *cel.Env {
	env, err := cel.NewEnv(
		cel.Variable("params", cel.DynType),
		cel.Variable("token", cel.DynType),
		// The binding's own default mappings use optional field selection
		// (`$token.?client_id`) for claims that may be absent, so this is not optional
		// for us: without it every default mapping fails to compile.
		cel.OptionalTypes(),
	)
	if err != nil {
		panic(err)
	}
	return env
}

// compiledExpr is one compiled mapping leaf.
type compiledExpr struct {
	src        string
	prg        cel.Program
	usesToken  bool
	usesParams bool
}

func compileExpr(src string) (*compiledExpr, error) {
	ast, iss := celEnv.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("CEL expression %q failed to compile: %w", src, iss.Err())
	}
	// Mappings arrive from a remote tools/list, so the programs are attacker-influenced.
	// Cap evaluation cost and check for interruption, or a hostile upstream can wedge
	// the PEP with an expensive expression.
	prg, err := celEnv.Program(ast,
		cel.CostLimit(celCostLimit),
		cel.InterruptCheckFrequency(celInterruptCheckFrequency))
	if err != nil {
		return nil, fmt.Errorf("CEL expression %q failed to plan: %w", src, err)
	}
	c := &compiledExpr{src: src, prg: prg}
	walkIdents(ast.NativeRep().Expr(), func(name string) {
		switch name {
		case "token":
			c.usesToken = true
		case "params":
			c.usesParams = true
		}
	})
	return c, nil
}

// walkIdents visits every identifier in the expression tree. Used to enforce
// the profile's "derived from the token input variable" requirements.
func walkIdents(e celast.Expr, fn func(name string)) {
	if e == nil {
		return
	}
	switch e.Kind() {
	case celast.IdentKind:
		fn(e.AsIdent())
	case celast.SelectKind:
		walkIdents(e.AsSelect().Operand(), fn)
	case celast.CallKind:
		call := e.AsCall()
		if call.IsMemberFunction() {
			walkIdents(call.Target(), fn)
		}
		for _, a := range call.Args() {
			walkIdents(a, fn)
		}
	case celast.ListKind:
		for _, el := range e.AsList().Elements() {
			walkIdents(el, fn)
		}
	case celast.MapKind:
		for _, entry := range e.AsMap().Entries() {
			me := entry.AsMapEntry()
			walkIdents(me.Key(), fn)
			walkIdents(me.Value(), fn)
		}
	case celast.StructKind:
		for _, f := range e.AsStruct().Fields() {
			walkIdents(f.AsStructField().Value(), fn)
		}
	case celast.ComprehensionKind:
		comp := e.AsComprehension()
		walkIdents(comp.IterRange(), fn)
		walkIdents(comp.AccuInit(), fn)
		walkIdents(comp.LoopCondition(), fn)
		walkIdents(comp.LoopStep(), fn)
		walkIdents(comp.Result(), fn)
	}
}

func (c *compiledExpr) eval(params, token map[string]any) (any, error) {
	out, _, err := c.prg.Eval(map[string]any{"params": params, "token": token})
	if err != nil {
		return nil, fmt.Errorf("CEL expression %q failed: %w", c.src, err)
	}
	// An optional (`?field`) evaluates to an optional value. An absent one becomes nil,
	// which the caller drops from the request — a claim that is not there should not
	// appear as an empty string the PDP might match on.
	if opt, ok := out.(*types.Optional); ok {
		if !opt.HasValue() {
			return nil, nil
		}
		out = opt.GetValue()
	}
	native, err := out.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
	if err != nil {
		return nil, fmt.Errorf("CEL expression %q produced an unconvertible value: %w", c.src, err)
	}
	return native.(*structpb.Value).AsInterface(), nil
}

// compiledNode mirrors a mapping element's JSON structure with string leaves
// replaced by compiled CEL programs. Non-string leaves (numbers, booleans,
// null) pass through as literals.
type compiledNode struct {
	expr    *compiledExpr // set when the node is a CEL string leaf
	literal any           // set when the node is a non-string scalar
	object  map[string]*compiledNode
	array   []*compiledNode
}

func compileNode(v any) (*compiledNode, error) {
	switch t := v.(type) {
	case string:
		e, err := compileExpr(t)
		if err != nil {
			return nil, err
		}
		return &compiledNode{expr: e}, nil
	case map[string]any:
		obj := make(map[string]*compiledNode, len(t))
		for k, vv := range t {
			n, err := compileNode(vv)
			if err != nil {
				return nil, err
			}
			obj[k] = n
		}
		return &compiledNode{object: obj}, nil
	case []any:
		arr := make([]*compiledNode, len(t))
		for i, vv := range t {
			n, err := compileNode(vv)
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

func (n *compiledNode) eval(params, token map[string]any) (any, error) {
	switch {
	case n.expr != nil:
		return n.expr.eval(params, token)
	case n.object != nil:
		out := make(map[string]any, len(n.object))
		for k, c := range n.object {
			v, err := c.eval(params, token)
			if err != nil {
				return nil, err
			}
			// An absent optional (`$token.?client_id` on a token without one) resolves
			// to nil and the key is dropped. Sending `"agent": null` would invite a
			// policy to match on it as a value; an absent claim should simply be absent.
			if v == nil {
				continue
			}
			out[k] = v
		}
		return out, nil
	case n.array != nil:
		out := make([]any, len(n.array))
		for i, c := range n.array {
			v, err := c.eval(params, token)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	default:
		return n.literal, nil
	}
}

func (n *compiledNode) usesToken() bool {
	switch {
	case n.expr != nil:
		return n.expr.usesToken
	case n.object != nil:
		for _, c := range n.object {
			if c.usesToken() {
				return true
			}
		}
	case n.array != nil:
		for _, c := range n.array {
			if c.usesToken() {
				return true
			}
		}
	}
	return false
}

package federation

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// Metadata policy, §6.1. A policy is entity type -> parameter -> operator -> value.

var operatorOrder = []string{"value", "add", "default", "one_of", "subset_of", "superset_of", "essential"}

func knownOperator(op string) bool {
	for _, o := range operatorOrder {
		if o == op {
			return true
		}
	}
	return false
}

type paramPolicy map[string]any

func parsePolicy(v any) (map[string]map[string]map[string]any, error) {
	byType, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metadata_policy is not an object")
	}
	out := make(map[string]map[string]map[string]any, len(byType))
	for et, rawParams := range byType {
		params, ok := rawParams.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("metadata_policy.%s is not an object", et)
		}
		out[et] = make(map[string]map[string]any, len(params))
		for name, rawOps := range params {
			ops, ok := rawOps.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("metadata_policy.%s.%s is not an object", et, name)
			}
			if err := validateOperators(ops); err != nil {
				return nil, fmt.Errorf("metadata_policy.%s.%s: %v", et, name, err)
			}
			out[et][name] = ops
		}
	}
	return out, nil
}

// validateOperators checks each operator's value type and the allowed combinations
// from §6.1.3.1. Unknown operators are left in place; the crit check decides whether
// they matter.
func validateOperators(ops paramPolicy) error {
	isArray := func(v any) bool { _, ok := v.([]any); return ok }
	for op, v := range ops {
		switch op {
		case "value":
			// any JSON value, including null
		case "add", "one_of", "subset_of", "superset_of":
			if !isArray(v) {
				return fmt.Errorf("%s must be an array", op)
			}
		case "default":
			if v == nil {
				return fmt.Errorf("default must not be null")
			}
		case "essential":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("essential must be a boolean")
			}
		}
	}
	value, hasValue := ops["value"]
	essential, _ := ops["essential"].(bool)
	if hasValue && value == nil && essential {
		return fmt.Errorf("value null contradicts essential true")
	}
	if hasValue && value == nil {
		if _, ok := ops["default"]; ok {
			return fmt.Errorf("value null cannot combine with default")
		}
	}
	if _, ok := ops["one_of"]; ok {
		for _, bad := range []string{"add", "subset_of", "superset_of"} {
			if _, present := ops[bad]; present {
				return fmt.Errorf("one_of cannot combine with %s", bad)
			}
		}
	}
	if hasValue && value != nil {
		if one, ok := ops["one_of"].([]any); ok && !contains(one, value) {
			return fmt.Errorf("value is not among one_of")
		}
		if sub, ok := ops["subset_of"].([]any); ok && !isSubset(value, sub) {
			return fmt.Errorf("value is not a subset of subset_of")
		}
		if sup, ok := ops["superset_of"].([]any); ok && !isSubset(sup, value) {
			return fmt.Errorf("value is not a superset of superset_of")
		}
		if add, ok := ops["add"].([]any); ok && !isSubset(add, value) {
			return fmt.Errorf("add is not a subset of value")
		}
	}
	if add, ok := ops["add"].([]any); ok {
		if sub, ok := ops["subset_of"].([]any); ok && !isSubset(add, sub) {
			return fmt.Errorf("add is not a subset of subset_of")
		}
	}
	if sub, ok := ops["subset_of"].([]any); ok {
		if sup, ok := ops["superset_of"].([]any); ok && !isSubset(sup, sub) {
			return fmt.Errorf("subset_of is not a superset of superset_of")
		}
	}
	return nil
}

// mergePolicies folds sub (a deeper Superior's policy) into acc (the policy resolved
// so far from above) per the §6.1.3.1 merge semantics.
func mergePolicies(acc, sub map[string]map[string]map[string]any, crit []string) error {
	for et, params := range sub {
		if acc[et] == nil {
			acc[et] = map[string]map[string]any{}
		}
		for name, ops := range params {
			merged, err := mergeOperators(acc[et][name], ops, crit)
			if err != nil {
				return fmt.Errorf("%s.%s: %v", et, name, err)
			}
			acc[et][name] = merged
		}
	}
	return nil
}

func mergeOperators(above, below paramPolicy, crit []string) (paramPolicy, error) {
	out := paramPolicy{}
	for k, v := range above {
		out[k] = v
	}
	for op, v := range below {
		if !knownOperator(op) {
			continue // unknown, not critical (parse rejected critical unknowns)
		}
		prev, had := out[op]
		if !had {
			out[op] = v
			continue
		}
		switch op {
		case "value", "default":
			if !reflect.DeepEqual(prev, v) {
				return nil, fmt.Errorf("%s conflicts between superiors", op)
			}
		case "add", "superset_of":
			out[op] = union(prev.([]any), v.([]any))
		case "subset_of":
			out[op] = intersection(prev.([]any), v.([]any))
		case "one_of":
			x := intersection(prev.([]any), v.([]any))
			if len(x) == 0 {
				return nil, fmt.Errorf("one_of intersection is empty")
			}
			out[op] = x
		case "essential":
			out[op] = prev.(bool) || v.(bool)
		}
	}
	if err := validateOperators(out); err != nil {
		return nil, err
	}
	return out, nil
}

// applyPolicy applies one parameter's merged operators, in the fixed order.
func applyPolicy(meta map[string]any, name string, ops paramPolicy) error {
	for _, op := range operatorOrder {
		v, present := ops[op]
		if !present {
			continue
		}
		cur, has := meta[name]
		switch op {
		case "value":
			if v == nil {
				delete(meta, name)
			} else {
				meta[name] = v
			}
		case "add":
			if !has {
				meta[name] = append([]any{}, v.([]any)...)
			} else {
				arr, ok := cur.([]any)
				if !ok {
					return fmt.Errorf("%s: add applies to arrays, parameter is %T", name, cur)
				}
				meta[name] = union(arr, v.([]any))
			}
		case "default":
			if !has {
				meta[name] = v
			}
		case "one_of":
			if has && !contains(v.([]any), cur) {
				return fmt.Errorf("%s: %s is not one of %v", name, render(cur), v)
			}
		case "subset_of":
			if has {
				arr, ok := cur.([]any)
				if !ok {
					return fmt.Errorf("%s: subset_of applies to arrays, parameter is %T", name, cur)
				}
				meta[name] = intersection(arr, v.([]any))
			}
		case "superset_of":
			if has {
				if !isSubset(v, cur) {
					return fmt.Errorf("%s: %s does not contain all of %v", name, render(cur), v)
				}
			}
		case "essential":
			if v.(bool) {
				if _, has := meta[name]; !has {
					return fmt.Errorf("%s is essential but absent", name)
				}
			}
		}
	}
	return nil
}

// resolveMetadata produces the leaf's Resolved Metadata (§6.1.4): start from its
// Entity Configuration, overlay any `metadata` the immediate Superior asserted about
// it, then apply the policies merged from the anchor downward.
func resolveMetadata(chain []*Statement) (map[string]map[string]any, error) {
	leaf := chain[0]
	meta := map[string]map[string]any{}
	for et, params := range leaf.Metadata {
		meta[et] = cloneParams(params)
	}
	if len(chain) > 2 {
		// chain[1] is the Subordinate Statement about the leaf; its `metadata` applies
		// to the leaf and is applied before any policy (§6.1.4.2).
		for et, params := range chain[1].Metadata {
			if meta[et] == nil {
				meta[et] = map[string]any{}
			}
			for k, v := range params {
				meta[et][k] = v
			}
		}
	}
	merged := map[string]map[string]map[string]any{}
	// Superiors from the top down: chain[len-2] is the anchor's statement.
	for j := len(chain) - 2; j >= 1; j-- {
		if err := mergePolicies(merged, chain[j].MetadataPolicy, chain[j].MetadataPolicyCrit); err != nil {
			return nil, fmt.Errorf("metadata policy from %s: %v", chain[j].Iss, err)
		}
	}
	for et, params := range merged {
		if meta[et] == nil {
			continue // policy alone does not make the leaf claim an entity type
		}
		for name, ops := range params {
			if err := applyPolicy(meta[et], name, ops); err != nil {
				return nil, fmt.Errorf("metadata policy for %s: %v", et, err)
			}
		}
	}
	return meta, nil
}

func cloneParams(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func contains(list []any, v any) bool {
	for _, x := range list {
		if reflect.DeepEqual(x, v) {
			return true
		}
	}
	return false
}

// isSubset reports whether every element of a is in b. Non-array operands are
// treated as single-element sets, which is how a scalar `value` combines with the
// array operators.
func isSubset(a, b any) bool {
	as, ok := a.([]any)
	if !ok {
		as = []any{a}
	}
	bs, ok := b.([]any)
	if !ok {
		bs = []any{b}
	}
	for _, x := range as {
		if !contains(bs, x) {
			return false
		}
	}
	return true
}

func union(a, b []any) []any {
	out := append([]any{}, a...)
	for _, x := range b {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func intersection(a, b []any) []any {
	out := []any{}
	for _, x := range a {
		if contains(b, x) && !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func render(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

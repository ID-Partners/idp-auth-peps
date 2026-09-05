package federation

import (
	"reflect"
	"testing"
)

func TestValidateOperatorCombinations(t *testing.T) {
	bad := map[string]paramPolicy{
		"default null":                {"default": nil},
		"essential not bool":          {"essential": "yes"},
		"value null essential":        {"value": nil, "essential": true},
		"value null default":          {"value": nil, "default": "x"},
		"one_of with add":             {"one_of": []any{"a"}, "add": []any{"a"}},
		"one_of with subset_of":       {"one_of": []any{"a"}, "subset_of": []any{"a"}},
		"one_of with superset_of":     {"one_of": []any{"a"}, "superset_of": []any{"a"}},
		"value not in one_of":         {"value": "b", "one_of": []any{"a"}},
		"value not subset":            {"value": []any{"b"}, "subset_of": []any{"a"}},
		"value not superset":          {"value": []any{"a"}, "superset_of": []any{"b"}},
		"add not subset of value":     {"value": []any{"a"}, "add": []any{"b"}},
		"add not subset of subset_of": {"add": []any{"b"}, "subset_of": []any{"a"}},
		"subset_of not superset":      {"subset_of": []any{"a"}, "superset_of": []any{"b"}},
		"superset_of not array":       {"superset_of": "a"},
	}
	for name, ops := range bad {
		if err := validateOperators(ops); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	good := map[string]paramPolicy{
		"value in one_of":      {"value": "a", "one_of": []any{"a"}},
		"value with essential": {"value": "a", "essential": true},
		"value null alone":     {"value": nil},
		"set equals":           {"subset_of": []any{"a"}, "superset_of": []any{"a"}, "add": []any{"a"}, "value": []any{"a"}, "default": []any{"a"}, "essential": false},
		"unknown operator":     {"regexp": "x"},
	}
	for name, ops := range good {
		if err := validateOperators(ops); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMergeOperators(t *testing.T) {
	above := paramPolicy{"add": []any{"a"}, "superset_of": []any{"a"}, "subset_of": []any{"a", "b", "c"}, "essential": false, "default": "x", "value": []any{"a", "b"}}
	below := paramPolicy{"add": []any{"b"}, "superset_of": []any{"b"}, "subset_of": []any{"a", "b", "d"}, "essential": true, "default": "x", "value": []any{"a", "b"}, "regexp": "ignored"}
	got, err := mergeOperators(above, below, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := paramPolicy{"add": []any{"a", "b"}, "superset_of": []any{"a", "b"}, "subset_of": []any{"a", "b"}, "essential": true, "default": "x", "value": []any{"a", "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if _, err := mergeOperators(paramPolicy{"default": "x"}, paramPolicy{"default": "y"}, nil); err == nil {
		t.Fatal("default conflict")
	}
	if got, err := mergeOperators(paramPolicy{"one_of": []any{"a", "b"}}, paramPolicy{"one_of": []any{"b"}}, nil); err != nil || !reflect.DeepEqual(got["one_of"], []any{"b"}) {
		t.Fatalf("one_of intersection: %v %v", got, err)
	}
}

func TestApplyPolicyEdgeCases(t *testing.T) {
	meta := map[string]any{}
	if err := applyPolicy(meta, "p", paramPolicy{"add": []any{"a", "a"}}); err != nil || !reflect.DeepEqual(meta["p"], []any{"a", "a"}) {
		// add to an absent parameter initialises it verbatim
		t.Fatalf("add init: %v %v", meta, err)
	}
	meta = map[string]any{"p": []any{"a"}}
	if err := applyPolicy(meta, "p", paramPolicy{"add": []any{"a", "b"}}); err != nil || !reflect.DeepEqual(meta["p"], []any{"a", "b"}) {
		t.Fatalf("add dedupes: %v %v", meta, err)
	}
	meta = map[string]any{}
	if err := applyPolicy(meta, "p", paramPolicy{"one_of": []any{"a"}, "superset_of": []any{"a"}, "subset_of": []any{"a"}}); err != nil {
		t.Fatalf("absent parameter passes the check operators: %v", err)
	}
	if _, present := meta["p"]; present {
		t.Fatal("check operators must not create the parameter")
	}
	meta = map[string]any{"p": "x"}
	if err := applyPolicy(meta, "p", paramPolicy{"default": "y"}); err != nil || meta["p"] != "x" {
		t.Fatalf("default must not override: %v", meta)
	}
	if err := applyPolicy(meta, "p", paramPolicy{"essential": false}); err != nil {
		t.Fatal(err)
	}
	meta = map[string]any{"p": []any{"a", "b"}}
	if err := applyPolicy(meta, "p", paramPolicy{"superset_of": []any{"a"}}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveMetadataDropsPolicyOnlyTypes(t *testing.T) {
	leaf := &Statement{Iss: "a", Sub: "a", Metadata: map[string]map[string]any{"oauth_resource": {"x": "1"}}}
	ss := &Statement{Iss: "ta", Sub: "a", MetadataPolicy: map[string]map[string]map[string]any{
		"openid_relying_party": {"client_name": {"default": "n"}},
		"oauth_resource":       {"y": {"default": "2"}},
	}}
	ta := &Statement{Iss: "ta", Sub: "ta"}
	got, err := resolveMetadata([]*Statement{leaf, ss, ta})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got["openid_relying_party"]; present {
		t.Fatal("a policy alone must not make the leaf claim an entity type")
	}
	if got["oauth_resource"]["y"] != "2" || got["oauth_resource"]["x"] != "1" {
		t.Fatalf("%v", got)
	}
}

func TestSetHelpers(t *testing.T) {
	if !isSubset("a", []any{"a"}) || isSubset([]any{"a"}, "b") || !isSubset([]any{}, "b") {
		t.Fatal("isSubset scalar handling")
	}
	if got := intersection([]any{"a", "a", "b"}, []any{"a"}); !reflect.DeepEqual(got, []any{"a"}) {
		t.Fatalf("intersection dedupes: %v", got)
	}
	if render(make(chan int)) != "" {
		t.Fatal("render swallows marshal errors")
	}
}

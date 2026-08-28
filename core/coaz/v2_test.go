package coaz

import (
	"encoding/json"
	"testing"
)

func mustMappingV2(t *testing.T, name, raw string) *CompiledMappingV2 {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	cm, err := CompileMappingV2(name, m)
	if err != nil {
		t.Fatalf("CompileMappingV2: %v", err)
	}
	return cm
}

var v2Token = map[string]any{
	"sub":       "alice@example.com",
	"client_id": "http://agentprovider.com/agent-app-id",
	"aud":       "https://mcp.example.com",
}

// The binding's worked example, verbatim from the declared-mapping figure.
func TestV2SpecExample(t *testing.T) {
	cm := mustMappingV2(t, "get_customer", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$token.sub" },
	    "action":   { "name": "get_customer" },
	    "resource": { "type": "customer", "id": "$params.arguments.id" },
	    "context":  { "agent": "$token.?client_id", "case": "$params.arguments.case" }
	  }
	}`)
	if cm.Batch {
		t.Fatal("the evaluation envelope must not batch")
	}
	if !cm.Anchored() {
		t.Fatal("subject.id is $token.sub — it should be trust-anchored")
	}

	params := map[string]any{
		"name":      "get_customer",
		"arguments": map[string]any{"id": "cust-12345", "case": "case-67890"},
	}
	built, err := cm.Build(params, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(built.Body, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		// Unquoted strings are LITERALS in v2 — the whole point of the discriminator.
		"subject":  map[string]any{"type": "identity", "id": "alice@example.com"},
		"action":   map[string]any{"name": "get_customer"},
		"resource": map[string]any{"type": "customer", "id": "cust-12345"},
		"context":  map[string]any{"agent": "http://agentprovider.com/agent-app-id", "case": "case-67890"},
	}
	if !jsonEqual(got, want) {
		t.Fatalf("built request mismatch\n got: %v\nwant: %v", got, want)
	}
}

// The v1/v2 trap: a bare word is a literal in v2 and a CEL identifier in v1.
func TestV2TreatsUnprefixedStringsAsLiterals(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$token.sub" },
	    "resource": { "type": "customer", "id": "a-fixed-id" },
	    "context":  { "channel": "ai-agent", "price": "$$9.99", "note": "a$b" }
	  }
	}`)
	built, err := cm.Build(map[string]any{}, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)

	res := got["resource"].(map[string]any)
	if res["id"] != "a-fixed-id" || res["type"] != "customer" {
		t.Fatalf("literals were not passed through verbatim: %v", res)
	}
	ctx := got["context"].(map[string]any)
	if ctx["channel"] != "ai-agent" {
		t.Fatalf("literal context value mangled: %v", ctx["channel"])
	}
	if ctx["price"] != "$9.99" {
		t.Fatalf("$$ should escape to a single leading $, got %v", ctx["price"])
	}
	if ctx["note"] != "a$b" {
		t.Fatalf("a $ that is not leading has no meaning, got %v", ctx["note"])
	}
}

func TestV2RejectsAMalformedEnvelope(t *testing.T) {
	cases := map[string]string{
		"no envelope":     `{"subject": {"id": "$token.sub"}}`,
		"two members":     `{"evaluation": {}, "evaluations": {}}`,
		"unknown key":     `{"evaluate": {}}`,
		"envelope scalar": `{"evaluation": "nope"}`,
		"empty":           `{}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal([]byte(raw), &m)
			if _, err := CompileMappingV2("t", m); err == nil {
				t.Fatal("expected a mapping error")
			}
		})
	}
}

// "Returning a list SHALL NOT cause the request to fan out" — the envelope alone
// decides, unlike v1 where a multi-element field triggered the boxcar API.
func TestV2ListValuesDoNotFanOut(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$token.sub" },
	    "resource": { "type": "account", "id": "a1", "properties": { "tags": ["x", "y", "z"] } },
	    "context":  { "agent": "$token.?client_id" }
	  }
	}`)
	built, err := cm.Build(map[string]any{}, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if built.Batch || built.Count != 1 {
		t.Fatalf("a list value must not fan out: batch=%v count=%d", built.Batch, built.Count)
	}
}

func TestV2EvaluationsEnvelopeBatches(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluations": {
	    "subject": { "type": "identity", "id": "$token.sub" },
	    "context": { "agent": "$token.?client_id" },
	    "evaluations": [
	      { "action": { "name": "debit" },  "resource": { "type": "account", "id": "$params.arguments.from" } },
	      { "action": { "name": "credit" }, "resource": { "type": "account", "id": "$params.arguments.to" } }
	    ]
	  }
	}`)
	if !cm.Batch {
		t.Fatal("the evaluations envelope must batch")
	}
	params := map[string]any{"arguments": map[string]any{"from": "acc-1", "to": "acc-2"}}
	built, err := cm.Build(params, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if built.Count != 2 {
		t.Fatalf("expected 2 decisions, got %d", built.Count)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	if subj := got["subject"].(map[string]any); subj["id"] != "alice@example.com" {
		t.Fatalf("top-level subject should apply to all entries: %v", subj)
	}
}

// Identity smuggling: an entry that sets its own subject is rejected outright.
func TestV2RejectsSubjectInsideAnEvaluationsEntry(t *testing.T) {
	var m map[string]any
	_ = json.Unmarshal([]byte(`{
	  "evaluations": {
	    "subject": { "type": "identity", "id": "$token.sub" },
	    "evaluations": [
	      { "subject": { "type": "identity", "id": "someone-else" },
	        "action": { "name": "debit" }, "resource": { "type": "account", "id": "a1" } }
	    ]
	  }
	}`), &m)
	if _, err := CompileMappingV2("t", m); err == nil {
		t.Fatal("a subject inside an evaluations entry must be a mapping error")
	}
}

// The trust anchor: an MCP server must not be able to name a different subject.
func TestV2VerifiesTheAnchoredSubject(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$token.sub" },
	    "resource": { "type": "customer", "id": "c1" },
	    "context":  { "agent": "$token.?client_id" }
	  }
	}`)
	// A token with no sub cannot anchor anything.
	if _, err := cm.Build(map[string]any{}, map[string]any{"client_id": "c"}, nil); err == nil {
		t.Fatal("expected a mapping error when the token carries no sub")
	}
}

func TestV2SuppliesTheDefaultSubjectWhenOmitted(t *testing.T) {
	// "If a declared mapping omits subject or subject.id, the PEP MUST supply the
	// default subject identifier ... so that every request still carries a
	// token-anchored subject."
	for name, raw := range map[string]string{
		"no subject":    `{"evaluation": {"resource": {"type": "customer", "id": "c1"}}}`,
		"no subject.id": `{"evaluation": {"subject": {"type": "identity"}, "resource": {"type": "customer", "id": "c1"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cm := mustMappingV2(t, "t", raw)
			if !cm.Anchored() {
				t.Fatal("a supplied default subject must be anchored")
			}
			built, err := cm.Build(map[string]any{}, v2Token, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			_ = json.Unmarshal(built.Body, &got)
			if subj := got["subject"].(map[string]any); subj["id"] != "alice@example.com" {
				t.Fatalf("default subject not supplied: %v", subj)
			}
		})
	}
}

// An override is permitted but is NOT an anchor, and must not be verified as one.
func TestV2OverriddenSubjectIsNotAnchored(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$params.arguments.on_behalf_of" },
	    "resource": { "type": "customer", "id": "c1" },
	    "context":  { "agent": "$token.?client_id" }
	  }
	}`)
	if cm.Anchored() {
		t.Fatal("a subject.id from params is asserted, not anchored")
	}
	params := map[string]any{"arguments": map[string]any{"on_behalf_of": "bob@example.com"}}
	built, err := cm.Build(params, v2Token, nil)
	if err != nil {
		t.Fatalf("an override should build, not fail: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	if subj := got["subject"].(map[string]any); subj["id"] != "bob@example.com" {
		t.Fatalf("override not honoured: %v", subj)
	}
}

func TestDeniedCodePerDialect(t *testing.T) {
	if got := DialectV2.DeniedCode(); got != -32001 {
		t.Fatalf("v2 denial code = %d, want -32001 (JSON-RPC server-error range)", got)
	}
	if got := DialectV1.DeniedCode(); got != -32401 {
		t.Fatalf("v1 denial code = %d, want -32401 (superseded, kept for v1 tools)", got)
	}
}

func TestV2ExtraContextDoesNotOverrideTheMapping(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$token.sub" },
	    "resource": { "type": "customer", "id": "c1" },
	    "context":  { "agent": "$token.?client_id" }
	  }
	}`)
	built, err := cm.Build(map[string]any{}, v2Token,
		map[string]any{"agent": "IGNORED", "channel": "ai-agent"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	ctx := got["context"].(map[string]any)
	if ctx["agent"] != "http://agentprovider.com/agent-app-id" {
		t.Fatalf("gateway context overrode a declared value: %v", ctx["agent"])
	}
	if ctx["channel"] != "ai-agent" {
		t.Fatalf("gateway context not merged into unset keys: %v", ctx)
	}
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func TestV2AbsentOptionalClaimIsOmittedNotNull(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluation": {
	    "subject":  { "type": "identity", "id": "$token.sub" },
	    "resource": { "type": "customer", "id": "c1" },
	    "context":  { "agent": "$token.?client_id" }
	  }
	}`)
	// A token with no client_id at all.
	built, err := cm.Build(map[string]any{}, map[string]any{"sub": "alice@example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	ctx, _ := got["context"].(map[string]any)
	if v, present := ctx["agent"]; present {
		t.Fatalf("an absent optional claim should be omitted, not sent as %v", v)
	}
}

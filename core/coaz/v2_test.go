package coaz

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
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
	    "action":   { "name": "t" },
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
	    "action":   { "name": "t" },
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
	    "action":   { "name": "t" },
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
		"no subject":    `{"evaluation": {"action": {"name": "t"}, "resource": {"type": "customer", "id": "c1"}}}`,
		"no subject.id": `{"evaluation": {"subject": {"type": "identity"}, "action": {"name": "t"}, "resource": {"type": "customer", "id": "c1"}}}`,
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
	    "action":   { "name": "t" },
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
	    "action":   { "name": "t" },
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
	    "action":   { "name": "t" },
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

// The framework: "subject, action, and resource are required for every evaluation. If an
// expression yields absent or null for a required field ... this is a mapping error."
// Without this the malformed request reaches the PDP and the deny reads as policy.
func TestV2RequiredFieldsMustResolve(t *testing.T) {
	cases := map[string]string{
		"no action": `{"evaluation": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "resource": {"type": "customer", "id": "c1"}}}`,
		"no resource": `{"evaluation": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "action": {"name": "t"}}}`,
		"resource.id absent": `{"evaluation": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "action": {"name": "t"},
		    "resource": {"type": "customer", "id": "$token.?nope"}}}`,
		"action.name absent": `{"evaluation": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "action": {"name": "$token.?nope"},
		    "resource": {"type": "customer", "id": "c1"}}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal([]byte(raw), &m)
			cm, err := CompileMappingV2("t", m)
			if err != nil {
				return // rejected at compile time is also correct
			}
			if _, err := cm.Build(map[string]any{}, v2Token, nil); err == nil {
				t.Fatal("expected a mapping error for a missing required field")
			}
		})
	}
}

func TestV2RequiredFieldsCheckedPerBoxcarEntry(t *testing.T) {
	cm := mustMappingV2(t, "t", `{
	  "evaluations": {
	    "subject": { "type": "identity", "id": "$token.sub" },
	    "action":  { "name": "transfer" },
	    "evaluations": [
	      { "resource": { "type": "account", "id": "a1" } },
	      { "resource": { "type": "account", "id": "$params.arguments.missing" } }
	    ]
	  }
	}`)
	// The second entry's resource.id does not resolve; the top-level action covers both.
	if _, err := cm.Build(map[string]any{"arguments": map[string]any{}}, v2Token, nil); err == nil {
		t.Fatal("a required field absent in one entry must fail the whole request")
	}
}

// The default mapping is the binding's, not an invention.
func TestDefaultToolsCallMappingMatchesTheBinding(t *testing.T) {
	cm, err := CompileMappingV2("tools/call", DefaultToolsCallMapping())
	if err != nil {
		t.Fatal(err)
	}
	if !cm.Anchored() {
		t.Fatal("the default mapping's subject must be token-anchored")
	}
	built, err := cm.Build(map[string]any{"name": "get_local_weather"}, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	want := map[string]any{
		"subject":  map[string]any{"type": "identity", "id": "alice@example.com"},
		"context":  map[string]any{"agent": "http://agentprovider.com/agent-app-id"},
		"action":   map[string]any{"name": "tools/call"},
		"resource": map[string]any{"type": "tool", "id": "get_local_weather"},
	}
	if !jsonEqual(got, want) {
		t.Fatalf("default mapping mismatch\n got: %v\nwant: %v", got, want)
	}
}

// Regression for a real bypass: an expression-valued `evaluations` deferred the
// structure to evaluation time, where it is built from caller-controlled params — so
// entries could carry their own subjects and the compile-time check inspected nothing.
// The smuggled subject reached the PDP as the authorized identity.
func TestV2RejectsExpressionValuedStructure(t *testing.T) {
	cases := map[string]string{
		"evaluations from an expression": `{"evaluations": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "action":  {"name": "t"},
		    "evaluations": "$params.arguments.smuggled"}}`,
		"subject from an expression": `{"evaluation": {
		    "subject": "$params.arguments.whoever",
		    "action":  {"name": "t"},
		    "resource": {"type": "r", "id": "r1"}}}`,
		"evaluations entry not an object": `{"evaluations": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "action":  {"name": "t"},
		    "evaluations": ["$params.arguments.x"]}}`,
		"evaluations missing": `{"evaluations": {
		    "subject": {"type": "identity", "id": "$token.sub"},
		    "action":  {"name": "t"}}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				t.Fatalf("bad fixture: %v", err)
			}
			if _, err := CompileMappingV2("t", m); err == nil {
				t.Fatal("structure must be literal — an expression here defers it to caller-controlled input")
			}
		})
	}
}

// AuthZEN subjects require a type; the binding's own defaults use "identity".
func TestV2DefaultedSubjectCarriesAType(t *testing.T) {
	cm := mustMappingV2(t, "t", `{"evaluation": {
	  "action":   {"name": "t"},
	  "resource": {"type": "customer", "id": "c1"}}}`)
	built, err := cm.Build(map[string]any{}, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	subj := got["subject"].(map[string]any)
	if subj["type"] != "identity" {
		t.Fatalf("defaulted subject must carry a type, got %v", subj)
	}
	if subj["id"] != "alice@example.com" {
		t.Fatalf("defaulted subject id wrong: %v", subj)
	}
}

// Every default mapping in the binding must compile and produce the documented shape.
func TestAllDefaultMappingsCompile(t *testing.T) {
	methods := []string{
		"tools/call", "tools/list",
		"resources/list", "resources/read", "resources/subscribe", "resources/unsubscribe",
		"prompts/list", "prompts/get",
		"completion/complete", "logging/setLevel",
		"tasks/get", "tasks/result", "tasks/cancel", "tasks/list",
		"initialize", // our deliberate addition — see defaults.go
	}
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			cm, err := CompiledDefault(m)
			if err != nil {
				t.Fatalf("default mapping for %s did not compile: %v", m, err)
			}
			if !cm.Anchored() {
				t.Fatalf("default mapping for %s must be token-anchored", m)
			}
		})
	}
}

func TestDefaultMappingShapes(t *testing.T) {
	tokenWithAud := map[string]any{
		"sub": "alice@example.com", "client_id": "agent-1", "aud": "https://mcp.example.com",
	}
	cases := []struct {
		method string
		params map[string]any
		want   map[string]any
	}{
		{"tools/list", map[string]any{}, map[string]any{"type": "mcp_server", "id": "https://mcp.example.com"}},
		{"resources/read", map[string]any{"uri": "file:///a"}, map[string]any{"type": "resource", "id": "file:///a"}},
		{"prompts/get", map[string]any{"name": "greet"}, map[string]any{"type": "prompt", "id": "greet"}},
		{"tasks/cancel", map[string]any{"taskId": "t-1"}, map[string]any{"type": "task", "id": "t-1"}},
		// The binding's one conditional default.
		{"completion/complete", map[string]any{"ref": map[string]any{"type": "ref/prompt", "name": "p1"}},
			map[string]any{"type": "prompt", "id": "p1"}},
		{"completion/complete", map[string]any{"ref": map[string]any{"type": "ref/resource", "uri": "file:///b"}},
			map[string]any{"type": "resource", "id": "file:///b"}},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			cm, err := CompiledDefault(tc.method)
			if err != nil {
				t.Fatal(err)
			}
			built, err := cm.Build(tc.params, tokenWithAud, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			_ = json.Unmarshal(built.Body, &got)
			if !jsonEqual(got["resource"], tc.want) {
				t.Fatalf("resource mismatch\n got: %v\nwant: %v", got["resource"], tc.want)
			}
			if action := got["action"].(map[string]any); action["name"] != tc.method {
				t.Fatalf("action.name should be the method, got %v", action["name"])
			}
		})
	}
}

func TestPassThroughAndUnknownMethods(t *testing.T) {
	for _, m := range []string{"ping", "notifications/initialized", "notifications/cancelled"} {
		if !IsPassThrough(m) {
			t.Errorf("%s should be pass-through", m)
		}
	}
	for _, m := range []string{"tools/call", "resources/read", "future/method"} {
		if IsPassThrough(m) {
			t.Errorf("%s must not be pass-through", m)
		}
	}
	// Unknown methods have no default — the engine denies them (fail closed).
	if _, ok := DefaultMappings("future/method"); ok {
		t.Error("an unknown method must not have a default mapping")
	}
	// logging/setLevel carries the level in context.
	cm, err := CompiledDefault("logging/setLevel")
	if err != nil {
		t.Fatal(err)
	}
	built, err := cm.Build(map[string]any{"level": "debug"},
		map[string]any{"sub": "a", "aud": "srv"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	if ctx := got["context"].(map[string]any); ctx["level"] != "debug" {
		t.Fatalf("logging/setLevel should carry level in context, got %v", ctx)
	}
}

// Unknown methods fail closed, which is the point of the rule.
func TestUnknownMethodIsDenied(t *testing.T) {
	e, mcp, _, _ := newEngineForTest(t, false, true, "ok by policy")
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"future/method","params":{}}`)
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok", body, specToken, nil,
		CallOptions{ApplyDefaultMappings: true})
	if v.Decision {
		t.Fatalf("an unknown method must be denied so future MCP versions fail closed, got %+v", v)
	}
	if !bytes.Contains(v.JSONRPCError, []byte("-32001")) {
		t.Fatalf("expected a -32001 denial, got %s", v.JSONRPCError)
	}
}

func TestPassThroughMethodsSkipThePDP(t *testing.T) {
	// A PDP that denies everything — a pass-through method must not reach it.
	e, mcp, _, _ := newEngineForTest(t, false, false, "denied by policy")
	for _, m := range []string{"ping", "notifications/initialized"} {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + m + `","params":{}}`)
		v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok", body, specToken, nil,
			CallOptions{ApplyDefaultMappings: true})
		if !v.Decision {
			t.Fatalf("%s must proceed without a PDP call, got %+v", m, v)
		}
	}
}

func TestNonToolsCallMethodIsGovernedByItsDefault(t *testing.T) {
	e, mcp, _, _ := newEngineForTest(t, false, false, "denied by policy")
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///secret"}}`)
	v := e.CheckToolCall(context.Background(), mcp.URL, "Bearer tok", body, specToken, nil,
		CallOptions{ApplyDefaultMappings: true})
	if v.Decision {
		t.Fatal("resources/read must be authorized against its default mapping, not waved through")
	}
	if !bytes.Contains(v.PDPRequest, []byte(`"file:///secret"`)) {
		t.Fatalf("the PDP should have been asked about the resource, got %s", v.PDPRequest)
	}
}

func TestDialectString(t *testing.T) {
	if DialectV2.String() != "coaz/v2" || DialectV1.String() != "coaz/v1" {
		t.Fatalf("dialect names: %q %q", DialectV2, DialectV1)
	}
}

func TestServerInitiatedSet(t *testing.T) {
	for _, m := range []string{"sampling/createMessage", "elicitation/create", "roots/list"} {
		if !IsServerInitiated(m) {
			t.Errorf("%s is server-initiated", m)
		}
	}
	for _, m := range []string{"tools/call", "ping", ""} {
		if IsServerInitiated(m) {
			t.Errorf("%s is not server-initiated", m)
		}
	}
}

func TestV2CompileRejectsUncompilableLeaves(t *testing.T) {
	var m map[string]any
	_ = json.Unmarshal([]byte(`{"evaluation": {
	  "subject":  {"type": "identity", "id": "$token.sub"},
	  "action":   {"name": "$this is not ( valid CEL"},
	  "resource": {"type": "r", "id": "x"}}}`), &m)
	if _, err := CompileMappingV2("t", m); err == nil {
		t.Fatal("a leaf that will not compile must fail at compile time, not at request time")
	}
}

func TestV2HandlesNonStringLeaves(t *testing.T) {
	// Numbers, booleans, null and nested arrays are literals and must survive intact.
	cm := mustMappingV2(t, "t", `{"evaluation": {
	  "subject":  {"type": "identity", "id": "$token.sub"},
	  "action":   {"name": "t"},
	  "resource": {"type": "r", "id": "x", "properties": {
	      "limit": 100, "active": true, "tags": ["a", "b"], "nested": {"deep": 1}}}}}`)
	built, err := cm.Build(map[string]any{}, v2Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(built.Body, &got)
	props := got["resource"].(map[string]any)["properties"].(map[string]any)
	if props["limit"].(float64) != 100 || props["active"] != true {
		t.Fatalf("scalar literals mangled: %v", props)
	}
	if tags := props["tags"].([]any); len(tags) != 2 || tags[0] != "a" {
		t.Fatalf("array literal mangled: %v", props["tags"])
	}
	if props["nested"].(map[string]any)["deep"].(float64) != 1 {
		t.Fatalf("nested object mangled: %v", props["nested"])
	}
}

func TestV2SubjectMustBeAnObject(t *testing.T) {
	var m map[string]any
	_ = json.Unmarshal([]byte(`{"evaluation": {"subject": 42, "action": {"name":"t"}, "resource": {"type":"r"}}}`), &m)
	if _, err := CompileMappingV2("t", m); err == nil {
		t.Fatal("a non-object subject must be rejected")
	}
}

func TestV2NonStringResolvedSubjectFailsClosed(t *testing.T) {
	// subject.id anchored but resolving to a non-string: must not be compared loosely.
	cm := mustMappingV2(t, "t", `{"evaluation": {
	  "subject":  {"type": "identity", "id": "$token.sub"},
	  "action":   {"name": "t"},
	  "resource": {"type": "r", "id": "x"}}}`)
	if _, err := cm.Build(map[string]any{}, map[string]any{"sub": 12345}, nil); err == nil {
		t.Fatal("a non-string subject claim must not satisfy the anchor")
	}
}

func TestDiscoveryCacheEvictsAndThenRefuses(t *testing.T) {
	d := newDiscoveryCache(time.Hour, nil)
	d.maxEntries = 2
	now := time.Now()
	d.entries["a"] = &discoveryEntry{fetchedAt: now}
	d.entries["b"] = &discoveryEntry{fetchedAt: now}

	if d.evictLocked(now) {
		t.Fatal("a full cache of live entries must refuse to grow")
	}
	// Once they age past the TTL they are reclaimed.
	if !d.evictLocked(now.Add(2 * time.Hour)) {
		t.Fatal("expired entries should be evicted to make room")
	}
	if len(d.entries) != 0 {
		t.Fatalf("expired entries should be gone, %d remain", len(d.entries))
	}
}

func TestCacheKeySeparatesCallers(t *testing.T) {
	// The leak this prevents: one caller's tools view served to another for the TTL.
	a := cacheKey("http://mcp", "Bearer alice")
	b := cacheKey("http://mcp", "Bearer bob")
	if a == b {
		t.Fatal("different credentials must not share a cache entry")
	}
	if cacheKey("http://mcp", "Bearer alice") != a {
		t.Fatal("the key must be stable for the same caller")
	}
	if strings.Contains(a, "alice") {
		t.Fatalf("the credential must be hashed, not stored: %q", a)
	}
}

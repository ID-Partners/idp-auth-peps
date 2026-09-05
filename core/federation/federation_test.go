package federation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ctx() context.Context { return context.Background() }

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("no anchors must fail")
	}
	if _, err := New(Options{TrustAnchors: []TrustAnchor{{EntityID: "https://a"}}}); err == nil {
		t.Fatal("anchor without keys must fail")
	}
	k := []map[string]any{{"kid": "x"}}
	if _, err := New(Options{TrustAnchors: []TrustAnchor{{EntityID: "https://a", Keys: k}, {EntityID: "https://a", Keys: k}}}); err == nil {
		t.Fatal("duplicate anchor must fail")
	}
	r, err := New(Options{TrustAnchors: []TrustAnchor{{EntityID: "https://a", Keys: k}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.opts.Leeway != 60*time.Second || r.opts.MaxPathLength != 4 || r.opts.MaxFetches != 16 || r.opts.TTL != 5*time.Minute || r.opts.NegativeTTL != 60*time.Second || r.opts.HTTPClient == nil || r.opts.Now == nil {
		t.Fatalf("defaults: %+v", r.opts)
	}
}

func TestThreeLevelHappyPath(t *testing.T) {
	f := threeLevel(t)
	r := newResolver(t, Options{}, f.anchor)
	res, err := r.Resolve(ctx(), f.leaf.id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject != f.leaf.id || res.TrustAnchor != f.anchor.id || len(res.Chain) != 4 {
		t.Fatalf("resolved %+v", res)
	}
	if got := pdps(res); !reflect.DeepEqual(got, []any{"https://pdp.good.example", "https://pdp.rogue.example"}) {
		t.Fatalf("no policy should leave the list intact: %v", got)
	}
	// min(exp): the subordinate statements expire in 1800s, the configurations in 3600s.
	if until := time.Until(res.ExpiresAt); until > 1801*time.Second || until < 1700*time.Second {
		t.Fatalf("ExpiresAt should be the chain's min(exp): %v", until)
	}
	// Cached: a second resolve makes no requests.
	before := atomic.LoadInt32(&f.leaf.hits) + atomic.LoadInt32(&f.mid.hits) + atomic.LoadInt32(&f.anchor.hits)
	if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
		t.Fatal(err)
	}
	after := atomic.LoadInt32(&f.leaf.hits) + atomic.LoadInt32(&f.mid.hits) + atomic.LoadInt32(&f.anchor.hits)
	if before != after {
		t.Fatalf("second resolve should be served from cache: %d -> %d", before, after)
	}
	if st := r.Status()[f.leaf.id]; !st.Cached {
		t.Fatalf("status %+v", st)
	}
}

func TestTwoLevelAndPolicyApplication(t *testing.T) {
	anchor, leaf := newEntity(t), newEntity(t)
	leaf.metadata["oauth_resource"] = map[string]any{
		"authzen_policy_decision_points": []any{"https://pdp.good.example", "https://pdp.rogue.example"},
		"scopes_supported":               []any{"read"},
	}
	anchor.subordinate(leaf, &subordinate{policy: map[string]any{
		"oauth_resource": map[string]any{
			"authzen_policy_decision_points":             map[string]any{"subset_of": []any{"https://pdp.good.example", "https://pdp.shared.example"}, "essential": true},
			"scopes_supported":                           map[string]any{"add": []any{"write"}, "superset_of": []any{"read"}},
			"resource":                                   map[string]any{"default": leaf.id},
			"bearer_methods_supported":                   map[string]any{"value": []any{"header"}},
			"tls_client_certificate_bound_access_tokens": map[string]any{"value": nil},
		},
	}})
	r := newResolver(t, Options{}, anchor)
	res, err := r.Resolve(ctx(), leaf.id)
	if err != nil {
		t.Fatal(err)
	}
	got := res.Metadata["oauth_resource"]
	if !reflect.DeepEqual(got["authzen_policy_decision_points"], []any{"https://pdp.good.example"}) {
		t.Fatalf("subset_of should strip the rogue PDP: %v", got)
	}
	if !reflect.DeepEqual(got["scopes_supported"], []any{"read", "write"}) || got["resource"] != leaf.id || !reflect.DeepEqual(got["bearer_methods_supported"], []any{"header"}) {
		t.Fatalf("add/default/value: %v", got)
	}
	if _, present := got["tls_client_certificate_bound_access_tokens"]; present {
		t.Fatal("value null should remove the parameter")
	}
	if len(res.Chain) != 3 {
		t.Fatalf("two-level chain has 3 statements, got %d", len(res.Chain))
	}
}

func TestSuperiorMetadataOverlayAppliedBeforePolicy(t *testing.T) {
	f := threeLevel(t)
	f.mid.subs[f.leaf.id].metadata = map[string]any{"oauth_resource": map[string]any{"authzen_policy_decision_points": []any{"https://pdp.mid.example"}}}
	f.anchor.subs[f.mid.id].policy = map[string]any{"oauth_resource": map[string]any{"authzen_policy_decision_points": map[string]any{"subset_of": []any{"https://pdp.mid.example", "https://pdp.good.example"}}}}
	r := newResolver(t, Options{}, f.anchor)
	res, err := r.Resolve(ctx(), f.leaf.id)
	if err != nil {
		t.Fatal(err)
	}
	if got := pdps(res); !reflect.DeepEqual(got, []any{"https://pdp.mid.example"}) {
		t.Fatalf("superior's metadata should replace the leaf's before policy: %v", got)
	}
}

func TestPolicyMergedTopDownAndHierarchy(t *testing.T) {
	f := threeLevel(t)
	f.anchor.subs[f.mid.id].policy = map[string]any{"oauth_resource": map[string]any{"authzen_policy_decision_points": map[string]any{"subset_of": []any{"https://pdp.good.example"}}}}
	// The intermediate tries to widen what the anchor allowed: intersection wins.
	f.mid.subs[f.leaf.id].policy = map[string]any{"oauth_resource": map[string]any{"authzen_policy_decision_points": map[string]any{"subset_of": []any{"https://pdp.good.example", "https://pdp.rogue.example"}}}}
	r := newResolver(t, Options{}, f.anchor)
	res, err := r.Resolve(ctx(), f.leaf.id)
	if err != nil {
		t.Fatal(err)
	}
	if got := pdps(res); !reflect.DeepEqual(got, []any{"https://pdp.good.example"}) {
		t.Fatalf("hierarchy: %v", got)
	}
}

func TestPolicyViolationsInvalidateTheChain(t *testing.T) {
	cases := map[string]struct {
		anchorPolicy, midPolicy map[string]any
		want                    string
	}{
		"essential absent": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"jwks_uri": map[string]any{"essential": true}}},
			want:         "essential but absent",
		},
		"value conflict between levels": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"value": "a"}}},
			midPolicy:    map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"value": "b"}}},
			want:         "conflicts",
		},
		"one_of empty intersection": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"one_of": []any{"a"}}}},
			midPolicy:    map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"one_of": []any{"b"}}}},
			want:         "one_of intersection is empty",
		},
		"one_of violated": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"one_of": []any{"a"}}}},
			want:         "is not one of",
		},
		"superset_of violated": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"authzen_policy_decision_points": map[string]any{"superset_of": []any{"https://pdp.other.example"}}}},
			want:         "does not contain",
		},
		"subset_of on a scalar": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"subset_of": []any{"a"}}}},
			want:         "applies to arrays",
		},
		"add on a scalar": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"add": []any{"a"}}}},
			want:         "applies to arrays",
		},
		"merged combination invalid": {
			anchorPolicy: map[string]any{"oauth_resource": map[string]any{"scopes_supported": map[string]any{"subset_of": []any{"a"}}}},
			midPolicy:    map[string]any{"oauth_resource": map[string]any{"scopes_supported": map[string]any{"superset_of": []any{"b"}}}},
			want:         "not a superset of superset_of",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := threeLevel(t)
			f.anchor.subs[f.mid.id].policy = tc.anchorPolicy
			f.mid.subs[f.leaf.id].policy = tc.midPolicy
			r := newResolver(t, Options{}, f.anchor)
			_, err := r.Resolve(ctx(), f.leaf.id)
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("want ErrInvalidChain, got %v", err)
			}
			mustContain(t, err, tc.want)
		})
	}
}

func TestUnknownOperatorIgnoredUnlessCritical(t *testing.T) {
	f := threeLevel(t)
	f.anchor.subs[f.mid.id].policy = map[string]any{"oauth_resource": map[string]any{"resource": map[string]any{"regexp": "^https"}}}
	r := newResolver(t, Options{}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
		t.Fatalf("unknown non-critical operator should be ignored: %v", err)
	}
	f.anchor.subs[f.mid.id].policyCrit = []any{"regexp"}
	r = newResolver(t, Options{}, f.anchor)
	_, err := r.Resolve(ctx(), f.leaf.id)
	mustContain(t, err, "does not implement")
}

func TestConstraints(t *testing.T) {
	t.Run("max_path_length exceeded", func(t *testing.T) {
		f := threeLevel(t)
		zero := 0.0
		f.anchor.subs[f.mid.id].constraints = map[string]any{"max_path_length": zero}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "intermediates below")
	})
	t.Run("max_path_length satisfied", func(t *testing.T) {
		f := threeLevel(t)
		f.anchor.subs[f.mid.id].constraints = map[string]any{"max_path_length": 1.0}
		f.mid.subs[f.leaf.id].constraints = map[string]any{"max_path_length": 0.0}
		r := newResolver(t, Options{}, f.anchor)
		if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("naming permitted", func(t *testing.T) {
		f := threeLevel(t)
		f.anchor.subs[f.mid.id].constraints = map[string]any{"naming_constraints": map[string]any{"permitted": []any{"https://only.example"}}}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "outside the naming constraints")
	})
	t.Run("naming excluded", func(t *testing.T) {
		f := threeLevel(t)
		f.anchor.subs[f.mid.id].constraints = map[string]any{"naming_constraints": map[string]any{"permitted": []any{"http://127.0.0.1"}, "excluded": []any{f.leaf.id}}}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "excluded")
	})
	t.Run("allowed_entity_types", func(t *testing.T) {
		f := threeLevel(t)
		f.anchor.subs[f.mid.id].constraints = map[string]any{"allowed_entity_types": []any{"openid_relying_party"}}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "does not allow")
		f.anchor.subs[f.mid.id].constraints = map[string]any{"allowed_entity_types": []any{"oauth_resource"}}
		r = newResolver(t, Options{}, f.anchor)
		if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStatementValidationFailures(t *testing.T) {
	type mut = func(hdr, claims map[string]any)
	cases := map[string]struct {
		leafEC mut
		midSS  func(sub string, hdr, claims map[string]any)
		want   string
	}{
		"wrong typ":       {leafEC: func(h, c map[string]any) { h["typ"] = "JWT" }, want: "typ is"},
		"alg none":        {leafEC: func(h, c map[string]any) { h["alg"] = "none" }, want: "alg"},
		"missing kid":     {leafEC: func(h, c map[string]any) { delete(h, "kid") }, want: "kid header missing"},
		"unknown kid":     {leafEC: func(h, c map[string]any) { h["kid"] = "nope" }, want: "not among"},
		"expired":         {leafEC: func(h, c map[string]any) { c["exp"] = float64(time.Now().Unix() - 3600) }, want: "expired"},
		"iat future":      {leafEC: func(h, c map[string]any) { c["iat"] = float64(time.Now().Unix() + 3600) }, want: "future"},
		"missing iat":     {leafEC: func(h, c map[string]any) { delete(c, "iat") }, want: "iat missing"},
		"missing exp":     {leafEC: func(h, c map[string]any) { delete(c, "exp") }, want: "exp missing"},
		"bad iss":         {leafEC: func(h, c map[string]any) { c["iss"] = "not a url" }, want: "not a valid entity identifier"},
		"missing jwks":    {leafEC: func(h, c map[string]any) { delete(c, "jwks") }, want: "jwks"},
		"empty jwks":      {leafEC: func(h, c map[string]any) { c["jwks"] = map[string]any{"keys": []any{}} }, want: "no keys"},
		"key without kid": {leafEC: func(h, c map[string]any) { c["jwks"] = map[string]any{"keys": []any{map[string]any{"kty": "EC"}}} }, want: "needs a kid"},
		"non-object key":  {leafEC: func(h, c map[string]any) { c["jwks"] = map[string]any{"keys": []any{"x"}} }, want: "non-object"},
		"duplicate kid": {leafEC: func(h, c map[string]any) {
			k := c["jwks"].(map[string]any)["keys"].([]any)[0]
			c["jwks"] = map[string]any{"keys": []any{k, k}}
		}, want: "duplicate kid"},
		"crit":             {leafEC: func(h, c map[string]any) { c["crit"] = []any{"x"} }, want: "crit"},
		"empty crit":       {leafEC: func(h, c map[string]any) { c["crit"] = []any{} }, want: "crit"},
		"null in metadata": {leafEC: func(h, c map[string]any) { c["metadata"] = map[string]any{"oauth_resource": map[string]any{"a": nil}} }, want: "null"},
		"null nested in array": {leafEC: func(h, c map[string]any) {
			c["metadata"] = map[string]any{"oauth_resource": map[string]any{"a": []any{nil}}}
		}, want: "null"},
		"metadata not object":      {leafEC: func(h, c map[string]any) { c["metadata"] = "x" }, want: "not an object"},
		"metadata type not obj":    {leafEC: func(h, c map[string]any) { c["metadata"] = map[string]any{"oauth_resource": 1} }, want: "not an object"},
		"policy in EC":             {leafEC: func(h, c map[string]any) { c["metadata_policy"] = map[string]any{} }, want: "not permitted in an entity configuration"},
		"empty authority_hints":    {leafEC: func(h, c map[string]any) { c["authority_hints"] = []any{} }, want: "must not be empty"},
		"hints not array":          {leafEC: func(h, c map[string]any) { c["authority_hints"] = "x" }, want: "not an array"},
		"hints non-string":         {leafEC: func(h, c map[string]any) { c["authority_hints"] = []any{1} }, want: "non-string"},
		"hint invalid":             {leafEC: func(h, c map[string]any) { c["authority_hints"] = []any{"nope"} }, want: "not a valid entity identifier"},
		"empty trust_anchor_hints": {leafEC: func(h, c map[string]any) { c["trust_anchor_hints"] = []any{} }, want: "must not be empty"},
		"bad trust_anchor_hints":   {leafEC: func(h, c map[string]any) { c["trust_anchor_hints"] = "x" }, want: "not an array"},
		"trust_chain header":       {leafEC: func(h, c map[string]any) { h["trust_chain"] = []any{} }, want: "trust_chain"},
		"EC about someone else":    {leafEC: func(h, c map[string]any) { c["sub"] = "https://other.example"; c["iss"] = "https://other.example" }, want: "is about"},
		"SS with hints":            {midSS: func(s string, h, c map[string]any) { c["authority_hints"] = []any{"https://x.example"} }, want: "not permitted in a subordinate statement"},
		"SS wrong sub":             {midSS: func(s string, h, c map[string]any) { c["sub"] = "https://other.example" }, want: "returned a statement about"},
		"SS empty policy_crit":     {midSS: func(s string, h, c map[string]any) { c["metadata_policy_crit"] = []any{} }, want: "must not be empty"},
		"SS bad policy_crit":       {midSS: func(s string, h, c map[string]any) { c["metadata_policy_crit"] = "x" }, want: "not an array"},
		"SS policy not object":     {midSS: func(s string, h, c map[string]any) { c["metadata_policy"] = "x" }, want: "not an object"},
		"SS policy type not obj":   {midSS: func(s string, h, c map[string]any) { c["metadata_policy"] = map[string]any{"oauth_resource": 1} }, want: "not an object"},
		"SS policy param not obj": {midSS: func(s string, h, c map[string]any) {
			c["metadata_policy"] = map[string]any{"oauth_resource": map[string]any{"x": 1}}
		}, want: "not an object"},
		"SS policy bad operator value": {midSS: func(s string, h, c map[string]any) {
			c["metadata_policy"] = map[string]any{"oauth_resource": map[string]any{"x": map[string]any{"add": "notarray"}}}
		}, want: "must be an array"},
		"SS constraints not object": {midSS: func(s string, h, c map[string]any) { c["constraints"] = "x" }, want: "not an object"},
		"SS bad max_path_length":    {midSS: func(s string, h, c map[string]any) { c["constraints"] = map[string]any{"max_path_length": -1.0} }, want: "non-negative"},
		"SS bad naming":             {midSS: func(s string, h, c map[string]any) { c["constraints"] = map[string]any{"naming_constraints": "x"} }, want: "not an object"},
		"SS bad permitted": {midSS: func(s string, h, c map[string]any) {
			c["constraints"] = map[string]any{"naming_constraints": map[string]any{"permitted": "x"}}
		}, want: "not an array"},
		"SS bad excluded": {midSS: func(s string, h, c map[string]any) {
			c["constraints"] = map[string]any{"naming_constraints": map[string]any{"excluded": "x"}}
		}, want: "not an array"},
		"SS bad allowed types":   {midSS: func(s string, h, c map[string]any) { c["constraints"] = map[string]any{"allowed_entity_types": "x"} }, want: "not an array"},
		"SS bad source_endpoint": {midSS: func(s string, h, c map[string]any) { c["source_endpoint"] = "nope" }, want: "source_endpoint"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := threeLevel(t)
			f.leaf.ecHook = tc.leafEC
			f.mid.ssHook = tc.midSS
			r := newResolver(t, Options{}, f.anchor)
			_, err := r.Resolve(ctx(), f.leaf.id)
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("want ErrInvalidChain, got %v", err)
			}
			mustContain(t, err, tc.want)
		})
	}
	t.Run("valid source_endpoint is accepted", func(t *testing.T) {
		f := threeLevel(t)
		f.mid.ssHook = func(s string, h, c map[string]any) { c["source_endpoint"] = f.mid.id + "/fetch" }
		r := newResolver(t, Options{}, f.anchor)
		if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSignatureBindings(t *testing.T) {
	t.Run("anchor EC signed by a key we did not configure", func(t *testing.T) {
		f := threeLevel(t)
		impostor := newEntity(t)
		r := newResolver(t, Options{TrustAnchors: []TrustAnchor{{EntityID: f.anchor.id, Keys: []map[string]any{impostor.jwk}}}})
		_, err := r.Resolve(ctx(), f.leaf.id)
		if !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("want ErrInvalidChain, got %v", err)
		}
		mustContain(t, err, "not among the issuer's federation keys")
	})
	t.Run("leaf EC not signed by the key its superior asserts", func(t *testing.T) {
		f := threeLevel(t)
		other := newEntity(t)
		f.leaf.signWith = other.key
		f.leaf.ecHook = func(h, c map[string]any) {
			h["kid"] = other.jwk["kid"]
			c["jwks"] = map[string]any{"keys": []any{other.jwk}}
		}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "does not verify against")
	})
	t.Run("SS signed with a key not in the superior's EC", func(t *testing.T) {
		f := threeLevel(t)
		other := newEntity(t)
		f.mid.ssHook = func(s string, h, c map[string]any) { h["kid"] = other.jwk["kid"] }
		f.mid.ssSign = other.key
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "subordinate statement about")
	})
	t.Run("tampered signature", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.ecHook = func(h, c map[string]any) { c["extra"] = "x" }
		// Sign with a different key but claim the real kid: kid matches, signature fails.
		other := newEntity(t)
		f.leaf.signWith = other.key
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "does not verify")
	})
}

func TestTopology(t *testing.T) {
	t.Run("not federated", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.ecStatus = 404
		r := newResolver(t, Options{}, f.anchor)
		if _, err := r.Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrNotFederated) {
			t.Fatalf("want ErrNotFederated, got %v", err)
		}
	})
	t.Run("leaf server error is transient", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.ecStatus = 500
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		if err == nil || errors.Is(err, ErrInvalidChain) || errors.Is(err, ErrNotFederated) {
			t.Fatalf("want a transient error, got %v", err)
		}
	})
	t.Run("leaf body not a JWS", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.ecBody = "garbage"
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "not a compact JWS")
	})
	t.Run("subject is an anchor", func(t *testing.T) {
		f := threeLevel(t)
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.anchor.id)
		mustContain(t, err, "is a trust anchor")
	})
	t.Run("no authority hints", func(t *testing.T) {
		lonely := newEntity(t)
		anchor := newEntity(t)
		r := newResolver(t, Options{}, anchor)
		_, err := r.Resolve(ctx(), lonely.id)
		mustContain(t, err, "no authority_hints")
	})
	t.Run("hint dead-ends without an anchor", func(t *testing.T) {
		leaf, mid := newEntity(t), newEntity(t)
		mid.subordinate(leaf, nil)
		anchor := newEntity(t) // configured but nobody points at it
		r := newResolver(t, Options{}, anchor)
		_, err := r.Resolve(ctx(), leaf.id)
		mustContain(t, err, "reaches a configured trust anchor")
	})
	t.Run("cycle", func(t *testing.T) {
		leaf, mid := newEntity(t), newEntity(t)
		mid.subordinate(leaf, nil)
		leaf.subordinate(mid, nil) // mid hints back at leaf
		anchor := newEntity(t)
		r := newResolver(t, Options{}, anchor)
		_, err := r.Resolve(ctx(), leaf.id)
		if !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("want ErrInvalidChain, got %v", err)
		}
	})
	t.Run("path length", func(t *testing.T) {
		f := threeLevel(t)
		r := newResolver(t, Options{MaxPathLength: 1}, f.anchor)
		if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
			t.Fatalf("one intermediate within a limit of 1: %v", err)
		}
		deeper := newEntity(t)
		deeper.subordinate(f.leaf, nil)
		f.anchor.subordinate(deeper, nil)
		// leaf -> deeper -> anchor is also depth 1, so we need a longer path only.
		leaf2, i1, i2 := newEntity(t), newEntity(t), newEntity(t)
		i1.subordinate(leaf2, nil)
		i2.subordinate(i1, nil)
		f.anchor.subordinate(i2, nil)
		_, err := r.Resolve(ctx(), leaf2.id)
		mustContain(t, err, "max path length")
	})
	t.Run("fetch budget", func(t *testing.T) {
		f := threeLevel(t)
		r := newResolver(t, Options{MaxFetches: 2}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "budget")
	})
	t.Run("superior without fetch endpoint", func(t *testing.T) {
		f := threeLevel(t)
		f.mid.ecHook = func(h, c map[string]any) { delete(c, "metadata") }
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "federation_fetch_endpoint")
	})
	t.Run("superior fetch endpoint not a URL", func(t *testing.T) {
		f := threeLevel(t)
		f.mid.ecHook = func(h, c map[string]any) {
			c["metadata"] = map[string]any{entityTypeFedEnt: map[string]any{"federation_fetch_endpoint": "nope#frag"}}
		}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "not a URL")
	})
	t.Run("superior 404s the subordinate", func(t *testing.T) {
		f := threeLevel(t)
		delete(f.mid.subs, f.leaf.id)
		f.mid.ecHook = func(h, c map[string]any) {
			c["metadata"] = map[string]any{entityTypeFedEnt: map[string]any{"federation_fetch_endpoint": f.mid.id + "/fetch"}}
		}
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "no trust chain")
	})
	t.Run("superior EC unreachable", func(t *testing.T) {
		f := threeLevel(t)
		f.mid.ecStatus = 500
		r := newResolver(t, Options{}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		mustContain(t, err, "no trust chain")
	})
	t.Run("two anchors, first configured wins", func(t *testing.T) {
		f := threeLevel(t)
		second := newEntity(t)
		second.subordinate(f.mid, &subordinate{policy: map[string]any{"oauth_resource": map[string]any{"authzen_policy_decision_points": map[string]any{"value": []any{"https://pdp.second.example"}}}}})
		// mid now hints [anchor, second]; the resolver's order decides.
		r := newResolver(t, Options{}, second, f.anchor)
		res, err := r.Resolve(ctx(), f.leaf.id)
		if err != nil {
			t.Fatal(err)
		}
		if res.TrustAnchor != second.id || !reflect.DeepEqual(pdps(res), []any{"https://pdp.second.example"}) {
			t.Fatalf("expected the first configured anchor: %s %v", res.TrustAnchor, pdps(res))
		}
		r = newResolver(t, Options{}, f.anchor, second)
		res, err = r.Resolve(ctx(), f.leaf.id)
		if err != nil || res.TrustAnchor != f.anchor.id {
			t.Fatalf("order flipped: %v %s", err, res.TrustAnchor)
		}
	})
	t.Run("only the second configured anchor is reachable", func(t *testing.T) {
		f := threeLevel(t)
		unreachable := newEntity(t)
		r := newResolver(t, Options{}, unreachable, f.anchor)
		res, err := r.Resolve(ctx(), f.leaf.id)
		if err != nil || res.TrustAnchor != f.anchor.id {
			t.Fatalf("%v %s", err, res.TrustAnchor)
		}
	})
	t.Run("hint visited twice is skipped", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.hints = append(f.leaf.hints, f.mid.id)
		r := newResolver(t, Options{}, f.anchor)
		if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFetchPolicy(t *testing.T) {
	f := threeLevel(t)
	r := newResolver(t, Options{FetchAllowed: func(u string) bool { return !strings.HasPrefix(u, f.anchor.id) }}, f.anchor)
	_, err := r.Resolve(ctx(), f.leaf.id)
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a refused fetch must surface as ErrNotAllowed: %v", err)
	}
	r = newResolver(t, Options{FetchAllowed: func(u string) bool { return !strings.HasPrefix(u, f.leaf.id) }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("leaf refused: %v", err)
	}
	r = newResolver(t, Options{FetchAllowed: func(u string) bool { return !strings.Contains(u, "/fetch?") }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("fetch endpoint refused: %v", err)
	}
	// Without AllowInsecure the http fixtures are refused outright.
	strict, err := New(Options{TrustAnchors: []TrustAnchor{f.anchor.anchor()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("http should be refused: %v", err)
	}
}

func TestStaleServedWhileRefreshFails(t *testing.T) {
	f := threeLevel(t)
	now := time.Now()
	r := newResolver(t, Options{TTL: time.Minute, Now: func() time.Time { return now }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
		t.Fatal(err)
	}
	f.mid.ecStatus = 500
	now = now.Add(2 * time.Minute)
	res, err := r.Resolve(ctx(), f.leaf.id)
	if err != nil || res.TrustAnchor != f.anchor.id {
		t.Fatalf("stale chain should be served: %v", err)
	}
}

func TestNegativeCache(t *testing.T) {
	f := threeLevel(t)
	f.leaf.ecStatus = 404
	r := newResolver(t, Options{}, f.anchor)
	r.Resolve(ctx(), f.leaf.id)
	r.Resolve(ctx(), f.leaf.id)
	if atomic.LoadInt32(&f.leaf.hits) != 1 {
		t.Fatalf("ErrNotFederated should be negatively cached: %d hits", f.leaf.hits)
	}
}

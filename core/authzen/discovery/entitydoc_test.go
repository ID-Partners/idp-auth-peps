package discovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/federation"
	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// P5: the PEP's federation entity served signed_metadata and no jwks_uri, so this
// package's own RFC9728Source refused the document ("signed_metadata but no jwks_uri")
// and a resource-mode PEP in front of it fell back to its static PDP. The entity now
// publishes the key set that verifies it.
func TestAResourceModePEPReadsTheEntitysDocument(t *testing.T) {
	key, err := jose.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &federation.Entity{Key: key, Asserted: map[string]any{ParamPolicyDecisionPoints: []any{"https://pdp.example"}}}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	e.ID = srv.URL
	fedPath, resPath := e.Paths()
	for _, p := range []string{fedPath, resPath, e.JWKSPath()} {
		mux.Handle(p, e.Handler())
	}
	src := &RFC9728Source{fetch: metafetch.New(nil, metafetch.Policy{AllowInsecure: true}, "", 0)}
	meta, err := src.Lookup(ctx(), srv.URL)
	if err != nil {
		t.Fatalf("the entity's own document must be readable by a resource-mode PEP: %v", err)
	}
	if len(meta.PDPs) != 1 || meta.PDPs[0] != "https://pdp.example" || meta.Document["metadata_source"] != "self" {
		t.Fatalf("%+v", meta)
	}
	if meta.ExpiresAt.IsZero() || meta.ExpiresAt.Before(time.Now()) {
		t.Fatalf("the signed exp travels as the document's expiry: %v", meta.ExpiresAt)
	}
	// And through a resource-mode chain, as a PEP in front of the entity reads it: the
	// document's PDP decides, not the static one.
	pdp := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	e.Asserted = map[string]any{ParamPolicyDecisionPoints: []any{pdp.URL}}
	c := mustNew(t, Options{Mode: ModeResource, StaticPDP: static.URL})
	ep, err := c.Resolve(ctx(), srv.URL)
	if err != nil || ep.Identifier != pdp.URL || ep.Resource == nil || ep.Resource.Document["metadata_source"] != "self" {
		t.Fatalf("%+v %v", ep, err)
	}
}

// signed_metadata's own validity: exp, nbf and typ were ignored, so a signed document
// stayed good forever and any JWT the resource's key had signed could stand in for one.
func TestSignedMetadataTimeAndTypeClaims(t *testing.T) {
	now := time.Now().Unix()
	cases := map[string]struct {
		mutate func(self string, doc, claims map[string]any)
		want   string
	}{
		"expired":              {func(_ string, _, c map[string]any) { c["exp"] = now - 3600 }, "expired"},
		"not yet valid":        {func(_ string, _, c map[string]any) { c["nbf"] = now + 3600 }, "not yet valid"},
		"exp not a number":     {func(_ string, _, c map[string]any) { c["exp"] = "soon" }, "exp"},
		"typ of another JWT":   {func(_ string, _, c map[string]any) { c["__typ"] = "entity-statement+jwt" }, "typ"},
		"typ of an access JWT": {func(_ string, _, c map[string]any) { c["__typ"] = "at+jwt" }, "typ"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSignedResource(t, c.mutate)
			if _, err := lookupSigned(t, s); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
	for _, typ := range []string{"JWT", "jwt", "application/jwt"} {
		s := newSignedResource(t, func(_ string, _, c map[string]any) { c["__typ"] = typ; c["exp"] = now + 600 })
		meta, err := lookupSigned(t, s)
		if err != nil {
			t.Fatalf("typ %q is a plain JWT: %v", typ, err)
		}
		if meta.ExpiresAt.Unix() != now+600 {
			t.Fatalf("exp must travel as the document's expiry: %v", meta.ExpiresAt)
		}
	}
}

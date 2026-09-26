package federation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// P4: signed_metadata started as {iss, iat} and then every resolved parameter was
// copied over it, so a superior — through Subordinate Statement metadata or a policy
// value — could set iss, sub, aud, exp or jti, and the PEP signed the result with its
// federation key and served it publicly: a well-formed private_key_jwt-style assertion
// on demand, valid forever.
func TestSignedMetadataCarriesOnlyMetadata(t *testing.T) {
	anchor := newEntity(t)
	e, _ := newHeldEntity(t, anchor)
	// The entity mints its configuration on this clock too, and the resolver checks it
	// against the wall clock: keep them together.
	now := time.Now().Truncate(time.Second)
	e.Now = func() time.Time { return now }
	pub, _ := e.PublicJWK()
	anchor.subs[e.ID] = &subordinate{
		keys: []map[string]any{pub},
		metadata: map[string]any{EntityTypeResource: map[string]any{
			param: []any{"https://pdp.controller.example"},
			"iss": "https://as.example", "sub": "client-1", "jti": "j-1", "exp": 4_000_000_000.0,
			"nbf": 1.0, "iat": 1.0, "cnf": map[string]any{"jkt": "x"}, "client_id": "client-1", "scope": "payments:write",
		}},
		policy: map[string]any{EntityTypeResource: map[string]any{"aud": map[string]any{"value": "https://as.example/token"}}},
	}
	doc, source, err := e.ProtectedResourceMetadata(ctx())
	if err != nil || source != "federation" {
		t.Fatalf("%v %s %v", doc, source, err)
	}
	signed, _ := doc["signed_metadata"].(string)
	if err := jose.VerifyJWS(signed, pub, "ES256"); err != nil {
		t.Fatal(err)
	}
	claims := jose.Claims(signed)
	for _, name := range []string{"sub", "aud", "jti", "nbf", "cnf", "client_id", "scope"} {
		if _, present := claims[name]; present {
			t.Errorf("signed_metadata must not carry %q from a superior: %v", name, claims[name])
		}
		if _, present := doc[name]; present {
			t.Errorf("the document must not carry %q either", name)
		}
	}
	if claims["iss"] != e.ID || claims["iat"] != float64(now.Unix()) {
		t.Errorf("iss and iat are the entity's own: %v %v", claims["iss"], claims["iat"])
	}
	exp, _ := claims["exp"].(float64)
	if exp <= float64(now.Unix()) || exp > float64(now.Add(time.Hour).Unix()) {
		t.Errorf("exp must be the entity's, and short: %v", claims["exp"])
	}
	// Whose word it is travels inside the signature, not only in a header.
	if claims["metadata_source"] != "federation" || doc["metadata_source"] != "federation" {
		t.Errorf("the source must be signed: %v", claims["metadata_source"])
	}
	if pd, _ := claims[param].([]any); len(pd) != 1 || pd[0] != "https://pdp.controller.example" {
		t.Errorf("the metadata itself is still signed: %v", claims)
	}
}

// The self-asserted document says so inside its signature, and its lifetime is capped
// like the federation's.
func TestSelfAssertedMetadataIsMarkedAndDated(t *testing.T) {
	e, _ := newHeldEntity(t, nil)
	now := time.Unix(1_800_000_000, 0)
	e.Now = func() time.Time { return now }
	e.MetadataLifetime = time.Minute
	doc, source, err := e.ProtectedResourceMetadata(ctx())
	if err != nil || source != "self" {
		t.Fatal(err)
	}
	c := jose.Claims(doc["signed_metadata"].(string))
	if c["metadata_source"] != "self" || c["exp"] != float64(now.Add(time.Minute).Unix()) {
		t.Fatalf("%v", c)
	}
}

// P5: the document always carried signed_metadata but never a jwks_uri, so the repo's
// own resource-mode PEP rejected it and fell back to its static PDP. The entity now
// publishes the key set that verifies it, and advertises where.
func TestTheEntityPublishesTheKeysItsDocumentIsSignedWith(t *testing.T) {
	e, srv := newHeldEntity(t, nil)
	jwksPath := e.JWKSPath()
	_, resPath := e.Paths()
	if jwksPath != resPath+"/jwks.json" {
		t.Fatalf("the key set sits beside the RFC 9728 document: %s", jwksPath)
	}
	doc, _, err := e.ProtectedResourceMetadata(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if doc["jwks_uri"] != srv.URL+jwksPath || e.JWKSURL() != srv.URL+jwksPath {
		t.Fatalf("jwks_uri: %v", doc["jwks_uri"])
	}
	resp, body := get(t, srv.URL+jwksPath)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	keys, err := jose.ParseJWKSet([]byte(body))
	if err != nil || len(keys) != 1 {
		t.Fatalf("%v %v", keys, err)
	}
	pub, _ := e.PublicJWK()
	if keys[0]["kid"] != pub["kid"] || keys[0]["alg"] != "ES256" || keys[0]["use"] != "sig" {
		t.Fatalf("the published key is the entity's signing key: %v", keys[0])
	}
	if err := jose.VerifyJWS(doc["signed_metadata"].(string), keys[0], "ES256"); err != nil {
		t.Fatalf("signed_metadata verifies against the published set: %v", err)
	}
	raw, _ := e.JWKS()
	var set map[string]any
	if json.Unmarshal(raw, &set) != nil || set["keys"] == nil {
		t.Fatalf("%s", raw)
	}
	// A key the JOSE layer cannot use is an error there too, and a 500 on the wire.
	bad := &Entity{ID: "https://x.example"}
	if _, err := bad.JWKS(); err == nil {
		t.Fatal("no key, no key set")
	}
	rec := httptest.NewRecorder()
	bad.Handler().ServeHTTP(rec, httptest.NewRequest("GET", bad.JWKSPath(), nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("%d", rec.Code)
	}
	if bad.String() != "federation entity https://x.example" {
		t.Fatal(bad.String())
	}
	if (&Entity{ID: "::"}).JWKSURL() != "" {
		t.Fatal("an unparseable identifier has no key set URL")
	}
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mintJWT signs a compact JWT with key, optionally naming a kid.
func mintJWT(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr := map[string]any{"alg": "ES256", "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := enc(hdr) + "." + enc(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer serves a JWKS containing key under kid.
func jwksServer(t *testing.T, key *ecdsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	jwk := publicJWK(key)
	jwk["kid"] = kid
	jwk["use"] = "sig"
	body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(body)
	}))
}

func validClaims() map[string]any {
	return map[string]any{
		"sub": "alice@example.com",
		"iss": "https://as.example.com",
		"aud": "https://api.example.com",
		"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
	}
}

func newTestValidator(t *testing.T, url string) *Validator {
	t.Helper()
	return NewValidator(ValidatorConfig{
		JWKSURL:  url,
		Issuer:   "https://as.example.com",
		Audience: "https://api.example.com",
	})
}

func TestValidatorAcceptsAWellFormedToken(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()

	claims, err := newTestValidator(t, srv.URL).Validate(context.Background(), mintJWT(t, key, "k1", validClaims()))
	if err != nil {
		t.Fatalf("expected the token to validate: %v", err)
	}
	if claims["sub"] != "alice@example.com" {
		t.Fatalf("claims not returned: %v", claims)
	}
}

// The bypass this closes: anyone can mint a token that DECODES to any claims they like.
// Only the signature check stops it.
func TestValidatorRejectsATokenSignedByTheWrongKey(t *testing.T) {
	real := newKey(t)
	attacker := newKey(t)
	srv := jwksServer(t, real, "k1")
	defer srv.Close()

	forged := mintJWT(t, attacker, "k1", map[string]any{
		"sub":   "victim@example.com",
		"iss":   "https://as.example.com",
		"aud":   "https://api.example.com",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"scope": "banking:payments:transfer", // the scope the step-up gate checks
	})
	if _, err := newTestValidator(t, srv.URL).Validate(context.Background(), forged); err == nil {
		t.Fatal("a token signed by an unknown key was accepted")
	}
}

func TestValidatorRejectsBadClaims(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	expired := validClaims()
	expired["exp"] = float64(time.Now().Add(-2 * time.Hour).Unix())

	wrongIss := validClaims()
	wrongIss["iss"] = "https://evil.example.com"

	wrongAud := validClaims()
	wrongAud["aud"] = "https://other.example.com"

	noExp := map[string]any{"sub": "a", "iss": "https://as.example.com", "aud": "https://api.example.com"}

	notYet := validClaims()
	notYet["nbf"] = float64(time.Now().Add(time.Hour).Unix())

	for name, claims := range map[string]map[string]any{
		"expired":       expired,
		"wrong issuer":  wrongIss,
		"wrong aud":     wrongAud,
		"no exp":        noExp,
		"not yet valid": notYet,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), mintJWT(t, key, "k1", claims)); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

// alg:none is the classic: strip the signature and assert whatever you like.
func TestValidatorRejectsAlgNone(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()

	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	unsigned := enc(map[string]any{"alg": "none", "kid": "k1"}) + "." + enc(validClaims()) + "."
	if _, err := newTestValidator(t, srv.URL).Validate(context.Background(), unsigned); err == nil {
		t.Fatal("alg:none was accepted")
	}
}

func TestValidatorRejectsAnUnknownKid(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()

	if _, err := newTestValidator(t, srv.URL).Validate(context.Background(), mintJWT(t, key, "k-unknown", validClaims())); err == nil {
		t.Fatal("a token naming an unknown kid was accepted")
	}
}

func TestValidatorRejectsMalformedTokens(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	for _, tok := range []string{"", "garbage", "a.b", "a.b.c.d"} {
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatalf("malformed token %q was accepted", tok)
		}
	}
}

func TestValidatorFailsWhenTheJWKSIsUnreachable(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	url := srv.URL
	srv.Close() // gone before the first fetch

	if _, err := newTestValidator(t, url).Validate(context.Background(), mintJWT(t, key, "k1", validClaims())); err == nil {
		t.Fatal("validation should fail closed when the JWKS cannot be fetched")
	}
}

// Not configured means not enabled — the caller falls back to decoding and main() warns.
func TestNewValidatorReturnsNilWithoutAJWKSURL(t *testing.T) {
	if NewValidator(ValidatorConfig{Issuer: "https://as.example.com"}) != nil {
		t.Fatal("a validator with no JWKS URL should be nil, so the caller knows it is unconfigured")
	}
}

func TestAudienceContainsHandlesStringAndArray(t *testing.T) {
	if !audienceContains("a", "a") {
		t.Fatal("string aud should match")
	}
	if !audienceContains([]any{"a", "b"}, "b") {
		t.Fatal("array aud should match")
	}
	if audienceContains([]any{"a"}, "b") || audienceContains(nil, "b") || audienceContains(42, "b") {
		t.Fatal("non-matching aud should not match")
	}
}

func TestUserClaimsDropsAForgedTokenWhenConfigured(t *testing.T) {
	real := newKey(t)
	attacker := newKey(t)
	srv := jwksServer(t, real, "k1")
	defer srv.Close()

	s := &server{userValidator: newTestValidator(t, srv.URL)}

	forged := mintJWT(t, attacker, "k1", validClaims())
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": forged}); got != nil {
		t.Fatalf("a forged X-User-Token yielded claims: %v", got)
	}

	genuine := mintJWT(t, real, "k1", validClaims())
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": genuine}); got == nil {
		t.Fatal("a genuine X-User-Token should yield claims")
	}
}

func TestUserClaimsFallsBackToDecodingWhenUnconfigured(t *testing.T) {
	// The pre-existing behaviour, retained so nothing breaks; main() warns about it.
	s := &server{}
	key := newKey(t)
	tok := mintJWT(t, key, "", validClaims())
	got := s.userClaims(context.Background(), map[string]string{"x-user-token": tok})
	if got == nil || got["sub"] != "alice@example.com" {
		t.Fatalf("unconfigured should decode, got %v", got)
	}
	if s.userClaims(context.Background(), map[string]string{}) != nil {
		t.Fatal("no header should yield no claims")
	}
}

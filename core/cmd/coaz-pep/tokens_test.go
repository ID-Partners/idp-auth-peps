package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
	principal := validClaims()["sub"].(string)

	forged := mintJWT(t, attacker, "k1", validClaims())
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": forged}, principal, "access", false); got != nil {
		t.Fatalf("a forged X-User-Token yielded claims: %v", got)
	}

	genuine := mintJWT(t, real, "k1", validClaims())
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": genuine}, principal, "access", false); got == nil {
		t.Fatal("a genuine X-User-Token should yield claims")
	}
}

// A genuine token is still only the user's login if it is THIS principal's: customer B's
// consent must not authorise customer A's payment, and an agent's own delegated token,
// or the access token presented twice, is not a user having logged in.
func TestUserClaimsBelongToThePrincipal(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()
	s := &server{userValidator: newTestValidator(t, srv.URL)}
	principal := validClaims()["sub"].(string)
	user := func(over map[string]any) string {
		c := validClaims()
		for k, v := range over {
			c[k] = v
		}
		return mintJWT(t, key, "k1", c)
	}

	someoneElse := user(map[string]any{"sub": "bob@example.com"})
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": someoneElse}, principal, "access", false); got != nil {
		t.Fatalf("another customer's login must not count for this principal: %v", got)
	}
	delegated := user(map[string]any{"act": map[string]any{"sub": "agent-1"}})
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": delegated}, principal, "access", false); got != nil {
		t.Fatalf("a delegated token is not a user's login: %v", got)
	}
	own := user(nil)
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": own}, principal, own, false); got != nil {
		t.Fatalf("the access token presented as the user token must not count: %v", got)
	}
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": own}, "", "access", false); got != nil {
		t.Fatalf("with no principal there is nobody for the login to belong to: %v", got)
	}
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": own}, principal, "access", false); got == nil {
		t.Fatal("the principal's own verified login counts")
	}
	// On a route that lets the PDP judge who may approve, another subject's verified
	// login counts — the PDP gets user_sub and decides. The other rules still hold.
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": someoneElse}, principal, "access", true); got == nil {
		t.Fatal("with user_token_subject=pdp an approver's login counts, for the PDP to judge")
	}
	if got := s.userClaims(context.Background(), map[string]string{"x-user-token": delegated}, principal, "access", true); got != nil {
		t.Fatal("a delegated token is never a login, whoever judges")
	}
}

func TestUserClaimsDecodingIsOptIn(t *testing.T) {
	key := newKey(t)
	tok := mintJWT(t, key, "", validClaims())
	principal := validClaims()["sub"].(string)

	// No verifier and decoding not allowed: an unverifiable token counts for nothing.
	if got := (&server{}).userClaims(context.Background(), map[string]string{"x-user-token": tok}, principal, "access", false); got != nil {
		t.Fatalf("an unverifiable token must not count, got %v", got)
	}
	s := &server{decodeUserTokens: true}
	got := s.userClaims(context.Background(), map[string]string{"x-user-token": tok}, principal, "access", false)
	if got == nil || got["sub"] != principal {
		t.Fatalf("decoding allowed should decode, got %v", got)
	}
	if s.userClaims(context.Background(), map[string]string{}, principal, "access", false) != nil {
		t.Fatal("no header should yield no claims")
	}
}

func TestVerifyJWSRSAAndErrorBranches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	claims := validClaims()

	for _, alg := range []string{"RS256", "PS256"} {
		t.Run(alg, func(t *testing.T) {
			input := enc(map[string]any{"alg": alg}) + "." + enc(claims)
			hash, _ := hashFor(alg)
			digest := hashBytes(hash, []byte(input))
			var sig []byte
			if alg == "PS256" {
				sig, err = rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			} else {
				sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
			}
			if err != nil {
				t.Fatal(err)
			}
			token := input + "." + base64.RawURLEncoding.EncodeToString(sig)
			if err := verifyJWS(token, jwk, alg); err != nil {
				t.Fatalf("a genuine %s token should verify: %v", alg, err)
			}
			// Flip a claim: the signature must stop matching.
			tampered := enc(map[string]any{"alg": alg}) + "." + enc(map[string]any{"sub": "someone-else"}) +
				"." + base64.RawURLEncoding.EncodeToString(sig)
			if err := verifyJWS(tampered, jwk, alg); err == nil {
				t.Fatalf("a tampered %s token was accepted", alg)
			}
		})
	}

	for name, tc := range map[string]struct{ token, alg string }{
		"not a JWS":       {"a.b", "RS256"},
		"sig not base64":  {"a.b.!!!", "RS256"},
		"unsupported alg": {"a.b.c", "HS256"},
		"EC alg RSA key":  {"a.b.AAAA", "ES256"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyJWS(tc.token, jwk, tc.alg); err == nil {
				t.Fatal("expected a verification failure")
			}
		})
	}
}

func TestJWKSLookupWithoutAKid(t *testing.T) {
	key := newKey(t)

	t.Run("single key is used when the token names no kid", func(t *testing.T) {
		srv := jwksServer(t, key, "")
		defer srv.Close()
		if _, err := newTestValidator(t, srv.URL).Validate(context.Background(), mintJWT(t, key, "", validClaims())); err != nil {
			t.Fatalf("a lone key should be usable without a kid: %v", err)
		}
	})

	t.Run("several keys and no kid is ambiguous, so refused", func(t *testing.T) {
		other := newKey(t)
		jwkA, jwkB := publicJWK(key), publicJWK(other)
		jwkA["kid"], jwkB["kid"] = "a", "b"
		body, _ := json.Marshal(map[string]any{"keys": []any{jwkA, jwkB}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		defer srv.Close()
		if _, err := newTestValidator(t, srv.URL).Validate(context.Background(), mintJWT(t, key, "", validClaims())); err == nil {
			t.Fatal("with several keys and no kid there is no safe choice")
		}
	})
}

func TestJWKSSkipsEncryptionKeysAndEmptySets(t *testing.T) {
	t.Run("use=enc is not a signing key", func(t *testing.T) {
		jwk := publicJWK(newKey(t))
		jwk["use"] = "enc"
		jwk["kid"] = "k1"
		body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		defer srv.Close()
		c := &jwksCache{url: srv.URL, client: srv.Client(), ttl: time.Minute}
		if _, err := c.fetch(context.Background()); err == nil {
			t.Fatal("a JWKS of only encryption keys has no usable signing key")
		}
	})

	for name, body := range map[string]string{
		"not json":  "{{{",
		"empty set": `{"keys":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c := &jwksCache{url: srv.URL, client: srv.Client(), ttl: time.Minute}
			if _, err := c.fetch(context.Background()); err == nil {
				t.Fatalf("%s should fail", name)
			}
		})
	}

	t.Run("non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		c := &jwksCache{url: srv.URL, client: srv.Client(), ttl: time.Minute}
		if _, err := c.fetch(context.Background()); err == nil {
			t.Fatal("a 500 from the JWKS endpoint should fail")
		}
	})
}

func TestJwkThumbprintCanonicalisation(t *testing.T) {
	// RFC 7638 §3.1 worked example.
	rsaThumb := jwkThumbprint(map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	})
	if rsaThumb != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("RFC 7638 example thumbprint: %q", rsaThumb)
	}
	if jwkThumbprint(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AA"}) == "" {
		t.Fatal("OKP keys should thumbprint")
	}
	for _, bad := range []map[string]any{{"kty": "oct", "k": "s"}, {}, nil} {
		if jwkThumbprint(bad) != "" {
			t.Errorf("%v should not thumbprint", bad)
		}
	}
}

func TestVerifyJWSUnsupportedAlgFamily(t *testing.T) {
	// An alg outside ES/RS/PS reaches the final unsupported return.
	if err := verifyJWS("aGVhZGVy.Y2xhaW1z."+base64.RawURLEncoding.EncodeToString([]byte("sig")), map[string]any{"kty": "oct"}, "ES256zz"); err == nil {
		t.Fatal("hashFor should reject an unknown alg before the family switch")
	}
	// A syntactically-valid ES alg but a key that is not EC: the ecdsaFromJWK error arm.
	if err := verifyJWS("aGVhZGVy.Y2xhaW1z."+base64.RawURLEncoding.EncodeToString(make([]byte, 64)), map[string]any{"kty": "RSA"}, "ES256"); err == nil {
		t.Fatal("an ES alg with an RSA key must error")
	}
}

func TestValidateUnreadableClaims(t *testing.T) {
	// A token whose signature verifies is required to reach the claims-nil check, which
	// cannot happen with a real token — the guard is defensive. Instead confirm the
	// public surface: a token with a non-JSON claims segment fails earlier, at decode.
	key := newKey(t)
	jwks := jwksServer(t, key, "k1")
	defer jwks.Close()
	v := newTestValidator(t, jwks.URL)
	hdr := b64urlEncode([]byte(`{"alg":"ES256","kid":"k1"}`))
	if _, err := v.Validate(context.Background(), hdr+"."+b64urlEncode([]byte("not json"))+".sig"); err == nil {
		t.Fatal("unreadable claims must fail validation")
	}
}

// A cold cache fetches once however many requests arrive together.
func TestJWKSColdFetchIsShared(t *testing.T) {
	key := newKey(t)
	var hits atomic.Int32
	jwk := publicJWK(key)
	jwk["kid"] = "k1"
	body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	v := newTestValidator(t, srv.URL)
	tok := mintJWT(t, key, "k1", validClaims())
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Validate(context.Background(), tok); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := hits.Load(); n != 1 {
		t.Fatalf("40 concurrent cold validations should share one fetch, got %d", n)
	}
}

// A stale cache with a slow or dead JWKS endpoint serves the keys it has at once and
// refreshes in the background, instead of every request waiting for its deadline.
func TestJWKSStaleKeysDoNotWaitForARefresh(t *testing.T) {
	key := newKey(t)
	var slow atomic.Bool
	jwk := publicJWK(key)
	jwk["kid"] = "k1"
	body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	v := newTestValidator(t, srv.URL)
	tok := mintJWT(t, key, "k1", validClaims())
	if _, err := v.Validate(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	slow.Store(true)
	v.jwks.mu.Lock()
	v.jwks.fetchedAt = time.Now().Add(-11 * time.Minute)
	v.jwks.nextAttempt = time.Time{}
	v.jwks.mu.Unlock()
	start := time.Now()
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if _, err := v.Validate(ctx, tok); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("stale keys should be served without waiting, took %v", d)
	}
}

// Past the staleness cap the old keys are not trusted: a key the issuer withdrew must
// stop verifying even while the endpoint is down.
func TestJWKSStopsTrustingKeysPastMaxStale(t *testing.T) {
	key := newKey(t)
	var fail atomic.Bool
	jwk := publicJWK(key)
	jwk["kid"] = "k1"
	body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := &jwksCache{url: srv.URL, client: srv.Client(), ttl: time.Minute, maxStale: time.Minute}
	if _, err := c.key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-3 * time.Minute)
	c.nextAttempt = time.Time{}
	c.mu.Unlock()
	if _, err := c.key(context.Background(), "k1"); err == nil {
		t.Fatal("keys past max-stale must not verify while the refresh fails")
	}
	// And the failure backs off: the next call does not fetch again at once.
	c.mu.Lock()
	next := c.nextAttempt
	c.mu.Unlock()
	if !next.After(time.Now()) {
		t.Fatal("a failed fetch must hold further fetches back")
	}
}

func TestJWKSReadyLoadsTheKeysOnce(t *testing.T) {
	key := newKey(t)
	srv := jwksServer(t, key, "k1")
	defer srv.Close()
	c := &jwksCache{url: srv.URL, client: srv.Client(), ttl: time.Minute}
	if err := c.ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	dead := &jwksCache{url: "http://127.0.0.1:1", client: &http.Client{Timeout: time.Second}, ttl: time.Minute}
	if err := dead.ready(context.Background()); err == nil {
		t.Fatal("an unreachable JWKS is not ready")
	}
}

func TestJWKSRefusesAnOversizedKeySet(t *testing.T) {
	keys := make([]any, maxJWKSKeys+1)
	for i := range keys {
		j := publicJWK(newKey(t))
		j["kid"] = fmt.Sprint(i)
		keys[i] = j
	}
	body, _ := json.Marshal(map[string]any{"keys": keys})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	c := &jwksCache{url: srv.URL, client: srv.Client(), ttl: time.Minute}
	if _, err := c.fetch(context.Background()); err == nil {
		t.Fatal("a JWKS with more keys than any issuer publishes is refused")
	}
}

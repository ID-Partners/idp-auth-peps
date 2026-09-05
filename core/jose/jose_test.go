package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"strings"
	"testing"
)

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignAndVerifyEveryFamily(t *testing.T) {
	claims := map[string]any{"sub": "x", "n": 1}
	cases := []struct {
		alg string
		key crypto.Signer
	}{
		{"ES256", ecKey(t, elliptic.P256())},
		{"ES384", ecKey(t, elliptic.P384())},
		{"ES512", ecKey(t, elliptic.P521())},
		{"RS256", rsaKey(t)},
		{"RS384", rsaKey(t)},
		{"PS256", rsaKey(t)},
		{"PS512", rsaKey(t)},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			tok, err := Sign(map[string]any{"alg": tc.alg, "typ": "JWT"}, claims, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := PublicJWK(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyJWS(tok, jwk, tc.alg); err != nil {
				t.Fatalf("verify %s: %v", tc.alg, err)
			}
			if Header(tok)["alg"] != tc.alg || Claims(tok)["sub"] != "x" {
				t.Fatalf("round trip lost header/claims: %v %v", Header(tok), Claims(tok))
			}
			if jwk["kid"] != Thumbprint(jwk) || jwk["kid"] == "" {
				t.Fatalf("kid should be the thumbprint")
			}
			// Tamper: flip the payload.
			parts := strings.Split(tok, ".")
			bad := parts[0] + "." + B64URLEncode([]byte(`{"sub":"y"}`)) + "." + parts[2]
			if err := VerifyJWS(bad, jwk, tc.alg); err == nil {
				t.Fatal("tampered token verified")
			}
		})
	}
}

func TestVerifyJWSRejects(t *testing.T) {
	ec := ecKey(t, elliptic.P256())
	ecJWK, _ := PublicJWK(ec)
	rs := rsaKey(t)
	rsJWK, _ := PublicJWK(rs)
	p384JWK, _ := PublicJWK(ecKey(t, elliptic.P384()))
	tok, _ := Sign(map[string]any{"alg": "ES256"}, map[string]any{"a": 1}, ec)

	cases := map[string]struct {
		tok  string
		jwk  map[string]any
		alg  string
		want string
	}{
		"not compact":      {"a.b", ecJWK, "ES256", "not a compact JWS"},
		"bad sig b64":      {"a.b.***", ecJWK, "ES256", "not base64url"},
		"hs256":            {tok, ecJWK, "HS256", "unsupported"},
		"none":             {tok, ecJWK, "none", "unsupported"},
		"es with rsa key":  {tok, rsJWK, "ES256", "kty is not EC"},
		"rs with ec key":   {tok, ecJWK, "RS256", "kty is not RSA"},
		"ps with ec key":   {tok, ecJWK, "PS256", "kty is not RSA"},
		"wrong sig length": {tok, p384JWK, "ES256", "wrong length"},
		"rs bad sig":       {strings.Join([]string{strings.Split(tok, ".")[0], strings.Split(tok, ".")[1], B64URLEncode(make([]byte, 256))}, "."), rsJWK, "RS256", "does not verify"},
		"ps bad sig":       {strings.Join([]string{strings.Split(tok, ".")[0], strings.Split(tok, ".")[1], B64URLEncode(make([]byte, 256))}, "."), rsJWK, "PS256", "does not verify"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyJWS(tc.tok, tc.jwk, tc.alg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestJWKParsingErrors(t *testing.T) {
	if _, err := ECDSAFromJWK(map[string]any{"kty": "EC", "crv": "P-999"}); err == nil || !strings.Contains(err.Error(), "curve") {
		t.Fatalf("want curve error, got %v", err)
	}
	if _, err := ECDSAFromJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": "***"}); err == nil || !strings.Contains(err.Error(), `"x"`) {
		t.Fatalf("want x error, got %v", err)
	}
	if _, err := ECDSAFromJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": "AQ", "y": "***"}); err == nil || !strings.Contains(err.Error(), `"y"`) {
		t.Fatalf("want y error, got %v", err)
	}
	if _, err := ECDSAFromJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"}); err == nil || !strings.Contains(err.Error(), "not a point") {
		t.Fatalf("want off-curve error, got %v", err)
	}
	if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": ""}); err == nil {
		t.Fatal("want n error")
	}
	for _, e := range []string{"", "AAAAAAAAAAAA", B64URLEncode([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})} {
		if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": "AQ", "e": e}); err == nil {
			t.Fatalf("want exponent error for e=%q", e)
		}
	}
	if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": "AQ", "e": "AQAB"}); err != nil {
		t.Fatalf("valid RSA JWK rejected: %v", err)
	}
}

func TestThumbprintAndParts(t *testing.T) {
	// RFC 7638 §3.1 example.
	jwk := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}
	if got := Thumbprint(jwk); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint = %s", got)
	}
	if Thumbprint(map[string]any{"kty": "oct"}) != "" {
		t.Fatal("oct keys have no thumbprint here")
	}
	if Thumbprint(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "abc"}) == "" {
		t.Fatal("OKP thumbprint missing")
	}
	if Part("a.b", 0) != nil || Part("***.b.c", 0) != nil || Part(B64URLEncode([]byte("[]"))+".b.c", 0) != nil {
		t.Fatal("malformed parts should decode to nil")
	}
	if got, err := B64URLDecode("YQ=="); err != nil || string(got) != "a" {
		t.Fatalf("padded decode: %v %q", err, got)
	}
}

func TestSignErrors(t *testing.T) {
	ec := ecKey(t, elliptic.P256())
	rs := rsaKey(t)
	if _, err := Sign(map[string]any{"alg": "HS256"}, nil, ec); err == nil {
		t.Fatal("HS256 must not sign")
	}
	if _, err := Sign(map[string]any{"alg": "RS256"}, nil, ec); err == nil {
		t.Fatal("RS256 with EC key must fail")
	}
	if _, err := Sign(map[string]any{"alg": "ES256"}, nil, rs); err == nil {
		t.Fatal("ES256 with RSA key must fail")
	}
	if _, err := Sign(map[string]any{"alg": "ES256"}, map[string]any{"bad": make(chan int)}, ec); err == nil {
		t.Fatal("unmarshalable claims must fail")
	}
	if _, err := Sign(map[string]any{"alg": "ES256", "bad": make(chan int)}, nil, ec); err == nil {
		t.Fatal("unmarshalable header must fail")
	}
	if _, err := Sign(map[string]any{"alg": "ES256"}, nil, fakeSigner{}); err == nil {
		t.Fatal("unknown key type must fail")
	}
	if _, err := PublicJWK(fakeSigner{}); err == nil {
		t.Fatal("unknown key type must fail")
	}
}

type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey { return nil }
func (fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

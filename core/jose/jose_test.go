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
	// A token whose header declares alg, with sig as its signature segment.
	withAlg := func(alg string, sig []byte) string {
		return B64URLEncode([]byte(`{"alg":"`+alg+`"}`)) + "." + B64URLEncode([]byte(`{"a":1}`)) + "." + B64URLEncode(sig)
	}
	hdr := strings.Split(tok, ".")[0]

	cases := map[string]struct {
		tok  string
		jwk  map[string]any
		alg  string
		want string
	}{
		"not compact":      {"a.b", ecJWK, "ES256", "not a compact JWS"},
		"bad header":       {"a.b.c", ecJWK, "ES256", "header is not readable"},
		"bad sig b64":      {hdr + ".b.***", ecJWK, "ES256", "not base64url"},
		"hs256":            {withAlg("HS256", []byte("x")), ecJWK, "HS256", "unsupported"},
		"none":             {withAlg("none", nil), ecJWK, "none", "unsupported"},
		"es with rsa key":  {tok, rsJWK, "ES256", "kty is not EC"},
		"rs with ec key":   {withAlg("RS256", make([]byte, 256)), ecJWK, "RS256", "kty is not RSA"},
		"ps with ec key":   {withAlg("PS256", make([]byte, 256)), ecJWK, "PS256", "kty is not RSA"},
		"es wrong curve":   {tok, p384JWK, "ES256", "needs curve P-256"},
		"wrong sig length": {withAlg("ES256", make([]byte, 63)), ecJWK, "ES256", "wrong length"},
		"rs bad sig":       {withAlg("RS256", make([]byte, 256)), rsJWK, "RS256", "does not verify"},
		"ps bad sig":       {withAlg("PS256", make([]byte, 256)), rsJWK, "PS256", "does not verify"},
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
	full := B64URLEncode([]byte(strings.Repeat("\x01", 32)))
	if _, err := ECDSAFromJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": full, "y": "***"}); err == nil || !strings.Contains(err.Error(), `"y"`) {
		t.Fatalf("want y error, got %v", err)
	}
	if _, err := ECDSAFromJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": full, "y": full}); err == nil || !strings.Contains(err.Error(), "not a point") {
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
	// A modulus short enough to factor must be refused, however well-formed the JWK is:
	// stdlib would verify against it and the signature would mean nothing.
	if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": "AQ", "e": "AQAB"}); err == nil || !strings.Contains(err.Error(), "minimum is 2048") {
		t.Fatalf("want a modulus-size error, got %v", err)
	}
	if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": rfc7638N, "e": "AQAB"}); err != nil {
		t.Fatalf("valid 2048-bit RSA JWK rejected: %v", err)
	}
}

// rfc7638N is the 2048-bit modulus from RFC 7638 3.1, used wherever a test needs a key of
// a size this package will actually accept.
const rfc7638N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

func TestThumbprintAndParts(t *testing.T) {
	// RFC 7638 §3.1 example.
	jwk := map[string]any{
		"kty": "RSA",
		"n":   rfc7638N,
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
	if _, err := B64URLDecode("YQ=="); err == nil {
		t.Fatal("padding is not base64url as JWS uses it")
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

// RFC 7638 is a JSON construction. Building it by interpolation would let a member value
// containing a quote reshape the document it sits inside, which is how two different keys
// come to share a thumbprint — so a value with JSON metacharacters must be escaped, and
// must not collide with the key it is imitating.
func TestThumbprintEscapesMemberValues(t *testing.T) {
	honest := map[string]any{"kty": "EC", "crv": "P-256", "x": "XX", "y": "YY"}
	// crv carries the rest of an honest-looking document.
	forged := map[string]any{
		"kty": "EC",
		"crv": `P-256","kty":"EC","x":"XX","y":"YY`,
		"x":   "XX",
		"y":   "YY",
	}
	if Thumbprint(honest) == "" {
		t.Fatal("the honest key should have a thumbprint")
	}
	if Thumbprint(honest) == Thumbprint(forged) {
		t.Fatal("a key whose member value contains JSON metacharacters must not share a thumbprint")
	}
	// A backslash must not escape the closing quote either.
	if Thumbprint(map[string]any{"kty": "EC", "crv": "P-256", "x": `A\`, "y": "YY"}) ==
		Thumbprint(map[string]any{"kty": "EC", "crv": "P-256", "x": `A\"`, "y": "YY"}) {
		t.Fatal("distinct values must give distinct thumbprints")
	}
	if Thumbprint(map[string]any{"kty": "oct", "k": "s"}) != "" {
		t.Error("a kty with no RFC 7638 construction has no thumbprint")
	}
}

// PublicJWK must describe the key it was given, including an unusual exponent.
func TestPublicJWKReportsTheRealExponent(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k.E = 3 // a legal, if unfashionable, exponent
	jwk, err := PublicJWK(k)
	if err != nil {
		t.Fatal(err)
	}
	if got := jwk["e"]; got != B64URLEncode([]byte{3}) {
		t.Fatalf("want the key's own exponent, got %v", got)
	}
	pub, err := RSAFromJWK(jwk)
	if err != nil {
		t.Fatalf("the JWK we emit must parse back: %v", err)
	}
	if pub.E != 3 {
		t.Fatalf("round trip lost the exponent: %d", pub.E)
	}
}

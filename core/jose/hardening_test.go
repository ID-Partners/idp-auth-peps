package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// P3: RSAFromJWK had a floor and no ceiling, and the exponent was accepted up to 2^31.
// A DPoP proof's header jwk of ~155K bits fits in a 60 KB header and costs 0.1-0.5 s to
// verify; a federation statement's jwks can carry a multi-million-bit key within the
// 1 MiB body cap. The ceiling is checked before any arithmetic.
func TestRSAModulusCeiling(t *testing.T) {
	huge := func(bits int) string {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			t.Fatal(err)
		}
		n.SetBit(n, bits-1, 1) // exactly `bits` long
		n.SetBit(n, 0, 1)      // odd, like a real modulus
		return B64URLEncode(n.Bytes())
	}
	for _, bits := range []int{8193, 16384, 160_000, 1_000_000} {
		start := time.Now()
		_, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": huge(bits), "e": "AQAB"})
		if err == nil || !strings.Contains(err.Error(), "maximum is 8192") {
			t.Fatalf("%d-bit modulus: want the ceiling, got %v", bits, err)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("%d-bit modulus: refusing it must be cheap", bits)
		}
	}
	if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": huge(8192), "e": "AQAB"}); err != nil {
		t.Fatalf("8192 bits is the ceiling, not over it: %v", err)
	}
	// Verification never reaches the arithmetic with an oversized key.
	tok := B64URLEncode([]byte(`{"alg":"RS256"}`)) + "." + B64URLEncode([]byte(`{}`)) + "." + B64URLEncode(make([]byte, 2048))
	if err := VerifyJWS(tok, map[string]any{"kty": "RSA", "n": huge(16384), "e": "AQAB"}, "RS256"); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("want the ceiling from VerifyJWS, got %v", err)
	}
}

// The exponent: odd, at least 3, and well below the 2^31 the old check allowed.
func TestRSAExponentBounds(t *testing.T) {
	e := func(v uint64) string { return B64URLEncode(new(big.Int).SetUint64(v).Bytes()) }
	for _, bad := range []uint64{0, 1, 2, 4, 65536, 1<<24 + 1, 1<<31 - 1} {
		if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": rfc7638N, "e": e(bad)}); err == nil || !strings.Contains(err.Error(), "exponent") {
			t.Errorf("e=%d must be refused: %v", bad, err)
		}
	}
	for _, good := range []uint64{3, 17, 65537, 1<<24 - 1} {
		if _, err := RSAFromJWK(map[string]any{"kty": "RSA", "n": rfc7638N, "e": e(good)}); err != nil {
			t.Errorf("e=%d is a legitimate exponent: %v", good, err)
		}
	}
}

// RFC 7518 §3.4 ties each ES alg to one curve. ES384 over a P-256 key used to verify.
func TestESAlgsAreBoundToTheirCurves(t *testing.T) {
	for _, tc := range []struct {
		alg   string
		curve elliptic.Curve
	}{{"ES384", elliptic.P256()}, {"ES256", elliptic.P384()}, {"ES512", elliptic.P384()}, {"ES256", elliptic.P521()}} {
		key := ecKey(t, tc.curve)
		tok, err := Sign(map[string]any{"alg": tc.alg}, map[string]any{"a": 1}, key)
		if err != nil {
			t.Fatal(err)
		}
		jwk, _ := PublicJWK(key)
		if err := VerifyJWS(tok, jwk, tc.alg); err == nil || !strings.Contains(err.Error(), "curve") {
			t.Errorf("%s over %s must be refused: %v", tc.alg, tc.curve.Params().Name, err)
		}
	}
}

// RFC 7515 §4.1.11: a recipient MUST reject a JWS whose crit names an extension it does
// not understand, and this package understands none. VerifyJWS never looked.
func TestCritHeaderIsRefused(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	jwk, _ := PublicJWK(key)
	for _, crit := range []any{[]any{"exp"}, []any{}, "b64"} {
		tok, err := Sign(map[string]any{"alg": "ES256", "crit": crit, "exp": 1}, map[string]any{"a": 1}, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyJWS(tok, jwk, "ES256"); err == nil || !strings.Contains(err.Error(), "crit") {
			t.Errorf("crit %v must be refused: %v", crit, err)
		}
	}
}

// The alg a caller verifies under is the one the header declares, and a JWK that names
// its alg verifies under that one only (RFC 8725 §3.1).
func TestAlgMustAgreeWithTheHeaderAndTheKey(t *testing.T) {
	rs := rsaKey(t)
	jwk, _ := PublicJWK(rs)
	tok, _ := Sign(map[string]any{"alg": "PS256"}, map[string]any{"a": 1}, rs)
	if err := VerifyJWS(tok, jwk, "PS256"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyJWS(tok, jwk, "RS256"); err == nil || !strings.Contains(err.Error(), "header alg") {
		t.Errorf("a caller's alg that is not the header's must be refused: %v", err)
	}
	jwk["alg"] = "RS256"
	if err := VerifyJWS(tok, jwk, "PS256"); err == nil || !strings.Contains(err.Error(), "RS256") {
		t.Errorf("a key published for RS256 must not verify PS256: %v", err)
	}
	if err := VerifyJWS(B64URLEncode([]byte("not json"))+".e30."+B64URLEncode([]byte("x")), jwk, "PS256"); err == nil || !strings.Contains(err.Error(), "header") {
		t.Errorf("an unreadable header must be refused: %v", err)
	}
}

// One value, one encoding: base64url as JWS uses it is unpadded and its unused trailing
// bits are zero. Anything else is a second spelling of the same bytes — a malleable
// signature segment, or a second thumbprint for the same key.
func TestNonCanonicalBase64URLIsRefused(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	jwk, _ := PublicJWK(key)
	tok, _ := Sign(map[string]any{"alg": "ES256"}, map[string]any{"a": 1}, key)
	parts := strings.Split(tok, ".")
	sig := parts[2] // 64 bytes: 86 characters, the last carrying 4 unused bits
	last := strings.IndexByte(b64Alphabet, sig[len(sig)-1])
	sibling := sig[:len(sig)-1] + string(b64Alphabet[last|1]) // same bytes, a trailing bit set
	for name, s := range map[string]string{"trailing bits": sibling, "padding": sig + "==", "newline": sig[:10] + "\n" + sig[10:]} {
		if err := VerifyJWS(parts[0]+"."+parts[1]+"."+s, jwk, "ES256"); err == nil {
			t.Errorf("%s: a second spelling of the signature must not verify", name)
		}
	}
	if _, err := B64URLDecode("YQ=="); err == nil {
		t.Error("padding is not base64url as JWS uses it")
	}
	if got, err := B64URLDecode("YQ"); err != nil || string(got) != "a" {
		t.Errorf("the canonical form decodes: %q %v", got, err)
	}
	if Part(tok+".extra", 0) != nil {
		t.Error("a compact JWS has exactly three segments")
	}
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// RFC 7518 §6.2.1.2: an EC coordinate is the full size for its curve. A shortened one is
// the same point spelt differently, and so a different thumbprint for the same key.
func TestECCoordinatesAreFullLength(t *testing.T) {
	var key *ecdsa.PrivateKey
	for key == nil || key.X.BitLen() > 248 { // a key whose x has a leading zero byte
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	jwk, _ := PublicJWK(key)
	if _, err := ECDSAFromJWK(jwk); err != nil {
		t.Fatalf("the full-length form parses: %v", err)
	}
	jwk["x"] = B64URLEncode(key.X.Bytes()) // 31 bytes
	if _, err := ECDSAFromJWK(jwk); err == nil || !strings.Contains(err.Error(), `"x"`) {
		t.Fatalf("a shortened coordinate must be refused: %v", err)
	}
}

// A JWK Set is bounded: rotation needs a handful of keys, not thousands.
func TestParseJWKSet(t *testing.T) {
	one := map[string]any{"kty": "EC", "kid": "k"}
	set := func(n int) []byte {
		keys := make([]any, n)
		for i := range keys {
			keys[i] = one
		}
		raw, _ := json.Marshal(map[string]any{"keys": keys})
		return raw
	}
	if keys, err := ParseJWKSet(set(MaxJWKSKeys)); err != nil || len(keys) != MaxJWKSKeys {
		t.Fatalf("%d keys is the cap, not over it: %v", MaxJWKSKeys, err)
	}
	for name, raw := range map[string][]byte{
		"too many":     set(MaxJWKSKeys + 1),
		"none":         set(0),
		"not JSON":     []byte("<html>"),
		"no keys":      []byte(`{"k":[]}`),
		"keys not arr": []byte(`{"keys":{}}`),
		"key not obj":  []byte(`{"keys":["x"]}`),
	} {
		if _, err := ParseJWKSet(raw); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if _, err := JWKSKeys("not a set"); err == nil {
		t.Error("a non-object set must be refused")
	}
}

// PrivateKeyFromJWK is held to the same ceiling: a key file cannot smuggle one in.
func TestPrivateRSAKeyCeiling(t *testing.T) {
	jwk := map[string]any{"kty": "RSA", "n": B64URLEncode(new(big.Int).Lsh(big.NewInt(1), 9000).Bytes()), "e": "AQAB", "d": "AQ", "p": "AQ", "q": "AQ"}
	if _, err := PrivateKeyFromJWK(jwk); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("%v", err)
	}
}

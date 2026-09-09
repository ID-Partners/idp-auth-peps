package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestPrivateKeyRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := PrivateJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := PublicJWK(key)
	if jwk["kid"] != pub["kid"] || jwk["d"] == nil {
		t.Fatalf("private and public forms must share a kid and the private one carry d: %v", jwk)
	}
	// Through JSON, as a file would carry it.
	raw, _ := json.Marshal(jwk)
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	loaded, err := PrivateKeyFromJWK(back)
	if err != nil {
		t.Fatal(err)
	}
	alg, err := AlgFor(loaded)
	if err != nil || alg != "ES256" {
		t.Fatalf("%s %v", alg, err)
	}
	tok, err := Sign(map[string]any{"alg": alg, "kid": jwk["kid"]}, map[string]any{"iss": "x"}, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyJWS(tok, pub, alg); err != nil {
		t.Fatalf("a token signed with the loaded key must verify with the original public key: %v", err)
	}
}

func TestPrivateKeyFromJWKRejectsBadKeys(t *testing.T) {
	key, _ := GenerateKey()
	jwk, _ := PrivateJWK(key)
	other, _ := GenerateKey()
	otherJWK, _ := PrivateJWK(other)
	cases := map[string]map[string]any{
		"no d":        {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]},
		"wrong d":     {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"], "d": otherJWK["d"]},
		"unknown kty": {"kty": "oct", "k": "x"},
		"bad curve":   {"kty": "EC", "crv": "P-999", "x": jwk["x"], "y": jwk["y"], "d": jwk["d"]},
		"rsa no d":    {"kty": "RSA", "n": "AQAB", "e": "AQAB"},
	}
	for name, c := range cases {
		if _, err := PrivateKeyFromJWK(c); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	if _, err := AlgFor(nil); err == nil {
		t.Error("AlgFor(nil) must fail")
	}
}

func TestRSAPrivateKeyFromJWK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := func(n *big.Int) string { return B64URLEncode(n.Bytes()) }
	jwk := map[string]any{
		"kty": "RSA", "n": b(key.N), "e": b(big.NewInt(int64(key.E))),
		"d": b(key.D), "p": b(key.Primes[0]), "q": b(key.Primes[1]),
	}
	loaded, err := PrivateKeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	alg, _ := AlgFor(loaded)
	if alg != "RS256" {
		t.Fatal(alg)
	}
	pub, _ := PublicJWK(loaded)
	tok, err := Sign(map[string]any{"alg": alg, "kid": pub["kid"]}, map[string]any{"iss": "x"}, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyJWS(tok, pub, alg); err != nil {
		t.Fatal(err)
	}
	// A mismatched prime is not a key.
	jwk["q"] = b(new(big.Int).Add(key.Primes[1], big.NewInt(2)))
	if _, err := PrivateKeyFromJWK(jwk); err == nil || !strings.Contains(err.Error(), "RSA private key") {
		t.Fatalf("a corrupt RSA key must be rejected: %v", err)
	}
}

func TestAlgForCurves(t *testing.T) {
	for curve, want := range map[elliptic.Curve]string{elliptic.P256(): "ES256", elliptic.P384(): "ES384", elliptic.P521(): "ES512"} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if alg, err := AlgFor(key); err != nil || alg != want {
			t.Fatalf("%s: %s %v", curve.Params().Name, alg, err)
		}
		jwk, err := PrivateJWK(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PrivateKeyFromJWK(jwk); err != nil {
			t.Fatalf("%s round trip: %v", curve.Params().Name, err)
		}
	}
	// A curve Go knows but the JOSE registry does not.
	if _, err := AlgFor(&ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P224()}}); err == nil {
		t.Fatal("P-224 has no JWS alg")
	}
	if _, err := PublicJWK(nil); err == nil {
		t.Fatal("PublicJWK(nil) must fail")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	b := func(n *big.Int) string { return B64URLEncode(n.Bytes()) }
	for name, jwk := range map[string]map[string]any{
		"rsa no p":  {"kty": "RSA", "n": b(rsaKey.N), "e": "AQAB", "d": b(rsaKey.D)},
		"rsa no q":  {"kty": "RSA", "n": b(rsaKey.N), "e": "AQAB", "d": b(rsaKey.D), "p": b(rsaKey.Primes[0])},
		"rsa bad n": {"kty": "RSA", "n": "!!", "e": "AQAB", "d": b(rsaKey.D)},
		"ec bad d":  {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "d": "!!"},
	} {
		if _, err := PrivateKeyFromJWK(jwk); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

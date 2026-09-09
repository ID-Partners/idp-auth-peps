package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// PrivateKeyFromJWK reads a private EC (P-256, P-384, P-521) or RSA key from its JWK
// form (RFC 7518 §6). This is how a PEP loads the key it holds as a federation entity.
func PrivateKeyFromJWK(jwk map[string]any) (crypto.Signer, error) {
	switch str(jwk["kty"]) {
	case "EC":
		pub, err := ECDSAFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		d, err := b64urlBigInt(jwk, "d")
		if err != nil {
			return nil, fmt.Errorf("EC private key: %w", err)
		}
		key := &ecdsa.PrivateKey{PublicKey: *pub, D: d}
		// The public point must be D·G, or the key is not a key.
		x, y := pub.Curve.ScalarBaseMult(d.Bytes())
		if x.Cmp(pub.X) != 0 || y.Cmp(pub.Y) != 0 {
			return nil, fmt.Errorf("EC private key: d does not match x and y")
		}
		return key, nil
	case "RSA":
		pub, err := RSAFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		d, err := b64urlBigInt(jwk, "d")
		if err != nil {
			return nil, fmt.Errorf("RSA private key: %w", err)
		}
		p, err := b64urlBigInt(jwk, "p")
		if err != nil {
			return nil, fmt.Errorf("RSA private key: %w", err)
		}
		q, err := b64urlBigInt(jwk, "q")
		if err != nil {
			return nil, fmt.Errorf("RSA private key: %w", err)
		}
		key := &rsa.PrivateKey{PublicKey: *pub, D: d, Primes: []*big.Int{p, q}}
		key.Precompute()
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("RSA private key: %w", err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("unsupported kty %q", str(jwk["kty"]))
}

// GenerateKey mints a fresh P-256 key, the ordinary choice for a federation entity.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PrivateJWK renders an EC private key as a JWK, with the public thumbprint as kid so
// the private and public forms name the same key.
func PrivateJWK(key *ecdsa.PrivateKey) (map[string]any, error) {
	jwk, err := PublicJWK(key)
	if err != nil {
		return nil, err
	}
	n := (key.Curve.Params().BitSize + 7) / 8
	d := make([]byte, n)
	key.D.FillBytes(d)
	jwk["d"] = B64URLEncode(d)
	return jwk, nil
}

// AlgFor is the JWS alg a key signs with: ES256/ES384/ES512 by curve, RS256 for RSA.
func AlgFor(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return "ES256", nil
		case "P-384":
			return "ES384", nil
		case "P-521":
			return "ES512", nil
		}
		return "", fmt.Errorf("unsupported curve %s", k.Curve.Params().Name)
	case *rsa.PrivateKey:
		return "RS256", nil
	}
	return "", fmt.Errorf("unsupported signing key %T", key)
}

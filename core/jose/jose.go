// Package jose holds the JWS/JWK primitives the PEP needs, and nothing more: compact
// JWS verification for the ES*/RS*/PS* families against a public JWK, JWK parsing, the
// RFC 7638 thumbprint and base64url. Stdlib only.
//
// It exists so that access-token validation, DPoP proof checks and OpenID Federation
// Entity Statement validation verify signatures the same way. Anything symmetric (HS*)
// is refused outright: the PEP never holds a shared secret with a token issuer, and a
// helper that quietly accepted one would be a trap for the next caller.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// B64URLDecode decodes unpadded base64url, tolerating padding.
func B64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// B64URLEncode encodes unpadded base64url.
func B64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Part decodes segment idx (0=header, 1=claims) of a compact JWS without verifying it.
func Part(token string, idx int) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 3 || idx >= len(parts) {
		return nil
	}
	raw, err := B64URLDecode(parts[idx])
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// Header decodes the protected header of a compact JWS without verifying it.
func Header(token string) map[string]any { return Part(token, 0) }

// Claims decodes the payload of a compact JWS without verifying it.
func Claims(token string) map[string]any { return Part(token, 1) }

// Thumbprint computes the RFC 7638 SHA-256 thumbprint (base64url) of a JWK for EC /
// RSA / OKP keys, using the canonical member ordering. Empty for any other kty.
func Thumbprint(jwk map[string]any) string {
	str := func(k string) string { s, _ := jwk[k].(string); return s }
	var canon string
	switch str("kty") {
	case "EC":
		canon = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, str("crv"), str("x"), str("y"))
	case "RSA":
		canon = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, str("e"), str("n"))
	case "OKP":
		canon = fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, str("crv"), str("x"))
	default:
		return ""
	}
	sum := sha256.Sum256([]byte(canon))
	return B64URLEncode(sum[:])
}

// HashFor maps a JWS alg to its digest. The FAMILY is checked as well as the size:
// matching on the suffix alone would hand back a hash for HS256, and while the callers
// reject HS* separately, a helper that quietly accepts a symmetric alg is a trap for the
// next caller.
func HashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		return crypto.SHA256, nil
	case "ES384", "RS384", "PS384":
		return crypto.SHA384, nil
	case "ES512", "RS512", "PS512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported DPoP alg %q", alg)
}

// HashBytes digests b with h.
func HashBytes(h crypto.Hash, b []byte) []byte {
	hasher := h.New()
	hasher.Write(b)
	return hasher.Sum(nil)
}

// ECDSAFromJWK parses an EC public JWK (P-256/384/521), rejecting off-curve points.
func ECDSAFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	if kty, _ := jwk["kty"].(string); kty != "EC" {
		return nil, fmt.Errorf("proof alg is ES* but the JWK kty is not EC")
	}
	var curve elliptic.Curve
	switch crv, _ := jwk["crv"].(string); crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
	x, err := b64urlBigInt(jwk, "x")
	if err != nil {
		return nil, err
	}
	y, err := b64urlBigInt(jwk, "y")
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("proof JWK is not a point on %s", curve.Params().Name)
	}
	return pub, nil
}

// RSAFromJWK parses an RSA public JWK, bounding the exponent.
func RSAFromJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	if kty, _ := jwk["kty"].(string); kty != "RSA" {
		return nil, fmt.Errorf("proof alg is RS*/PS* but the JWK kty is not RSA")
	}
	n, err := b64urlBigInt(jwk, "n")
	if err != nil {
		return nil, err
	}
	eBytes, err := B64URLDecode(str(jwk["e"]))
	if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("proof JWK has an unusable exponent")
	}
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(padded)
	if e > 1<<31 {
		return nil, fmt.Errorf("proof JWK exponent is out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func b64urlBigInt(jwk map[string]any, field string) (*big.Int, error) {
	raw, err := B64URLDecode(str(jwk[field]))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("proof JWK field %q is not base64url", field)
	}
	return new(big.Int).SetBytes(raw), nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// VerifyJWS checks a compact JWS against one public JWK under alg. ES* signatures are
// the fixed-width R||S form JWS mandates, not ASN.1.
func VerifyJWS(token string, jwk map[string]any, alg string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token is not a compact JWS")
	}
	sig, err := B64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("token signature is not base64url")
	}
	hash, err := HashFor(alg)
	if err != nil {
		return err
	}
	digest := HashBytes(hash, []byte(parts[0]+"."+parts[1]))

	switch {
	case strings.HasPrefix(alg, "ES"):
		pub, err := ECDSAFromJWK(jwk)
		if err != nil {
			return err
		}
		n := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return fmt.Errorf("token signature has the wrong length for %s", alg)
		}
		if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
			return fmt.Errorf("token signature does not verify")
		}
		return nil
	case strings.HasPrefix(alg, "PS"):
		pub, err := RSAFromJWK(jwk)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return fmt.Errorf("token signature does not verify")
		}
		return nil
	case strings.HasPrefix(alg, "RS"):
		pub, err := RSAFromJWK(jwk)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
			return fmt.Errorf("token signature does not verify")
		}
		return nil
	}
	// HS* would mean a shared secret the PEP does not hold; anything else is unknown.
	return fmt.Errorf("unsupported token alg %q", alg)
}

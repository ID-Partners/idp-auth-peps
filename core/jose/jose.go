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

const (
	// minRSABits is the smallest RSA modulus this package will verify against.
	minRSABits = 2048
	// maxRSABits is the largest. Verification cost grows with the square of the
	// modulus and nothing in stdlib bounds it, while the keys arrive in places an
	// attacker writes: a DPoP proof's header, an Entity Statement's jwks. 8192 bits is
	// twice what any issuer uses.
	maxRSABits = 8192
	// maxRSAExponent bounds e. Every mainstream library uses 65537 (a few legacy keys
	// 3); the ceiling leaves room for the unusual without letting e decide the cost.
	maxRSAExponent = 1<<24 - 1
)

// MaxJWKSKeys bounds the keys one JWK Set may carry. Rotation needs two or three; a set
// of more than this is misconfigured, or someone making the verifier work.
const MaxJWKSKeys = 32

// b64 is base64url as JWS uses it (RFC 7515 §2): unpadded, and strict about the unused
// trailing bits, so one value has exactly one spelling.
var b64 = base64.RawURLEncoding.Strict()

// B64URLDecode decodes base64url as JWS uses it: unpadded and canonical. Padding,
// non-zero trailing bits and line breaks are refused rather than tolerated — each would
// be a second spelling of the same bytes, which makes a signature segment malleable and
// gives one key two thumbprints.
func B64URLDecode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("base64url must not contain line breaks")
	}
	return b64.DecodeString(s)
}

// B64URLEncode encodes unpadded base64url.
func B64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Part decodes segment idx (0=header, 1=claims) of a compact JWS without verifying it.
// Anything that is not exactly three segments is not a compact JWS.
func Part(token string, idx int) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || idx < 0 || idx > 1 {
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
	var members []string
	switch str("kty") {
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	default:
		return ""
	}
	// RFC 7638 is a JSON construction, so it is built with the JSON encoder rather than
	// with fmt: interpolating member values straight into a template would let a value
	// containing a quote or a backslash reshape the document it is supposed to be inside,
	// which is how two different keys end up sharing a thumbprint. Required members are
	// lexicographic by name and that is the order above.
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			b.WriteByte(',')
		}
		// Marshalling a Go string cannot fail, so neither result needs checking.
		name, _ := json.Marshal(m)
		value, _ := json.Marshal(str(m))
		b.Write(name)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	sum := sha256.Sum256([]byte(b.String()))
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
	return 0, fmt.Errorf("unsupported JWS alg %q", alg)
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
		return nil, fmt.Errorf("alg is ES* but the JWK kty is not EC")
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
	// RFC 7518 §6.2.1.2: each coordinate is the full size for the curve. A shortened one
	// is the same point spelt differently, and a second thumbprint for the same key.
	size := (curve.Params().BitSize + 7) / 8
	x, err := coordinate(jwk, "x", size)
	if err != nil {
		return nil, err
	}
	y, err := coordinate(jwk, "y", size)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("JWK is not a point on %s", curve.Params().Name)
	}
	return pub, nil
}

// RSAFromJWK parses an RSA public JWK, bounding the modulus on both sides and the
// exponent.
func RSAFromJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	if kty, _ := jwk["kty"].(string); kty != "RSA" {
		return nil, fmt.Errorf("alg is RS*/PS* but the JWK kty is not RSA")
	}
	raw, err := B64URLDecode(str(jwk["n"]))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("JWK field %q is not base64url", "n")
	}
	// Measured before anything is built from it: a multi-megabit modulus costs
	// seconds to verify against and nothing to send. One leading zero octet is
	// tolerated, as RFC 7518 §6.3.1.1 notes some libraries emit it.
	if len(raw) > maxRSABits/8+1 {
		return nil, fmt.Errorf("JWK RSA modulus is %d bits, the maximum is %d", 8*len(raw), maxRSABits)
	}
	n := new(big.Int).SetBytes(raw)
	// A modulus this side of 2048 bits is not a key, it is an invitation: stdlib will
	// verify a signature against it perfectly happily, and the holder of a short modulus
	// is whoever cared to factor it.
	switch bits := n.BitLen(); {
	case bits < minRSABits:
		return nil, fmt.Errorf("JWK RSA modulus is %d bits, the minimum is %d", bits, minRSABits)
	case bits > maxRSABits:
		return nil, fmt.Errorf("JWK RSA modulus is %d bits, the maximum is %d", bits, maxRSABits)
	}
	eBytes, err := B64URLDecode(str(jwk["e"]))
	if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("JWK has an unusable exponent")
	}
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(padded)
	// Odd (an even e has no inverse modulo φ(n), so the key could not have signed),
	// at least 3, and small enough that the modulus, not e, decides the cost.
	if e < 3 || e%2 == 0 || e > maxRSAExponent {
		return nil, fmt.Errorf("JWK exponent %d is out of range (odd, 3 to %d)", e, maxRSAExponent)
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func b64urlBigInt(jwk map[string]any, field string) (*big.Int, error) {
	raw, err := B64URLDecode(str(jwk[field]))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("JWK field %q is not base64url", field)
	}
	return new(big.Int).SetBytes(raw), nil
}

// coordinate reads an EC coordinate that must be exactly size octets.
func coordinate(jwk map[string]any, field string, size int) (*big.Int, error) {
	raw, err := B64URLDecode(str(jwk[field]))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("JWK field %q is not base64url", field)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("JWK field %q is %d octets, the curve needs %d", field, len(raw), size)
	}
	return new(big.Int).SetBytes(raw), nil
}

// ParseJWKSet reads a JWK Set document (RFC 7517 §5): an object whose "keys" member is
// an array of between one and MaxJWKSKeys JWKs.
func ParseJWKSet(raw []byte) ([]map[string]any, error) {
	var set any
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("JWK set is not JSON")
	}
	return JWKSKeys(set)
}

// JWKSKeys does the same for a JWK Set already decoded, such as an Entity Statement's
// jwks claim.
func JWKSKeys(set any) ([]map[string]any, error) {
	obj, ok := set.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JWK set is not an object")
	}
	list, ok := obj["keys"].([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("JWK set has no keys")
	}
	if len(list) > MaxJWKSKeys {
		return nil, fmt.Errorf("JWK set has %d keys, the maximum is %d", len(list), MaxJWKSKeys)
	}
	keys := make([]map[string]any, 0, len(list))
	for _, k := range list {
		jwk, ok := k.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("JWK set contains a non-object key")
		}
		keys = append(keys, jwk)
	}
	return keys, nil
}

// curveFor is the one curve RFC 7518 §3.4 allows each ES alg.
func curveFor(alg string) elliptic.Curve {
	switch alg {
	case "ES256":
		return elliptic.P256()
	case "ES384":
		return elliptic.P384()
	}
	return elliptic.P521()
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// VerifyJWS checks a compact JWS against one public JWK under alg. ES* signatures are
// the fixed-width R||S form JWS mandates, not ASN.1.
//
// alg must be the one the protected header declares, and the header may not carry
// crit: RFC 7515 §4.1.11 requires rejecting a critical extension that is not
// understood, and none is. A JWK that names its own alg verifies under that alg only
// (RFC 8725 §3.1), and an ES alg only over its own curve (RFC 7518 §3.4).
func VerifyJWS(token string, jwk map[string]any, alg string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token is not a compact JWS")
	}
	hdr := Part(token, 0)
	if hdr == nil {
		return fmt.Errorf("token header is not readable")
	}
	if declared, _ := hdr["alg"].(string); declared != alg {
		return fmt.Errorf("token header alg %q is not %q", declared, alg)
	}
	if _, present := hdr["crit"]; present {
		return fmt.Errorf("token header names critical extensions (crit), which are not supported")
	}
	if own, _ := jwk["alg"].(string); own != "" && own != alg {
		return fmt.Errorf("the JWK is published for %s, not %s", own, alg)
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
		if want := curveFor(alg); pub.Curve != want {
			return fmt.Errorf("%s needs curve %s, the JWK is %s", alg, want.Params().Name, pub.Curve.Params().Name)
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
	default: // RS*: HashFor admits nothing else — HS* would mean a shared secret the PEP does not hold
		pub, err := RSAFromJWK(jwk)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
			return fmt.Errorf("token signature does not verify")
		}
		return nil
	}
}

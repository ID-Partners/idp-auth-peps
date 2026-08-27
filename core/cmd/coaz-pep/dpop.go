package main

// DPoP proof verification (RFC 9449).
//
// The cnf.jkt comparison on its own proves nothing: the proof's public JWK travels in
// the proof header, so anyone who has seen one proof can mint another that thumbprints
// to the same jkt. The binding only means something once the proof's SIGNATURE is
// verified with that embedded key, and once `ath` is compared against the access token
// actually presented. Both are done here.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// dpopMaxAge bounds how old a proof's iat may be. RFC 9449 §11.1 leaves the window to
// the server; 300s is the commonly deployed value and tolerates modest clock skew.
const dpopMaxAge = 300 * time.Second

// verifyProofSignature checks the compact JWS in `proof` against the JWK embedded in its
// own header. Supports ES256/384/512 and RS256/384/512 + PS256/384/512 — between them,
// everything a real DPoP client emits.
func verifyProofSignature(proof string, jwk map[string]any, alg string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return fmt.Errorf("proof is not a compact JWS")
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return fmt.Errorf("proof signature is not base64url")
	}

	hash, err := hashFor(alg)
	if err != nil {
		return err
	}
	digest := hashBytes(hash, signingInput)

	switch {
	case strings.HasPrefix(alg, "ES"):
		pub, err := ecdsaFromJWK(jwk)
		if err != nil {
			return err
		}
		// JWS ECDSA signatures are the fixed-width R||S form, not ASN.1.
		n := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return fmt.Errorf("proof signature has the wrong length for %s", alg)
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return fmt.Errorf("proof signature does not verify")
		}
		return nil

	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		pub, err := rsaFromJWK(jwk)
		if err != nil {
			return err
		}
		if strings.HasPrefix(alg, "PS") {
			if err := rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				return fmt.Errorf("proof signature does not verify")
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
			return fmt.Errorf("proof signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unsupported DPoP alg %q", alg)
}

func hashFor(alg string) (crypto.Hash, error) {
	switch {
	case strings.HasSuffix(alg, "256"):
		return crypto.SHA256, nil
	case strings.HasSuffix(alg, "384"):
		return crypto.SHA384, nil
	case strings.HasSuffix(alg, "512"):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported DPoP alg %q", alg)
}

func hashBytes(h crypto.Hash, b []byte) []byte {
	hasher := h.New()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func ecdsaFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
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

func rsaFromJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	if kty, _ := jwk["kty"].(string); kty != "RSA" {
		return nil, fmt.Errorf("proof alg is RS*/PS* but the JWK kty is not RSA")
	}
	n, err := b64urlBigInt(jwk, "n")
	if err != nil {
		return nil, err
	}
	eBytes, err := b64urlDecode(str(jwk["e"]))
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
	raw, err := b64urlDecode(str(jwk[field]))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("proof JWK field %q is not base64url", field)
	}
	return new(big.Int).SetBytes(raw), nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// accessTokenHash is the RFC 9449 `ath`: base64url(SHA-256(access token)).
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// constantTimeEqual avoids leaking where two values diverge.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// replayCache rejects a DPoP `jti` seen before, within the proof-acceptance window.
// Bounded so a flood of unique jtis cannot grow it without limit.
type replayCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	maxSize int
}

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{seen: make(map[string]time.Time), ttl: ttl, maxSize: 100_000}
}

// observe records jti and reports whether it is fresh (true) or a replay (false).
func (r *replayCache) observe(jti string, now time.Time) bool {
	if jti == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if at, ok := r.seen[jti]; ok && now.Sub(at) < r.ttl {
		return false
	}
	if len(r.seen) >= r.maxSize {
		for k, at := range r.seen {
			if now.Sub(at) >= r.ttl {
				delete(r.seen, k)
			}
		}
		// Still full of live entries: refuse rather than grow without bound. Failing
		// closed under a jti flood is the safe direction.
		if len(r.seen) >= r.maxSize {
			return false
		}
	}
	r.seen[jti] = now
	return true
}

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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

func hashFor(alg string) (crypto.Hash, error)                   { return jose.HashFor(alg) }
func hashBytes(h crypto.Hash, b []byte) []byte                  { return jose.HashBytes(h, b) }
func ecdsaFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) { return jose.ECDSAFromJWK(jwk) }
func rsaFromJWK(jwk map[string]any) (*rsa.PublicKey, error)     { return jose.RSAFromJWK(jwk) }

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

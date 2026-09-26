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
// the server; 300s is the commonly deployed value. dpopMaxSkew bounds how far in the
// future it may be: clock skew, not a licence to mint proofs for later.
const (
	dpopMaxAge  = 300 * time.Second
	dpopMaxSkew = 60 * time.Second
)

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

// accessTokenHash is the RFC 9449 `ath`: base64url(SHA-256(access token)).
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// constantTimeEqual avoids leaking where two values diverge.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// replayCache rejects a DPoP proof (jkt, jti) seen before, for as long as that proof
// could still be accepted: until its iat plus the acceptance window.
//
// It must not be a lever against everyone else. The old cache refused every new proof
// once it held 100k live entries — about 333 proofs a second per replica — so heavy
// traffic, or one client minting fresh jtis, switched DPoP off for all. Now a single key
// is held to maxPerKey live proofs (that client is refused, nobody else), and at the
// global cap the entries closest to expiry are dropped instead of new proofs refused:
// dropping an old entry reopens replay of that one proof for its last seconds, refusing
// new proofs is an outage.
type replayCache struct {
	mu        sync.Mutex
	window    time.Duration
	maxSize   int
	maxPerKey int
	seen      map[string]int64 // jkt|jti -> expiry, unix seconds
	perKey    map[string]int   // jkt -> live entries
	buckets   map[int64][]string
	oldest    int64 // no bucket below this second holds entries
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{window: window, maxSize: 500_000, maxPerKey: 20_000,
		seen: map[string]int64{}, perKey: map[string]int{}, buckets: map[int64][]string{}}
}

// observe records the proof and reports whether it is fresh (true) or a replay, or a
// key over its quota (false).
func (r *replayCache) observe(jkt, jti string, iat, now time.Time) bool {
	if jti == "" {
		return false
	}
	key := jkt + "|" + jti
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now.Unix())
	if _, dup := r.seen[key]; dup {
		return false
	}
	if r.perKey[jkt] >= r.maxPerKey {
		return false
	}
	for len(r.seen) >= r.maxSize {
		r.dropOldestLocked()
	}
	// Held until the proof could no longer pass the iat check — later of now and iat,
	// plus the window — so a future-dated proof cannot be replayed once its entry lapses.
	from := now
	if iat.After(from) {
		from = iat
	}
	exp := from.Add(r.window).Unix() + 1
	r.seen[key] = exp
	r.perKey[jkt]++
	r.buckets[exp] = append(r.buckets[exp], key)
	if exp < r.oldest || r.oldest == 0 {
		r.oldest = exp
	}
	return true
}

// expireLocked drops every bucket that has lapsed. Buckets are one second wide, so this
// walks at most the seconds since the last call.
func (r *replayCache) expireLocked(now int64) {
	if r.oldest == 0 {
		return
	}
	for sec := r.oldest; sec <= now; sec++ {
		r.dropBucketLocked(sec)
		r.oldest = sec + 1
	}
}

func (r *replayCache) dropOldestLocked() {
	for len(r.buckets) > 0 {
		if _, ok := r.buckets[r.oldest]; ok {
			r.dropBucketLocked(r.oldest)
			return
		}
		r.oldest++
	}
}

func (r *replayCache) dropBucketLocked(sec int64) {
	for _, key := range r.buckets[sec] {
		if r.seen[key] != sec {
			continue
		}
		delete(r.seen, key)
		jkt, _, _ := strings.Cut(key, "|")
		if r.perKey[jkt]--; r.perKey[jkt] <= 0 {
			delete(r.perKey, jkt)
		}
	}
	delete(r.buckets, sec)
}

package main

// Access-token validation.
//
// The COAZ-MCP binding is explicit: "The access token ... MUST be validated by the PEP
// before its claims are used. The PEP MUST verify the token signature, issuer, audience,
// and expiration." Decoding is not validating.
//
// This matters twice over here. The obvious case is the access token. The sharper one is
// X-User-Token: its claims feed user_scope, user_acr, authorization_details and the
// consented-amount cap, which are exactly the inputs the step-up and consent gates turn
// on. Unverified, a forged X-User-Token walks straight through those gates.
//
// Verification is enabled by configuration. When a validator is configured it FAILS
// CLOSED; when it is not, tokens are decoded as before and main() warns at startup. That
// keeps an unconfigured deployment running while making the gap loud, rather than
// silently shipping a bypass.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Validator verifies compact JWTs against a JWKS and checks the registered claims.
type Validator struct {
	issuer   string
	audience string
	jwks     *jwksCache
	// leeway absorbs clock skew on exp/nbf.
	leeway time.Duration
}

// ValidatorConfig is the configuration for one token validator.
type ValidatorConfig struct {
	JWKSURL  string
	Issuer   string
	Audience string
	Leeway   time.Duration
	Client   *http.Client
}

// NewValidator returns nil when no JWKS URL is configured — the caller treats a nil
// validator as "not configured" and falls back to decoding, having warned.
func NewValidator(cfg ValidatorConfig) *Validator {
	if cfg.JWKSURL == "" {
		return nil
	}
	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = 60 * time.Second
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Validator{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		leeway:   leeway,
		jwks:     &jwksCache{url: cfg.JWKSURL, client: client, ttl: 10 * time.Minute},
	}
}

// Validate verifies signature, issuer, audience and expiry, returning the claims.
func (v *Validator) Validate(ctx context.Context, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token is not a compact JWS")
	}
	hdr := jwtHeader(token)
	if hdr == nil {
		return nil, fmt.Errorf("token header is not readable")
	}
	alg := claimString(hdr, "alg")
	// "none" would let a caller assert any claims at all.
	if alg == "" || strings.EqualFold(alg, "none") {
		return nil, fmt.Errorf("token alg %q is not acceptable", alg)
	}
	kid := claimString(hdr, "kid")

	jwk, err := v.jwks.key(ctx, kid)
	if err != nil {
		return nil, err
	}
	if err := verifyJWS(token, jwk, alg); err != nil {
		return nil, err
	}

	claims := jwtClaims(token)
	if claims == nil {
		return nil, fmt.Errorf("token claims are not readable")
	}
	now := time.Now()
	if exp, ok := numericClaim(claims, "exp"); ok {
		if now.After(time.Unix(int64(exp), 0).Add(v.leeway)) {
			return nil, fmt.Errorf("token has expired")
		}
	} else {
		return nil, fmt.Errorf("token has no exp claim")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok {
		if now.Before(time.Unix(int64(nbf), 0).Add(-v.leeway)) {
			return nil, fmt.Errorf("token is not yet valid")
		}
	}
	if v.issuer != "" && claimString(claims, "iss") != v.issuer {
		return nil, fmt.Errorf("token issuer does not match the configured issuer")
	}
	if v.audience != "" && !audienceContains(claims["aud"], v.audience) {
		return nil, fmt.Errorf("token audience does not include %q", v.audience)
	}
	return claims, nil
}

// audienceContains handles `aud` as either a string or an array, per RFC 7519.
func audienceContains(aud any, want string) bool {
	switch t := aud.(type) {
	case string:
		return t == want
	case []any:
		for _, v := range t {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// verifyJWS checks a compact JWS against one JWK. Shares the key parsing and signature
// verification used for DPoP proofs.
func verifyJWS(token string, jwk map[string]any, alg string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token is not a compact JWS")
	}
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return fmt.Errorf("token signature is not base64url")
	}
	hash, err := hashFor(alg)
	if err != nil {
		return err
	}
	digest := hashBytes(hash, []byte(parts[0]+"."+parts[1]))

	switch {
	case strings.HasPrefix(alg, "ES"):
		pub, err := ecdsaFromJWK(jwk)
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
		pub, err := rsaFromJWK(jwk)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return fmt.Errorf("token signature does not verify")
		}
		return nil
	case strings.HasPrefix(alg, "RS"):
		pub, err := rsaFromJWK(jwk)
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

// jwksCache fetches and caches a JWKS, refreshing on an unknown kid (key rotation) but
// no more often than minRefresh, so an attacker cannot use bogus kids to force traffic.
type jwksCache struct {
	url    string
	client *http.Client
	ttl    time.Duration

	mu          sync.Mutex
	keys        map[string]map[string]any
	fetchedAt   time.Time
	lastAttempt time.Time
}

const minJWKSRefresh = 30 * time.Second

func (c *jwksCache) key(ctx context.Context, kid string) (map[string]any, error) {
	c.mu.Lock()
	fresh := c.keys != nil && time.Since(c.fetchedAt) < c.ttl
	if fresh {
		if k, ok := c.lookupLocked(kid); ok {
			c.mu.Unlock()
			return k, nil
		}
	}
	canRefresh := time.Since(c.lastAttempt) >= minJWKSRefresh
	c.mu.Unlock()

	if !fresh || canRefresh {
		if err := c.refresh(ctx); err != nil {
			c.mu.Lock()
			k, ok := c.lookupLocked(kid)
			c.mu.Unlock()
			if ok {
				return k, nil // serve a stale-but-known key rather than failing every request
			}
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.lookupLocked(kid); ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key in the JWKS matches kid %q", kid)
}

// lookupLocked returns the keyed entry, or the only key when the token names no kid.
func (c *jwksCache) lookupLocked(kid string) (map[string]any, bool) {
	if c.keys == nil {
		return nil, false
	}
	if kid != "" {
		k, ok := c.keys[kid]
		return k, ok
	}
	if len(c.keys) == 1 {
		for _, k := range c.keys {
			return k, true
		}
	}
	// With several keys and no kid there is no safe choice.
	return nil, false
}

func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	c.lastAttempt = time.Now()
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("JWKS is not valid JSON: %w", err)
	}
	keys := make(map[string]map[string]any, len(doc.Keys))
	for _, k := range doc.Keys {
		if use, _ := k["use"].(string); use == "enc" {
			continue // encryption keys never verify a signature
		}
		kid, _ := k["kid"].(string)
		keys[kid] = k
	}
	if len(keys) == 0 {
		return fmt.Errorf("JWKS contained no usable signing keys")
	}
	c.mu.Lock()
	c.keys, c.fetchedAt = keys, time.Now()
	c.mu.Unlock()
	return nil
}

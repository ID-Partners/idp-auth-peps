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
// Verification is enabled by configuration and FAILS CLOSED. main() refuses to start
// without it unless PEP_ALLOW_INSECURE is set, in which case tokens are decoded.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// verifyJWS checks a compact JWS against one JWK. Shares the key parsing and signature
// verification used for DPoP proofs.
func verifyJWS(token string, jwk map[string]any, alg string) error {
	return jose.VerifyJWS(token, jwk, alg)
}

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
	// MaxStale bounds how long keys are trusted past their refresh time while the JWKS
	// endpoint keeps failing (default an hour).
	MaxStale time.Duration
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
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: noRedirects}
	}
	return &Validator{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		leeway:   leeway,
		jwks:     &jwksCache{url: cfg.JWKSURL, client: client, ttl: 10 * time.Minute, maxStale: cfg.MaxStale},
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

// jwksCache holds one JWKS. The keys are refreshed OFF the request path: a request that
// finds them stale is served from the cache and starts one background refresh, so a slow
// or failing JWKS endpoint costs nothing but freshness — until maxStale, after which the
// old keys are no longer trusted (a key the issuer withdrew must stop verifying). Only a
// cold cache, or a kid the cache has never seen, makes a request wait for a fetch, and
// then every concurrent request waits for the SAME fetch.
type jwksCache struct {
	url    string
	client *http.Client
	ttl    time.Duration
	// maxStale bounds how long past ttl the keys are served while refreshes fail.
	maxStale time.Duration

	mu        sync.Mutex
	keys      map[string]map[string]any
	fetchedAt time.Time
	// flight is the fetch in progress, shared by everyone who needs it.
	flight *jwksFlight
	// nextAttempt holds refreshes back after a failure (exponential, capped), and after
	// an unknown-kid fetch (minJWKSRefresh), so neither a dead endpoint nor a stream of
	// made-up kids turns into a stream of fetches.
	nextAttempt time.Time
	failures    int
}

type jwksFlight struct {
	done chan struct{}
	err  error
}

const (
	minJWKSRefresh  = 30 * time.Second
	maxJWKSBackoff  = 5 * time.Minute
	defaultMaxStale = time.Hour
	// maxJWKSKeys bounds the set: a real issuer publishes a handful.
	maxJWKSKeys = 64
)

func (c *jwksCache) key(ctx context.Context, kid string) (map[string]any, error) {
	c.mu.Lock()
	now := time.Now()
	age := now.Sub(c.fetchedAt)
	if c.keys != nil && age < c.ttl+c.maxStaleOrDefault() {
		k, ok := c.lookupLocked(kid)
		if age >= c.ttl && !now.Before(c.nextAttempt) {
			c.startLocked() // stale: refresh in the background, serve what we have
		}
		if ok {
			c.mu.Unlock()
			return k, nil
		}
		// An unknown kid may be a rotation the cache has not seen yet — but only worth a
		// fetch if one has not just been made.
		if now.Before(c.nextAttempt) {
			c.mu.Unlock()
			return nil, fmt.Errorf("no key in the JWKS matches kid %q", kid)
		}
	}
	f := c.startLocked()
	c.mu.Unlock()

	select {
	case <-f.done:
	case <-ctx.Done():
		return nil, fmt.Errorf("JWKS fetch: %w", ctx.Err())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl+c.maxStaleOrDefault() {
		if k, ok := c.lookupLocked(kid); ok {
			return k, nil
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return nil, fmt.Errorf("no key in the JWKS matches kid %q", kid)
}

// ready loads the keys once, for the readiness probe.
func (c *jwksCache) ready(ctx context.Context) error {
	c.mu.Lock()
	if c.keys != nil {
		c.mu.Unlock()
		return nil
	}
	f := c.startLocked()
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *jwksCache) maxStaleOrDefault() time.Duration {
	if c.maxStale > 0 {
		return c.maxStale
	}
	return defaultMaxStale
}

// startLocked returns the fetch in flight, starting one if there is none. The fetch runs
// on its own context: the request that started it may give up, the fetch should not.
func (c *jwksCache) startLocked() *jwksFlight {
	if c.flight != nil {
		return c.flight
	}
	f := &jwksFlight{done: make(chan struct{})}
	c.flight = f
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		keys, err := c.fetch(ctx)
		c.mu.Lock()
		now := time.Now()
		if err == nil {
			c.keys, c.fetchedAt, c.failures = keys, now, 0
			c.nextAttempt = now.Add(minJWKSRefresh)
		} else {
			c.failures++
			backoff := minJWKSRefresh << min(c.failures-1, 4)
			if backoff > maxJWKSBackoff {
				backoff = maxJWKSBackoff
			}
			c.nextAttempt = now.Add(backoff)
		}
		f.err = err
		c.flight = nil
		c.mu.Unlock()
		close(f.done)
	}()
	return f
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

func (c *jwksCache) fetch(ctx context.Context) (map[string]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("JWKS is not valid JSON: %w", err)
	}
	if len(doc.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("JWKS holds %d keys, more than the %d accepted", len(doc.Keys), maxJWKSKeys)
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
		return nil, fmt.Errorf("JWKS contained no usable signing keys")
	}
	return keys, nil
}

package federation

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// EntityTypeResource is the OpenID Federation Entity Type for a protected resource.
const EntityTypeResource = "oauth_resource"

// ProtectedResourceWellKnown is RFC 9728's well-known segment, inserted after the host.
const ProtectedResourceWellKnown = "/.well-known/oauth-protected-resource"

// Entity is the federation identity of a protected resource, held by the PEP that
// fronts it: a key, an identifier, and who vouches for it. It publishes two documents.
//
// The Entity Configuration (/.well-known/openid-federation) is deliberately minimal —
// keys, authority_hints, and the entity type — because it is what a trust controller
// fetches to onboard the resource, and nothing about the resource's policy should have
// to be maintained on the PEP. The controller says what the resource requires and which
// PDP decides for it, in the Subordinate Statement it issues.
//
// The protected resource metadata (RFC 9728) republishes what the federation resolved:
// the PEP walks its own chain and serves the result, so a plain RFC 9728 consumer reads
// the federation's word without knowing there is a federation. Until the controller has
// onboarded the entity, the document is self-asserted from Asserted. Either way it
// carries signed_metadata, signed with the same key the Entity Configuration is, and
// metadata_source ("federation" or "self") inside the signature, so the signature says
// whose word it carries; jwks_uri names the key set that verifies it, served at
// JWKSPath. The signed claims are metadata and nothing else: no parameter a superior
// resolved can make the entity sign a JWT that reads as an assertion about someone,
// for someone, or forever.
type Entity struct {
	// ID is the entity identifier: the resource identifier, an https URL.
	ID string
	// Key signs both documents. Its public half is the entity's Federation Entity Key.
	Key crypto.Signer
	// AuthorityHints names the superiors a trust controller may be reached through.
	AuthorityHints []string
	// Asserted is what the RFC 9728 document carries before the federation has
	// spoken: typically nothing beyond the PDP the PEP is configured with.
	Asserted map[string]any
	// Resolver walks the entity's own chain so the RFC 9728 document can republish
	// the resolved metadata. Nil publishes Asserted, always.
	Resolver *Resolver
	// Lifetime of each Entity Configuration minted. Default 24h.
	Lifetime time.Duration
	// MetadataLifetime is how long each signed_metadata is valid: short, because the
	// document is re-signed on every request and a copy should not outlive what it
	// says. Never past the resolved chain's expiry. Default 10m.
	MetadataLifetime time.Duration
	// Logf receives one line when resolution fails; nil discards.
	Logf func(string, ...any)
	// Now is the clock; tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	jwk     map[string]any
	alg     string
	minted  string
	until   time.Time
	lastLog string
}

// logOnce logs a resolution failure the first time it is seen, not on every fetch
// while the failure is still cached.
func (e *Entity) logOnce(msg string) {
	e.mu.Lock()
	changed := msg != e.lastLog
	e.lastLog = msg
	e.mu.Unlock()
	if changed {
		e.logf("%s", msg)
	}
}

func (e *Entity) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Entity) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

func (e *Entity) keys() (map[string]any, string, error) {
	if e.jwk != nil {
		return e.jwk, e.alg, nil
	}
	jwk, err := jose.PublicJWK(e.Key)
	if err != nil {
		return nil, "", err
	}
	alg, err := jose.AlgFor(e.Key)
	if err != nil {
		return nil, "", err
	}
	e.jwk, e.alg = jwk, alg
	return jwk, alg, nil
}

// PublicJWK is the entity's Federation Entity Key, kid included.
func (e *Entity) PublicJWK() (map[string]any, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	jwk, _, err := e.keys()
	return jwk, err
}

// Paths are where the two documents live for this identifier, per each spec's rule:
// OpenID Federation appends its well-known segment to the identifier's path; RFC 9728
// inserts its own after the host and keeps the identifier's path after it.
func (e *Entity) Paths() (federationPath, resourcePath string) {
	path := ""
	if u, err := url.Parse(e.ID); err == nil {
		path = strings.TrimRight(u.Path, "/")
	}
	return path + WellKnown, ProtectedResourceWellKnown + path
}

// JWKSPath is where Handler serves the entity's public key set: beside its RFC 9728
// document, so a gateway that already routes that document's prefix to the PEP routes
// this too. (It is also where the metadata of a resource at {ID}/jwks.json would live,
// under RFC 9728's path insertion; a PEP that fronts such a resource must not also be
// its entity.)
func (e *Entity) JWKSPath() string {
	_, res := e.Paths()
	return res + "/jwks.json"
}

// JWKSURL is JWKSPath on the entity's own origin: what the RFC 9728 document
// advertises as jwks_uri. Empty when ID does not parse.
func (e *Entity) JWKSURL() string {
	u, err := url.Parse(e.ID)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + e.JWKSPath()
}

// JWKS is the entity's public key set (RFC 7517 §5): the Federation Entity Key that
// signs both documents, marked for signatures under the one alg it signs with.
func (e *Entity) JWKS() ([]byte, error) {
	e.mu.Lock()
	jwk, alg, err := e.keys()
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	pub := map[string]any{"use": "sig", "alg": alg}
	for k, v := range jwk {
		pub[k] = v
	}
	return json.Marshal(map[string]any{"keys": []any{pub}})
}

// Configuration mints (and briefly caches) the signed Entity Configuration.
func (e *Entity) Configuration() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if e.minted != "" && now.Before(e.until) {
		return e.minted, nil
	}
	jwk, alg, err := e.keys()
	if err != nil {
		return "", err
	}
	lifetime := e.Lifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	hints := make([]any, 0, len(e.AuthorityHints))
	for _, h := range e.AuthorityHints {
		hints = append(hints, h)
	}
	claims := map[string]any{
		"iss": e.ID, "sub": e.ID,
		"iat": now.Unix(), "exp": now.Add(lifetime).Unix(),
		"jwks":            map[string]any{"keys": []any{jwk}},
		"authority_hints": hints,
		// The entity type, and nothing the controller would rather maintain itself.
		"metadata": map[string]any{EntityTypeResource: map[string]any{"resource": e.ID}},
	}
	tok, err := jose.Sign(map[string]any{"alg": alg, "typ": typEntityStatement, "kid": jwk["kid"]}, claims, e.Key)
	if err != nil {
		return "", err
	}
	e.minted, e.until = tok, now.Add(lifetime/2)
	return tok, nil
}

// ProtectedResourceMetadata is the RFC 9728 document: the federation's resolved
// oauth_resource metadata when the chain validates, Asserted otherwise, with
// signed_metadata either way. Source is "federation" or "self", and the document
// carries it as metadata_source, signed.
func (e *Entity) ProtectedResourceMetadata(ctx context.Context) (doc map[string]any, source string, err error) {
	params := e.Asserted
	source = "self"
	now := e.now()
	lifetime := e.MetadataLifetime
	if lifetime <= 0 {
		lifetime = 10 * time.Minute
	}
	exp := now.Add(lifetime)
	if e.Resolver != nil {
		ec, err := e.Configuration()
		if err != nil {
			return nil, "", err
		}
		res, err := e.Resolver.ResolveLeaf(ctx, ec)
		switch {
		case err != nil:
			e.logOnce(fmt.Sprintf("federation entity %s: chain did not resolve, publishing self-asserted metadata: %v", e.ID, err))
		case res.Metadata[EntityTypeResource] == nil:
			e.logOnce(fmt.Sprintf("federation entity %s: chain resolved but carries no %s metadata, publishing self-asserted metadata", e.ID, EntityTypeResource))
		default:
			e.logOnce(fmt.Sprintf("federation entity %s: chain resolved via %s, publishing the federation's metadata", e.ID, res.TrustAnchor))
			params, source = res.Metadata[EntityTypeResource], "federation"
			if res.ExpiresAt.Before(exp) {
				exp = res.ExpiresAt // never outlive the chain that said it
			}
		}
	}
	doc = map[string]any{}
	for k, v := range params {
		if !notMetadata[k] {
			doc[k] = v
		}
	}
	// The identifier is not the controller's to change, the key set is the one that
	// verifies the signature below, and whose word this is belongs inside it.
	doc["resource"] = e.ID
	delete(doc, "jwks_uri")
	if uri := e.JWKSURL(); uri != "" {
		doc["jwks_uri"] = uri
	}
	doc["metadata_source"] = source
	signed, err := e.signMetadata(doc, now, exp)
	if err != nil {
		return nil, "", err
	}
	doc["signed_metadata"] = signed
	return doc, source, nil
}

// notMetadata are the names a resolved parameter may not take in the document or its
// signature. The JWT-registered claims (RFC 7519 §4.1) decide what a JWT is — who it
// is from and about, who it is for, when it is valid, whether it is a replay — and the
// rest make a JWT a credential when presented as one. A superior's metadata or a
// policy value could otherwise have the entity sign, and publish, a well-formed client
// assertion or access token with its federation key. None of them is an RFC 9728
// parameter; signed_metadata must not nest.
var notMetadata = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"cnf": true, "nonce": true, "scope": true, "client_id": true, "azp": true, "act": true,
	"may_act": true, "acr": true, "amr": true, "auth_time": true, "signed_metadata": true,
}

// signMetadata is RFC 9728 §2.1's signed_metadata: the document's parameters as claims
// of a JWT issued by the resource, signed with the Federation Entity Key. iss, iat and
// exp are set last, so nothing in doc can supply them.
func (e *Entity) signMetadata(doc map[string]any, now, exp time.Time) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	jwk, alg, err := e.keys()
	if err != nil {
		return "", err
	}
	claims := make(map[string]any, len(doc)+3)
	for k, v := range doc {
		claims[k] = v
	}
	claims["iss"], claims["iat"], claims["exp"] = e.ID, now.Unix(), exp.Unix()
	return jose.Sign(map[string]any{"alg": alg, "typ": "JWT", "kid": jwk["kid"]}, claims, e.Key)
}

// Handler serves both documents at Paths(), the key set at JWKSPath(), and nothing else.
func (e *Entity) Handler() http.Handler {
	fedPath, resPath := e.Paths()
	jwksPath := e.JWKSPath()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case fedPath:
			tok, err := e.Configuration()
			if err != nil {
				http.Error(w, "entity configuration unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write([]byte(tok))
		case resPath:
			doc, source, err := e.ProtectedResourceMetadata(r.Context())
			if err != nil {
				http.Error(w, "protected resource metadata unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-cache")
			// A hint on the wire, for operators; the signed claim is the one to trust.
			w.Header().Set("X-Resource-Metadata-Source", source)
			_ = json.NewEncoder(w).Encode(doc)
		case jwksPath:
			set, err := e.JWKS()
			if err != nil {
				http.Error(w, "key set unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/jwk-set+json")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(set)
		default:
			http.NotFound(w, r)
		}
	})
}

// String names the entity for logs.
func (e *Entity) String() string { return fmt.Sprintf("federation entity %s", e.ID) }

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
// onboarded the entity, the document is self-asserted from Asserted, and says so only
// by carrying no more than that. Either way it carries signed_metadata, signed with the
// same key the Entity Configuration is.
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
// signed_metadata either way. Source is "federation" or "self".
func (e *Entity) ProtectedResourceMetadata(ctx context.Context) (doc map[string]any, source string, err error) {
	doc = map[string]any{"resource": e.ID}
	for k, v := range e.Asserted {
		doc[k] = v
	}
	source = "self"
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
			doc = map[string]any{}
			for k, v := range res.Metadata[EntityTypeResource] {
				doc[k] = v
			}
			// The identifier is not the controller's to change, and signed_metadata
			// must not nest.
			doc["resource"] = e.ID
			delete(doc, "signed_metadata")
			source = "federation"
		}
	}
	signed, err := e.signMetadata(doc)
	if err != nil {
		return nil, "", err
	}
	doc["signed_metadata"] = signed
	return doc, source, nil
}

// signMetadata is RFC 9728 §2.1's signed_metadata: the document's parameters as claims
// of a JWT whose iss is the resource, signed with the Federation Entity Key.
func (e *Entity) signMetadata(doc map[string]any) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	jwk, alg, err := e.keys()
	if err != nil {
		return "", err
	}
	claims := map[string]any{"iss": e.ID, "iat": e.now().Unix()}
	for k, v := range doc {
		if k != "signed_metadata" {
			claims[k] = v
		}
	}
	return jose.Sign(map[string]any{"alg": alg, "typ": "JWT", "kid": jwk["kid"]}, claims, e.Key)
}

// Handler serves both documents at Paths(), and nothing else.
func (e *Entity) Handler() http.Handler {
	fedPath, resPath := e.Paths()
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
			// Not a parameter of the document — a hint on the wire, for operators.
			w.Header().Set("X-Resource-Metadata-Source", source)
			_ = json.NewEncoder(w).Encode(doc)
		default:
			http.NotFound(w, r)
		}
	})
}

// String names the entity for logs.
func (e *Entity) String() string { return fmt.Sprintf("federation entity %s", e.ID) }

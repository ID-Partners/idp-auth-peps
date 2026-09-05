// Package federation resolves an Entity's Trust Chain under OpenID Federation 1.0
// (Final, February 2026) and returns its Resolved Metadata.
//
// The PEP uses it to learn, for a protected resource that is a federation member, what
// the federation — not the resource itself — says about it. A resource's own
// /.well-known/oauth-protected-resource is a self-assertion; the metadata that survives
// the chain has been constrained by every Superior's metadata_policy and is signed back
// to a Trust Anchor whose keys the operator configured out of band.
//
// Scope: Entity Configuration and Subordinate Statement fetching (§10.1), the §3.2
// validation rules, the §4 chain invariants, §6.1 metadata policy with the seven
// standard operators, and §6.2 constraints. Not in scope: Trust Marks, the resolve
// endpoint, historical keys, and client authentication at federation endpoints.
package federation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
	"github.com/ID-Partners/idp-auth-peps/core/internal/ttlcache"
)

// WellKnown is appended to an Entity Identifier to locate its Entity Configuration.
// Unlike RFC 8414 / RFC 9728 this is a suffix, not an insertion after the host.
const WellKnown = "/.well-known/openid-federation"

const (
	typEntityStatement = "entity-statement+jwt"
	contentType        = "application/entity-statement+jwt"
	entityTypeFedEnt   = "federation_entity"
)

var (
	// ErrNotFederated: the entity publishes no Entity Configuration (404). The caller
	// decides whether that is fine; the PEP falls back to its static PDP.
	ErrNotFederated = errors.New("entity publishes no entity configuration")
	// ErrInvalidChain is permanent: a statement failed validation, an invariant was
	// broken, a constraint or a policy was violated. Never retried within NegativeTTL.
	ErrInvalidChain = errors.New("trust chain invalid")
	// ErrNotAllowed is re-exported so callers can test for a refused fetch.
	ErrNotAllowed = metafetch.ErrNotAllowed
)

// TrustAnchor is a federation root the operator trusts. Keys are the anchor's
// Federation Entity Keys as distributed out of band; its published Entity
// Configuration is verified against these, never against itself.
type TrustAnchor struct {
	EntityID string
	Keys     []map[string]any
}

// Options configures a Resolver.
type Options struct {
	TrustAnchors []TrustAnchor
	HTTPClient   *http.Client
	// Leeway tolerated on iat/exp. Default 60s.
	Leeway time.Duration
	// MaxPathLength bounds the intermediates between subject and anchor. Default 4.
	MaxPathLength int
	// MaxFetches bounds the HTTP requests one resolution may make. Default 16.
	MaxFetches int
	// TTL caps how long a resolved chain is reused; min(exp) over the chain applies
	// as well. Default 5m.
	TTL time.Duration
	// NegativeTTL caches ErrInvalidChain / ErrNotFederated. Default 60s.
	NegativeTTL time.Duration
	// MaxEntries bounds the resolution cache. Default 1024.
	MaxEntries int
	// AllowInsecure permits http Entity Identifiers and endpoints (tests, dev).
	AllowInsecure bool
	// FetchAllowed is the operator's allowlist for every URL touched while walking the
	// chain. Nil means any https host.
	FetchAllowed func(string) bool
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// Resolved is what the federation says about Subject once the chain to TrustAnchor
// has been validated and every Superior's policy applied.
type Resolved struct {
	Subject     string
	TrustAnchor string
	// Metadata is keyed by Entity Type Identifier, then parameter.
	Metadata map[string]map[string]any
	// ExpiresAt is min(exp) over the chain, capped by the TTL.
	ExpiresAt time.Time
	// Chain holds the compact JWTs ES[0]..ES[i], for logs and tests.
	Chain []string
}

// Resolver walks and validates Trust Chains, caching the result per subject.
type Resolver struct {
	opts    Options
	anchors map[string]TrustAnchor
	order   map[string]int
	fetch   *metafetch.Client
	cache   *ttlcache.Cache[Resolved]
}

// New builds a Resolver. At least one Trust Anchor is required; without one there is
// nothing a chain could end at.
func New(o Options) (*Resolver, error) {
	if len(o.TrustAnchors) == 0 {
		return nil, errors.New("federation: at least one trust anchor is required")
	}
	if o.Leeway <= 0 {
		o.Leeway = 60 * time.Second
	}
	if o.MaxPathLength <= 0 {
		o.MaxPathLength = 4
	}
	if o.MaxFetches <= 0 {
		o.MaxFetches = 16
	}
	if o.TTL <= 0 {
		o.TTL = 5 * time.Minute
	}
	if o.NegativeTTL <= 0 {
		o.NegativeTTL = 60 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	r := &Resolver{opts: o, anchors: map[string]TrustAnchor{}, order: map[string]int{}}
	for i, ta := range o.TrustAnchors {
		if ta.EntityID == "" || len(ta.Keys) == 0 {
			return nil, fmt.Errorf("federation: trust anchor %d needs an entity id and keys", i)
		}
		if _, dup := r.anchors[ta.EntityID]; dup {
			return nil, fmt.Errorf("federation: trust anchor %s listed twice", ta.EntityID)
		}
		r.anchors[ta.EntityID] = ta
		r.order[ta.EntityID] = i
	}
	r.fetch = metafetch.New(o.HTTPClient, metafetch.Policy{AllowInsecure: o.AllowInsecure, Allow: o.FetchAllowed}, "", 0)
	r.cache = ttlcache.New[Resolved](ttlcache.Options{
		TTL: o.TTL, NegativeTTL: o.NegativeTTL, MaxEntries: o.MaxEntries, Now: o.Now,
	})
	return r, nil
}

// Resolve returns the Resolved Metadata for entityID, from cache when fresh.
func (r *Resolver) Resolve(ctx context.Context, entityID string) (Resolved, error) {
	return r.cache.Get(ctx, entityID, func(ctx context.Context, id string) (Resolved, time.Time, error) {
		res, err := r.resolve(ctx, id)
		if err != nil {
			return Resolved{}, time.Time{}, err
		}
		return res, res.ExpiresAt, nil
	})
}

// Status snapshots the resolution cache.
func (r *Resolver) Status() map[string]ttlcache.EntryStatus { return r.cache.Status() }

func (r *Resolver) resolve(ctx context.Context, entityID string) (Resolved, error) {
	chain, anchor, err := r.walk(ctx, entityID)
	if err != nil {
		return Resolved{}, err
	}
	if err := checkConstraints(chain); err != nil {
		return Resolved{}, fmt.Errorf("%w: %v", ErrInvalidChain, err)
	}
	meta, err := resolveMetadata(chain)
	if err != nil {
		return Resolved{}, fmt.Errorf("%w: %v", ErrInvalidChain, err)
	}
	out := Resolved{Subject: entityID, TrustAnchor: anchor, Metadata: meta}
	for _, st := range chain {
		out.Chain = append(out.Chain, st.Raw)
		if out.ExpiresAt.IsZero() || st.Exp.Before(out.ExpiresAt) {
			out.ExpiresAt = st.Exp
		}
	}
	return out, nil
}

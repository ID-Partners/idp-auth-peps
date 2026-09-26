package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/federation"
)

// resolverAt is the miniFed resolver on a test clock.
func (f *miniFed) resolverAt(t *testing.T, o federation.Options) *federation.Resolver {
	t.Helper()
	o.TrustAnchors = []federation.TrustAnchor{{EntityID: f.anchor.URL, Keys: []map[string]any{f.anchorJWK}}}
	o.AllowInsecure = true
	r, err := federation.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// P1, through discovery: once the leaf's chain stops validating, the next refresh is a
// refusal — not the last good chain, and not the static PDP.
func TestAnInvalidChainIsNotServedFromCache(t *testing.T) {
	good := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	f := newMiniFed(t)
	f.leafPDPs = []any{good.URL}
	now := time.Now()
	clock := func() time.Time { return now }
	c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, TTL: time.Minute, Now: clock,
		Federation: f.resolverAt(t, federation.Options{TTL: time.Minute, Now: clock})})
	if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != good.URL {
		t.Fatalf("%+v %v", ep, err)
	}
	f.breakLeafSig = true
	now = now.Add(61 * time.Second)
	ep, err := c.Resolve(ctx(), f.leaf.URL)
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("the invalid chain must be refused, not served stale: %+v %v", ep, err)
	}
	if s := c.Status().Resources[f.leaf.URL]; s.Cached {
		t.Fatalf("the refusal evicts the cached metadata: %+v", s)
	}
}

// The resolved metadata is held no longer than the chain it came from: discovery's own
// TTL used to hold even a short-lived chain for the whole TTL, because the chain's
// expiry never made it out of lookupResource.
func TestResolvedMetadataIsHeldNoLongerThanItsChain(t *testing.T) {
	good := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	f := newMiniFed(t)
	f.leafPDPs = []any{good.URL}
	now := time.Now()
	clock := func() time.Time { return now }
	fed := f.resolverAt(t, federation.Options{TTL: 3 * time.Hour, Now: clock})
	c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, TTL: 3 * time.Hour, Now: clock, Federation: fed})
	ep, err := c.Resolve(ctx(), f.leaf.URL)
	if err != nil || ep.Identifier != good.URL || ep.Resource == nil || ep.Resource.ExpiresAt.IsZero() {
		t.Fatalf("%+v %v", ep, err)
	}
	f.leafStatus = 500 // the leaf is down when the chain expires
	now = ep.Resource.ExpiresAt.Add(time.Second)
	if ep, err := c.Resolve(ctx(), f.leaf.URL); err == nil && ep.Identifier == good.URL {
		t.Fatalf("metadata from an expired chain must not be served: %+v", ep)
	}
}

// P8, through discovery: a cancelled request used to be cached as the resource's answer
// for 30s in discovery and 60s in the resolver, pinning the resource to the static PDP.
func TestACancelledRequestDoesNotPinTheResource(t *testing.T) {
	good := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	f := newMiniFed(t)
	f.leafPDPs = []any{good.URL}
	c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, Federation: f.resolver(t)})
	cancelled, cancel := context.WithCancel(ctx())
	cancel()
	c.Resolve(cancelled, f.leaf.URL)
	if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != good.URL {
		t.Fatalf("a cancelled request must not decide for the next one: %+v %v", ep, err)
	}
}

// P1 with a 404, through discovery: the anchor offboards the member. From the next
// refresh the member is outside the federation — the operator's own PDP — rather than
// decided for another MaxStale by a chain the anchor has withdrawn.
func TestAnOffboardedMemberFallsToStatic(t *testing.T) {
	good := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	f := newMiniFed(t)
	f.leafPDPs = []any{good.URL}
	now := time.Now()
	clock := func() time.Time { return now }
	c := mustNew(t, Options{Mode: ModeFederation, StaticPDP: static.URL, TTL: time.Minute, Now: clock,
		Federation: f.resolverAt(t, federation.Options{TTL: time.Minute, Now: clock})})
	if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != good.URL {
		t.Fatalf("%+v %v", ep, err)
	}
	f.ssStatus = 404
	now = now.Add(61 * time.Second) // past the TTL, well inside MaxStale
	if ep, err := c.Resolve(ctx(), f.leaf.URL); err != nil || ep.Identifier != static.URL || ep.Resource != nil {
		t.Fatalf("an offboarded member is not a member: %+v %v", ep, err)
	}
}

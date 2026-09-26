package federation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// P1: a cached chain used to be served forever once refreshes started failing, with
// ExpiresAt long past and ErrInvalidChain never reaching the caller. Revocation or key
// rotation at a superior never reached a running PEP.

// The intermediate's statement about the leaf stops verifying — its key rotated, or it
// was compromised and re-keyed. The next refresh is a refusal, and the stale chain goes.
func TestAnInvalidChainReplacesTheCachedOne(t *testing.T) {
	f := threeLevel(t)
	now := time.Now()
	r := newResolver(t, Options{TTL: time.Minute, NegativeTTL: 30 * time.Second, Now: func() time.Time { return now }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
		t.Fatal(err)
	}
	other := newEntity(t)
	f.mid.ssSign = other.key // same kid, different key: the statement no longer verifies
	now = now.Add(61 * time.Second)
	res, err := r.Resolve(ctx(), f.leaf.id)
	if !errors.Is(err, ErrInvalidChain) || res.Subject != "" {
		t.Fatalf("an invalid chain must replace the cached one, not hide behind it: %+v %v", res, err)
	}
	if st := r.Status()[f.leaf.id]; st.Cached {
		t.Fatalf("the refusal evicts the chain: %+v", st)
	}
	// ResolveLeaf, the entity's own chain, is held to the same rule.
	f2 := threeLevel(t)
	r2 := newResolver(t, Options{TTL: time.Minute, Now: func() time.Time { return now }}, f2.anchor)
	_, ec := get(t, f2.leaf.id+WellKnown)
	if _, err := r2.ResolveLeaf(ctx(), ec); err != nil {
		t.Fatal(err)
	}
	f2.mid.ssSign = newEntity(t).key
	now = now.Add(61 * time.Second)
	if _, err := r2.ResolveLeaf(ctx(), ec); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("the entity's own chain: %v", err)
	}
}

// A chain expires at min(exp) over its statements (§10.4). Past that it is not served,
// however the refresh fails.
func TestAChainIsNotServedPastItsExpiry(t *testing.T) {
	f := threeLevel(t)
	now := time.Now()
	r := newResolver(t, Options{TTL: 2 * time.Hour, Now: func() time.Time { return now }}, f.anchor)
	res, err := r.Resolve(ctx(), f.leaf.id)
	if err != nil {
		t.Fatal(err)
	}
	f.mid.ecStatus = 500 // an outage, not a refusal
	now = res.ExpiresAt.Add(time.Second)
	if res, err := r.Resolve(ctx(), f.leaf.id); err == nil {
		t.Fatalf("a chain past its expiry must not be served stale: %+v", res)
	}
}

// An outage is ridden out on the last good chain — for MaxStale past the TTL, and no
// longer.
func TestStaleServingIsBounded(t *testing.T) {
	f := threeLevel(t)
	now := time.Now()
	r := newResolver(t, Options{TTL: time.Minute, MaxStale: 2 * time.Minute, Now: func() time.Time { return now }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
		t.Fatal(err)
	}
	f.mid.ecStatus = 500
	now = now.Add(2 * time.Minute)
	if res, err := r.Resolve(ctx(), f.leaf.id); err != nil || res.TrustAnchor != f.anchor.id {
		t.Fatalf("inside MaxStale the chain is still served: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := r.Resolve(ctx(), f.leaf.id); err == nil {
		t.Fatal("past MaxStale the chain must not be served")
	}
}

// P8: the shared resolution ran on the first caller's context, and its cancellation was
// cached as the answer for NegativeTTL. One cancelled request then failed every request
// for that entity for a minute.
func TestACancelledRequestDoesNotPoisonTheChain(t *testing.T) {
	f := threeLevel(t)
	r := newResolver(t, Options{}, f.anchor)
	cancelled, cancel := context.WithCancel(ctx())
	cancel()
	r.Resolve(cancelled, f.leaf.id)
	if res, err := r.Resolve(ctx(), f.leaf.id); err != nil || res.Subject != f.leaf.id {
		t.Fatalf("a cancelled request must not decide for the next one: %+v %v", res, err)
	}
}

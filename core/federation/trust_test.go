package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
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

// under reports whether u is id or beneath it: a bare prefix test on test-server URLs
// would let port 5000 match port 50001.
func under(u, id string) bool { return u == id || strings.HasPrefix(u, id+"/") }

// keepFetchEndpoint makes a superior publish its fetch endpoint whether or not it has
// any subordinates left, so that asking it about one it dropped is a 404.
func (e *entity) keepFetchEndpoint() {
	e.ecHook = func(_, c map[string]any) {
		c["metadata"] = map[string]any{entityTypeFedEnt: map[string]any{"federation_fetch_endpoint": e.id + "/fetch"}}
	}
}

// P9: one off-allowlist authority hint anywhere in the search used to end the whole
// resolution with ErrNotAllowed, even when another hint led to a valid chain — so hint
// order decided the answer. A refused hint is a path not taken.
func TestARefusedHintIsAnUnexploredPath(t *testing.T) {
	for _, first := range []bool{true, false} {
		f := threeLevel(t)
		stray := newEntity(t) // a superior on a host the operator does not allow
		if first {
			f.leaf.hints = append([]string{stray.id}, f.leaf.hints...)
		} else {
			f.leaf.hints = append(f.leaf.hints, stray.id)
		}
		r := newResolver(t, Options{FetchAllowed: func(u string) bool { return !under(u, stray.id) }}, f.anchor)
		if res, err := r.Resolve(ctx(), f.leaf.id); err != nil || res.TrustAnchor != f.anchor.id {
			t.Fatalf("refused hint first=%v: a valid chain through another hint must win: %v", first, err)
		}
		if atomic.LoadInt32(&stray.hits) != 0 {
			t.Fatal("a refused hint must not be fetched")
		}
	}
	// With no chain found, a refusal met on the way is the answer.
	f := threeLevel(t)
	r := newResolver(t, Options{FetchAllowed: func(u string) bool { return !under(u, f.anchor.id) }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("no chain, and a refused fetch on the way: %v", err)
	}
}

// P1 with a 404: a superior that no longer knows the subject has offboarded it. That is
// the federation's answer, not an outage to ride out on the cached chain: the next
// refresh reports the entity as not a member, and the chain goes.
func TestAnOffboardedMemberIsNotServedFromCache(t *testing.T) {
	f := threeLevel(t)
	now := time.Now()
	r := newResolver(t, Options{TTL: time.Minute, Now: func() time.Time { return now }}, f.anchor)
	if _, err := r.Resolve(ctx(), f.leaf.id); err != nil {
		t.Fatal(err)
	}
	delete(f.mid.subs, f.leaf.id)
	f.mid.keepFetchEndpoint()
	now = now.Add(61 * time.Second)
	_, err := r.Resolve(ctx(), f.leaf.id)
	if !errors.Is(err, ErrNotFederated) || !strings.Contains(err.Error(), "no trust chain") {
		t.Fatalf("an offboarded member is not a member: %v", err)
	}
	if st := r.Status()[f.leaf.id]; st.Cached {
		t.Fatalf("the cached chain must go: %+v", st)
	}
	// The same when the anchor drops the intermediate: nothing beneath it is vouched for.
	f2 := threeLevel(t)
	r2 := newResolver(t, Options{}, f2.anchor)
	delete(f2.anchor.subs, f2.mid.id)
	f2.anchor.keepFetchEndpoint()
	if _, err := r2.Resolve(ctx(), f2.leaf.id); !errors.Is(err, ErrNotFederated) {
		t.Fatalf("an intermediate the anchor dropped: %v", err)
	}
}

// When no chain is found the reasons are ranked, not taken in whatever order the
// search met them: a path that could not be explored is not proof there is none.
func TestNoChainIsClassifiedNotGuessed(t *testing.T) {
	t.Run("an invalid path and an unreachable one: unavailable, not invalid", func(t *testing.T) {
		f := threeLevel(t)
		down := newEntity(t)
		down.ecStatus = 500
		// Met first, so an answer taken from whatever failed last would say "invalid".
		f.leaf.hints = append([]string{down.id}, f.leaf.hints...)
		f.mid.ssSign = newEntity(t).key
		_, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id)
		if err == nil || errors.Is(err, ErrInvalidChain) || errors.Is(err, ErrNotFederated) {
			t.Fatalf("with a path unexplored the answer is an outage: %v", err)
		}
	})
	t.Run("an invalid path beats a superior that does not know the subject", func(t *testing.T) {
		f := threeLevel(t)
		stranger := newEntity(t)
		stranger.keepFetchEndpoint()
		// Met last, so an answer taken from whatever failed last would say "not found".
		f.leaf.hints = append(f.leaf.hints, stranger.id)
		f.mid.ssSign = newEntity(t).key
		_, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id)
		if !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("a statement that fails validation is not an absence: %v", err)
		}
	})
	t.Run("two refusals: the first met is the one reported", func(t *testing.T) {
		f := threeLevel(t)
		a, b := newEntity(t), newEntity(t)
		f.leaf.hints = []string{a.id, b.id}
		r := newResolver(t, Options{FetchAllowed: func(u string) bool { return !under(u, a.id) && !under(u, b.id) }}, f.anchor)
		_, err := r.Resolve(ctx(), f.leaf.id)
		if !errors.Is(err, ErrNotAllowed) || !strings.Contains(err.Error(), a.id) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an exhausted fetch budget is an invalid chain, not an outage", func(t *testing.T) {
		f := threeLevel(t)
		_, err := newResolver(t, Options{MaxFetches: 2}, f.anchor).Resolve(ctx(), f.leaf.id)
		if !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("%v", err)
		}
	})
}

// The demo's lever: the controller offboards the PEP's own entity. Its RFC 9728 document
// reverts to self-asserted at the next refresh, where it used to keep saying
// "federation" for as long as the refresh kept failing.
func TestAnOffboardedEntityRepublishesItsOwnWord(t *testing.T) {
	anchor := newEntity(t)
	anchor.keepFetchEndpoint()
	e, srv := newHeldEntity(t, anchor)
	now := time.Now()
	e.Resolver = newResolver(t, Options{TTL: time.Minute, NegativeTTL: time.Second, Now: func() time.Time { return now }}, anchor)
	pub, _ := e.PublicJWK()
	anchor.subs[e.ID] = &subordinate{keys: []map[string]any{pub}}
	_, resPath := e.Paths()
	if resp, body := get(t, srv.URL+resPath); resp.Header.Get("X-Resource-Metadata-Source") != "federation" {
		t.Fatalf("onboarded: %s", body)
	}
	delete(anchor.subs, e.ID)
	now = now.Add(61 * time.Second)
	if resp, body := get(t, srv.URL+resPath); resp.Header.Get("X-Resource-Metadata-Source") != "self" {
		t.Fatalf("offboarding must revert at the next refresh: %s", body)
	}
}

// The JOSE rules reach the chain: a statement whose header carries crit, one signed
// under an ES alg that is not its key's curve, and one whose jwks is oversized each
// invalidate the chain.
func TestStatementsAreHeldToTheJOSERules(t *testing.T) {
	cases := map[string]func(f fed){
		"header crit": func(f fed) {
			f.leaf.ecHook = func(h, c map[string]any) { h["crit"] = []any{"exp"}; h["exp"] = 1 }
		},
		"ES384 over a P-256 key": func(f fed) {
			f.leaf.ecHook = func(h, c map[string]any) { h["alg"] = "ES384" }
		},
		"a key set past the cap": func(f fed) {
			f.leaf.ecHook = func(h, c map[string]any) {
				keys := []any{f.leaf.jwk}
				for i := 0; len(keys) <= jose.MaxJWKSKeys; i++ {
					k := map[string]any{}
					for n, v := range f.leaf.jwk {
						k[n] = v
					}
					k["kid"] = fmt.Sprintf("spare-%d", i)
					keys = append(keys, k)
				}
				c["jwks"] = map[string]any{"keys": keys}
			}
		},
	}
	for name, bend := range cases {
		t.Run(name, func(t *testing.T) {
			f := threeLevel(t)
			bend(f)
			if _, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("want ErrInvalidChain, got %v", err)
			}
		})
	}
}

package ttlcache

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The rules that keep a stale value from becoming a trust problem: a value is never
// served past the expiry its fetch returned, stale serving is bounded, and a refusal is
// never masked by a stale value.

var errRefused = errors.New("refused")

func refusal(err error) bool { return errors.Is(err, errRefused) }

// A fetch that answers from a script: each call takes the next step.
type step struct {
	val string
	exp time.Duration // relative to the clock; zero means none
	err error
}

func scripted(ck *clock, steps ...step) (Fetch[string], *int32) {
	var n int32
	return func(_ context.Context, _ string) (string, time.Time, error) {
		i := int(atomic.AddInt32(&n, 1)) - 1
		if i >= len(steps) {
			i = len(steps) - 1
		}
		s := steps[i]
		if s.err != nil {
			return "", time.Time{}, s.err
		}
		var exp time.Time
		if s.exp != 0 {
			exp = ck.now().Add(s.exp)
		}
		return s.val, exp, nil
	}, &n
}

// A Trust Chain expires at min(exp). Once it has, it is not served again, stale or not:
// a refresh failure then is an error, never the expired chain.
func TestHardExpiryIsNeverServedStale(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Hour})
	f, n := scripted(ck, step{val: "chain", exp: 10 * time.Second}, step{err: errors.New("anchor down")})
	if v, err := c.Get(context.Background(), "k", f); err != nil || v != "chain" {
		t.Fatalf("%q %v", v, err)
	}
	ck.tick(11 * time.Second)
	v, err := c.Get(context.Background(), "k", f)
	if err == nil || v != "" {
		t.Fatalf("a value past its own expiry must not be served: %q %v", v, err)
	}
	if *n != 2 {
		t.Fatalf("fetches %d", *n)
	}
}

// Past the soft TTL a stale value rides out an outage for MaxStale, and no longer.
func TestMaxStaleBoundsStaleServing(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute, MaxStale: 2 * time.Minute, MinRefresh: time.Second})
	f, _ := scripted(ck, step{val: "v"}, step{err: errors.New("down")})
	c.Get(context.Background(), "k", f)
	ck.tick(90 * time.Second)
	if v, err := c.Get(context.Background(), "k", f); err != nil || v != "v" {
		t.Fatalf("inside MaxStale the stale value is served: %q %v", v, err)
	}
	ck.tick(2 * time.Minute) // 3m30s after the fetch: past TTL + MaxStale
	if v, err := c.Get(context.Background(), "k", f); err == nil || v != "" {
		t.Fatalf("past MaxStale the stale value must not be served: %q %v", v, err)
	}
}

func TestMaxStaleDefaultsToTheTTLAndNegativeDisablesIt(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute, MinRefresh: time.Second})
	f, _ := scripted(ck, step{val: "v"}, step{err: errors.New("down")})
	c.Get(context.Background(), "k", f)
	ck.tick(119 * time.Second)
	if v, err := c.Get(context.Background(), "k", f); err != nil || v != "v" {
		t.Fatalf("default MaxStale is the TTL: %q %v", v, err)
	}
	ck.tick(2 * time.Second)
	if _, err := c.Get(context.Background(), "k", f); err == nil {
		t.Fatal("past TTL + TTL nothing is served")
	}

	c2, ck2 := newTest(t, Options{TTL: time.Minute, MaxStale: -1})
	f2, _ := scripted(ck2, step{val: "v"}, step{err: errors.New("down")})
	c2.Get(context.Background(), "k", f2)
	ck2.tick(61 * time.Second)
	if _, err := c2.Get(context.Background(), "k", f2); err == nil {
		t.Fatal("a negative MaxStale serves nothing stale")
	}
}

// A refusal is authoritative: the chain no longer validates, the fetch was refused. It
// evicts the value and is returned as it is, and it is remembered for NegativeTTL.
func TestRefusalEvictsAndIsNeverMasked(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute, NegativeTTL: 30 * time.Second, IsRefusal: refusal})
	f, n := scripted(ck, step{val: "chain"}, step{err: fmt.Errorf("mid key rotated: %w", errRefused)}, step{val: "chain2"})
	c.Get(context.Background(), "k", f)
	ck.tick(61 * time.Second)
	v, err := c.Get(context.Background(), "k", f)
	if !errors.Is(err, errRefused) || v != "" {
		t.Fatalf("the refusal must be returned, not the stale value: %q %v", v, err)
	}
	if s := c.Status()["k"]; s.Cached || !errors.Is(s.LastErr, errRefused) {
		t.Fatalf("a refusal evicts the value: %+v", s)
	}
	ck.tick(10 * time.Second)
	if _, err := c.Get(context.Background(), "k", f); !errors.Is(err, errRefused) || *n != 2 {
		t.Fatalf("the refusal is remembered for NegativeTTL: %v, %d fetches", err, *n)
	}
	ck.tick(25 * time.Second)
	if v, err := c.Get(context.Background(), "k", f); err != nil || v != "chain2" {
		t.Fatalf("after NegativeTTL it is asked again: %q %v", v, err)
	}
}

// With no NegativeTTL, everyone waiting on a refused fetch gets the refusal: they do not
// each start another fetch.
func TestWaitersShareOneAnswer(t *testing.T) {
	c, _ := newTest(t, Options{IsRefusal: refusal})
	var n int32
	release := make(chan struct{})
	f := func(context.Context, string) (string, time.Time, error) {
		atomic.AddInt32(&n, 1)
		<-release
		return "", time.Time{}, errRefused
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "k", f); !errors.Is(err, errRefused) {
				t.Errorf("want the refusal, got %v", err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if n != 1 {
		t.Fatalf("one fetch for every waiter, got %d", n)
	}
}

// P8: the shared fetch used to run on the first caller's context and cache its
// cancellation, so one cancelled request pinned the key to an error for NegativeTTL.
func TestACallersCancellationIsNeverCached(t *testing.T) {
	c, _ := newTest(t, Options{NegativeTTL: 30 * time.Second})
	var n int32
	f := func(ctx context.Context, _ string) (string, time.Time, error) {
		atomic.AddInt32(&n, 1)
		if err := ctx.Err(); err != nil {
			return "", time.Time{}, err
		}
		return "v", time.Time{}, nil
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	c.Get(cancelled, "k", f)
	v, err := c.Get(context.Background(), "k", f)
	if err != nil || v != "v" {
		t.Fatalf("a cancelled caller must not fail the next one: %q %v", v, err)
	}
}

// The fetch is bounded by FetchTimeout rather than by whoever happened to start it, and
// a timeout is not remembered as the answer.
func TestFetchTimeoutBoundsTheSharedFetch(t *testing.T) {
	c, _ := newTest(t, Options{FetchTimeout: 30 * time.Millisecond, NegativeTTL: time.Hour})
	var n int32
	slow := func(ctx context.Context, _ string) (string, time.Time, error) {
		atomic.AddInt32(&n, 1)
		<-ctx.Done()
		return "", time.Time{}, ctx.Err()
	}
	start := time.Now()
	if _, err := c.Get(context.Background(), "k", slow); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the fetch's own deadline, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("FetchTimeout did not bound the fetch")
	}
	c.Get(context.Background(), "k", slow)
	if n != 2 {
		t.Fatalf("a timed-out fetch must not be negatively cached: %d fetches", n)
	}
	// The uncached path (a full cache) is bounded the same way.
	full, _ := newTest(t, Options{FetchTimeout: 30 * time.Millisecond, MaxEntries: 1})
	full.Get(context.Background(), "a", func(context.Context, string) (string, time.Time, error) { return "a", time.Time{}, nil })
	if _, err := full.Get(context.Background(), "b", slow); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uncached fetch: %v", err)
	}
}

// A caller waiting on someone else's fetch leaves when its own context does, and gets
// the stale value if one is still servable; the fetch carries on for everyone else.
func TestAWaitingCallerHonoursItsOwnContext(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute})
	release := make(chan struct{})
	var calls int32
	f := func(context.Context, string) (string, time.Time, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return "old", time.Time{}, nil
		}
		<-release
		return "new", time.Time{}, nil
	}
	c.Get(context.Background(), "k", f)
	ck.tick(61 * time.Second)

	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	var got string
	var gotErr error
	go func() { got, gotErr = c.Get(short, "k", f); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a caller must not wait past its own deadline for a shared fetch")
	}
	if gotErr != nil || got != "old" {
		t.Fatalf("the stale value was still servable: %q %v", got, gotErr)
	}
	// With nothing servable, the caller's own context error comes back.
	fresh, _ := newTest(t, Options{})
	block := make(chan struct{})
	defer close(block)
	short2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if _, err := fresh.Get(short2, "k", func(context.Context, string) (string, time.Time, error) {
		<-block
		return "", time.Time{}, nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the caller's deadline, got %v", err)
	}
	close(release)
	// The abandoned fetch still lands, for the next caller.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if v, err := c.Get(context.Background(), "k", f); err == nil && v == "new" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the abandoned fetch never populated the cache")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// evictExpiredLocked read an entry's fields under the cache lock while Get wrote them
// under the entry lock. Many keys, a tiny cache and a clock that keeps moving make the
// two meet; run with -race.
func TestEvictionAndGetDoNotRace(t *testing.T) {
	c, ck := newTest(t, Options{TTL: 10 * time.Millisecond, MaxStale: -1, MaxEntries: 4, NegativeTTL: 5 * time.Millisecond})
	f := func(_ context.Context, key string) (string, time.Time, error) {
		if key[len(key)-1] == '7' {
			return "", time.Time{}, errors.New("bad key")
		}
		return key, ck.now().Add(5 * time.Millisecond), nil
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				ck.tick(time.Millisecond)
				_ = c.Status()
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 400; i++ {
				c.Get(context.Background(), fmt.Sprintf("key-%d", r.Intn(24)), f)
			}
		}(int64(g))
	}
	wg.Wait()
	close(stop)
	if c.Len() > 4 {
		t.Fatalf("the cache grew past MaxEntries: %d", c.Len())
	}
}

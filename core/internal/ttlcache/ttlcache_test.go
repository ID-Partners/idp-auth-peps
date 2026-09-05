package ttlcache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time       { return c.t }
func (c *clock) tick(d time.Duration) { c.t = c.t.Add(d) }

func newTest(t *testing.T, o Options) (*Cache[string], *clock) {
	t.Helper()
	ck := &clock{t: time.Unix(1_700_000_000, 0)}
	o.Now = ck.now
	return New[string](o), ck
}

func counting(vals ...string) (Fetch[string], *int32, *error) {
	var n int32
	var fail error
	return func(_ context.Context, key string) (string, time.Time, error) {
		i := atomic.AddInt32(&n, 1)
		if fail != nil {
			return "", time.Time{}, fail
		}
		v := vals[(int(i)-1)%len(vals)]
		return key + ":" + v, time.Time{}, nil
	}, &n, &fail
}

func TestFreshHitDoesNotRefetch(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute})
	f, n, _ := counting("a", "b")
	v1, _ := c.Get(context.Background(), "k", f)
	ck.tick(30 * time.Second)
	v2, _ := c.Get(context.Background(), "k", f)
	if v1 != "k:a" || v2 != "k:a" || *n != 1 {
		t.Fatalf("v1=%s v2=%s fetches=%d", v1, v2, *n)
	}
	if s := c.Status()["k"]; !s.Cached || s.Stale {
		t.Fatalf("status %+v", s)
	}
}

func TestExpiryRefetches(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute})
	f, n, _ := counting("a", "b")
	c.Get(context.Background(), "k", f)
	ck.tick(61 * time.Second)
	if s := c.Status()["k"]; !s.Stale {
		t.Fatalf("expected stale: %+v", s)
	}
	v, _ := c.Get(context.Background(), "k", f)
	if v != "k:b" || *n != 2 {
		t.Fatalf("v=%s fetches=%d", v, *n)
	}
}

func TestFetchExpiryCapsTTL(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Hour})
	var n int32
	f := func(_ context.Context, _ string) (string, time.Time, error) {
		atomic.AddInt32(&n, 1)
		return "v", ck.now().Add(10 * time.Second), nil
	}
	c.Get(context.Background(), "k", f)
	ck.tick(11 * time.Second)
	c.Get(context.Background(), "k", f)
	if n != 2 {
		t.Fatalf("fetch expiry ignored: %d fetches", n)
	}
	// An expiry later than the TTL does not extend it.
	c2, ck2 := newTest(t, Options{TTL: 10 * time.Second})
	var n2 int32
	f2 := func(_ context.Context, _ string) (string, time.Time, error) {
		atomic.AddInt32(&n2, 1)
		return "v", ck2.now().Add(time.Hour), nil
	}
	c2.Get(context.Background(), "k", f2)
	ck2.tick(11 * time.Second)
	c2.Get(context.Background(), "k", f2)
	if n2 != 2 {
		t.Fatalf("TTL not applied: %d fetches", n2)
	}
}

func TestServeStaleAndThrottle(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute, MinRefresh: 30 * time.Second})
	f, n, fail := counting("a")
	c.Get(context.Background(), "k", f)
	ck.tick(61 * time.Second)
	*fail = errors.New("down")
	v, err := c.Get(context.Background(), "k", f)
	if err != nil || v != "k:a" || *n != 2 {
		t.Fatalf("stale not served: v=%s err=%v n=%d", v, err, *n)
	}
	if s := c.Status()["k"]; s.LastErr == nil {
		t.Fatal("last error not recorded")
	}
	ck.tick(10 * time.Second)
	c.Get(context.Background(), "k", f)
	if *n != 2 {
		t.Fatalf("refresh not throttled: %d", *n)
	}
	ck.tick(25 * time.Second)
	c.Get(context.Background(), "k", f)
	if *n != 3 {
		t.Fatalf("refresh should retry after MinRefresh: %d", *n)
	}
	*fail = nil
	ck.tick(30 * time.Second)
	v, err = c.Get(context.Background(), "k", f)
	if err != nil || v != "k:a" {
		t.Fatalf("recovered value: v=%s err=%v", v, err)
	}
	if s := c.Status()["k"]; s.LastErr != nil || s.Stale {
		t.Fatalf("recovery should clear the error: %+v", s)
	}
}

func TestErrorWithNothingCached(t *testing.T) {
	c, ck := newTest(t, Options{NegativeTTL: 20 * time.Second})
	f, n, fail := counting("a")
	*fail = errors.New("nope")
	if _, err := c.Get(context.Background(), "k", f); err == nil {
		t.Fatal("want error")
	}
	if _, err := c.Get(context.Background(), "k", f); err == nil || *n != 1 {
		t.Fatalf("negative cache should hold: err=%v n=%d", err, *n)
	}
	ck.tick(21 * time.Second)
	*fail = nil
	v, err := c.Get(context.Background(), "k", f)
	if err != nil || v != "k:a" || *n != 2 {
		t.Fatalf("after negative TTL: v=%s err=%v n=%d", v, err, *n)
	}
	// Without a NegativeTTL, every call retries.
	c2, _ := newTest(t, Options{})
	f2, n2, fail2 := counting("a")
	*fail2 = errors.New("nope")
	c2.Get(context.Background(), "k", f2)
	c2.Get(context.Background(), "k", f2)
	if *n2 != 2 {
		t.Fatalf("no negative cache means retry: %d", *n2)
	}
}

func TestCapacity(t *testing.T) {
	c, ck := newTest(t, Options{TTL: time.Minute, MaxEntries: 2, NegativeTTL: time.Second})
	f, n, _ := counting("a")
	c.Get(context.Background(), "a", f)
	c.Get(context.Background(), "b", f)
	// Full of live entries: c is served uncached.
	c.Get(context.Background(), "c", f)
	c.Get(context.Background(), "c", f)
	if c.Len() != 2 || *n != 4 {
		t.Fatalf("len=%d fetches=%d", c.Len(), *n)
	}
	// Expire everything; the next new key evicts and is remembered.
	ck.tick(2 * time.Minute)
	c.Get(context.Background(), "d", f)
	c.Get(context.Background(), "d", f)
	if c.Len() != 1 || *n != 5 {
		t.Fatalf("after eviction len=%d fetches=%d", c.Len(), *n)
	}
	// A negative entry past its window is evictable too.
	f2, _, fail2 := counting("x")
	*fail2 = errors.New("bad")
	c.Get(context.Background(), "neg", f2)
	ck.tick(2 * time.Second)
	c.Get(context.Background(), "e", f)
	if c.Len() != 2 {
		t.Fatalf("negative entry not evicted: %d", c.Len())
	}
}

func TestConcurrentCallersShareOneFetch(t *testing.T) {
	c, _ := newTest(t, Options{})
	var n int32
	release := make(chan struct{})
	f := func(_ context.Context, _ string) (string, time.Time, error) {
		atomic.AddInt32(&n, 1)
		<-release
		return "v", time.Time{}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := c.Get(context.Background(), "k", f); err != nil || v != "v" {
				t.Errorf("v=%s err=%v", v, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if n != 1 {
		t.Fatalf("expected one fetch, got %d", n)
	}
}

func TestDefaults(t *testing.T) {
	c := New[int](Options{})
	if c.opts.TTL != 5*time.Minute || c.opts.MinRefresh != 30*time.Second || c.opts.MaxEntries != 1024 || c.opts.Now == nil {
		t.Fatalf("defaults: %+v", c.opts)
	}
}

// Package ttlcache is the one cache shape the PEP's metadata fetches share: a bounded,
// keyed TTL cache that serves a stale value rather than failing while a refresh is
// failing, throttles refresh attempts so a bad key cannot be used to generate traffic,
// and lets concurrent callers for one key wait on a single fetch.
//
// It is the pattern jwksCache in cmd/coaz-pep established, made generic so the
// discovery chain and the federation resolver do not each grow their own copy.
package ttlcache

import (
	"context"
	"sync"
	"time"
)

// Fetch produces the value for key. The returned expiry, when non-zero, caps the
// entry's lifetime below the cache TTL (a Trust Chain expires at its min(exp), for
// instance). Zero means "use the TTL".
type Fetch[T any] func(ctx context.Context, key string) (T, time.Time, error)

// Options tunes a Cache. Zero values take the defaults noted on each field.
type Options struct {
	// TTL is how long a fetched value is fresh. Default 5m.
	TTL time.Duration
	// MinRefresh bounds how often a stale entry is re-fetched while fetches keep
	// failing; the stale value is served in between. Default 30s.
	MinRefresh time.Duration
	// NegativeTTL caches a fetch error for a key that has no value yet, so a resource
	// that fails validation is not re-walked on every request. Zero disables it.
	NegativeTTL time.Duration
	// MaxEntries bounds the cache. Beyond it, expired entries are evicted; if it is
	// still full the fetch runs uncached. Default 1024.
	MaxEntries int
	// Now is the clock; tests replace it.
	Now func() time.Time
}

type entry[T any] struct {
	mu          sync.Mutex // held across a fetch: concurrent callers for one key wait
	val         T
	ok          bool
	expires     time.Time
	lastAttempt time.Time
	lastErr     error
	negUntil    time.Time
}

// Cache is safe for concurrent use.
type Cache[T any] struct {
	opts    Options
	mu      sync.Mutex
	entries map[string]*entry[T]
}

// EntryStatus is a point-in-time view of one entry, for logs and tests.
type EntryStatus struct {
	Cached  bool
	Stale   bool
	Expires time.Time
	LastErr error
}

func New[T any](o Options) *Cache[T] {
	if o.TTL <= 0 {
		o.TTL = 5 * time.Minute
	}
	if o.MinRefresh <= 0 {
		o.MinRefresh = 30 * time.Second
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 1024
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Cache[T]{opts: o, entries: make(map[string]*entry[T])}
}

// Get returns the cached value for key, fetching or refreshing it as the TTL and the
// throttles dictate.
func (c *Cache[T]) Get(ctx context.Context, key string, fetch Fetch[T]) (T, error) {
	e, cached := c.entryFor(key)
	if !cached {
		// Full, and nothing evictable: serve without remembering.
		v, _, err := fetch(ctx, key)
		return v, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	now := c.opts.Now()

	if e.ok && now.Before(e.expires) {
		return e.val, nil
	}
	if !e.ok && e.lastErr != nil && now.Before(e.negUntil) {
		return e.val, e.lastErr
	}
	if e.ok && e.lastErr != nil && now.Sub(e.lastAttempt) < c.opts.MinRefresh {
		return e.val, nil // stale, and a refresh failed recently: serve it, do not hammer
	}

	e.lastAttempt = now
	v, exp, err := fetch(ctx, key)
	if err != nil {
		e.lastErr = err
		if e.ok {
			return e.val, nil // serve stale rather than fail every request
		}
		if c.opts.NegativeTTL > 0 {
			e.negUntil = now.Add(c.opts.NegativeTTL)
		}
		return v, err
	}
	limit := now.Add(c.opts.TTL)
	if !exp.IsZero() && exp.Before(limit) {
		limit = exp
	}
	e.val, e.ok, e.expires, e.lastErr = v, true, limit, nil
	return v, nil
}

// entryFor returns the entry for key, creating it when there is room. The bool is
// false only when the cache is full of live entries.
func (c *Cache[T]) entryFor(key string) (*entry[T], bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		return e, true
	}
	if len(c.entries) >= c.opts.MaxEntries {
		c.evictExpiredLocked()
		if len(c.entries) >= c.opts.MaxEntries {
			return nil, false
		}
	}
	e := &entry[T]{}
	c.entries[key] = e
	return e, true
}

func (c *Cache[T]) evictExpiredLocked() {
	now := c.opts.Now()
	for k, e := range c.entries {
		// Reading without the entry lock is fine here: a wrong guess only means an
		// entry survives one more round, or a live one being refreshed is dropped and
		// re-fetched next time.
		if (e.ok && !now.Before(e.expires)) || (!e.ok && !now.Before(e.negUntil)) {
			delete(c.entries, k)
		}
	}
}

// Status snapshots every entry.
func (c *Cache[T]) Status() map[string]EntryStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opts.Now()
	out := make(map[string]EntryStatus, len(c.entries))
	for k, e := range c.entries {
		out[k] = EntryStatus{Cached: e.ok, Stale: e.ok && !now.Before(e.expires), Expires: e.expires, LastErr: e.lastErr}
	}
	return out
}

// Len is the number of keys held.
func (c *Cache[T]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

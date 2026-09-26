// Package ttlcache is the one cache shape the PEP's metadata fetches share: a bounded,
// keyed TTL cache that serves a stale value for a bounded time rather than failing while
// a refresh is failing, throttles refresh attempts so a bad key cannot be used to
// generate traffic, and lets concurrent callers for one key share a single fetch.
//
// It is the pattern jwksCache in cmd/coaz-pep established, made generic so the
// discovery chain and the federation resolver do not each grow their own copy.
//
// What it caches decides who authorises access, so three rules keep a stale value from
// becoming a trust problem:
//
//   - A value is never served at or past the expiry its fetch returned — a Trust
//     Chain's min(exp), a signed document's exp. That is its hard expiry, stale or not.
//   - Past the TTL, a value rides out failing refreshes for MaxStale, and no longer.
//   - A refusal (Options.IsRefusal) evicts the value and is returned as it is. A chain
//     that no longer validates, or a fetch the policy refused, is not an outage to be
//     ridden out on the last good answer.
//
// The fetch itself runs detached from the context of whoever triggered it, bounded by
// FetchTimeout instead: a caller that gives up leaves, and the fetch carries on for
// everyone else, so one cancelled request cannot fail or poison the key for the rest.
package ttlcache

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Fetch produces the value for key. The returned expiry, when non-zero, is the value's
// own: it caps the entry's lifetime below the TTL (a Trust Chain expires at its
// min(exp), for instance) and the value is never served at or past it. Zero means "use
// the TTL".
type Fetch[T any] func(ctx context.Context, key string) (T, time.Time, error)

// Options tunes a Cache. Zero values take the defaults noted on each field.
type Options struct {
	// TTL is how long a fetched value is fresh. Default 5m.
	TTL time.Duration
	// MaxStale bounds how long past its TTL a value may still be served while refreshes
	// fail. Zero means the TTL again; negative serves nothing stale. Never past the
	// value's own expiry.
	MaxStale time.Duration
	// MinRefresh bounds how often a stale entry is re-fetched while fetches keep
	// failing; the stale value is served in between. Default 30s.
	MinRefresh time.Duration
	// NegativeTTL caches a fetch error for a key with nothing servable, so a resource
	// that fails validation is not re-walked on every request. Zero disables it. A
	// context error — a fetch that timed out — is never cached.
	NegativeTTL time.Duration
	// IsRefusal reports whether a fetch error is authoritative rather than an outage:
	// the value is evicted and the error returned, never masked by a stale value, and
	// remembered for NegativeTTL. Nil treats every error as an outage.
	IsRefusal func(error) bool
	// FetchTimeout bounds a fetch. A shared fetch runs detached from the caller's
	// context (context.WithoutCancel), so this is what bounds it instead. Zero leaves
	// only the fetch's own limits.
	FetchTimeout time.Duration
	// MaxEntries bounds the cache. Beyond it, dead entries are evicted; if it is still
	// full the fetch runs uncached. Default 1024.
	MaxEntries int
	// Now is the clock; tests replace it.
	Now func() time.Time
}

type entry[T any] struct {
	mu  sync.Mutex
	val T
	ok  bool
	// fresh until soft; servable while refreshes fail until staleUntil, which is never
	// later than the value's own expiry.
	soft, staleUntil time.Time
	lastAttempt      time.Time
	lastErr          error
	negUntil         time.Time
	// call is the fetch in flight, nil when there is none.
	call *call[T]
}

// call is one fetch and the answer everyone waiting on it gets.
type call[T any] struct {
	done chan struct{}
	val  T
	err  error
}

func (e *entry[T]) fresh(now time.Time) bool    { return e.ok && now.Before(e.soft) }
func (e *entry[T]) servable(now time.Time) bool { return e.ok && now.Before(e.staleUntil) }

// Cache is safe for concurrent use.
type Cache[T any] struct {
	opts    Options
	mu      sync.Mutex
	entries map[string]*entry[T]
}

// EntryStatus is a point-in-time view of one entry, for logs and tests.
type EntryStatus struct {
	Cached bool
	Stale  bool
	// Expires is the end of the TTL; StaleUntil the last moment a stale value may be
	// served.
	Expires    time.Time
	StaleUntil time.Time
	LastErr    error
}

func New[T any](o Options) *Cache[T] {
	if o.TTL <= 0 {
		o.TTL = 5 * time.Minute
	}
	if o.MaxStale == 0 {
		o.MaxStale = o.TTL
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
// throttles dictate. A caller waiting on a fetch leaves when its own context does,
// with the stale value if one is still servable and its context's error otherwise.
func (c *Cache[T]) Get(ctx context.Context, key string, fetch Fetch[T]) (T, error) {
	e, cached := c.entryFor(key)
	if !cached {
		// Full, and nothing evictable: serve without remembering.
		fctx, cancel := c.bound(ctx)
		defer cancel()
		v, _, err := fetch(fctx, key)
		return v, err
	}

	e.mu.Lock()
	now := c.opts.Now()
	switch {
	case e.fresh(now):
		v := e.val
		e.mu.Unlock()
		return v, nil
	case !e.servable(now) && e.lastErr != nil && now.Before(e.negUntil):
		err := e.lastErr
		e.mu.Unlock()
		var zero T
		return zero, err
	case e.servable(now) && e.lastErr != nil && now.Sub(e.lastAttempt) < c.opts.MinRefresh:
		v := e.val // stale, and a refresh failed recently: serve it, do not hammer
		e.mu.Unlock()
		return v, nil
	}
	cl := e.call
	if cl == nil {
		cl = &call[T]{done: make(chan struct{})}
		e.call, e.lastAttempt = cl, now
		go c.run(ctx, e, cl, key, fetch, now)
	}
	e.mu.Unlock()

	select {
	case <-cl.done:
		return cl.val, cl.err
	case <-ctx.Done():
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.servable(c.opts.Now()) {
			return e.val, nil
		}
		var zero T
		return zero, ctx.Err()
	}
}

// bound applies FetchTimeout to ctx.
func (c *Cache[T]) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.opts.FetchTimeout > 0 {
		return context.WithTimeout(ctx, c.opts.FetchTimeout)
	}
	return ctx, func() {}
}

// run performs one fetch for everyone waiting on cl and records the outcome.
func (c *Cache[T]) run(ctx context.Context, e *entry[T], cl *call[T], key string, fetch Fetch[T], start time.Time) {
	fctx, cancel := c.bound(context.WithoutCancel(ctx))
	defer cancel()
	v, exp, err := fetch(fctx, key)

	e.mu.Lock()
	defer e.mu.Unlock()
	defer close(cl.done)
	e.call = nil
	switch {
	case err == nil:
		e.store(v, exp, start, c.opts)
		cl.val = v
	case c.opts.IsRefusal != nil && c.opts.IsRefusal(err):
		var zero T
		e.val, e.ok, e.lastErr = zero, false, err
		e.negUntil = time.Time{}
		if c.opts.NegativeTTL > 0 {
			e.negUntil = start.Add(c.opts.NegativeTTL)
		}
		cl.err = err
	default:
		e.lastErr = err
		if c.opts.NegativeTTL > 0 && !isContextErr(err) {
			e.negUntil = start.Add(c.opts.NegativeTTL)
		}
		if e.servable(c.opts.Now()) {
			cl.val = e.val // serve stale rather than fail every request, for now
		} else {
			cl.err = err
		}
	}
}

// store records a fetched value: fresh for the TTL, servable stale for MaxStale beyond
// it, and never past exp, the value's own expiry.
func (e *entry[T]) store(v T, exp, start time.Time, o Options) {
	e.val, e.ok, e.lastErr, e.negUntil = v, true, nil, time.Time{}
	e.soft = start.Add(o.TTL)
	if !exp.IsZero() && exp.Before(e.soft) {
		e.soft = exp
	}
	e.staleUntil = e.soft
	if o.MaxStale > 0 {
		e.staleUntil = e.soft.Add(o.MaxStale)
	}
	if !exp.IsZero() && exp.Before(e.staleUntil) {
		e.staleUntil = exp
	}
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
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
		c.evictDeadLocked()
		if len(c.entries) >= c.opts.MaxEntries {
			return nil, false
		}
	}
	e := &entry[T]{}
	c.entries[key] = e
	return e, true
}

// evictDeadLocked drops entries with nothing left to give: no servable value, no
// negative answer still in force, and no fetch in flight. Lock order is always the
// cache, then an entry; nothing takes them the other way round.
func (c *Cache[T]) evictDeadLocked() {
	now := c.opts.Now()
	for k, e := range c.entries {
		e.mu.Lock()
		// lastAttempt is zero only for an entry created a moment ago whose first fetch
		// is about to start: its creator still holds it.
		dead := e.call == nil && !e.lastAttempt.IsZero() && !e.servable(now) && !now.Before(e.negUntil)
		e.mu.Unlock()
		if dead {
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
		e.mu.Lock()
		out[k] = EntryStatus{Cached: e.ok, Stale: e.ok && !e.fresh(now), Expires: e.soft, StaleUntil: e.staleUntil, LastErr: e.lastErr}
		e.mu.Unlock()
	}
	return out
}

// Len is the number of keys held.
func (c *Cache[T]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

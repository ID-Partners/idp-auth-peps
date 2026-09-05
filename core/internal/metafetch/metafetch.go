// Package metafetch is the bounded HTTP GET the PEP uses for every metadata document it
// discovers: well-known JSON, Entity Configurations, Subordinate Statements. One place
// holds the rules — https unless told otherwise, an operator allowlist, a body cap, and
// redirects that are re-checked hop by hop and capped — because a fetch that forgets one
// of them is an SSRF primitive handed to whoever controls a metadata document.
package metafetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotAllowed marks a URL the policy refused. Callers treat it as a hard failure,
// never as "try the next source": a refused URL came from someone's metadata, and
// silently routing around it would hide the attempt.
var ErrNotAllowed = errors.New("url not permitted")

// ErrNotFound is a 404: the document does not exist. Distinct from other failures
// because most callers have a spec-defined fallback for "no metadata" and none for
// "the server is on fire".
var ErrNotFound = errors.New("not found")

// Policy decides which URLs may be fetched.
type Policy struct {
	// AllowInsecure permits http. Off, http is allowed only when the URL shares scheme
	// and host with TrustedOrigin — an operator who configured an http PDP has already
	// accepted that its own documents travel the same way.
	AllowInsecure bool
	// Allow is the operator's allowlist. Nil means unrestricted.
	Allow func(raw string) bool
}

// Check applies the policy to raw. trustedOrigin may be "".
func (p Policy) Check(raw, trustedOrigin string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: %q is not an absolute URL", ErrNotAllowed, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.AllowInsecure && !sameOrigin(u, trustedOrigin) {
			return fmt.Errorf("%w: %q is not https", ErrNotAllowed, raw)
		}
	default:
		return fmt.Errorf("%w: %q has scheme %q", ErrNotAllowed, raw, u.Scheme)
	}
	if p.Allow != nil && !p.Allow(raw) {
		return fmt.Errorf("%w: %q is outside the allowlist", ErrNotAllowed, raw)
	}
	return nil
}

func sameOrigin(u *url.URL, trusted string) bool {
	if trusted == "" {
		return false
	}
	t, err := url.Parse(trusted)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, t.Scheme) && strings.EqualFold(u.Host, t.Host)
}

// Client performs policy-checked GETs.
type Client struct {
	http     *http.Client
	maxBytes int64
	policy   Policy
	origin   string
}

const (
	defaultMaxBytes = 1 << 20
	maxRedirects    = 3
)

// New wraps base (nil for a default 10s client). The returned client's redirect policy
// re-checks every hop, so base's own CheckRedirect is replaced.
func New(base *http.Client, policy Policy, trustedOrigin string, maxBytes int64) *Client {
	if base == nil {
		base = &http.Client{}
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	c := &Client{policy: policy, origin: trustedOrigin, maxBytes: maxBytes}
	hc := *base
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrNotAllowed, maxRedirects)
		}
		return c.policy.Check(req.URL.String(), c.origin)
	}
	c.http = &hc
	return c
}

// Get fetches raw after checking it. accept is sent as the Accept header. A 404 yields
// ErrNotFound; any other non-2xx is an error carrying the status.
func (c *Client) Get(ctx context.Context, raw, accept string) ([]byte, error) {
	if err := c.policy.Check(raw, c.origin); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %d", raw, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > c.maxBytes {
		return nil, fmt.Errorf("GET %s: body exceeds %d bytes", raw, c.maxBytes)
	}
	return body, nil
}

// Check exposes the policy for callers that validate URLs they will not fetch, such as
// endpoints read out of a document.
func (c *Client) Check(raw string) error { return c.policy.Check(raw, c.origin) }

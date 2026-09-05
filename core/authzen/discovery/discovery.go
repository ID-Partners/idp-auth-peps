// Package discovery answers one question for a PEP: given the protected resource this
// request is for, where is the AuthZEN evaluation endpoint?
//
// The chain is resource -> PDP identifier -> PDP metadata -> endpoints:
//
//	resource identifier (route config)
//	  ├─ federation: resolved oauth_resource metadata from a Trust Chain   (authoritative)
//	  ├─ rfc9728:    {resource}/.well-known/oauth-protected-resource       (self-asserted)
//	  └─ static:     AUTHZEN_URL                                           (fallback)
//	PDP identifier
//	  ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9)
//	  └─ 404 / unreachable -> {pdp}/access/v1/evaluation (spec-permitted defaults)
//
// The protected-resource parameter that names the PDP is not standardised anywhere —
// not in RFC 9728, AuthZEN 1.0, the MCP profile, or Federation 1.0 — so it is minted
// here once, as ParamPolicyDecisionPoints, in a shape valid both in an RFC 9728
// document and under metadata.oauth_resource in an Entity Statement.
//
// One error is never swallowed: ErrNotAllowed. Everything else degrades — stale cache,
// next source, static PDP — and only when nothing is left does Resolve fail, closed.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/federation"
	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
	"github.com/ID-Partners/idp-auth-peps/core/internal/ttlcache"
)

// ParamPolicyDecisionPoints is the protected-resource metadata parameter naming the
// PDPs that decide for a resource: an array of PDP identifiers (the AuthZEN
// policy_decision_point value, not an endpoint), first preferred. Provisional pending
// an AuthZEN WG profile; renaming it is this one constant.
const ParamPolicyDecisionPoints = "authzen_policy_decision_points"

const (
	wellKnownResource  = "oauth-protected-resource"
	wellKnownPDP       = "authzen-configuration"
	entityTypeResource = "oauth_resource"
)

var (
	// ErrNoMetadata: a source has nothing for this resource. Try the next one.
	ErrNoMetadata = errors.New("no metadata")
	// ErrInvalid: a document exists but violates a MUST (wrong `resource` echo, missing
	// required member). The source is skipped; the fallback is the operator's own PDP.
	ErrInvalid = errors.New("invalid metadata")
	// ErrNotAllowed: a URL the policy refused, or a federation chain that failed
	// validation. Never falls through — see the package comment.
	ErrNotAllowed = metafetch.ErrNotAllowed
	// ErrNoPDP: every source and every candidate failed. The PEP fails closed.
	ErrNoPDP = errors.New("no PDP could be resolved")
)

// Mode selects the metadata sources.
type Mode string

const (
	// ModeOff: static PDP, default paths, no HTTP. Today's behaviour.
	ModeOff Mode = "off"
	// ModeAuthZEN: static PDP, but read its authzen-configuration.
	ModeAuthZEN Mode = "authzen"
	// ModeResource: RFC 9728 per resource, then static.
	ModeResource Mode = "resource"
	// ModeFederation: Trust Chain per resource, then static. Never RFC 9728: a
	// resource outside the federation gets the operator's PDP, not its own claim.
	ModeFederation Mode = "federation"
)

// ParseMode accepts the four modes; "" is off.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return ModeOff, nil
	case ModeOff, ModeAuthZEN, ModeResource, ModeFederation:
		return m, nil
	default:
		return "", fmt.Errorf("unknown PDP discovery mode %q (off, authzen, resource, federation)", s)
	}
}

// PDPEndpoints is what a PEP needs to call one PDP.
type PDPEndpoints struct {
	// Identifier is the PDP's policy_decision_point value.
	Identifier string
	// Evaluation is access_evaluation_endpoint; always set.
	Evaluation string
	// Evaluations is access_evaluations_endpoint; "" when the PDP advertises none.
	Evaluations string
	// Capabilities as advertised; nothing gates on them yet.
	Capabilities []string
	// APIKey is the bearer bound to this Identifier, "" for none. A discovered PDP
	// never inherits the static key.
	APIKey string
	// Source names which MetadataSource produced the identifier.
	Source string
}

// DefaultEndpoints is the spec-permitted shape for a PDP without metadata.
func DefaultEndpoints(pdp string) PDPEndpoints {
	pdp = strings.TrimRight(pdp, "/")
	return PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/access/v1/evaluation", Evaluations: pdp + "/access/v1/evaluations"}
}

// Resolver is what the engine and the service depend on.
type Resolver interface {
	Resolve(ctx context.Context, resource string) (PDPEndpoints, error)
}

// MetadataSource yields the ordered PDP identifiers for a resource.
type MetadataSource interface {
	Name() string
	PDPs(ctx context.Context, resource string) ([]string, error)
}

// Options configures a Chain.
type Options struct {
	Mode Mode
	// StaticPDP is the operator-configured PDP base URL (AUTHZEN_URL), the final
	// fallback in every mode.
	StaticPDP string
	// APIKeys maps PDP identifier to bearer. The caller seeds {StaticPDP: key}.
	APIKeys map[string]string
	// HTTPClient for metadata fetches. Default 10s timeout.
	HTTPClient *http.Client
	// TTL / MinRefresh / MaxEntries tune both caches. Defaults 5m / 30s / 1024.
	TTL, MinRefresh time.Duration
	MaxEntries      int
	// AllowInsecure permits http for discovered URLs. Same-origin http as StaticPDP is
	// always permitted.
	AllowInsecure bool
	// ResourceAllowed / PDPAllowed are the operator's allowlists. Nil = unrestricted.
	ResourceAllowed, PDPAllowed func(string) bool
	// Federation is required in ModeFederation.
	Federation *federation.Resolver
	// Sources overrides the mode-derived list. Tests and future sources.
	Sources []MetadataSource
	// Logf receives one line per degraded step. Default log.Printf.
	Logf func(format string, args ...any)
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// Chain is the Resolver.
type Chain struct {
	opts      Options
	sources   []MetadataSource
	resources *ttlcache.Cache[[]string]
	pdps      *ttlcache.Cache[PDPEndpoints]
	resFetch  *metafetch.Client
	pdpFetch  *metafetch.Client
}

// New builds a Chain. ModeFederation without a federation.Resolver is an error.
func New(o Options) (*Chain, error) {
	if o.Mode == "" {
		o.Mode = ModeOff
	}
	if o.Mode == ModeFederation && o.Federation == nil && o.Sources == nil {
		return nil, errors.New("discovery: federation mode needs a federation resolver")
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.StaticPDP = strings.TrimRight(o.StaticPDP, "/")
	c := &Chain{opts: o}
	c.resFetch = metafetch.New(o.HTTPClient, metafetch.Policy{AllowInsecure: o.AllowInsecure, Allow: o.ResourceAllowed}, "", 0)
	c.pdpFetch = metafetch.New(o.HTTPClient, metafetch.Policy{AllowInsecure: o.AllowInsecure, Allow: o.PDPAllowed}, o.StaticPDP, 0)
	cacheOpts := ttlcache.Options{TTL: o.TTL, MinRefresh: o.MinRefresh, MaxEntries: o.MaxEntries, Now: o.Now}
	// A resource whose metadata cannot be fetched is served by the static PDP for a
	// while rather than re-fetched on every request: that fetch sits in the request
	// path, and a down resource must not turn into a slow PEP.
	resOpts := cacheOpts
	resOpts.NegativeTTL = o.MinRefresh
	if resOpts.NegativeTTL <= 0 {
		resOpts.NegativeTTL = 30 * time.Second
	}
	c.resources = ttlcache.New[[]string](resOpts)
	c.pdps = ttlcache.New[PDPEndpoints](cacheOpts)

	switch {
	case o.Sources != nil:
		c.sources = o.Sources
	case o.Mode == ModeResource:
		c.sources = []MetadataSource{&RFC9728Source{fetch: c.resFetch}}
	case o.Mode == ModeFederation:
		c.sources = []MetadataSource{&FederationSource{Federation: o.Federation}}
	}
	return c, nil
}

// Static is the zero-config Chain: one PDP, default paths, no HTTP. What every
// existing caller gets when it passes a URL.
func Static(pdpURL, apiKey string) *Chain {
	pdpURL = strings.TrimRight(pdpURL, "/")
	c, _ := New(Options{Mode: ModeOff, StaticPDP: pdpURL, APIKeys: map[string]string{pdpURL: apiKey}})
	return c
}

// Resolve returns the endpoints of the PDP that decides for resource. resource may be
// "" for "whatever the static PDP is".
func (c *Chain) Resolve(ctx context.Context, resource string) (PDPEndpoints, error) {
	if c.opts.Mode == ModeOff {
		if c.opts.StaticPDP == "" {
			return PDPEndpoints{}, ErrNoPDP
		}
		ep := DefaultEndpoints(c.opts.StaticPDP)
		ep.APIKey, ep.Source = c.opts.APIKeys[ep.Identifier], "static"
		return ep, nil
	}

	var candidates []string
	var err error
	if resource == "" || c.opts.Mode == ModeAuthZEN {
		if c.opts.StaticPDP == "" {
			return PDPEndpoints{}, ErrNoPDP
		}
		candidates = []string{c.opts.StaticPDP}
	} else {
		candidates, err = c.resources.Get(ctx, resource, c.lookupPDPs)
		if err != nil {
			if errors.Is(err, ErrNotAllowed) {
				return PDPEndpoints{}, err
			}
			// Transient, and nothing stale to serve: the operator's own PDP is the
			// fallback. Not a downgrade — it is the PDP they configured.
			if c.opts.StaticPDP == "" {
				return PDPEndpoints{}, fmt.Errorf("%w for %s: %v", ErrNoPDP, resource, err)
			}
			c.opts.Logf("pdp discovery: %s: %v; using the static PDP", resource, err)
			candidates = []string{c.opts.StaticPDP}
		}
	}

	var last error
	for _, pdp := range candidates {
		ep, err := c.pdps.Get(ctx, pdp, c.fetchConfig)
		if err == nil {
			ep.APIKey = c.opts.APIKeys[ep.Identifier]
			return ep, nil
		}
		if errors.Is(err, ErrNotAllowed) {
			return PDPEndpoints{}, err
		}
		c.opts.Logf("pdp discovery: %s: %v", pdp, err)
		last = err
	}
	return PDPEndpoints{}, fmt.Errorf("%w for %s: %v", ErrNoPDP, resource, last)
}

// lookupPDPs walks the sources in order; the first non-empty list wins. No metadata
// anywhere resolves to the static PDP, and that answer is cached like any other. A
// transient failure is returned as an error so the cache can serve a stale list.
func (c *Chain) lookupPDPs(ctx context.Context, resource string) ([]string, time.Time, error) {
	for _, src := range c.sources {
		pdps, err := src.PDPs(ctx, resource)
		if err == nil && len(pdps) > 0 {
			return pdps, time.Time{}, nil
		}
		switch {
		case err == nil, errors.Is(err, ErrNoMetadata):
		case errors.Is(err, ErrNotAllowed):
			return nil, time.Time{}, err
		case errors.Is(err, ErrInvalid):
			c.opts.Logf("pdp discovery: %s for %s: %v", src.Name(), resource, err)
		default:
			return nil, time.Time{}, fmt.Errorf("%s: %w", src.Name(), err)
		}
	}
	if c.opts.StaticPDP == "" {
		return nil, time.Time{}, ErrNoMetadata
	}
	return []string{c.opts.StaticPDP}, time.Time{}, nil
}

// fetchConfig reads {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9), falling
// back to the default paths when the PDP publishes none.
func (c *Chain) fetchConfig(ctx context.Context, pdp string) (PDPEndpoints, time.Time, error) {
	if err := c.pdpFetch.Check(pdp); err != nil {
		return PDPEndpoints{}, time.Time{}, err
	}
	wk, err := WellKnownURL(pdp, wellKnownPDP)
	if err != nil {
		return PDPEndpoints{}, time.Time{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	body, err := c.pdpFetch.Get(ctx, wk, "application/json")
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			return PDPEndpoints{}, time.Time{}, err
		}
		if !errors.Is(err, metafetch.ErrNotFound) {
			c.opts.Logf("pdp discovery: %s: %v; using default AuthZEN paths", wk, err)
		}
		return DefaultEndpoints(pdp), time.Time{}, nil
	}
	var doc struct {
		PDP          string   `json:"policy_decision_point"`
		Evaluation   string   `json:"access_evaluation_endpoint"`
		Evaluations  string   `json:"access_evaluations_endpoint"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return PDPEndpoints{}, time.Time{}, fmt.Errorf("%w: %s is not JSON: %v", ErrInvalid, wk, err)
	}
	if strings.TrimRight(doc.PDP, "/") != strings.TrimRight(pdp, "/") {
		// The wrong host answered, or the document is about another PDP. Defaults would
		// send decisions to a URL nobody vouched for.
		return PDPEndpoints{}, time.Time{}, fmt.Errorf("%w: %s says policy_decision_point is %q, expected %q", ErrInvalid, wk, doc.PDP, pdp)
	}
	if doc.Evaluation == "" {
		return PDPEndpoints{}, time.Time{}, fmt.Errorf("%w: %s has no access_evaluation_endpoint", ErrInvalid, wk)
	}
	for _, u := range []string{doc.Evaluation, doc.Evaluations} {
		if u == "" {
			continue
		}
		if err := c.pdpFetch.Check(u); err != nil {
			return PDPEndpoints{}, time.Time{}, err
		}
	}
	return PDPEndpoints{Identifier: strings.TrimRight(pdp, "/"), Evaluation: doc.Evaluation, Evaluations: doc.Evaluations, Capabilities: doc.Capabilities}, time.Time{}, nil
}

// Warm resolves the static PDP so a bad configuration is loud at boot rather than on
// the first request. Non-fatal by design: the caller logs.
func (c *Chain) Warm(ctx context.Context) error {
	_, err := c.Resolve(ctx, "")
	return err
}

// Status is a snapshot for logs and tests.
type Status struct {
	Mode      Mode
	Sources   []string
	Resources map[string]ttlcache.EntryStatus
	PDPs      map[string]ttlcache.EntryStatus
}

func (c *Chain) Status() Status {
	s := Status{Mode: c.opts.Mode, Resources: c.resources.Status(), PDPs: c.pdps.Status()}
	for _, src := range c.sources {
		s.Sources = append(s.Sources, src.Name())
	}
	return s
}

// WellKnownURL applies the RFC 8414 / RFC 9728 / AuthZEN rule: insert
// /.well-known/<suffix> between the host and any path. An identifier with a query or
// fragment is not a valid identifier.
func WellKnownURL(identifier, suffix string) (string, error) {
	u, err := url.Parse(identifier)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("%q is not an absolute URL", identifier)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q must not have a query or fragment", identifier)
	}
	path := strings.TrimRight(u.Path, "/")
	u.Path = "/.well-known/" + suffix + path
	u.RawPath = ""
	return u.String(), nil
}

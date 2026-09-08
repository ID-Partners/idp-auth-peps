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
	// FailOpen is this layer's effective failure mode: when true, an AVAILABILITY
	// failure — unreachable, erroring, unresolvable — skips the layer instead of
	// failing the request. A refusal (allowlist, invalid chain) is never skipped, and a
	// deny is a decision, not a failure.
	FailOpen bool
	// Resource is what the resource's own metadata said, verbatim, and where it came
	// from. Nil when the PDP came from static configuration. The PEP reads the PDP list
	// out of it and forwards the rest to the PDP as context — it decides nothing from
	// it. That is the point: what a resource requires (scopes, acr, sender-constrained
	// tokens) is policy input, and policy lives in the PDP.
	Resource *ResourceMetadata
}

// ResourceMetadata is a resource's declared posture: the RFC 9728 document, or the
// federation-resolved oauth_resource metadata, as published. Source says which, so
// the PDP knows whether it is looking at a self-assertion or at what the federation
// vouched for.
type ResourceMetadata struct {
	Source   string
	Document map[string]any
	// PDPs is the ordered list read out of Document, first preferred.
	PDPs []string
}

// DefaultEndpoints is the spec-permitted shape for a PDP without metadata.
func DefaultEndpoints(pdp string) PDPEndpoints {
	pdp = strings.TrimRight(pdp, "/")
	return PDPEndpoints{Identifier: pdp, Evaluation: pdp + "/access/v1/evaluation", Evaluations: pdp + "/access/v1/evaluations"}
}

// Resolver is what the engine and the service depend on.
type Resolver interface {
	// Resolve finds the PDP that decides for resource ("" means the static one).
	Resolve(ctx context.Context, resource string) (PDPEndpoints, error)
	// ResolvePDP reads the metadata of an explicitly named PDP — an operator-configured
	// layer rather than a discovered one.
	ResolvePDP(ctx context.Context, pdp string) (PDPEndpoints, error)
}

// Layer names. A route's policy is an ordered list of these; anything else in the list
// is taken as a PDP identifier.
const (
	// LayerResource is the PDP discovery finds for the route's resource — federation,
	// then RFC 9728, then static. The default, and today's single behaviour.
	LayerResource = "resource"
	// LayerStatic is the operator's configured PDP, asked regardless of what discovery
	// finds: the slot for an estate-wide PDP that judges the token and the client.
	LayerStatic = "static"
)

// LayerSpec is one entry of a route's policy: a layer name and, optionally, its own
// failure mode. FailOpen nil inherits the PEP's default.
type LayerSpec struct {
	Name     string
	FailOpen *bool
}

// Resolved is the outcome of resolving a layer list: the PDPs to ask, in order, and
// the fail-open layers that could not be resolved and were skipped.
type Resolved struct {
	PDPs    []PDPEndpoints
	Skipped []string
}

// ResolveLayers resolves each layer in order and returns the PDPs to ask, in that order,
// with duplicates collapsed to one call. An empty list means [resource]. failOpen is
// the PEP's default; a layer's own setting overrides it.
//
// Layering is what lets a generic PDP service every endpoint — one that looks at the
// token, the client and risk signals — and a resource-specific PDP apply the resource's
// own metadata after it. Every layer must permit; the first that does not is the answer.
// The PEP does the ordering and the folding, nothing else.
//
// A layer that cannot be resolved fails the request, unless it is fail-open, in which
// case it is skipped and named in Skipped. A refusal — ErrNotAllowed, which also wraps
// an invalid federation chain — is never skipped: fail-open is about availability, and a
// refusal is not an outage.
func ResolveLayers(ctx context.Context, r Resolver, resource string, layers []LayerSpec, failOpen bool) (Resolved, error) {
	if len(layers) == 0 {
		layers = []LayerSpec{{Name: LayerResource}}
	}
	var res Resolved
	seen := map[string]int{}
	for _, layer := range layers {
		open := failOpen
		if layer.FailOpen != nil {
			open = *layer.FailOpen
		}
		var ep PDPEndpoints
		var err error
		switch layer.Name {
		case LayerResource:
			ep, err = r.Resolve(ctx, resource)
		case LayerStatic:
			ep, err = r.Resolve(ctx, "")
		default:
			ep, err = r.ResolvePDP(ctx, layer.Name)
		}
		if err != nil {
			if errors.Is(err, ErrNotAllowed) || !open {
				return Resolved{}, fmt.Errorf("layer %q: %w", layer.Name, err)
			}
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%v)", layer.Name, err))
			continue
		}
		ep.FailOpen = open
		if i, dup := seen[ep.Identifier]; dup {
			// The same PDP twice is one call. Keep the resource metadata if this
			// occurrence carried it and the earlier one did not; the stricter failure
			// mode wins.
			if res.PDPs[i].Resource == nil && ep.Resource != nil {
				res.PDPs[i].Resource = ep.Resource
			}
			res.PDPs[i].FailOpen = res.PDPs[i].FailOpen && open
			continue
		}
		seen[ep.Identifier] = len(res.PDPs)
		res.PDPs = append(res.PDPs, ep)
	}
	return res, nil
}

// ResourceMetadataOf is the one document to forward for a layered call: whichever layer
// read the resource's metadata. Nil when none did.
func ResourceMetadataOf(eps []PDPEndpoints) *ResourceMetadata {
	for _, ep := range eps {
		if ep.Resource != nil {
			return ep.Resource
		}
	}
	return nil
}

// ParseLayers reads a layer list, one entry per comma or line. Each entry is a layer
// name — static, resource, or a PDP identifier — optionally followed by a failure mode:
//
//	http://estate.example fail-open, resource
//
// An unknown modifier or an unrecognisable name is an error: a policy that cannot be
// read must not be silently narrowed.
func ParseLayers(raw string) ([]LayerSpec, error) {
	var out []LayerSpec
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		spec := LayerSpec{Name: strings.TrimRight(fields[0], "/")}
		if spec.Name != LayerResource && spec.Name != LayerStatic && !strings.Contains(spec.Name, "://") {
			return nil, fmt.Errorf("layer %q is neither static, resource nor a PDP identifier", spec.Name)
		}
		for _, mod := range fields[1:] {
			switch strings.ToLower(mod) {
			case "fail-open":
				t := true
				spec.FailOpen = &t
			case "fail-closed":
				f := false
				spec.FailOpen = &f
			default:
				return nil, fmt.Errorf("layer %q: unknown modifier %q (fail-open, fail-closed)", spec.Name, mod)
			}
		}
		out = append(out, spec)
	}
	return out, nil
}

// LayerNames renders specs for logs.
func LayerNames(layers []LayerSpec) []string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		s := l.Name
		if l.FailOpen != nil {
			if *l.FailOpen {
				s += " fail-open"
			} else {
				s += " fail-closed"
			}
		}
		out = append(out, s)
	}
	return out
}

// MetadataSource yields a resource's metadata: the PDPs that decide for it, and the
// document that named them.
type MetadataSource interface {
	Name() string
	Lookup(ctx context.Context, resource string) (ResourceMetadata, error)
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
	resources *ttlcache.Cache[ResourceMetadata]
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
	c.resources = ttlcache.New[ResourceMetadata](resOpts)
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
	var from *ResourceMetadata
	if resource == "" || c.opts.Mode == ModeAuthZEN {
		if c.opts.StaticPDP == "" {
			return PDPEndpoints{}, ErrNoPDP
		}
		candidates = []string{c.opts.StaticPDP}
	} else {
		// Which resources may be looked up at all is the operator's call, whatever the
		// source. Checked here, before any cache or fetch, so a refused resource costs
		// nothing and cannot inherit another caller's cached answer.
		if c.opts.ResourceAllowed != nil && !c.opts.ResourceAllowed(resource) {
			return PDPEndpoints{}, fmt.Errorf("%w: %q is outside the resource allowlist", ErrNotAllowed, resource)
		}
		meta, err := c.resources.Get(ctx, resource, c.lookupResource)
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
		} else {
			candidates = meta.PDPs
			if meta.Document != nil {
				m := meta
				from = &m
			}
		}
	}

	var last error
	for _, pdp := range candidates {
		ep, err := c.pdps.Get(ctx, pdp, c.fetchConfig)
		if err == nil {
			ep.APIKey = c.opts.APIKeys[ep.Identifier]
			ep.Resource = from
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

// lookupResource walks the sources in order; the first that names a PDP wins. No
// metadata anywhere resolves to the static PDP, and that answer is cached like any
// other. A transient failure is returned as an error so the cache can serve stale.
func (c *Chain) lookupResource(ctx context.Context, resource string) (ResourceMetadata, time.Time, error) {
	for _, src := range c.sources {
		meta, err := src.Lookup(ctx, resource)
		if err == nil && len(meta.PDPs) > 0 {
			return meta, time.Time{}, nil
		}
		switch {
		case err == nil, errors.Is(err, ErrNoMetadata):
		case errors.Is(err, ErrNotAllowed):
			return ResourceMetadata{}, time.Time{}, err
		case errors.Is(err, ErrInvalid):
			c.opts.Logf("pdp discovery: %s for %s: %v", src.Name(), resource, err)
		default:
			return ResourceMetadata{}, time.Time{}, fmt.Errorf("%s: %w", src.Name(), err)
		}
	}
	if c.opts.StaticPDP == "" {
		return ResourceMetadata{}, time.Time{}, ErrNoMetadata
	}
	return ResourceMetadata{PDPs: []string{c.opts.StaticPDP}}, time.Time{}, nil
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

// ResolvePDP reads the metadata of an explicitly named PDP. Off mode reads nothing, as
// everywhere else. The PDP allowlist applies: a layer URL that arrived in per-route
// config is caller-supplied over the check API, exactly like mcp_upstream_url, and gets
// the same treatment; ones from the service's own configuration are allowlisted by it.
func (c *Chain) ResolvePDP(ctx context.Context, pdp string) (PDPEndpoints, error) {
	pdp = strings.TrimRight(pdp, "/")
	if c.opts.Mode == ModeOff {
		ep := DefaultEndpoints(pdp)
		ep.APIKey, ep.Source = c.opts.APIKeys[pdp], "layer"
		return ep, nil
	}
	ep, err := c.pdps.Get(ctx, pdp, c.fetchConfig)
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			return PDPEndpoints{}, err
		}
		return PDPEndpoints{}, fmt.Errorf("%w: %s: %v", ErrNoPDP, pdp, err)
	}
	ep.APIKey, ep.Source = c.opts.APIKeys[ep.Identifier], "layer"
	return ep, nil
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

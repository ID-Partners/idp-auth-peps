package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ID-Partners/idp-auth-peps/core/federation"
	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
)

// StaticSource names the operator-configured PDP for every resource.
type StaticSource struct{ PDP string }

func (StaticSource) Name() string { return "static" }

func (s StaticSource) Lookup(context.Context, string) (ResourceMetadata, error) {
	if s.PDP == "" {
		return ResourceMetadata{}, ErrNoMetadata
	}
	return ResourceMetadata{PDPs: []string{s.PDP}}, nil
}

// RFC9728Source reads the resource's own protected resource metadata.
type RFC9728Source struct{ fetch *metafetch.Client }

func (*RFC9728Source) Name() string { return "rfc9728" }

func (s *RFC9728Source) Lookup(ctx context.Context, resource string) (ResourceMetadata, error) {
	wk, err := WellKnownURL(resource, wellKnownResource)
	if err != nil {
		return ResourceMetadata{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	body, err := s.fetch.Get(ctx, wk, "application/json")
	if err != nil {
		if errors.Is(err, metafetch.ErrNotFound) {
			return ResourceMetadata{}, ErrNoMetadata
		}
		return ResourceMetadata{}, err // ErrNotAllowed or transport
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return ResourceMetadata{}, fmt.Errorf("%w: %s is not JSON", ErrInvalid, wk)
	}
	// RFC 9728 §3.3: the echoed identifier MUST be identical, or an attacker who can
	// answer at that path has just named a PDP for someone else's resource.
	if echoed, _ := doc["resource"].(string); echoed != resource {
		return ResourceMetadata{}, fmt.Errorf("%w: %s says resource is %q, expected %q", ErrInvalid, wk, echoed, resource)
	}
	raw, _ := doc[ParamPolicyDecisionPoints].([]any)
	pdps, err := pdpList(raw, wk)
	if err != nil {
		return ResourceMetadata{}, err
	}
	// The whole document travels to the PDP. The PEP does not know or care which other
	// members are in it — scopes_supported, acr requirements, DPoP requirements — only
	// that the resource published them and the PDP may want them.
	return ResourceMetadata{Source: "rfc9728", Document: doc, PDPs: pdps}, nil
}

// FederationSource reads the resolved oauth_resource metadata from a Trust Chain.
type FederationSource struct{ Federation *federation.Resolver }

func (*FederationSource) Name() string { return "federation" }

func (s *FederationSource) Lookup(ctx context.Context, resource string) (ResourceMetadata, error) {
	res, err := s.Federation.Resolve(ctx, resource)
	if err != nil {
		switch {
		case errors.Is(err, federation.ErrNotFederated):
			return ResourceMetadata{}, ErrNoMetadata
		case errors.Is(err, federation.ErrInvalidChain), errors.Is(err, federation.ErrNotAllowed):
			// A resource that claims membership and fails validation is a signal, not
			// an outage. Never route around it to the resource's own word or to a
			// default.
			return ResourceMetadata{}, fmt.Errorf("%w: %v", ErrNotAllowed, err)
		}
		return ResourceMetadata{}, err
	}
	if res.Subject != resource {
		return ResourceMetadata{}, fmt.Errorf("%w: federation resolved %q, expected %q", ErrNotAllowed, res.Subject, resource)
	}
	meta, ok := res.Metadata[entityTypeResource]
	if !ok {
		return ResourceMetadata{}, ErrNoMetadata
	}
	raw, _ := meta[ParamPolicyDecisionPoints].([]any)
	pdps, err := pdpList(raw, "resolved metadata of "+resource)
	if err != nil {
		return ResourceMetadata{}, err
	}
	// What travels to the PDP is the RESOLVED metadata: what survived every superior's
	// metadata_policy, not what the resource wrote. A federation that pins a floor on
	// the acr a resource may require has pinned it for the PDP too.
	return ResourceMetadata{Source: "federation", Document: meta, PDPs: pdps}, nil
}

func pdpList(raw []any, from string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		u, err := url.Parse(s)
		if s == "" || err != nil || !u.IsAbs() || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("%w: %s lists %q, which is not a PDP identifier", ErrInvalid, from, s)
		}
		out = append(out, strings.TrimRight(s, "/"))
	}
	if len(out) == 0 {
		return nil, ErrNoMetadata
	}
	return out, nil
}

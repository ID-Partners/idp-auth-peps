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

func (s StaticSource) PDPs(context.Context, string) ([]string, error) {
	if s.PDP == "" {
		return nil, ErrNoMetadata
	}
	return []string{s.PDP}, nil
}

// RFC9728Source reads the resource's own protected resource metadata.
type RFC9728Source struct{ fetch *metafetch.Client }

func (*RFC9728Source) Name() string { return "rfc9728" }

func (s *RFC9728Source) PDPs(ctx context.Context, resource string) ([]string, error) {
	wk, err := WellKnownURL(resource, wellKnownResource)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	body, err := s.fetch.Get(ctx, wk, "application/json")
	if err != nil {
		if errors.Is(err, metafetch.ErrNotFound) {
			return nil, ErrNoMetadata
		}
		return nil, err // ErrNotAllowed or transport
	}
	var doc struct {
		Resource string `json:"resource"`
		PDPs     []any  `json:"authzen_policy_decision_points"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s is not JSON: %v", ErrInvalid, wk, err)
	}
	// RFC 9728 §3.3: the echoed identifier MUST be identical, or an attacker who can
	// answer at that path has just named a PDP for someone else's resource.
	if doc.Resource != resource {
		return nil, fmt.Errorf("%w: %s says resource is %q, expected %q", ErrInvalid, wk, doc.Resource, resource)
	}
	return pdpList(doc.PDPs, wk)
}

// FederationSource reads the resolved oauth_resource metadata from a Trust Chain.
type FederationSource struct{ Federation *federation.Resolver }

func (*FederationSource) Name() string { return "federation" }

func (s *FederationSource) PDPs(ctx context.Context, resource string) ([]string, error) {
	res, err := s.Federation.Resolve(ctx, resource)
	if err != nil {
		switch {
		case errors.Is(err, federation.ErrNotFederated):
			return nil, ErrNoMetadata
		case errors.Is(err, federation.ErrInvalidChain), errors.Is(err, federation.ErrNotAllowed):
			// A resource that claims membership and fails validation is a signal, not
			// an outage. Never route around it to the resource's own word or to a
			// default.
			return nil, fmt.Errorf("%w: %v", ErrNotAllowed, err)
		}
		return nil, err
	}
	if res.Subject != resource {
		return nil, fmt.Errorf("%w: federation resolved %q, expected %q", ErrNotAllowed, res.Subject, resource)
	}
	meta, ok := res.Metadata[entityTypeResource]
	if !ok {
		return nil, ErrNoMetadata
	}
	raw, _ := meta[ParamPolicyDecisionPoints].([]any)
	return pdpList(raw, "resolved metadata of "+resource)
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

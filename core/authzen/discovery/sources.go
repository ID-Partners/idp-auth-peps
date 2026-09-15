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
	"github.com/ID-Partners/idp-auth-peps/core/jose"
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
	// RFC 9728 §2.1 signed_metadata, when the resource published one.
	if err := s.applySignedMetadata(ctx, doc, resource, wk); err != nil {
		return ResourceMetadata{}, err
	}
	raw, _ := doc[ParamPolicyDecisionPoints].([]any)
	pdps, err := pdpList(raw, wk)
	if err != nil {
		return ResourceMetadata{}, err
	}
	layers, err := layerList(doc, wk)
	if err != nil {
		return ResourceMetadata{}, err
	}
	// The whole document travels to the PDP. The PEP does not know or care which other
	// members are in it — scopes_supported, acr requirements, DPoP requirements — only
	// that the resource published them and the PDP may want them.
	return ResourceMetadata{Source: "rfc9728", Document: doc, PDPs: pdps, Layers: layers}, nil
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
	// The same goes for the layers: a metadata_policy `add` on ParamPolicyLayers is
	// how a federation puts its own PDP in front of every member's, and a member
	// cannot take it out again by editing its own configuration.
	layers, err := layerList(meta, "resolved metadata of "+resource)
	if err != nil {
		return ResourceMetadata{}, err
	}
	// What travels to the PDP is the RESOLVED metadata: what survived every superior's
	// metadata_policy, not what the resource wrote. A federation that pins a floor on
	// the acr a resource may require has pinned it for the PDP too.
	return ResourceMetadata{Source: "federation", Document: meta, PDPs: pdps, Layers: layers}, nil
}

func pdpList(raw []any, from string) ([]string, error) {
	out, err := identifiers(raw, from)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNoMetadata
	}
	return out, nil
}

// layerList reads ParamPolicyLayers out of a document: absent or empty is no layers,
// anything that is not an array of PDP identifiers is an invalid document — a policy
// the PEP cannot read is not one it may quietly narrow.
func layerList(doc map[string]any, from string) ([]string, error) {
	v, present := doc[ParamPolicyLayers]
	if !present {
		return nil, nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s %s is not an array", ErrInvalid, from, ParamPolicyLayers)
	}
	return identifiers(raw, from)
}

func identifiers(raw []any, from string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		u, err := url.Parse(s)
		if s == "" || err != nil || !u.IsAbs() || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("%w: %s lists %q, which is not a PDP identifier", ErrInvalid, from, s)
		}
		out = append(out, strings.TrimRight(s, "/"))
	}
	return out, nil
}

// jwtReserved are the JWS/JWT claims that carry the assertion itself rather than a
// metadata parameter, so they are not merged into the document.
var jwtReserved = map[string]bool{"iss": true, "iat": true, "exp": true, "nbf": true, "aud": true, "jti": true, "sub": true}

// applySignedMetadata verifies RFC 9728 §2.1's signed_metadata and lets its claims
// override the plain JSON members, in place. A document without one is left alone.
//
// The RFC permits ignoring the member outright — "Consumers of the metadata MAY ignore the
// signed metadata if they do not support this feature" — but supporting it has a sharp
// edge. A consumer that does "MUST validate that any signed metadata was signed by a key
// belonging to the issuer", and the signed values "MUST take precedence over the
// corresponding values conveyed using plain JSON elements". So once we look at it, a
// present-but-unverifiable signature can never fall back to the unsigned body: that would
// be a downgrade an attacker forces by breaking the signature, which is easier than
// forging one.
//
// What this proves is narrow, and worth saying plainly: the body was signed by a key
// published at the document's OWN jwks_uri. Both are served by the resource, so it is a
// self-assertion either way. It catches a body altered in front of the resource — a cache,
// a proxy, a compromised CDN — but it is not the federation's word about the resource.
// That is what FederationSource is for, and why it is asked first.
func (s *RFC9728Source) applySignedMetadata(ctx context.Context, doc map[string]any, resource, wk string) error {
	raw, present := doc["signed_metadata"]
	if !present {
		return nil
	}
	tok, _ := raw.(string)
	if tok == "" {
		return fmt.Errorf("%w: %s carries an empty signed_metadata", ErrInvalid, wk)
	}
	hdr, claims := jose.Header(tok), jose.Claims(tok)
	if hdr == nil || claims == nil {
		return fmt.Errorf("%w: %s signed_metadata is not a compact JWS", ErrInvalid, wk)
	}
	// "MUST contain an iss claim denoting the party attesting to the claims." The only
	// keys we can locate are the resource's own, so an assertion by anyone else is one we
	// cannot validate — and an unvalidatable signature is not a reason to trust the body.
	if iss, _ := claims["iss"].(string); iss != resource {
		return fmt.Errorf("%w: %s signed_metadata is issued by %q, not the resource", ErrInvalid, wk, claims["iss"])
	}
	// A signature lifted from another resource's document must not pass here.
	if r, ok := claims["resource"].(string); ok && r != resource {
		return fmt.Errorf("%w: %s signed_metadata is about %q", ErrInvalid, wk, r)
	}
	alg, _ := hdr["alg"].(string)
	if _, err := jose.HashFor(alg); err != nil {
		return fmt.Errorf("%w: %s signed_metadata alg %q is not acceptable", ErrInvalid, wk, alg)
	}
	jwksURI, _ := doc["jwks_uri"].(string)
	if jwksURI == "" {
		return fmt.Errorf("%w: %s has signed_metadata but no jwks_uri to verify it with", ErrInvalid, wk)
	}
	body, err := s.fetch.Get(ctx, jwksURI, "application/json")
	if err != nil {
		// A refused URL stays refused; anything else means we cannot verify, and an
		// unverified signed document is not usable.
		if errors.Is(err, metafetch.ErrNotAllowed) {
			return err
		}
		return fmt.Errorf("%w: fetching %s to verify signed_metadata: %v", ErrInvalid, jwksURI, err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
		return fmt.Errorf("%w: %s served no usable JWK set", ErrInvalid, jwksURI)
	}
	kid, _ := hdr["kid"].(string)
	verified := false
	for _, k := range set.Keys {
		// With a kid, only that key may verify; without one, any key in the set may.
		if kid != "" {
			if id, _ := k["kid"].(string); id != kid {
				continue
			}
		}
		if jose.VerifyJWS(tok, k, alg) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return fmt.Errorf("%w: %s signed_metadata does not verify against any key at %s", ErrInvalid, wk, jwksURI)
	}
	// Precedence: the signed claims win over the plain members.
	for k, v := range claims {
		if !jwtReserved[k] && k != "signed_metadata" {
			doc[k] = v
		}
	}
	return nil
}

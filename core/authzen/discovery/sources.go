package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

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
type RFC9728Source struct {
	fetch *metafetch.Client
	// now is the clock signed_metadata's exp and nbf are read against; nil is the wall
	// clock.
	now func() time.Time
}

// signedMetadataLeeway absorbs clock skew on signed_metadata's exp and nbf.
const signedMetadataLeeway = 60 * time.Second

func (*RFC9728Source) Name() string { return "rfc9728" }

func (s *RFC9728Source) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

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
	expires, err := s.applySignedMetadata(ctx, doc, resource, wk)
	if err != nil {
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
	return ResourceMetadata{Source: "rfc9728", Document: doc, PDPs: pdps, Layers: layers, ExpiresAt: expires}, nil
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
	// From here the federation vouches for the resource, so what it resolved is the
	// only word that counts. If the PEP cannot use it — no oauth_resource metadata, no
	// PDP, a list a policy's subset_of stripped to [] (which essential accepts,
	// §6.1.3.1.8), an entry that is not a PDP identifier — that is a refusal. Falling
	// back to the static PDP would drop whatever else the anchor resolved: the layers
	// it added in front of every member, the acr floor it set.
	from := "resolved metadata of " + resource
	meta, ok := res.Metadata[entityTypeResource]
	if !ok {
		return ResourceMetadata{}, fmt.Errorf("%w: the federation vouches for %s but resolves no %s metadata", ErrNotAllowed, resource, entityTypeResource)
	}
	raw, _ := meta[ParamPolicyDecisionPoints].([]any)
	pdps, err := identifiers(raw, from)
	if err != nil {
		return ResourceMetadata{}, fmt.Errorf("%w: %v", ErrNotAllowed, err)
	}
	if len(pdps) == 0 {
		return ResourceMetadata{}, fmt.Errorf("%w: %s names no PDP the federation allows", ErrNotAllowed, from)
	}
	// The same goes for the layers: a metadata_policy `add` on ParamPolicyLayers is
	// how a federation puts its own PDP in front of every member's, and a member
	// cannot take it out again by editing its own configuration.
	layers, err := layerList(meta, from)
	if err != nil {
		return ResourceMetadata{}, fmt.Errorf("%w: %v", ErrNotAllowed, err)
	}
	// What travels to the PDP is the RESOLVED metadata: what survived every superior's
	// metadata_policy, not what the resource wrote. A federation that pins a floor on
	// the acr a resource may require has pinned it for the PDP too.
	return ResourceMetadata{Source: "federation", Document: meta, PDPs: pdps, Layers: layers, ExpiresAt: res.ExpiresAt}, nil
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
// What this proves is narrow, and worth saying plainly: the claims were signed by a key
// published at the jwks_uri the same document names. Both are served by the resource,
// so it is a self-assertion either way, and it is only as strong as the document: whoever
// can rewrite the document can re-point jwks_uri at a key of their own. It is not the
// federation's word about the resource. That is what FederationSource is for, and why
// it is asked first. What it does add is that the signed claims are dated — exp and nbf
// are enforced, and exp is when the document stops being served from cache — and typed:
// a JWT minted for another purpose (typ other than JWT) is not signed metadata.
//
// The returned time is the signed exp, zero when there is none.
func (s *RFC9728Source) applySignedMetadata(ctx context.Context, doc map[string]any, resource, wk string) (time.Time, error) {
	raw, present := doc["signed_metadata"]
	if !present {
		return time.Time{}, nil
	}
	tok, _ := raw.(string)
	if tok == "" {
		return time.Time{}, fmt.Errorf("%w: %s carries an empty signed_metadata", ErrInvalid, wk)
	}
	hdr, claims := jose.Header(tok), jose.Claims(tok)
	if hdr == nil || claims == nil {
		return time.Time{}, fmt.Errorf("%w: %s signed_metadata is not a compact JWS", ErrInvalid, wk)
	}
	// "MUST contain an iss claim denoting the party attesting to the claims." The only
	// keys we can locate are the resource's own, so an assertion by anyone else is one we
	// cannot validate — and an unvalidatable signature is not a reason to trust the body.
	if iss, _ := claims["iss"].(string); iss != resource {
		return time.Time{}, fmt.Errorf("%w: %s signed_metadata is issued by %q, not the resource", ErrInvalid, wk, claims["iss"])
	}
	// A signature lifted from another resource's document must not pass here.
	if r, ok := claims["resource"].(string); ok && r != resource {
		return time.Time{}, fmt.Errorf("%w: %s signed_metadata is about %q", ErrInvalid, wk, r)
	}
	// RFC 9728 defines no typ of its own, so a plain JWT, or no typ at all; anything else
	// is a JWT minted for some other purpose — an entity statement, an access token —
	// that the resource's key happened to sign.
	if typ, present := hdr["typ"]; present {
		if s, _ := typ.(string); !strings.EqualFold(s, "JWT") && !strings.EqualFold(s, "application/jwt") {
			return time.Time{}, fmt.Errorf("%w: %s signed_metadata has typ %v, not JWT", ErrInvalid, wk, typ)
		}
	}
	expires, err := s.validity(claims)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s signed_metadata %v", ErrInvalid, wk, err)
	}
	alg, _ := hdr["alg"].(string)
	if _, err := jose.HashFor(alg); err != nil {
		return time.Time{}, fmt.Errorf("%w: %s signed_metadata alg %q is not acceptable", ErrInvalid, wk, alg)
	}
	jwksURI, _ := doc["jwks_uri"].(string)
	if jwksURI == "" {
		return time.Time{}, fmt.Errorf("%w: %s has signed_metadata but no jwks_uri to verify it with", ErrInvalid, wk)
	}
	body, err := s.fetch.Get(ctx, jwksURI, "application/json")
	if err != nil {
		// A refused URL stays refused; anything else means we cannot verify, and an
		// unverified signed document is not usable.
		if errors.Is(err, metafetch.ErrNotAllowed) {
			return time.Time{}, err
		}
		return time.Time{}, fmt.Errorf("%w: fetching %s to verify signed_metadata: %v", ErrInvalid, jwksURI, err)
	}
	keys, err := jose.ParseJWKSet(body)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s served no usable JWK set: %v", ErrInvalid, jwksURI, err)
	}
	kid, _ := hdr["kid"].(string)
	verified := false
	for _, k := range keys {
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
		return time.Time{}, fmt.Errorf("%w: %s signed_metadata does not verify against any key at %s", ErrInvalid, wk, jwksURI)
	}
	// Precedence: the signed claims win over the plain members.
	for k, v := range claims {
		if !jwtReserved[k] && k != "signed_metadata" {
			doc[k] = v
		}
	}
	return expires, nil
}

// validity checks signed_metadata's exp and nbf, when present, against the clock with a
// little leeway, and returns exp.
func (s *RFC9728Source) validity(claims map[string]any) (time.Time, error) {
	now := s.clock()
	var expires time.Time
	for _, name := range []string{"exp", "nbf"} {
		v, present := claims[name]
		if !present {
			continue
		}
		n, ok := v.(float64)
		if !ok {
			return time.Time{}, fmt.Errorf("%s is not a number", name)
		}
		at := time.Unix(int64(n), 0)
		switch {
		case name == "exp" && !at.After(now.Add(-signedMetadataLeeway)):
			return time.Time{}, fmt.Errorf("expired at %s", at.UTC().Format(time.RFC3339))
		case name == "nbf" && at.After(now.Add(signedMetadataLeeway)):
			return time.Time{}, fmt.Errorf("is not yet valid (nbf %s)", at.UTC().Format(time.RFC3339))
		case name == "exp":
			expires = at
		}
	}
	return expires, nil
}

package federation

import (
	"fmt"
	"net/url"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// Statement is one parsed Entity Statement — an Entity Configuration when iss == sub,
// a Subordinate Statement otherwise.
type Statement struct {
	Raw      string
	Header   map[string]any
	Claims   map[string]any
	Iss, Sub string
	Iat, Exp time.Time
	// JWKS holds the subject's Federation Entity Keys.
	JWKS []map[string]any
	// Metadata is keyed by Entity Type Identifier. Nil when absent.
	Metadata map[string]map[string]any
	// Entity Configuration only.
	AuthorityHints []string
	// Subordinate Statement only.
	MetadataPolicy     map[string]map[string]map[string]any
	MetadataPolicyCrit []string
	Constraints        *Constraints
}

// IsEntityConfiguration reports whether the statement is self-issued.
func (s *Statement) IsEntityConfiguration() bool { return s.Iss == s.Sub }

// Constraints is the §6.2 claim of a Subordinate Statement.
type Constraints struct {
	MaxPathLength      *int
	NamingPermitted    []string
	NamingExcluded     []string
	AllowedEntityTypes []string
}

var (
	entityConfigurationOnly = []string{"authority_hints", "trust_anchor_hints", "trust_marks", "trust_mark_issuers", "trust_mark_owners"}
	subordinateOnly         = []string{"metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint"}
)

// parseStatement decodes and syntactically validates one Entity Statement (§3.2 steps
// 1–9 and 13–23). Signature verification is separate because the key comes from the
// issuer's Entity Configuration, which the caller holds.
func parseStatement(raw string, now time.Time, leeway time.Duration) (*Statement, error) {
	hdr := jose.Header(raw)
	claims := jose.Claims(raw)
	if hdr == nil || claims == nil {
		return nil, fmt.Errorf("not a compact JWS")
	}
	if typ, _ := hdr["typ"].(string); typ != typEntityStatement {
		return nil, fmt.Errorf("typ is %q, want %q", typ, typEntityStatement)
	}
	alg, _ := hdr["alg"].(string)
	if _, err := jose.HashFor(alg); err != nil {
		return nil, fmt.Errorf("alg %q is not acceptable", alg)
	}
	if kid, _ := hdr["kid"].(string); kid == "" {
		return nil, fmt.Errorf("kid header missing")
	}
	if _, ok := hdr["trust_chain"]; ok {
		return nil, fmt.Errorf("entity statements must not carry a trust_chain header")
	}

	st := &Statement{Raw: raw, Header: hdr, Claims: claims}
	st.Iss, _ = claims["iss"].(string)
	st.Sub, _ = claims["sub"].(string)
	for name, v := range map[string]string{"iss": st.Iss, "sub": st.Sub} {
		if !validEntityID(v) {
			return nil, fmt.Errorf("%s %q is not a valid entity identifier", name, v)
		}
	}
	iat, ok := numClaim(claims, "iat")
	if !ok {
		return nil, fmt.Errorf("iat missing")
	}
	exp, ok := numClaim(claims, "exp")
	if !ok {
		return nil, fmt.Errorf("exp missing")
	}
	st.Iat, st.Exp = time.Unix(iat, 0), time.Unix(exp, 0)
	if st.Iat.After(now.Add(leeway)) {
		return nil, fmt.Errorf("iat is in the future")
	}
	if !st.Exp.After(now.Add(-leeway)) {
		return nil, fmt.Errorf("statement expired")
	}

	keys, err := parseJWKS(claims["jwks"])
	if err != nil {
		return nil, err
	}
	st.JWKS = keys

	if crit, present := claims["crit"]; present {
		list, ok := crit.([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("crit must be a non-empty array")
		}
		// No extension claims are implemented, so every crit entry is one we do not
		// understand — and spec-defined claims must not be listed there at all.
		return nil, fmt.Errorf("crit names claims this resolver does not understand: %v", list)
	}

	if m, present := claims["metadata"]; present {
		meta, err := parseMetadata(m)
		if err != nil {
			return nil, err
		}
		st.Metadata = meta
	}

	if st.IsEntityConfiguration() {
		for _, c := range subordinateOnly {
			if _, present := claims[c]; present {
				return nil, fmt.Errorf("%s is not permitted in an entity configuration", c)
			}
		}
		if hints, present := claims["authority_hints"]; present {
			st.AuthorityHints, err = stringList(hints, "authority_hints")
			if err != nil {
				return nil, err
			}
			if len(st.AuthorityHints) == 0 {
				return nil, fmt.Errorf("authority_hints must not be empty")
			}
			for _, h := range st.AuthorityHints {
				if !validEntityID(h) {
					return nil, fmt.Errorf("authority hint %q is not a valid entity identifier", h)
				}
			}
		}
		if tah, present := claims["trust_anchor_hints"]; present {
			l, err := stringList(tah, "trust_anchor_hints")
			if err != nil {
				return nil, err
			}
			if len(l) == 0 {
				return nil, fmt.Errorf("trust_anchor_hints must not be empty")
			}
		}
		return st, nil
	}

	for _, c := range entityConfigurationOnly {
		if _, present := claims[c]; present {
			return nil, fmt.Errorf("%s is not permitted in a subordinate statement", c)
		}
	}
	if mpc, present := claims["metadata_policy_crit"]; present {
		st.MetadataPolicyCrit, err = stringList(mpc, "metadata_policy_crit")
		if err != nil {
			return nil, err
		}
		if len(st.MetadataPolicyCrit) == 0 {
			return nil, fmt.Errorf("metadata_policy_crit must not be empty")
		}
		for _, op := range st.MetadataPolicyCrit {
			if !knownOperator(op) {
				return nil, fmt.Errorf("metadata_policy_crit names operator %q, which this resolver does not implement", op)
			}
		}
	}
	if mp, present := claims["metadata_policy"]; present {
		st.MetadataPolicy, err = parsePolicy(mp)
		if err != nil {
			return nil, err
		}
	}
	if c, present := claims["constraints"]; present {
		st.Constraints, err = parseConstraints(c)
		if err != nil {
			return nil, err
		}
	}
	if se, present := claims["source_endpoint"]; present {
		s, _ := se.(string)
		if u, err := url.Parse(s); err != nil || !u.IsAbs() {
			return nil, fmt.Errorf("source_endpoint is not a URL")
		}
	}
	return st, nil
}

// verifyWith checks the statement's signature against keys (the issuer's Federation
// Entity Keys), by kid (§3.2 steps 11–12).
func (s *Statement) verifyWith(keys []map[string]any) error {
	kid, _ := s.Header["kid"].(string)
	alg, _ := s.Header["alg"].(string)
	for _, k := range keys {
		if id, _ := k["kid"].(string); id == kid {
			if err := jose.VerifyJWS(s.Raw, k, alg); err != nil {
				return fmt.Errorf("signature by kid %q does not verify: %v", kid, err)
			}
			return nil
		}
	}
	return fmt.Errorf("kid %q is not among the issuer's federation keys", kid)
}

func validEntityID(s string) bool {
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

func numClaim(claims map[string]any, name string) (int64, bool) {
	switch v := claims[name].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

func parseJWKS(v any) ([]map[string]any, error) {
	set, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jwks missing or not an object")
	}
	raw, ok := set["keys"].([]any)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("jwks has no keys")
	}
	seen := map[string]bool{}
	keys := make([]map[string]any, 0, len(raw))
	for _, k := range raw {
		jwk, ok := k.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("jwks contains a non-object key")
		}
		kid, _ := jwk["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("every federation key needs a kid")
		}
		if seen[kid] {
			return nil, fmt.Errorf("duplicate kid %q in jwks", kid)
		}
		seen[kid] = true
		keys = append(keys, jwk)
	}
	return keys, nil
}

func parseMetadata(v any) (map[string]map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metadata is not an object")
	}
	out := make(map[string]map[string]any, len(m))
	for et, raw := range m {
		params, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("metadata.%s is not an object", et)
		}
		if hasNull(params) {
			return nil, fmt.Errorf("metadata.%s contains a null value", et)
		}
		out[et] = params
	}
	return out, nil
}

func hasNull(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		for _, x := range t {
			if hasNull(x) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if hasNull(x) {
				return true
			}
		}
	}
	return false
}

func stringList(v any, name string) ([]string, error) {
	raw, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an array", name)
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("%s contains a non-string", name)
		}
		out = append(out, s)
	}
	return out, nil
}

func parseConstraints(v any) (*Constraints, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("constraints is not an object")
	}
	c := &Constraints{}
	if mpl, present := m["max_path_length"]; present {
		f, ok := mpl.(float64)
		if !ok || f < 0 || f != float64(int(f)) {
			return nil, fmt.Errorf("constraints.max_path_length must be a non-negative integer")
		}
		n := int(f)
		c.MaxPathLength = &n
	}
	if nc, present := m["naming_constraints"]; present {
		obj, ok := nc.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("constraints.naming_constraints is not an object")
		}
		var err error
		if p, present := obj["permitted"]; present {
			if c.NamingPermitted, err = stringList(p, "naming_constraints.permitted"); err != nil {
				return nil, err
			}
		}
		if e, present := obj["excluded"]; present {
			if c.NamingExcluded, err = stringList(e, "naming_constraints.excluded"); err != nil {
				return nil, err
			}
		}
	}
	if aet, present := m["allowed_entity_types"]; present {
		var err error
		if c.AllowedEntityTypes, err = stringList(aet, "constraints.allowed_entity_types"); err != nil {
			return nil, err
		}
	}
	return c, nil
}

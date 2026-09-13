package federation

import (
	"fmt"
	"strings"
)

// checkConstraints enforces §6.2 across the chain. A Subordinate Statement's
// constraints apply to its subject and everything below it, cumulatively: nothing
// deeper can relax what a Superior set.
//
// Positions: chain[0] is the leaf's Entity Configuration, chain[j] for 1 <= j < len-1
// is the Subordinate Statement about the entity chain[j-1].Sub, and the last element
// is the anchor's Entity Configuration.
func checkConstraints(chain []*Statement) error {
	last := len(chain) - 1
	for j := 1; j < last; j++ {
		c := chain[j].Constraints
		if c == nil {
			continue
		}
		subject := chain[j].Sub
		// Entities at or below the subject: chain[0..j-1].Sub. Intermediates below the
		// subject are chain[1..j-1].Sub, i.e. j-1 of them.
		if c.MaxPathLength != nil && j-1 > *c.MaxPathLength {
			return fmt.Errorf("%s allows %d intermediates below %s, chain has %d", chain[j].Iss, *c.MaxPathLength, subject, j-1)
		}
		for k := 0; k < j; k++ {
			id := chain[k].Sub
			if len(c.NamingPermitted) > 0 && !anyPrefix(id, c.NamingPermitted) {
				return fmt.Errorf("%s is outside the naming constraints %s set", id, chain[j].Iss)
			}
			if anyPrefix(id, c.NamingExcluded) {
				return fmt.Errorf("%s is excluded by the naming constraints %s set", id, chain[j].Iss)
			}
		}
		if len(c.AllowedEntityTypes) > 0 {
			allowed := map[string]bool{entityTypeFedEnt: true}
			for _, t := range c.AllowedEntityTypes {
				allowed[t] = true
			}
			for k := 0; k < j; k++ {
				for et := range chain[k].Metadata {
					if !allowed[et] {
						return fmt.Errorf("%s declares entity type %s, which %s does not allow", chain[k].Sub, et, chain[j].Iss)
					}
				}
			}
		}
	}
	return nil
}

// anyPrefix reports whether s is covered by any of the naming constraints.
//
// A bare string prefix is not enough. A constraint naming https://bank.example.com would
// then also cover https://bank.example.com.evil.test, so an intermediate limited to its
// own namespace could still vouch for a lookalike host someone else controls — which is
// the one thing the constraint exists to prevent. A constraint therefore matches only at
// a boundary: the identifier must equal it, or continue with a delimiter rather than with
// more hostname.
func anyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if coveredBy(s, p) {
			return true
		}
	}
	return false
}

// coveredBy is boundary-aware prefix matching for entity identifiers.
//
// Deliberately nothing more. A host-suffix form ("https://.example.com" delegating every
// subdomain, as RFC 5280 name constraints allow) is NOT implemented, because §6.2.2's
// normative matching rule could not be confirmed and guessing it would risk making a
// constraint looser than whoever set it intended — the opposite of the point. This
// matches at a boundary or not at all, which is strictly tighter than the bare prefix
// test it replaces.
func coveredBy(id, constraint string) bool {
	if constraint == "" || !strings.HasPrefix(id, constraint) {
		return false
	}
	if len(id) == len(constraint) {
		return true
	}
	// The constraint ended where the identifier continues; the next character decides
	// whether that is a sub-name (fine) or the rest of a different name (not).
	switch id[len(constraint)] {
	case '/', '?', '#':
		return true // a path, query or fragment under the same authority
	case ':':
		// A port on the same host, and only when the constraint stopped at the host:
		// a constraint that already names a path cannot be extended by a port.
		return !strings.Contains(afterScheme(constraint), "/")
	default:
		return false
	}
}

// afterScheme is constraint without its URL scheme, so "ends at the host" can be tested
// without the "//" of the scheme counting as a path separator.
func afterScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

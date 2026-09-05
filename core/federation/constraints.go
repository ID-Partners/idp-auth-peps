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

func anyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

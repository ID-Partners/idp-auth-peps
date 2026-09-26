package federation

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
)

// checkConstraints enforces §6.2 across the chain. A Subordinate Statement's
// constraints apply to its subject and everything below it (§3.1.3), cumulatively:
// nothing deeper can relax what a Superior set.
//
// Positions: chain[0] is the leaf's Entity Configuration, chain[j] for 1 <= j < len-1
// is the Subordinate Statement about the entity chain[j].Sub, issued by its superior,
// and the last element is the anchor's Entity Configuration. The entities at or below
// chain[j].Sub are chain[0..j].Sub.
func checkConstraints(chain []*Statement) error {
	last := len(chain) - 1
	for j := 1; j < last; j++ {
		c := chain[j].Constraints
		if c == nil {
			continue
		}
		subject := chain[j].Sub
		// Intermediates below the subject are chain[1..j-1].Sub, i.e. j-1 of them.
		if c.MaxPathLength != nil && j-1 > *c.MaxPathLength {
			return fmt.Errorf("%s allows %d intermediates below %s, chain has %d", chain[j].Iss, *c.MaxPathLength, subject, j-1)
		}
		for k := 0; k <= j; k++ {
			id := chain[k].Sub
			// A permitted list that is present permits only what it names — an empty
			// one, nothing.
			if c.NamingPermitted != nil {
				ok, err := anyCovers(id, c.NamingPermitted)
				if err != nil {
					return fmt.Errorf("naming constraints %s set: %v", chain[j].Iss, err)
				}
				if !ok {
					return fmt.Errorf("%s is outside the naming constraints %s set", id, chain[j].Iss)
				}
			}
			excluded, err := anyCovers(id, c.NamingExcluded)
			if err != nil {
				return fmt.Errorf("naming constraints %s set: %v", chain[j].Iss, err)
			}
			if excluded {
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

func anyCovers(id string, constraints []string) (bool, error) {
	for _, c := range constraints {
		ok, err := coveredBy(id, c)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// coveredBy reports whether the entity identifier id falls within one naming
// constraint.
//
// §6.2.2 uses RFC 5280's domain name constraints, applied to the host of the
// identifier: "host.example.com" names one host, ".example.com" any host with one or
// more labels in front of it (and not example.com itself). A host that is not a name
// — an IP literal — cannot be judged against one, and RFC 5280 rejects it outright;
// so does this, as an error that invalidates the chain.
//
// A constraint written as an http(s) URL is this resolver's extension, kept because
// deployments use it: it names a URL subtree and matches at a boundary only, so
// https://bank.example.com does not cover https://bank.example.com.evil.test. A
// trailing "/" already is a boundary. Both sides are compared in one spelling — scheme
// and host in lower case, the default port dropped, unreserved characters decoded —
// so an identifier cannot step out of an excluded subtree by spelling itself
// differently.
func coveredBy(id, constraint string) (bool, error) {
	if constraint == "" {
		return false, nil
	}
	if !strings.Contains(constraint, "://") {
		return domainCovers(id, constraint)
	}
	have, err := canonicalURL(id)
	if err != nil {
		return false, fmt.Errorf("%s: %v", id, err)
	}
	want, err := canonicalURL(constraint)
	if err != nil {
		return false, nil // parseConstraints refuses these; nothing reaches here
	}
	want = strings.TrimSuffix(want, "/")
	if want == strings.TrimSuffix(have, "/") {
		return true, nil
	}
	if !strings.HasPrefix(have, want) {
		return false, nil
	}
	// The constraint ended where the identifier continues; the next character decides
	// whether that is a sub-name (fine) or the rest of a different name (not).
	switch have[len(want)] {
	case '/':
		return true, nil
	case ':':
		// A port on the same host, and only when the constraint stopped at the host:
		// a constraint that already names a path cannot be extended by a port. (want
		// is canonical, so it has a scheme: skip its "//".)
		return !strings.Contains(want[strings.Index(want, "://")+3:], "/"), nil
	}
	return false, nil
}

// domainCovers applies an RFC 5280 domain name constraint to id's host.
func domainCovers(id, constraint string) (bool, error) {
	u, err := url.Parse(id)
	if err != nil || u.Host == "" {
		return false, fmt.Errorf("%s has no host", id)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if net.ParseIP(host) != nil || !validDomainName(host) {
		return false, fmt.Errorf("%s's host is not a domain name, so a domain name constraint cannot be applied to it", id)
	}
	c := strings.ToLower(constraint)
	if strings.HasPrefix(c, ".") {
		return strings.HasSuffix(host, c), nil
	}
	return host == c, nil
}

// validDomainName is RFC 1123 host syntax: labels of letters, digits and hyphens, none
// empty, none starting or ending with a hyphen.
func validDomainName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validNamingConstraint accepts a domain name constraint (§6.2.2) or an http(s) URL
// subtree.
func validNamingConstraint(s string) bool {
	if !strings.Contains(s, "://") {
		return validDomainName(strings.TrimPrefix(s, "."))
	}
	_, err := canonicalURL(s)
	return err == nil
}

// canonicalURL is an http(s) URL in one spelling: scheme and host in lower case, the
// default port dropped, unreserved characters decoded. A URL that could name one place
// and match another — dot segments, encoded slashes, credentials, a query or a
// fragment — has no canonical form here.
func canonicalURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("not an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("scheme %q", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("carries credentials, a query or a fragment")
	}
	if err := metafetch.PlainPath(u); err != nil {
		return "", err
	}
	host := strings.ToLower(u.Host)
	if p := u.Port(); (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		host = strings.TrimSuffix(host, ":"+p)
	}
	// u.Path is the decoded path; with separators and dot segments already refused,
	// decoding cannot change where it points.
	return scheme + "://" + host + u.Path, nil
}

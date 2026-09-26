package federation

import (
	"strings"
	"testing"
)

// §6.2.2: naming constraints use RFC 5280's domain name syntax, applied to the host of
// the Entity Identifier. "host.example.com" names one host; ".example.com" any host
// with one or more labels in front of it, and not example.com itself.
func TestNamingConstraintsDomainForms(t *testing.T) {
	cases := []struct {
		id, constraint string
		want           bool
	}{
		{"https://a.example.com", ".example.com", true},
		{"https://a.b.example.com:8443/tenant", ".example.com", true},
		{"https://A.Example.COM", ".example.com", true},
		{"https://a.example.com.", ".example.com", true}, // an absolute name is the same host
		{"https://example.com", ".example.com", false},
		{"https://evilexample.com", ".example.com", false},
		{"https://a.example.com.evil.test", ".example.com", false},
		{"https://host.example.com/x", "host.example.com", true},
		{"https://HOST.example.com", "host.example.com", true},
		{"https://a.host.example.com", "host.example.com", false},
		{"https://host.example.community", "host.example.com", false},
	}
	for _, c := range cases {
		got, err := coveredBy(c.id, c.constraint)
		if err != nil || got != c.want {
			t.Errorf("coveredBy(%q, %q) = %v, %v; want %v", c.id, c.constraint, got, err, c.want)
		}
	}
	// RFC 5280: a domain constraint applied to a URI without a host name — an IP
	// literal — rejects it outright.
	for _, id := range []string{"https://127.0.0.1:8443", "https://[::1]/x"} {
		if _, err := coveredBy(id, ".example.com"); err == nil {
			t.Errorf("%s: a host that is not a name cannot satisfy or escape a domain constraint", id)
		}
	}
}

// P6: a URL constraint ending in "/" is already at a boundary. An excluded
// https://fed.example/evil/ did not exclude https://fed.example/evil/leaf, because the
// character after the prefix was 'l'.
func TestNamingConstraintsURLForms(t *testing.T) {
	covered := [][2]string{
		{"https://f.example/e/leaf", "https://f.example/e/"},
		{"https://f.example/e", "https://f.example/e/"}, // the root of the subtree it names
		{"https://f.example/e/leaf", "https://f.example/e"},
		{"https://F.EXAMPLE/e/leaf", "https://f.example/e/"},     // host case
		{"https://f.example:443/e/leaf", "https://f.example/e/"}, // the default port
		{"https://f.example/%65/leaf", "https://f.example/e/"},   // an unreserved character, encoded
		{"https://f.example:8443/x", "https://f.example"},        // a port when the constraint stops at the host
	}
	for _, c := range covered {
		if got, err := coveredBy(c[0], c[1]); err != nil || !got {
			t.Errorf("%q should be covered by %q: %v %v", c[0], c[1], got, err)
		}
	}
	notCovered := [][2]string{
		{"https://f.example/evil", "https://f.example/e/"},
		{"https://f.example/e/leaf", "http://f.example/e/"},
		{"https://f.example/ex", "https://f.example/e"},
		{"https://f.example/e/x:8443", "https://f.example/e/x"},
	}
	for _, c := range notCovered {
		if got, err := coveredBy(c[0], c[1]); err != nil || got {
			t.Errorf("%q must not be covered by %q: %v %v", c[0], c[1], got, err)
		}
	}
}

// §3.1.3: a Subordinate Statement's constraints apply to its subject as well as to every
// entity beneath it. The subject of the anchor's statement about an intermediate was
// never checked against the anchor's own naming constraints.
func TestConstraintsBindTheStatementsOwnSubject(t *testing.T) {
	leaf := &Statement{Iss: "https://leaf.good.example", Sub: "https://leaf.good.example"}
	aboutLeaf := &Statement{Iss: "https://mid.evil.example", Sub: "https://leaf.good.example"}
	aboutMid := &Statement{Iss: "https://ta.example", Sub: "https://mid.evil.example",
		Constraints: &Constraints{NamingExcluded: []string{".evil.example"}}}
	anchor := &Statement{Iss: "https://ta.example", Sub: "https://ta.example"}
	err := checkConstraints([]*Statement{leaf, aboutLeaf, aboutMid, anchor})
	if err == nil || !strings.Contains(err.Error(), "mid.evil.example") {
		t.Fatalf("the intermediate the anchor's statement is about must meet its constraints: %v", err)
	}
	aboutMid.Constraints = &Constraints{NamingPermitted: []string{".good.example"}}
	if err := checkConstraints([]*Statement{leaf, aboutLeaf, aboutMid, anchor}); err == nil {
		t.Fatal("an intermediate outside the permitted names must invalidate the chain")
	}
	// A present but empty permitted list permits nothing.
	aboutMid.Constraints = &Constraints{NamingPermitted: []string{}}
	if err := checkConstraints([]*Statement{leaf, aboutLeaf, aboutMid, anchor}); err == nil {
		t.Fatal("permitted: [] must permit no one")
	}
	aboutMid.Constraints = &Constraints{NamingPermitted: []string{".good.example", "mid.evil.example"}}
	if err := checkConstraints([]*Statement{leaf, aboutLeaf, aboutMid, anchor}); err != nil {
		t.Fatalf("every entity at or below the subject is permitted: %v", err)
	}
}

// A naming constraint that is neither a domain name nor a URL is a malformed statement:
// guessing what it meant could make it looser than whoever set it intended.
func TestMalformedNamingConstraintsInvalidateTheStatement(t *testing.T) {
	for _, bad := range []any{"*.example.com", "not a name", "https://", "ftp://f.example", "https://f.example/a/../b", "https://u:p@f.example", "example..com", "-bad.example.com", ".", ""} {
		_, err := parseConstraints(map[string]any{"naming_constraints": map[string]any{"excluded": []any{bad}}})
		if err == nil {
			t.Errorf("%q must not parse as a naming constraint", bad)
		}
	}
	for _, good := range []any{".example.com", "host.example.com", "https://f.example/e/", "http://127.0.0.1:8080", "localhost"} {
		if _, err := parseConstraints(map[string]any{"naming_constraints": map[string]any{"permitted": []any{good}}}); err != nil {
			t.Errorf("%q is a naming constraint: %v", good, err)
		}
	}
}

// The edges: a malformed constraint URL covers nothing, an identifier with no host
// cannot be judged, and an IP-literal host under a domain constraint is an error from
// either list — which invalidates the chain.
func TestNamingConstraintEdges(t *testing.T) {
	if ok, err := coveredBy("https://a.example", "ftp://a.example"); ok || err != nil {
		t.Errorf("a constraint that is not an http(s) URL covers nothing: %v %v", ok, err)
	}
	if _, err := coveredBy("not a url", ".example.com"); err == nil {
		t.Error("an identifier with no host cannot be judged")
	}
	ipLeaf := &Statement{Iss: "https://10.0.0.1", Sub: "https://10.0.0.1"}
	aboutLeaf := &Statement{Iss: "https://ta.example", Sub: "https://10.0.0.1"}
	anchor := &Statement{Iss: "https://ta.example", Sub: "https://ta.example"}
	for _, c := range []*Constraints{{NamingPermitted: []string{".example.com"}}, {NamingExcluded: []string{".example.com"}}} {
		aboutLeaf.Constraints = c
		if err := checkConstraints([]*Statement{ipLeaf, aboutLeaf, anchor}); err == nil || !strings.Contains(err.Error(), "not a domain name") {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

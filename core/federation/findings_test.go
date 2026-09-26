package federation

import (
	"strings"
	"testing"
)

// A naming constraint is a namespace limit, so it must match at a boundary. A bare string
// prefix would let a constraint naming https://bank.example.com also cover
// https://bank.example.com.evil.test, which is the one thing it exists to prevent.
func TestNamingConstraintsMatchAtABoundary(t *testing.T) {
	const c = "https://bank.example.com"
	covered := []string{
		c,               // the constraint itself
		c + "/",         // a trailing slash
		c + "/branch/1", // a path beneath it
		c + ":8443",     // a port on the same host
	}
	// An entity identifier never carries a query or fragment (§1.2), so one that does is
	// an error rather than a match.
	if _, err := coveredBy(c+"?x=1", c); err == nil {
		t.Error("an identifier with a query is not an entity identifier")
	}
	for _, id := range covered {
		if ok, err := coveredBy(id, c); !ok || err != nil {
			t.Errorf("%q should be covered by %q: %v", id, c, err)
		}
	}
	notCovered := []string{
		c + ".evil.test", // the lookalike the old prefix match admitted
		c + "-evil.test",
		c + "x",
		"https://bank.example.community",
		"http://bank.example.com", // a different scheme is a different authority
		"https://evil.test/" + c,
	}
	for _, id := range notCovered {
		if ok, _ := coveredBy(id, c); ok {
			t.Errorf("%q must NOT be covered by %q", id, c)
		}
	}
	// The host-suffix form is §6.2.2's bare ".example.com" (see the domain-form tests);
	// written inside a URL it is not a host at all, and covers nothing.
	if ok, _ := coveredBy("https://a.example.com", "https://.example.com"); ok {
		t.Error("a URL whose host starts with a dot names no host")
	}
	// A constraint that already names a path cannot be extended by a port.
	if ok, _ := coveredBy("https://bank.example.com/x:8443", "https://bank.example.com/x"); ok {
		t.Error("a path constraint must not be extended by a port")
	}
	if ok, _ := coveredBy("anything", ""); ok {
		t.Error("an empty constraint must cover nothing")
	}
}

// Entity Identifiers use https (Federation 1.0 1.2). http is admitted only when the
// operator has already accepted insecure metadata.
func TestEntityIdentifiersRequireHTTPS(t *testing.T) {
	if !validEntityID("https://a.example", false) {
		t.Error("https must be valid")
	}
	if validEntityID("http://a.example", false) {
		t.Error("http must be refused unless insecure metadata is allowed")
	}
	if !validEntityID("http://a.example", true) {
		t.Error("http must be allowed when the operator opted in")
	}
	for _, bad := range []string{"", "a.example", "ftp://a.example", "https://a.example#f", "https://a.example?q=1", "https:///nohost"} {
		if validEntityID(bad, true) {
			t.Errorf("%q must not be a valid entity identifier", bad)
		}
	}
}

// A federation key that says what it is for is taken at its word.
func TestKeyUseGatesSignatureVerification(t *testing.T) {
	if !usableForSigning(map[string]any{"kid": "k"}) {
		t.Error("a key declaring neither use nor key_ops is unrestricted")
	}
	if !usableForSigning(map[string]any{"use": "sig"}) {
		t.Error("use=sig is a signing key")
	}
	if usableForSigning(map[string]any{"use": "enc"}) {
		t.Error("use=enc must not verify a signature")
	}
	if !usableForSigning(map[string]any{"key_ops": []any{"verify"}}) {
		t.Error("key_ops containing verify is a signing key")
	}
	if usableForSigning(map[string]any{"key_ops": []any{"encrypt"}}) {
		t.Error("key_ops without verify must not verify a signature")
	}
}

// verifyWith must refuse an encryption-only key even when the kid matches.
func TestVerifyWithRefusesANonSigningKey(t *testing.T) {
	st := &Statement{Raw: "a.b.c", Header: map[string]any{"kid": "k1", "alg": "ES256"}}
	err := st.verifyWith([]map[string]any{{"kid": "k1", "use": "enc"}})
	if err == nil || !strings.Contains(err.Error(), "not published for signature verification") {
		t.Fatalf("want a key-use refusal, got %v", err)
	}
}

package discovery

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// P11, through discovery: a path-scoped allowlist entry is only as good as the string
// it is compared with. A resource identifier or a PDP identifier that climbs out of its
// prefix with dot segments — literal or percent-encoded — is refused before the
// operator's matcher sees it, and before anything is fetched.
func TestAnAllowlistCannotBeEscapedWithDotSegments(t *testing.T) {
	static := newPDP(t, nil)
	var asked int32
	prefix := func(p string) func(string) bool {
		return func(u string) bool {
			atomic.AddInt32(&asked, 1)
			return u == p || strings.HasPrefix(u, p+"/")
		}
	}
	res := newResource(t, func(self string) any { return map[string]any{"resource": self} })
	c := mustNew(t, Options{Mode: ModeResource, StaticPDP: static.URL, ResourceAllowed: prefix(res.URL + "/tenants/a")})
	for _, id := range []string{res.URL + "/tenants/a/../b", res.URL + "/tenants/a/%2e%2e/b"} {
		if _, err := c.Resolve(ctx(), id); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want a refusal, got %v", id, err)
		}
	}
	if atomic.LoadInt32(&res.hits) != 0 || atomic.LoadInt32(&asked) != 0 {
		t.Fatalf("refused before the matcher or any fetch: hits=%d asked=%d", res.hits, asked)
	}

	// A document naming a PDP identifier that climbs out of its tenant.
	pdp := newPDP(t, fullConfig)
	doc := newResource(t, func(self string) any {
		return map[string]any{"resource": self, ParamPolicyDecisionPoints: []string{pdp.URL + "/tenants/a/%2e%2e/b"}}
	})
	c2 := mustNew(t, Options{Mode: ModeResource, StaticPDP: static.URL, PDPAllowed: prefix(pdp.URL + "/tenants/a")})
	if _, err := c2.Resolve(ctx(), doc.URL); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a discovered PDP climbing out of its prefix: %v", err)
	}
	if atomic.LoadInt32(&pdp.hits) != 0 {
		t.Fatal("the escaping PDP must not be contacted")
	}
}

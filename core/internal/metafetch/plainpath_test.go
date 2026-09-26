package metafetch

import (
	"errors"
	"net/url"
	"testing"
)

// P11's mechanism: an allowlist compares strings while the server resolves dot
// segments, so https://pdp.example/tenants/a/../b passes a prefix check for tenant a
// and reaches tenant b. A path that could be resolved somewhere else is refused.
func TestPlainPath(t *testing.T) {
	refused := []string{
		"https://p.example/t/a/../b",
		"https://p.example/t/a/./b",
		"https://p.example/t/a/%2e%2e/b",
		"https://p.example/t/a/%2E%2e/b",
		"https://p.example/t/a/.%2e",
		"https://p.example/t/a%2F..%2Fb",
		"https://p.example/t/a%5c..%5cb",
		"https://p.example/t/a\\b",
		"https://p.example/..",
	}
	for _, raw := range refused {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if err := PlainPath(u); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want a refusal, got %v", raw, err)
		}
	}
	for _, raw := range []string{"https://p.example", "https://p.example/", "https://p.example/t/a..b/c", "https://p.example/t/%7Euser", "https://p.example/.well-known/x"} {
		u, _ := url.Parse(raw)
		if err := PlainPath(u); err != nil {
			t.Errorf("%s is a plain path: %v", raw, err)
		}
	}
}

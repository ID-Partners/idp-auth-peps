package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// §8.1.2 and §9: an Entity Statement is served as application/entity-statement+jwt.
// Anything else is not an Entity Statement response, whatever its body looks like.
func TestStatementsMustBeServedAsEntityStatements(t *testing.T) {
	t.Run("an entity configuration served as JSON", func(t *testing.T) {
		f := threeLevel(t)
		f.mid.contentType = "application/json"
		_, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id)
		if !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), "content type") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a subordinate statement served as text", func(t *testing.T) {
		f := threeLevel(t)
		f.anchor.fetchContentType = "text/plain"
		_, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id)
		if !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), "content type") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the subject's own configuration", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.contentType = "application/jwt"
		if _, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("parameters and case are tolerated", func(t *testing.T) {
		f := threeLevel(t)
		f.leaf.contentType = "Application/Entity-Statement+JWT; charset=utf-8"
		if _, err := newResolver(t, Options{}, f.anchor).Resolve(ctx(), f.leaf.id); err != nil {
			t.Fatal(err)
		}
	})
}

// Trust anchor keys are the one thing configured out of band. A key that could never
// verify anything is a configuration error to refuse at startup, not a chain that fails
// on every request; and a private key has no business in an anchors file.
func TestTrustAnchorKeysAreValidatedAtStartup(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := jose.PublicJWK(key)
	priv, _ := jose.PrivateJWK(key)
	with := func(changes map[string]any) map[string]any {
		k := map[string]any{}
		for n, v := range pub {
			k[n] = v
		}
		for n, v := range changes {
			if v == nil {
				delete(k, n)
			} else {
				k[n] = v
			}
		}
		return k
	}
	good := TrustAnchor{EntityID: "https://ta.example", Keys: []map[string]any{pub}}
	if _, err := New(Options{TrustAnchors: []TrustAnchor{good}}); err != nil {
		t.Fatalf("a public signing key is an anchor key: %v", err)
	}
	bad := map[string]TrustAnchor{
		"a private key":               {EntityID: "https://ta.example", Keys: []map[string]any{priv}},
		"no kid":                      {EntityID: "https://ta.example", Keys: []map[string]any{with(map[string]any{"kid": nil})}},
		"a shared kid":                {EntityID: "https://ta.example", Keys: []map[string]any{pub, with(map[string]any{"x": pub["y"]})}},
		"an encryption key":           {EntityID: "https://ta.example", Keys: []map[string]any{with(map[string]any{"use": "enc"})}},
		"not a key":                   {EntityID: "https://ta.example", Keys: []map[string]any{{"kid": "x"}}},
		"an off-curve point":          {EntityID: "https://ta.example", Keys: []map[string]any{with(map[string]any{"x": pub["y"]})}},
		"http without insecure":       {EntityID: "http://ta.example", Keys: []map[string]any{pub}},
		"not an entity identifier":    {EntityID: "https://ta.example/?q", Keys: []map[string]any{pub}},
		"a symmetric key":             {EntityID: "https://ta.example", Keys: []map[string]any{{"kty": "oct", "kid": "s", "k": "c2VjcmV0"}}},
		"an RSA key below the floor":  {EntityID: "https://ta.example", Keys: []map[string]any{{"kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB"}}},
		"more keys than a set may be": {EntityID: "https://ta.example", Keys: manyKeys(pub, jose.MaxJWKSKeys+1)},
	}
	for name, ta := range bad {
		if _, err := New(Options{TrustAnchors: []TrustAnchor{ta}}); err == nil {
			t.Errorf("%s: must be refused at startup", name)
		}
	}
	if _, err := New(Options{TrustAnchors: []TrustAnchor{{EntityID: "http://ta.example", Keys: []map[string]any{pub}}}, AllowInsecure: true}); err != nil {
		t.Fatalf("http is an anchor identifier when insecure metadata is allowed: %v", err)
	}
}

func manyKeys(k map[string]any, n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := range out {
		c := map[string]any{}
		for name, v := range k {
			c[name] = v
		}
		c["kid"] = strings.Repeat("k", i+1)
		out[i] = c
	}
	return out
}

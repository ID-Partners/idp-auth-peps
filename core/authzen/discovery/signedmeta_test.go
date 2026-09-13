package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// resourceWithSignedMetadata stands up a resource that publishes an RFC 9728 document
// plus a JWK set, and lets a test bend either one.
type signedResource struct {
	*httptest.Server
	key      *ecdsa.PrivateKey
	doc      map[string]any
	jwksKeys []map[string]any
	jwksCode int
}

func newSignedResource(t *testing.T, mutate func(self string, doc map[string]any, claims map[string]any)) *signedResource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	s := &signedResource{key: key, jwksKeys: []map[string]any{pub}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self := s.URL
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			doc := map[string]any{
				"resource":                self,
				"jwks_uri":                self + "/jwks",
				ParamPolicyDecisionPoints: []any{self + "/plain-pdp"},
			}
			claims := map[string]any{"iss": self, "resource": self}
			for k, v := range doc {
				if k != "resource" {
					claims[k] = v
				}
			}
			if mutate != nil {
				mutate(self, doc, claims)
			}
			if _, skip := doc["__unsigned"]; skip {
				delete(doc, "__unsigned")
			} else {
				tok, err := jose.Sign(map[string]any{"alg": "ES256", "kid": pub["kid"]}, claims, key)
				if err != nil {
					t.Fatal(err)
				}
				doc["signed_metadata"] = tok
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		case "/jwks":
			if s.jwksCode != 0 {
				w.WriteHeader(s.jwksCode)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": s.jwksKeys})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func lookupSigned(t *testing.T, s *signedResource) (ResourceMetadata, error) {
	t.Helper()
	src := &RFC9728Source{fetch: metafetch.New(nil, metafetch.Policy{AllowInsecure: true}, "", 0)}
	return src.Lookup(ctx(), s.URL)
}

// RFC 9728 2.1: once a consumer supports signed_metadata, the signed values "MUST take
// precedence over the corresponding values conveyed using plain JSON elements".
func TestSignedMetadataTakesPrecedence(t *testing.T) {
	s := newSignedResource(t, func(self string, doc, claims map[string]any) {
		doc[ParamPolicyDecisionPoints] = []any{self + "/plain-pdp"}
		claims[ParamPolicyDecisionPoints] = []any{self + "/signed-pdp"}
	})
	meta, err := lookupSigned(t, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.PDPs) != 1 || !strings.HasSuffix(meta.PDPs[0], "/signed-pdp") {
		t.Fatalf("the signed PDP list must win over the plain one, got %v", meta.PDPs)
	}
}

// The sharp edge of supporting it: a present-but-broken signature must never fall back to
// the unsigned body. Breaking a signature is easier than forging one, so a downgrade here
// would be the cheapest attack on the document.
func TestUnverifiableSignedMetadataIsNeverDowngraded(t *testing.T) {
	cases := map[string]func(*signedResource){
		"signed by a key that is not in the set": func(s *signedResource) {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			pub, _ := jose.PublicJWK(other)
			pub["kid"] = s.jwksKeys[0]["kid"] // same kid, different key
			s.jwksKeys = []map[string]any{pub}
		},
		"jwks_uri unreachable":    func(s *signedResource) { s.jwksCode = http.StatusInternalServerError },
		"jwks_uri serves no keys": func(s *signedResource) { s.jwksKeys = nil },
	}
	for name, bend := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSignedResource(t, nil)
			bend(s)
			if _, err := lookupSigned(t, s); err == nil {
				t.Fatal("an unverifiable signed_metadata must fail, not fall back to the unsigned body")
			}
		})
	}
}

func TestSignedMetadataClaimChecks(t *testing.T) {
	cases := map[string]struct {
		mutate func(self string, doc, claims map[string]any)
		want   string
	}{
		"issued by someone else": {
			mutate: func(self string, doc, claims map[string]any) { claims["iss"] = "https://elsewhere.example" },
			want:   "not the resource",
		},
		"about another resource": {
			mutate: func(self string, doc, claims map[string]any) { claims["resource"] = "https://other.example" },
			want:   "signed_metadata is about",
		},
		"no jwks_uri to verify with": {
			mutate: func(self string, doc, claims map[string]any) { delete(doc, "jwks_uri") },
			want:   "no jwks_uri",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSignedResource(t, c.mutate)
			_, err := lookupSigned(t, s)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
}

// A document without the member is left exactly as it was: the RFC permits publishing
// none, and most resources will not.
func TestUnsignedDocumentStillWorks(t *testing.T) {
	s := newSignedResource(t, func(self string, doc, claims map[string]any) { doc["__unsigned"] = true })
	meta, err := lookupSigned(t, s)
	if err != nil {
		t.Fatalf("an unsigned document must still resolve: %v", err)
	}
	if len(meta.PDPs) != 1 || !strings.HasSuffix(meta.PDPs[0], "/plain-pdp") {
		t.Fatalf("got %v", meta.PDPs)
	}
}

// An empty member is a malformed document, not an absent one.
func TestEmptySignedMetadataIsInvalid(t *testing.T) {
	s := newSignedResource(t, func(self string, doc, claims map[string]any) {
		doc["__unsigned"] = true
		doc["signed_metadata"] = ""
	})
	if _, err := lookupSigned(t, s); err == nil || !strings.Contains(err.Error(), "empty signed_metadata") {
		t.Fatalf("want an empty-member error, got %v", err)
	}
}

// The remaining refusals, each of which must fail rather than fall back.
func TestSignedMetadataRefusals(t *testing.T) {
	t.Run("not a compact JWS", func(t *testing.T) {
		s := newSignedResource(t, func(self string, doc, claims map[string]any) {
			doc["__unsigned"] = true
			doc["signed_metadata"] = "not.a.jws"
		})
		if _, err := lookupSigned(t, s); err == nil || !strings.Contains(err.Error(), "not a compact JWS") {
			t.Fatalf("want a malformed-JWS error, got %v", err)
		}
	})

	t.Run("an alg we will not verify", func(t *testing.T) {
		// `none` is the whole reason this check exists: it would let anyone assert
		// metadata for the resource.
		s := newSignedResource(t, func(self string, doc, claims map[string]any) {
			doc["__unsigned"] = true
			hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + self + `"}`))
			doc["signed_metadata"] = hdr + "." + body + "."
		})
		if _, err := lookupSigned(t, s); err == nil || !strings.Contains(err.Error(), "is not acceptable") {
			t.Fatalf("want an alg refusal, got %v", err)
		}
	})

	t.Run("a jwks_uri the policy refuses stays refused", func(t *testing.T) {
		s := newSignedResource(t, nil)
		// Everything but the JWK set may be fetched, so the refusal is specifically the
		// key lookup — and ErrNotAllowed must propagate rather than become ErrInvalid.
		src := &RFC9728Source{fetch: metafetch.New(nil, metafetch.Policy{
			AllowInsecure: true,
			Allow:         func(u string) bool { return !strings.HasSuffix(u, "/jwks") },
		}, "", 0)}
		_, err := src.Lookup(ctx(), s.URL)
		if !errors.Is(err, metafetch.ErrNotAllowed) {
			t.Fatalf("want ErrNotAllowed to propagate, got %v", err)
		}
	})

	t.Run("a kid names which key may verify", func(t *testing.T) {
		s := newSignedResource(t, nil)
		// An unrelated key first in the set must be skipped by kid, not tried and trusted.
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		decoy, err := jose.PublicJWK(other)
		if err != nil {
			t.Fatal(err)
		}
		decoy["kid"] = "someone-else"
		s.jwksKeys = append([]map[string]any{decoy}, s.jwksKeys...)
		if _, err := lookupSigned(t, s); err != nil {
			t.Fatalf("the right key is in the set and should verify: %v", err)
		}
	})
}

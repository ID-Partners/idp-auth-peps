package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
	"github.com/ID-Partners/idp-auth-peps/core/jose"
)

// The PEP as the resource's federation face: it holds the key, publishes a minimal
// entity configuration for the controller to onboard, and republishes as RFC 9728
// whatever the controller resolved for it.
func TestFederationEntityOnTheService(t *testing.T) {
	f := newFedFixture(t)
	f.policy = nil
	// What the controller says about the resource — none of it configured on the PEP.
	f.subMeta = map[string]any{"oauth_resource": map[string]any{
		discovery.ParamPolicyDecisionPoints: []any{"http://pdp.controller.example"},
		"scopes_supported":                  []any{"accounts:read"},
		"acr_values_required":               []any{"urn:idp:loa:mfa"},
	}}
	// The anchor vouches for the fixture leaf's key, so the PEP holds that key.
	keyFile := filepath.Join(t.TempDir(), "entity.json")
	priv, _ := jose.PrivateJWK(f.leafKey)
	raw, _ := json.Marshal(priv)
	if err := os.WriteFile(keyFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{
		"AUTHZEN_URL": "http://static.invalid/pdp", "PDP_DISCOVERY_INSECURE": "true", "PDP_METADATA_TTL": "1s",
		"FEDERATION_TRUST_ANCHORS_FILE": f.anchorsFile(t),
		"FEDERATION_ENTITY_ID":          f.leaf.URL + "/",
		"FEDERATION_ENTITY_KEY_FILE":    keyFile,
		"FEDERATION_AUTHORITY_HINTS":    f.anchor.URL + "/, ",
	}
	build := func(over map[string]string) (*server, *httptest.Server, error) {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range over {
			env[k] = v
		}
		srv, httpSrv, _, err := buildServer(func(k string) string { return env[k] })
		if err != nil {
			return nil, nil, err
		}
		ts := httptest.NewServer(httpSrv.Handler)
		t.Cleanup(ts.Close)
		return srv, ts, nil
	}
	get := func(ts *httptest.Server, path string) (*http.Response, string) {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	t.Run("minimal entity configuration, resolved RFC 9728", func(t *testing.T) {
		srv, ts, err := build(nil)
		if err != nil {
			t.Fatal(err)
		}
		if srv.entity == nil || srv.entity.ID != f.leaf.URL {
			t.Fatalf("entity: %+v", srv.entity)
		}
		resp, ec := get(ts, "/.well-known/openid-federation")
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/entity-statement+jwt") {
			t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		c := jose.Claims(ec)
		if c["iss"] != f.leaf.URL || c["sub"] != f.leaf.URL {
			t.Fatalf("%v", c)
		}
		if hints, _ := c["authority_hints"].([]any); len(hints) != 1 || hints[0] != f.anchor.URL {
			t.Fatalf("authority_hints: %v", c["authority_hints"])
		}
		meta, _ := c["metadata"].(map[string]any)
		or, _ := meta["oauth_resource"].(map[string]any)
		if len(or) != 1 || or["resource"] != f.leaf.URL {
			t.Fatalf("the entity configuration carries only the entity type: %v", meta)
		}
		if err := jose.VerifyJWS(ec, f.leafJWK, "ES256"); err != nil {
			t.Fatalf("signed with the held key: %v", err)
		}

		resp, body := get(ts, "/.well-known/oauth-protected-resource")
		if resp.StatusCode != 200 || resp.Header.Get("X-Resource-Metadata-Source") != "federation" {
			t.Fatalf("%d %s: %s", resp.StatusCode, resp.Header.Get("X-Resource-Metadata-Source"), body)
		}
		var doc map[string]any
		_ = json.Unmarshal([]byte(body), &doc)
		if pd, _ := doc[discovery.ParamPolicyDecisionPoints].([]any); len(pd) != 1 || pd[0] != "http://pdp.controller.example" {
			t.Fatalf("the controller's PDP, not the configured one: %v", doc)
		}
		if doc["resource"] != f.leaf.URL || doc["scopes_supported"] == nil || doc["acr_values_required"] == nil {
			t.Fatalf("%v", doc)
		}
		signed, _ := doc["signed_metadata"].(string)
		if err := jose.VerifyJWS(signed, f.leafJWK, "ES256"); err != nil {
			t.Fatalf("signed_metadata: %v", err)
		}
		if resp, _ := get(ts, "/.well-known/nothing"); resp.StatusCode != 404 {
			t.Fatal(resp.StatusCode)
		}
	})
	t.Run("without anchors it publishes what it is configured with", func(t *testing.T) {
		_, ts, err := build(map[string]string{"FEDERATION_TRUST_ANCHORS_FILE": ""})
		if err != nil {
			t.Fatal(err)
		}
		resp, body := get(ts, "/.well-known/oauth-protected-resource")
		if resp.Header.Get("X-Resource-Metadata-Source") != "self" {
			t.Fatalf("%s: %s", resp.Header.Get("X-Resource-Metadata-Source"), body)
		}
		var doc map[string]any
		_ = json.Unmarshal([]byte(body), &doc)
		if pd, _ := doc[discovery.ParamPolicyDecisionPoints].([]any); len(pd) != 1 || pd[0] != "http://static.invalid/pdp" || doc["scopes_supported"] != nil {
			t.Fatalf("%v", doc)
		}
	})
	t.Run("a key is minted when asked, and reused", func(t *testing.T) {
		fresh := filepath.Join(t.TempDir(), "new.json")
		if _, _, err := build(map[string]string{"FEDERATION_ENTITY_KEY_FILE": fresh}); err == nil {
			t.Fatal("a missing key file must fail unless generation is asked for")
		}
		srv, _, err := build(map[string]string{"FEDERATION_ENTITY_KEY_FILE": fresh, "FEDERATION_ENTITY_KEY_GENERATE": "true"})
		if err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%v %v", info, err)
		}
		first, _ := srv.entity.PublicJWK()
		srv2, _, err := build(map[string]string{"FEDERATION_ENTITY_KEY_FILE": fresh})
		if err != nil {
			t.Fatal(err)
		}
		second, _ := srv2.entity.PublicJWK()
		if first["kid"] != second["kid"] {
			t.Fatal("the minted key must be reused on the next start")
		}
	})
	t.Run("misconfiguration fails startup", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		_ = os.WriteFile(bad, []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b"}`), 0o600)
		notJSON := filepath.Join(t.TempDir(), "x.json")
		_ = os.WriteFile(notJSON, []byte(`nope`), 0o600)
		for name, over := range map[string]map[string]string{
			"bad id":        {"FEDERATION_ENTITY_ID": "not a url"},
			"id with query": {"FEDERATION_ENTITY_ID": "http://x.example/?a=1"},
			"no hints":      {"FEDERATION_AUTHORITY_HINTS": " , "},
			"no key file":   {"FEDERATION_ENTITY_KEY_FILE": ""},
			"bad key":       {"FEDERATION_ENTITY_KEY_FILE": bad},
			"not json":      {"FEDERATION_ENTITY_KEY_FILE": notJSON},
			"unwritable":    {"FEDERATION_ENTITY_KEY_FILE": "/nonexistent-dir/k.json", "FEDERATION_ENTITY_KEY_GENERATE": "true"},
		} {
			if _, _, err := build(over); err == nil {
				t.Errorf("%s: must fail startup", name)
			}
		}
	})
}

package main

import (
	"strings"
	"testing"
)

// insecureEnv is a test environment with PEP_ALLOW_INSECURE set unless m says otherwise:
// for tests about something other than the security settings themselves.
func insecureEnv(m map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		if k == "PEP_ALLOW_INSECURE" {
			return "true"
		}
		return ""
	}
}

// secureEnv is the least a production PEP starts with.
func secureEnv(over map[string]string) func(string) string {
	m := map[string]string{
		"AUTHZEN_URL":            "http://pdp:8080",
		"CHECK_API_TOKEN":        "secret",
		"MCP_UPSTREAM_ALLOWLIST": "http://a:8090/mcp, http://b:8090/mcp",
		"ACCESS_TOKEN_JWKS_URL":  "https://as/jwks",
		"ACCESS_TOKEN_ISSUER":    "https://as",
		"ACCESS_TOKEN_AUDIENCE":  "https://api",
		"USER_TOKEN_AUDIENCE":    "banking-app",
	}
	for k, v := range over {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

// buildServer holds all of main's config-bearing logic. main() itself is the
// listen/serve shell and is the one documented coverage exclusion.
func TestBuildServer(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	t.Run("requires AUTHZEN_URL, and an absolute one", func(t *testing.T) {
		if _, _, _, err := buildServer(insecureEnv(map[string]string{})); err == nil {
			t.Fatal("AUTHZEN_URL is mandatory")
		}
		if _, _, _, err := buildServer(insecureEnv(map[string]string{"AUTHZEN_URL": "authzen_pdp:8080"})); err == nil {
			t.Fatal("AUTHZEN_URL must be an absolute http(s) URL")
		}
	})

	t.Run("insecure settings refuse startup, all named at once", func(t *testing.T) {
		_, _, _, err := buildServer(env(map[string]string{"AUTHZEN_URL": "http://pdp:8080"}))
		if err == nil {
			t.Fatal("a PEP with an open check API and unverified tokens must not start")
		}
		for _, want := range []string{"CHECK_API_TOKEN", "MCP_UPSTREAM_ALLOWLIST", "ACCESS_TOKEN_JWKS_URL", "PEP_ALLOW_INSECURE"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal should name %s: %v", want, err)
			}
		}
		if _, _, _, err := buildServer(secureEnv(map[string]string{"ACCESS_TOKEN_ISSUER": "", "ACCESS_TOKEN_AUDIENCE": ""})); err == nil ||
			!strings.Contains(err.Error(), "ACCESS_TOKEN_ISSUER") || !strings.Contains(err.Error(), "ACCESS_TOKEN_AUDIENCE") {
			t.Fatalf("a JWKS without issuer and audience checks is a gap: %v", err)
		}
		if _, _, _, err := buildServer(secureEnv(map[string]string{"PDP_TLS_INSECURE": "true"})); err == nil {
			t.Fatal("PDP_TLS_INSECURE needs the hatch")
		}
	})

	t.Run("the hatch starts an insecure PEP, and marks it", func(t *testing.T) {
		srv, httpSrv, grpcPort, err := buildServer(insecureEnv(map[string]string{"AUTHZEN_URL": "http://pdp:8080/"}))
		if err != nil {
			t.Fatal(err)
		}
		if srv.authzenURL != "http://pdp:8080" {
			t.Fatalf("trailing slash should be trimmed, got %q", srv.authzenURL)
		}
		if grpcPort != "9191" || httpSrv.Addr != ":9192" {
			t.Fatalf("default ports wrong: grpc=%q http=%q", grpcPort, httpSrv.Addr)
		}
		if !srv.insecure || srv.accessValidator != nil || srv.userValidator != nil || !srv.decodeUserTokens {
			t.Fatalf("with the hatch and no JWKS tokens are decoded, and the PEP says so: %+v", srv)
		}
	})

	t.Run("full config is threaded through", func(t *testing.T) {
		srv, httpSrv, grpcPort, err := buildServer(secureEnv(map[string]string{
			"AUTHZEN_API_KEY":    "k",
			"PORT":               "7001",
			"HTTP_PORT":          "7002",
			"HTTP_ADDR":          "127.0.0.1",
			"COAZ_DISCOVERY_TTL": "5s",
			"DPOP_HTU_BASE":      "https://api.example.com/",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if grpcPort != "7001" || httpSrv.Addr != "127.0.0.1:7002" {
			t.Fatalf("ports/addr not threaded: grpc=%q http=%q", grpcPort, httpSrv.Addr)
		}
		if len(srv.upstreamAllowlist) != 2 || srv.accessValidator == nil || srv.userValidator == nil || srv.insecure {
			t.Fatalf("secure config: %+v", srv)
		}
		if srv.dpopHTUBase != "https://api.example.com" {
			t.Fatalf("DPOP_HTU_BASE: %q", srv.dpopHTUBase)
		}
	})

	t.Run("a user token with no audience to check is ignored, not decoded", func(t *testing.T) {
		srv, _, _, err := buildServer(secureEnv(map[string]string{"USER_TOKEN_AUDIENCE": ""}))
		if err != nil {
			t.Fatal(err)
		}
		if srv.userValidator != nil || srv.decodeUserTokens {
			t.Fatal("without USER_TOKEN_AUDIENCE an agent's own token would pass as the user's login")
		}
	})

	t.Run("user validator can be configured independently", func(t *testing.T) {
		srv, _, _, err := buildServer(secureEnv(map[string]string{
			"USER_TOKEN_JWKS_URL": "https://as/user-jwks",
			"USER_TOKEN_ISSUER":   "https://as",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if srv.userValidator == nil || srv.userValidator.jwks.url != "https://as/user-jwks" {
			t.Fatal("USER_TOKEN_JWKS_URL should build the user validator")
		}
	})

	t.Run("bad values are refused, not replaced", func(t *testing.T) {
		for k, v := range map[string]string{
			"COAZ_DISCOVERY_TTL": "not-a-duration",
			"DPOP_HTU_BASE":      "https://api.example.com/v1",
			"PDP_FAIL_MODE":      "sometimes",
		} {
			if _, _, _, err := buildServer(secureEnv(map[string]string{k: v})); err == nil {
				t.Errorf("%s=%q should fail startup", k, v)
			}
		}
	})
}

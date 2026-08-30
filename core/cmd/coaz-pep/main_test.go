package main

import "testing"

// buildServer holds all of main's config-bearing logic. main() itself is the
// listen/serve shell and is the one documented coverage exclusion.
func TestBuildServer(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	t.Run("requires AUTHZEN_URL", func(t *testing.T) {
		if _, _, _, err := buildServer(env(map[string]string{})); err == nil {
			t.Fatal("AUTHZEN_URL is mandatory")
		}
	})

	t.Run("minimal config wires the server and warns", func(t *testing.T) {
		srv, httpSrv, grpcPort, err := buildServer(env(map[string]string{"AUTHZEN_URL": "http://pdp:8080/"}))
		if err != nil {
			t.Fatal(err)
		}
		if srv.authzenURL != "http://pdp:8080" {
			t.Fatalf("trailing slash should be trimmed, got %q", srv.authzenURL)
		}
		if grpcPort != "9191" || httpSrv.Addr != ":9192" {
			t.Fatalf("default ports wrong: grpc=%q http=%q", grpcPort, httpSrv.Addr)
		}
		// Unconfigured validators — decode-and-warn, not nil-panic.
		if srv.accessValidator != nil || srv.userValidator != nil {
			t.Fatal("no JWKS configured should leave the validators nil (decode mode)")
		}
		if len(srv.upstreamAllowlist) != 0 {
			t.Fatal("no allowlist configured should be empty")
		}
	})

	t.Run("full config is threaded through", func(t *testing.T) {
		srv, httpSrv, grpcPort, err := buildServer(env(map[string]string{
			"AUTHZEN_URL":            "http://pdp:8080",
			"AUTHZEN_API_KEY":        "k",
			"PORT":                   "7001",
			"HTTP_PORT":              "7002",
			"HTTP_ADDR":              "127.0.0.1",
			"COAZ_DISCOVERY_TTL":     "5s",
			"PDP_TLS_INSECURE":       "true",
			"CHECK_API_TOKEN":        "secret",
			"MCP_UPSTREAM_ALLOWLIST": "http://a:8090/mcp, http://b:8090/mcp",
			"ACCESS_TOKEN_JWKS_URL":  "https://as/jwks",
			"ACCESS_TOKEN_ISSUER":    "https://as",
			"ACCESS_TOKEN_AUDIENCE":  "https://api",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if grpcPort != "7001" || httpSrv.Addr != "127.0.0.1:7002" {
			t.Fatalf("ports/addr not threaded: grpc=%q http=%q", grpcPort, httpSrv.Addr)
		}
		if len(srv.upstreamAllowlist) != 2 {
			t.Fatalf("allowlist should have two entries, got %v", srv.upstreamAllowlist)
		}
		if srv.accessValidator == nil {
			t.Fatal("a configured JWKS should build an access validator")
		}
		// USER_TOKEN_* fall back to the access-token config.
		if srv.userValidator == nil {
			t.Fatal("the user validator should fall back to the access-token JWKS")
		}
	})

	t.Run("user validator can be configured independently", func(t *testing.T) {
		srv, _, _, err := buildServer(env(map[string]string{
			"AUTHZEN_URL":         "http://pdp:8080",
			"USER_TOKEN_JWKS_URL": "https://as/user-jwks",
			"USER_TOKEN_ISSUER":   "https://as",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if srv.userValidator == nil {
			t.Fatal("USER_TOKEN_JWKS_URL alone should build the user validator")
		}
		if srv.accessValidator != nil {
			t.Fatal("no ACCESS_TOKEN_JWKS_URL should leave the access validator nil")
		}
	})

	t.Run("a bad TTL falls back to the default", func(t *testing.T) {
		// An unparseable duration must not fail startup; it falls back to 60s.
		if _, _, _, err := buildServer(env(map[string]string{
			"AUTHZEN_URL": "http://pdp:8080", "COAZ_DISCOVERY_TTL": "not-a-duration",
		})); err != nil {
			t.Fatalf("a bad TTL should not fail startup: %v", err)
		}
	})
}

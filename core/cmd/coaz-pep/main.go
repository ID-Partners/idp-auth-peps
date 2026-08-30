package main

// coaz-pep: an AuthZEN Policy Enforcement Point for API gateways, with
// support for the OpenID AuthZEN MCP profile (COAZ).
//
// It serves two frontends over the same PEP core:
//
//   - Envoy External Authorization gRPC (agentgateway/Envoy/Istio attach it
//     via their extAuthz policy) — default :9191
//   - HTTP check API (the Kong authzen-pdp plugin delegates to it) — default :9192
//
// Environment:
//   AUTHZEN_URL          AuthZEN PDP base URL (required), e.g. http://authzen-adapter:8080
//   AUTHZEN_API_KEY      Bearer key for the PDP
//   PORT                 ext_authz gRPC port (default 9191)
//   HTTP_PORT            HTTP check API port (default 9192)
//   COAZ_DISCOVERY_TTL   tools/list cache TTL, Go duration (default 60s)
//   PDP_TLS_INSECURE     "true" to skip PDP TLS verification (demo only)

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/ID-Partners/idp-auth-peps/core/coaz"
)

// buildServer assembles the server, HTTP mux and http.Server from the environment.
// All of the decision-bearing wiring lives here — validator config, the SSRF guards,
// the check-token — so it is unit-testable; main() is left as the thin listen/serve
// shell, which is the one part that cannot be exercised without binding real sockets.
// getenv is injected so a test can drive the whole matrix of configurations.
func buildServer(getenv func(string) string) (*server, *http.Server, string, error) {
	env := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	grpcPort := env("PORT", "9191")
	httpPort := env("HTTP_PORT", "9192")
	authzenURL := strings.TrimRight(getenv("AUTHZEN_URL"), "/")
	if authzenURL == "" {
		return nil, nil, "", fmt.Errorf("AUTHZEN_URL is required (e.g. http://authzen-adapter:8080)")
	}
	ttl := 60 * time.Second
	if v := getenv("COAZ_DISCOVERY_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ttl = d
		}
	}

	httpc := &http.Client{Timeout: 10 * time.Second}
	if strings.EqualFold(getenv("PDP_TLS_INSECURE"), "true") {
		httpc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	srv := &server{
		authzenURL:    authzenURL,
		authzenAPIKey: getenv("AUTHZEN_API_KEY"),
		httpc:         httpc,
		coaz: coaz.NewEngine(coaz.Options{
			PDP:          coaz.PDPConfig{URL: authzenURL, APIKey: getenv("AUTHZEN_API_KEY"), HTTPClient: httpc},
			DiscoveryTTL: ttl,
		}),
	}

	// This endpoint takes a caller-supplied mcp_upstream_url AND a caller-supplied
	// authorization header, then fetches that URL with that header. Left open, it is an
	// SSRF and credential-relay primitive, so it takes two guards: a shared secret and
	// an upstream allowlist. Both warn loudly when unset rather than silently failing
	// open, because an operator who has not configured them should know.
	checkToken := getenv("CHECK_API_TOKEN")
	if checkToken == "" {
		log.Printf("WARNING: CHECK_API_TOKEN is unset — the HTTP check API on :%s is "+
			"UNAUTHENTICATED. Set it, or keep the port off any untrusted network.", httpPort)
	}
	srv.upstreamAllowlist = parseAllowlist(getenv("MCP_UPSTREAM_ALLOWLIST"))
	if len(srv.upstreamAllowlist) == 0 {
		log.Printf("WARNING: MCP_UPSTREAM_ALLOWLIST is unset — any caller-supplied " +
			"mcp_upstream_url will be fetched server-side. Set it to the MCP servers you govern.")
	}

	// Token validation. Configured -> fail closed; unconfigured -> decode and warn.
	// X-User-Token is the sharper of the two: its claims drive the step-up and consent
	// gates, so an unverified one is a bypass of both.
	srv.accessValidator = NewValidator(ValidatorConfig{
		JWKSURL:  getenv("ACCESS_TOKEN_JWKS_URL"),
		Issuer:   getenv("ACCESS_TOKEN_ISSUER"),
		Audience: getenv("ACCESS_TOKEN_AUDIENCE"),
	})
	srv.userValidator = NewValidator(ValidatorConfig{
		JWKSURL:  env("USER_TOKEN_JWKS_URL", getenv("ACCESS_TOKEN_JWKS_URL")),
		Issuer:   env("USER_TOKEN_ISSUER", getenv("ACCESS_TOKEN_ISSUER")),
		Audience: getenv("USER_TOKEN_AUDIENCE"),
	})
	if srv.accessValidator == nil {
		log.Printf("WARNING: ACCESS_TOKEN_JWKS_URL is unset — access tokens are DECODED, " +
			"NOT VERIFIED. The COAZ-MCP binding requires validation before claims are used.")
	}
	if srv.userValidator == nil {
		log.Printf("WARNING: no JWKS configured for X-User-Token — it is DECODED, NOT VERIFIED. " +
			"Its claims drive the step-up and consent gates, so a forged one bypasses them.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mcp/check", requireCheckToken(checkToken, srv.handleHTTPCheck))
	// Sender-constraint verification for gateways that cannot do it themselves — the
	// Kong plugin, which has no JOSE verifier available to it.
	mux.HandleFunc("/v1/dpop/verify", requireCheckToken(checkToken, srv.handleDpopVerify))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	httpSrv := &http.Server{
		Addr:              env("HTTP_ADDR", "") + ":" + httpPort,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Slowloris
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv, httpSrv, grpcPort, nil
}

// main is the listen/serve shell: it binds real sockets, so it is the one function that
// cannot be meaningfully unit-tested and is excluded from the coverage bar. Everything it
// decides is in buildServer, which is tested. Keep this function trivial — anything with
// a branch worth asserting belongs in buildServer.
func main() {
	srv, httpSrv, grpcPort, err := buildServer(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		log.Printf("coaz-pep HTTP check API listening on %s", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	lis, err := net.Listen("tcp", ":"+grpcPort) // dual-stack
	if err != nil {
		log.Fatalf("listen :%s: %v", grpcPort, err)
	}
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, srv)
	healthpb.RegisterHealthServer(gs, health.NewServer())
	log.Printf("coaz-pep ext_authz (Envoy gRPC) listening on :%s, PDP at %s", grpcPort, srv.authzenURL)
	if err := gs.Serve(lis); err != nil {
		log.Fatal(err)
	}
}

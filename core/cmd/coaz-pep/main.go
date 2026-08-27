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

func main() {
	grpcPort := envOr("PORT", "9191")
	httpPort := envOr("HTTP_PORT", "9192")
	authzenURL := strings.TrimRight(os.Getenv("AUTHZEN_URL"), "/")
	if authzenURL == "" {
		log.Fatal("AUTHZEN_URL is required (e.g. http://authzen-adapter:8080)")
	}
	ttl := 60 * time.Second
	if v := os.Getenv("COAZ_DISCOVERY_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ttl = d
		}
	}

	httpc := &http.Client{Timeout: 10 * time.Second}
	if strings.EqualFold(os.Getenv("PDP_TLS_INSECURE"), "true") {
		httpc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	srv := &server{
		authzenURL:    authzenURL,
		authzenAPIKey: os.Getenv("AUTHZEN_API_KEY"),
		httpc:         httpc,
		coaz: coaz.NewEngine(coaz.Options{
			PDP:          coaz.PDPConfig{URL: authzenURL, APIKey: os.Getenv("AUTHZEN_API_KEY"), HTTPClient: httpc},
			DiscoveryTTL: ttl,
		}),
	}

	// HTTP check API (Kong et al.)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mcp/check", srv.handleHTTPCheck)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	go func() {
		log.Printf("coaz-pep HTTP check API listening on :%s", httpPort)
		if err := http.ListenAndServe(":"+httpPort, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// Envoy ext_authz gRPC
	lis, err := net.Listen("tcp", ":"+grpcPort) // dual-stack
	if err != nil {
		log.Fatalf("listen :%s: %v", grpcPort, err)
	}
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, srv)
	healthpb.RegisterHealthServer(gs, health.NewServer())
	log.Printf("coaz-pep ext_authz (Envoy gRPC) listening on :%s, PDP at %s, COAZ discovery TTL %s",
		grpcPort, authzenURL, ttl)
	if err := gs.Serve(lis); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

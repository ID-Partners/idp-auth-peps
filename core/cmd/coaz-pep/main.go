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
//
// PDP discovery (see core/authzen/discovery):
//   PDP_DISCOVERY                off | authzen | resource | federation (default off)
//   PDP_METADATA_TTL             resource/PDP metadata cache TTL (default 5m)
//   PDP_ALLOWLIST                permitted discovered PDP prefixes; AUTHZEN_URL always included
//   RESOURCE_METADATA_ALLOWLIST  permitted `resource` prefixes for metadata fetches
//   PDP_DISCOVERY_INSECURE       "true" allows http for discovered URLs (dev only)
//   FEDERATION_TRUST_ANCHORS_FILE JSON {"<entity id>": {"keys":[JWK...]}}; federation mode
//   FEDERATION_FETCH_ALLOWLIST   permitted prefixes for the climb: superiors' entity configurations and fetch endpoints
//                                (the subject's own is governed by RESOURCE_METADATA_ALLOWLIST)
//   FEDERATION_MAX_PATH_LENGTH   intermediates allowed between resource and anchor (default 4)

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
	"github.com/ID-Partners/idp-auth-peps/core/coaz"
	"github.com/ID-Partners/idp-auth-peps/core/federation"
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

	resolver, err := buildResolver(getenv, authzenURL, httpc)
	if err != nil {
		return nil, nil, "", err
	}

	srv := &server{
		authzenURL:    authzenURL,
		authzenAPIKey: getenv("AUTHZEN_API_KEY"),
		httpc:         httpc,
		resolver:      resolver,
		coaz: coaz.NewEngine(coaz.Options{
			PDP:          coaz.PDPConfig{URL: authzenURL, APIKey: getenv("AUTHZEN_API_KEY"), HTTPClient: httpc},
			Resolver:     resolver,
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

// buildResolver assembles PDP discovery from the environment. Off (the default) is the
// static PDP with the AuthZEN default paths and no HTTP — byte-for-byte today's
// behaviour. Warm-up failures are logged, not fatal: the resolver degrades to the
// default paths, and a PDP that is down at boot is a runtime condition, not a config
// error.
func buildResolver(getenv func(string) string, authzenURL string, httpc *http.Client) (*discovery.Chain, error) {
	mode, err := discovery.ParseMode(getenv("PDP_DISCOVERY"))
	if err != nil {
		return nil, err
	}
	metaTTL := 5 * time.Minute
	if v := getenv("PDP_METADATA_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			metaTTL = d
		} else {
			log.Printf("WARNING: PDP_METADATA_TTL %q is not a duration; using %s", v, metaTTL)
		}
	}
	insecure := strings.EqualFold(getenv("PDP_DISCOVERY_INSECURE"), "true")
	resAllow := parseAllowlist(getenv("RESOURCE_METADATA_ALLOWLIST"))

	opts := discovery.Options{
		Mode:          mode,
		StaticPDP:     authzenURL,
		APIKeys:       map[string]string{authzenURL: getenv("AUTHZEN_API_KEY")},
		HTTPClient:    httpc,
		TTL:           metaTTL,
		AllowInsecure: insecure,
	}
	// The static PDP is the operator's own and is always permitted; the allowlist
	// bounds what a resource's metadata may add to it.
	if pdpAllow := parseAllowlist(getenv("PDP_ALLOWLIST")); len(pdpAllow) > 0 {
		pdpAllow = append(pdpAllow, authzenURL)
		opts.PDPAllowed = func(u string) bool { return upstreamAllowed(pdpAllow, u) }
	}
	if mode == discovery.ModeResource || mode == discovery.ModeFederation {
		if len(resAllow) == 0 {
			log.Printf("WARNING: RESOURCE_METADATA_ALLOWLIST is unset — any caller-supplied " +
				"`resource` will have its metadata fetched server-side. Set it to the resources you govern.")
		} else {
			opts.ResourceAllowed = func(u string) bool { return upstreamAllowed(resAllow, u) }
		}
		if getenv("PDP_ALLOWLIST") == "" {
			log.Printf("WARNING: PDP_ALLOWLIST is unset — a resource's metadata may point this PEP at " +
				"any https PDP. Set it to the PDPs you trust.")
		}
	}
	if mode == discovery.ModeFederation {
		fed, err := buildFederation(getenv, httpc, insecure, opts.ResourceAllowed)
		if err != nil {
			return nil, err
		}
		opts.Federation = fed
	}
	if mode != discovery.ModeOff && insecure {
		log.Printf("WARNING: PDP_DISCOVERY_INSECURE is set — discovered http URLs are accepted. Dev only.")
	}
	chain, err := discovery.New(opts)
	if err != nil {
		return nil, err
	}
	if mode != discovery.ModeOff {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := chain.Warm(ctx); err != nil {
			log.Printf("WARNING: PDP discovery warm-up for %s failed: %v", authzenURL, err)
		} else if ep, err := chain.Resolve(ctx, ""); err == nil {
			log.Printf("PDP discovery (%s): %s evaluates at %s", mode, ep.Identifier, ep.Evaluation)
		}
	}
	return chain, nil
}

// buildFederation loads the Trust Anchors and builds the chain resolver.
func buildFederation(getenv func(string) string, httpc *http.Client, insecure bool, resourceAllowed func(string) bool) (*federation.Resolver, error) {
	path := getenv("FEDERATION_TRUST_ANCHORS_FILE")
	if path == "" {
		return nil, fmt.Errorf("PDP_DISCOVERY=federation requires FEDERATION_TRUST_ANCHORS_FILE")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading FEDERATION_TRUST_ANCHORS_FILE: %w", err)
	}
	var doc map[string]struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("FEDERATION_TRUST_ANCHORS_FILE is not {\"<entity id>\": {\"keys\": [...]}}: %w", err)
	}
	var anchors []federation.TrustAnchor
	for id, v := range doc {
		anchors = append(anchors, federation.TrustAnchor{EntityID: strings.TrimRight(id, "/"), Keys: v.Keys})
	}
	// The resource allowlist governs the subject's own Entity Configuration; the fetch
	// allowlist governs the climb from there to the anchor.
	fopts := federation.Options{TrustAnchors: anchors, HTTPClient: httpc, AllowInsecure: insecure, SubjectAllowed: resourceAllowed}
	if v := getenv("FEDERATION_MAX_PATH_LENGTH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("FEDERATION_MAX_PATH_LENGTH %q is not a non-negative integer", v)
		}
		fopts.MaxPathLength = n
	}
	if allow := parseAllowlist(getenv("FEDERATION_FETCH_ALLOWLIST")); len(allow) > 0 {
		fopts.FetchAllowed = func(u string) bool { return upstreamAllowed(allow, u) }
	} else {
		log.Printf("WARNING: FEDERATION_FETCH_ALLOWLIST is unset — walking a trust chain may fetch " +
			"from any https host an authority_hints names.")
	}
	return federation.New(fopts)
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

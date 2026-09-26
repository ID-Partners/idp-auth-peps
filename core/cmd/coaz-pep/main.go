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
//   PEP_ALLOW_INSECURE   "true" to start despite missing security settings, each of which
//                        is then logged; without it they refuse startup. Development only.
//   GRPC_TLS_CERT_FILE / GRPC_TLS_KEY_FILE  serve ext_authz over TLS; add
//   GRPC_TLS_CLIENT_CA_FILE to require client certificates (mTLS)
//   LOG_FORMAT           json (default) or text
//   DPOP_HTU_BASE        the external origin clients send DPoP proofs for, e.g.
//                        https://api.example.com; htu must be it plus the request path
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
//   PDP_LAYERS                   ordered PDPs to ask, every one of which must permit: `static`,
//                                `resource`, or a PDP identifier, each optionally followed by
//                                `fail-open` or `fail-closed` (default: resource). Routes may
//                                override with `pdp_layers`; explicit identifiers there must be
//                                on PDP_ALLOWLIST, ones named here are allowlisted automatically.
//   PDP_FAIL_MODE                `closed` (default) or `open`: what a layer does when its PDP
//                                cannot be reached, unless the layer says for itself. Open skips
//                                the layer; a permit that skipped anything carries
//                                X-PDP-Fail-Open. Refusals (allowlist, invalid chain) never open.
//   FEDERATION_ENTITY_ID         make this PEP the federation entity for the resource it fronts: it
//                                publishes a minimal Entity Configuration (keys, authority_hints, the
//                                entity type) at {id}/.well-known/openid-federation for a trust
//                                controller to onboard, and RFC 9728 metadata at
//                                /.well-known/oauth-protected-resource{path} that republishes what the
//                                federation resolved (needs FEDERATION_TRUST_ANCHORS_FILE), or what
//                                this PEP is configured with until it has been onboarded.
//   FEDERATION_ENTITY_KEY_FILE   private JWK (EC or RSA) the entity signs with; required with an id
//   FEDERATION_ENTITY_KEY_GENERATE  `true` to mint a P-256 key into that file when it is absent
//   FEDERATION_AUTHORITY_HINTS   comma-separated superiors the trust controller is reached through

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ID-Partners/idp-auth-peps/core/jose"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
	"github.com/ID-Partners/idp-auth-peps/core/coaz"
	"github.com/ID-Partners/idp-auth-peps/core/federation"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

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
	// Every security setting left unset is collected here. Unless PEP_ALLOW_INSECURE is
	// set they refuse startup, all of them named at once; with it, each is logged. A PEP
	// that comes up with an open check API or unverified tokens is worse than one that
	// does not come up.
	var gaps []string
	insecure := func(format string, args ...any) { gaps = append(gaps, fmt.Sprintf(format, args...)) }

	grpcPort := env("PORT", "9191")
	httpPort := env("HTTP_PORT", "9192")
	authzenURL := strings.TrimRight(getenv("AUTHZEN_URL"), "/")
	if authzenURL == "" {
		return nil, nil, "", fmt.Errorf("AUTHZEN_URL is required (e.g. http://authzen-adapter:8080)")
	}
	if u, err := url.Parse(authzenURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, nil, "", fmt.Errorf("AUTHZEN_URL %q is not an absolute http(s) URL", authzenURL)
	}
	ttl, err := durationEnv(getenv, "COAZ_DISCOVERY_TTL", 60*time.Second)
	if err != nil {
		return nil, nil, "", err
	}

	// The PDP is asked, never followed: a redirect would send the request — and a
	// forwarded access token — somewhere the allowlist never approved.
	httpc := &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirects}
	if strings.EqualFold(getenv("PDP_TLS_INSECURE"), "true") {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpc.Transport = t
		insecure("PDP_TLS_INSECURE is set: the PDP's TLS certificate is not verified")
	}
	// Metadata and federation fetches get their own client: PDP_TLS_INSECURE is about the
	// PDP, and must not quietly switch off TLS for the trust chain as well. metafetch
	// re-checks its allowlist on every redirect hop itself.
	metac := &http.Client{Timeout: 10 * time.Second}

	layers, err := discovery.ParseLayers(getenv("PDP_LAYERS"))
	if err != nil {
		return nil, nil, "", fmt.Errorf("PDP_LAYERS: %w", err)
	}
	failOpen := false
	switch strings.ToLower(getenv("PDP_FAIL_MODE")) {
	case "", "closed":
	case "open":
		failOpen = true
		slog.Warn("PDP_FAIL_MODE=open — a PDP that cannot be reached is SKIPPED and the request " +
			"may be permitted with X-PDP-Fail-Open set. Refusals still fail closed. Make sure that is the intent.")
	default:
		return nil, nil, "", fmt.Errorf("PDP_FAIL_MODE %q is neither open nor closed", getenv("PDP_FAIL_MODE"))
	}
	for _, l := range layers {
		if l.FailOpen != nil && *l.FailOpen {
			slog.Warn(fmt.Sprintf("PDP_LAYERS: %s is fail-open — when it cannot be reached it is skipped.", l.Name))
		}
	}
	resolver, fed, err := buildResolver(getenv, authzenURL, metac, layers, insecure)
	if err != nil {
		return nil, nil, "", err
	}

	srv := &server{
		authzenURL:    authzenURL,
		authzenAPIKey: getenv("AUTHZEN_API_KEY"),
		httpc:         httpc,
		resolver:      resolver,
		defaultLayers: layers,
		failOpen:      failOpen,
		dpopHTUBase:   strings.TrimRight(getenv("DPOP_HTU_BASE"), "/"),
		metrics:       newMetrics(),
		coaz: coaz.NewEngine(coaz.Options{
			PDP:                 coaz.PDPConfig{URL: authzenURL, APIKey: getenv("AUTHZEN_API_KEY"), HTTPClient: httpc},
			Resolver:            resolver,
			DiscoveryTTL:        ttl,
			DiscoveryHTTPClient: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirects},
		}),
	}
	if srv.dpopHTUBase != "" {
		if u, err := url.Parse(srv.dpopHTUBase); err != nil || !u.IsAbs() || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return nil, nil, "", fmt.Errorf("DPOP_HTU_BASE %q is not an origin like https://api.example.com", srv.dpopHTUBase)
		}
	}

	// This endpoint takes a caller-supplied mcp_upstream_url AND a caller-supplied
	// authorization header, then fetches that URL with that header. Left open, it is an
	// SSRF and credential-relay primitive, so it takes two guards: a shared secret and
	// an upstream allowlist.
	checkToken := getenv("CHECK_API_TOKEN")
	if checkToken == "" {
		insecure("CHECK_API_TOKEN is unset: the HTTP check API on :%s is unauthenticated", httpPort)
	}
	srv.upstreamAllowlist = parseAllowlist(getenv("MCP_UPSTREAM_ALLOWLIST"))
	if len(srv.upstreamAllowlist) == 0 {
		insecure("MCP_UPSTREAM_ALLOWLIST is unset: any caller-supplied mcp_upstream_url is fetched server-side")
	}

	// Token validation. The binding: "The PEP MUST verify the token signature, issuer,
	// audience, and expiration." Each of those left unconfigured is a gap.
	srv.accessValidator = NewValidator(ValidatorConfig{
		JWKSURL:  getenv("ACCESS_TOKEN_JWKS_URL"),
		Issuer:   getenv("ACCESS_TOKEN_ISSUER"),
		Audience: getenv("ACCESS_TOKEN_AUDIENCE"),
	})
	if srv.accessValidator == nil {
		insecure("ACCESS_TOKEN_JWKS_URL is unset: access tokens and X-User-Token are decoded, not verified")
	} else {
		if getenv("ACCESS_TOKEN_ISSUER") == "" {
			insecure("ACCESS_TOKEN_ISSUER is unset: the access token's issuer is not checked")
		}
		if getenv("ACCESS_TOKEN_AUDIENCE") == "" {
			insecure("ACCESS_TOKEN_AUDIENCE is unset: a token minted for another resource is accepted")
		}
	}
	// X-User-Token needs an audience as well as a key: the agent's own access token comes
	// from the same issuer and verifies against the same JWKS, and without an audience it
	// would pass as the user having logged in.
	userJWKS, userAud := env("USER_TOKEN_JWKS_URL", getenv("ACCESS_TOKEN_JWKS_URL")), getenv("USER_TOKEN_AUDIENCE")
	switch {
	case userJWKS != "" && userAud != "":
		srv.userValidator = NewValidator(ValidatorConfig{
			JWKSURL:  userJWKS,
			Issuer:   env("USER_TOKEN_ISSUER", getenv("ACCESS_TOKEN_ISSUER")),
			Audience: userAud,
		})
	case userJWKS != "":
		slog.Warn("USER_TOKEN_AUDIENCE is unset — X-User-Token is IGNORED, so require_user_login " +
			"routes deny. Set it to the audience the user's own login token carries.")
	default:
		// Only reachable without any JWKS, which is itself a gap above.
		srv.decodeUserTokens = true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mcp/check", requireCheckToken(checkToken, srv.handleHTTPCheck))
	// Sender-constraint verification for gateways that cannot do it themselves.
	mux.HandleFunc("/v1/dpop/verify", requireCheckToken(checkToken, srv.handleDpopVerify))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", srv.handleReady)
	mux.Handle("/metrics", srv.metrics)
	// The PEP as the resource's federation face: the gateway routes the resource's two
	// well-known paths here.
	if id := strings.TrimRight(getenv("FEDERATION_ENTITY_ID"), "/"); id != "" {
		ent, err := buildEntity(getenv, id, authzenURL, fed)
		if err != nil {
			return nil, nil, "", err
		}
		srv.entity = ent
		fedPath, resPath := ent.Paths()
		mux.Handle(fedPath, ent.Handler())
		mux.Handle(resPath, ent.Handler())
		log.Printf("federation entity %s: entity configuration at %s, protected resource metadata at %s", id, fedPath, resPath)
		if fed == nil {
			slog.Warn(fmt.Sprintf("FEDERATION_TRUST_ANCHORS_FILE is unset — %s publishes the PDP it is configured "+
				"with, not what a federation resolves for it. Set the anchors so the RFC 9728 document is the controller's word.", id))
		}
	}

	if len(gaps) > 0 {
		if !strings.EqualFold(getenv("PEP_ALLOW_INSECURE"), "true") {
			return nil, nil, "", fmt.Errorf("refusing to start with insecure settings:\n  - %s\n"+
				"Configure them, or set PEP_ALLOW_INSECURE=true for development — never for anything a real client reaches",
				strings.Join(gaps, "\n  - "))
		}
		for _, g := range gaps {
			slog.Warn("insecure setting allowed by PEP_ALLOW_INSECURE", "gap", g)
		}
		srv.insecure = true
	}

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

// noRedirects makes a client return a redirect instead of following it.
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// durationEnv reads a Go duration, refusing one that does not parse: a typo in a TTL
// must not silently become the default.
func durationEnv(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s %q is not a positive duration", key, v)
	}
	return d, nil
}

// buildResolver assembles PDP discovery from the environment. Off (the default) is the
// static PDP with the AuthZEN default paths and no HTTP — byte-for-byte today's
// behaviour. Warm-up failures are logged, not fatal: the resolver degrades to the
// default paths, and a PDP that is down at boot is a runtime condition, not a config
// error.
func buildResolver(getenv func(string) string, authzenURL string, httpc *http.Client, layers []discovery.LayerSpec, insecure func(string, ...any)) (*discovery.Chain, *federation.Resolver, error) {
	mode, err := discovery.ParseMode(getenv("PDP_DISCOVERY"))
	if err != nil {
		return nil, nil, err
	}
	metaTTL, err := durationEnv(getenv, "PDP_METADATA_TTL", 5*time.Minute)
	if err != nil {
		return nil, nil, err
	}
	allowHTTP := strings.EqualFold(getenv("PDP_DISCOVERY_INSECURE"), "true")
	resAllow := parseAllowlist(getenv("RESOURCE_METADATA_ALLOWLIST"))

	opts := discovery.Options{
		Mode:          mode,
		StaticPDP:     authzenURL,
		APIKeys:       map[string]string{authzenURL: getenv("AUTHZEN_API_KEY")},
		HTTPClient:    httpc,
		TTL:           metaTTL,
		AllowInsecure: allowHTTP,
	}
	// The static PDP is the operator's own and is always permitted, and so is any PDP
	// the operator named as a layer in this service's own configuration; the allowlist
	// bounds what a resource's metadata or a route's config may add.
	if pdpAllow := parseAllowlist(getenv("PDP_ALLOWLIST")); len(pdpAllow) > 0 {
		pdpAllow = append(pdpAllow, authzenURL)
		for _, l := range layers {
			if strings.Contains(l.Name, "://") {
				pdpAllow = append(pdpAllow, l.Name)
			}
		}
		opts.PDPAllowed = func(u string) bool { return upstreamAllowed(pdpAllow, u) }
	}
	if mode == discovery.ModeResource || mode == discovery.ModeFederation {
		if len(resAllow) == 0 {
			insecure("RESOURCE_METADATA_ALLOWLIST is unset: any caller-supplied resource has its metadata fetched server-side")
		} else {
			opts.ResourceAllowed = func(u string) bool { return upstreamAllowed(resAllow, u) }
		}
		if getenv("PDP_ALLOWLIST") == "" {
			insecure("PDP_ALLOWLIST is unset: a resource's metadata may point this PEP at any https PDP")
		}
	}
	// A chain resolver is built whenever anchors are configured: federation-mode
	// discovery uses it, and so does the PEP's own entity (FEDERATION_ENTITY_ID), which
	// may run in any discovery mode.
	var fed *federation.Resolver
	if mode == discovery.ModeFederation || getenv("FEDERATION_TRUST_ANCHORS_FILE") != "" {
		f, err := buildFederation(getenv, httpc, allowHTTP, opts.ResourceAllowed, metaTTL, insecure)
		if err != nil {
			return nil, nil, err
		}
		fed = f
		if mode == discovery.ModeFederation {
			opts.Federation = fed
		}
	}
	if mode != discovery.ModeOff && allowHTTP {
		insecure("PDP_DISCOVERY_INSECURE is set: discovered http URLs are accepted")
	}
	chain, err := discovery.New(opts)
	if err != nil {
		return nil, nil, err
	}
	if mode != discovery.ModeOff {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := chain.Warm(ctx); err != nil {
			slog.Warn(fmt.Sprintf("PDP discovery warm-up for %s failed: %v", authzenURL, err))
		} else if ep, err := chain.Resolve(ctx, ""); err == nil {
			log.Printf("PDP discovery (%s): %s evaluates at %s", mode, ep.Identifier, ep.Evaluation)
		}
	}
	return chain, fed, nil
}

// buildFederation loads the Trust Anchors and builds the chain resolver.
func buildFederation(getenv func(string) string, httpc *http.Client, allowHTTP bool, resourceAllowed func(string) bool, ttl time.Duration, insecure func(string, ...any)) (*federation.Resolver, error) {
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
	fopts := federation.Options{TrustAnchors: anchors, HTTPClient: httpc, AllowInsecure: allowHTTP, SubjectAllowed: resourceAllowed}
	// PDP_METADATA_TTL bounds a resolved chain as it bounds any other metadata, and a
	// short one also shortens how long a failed chain is remembered — so an entity
	// onboarded a moment ago is seen a moment later.
	if ttl > 0 {
		fopts.TTL = ttl
		if ttl < 60*time.Second {
			fopts.NegativeTTL = ttl
		}
	}
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
		insecure("FEDERATION_FETCH_ALLOWLIST is unset: walking a trust chain may fetch from any https host an authority_hints names")
	}
	return federation.New(fopts)
}

// buildEntity loads the PEP's federation identity: the resource identifier it fronts,
// the key it signs with, and who vouches for it. Nothing about the resource's policy is
// configured here — that is the trust controller's to maintain, and the entity
// republishes what the controller resolved.
func buildEntity(getenv func(string) string, id, authzenURL string, fed *federation.Resolver) (*federation.Entity, error) {
	u, err := url.Parse(id)
	if err != nil || !u.IsAbs() || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("FEDERATION_ENTITY_ID %q is not an absolute URL without query or fragment", id)
	}
	var hints []string
	for _, h := range strings.Split(getenv("FEDERATION_AUTHORITY_HINTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hints = append(hints, strings.TrimRight(h, "/"))
		}
	}
	if len(hints) == 0 {
		return nil, fmt.Errorf("FEDERATION_ENTITY_ID needs FEDERATION_AUTHORITY_HINTS: who vouches for %s", id)
	}
	path := getenv("FEDERATION_ENTITY_KEY_FILE")
	if path == "" {
		return nil, fmt.Errorf("FEDERATION_ENTITY_ID needs FEDERATION_ENTITY_KEY_FILE")
	}
	key, err := loadOrGenerateKey(path, strings.EqualFold(getenv("FEDERATION_ENTITY_KEY_GENERATE"), "true"))
	if err != nil {
		return nil, err
	}
	return &federation.Entity{
		ID: id, Key: key, AuthorityHints: hints, Resolver: fed, Logf: log.Printf,
		// Before the controller has spoken, the document says only what this PEP is
		// configured with.
		Asserted: map[string]any{discovery.ParamPolicyDecisionPoints: []any{authzenURL}},
	}, nil
}

// loadOrGenerateKey reads a private JWK, or mints a P-256 one into the file when asked.
func loadOrGenerateKey(path string, generate bool) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && generate {
		key, err := jose.GenerateKey()
		if err != nil {
			return nil, err
		}
		jwk, err := jose.PrivateJWK(key)
		if err != nil {
			return nil, err
		}
		out, _ := json.MarshalIndent(jwk, "", "  ")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return nil, fmt.Errorf("writing FEDERATION_ENTITY_KEY_FILE: %w", err)
		}
		slog.Warn(fmt.Sprintf("minted a new federation entity key into %s (kid %s) — the trust controller "+
			"must onboard this key before the chain resolves.", path, jwk["kid"]))
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading FEDERATION_ENTITY_KEY_FILE: %w", err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("FEDERATION_ENTITY_KEY_FILE is not a JWK: %w", err)
	}
	key, err := jose.PrivateKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("FEDERATION_ENTITY_KEY_FILE: %w", err)
	}
	return key, nil
}

// main is the listen shell: it binds real sockets and waits for a signal, so it is the
// one function excluded from the coverage bar. Everything it decides is in buildServer,
// grpcServerOptions and run, which are tested. Keep this function trivial.
func main() {
	setupLogging(os.Getenv("LOG_FORMAT"))
	fatal := func(msg string, err error) {
		slog.Error(msg, "error", err)
		os.Exit(1)
	}
	log.Printf("coaz-pep %s", version)
	srv, httpSrv, grpcPort, err := buildServer(os.Getenv)
	if err != nil {
		fatal("configuration refused", err)
	}
	opts, err := grpcServerOptions(os.Getenv)
	if err != nil {
		fatal("gRPC configuration refused", err)
	}
	lis, err := net.Listen("tcp", ":"+grpcPort) // dual-stack
	if err != nil {
		fatal("listen", err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	if err := run(srv, httpSrv, lis, opts, stop); err != nil {
		fatal("serve", err)
	}
}

// run serves ext_authz on lis and the HTTP API on httpSrv until one of them fails or
// stop fires. On stop it drains rather than drops: readiness goes false so the gateway
// stops sending new checks, in-flight ones finish, and only then do the listeners close.
// A check cut off mid-flight is a deny the client never earned.
func run(srv *server, httpSrv *http.Server, lis net.Listener, opts []grpc.ServerOption, stop <-chan os.Signal) error {
	gs := grpc.NewServer(opts...)
	authv3.RegisterAuthorizationServer(gs, srv)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)

	errc := make(chan error, 2)
	go func() {
		log.Printf("coaz-pep HTTP check API listening on %s", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	go func() {
		log.Printf("coaz-pep ext_authz (Envoy gRPC) listening on %s, PDP at %s", lis.Addr(), srv.authzenURL)
		if err := gs.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		gs.Stop()
		_ = httpSrv.Close()
		return err
	case sig := <-stop:
		log.Printf("coaz-pep: %v received, draining for up to %s", sig, drainTimeout)
	}
	srv.draining.Store(true)
	hs.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	done := make(chan struct{})
	go func() { gs.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		gs.Stop()
	}
	return nil
}

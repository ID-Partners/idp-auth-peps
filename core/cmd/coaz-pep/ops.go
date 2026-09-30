package main

// Operating the PEP: the gRPC server's hardening, readiness, logging, the per-decision
// audit record and Prometheus metrics. Nothing here decides anything.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/ID-Partners/idp-auth-peps/core/internal/ttlcache"
)

// drainTimeout bounds a graceful shutdown. Kubernetes' default grace period is 30s.
const drainTimeout = 25 * time.Second

// grpcServerOptions hardens the ext_authz server: a panic becomes an error the gateway
// fails closed on instead of killing the process; messages are bounded; connections are
// recycled so a new replica gets its share of an Envoy's long-lived streams; and, when a
// certificate is configured, the port speaks TLS — mutual TLS when a client CA is given.
// Without TLS the port must be reachable only by the gateway (a mesh sidecar's mTLS, or
// a NetworkPolicy): its per-route configuration arrives in the request.
func grpcServerOptions(getenv func(string) string) ([]grpc.ServerOption, error) {
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(recoverUnary),
		grpc.MaxRecvMsgSize(4 << 20),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge:      5 * time.Minute,
			MaxConnectionAgeGrace: 30 * time.Second,
			Time:                  2 * time.Minute,
			Timeout:               20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: true}),
	}
	cert, key, ca := getenv("GRPC_TLS_CERT_FILE"), getenv("GRPC_TLS_KEY_FILE"), getenv("GRPC_TLS_CLIENT_CA_FILE")
	if cert == "" && key == "" {
		if ca != "" {
			return nil, fmt.Errorf("GRPC_TLS_CLIENT_CA_FILE needs GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE")
		}
		return opts, nil
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("GRPC_TLS_CERT_FILE / GRPC_TLS_KEY_FILE: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("GRPC_TLS_CLIENT_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("GRPC_TLS_CLIENT_CA_FILE holds no PEM certificate")
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return append(opts, grpc.Creds(credentials.NewTLS(cfg))), nil
}

// recoverUnary turns a panic in a handler into an Internal error. Envoy treats a failed
// check as a deny (failure_mode_allow: false), which is the fail-closed answer; an
// unrecovered panic would take every other in-flight check down with the process.
func recoverUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in %s: %v\n%s", info.FullMethod, r, debug.Stack())
			resp, err = nil, status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(ctx, req)
}

// errDraining is readiness while the server drains.
var errDraining = errors.New("draining")

// readiness is what /readyz and the gRPC health service both report: nil once the server
// can decide, meaning it is not draining and the access token's JWKS is loaded when
// there is one to verify tokens against.
func (s *server) readiness(ctx context.Context) error {
	if s.draining.Load() {
		return errDraining
	}
	if s.accessValidator != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := s.accessValidator.jwks.ready(ctx); err != nil {
			return fmt.Errorf("access token JWKS not loaded: %w", err)
		}
	}
	return nil
}

// handleReady is the readiness probe: false while draining, and false until the access
// token JWKS has loaded when tokens are verified. /healthz stays liveness only.
func (s *server) handleReady(w http.ResponseWriter, r *http.Request) {
	switch err := s.readiness(r.Context()); {
	case errors.Is(err, errDraining):
		http.Error(w, "draining", http.StatusServiceUnavailable)
	case err != nil:
		http.Error(w, "access token JWKS not loaded", http.StatusServiceUnavailable)
	default:
		_, _ = w.Write([]byte("ready"))
	}
}

// authService is the name the ext_authz service is registered under. The gRPC health
// service answers for it and for the server as a whole ("").
const authService = "envoy.service.auth.v3.Authorization"

// readinessEvery is how often the gRPC health service re-checks readiness.
var readinessEvery = 5 * time.Second

// followReadiness keeps the gRPC health service saying what /readyz says until ctx ends:
// it checks at once, then every readinessEvery, and sets the status when it changes.
// Once a drain calls Shutdown the health server ignores it and stays NOT_SERVING.
func (s *server) followReadiness(ctx context.Context, hs *health.Server) {
	t := time.NewTicker(readinessEvery)
	defer t.Stop()
	last := healthpb.HealthCheckResponse_UNKNOWN
	for {
		st := healthpb.HealthCheckResponse_SERVING
		if s.readiness(ctx) != nil {
			st = healthpb.HealthCheckResponse_NOT_SERVING
		}
		if st != last {
			hs.SetServingStatus("", st)
			hs.SetServingStatus(authService, st)
			last = st
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// setupLogging makes every log line structured. Setting slog's default also routes the
// standard log package through it, so existing log.Printf lines become JSON records.
func setupLogging(format string) {
	var h slog.Handler = slog.NewJSONHandler(os.Stderr, nil)
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(h))
}

// audit records one decision: who, what, the outcome and why, never a token. surface is
// "grpc" (ext_authz) or "http" (the check API).
func (s *server) audit(surface string, conf pepConfig, method, path string, headers map[string]string, resp *authv3.CheckResponse, started time.Time) {
	outcome, status := "permit", 200
	var hdrs map[string]string
	reason := ""
	if denied := resp.GetDeniedResponse(); denied != nil {
		outcome, status = "deny", int(denied.GetStatus().GetCode())
		hdrs = flattenHeaders(denied.GetHeaders())
		reason = denialReason(denied.GetBody())
	} else {
		hdrs = flattenHeaders(resp.GetOkResponse().GetResponseHeadersToAdd())
	}
	if r := hdrs["X-PDP-Reason"]; r != "" {
		reason = r
	}
	failOpen := hdrs["X-PDP-Fail-Open"]
	s.metrics.decision(outcome, conf.style, failOpen)
	slog.Info("decision",
		"pep", conf.pepLabel, "surface", surface, "style", conf.style,
		"method", method, "path", path, "request_id", headers["x-request-id"],
		"outcome", outcome, "status", status,
		"action", hdrs["X-PDP-Action"], "reason", reason,
		"fail_open", failOpen, "insecure", s.insecure,
		"duration_ms", float64(time.Since(started).Microseconds())/1000)
}

// denialReason is the client-facing reason in a denial body: the gateway deny shape's
// "reason", or a JSON-RPC error's message.
func denialReason(body string) string {
	var d struct {
		Reason string `json:"reason"`
		Error  any    `json:"error"`
	}
	if json.Unmarshal([]byte(body), &d) != nil {
		return ""
	}
	if d.Reason != "" {
		return d.Reason
	}
	if e, ok := d.Error.(map[string]any); ok {
		m, _ := e["message"].(string)
		return m
	}
	return ""
}

// metrics is a minimal Prometheus exposition, kept dependency-free: counters and one
// latency histogram, all with small, bounded label sets. A layer is a PDP identifier the
// configuration or the allowlist bounds; a DPoP reason is one of a fixed few.
type metrics struct {
	mu        sync.Mutex
	decisions map[[3]string]uint64 // outcome, style, fail_open
	failOpen  map[string]uint64    // layer
	dpop      map[string]uint64    // reason
	pdpCalls  map[string]uint64    // result
	pdpBucket []uint64
	pdpSum    float64
	pdpCount  uint64
	// caches report their counts when scraped: name -> what lookups were answered with.
	caches []func() map[string]ttlcache.Stats
}

var pdpBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func newMetrics() *metrics {
	return &metrics{decisions: map[[3]string]uint64{}, failOpen: map[string]uint64{}, dpop: map[string]uint64{},
		pdpCalls: map[string]uint64{}, pdpBucket: make([]uint64, len(pdpBuckets))}
}

// decision counts one decision, and each layer it skipped: failedOpen is the
// X-PDP-Fail-Open value, the skipped layers' identifiers, comma-separated.
func (m *metrics) decision(outcome, style, failedOpen string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[[3]string{outcome, style, fmt.Sprint(failedOpen != "")}]++
	for _, layer := range strings.Split(failedOpen, ",") {
		if layer = strings.TrimSpace(layer); layer != "" {
			m.failOpen[layer]++
		}
	}
}

// dpopRejected counts one DPoP proof refused, by reason.
func (m *metrics) dpopRejected(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.dpop[reason]++
	m.mu.Unlock()
}

// cache registers a cache whose counts are read at each scrape.
func (m *metrics) cache(stats func() map[string]ttlcache.Stats) {
	m.mu.Lock()
	m.caches = append(m.caches, stats)
	m.mu.Unlock()
}

// pdpCall records one PDP evaluation: result is ok, unavailable or refused.
func (m *metrics) pdpCall(result string, d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pdpCalls[result]++
	sec := d.Seconds()
	for i, b := range pdpBuckets {
		if sec <= b {
			m.pdpBucket[i]++
		}
	}
	m.pdpSum += sec
	m.pdpCount++
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	b.WriteString("# HELP coazpep_decisions_total Authorization decisions, by outcome.\n# TYPE coazpep_decisions_total counter\n")
	keys := make([][3]string, 0, len(m.decisions))
	for k := range m.decisions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.Join(keys[i][:], ",") < strings.Join(keys[j][:], ",") })
	for _, k := range keys {
		fmt.Fprintf(&b, "coazpep_decisions_total{outcome=%q,style=%q,fail_open=%q} %d\n", k[0], k[1], k[2], m.decisions[k])
	}
	b.WriteString("# HELP coazpep_pdp_calls_total PDP evaluations by the service, by result.\n# TYPE coazpep_pdp_calls_total counter\n")
	results := make([]string, 0, len(m.pdpCalls))
	for r := range m.pdpCalls {
		results = append(results, r)
	}
	sort.Strings(results)
	for _, r := range results {
		fmt.Fprintf(&b, "coazpep_pdp_calls_total{result=%q} %d\n", r, m.pdpCalls[r])
	}
	b.WriteString("# HELP coazpep_pdp_call_seconds PDP evaluation latency.\n# TYPE coazpep_pdp_call_seconds histogram\n")
	for i, le := range pdpBuckets {
		fmt.Fprintf(&b, "coazpep_pdp_call_seconds_bucket{le=%q} %d\n", fmt.Sprint(le), m.pdpBucket[i])
	}
	fmt.Fprintf(&b, "coazpep_pdp_call_seconds_bucket{le=\"+Inf\"} %d\ncoazpep_pdp_call_seconds_sum %g\ncoazpep_pdp_call_seconds_count %d\n",
		m.pdpCount, m.pdpSum, m.pdpCount)
	b.WriteString("# HELP coazpep_fail_open_total Layers skipped because their PDP could not be reached and the layer is fail-open, by layer.\n# TYPE coazpep_fail_open_total counter\n")
	for _, l := range sortedKeys(m.failOpen) {
		fmt.Fprintf(&b, "coazpep_fail_open_total{layer=%q} %d\n", l, m.failOpen[l])
	}
	b.WriteString("# HELP coazpep_dpop_rejections_total DPoP proofs refused, by reason.\n# TYPE coazpep_dpop_rejections_total counter\n")
	for _, r := range sortedKeys(m.dpop) {
		fmt.Fprintf(&b, "coazpep_dpop_rejections_total{reason=%q} %d\n", r, m.dpop[r])
	}
	b.WriteString("# HELP coazpep_cache_lookups_total What each cache answered a lookup with: a fresh value (hit), a fetch waited on (miss), a value past its TTL served while refreshing (stale), or an error.\n# TYPE coazpep_cache_lookups_total counter\n")
	all := map[string]ttlcache.Stats{}
	for _, f := range m.caches {
		for name, st := range f() {
			all[name] = st
		}
	}
	for _, name := range sortedKeys(all) {
		st := all[name]
		for _, r := range []struct {
			result string
			n      uint64
		}{{"hit", st.Hits}, {"miss", st.Misses}, {"stale", st.Stale}, {"error", st.Errors}} {
			fmt.Fprintf(&b, "coazpep_cache_lookups_total{cache=%q,result=%q} %d\n", name, r.result, r.n)
		}
	}
	_, _ = w.Write([]byte(b.String()))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

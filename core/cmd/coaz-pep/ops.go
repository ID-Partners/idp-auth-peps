package main

// Operating the PEP: the gRPC server's hardening, readiness, logging, the per-decision
// audit record and Prometheus metrics. Nothing here decides anything.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
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

// handleReady is the readiness probe: false while draining, and false until the access
// token JWKS — when one is configured — has been loaded once. A replica that cannot
// verify a single token should not be taking traffic; one whose PDP is down still is,
// because it answers with a fail-closed deny rather than nothing.
func (s *server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	if s.accessValidator != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.accessValidator.jwks.ready(ctx); err != nil {
			http.Error(w, "access token JWKS not loaded", http.StatusServiceUnavailable)
			return
		}
	}
	_, _ = w.Write([]byte("ready"))
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
	s.metrics.decision(outcome, conf.style, failOpen != "")
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
// latency histogram, all with small, bounded label sets.
type metrics struct {
	mu        sync.Mutex
	decisions map[[3]string]uint64 // outcome, style, fail_open
	pdpCalls  map[string]uint64    // result
	pdpBucket []uint64
	pdpSum    float64
	pdpCount  uint64
}

var pdpBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func newMetrics() *metrics {
	return &metrics{decisions: map[[3]string]uint64{}, pdpCalls: map[string]uint64{}, pdpBucket: make([]uint64, len(pdpBuckets))}
}

func (m *metrics) decision(outcome, style string, failedOpen bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.decisions[[3]string{outcome, style, fmt.Sprint(failedOpen)}]++
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
	_, _ = w.Write([]byte(b.String()))
}

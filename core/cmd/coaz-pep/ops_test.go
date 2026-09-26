package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCServerOptions(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if opts, err := grpcServerOptions(env(nil)); err != nil || len(opts) == 0 {
		t.Fatalf("plaintext options: %v", err)
	}
	cert, key := selfSigned(t)
	if opts, err := grpcServerOptions(env(map[string]string{"GRPC_TLS_CERT_FILE": cert, "GRPC_TLS_KEY_FILE": key, "GRPC_TLS_CLIENT_CA_FILE": cert})); err != nil || len(opts) < 2 {
		t.Fatalf("mTLS options: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"CA without a certificate": {"GRPC_TLS_CLIENT_CA_FILE": cert},
		"missing key":              {"GRPC_TLS_CERT_FILE": cert, "GRPC_TLS_KEY_FILE": filepath.Join(t.TempDir(), "none")},
		"missing CA":               {"GRPC_TLS_CERT_FILE": cert, "GRPC_TLS_KEY_FILE": key, "GRPC_TLS_CLIENT_CA_FILE": filepath.Join(t.TempDir(), "none")},
		"CA that is not PEM":       {"GRPC_TLS_CERT_FILE": cert, "GRPC_TLS_KEY_FILE": key, "GRPC_TLS_CLIENT_CA_FILE": writeFile(t, "not pem")},
	} {
		if _, err := grpcServerOptions(env(m)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func selfSigned(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "coaz-pep"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return certFile, keyFile
}

// A panicking handler must become an error the gateway fails closed on, not a crash.
func TestRecoverUnaryTurnsAPanicIntoAnError(t *testing.T) {
	_, err := recoverUnary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x"},
		func(context.Context, any) (any, error) { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("got %v", err)
	}
	resp, err := recoverUnary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x"},
		func(context.Context, any) (any, error) { return "ok", nil })
	if err != nil || resp != "ok" {
		t.Fatalf("a normal call passes through: %v %v", resp, err)
	}
}

func TestReadiness(t *testing.T) {
	key := newKey(t)
	jwks := jwksServer(t, key, "k1")
	defer jwks.Close()
	get := func(s *server) int {
		rec := httptest.NewRecorder()
		s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}
	if code := get(&server{}); code != http.StatusOK {
		t.Fatalf("no validator configured: ready, got %d", code)
	}
	s := &server{accessValidator: newTestValidator(t, jwks.URL)}
	if code := get(s); code != http.StatusOK {
		t.Fatalf("JWKS loads: ready, got %d", code)
	}
	s.draining.Store(true)
	if code := get(s); code != http.StatusServiceUnavailable {
		t.Fatalf("draining is not ready, got %d", code)
	}
	dead := &server{accessValidator: NewValidator(ValidatorConfig{JWKSURL: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}})}
	if code := get(dead); code != http.StatusServiceUnavailable {
		t.Fatalf("a JWKS that cannot load is not ready, got %d", code)
	}
}

func TestMetricsExposition(t *testing.T) {
	m := newMetrics()
	m.decision("permit", "rest", false)
	m.decision("deny", "mcp", false)
	m.decision("permit", "mcp", true)
	m.pdpCall("ok", 30*time.Millisecond)
	m.pdpCall("unavailable", 2*time.Second)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`coazpep_decisions_total{outcome="permit",style="mcp",fail_open="true"} 1`,
		`coazpep_pdp_calls_total{result="unavailable"} 1`,
		`coazpep_pdp_call_seconds_bucket{le="0.05"} 1`,
		`coazpep_pdp_call_seconds_count 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in\n%s", want, body)
		}
	}
	var nilMetrics *metrics
	nilMetrics.decision("permit", "rest", false) // a server built in a test has none
	nilMetrics.pdpCall("ok", time.Millisecond)
}

func TestAuditAndLoggingSetup(t *testing.T) {
	setupLogging("text")
	setupLogging("json")
	s := &server{metrics: newMetrics()}
	resp := permitWith("pep", "a", "ok", identity{sub: "alice"}, []string{"https://pdp (down)"})
	s.audit("grpc", configFrom(nil), "GET", "/x", map[string]string{"x-request-id": "r1"}, resp, time.Now())
	s.audit("http", configFrom(nil), "GET", "/x", nil, denySimple("pep", 403, codes.PermissionDenied, "no", nil), time.Now())
	if s.metrics.decisions[[3]string{"permit", "rest", "true"}] != 1 || s.metrics.decisions[[3]string{"deny", "rest", "false"}] != 1 {
		t.Fatalf("audit counts decisions: %v", s.metrics.decisions)
	}
}

// RFC 9449 §7.2: a DPoP-bound token presented as a bearer token is rejected on every
// route, not only those that set require_dpop.
func TestABoundTokenIsNotABearerToken(t *testing.T) {
	pdp := newPDPStub(t, map[string]any{"decision": true}, 200)
	s := newServer(t, pdp.URL)
	tok := mintUnsigned(map[string]any{"sub": "alice", "cnf": map[string]any{"jkt": "someone-elses-key"}})
	resp := s.check(context.Background(), restConf(nil), "GET", "/accounts/a1/balance",
		map[string]string{"authorization": "Bearer " + tok}, "")
	if resp.GetOkResponse() != nil || len(pdp.requests) != 0 {
		t.Fatal("a stolen bound token must not work as a bearer token")
	}
}

// The binding is compared before the signature is verified: a proof whose key the token
// was never bound to costs no signature check, however big its key.
func TestDpopComparesTheBindingBeforeTheSignature(t *testing.T) {
	bound, other := newKey(t), newKey(t)
	proof := mintProof(t, other, freshProofClaims("order-1"))
	resp := checkDpop("t", "dpop", "POST", "/payments", "", testToken, map[string]string{"dpop": proof}, boundClaims(bound))
	if resp == nil || !strings.Contains(resp.GetDeniedResponse().GetBody(), "cnf.jkt") {
		t.Fatalf("expected the binding mismatch, got %v", resp.GetDeniedResponse().GetBody())
	}
}

// run drains on a signal: readiness drops, then both listeners close.
func TestRunDrainsOnSignal(t *testing.T) {
	srv, httpSrv, _, err := buildServer(insecureEnv(map[string]string{"AUTHZEN_URL": "http://pdp:8080", "HTTP_ADDR": "127.0.0.1", "HTTP_PORT": "0"}))
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- run(srv, httpSrv, lis, nil, stop) }()
	time.Sleep(50 * time.Millisecond)
	stop <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not drain")
	}
	if !srv.draining.Load() {
		t.Fatal("readiness must drop before the listeners close")
	}
}

// A listener that fails is an error run returns, not a hang.
func TestRunReturnsAListenerFailure(t *testing.T) {
	srv, httpSrv, _, err := buildServer(insecureEnv(map[string]string{"AUTHZEN_URL": "http://pdp:8080", "HTTP_ADDR": "256.0.0.1", "HTTP_PORT": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := run(srv, httpSrv, lis, nil, make(chan os.Signal)); err == nil {
		t.Fatal("an HTTP listener that cannot bind must fail run")
	}
}

// The PDP is asked, never followed.
func TestThePDPClientDoesNotFollowRedirects(t *testing.T) {
	elsewhere := newPDPStub(t, map[string]any{"decision": true}, 200)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	srv, _, _, err := buildServer(insecureEnv(map[string]string{"AUTHZEN_URL": redirecting.URL}))
	if err != nil {
		t.Fatal(err)
	}
	resp := srv.check(context.Background(), restConf(nil), "GET", "/accounts/a1/balance",
		map[string]string{"authorization": "Bearer " + mintUnsigned(map[string]any{"sub": "alice"})}, "")
	if resp.GetOkResponse() != nil || len(elsewhere.requests) != 0 {
		t.Fatal("a redirect from the PDP is a refusal, and the other origin is never asked")
	}
}

func TestSmallHelpers(t *testing.T) {
	if clientIDOf(map[string]any{"azp": "a"}) != "a" || clientIDOf(map[string]any{"client_id": "c", "azp": "a"}) != "c" {
		t.Fatal("clientIDOf prefers client_id, then azp")
	}
	for u, want := range map[string]string{"https://a.example": "a.example:443", "http://a.example": "a.example:80", "https://a.example:8443": "a.example:8443"} {
		parsed, _ := url.Parse(u)
		if hostPort(parsed) != want {
			t.Errorf("hostPort(%s) = %s", u, hostPort(parsed))
		}
	}
	if !htuMatches("https://api.example.com:443/", "https://api.example.com", "/") {
		t.Error("the default port and the root path match")
	}
	if htuMatches("https://api.example.com/x", "::bad", "/x") {
		t.Error("an unparseable base matches nothing")
	}
}

func TestDenialReason(t *testing.T) {
	for body, want := range map[string]string{
		`{"error":"authorization_failed","reason":"Authorization service unavailable"}`:       "Authorization service unavailable",
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request: batch"}}`: "Invalid Request: batch",
		`not json`: "",
		`{}`:       "",
	} {
		if got := denialReason(body); got != want {
			t.Errorf("denialReason(%s) = %q, want %q", body, got, want)
		}
	}
}

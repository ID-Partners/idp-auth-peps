package main

// The PEP core: an Envoy External Authorization (ext_authz) implementation
// that enforces delegated-identity policy at an API gateway by consulting an
// AuthZEN PDP, with support for the OpenID AuthZEN MCP profile (COAZ).
//
// For every proxied request it:
//
//   1. extracts the delegated access token (DPoP or Bearer) and reads its
//      claims (sub = principal, act.sub = acting agent, scope, cnf.jkt), and the
//      logged-in user's X-User-Token, which counts only when it verifies and belongs
//      to the same principal;
//   2. if DPoP is required, checks the sender-constraint binding (RFC 9449);
//   3. authorizes the request:
//        - MCP routes: every JSON-RPC message is parsed strictly and decided by the
//          COAZ engine — a tool's declared x-authzen-mapping, otherwise the binding's
//          default mapping for its method; ping, notifications and a client's
//          responses pass; a body the PEP cannot read unambiguously is refused;
//        - REST routes: the request maps to a business action/resource and is
//          evaluated at the PDP;
//   4. PERMIT -> forward with X-Auth-* identity headers and X-PDP-* decision
//      headers; DENY -> the exact challenge or JSON-RPC error passes through.
//
// Token signatures are verified when a JWKS is configured, which main() requires unless
// PEP_ALLOW_INSECURE is set. The authorization decision itself is always the PDP's.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
	"github.com/ID-Partners/idp-auth-peps/core/coaz"
	"github.com/ID-Partners/idp-auth-peps/core/federation"
)

// pepConfig mirrors a gateway route's PEP knobs, populated from the extAuthz
// `context` map (Envoy context_extensions) or the Kong plugin config.
type pepConfig struct {
	pepLabel         string
	style            string // "mcp" | "rest"
	requireToken     bool
	requireDpop      bool
	requireUserLogin bool
	stepupScope      string
	stepupAction     string
	// mcpUpstreamURL enables COAZ on an MCP route: the MCP server whose
	// tools/list declares the x-coaz-mapping objects.
	mcpUpstreamURL string
	// coazDefaults applies the binding's default mappings: every MCP method is decided,
	// a tool that declares no mapping included. On unless the route says "false", which
	// keeps the pre-binding pass-through as an explicit opt-out.
	coazDefaults bool
	// coazV2Only refuses tools that declare only the superseded `coaz: true` mapping,
	// whose subject can come from the caller's params.
	coazV2Only bool
	// legacySubjectIdentity additionally sends the non-standard `subject.identity`
	// alongside the correct `subject.id`. On by default so upgrading the PEP alone
	// cannot break a policy that still reads the old field; turn it off once the
	// policies read `subject.id`, and the field goes away in a later release.
	legacySubjectIdentity bool
	// resource is the protected resource's identifier (RFC 8707), the key PDP
	// discovery works from. Absent, an MCP route is identified by its upstream URL and a
	// REST route uses the static PDP.
	resource string
	// forwardAccessToken sends the raw token to the PDP as context.access_token, so
	// the PDP can verify and inspect it rather than trust what this PEP decoded. Off
	// by default: a bearer token should only travel over a PDP connection that is TLS
	// and authenticated, and that is the operator's call.
	forwardAccessToken bool
	// layers is the ordered list of PDPs to ask (see discovery.ResolveLayers). Empty
	// means the service default, which is the resource's PDP alone.
	layers []discovery.LayerSpec
	// confErr is route configuration that could not be read — an unknown style, a knob
	// that is neither true nor false, a bad layer list. Such a route fails closed rather
	// than run a narrower policy than it was given.
	confErr error
	// failOpen is the route's failure mode, when it sets one: nil inherits the
	// service's PDP_FAIL_MODE.
	failOpen *bool
}

// resourceID is the identifier handed to PDP discovery for this route.
func (c pepConfig) resourceID() string {
	if c.resource != "" {
		return c.resource
	}
	if c.style == "mcp" {
		return c.mcpUpstreamURL // the MCP server's URL is its own identifier
	}
	return ""
}

func configFrom(ext map[string]string) pepConfig {
	var errs []string
	get := func(k, def string) string {
		if v, ok := ext[k]; ok && v != "" {
			return v
		}
		return def
	}
	// A knob that is neither true nor false is an error, not false: "yes" or "1" on
	// require_token must not quietly mean the token is optional.
	flag := func(k string, def bool) bool {
		switch strings.ToLower(ext[k]) {
		case "":
			return def
		case "true":
			return true
		case "false":
			return false
		}
		errs = append(errs, fmt.Sprintf("%s %q is neither true nor false", k, ext[k]))
		return def
	}
	c := pepConfig{
		pepLabel:         get("pep_label", "coaz-pep"),
		style:            strings.ToLower(get("style", "rest")),
		requireToken:     flag("require_token", false),
		requireDpop:      flag("require_dpop", false),
		requireUserLogin: flag("require_user_login", false),
		stepupScope:      ext["stepup_scope"],
		stepupAction:     get("stepup_action", "make_payment"),
		mcpUpstreamURL:   ext["mcp_upstream_url"],
		coazDefaults:     flag("coaz_defaults", true),
		coazV2Only:       flag("coaz_v2_only", false),
		// Defaults ON: absent config must not silently drop a field a deployed policy
		// may still be reading. Only an explicit "false" removes it.
		legacySubjectIdentity: flag("legacy_subject_identity", true),
		resource:              strings.TrimRight(ext["resource"], "/"),
		forwardAccessToken:    flag("forward_access_token", false),
	}
	if c.style != "rest" && c.style != "mcp" {
		// An unknown style would otherwise fall to the REST mapping and skip COAZ.
		errs = append(errs, fmt.Sprintf("style %q is neither rest nor mcp", ext["style"]))
	}
	var err error
	if c.layers, err = discovery.ParseLayers(ext["pdp_layers"]); err != nil {
		errs = append(errs, err.Error())
	}
	switch strings.ToLower(ext["fail_mode"]) {
	case "open":
		t := true
		c.failOpen = &t
	case "closed":
		f := false
		c.failOpen = &f
	case "":
	default:
		errs = append(errs, fmt.Sprintf("fail_mode %q is neither open nor closed", ext["fail_mode"]))
	}
	if len(errs) > 0 {
		c.confErr = errors.New(strings.Join(errs, "; "))
	}
	return c
}

type server struct {
	authzenURL    string
	authzenAPIKey string
	httpc         *http.Client
	coaz          *coaz.Engine
	// resolver finds the PDP for a route's resource. Nil means the static PDP.
	resolver discovery.Resolver
	// defaultLayers is the service-wide layer list (PDP_LAYERS), used by routes that
	// name none; failOpen is the service-wide failure mode (PDP_FAIL_MODE).
	defaultLayers []discovery.LayerSpec
	failOpen      bool
	// entity is this PEP's own federation identity, when it has one.
	entity *federation.Entity
	// upstreamAllowlist bounds which MCP servers a caller may point the PEP at.
	// Empty means unrestricted — main() warns when that is so.
	upstreamAllowlist []string
	// accessValidator verifies the Authorization access token; userValidator verifies
	// X-User-Token. Nil means "not configured": claims are decoded as before and
	// main() warns. Non-nil means fail closed.
	accessValidator *Validator
	userValidator   *Validator
	// decodeUserTokens lets an unverifiable X-User-Token count, decoded. Without it a
	// user token that cannot be verified counts for nothing.
	decodeUserTokens bool
	// dpopHTUBase is the external origin DPoP proofs are made for (DPOP_HTU_BASE).
	dpopHTUBase string
	// insecure records that the PEP started with PEP_ALLOW_INSECURE and a gap; every
	// audit record says so.
	insecure bool
	// draining is set on SIGTERM so readiness drops before the listeners close.
	draining atomic.Bool
	metrics  *metrics
}

// userClaims returns the claims of the X-User-Token, or nil when it does not count.
//
// These claims drive user_scope, user_acr, authorization_details and the consented
// amount cap — the step-up and consent gates. A forged token here is a bypass of both,
// and so is a genuine one belonging to someone else: customer B's consent must not
// authorise customer A's payment. So the token counts only when it verifies (or, with
// no verifier, when decoding was allowed) AND it is the principal's own login: its sub is
// the access token's sub, it is not the access token itself, and it is not a delegated
// token (no act claim) — an agent's own token is not a user having logged in.
func (s *server) userClaims(ctx context.Context, headers map[string]string, principal, accessToken string) map[string]any {
	raw := headers["x-user-token"]
	if raw == "" {
		return nil
	}
	var claims map[string]any
	switch {
	case s.userValidator != nil:
		c, err := s.userValidator.Validate(ctx, raw)
		if err != nil {
			log.Printf("X-User-Token rejected: %v", err)
			return nil
		}
		claims = c
	case s.decodeUserTokens:
		claims = jwtClaims(raw)
	default:
		return nil
	}
	switch {
	case raw == accessToken:
		log.Printf("X-User-Token ignored: it is the access token")
		return nil
	case claims["act"] != nil:
		log.Printf("X-User-Token ignored: it is a delegated token (act), not a user's login")
		return nil
	case principal == "" || claimString(claims, "sub") != principal:
		log.Printf("X-User-Token ignored: its subject is not the access token's")
		return nil
	}
	return claims
}

// ---------- CheckResponse builders ----------

func headerOpts(h map[string]string) []*corev3.HeaderValueOption {
	out := make([]*corev3.HeaderValueOption, 0, len(h))
	for k, v := range h {
		out = append(out, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: k, Value: sanitizeHeader(v)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return out
}

// sanitizeHeader keeps values the PDP or a client chose from breaking the header
// framing: every control character becomes a space.
func sanitizeHeader(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v)
}

func deniedRaw(httpStatus typev3.StatusCode, rpcCode codes.Code, body []byte, headers map[string]string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(rpcCode)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: httpStatus},
				Headers: headerOpts(headers),
				Body:    string(body),
			},
		},
	}
}

func deny(httpStatus typev3.StatusCode, rpcCode codes.Code, body map[string]any, headers map[string]string) *authv3.CheckResponse {
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	raw, _ := json.Marshal(body)
	return deniedRaw(httpStatus, rpcCode, raw, headers)
}

// denySimple matches the classic gateway deny JSON shape.
func denySimple(pep string, httpStatus typev3.StatusCode, rpcCode codes.Code, reason string, extraHeaders map[string]string) *authv3.CheckResponse {
	return deny(httpStatus, rpcCode, map[string]any{
		"error":  "authorization_failed",
		"pep":    pep,
		"reason": reason,
	}, extraHeaders)
}

// identity is who a permit vouches for, carried upstream as the X-Auth-* headers.
type identity struct {
	sub, act, scope, acr string
}

// permit lets the request through, tagging the upstream request with the
// delegation identity and the response with the PDP decision.
func permit(pep, action, reason string, id identity) *authv3.CheckResponse {
	return permitWith(pep, action, reason, id, nil)
}

// permitWith is permit with the fail-open marker: X-PDP-Fail-Open names the layers that
// were skipped, so a permit that rests on fewer opinions than the policy asked for is
// visible on the wire and countable downstream.
//
// The X-Auth-* headers are the PEP's word on who is calling, so a client's own copies
// never reach the upstream: a value is set with OVERWRITE (which discards every copy the
// client sent), and a header this PEP has no value for is removed rather than set empty
// — Envoy drops an empty-valued mutation, which would leave the client's copy in place.
func permitWith(pep, action, reason string, id identity, failedOpen []string) *authv3.CheckResponse {
	responseHeaders := map[string]string{
		"X-PDP-PEP":      pep,
		"X-PDP-Decision": "PERMIT",
		"X-PDP-Action":   action,
		"X-PDP-Reason":   reason,
	}
	if len(failedOpen) > 0 {
		responseHeaders["X-PDP-Fail-Open"] = strings.Join(coaz.LayerNames(failedOpen), ", ")
	}
	set := map[string]string{}
	var remove []string
	for _, h := range []struct{ name, value string }{
		{"X-Auth-Principal", id.sub}, {"X-Auth-Agent", id.act}, {"X-Auth-Scope", id.scope}, {"X-Auth-Acr", id.acr},
	} {
		if v := sanitizeHeader(h.value); v != "" {
			set[h.name] = v
		} else {
			remove = append(remove, h.name)
		}
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers:              headerOpts(set),
				HeadersToRemove:      remove,
				ResponseHeadersToAdd: headerOpts(responseHeaders),
			},
		},
	}
}

// ---------- the PEP ----------

func (s *server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()
	conf := configFrom(attrs.GetContextExtensions())

	headers := map[string]string{}
	for k, v := range httpReq.GetHeaders() {
		headers[strings.ToLower(k)] = v
	}
	path := httpReq.GetPath()
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	// With pack_as_bytes the body arrives in raw_body and body is empty; reading only one
	// of them would authorise an empty body while the upstream receives the real one.
	body := httpReq.GetBody()
	if raw := httpReq.GetRawBody(); len(raw) > 0 {
		body = string(raw)
	}
	started := time.Now()
	resp := s.check(ctx, conf, httpReq.GetMethod(), path, headers, body)
	s.audit("grpc", conf, httpReq.GetMethod(), path, headers, resp, started)
	return resp, nil
}

// check is the transport-independent pipeline, shared by the ext_authz gRPC
// server and the HTTP check API (used by the Kong plugin).
func (s *server) check(ctx context.Context, conf pepConfig, method, path string, headers map[string]string, body string) *authv3.CheckResponse {
	pep := conf.pepLabel
	if conf.confErr != nil {
		log.Printf("[%s] route policy unreadable: %v", pep, conf.confErr)
		return denySimple(pep, typev3.StatusCode_ServiceUnavailable, codes.Unavailable,
			"Authorization policy for this route could not be read; denying (fail-closed).", nil)
	}

	// 1) token + claims
	token, scheme := extractToken(headers["authorization"])
	if token == "" && conf.requireToken {
		log.Printf("[%s] 401 no access token %s %q", pep, method, path)
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
			"No access token presented to the gateway.", nil)
	}

	// The binding: "The access token ... MUST be validated by the PEP before its claims
	// are used." When a validator is configured this fails closed; when it is not, the
	// token is decoded, which main() allows only with PEP_ALLOW_INSECURE.
	var claims map[string]any
	if s.accessValidator != nil && token != "" {
		verified, err := s.accessValidator.Validate(ctx, token)
		if err != nil {
			log.Printf("[%s] access token rejected: %v", pep, err)
			return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
				"Access token failed validation.", map[string]string{
					"WWW-Authenticate": `Bearer error="invalid_token"`,
				})
		}
		claims = verified
	} else {
		claims = jwtClaims(token)
	}
	sub := claimString(claims, "sub")
	id := identity{sub: sub, act: actorSub(claims), scope: scopeString(claims), acr: strClaim(claims, "acr")}
	clientID := claimString(claims, "client_id")
	if clientID == "" {
		clientID = claimString(claims, "azp")
	}

	if conf.requireToken && sub == "" {
		log.Printf("[%s] 401 access token has no subject %s %q", pep, method, path)
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
			"Access token missing or unreadable (no subject claim).", nil)
	}

	// 2) Step-up: require a logged-in END USER (RFC 9470 step-up challenge) — the
	//    principal's own verified login, see userClaims.
	uclaims := s.userClaims(ctx, headers, sub, token)
	if conf.requireUserLogin && claimString(uclaims, "sub") == "" {
		log.Printf("[%s] 401 login_required %s %q", pep, method, path)
		return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
			"error":      "login_required",
			"pep":        pep,
			"reason":     "The gateway requires an authenticated user (no valid X-User-Token).",
			"acr_values": "urn:pingidentity:loa:password",
		}, map[string]string{
			"WWW-Authenticate": `Bearer error="insufficient_user_authentication", ` +
				`error_description="Login required", acr_values="urn:pingidentity:loa:password"`,
		})
	}

	// 3) DPoP sender-constraint binding (RFC 9449). A route that requires it checks every
	//    request; any route checks a token that is bound (cnf.jkt) or presented as DPoP —
	//    §7.2: a DPoP-bound token presented as a bearer token MUST be rejected, or a
	//    stolen bound token is as good as a bearer one wherever require_dpop is off.
	if conf.requireDpop || scheme == "dpop" || dpopBound(claims) {
		if resp := checkDpop(pep, scheme, method, path, s.dpopHTUBase, token, headers, claims); resp != nil {
			return resp
		}
	}

	// 4) MCP: every message is decided by the COAZ engine.
	if conf.style == "mcp" {
		return s.checkMCP(ctx, conf, method, path, headers, body, token, claims, uclaims, id)
	}

	// 5) REST: map the HTTP request to an AuthZEN action/resource/context.
	return s.decide(ctx, conf, mapRequest(conf.style, method, path, body), method, path, token, claims, uclaims, id, clientID)
}

// userContext is what the PEP asserts about the logged-in user and the token's audience,
// carried into every PDP request so the policy can check consent against the call.
//
//	user_scope            the coarse consented scope (RFC 9068); without it a step-up
//	                      rule's "user hasn't approved" test always trips, and loops.
//	authorization_details the fine-grained RAR (RFC 9396) the customer consented to,
//	                      with the consented payment cap and destination pre-extracted
//	                      so the policy can compare with plain comparisons.
//	token_aud             the agent token's audience (RFC 8707 / FAPI 2.0).
//	user_acr              how the user authenticated; the staff-approval channel is
//	                      recognised by its acr.
//
// Both PEPs must send the same, or a payment authorised at the MCP edge is re-challenged
// at the API edge and the flow loops on step-up.
func userContext(uclaims, claims map[string]any) map[string]any {
	ctx := map[string]any{
		"user_scope": scopeString(uclaims),
		"token_aud":  audString(claims),
		"user_acr":   strClaim(uclaims, "acr"),
	}
	if ad, ok := uclaims["authorization_details"]; ok && ad != nil {
		ctx["authorization_details"] = ad
		if amt, cred, found := consentedPayment(ad); found {
			ctx["consented_amount"] = amt
			ctx["consented_creditor"] = cred
		}
	}
	return ctx
}

// checkMCP decides one request on an MCP route.
//
// GET (the server's SSE stream) and DELETE (ending a session) carry no JSON-RPC message
// and pass on the token checks already made. A POST body must parse strictly as ONE
// JSON-RPC message — see coaz.ParseRequest — and then the engine decides it, whatever
// its method. Anything the PEP could read one way and the upstream another is refused:
// a batch, a body Envoy truncated, an encoded body, duplicate or case-variant members.
func (s *server) checkMCP(ctx context.Context, conf pepConfig, method, path string, headers map[string]string, body, token string, claims, uclaims map[string]any, id identity) *authv3.CheckResponse {
	pep := conf.pepLabel
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "DELETE":
		return permit(pep, "mcp:"+strings.ToLower(method), "MCP transport request; policy applies to JSON-RPC messages.", id)
	case "POST":
	default:
		return rpcRefusal(pep, typev3.StatusCode_MethodNotAllowed, "Invalid Request: method not supported on an MCP endpoint")
	}
	if strings.EqualFold(headers["x-envoy-auth-partial-body"], "true") {
		log.Printf("[%s] 413 partial body on an MCP route", pep)
		return rpcRefusal(pep, typev3.StatusCode_PayloadTooLarge, "Invalid Request: request body too large for the PEP to authorise")
	}
	if enc := strings.TrimSpace(headers["content-encoding"]); enc != "" && !strings.EqualFold(enc, "identity") {
		log.Printf("[%s] 415 Content-Encoding %q on an MCP route", pep, enc)
		return rpcRefusal(pep, typev3.StatusCode_UnsupportedMediaType, "Invalid Request: Content-Encoding not supported by the PEP")
	}
	rpc, err := coaz.ParseRequest([]byte(body))
	if err != nil {
		log.Printf("[%s] refused an MCP body: %v", pep, err)
		return coazDeny(pep, coaz.Refused(err), "mcp")
	}
	action := rpc.Method
	if rpc.ToolName != "" {
		action = "tools/call:" + rpc.ToolName
	} else if rpc.Kind == coaz.KindResponse {
		action = "jsonrpc-response"
	}

	// The upstream may be caller-supplied over the HTTP check API, so it is checked
	// before anything fetches it.
	if conf.mcpUpstreamURL != "" && !upstreamAllowed(s.upstreamAllowlist, conf.mcpUpstreamURL) {
		log.Printf("[%s] refusing mcp_upstream_url outside the allowlist: %q", pep, conf.mcpUpstreamURL)
		return denySimple(pep, typev3.StatusCode_Forbidden, codes.PermissionDenied,
			"Configured MCP upstream is not permitted by this PEP.", nil)
	}
	callOpts := coaz.CallOptions{ApplyDefaultMappings: conf.coazDefaults, RequireV2: conf.coazV2Only,
		Resource: conf.resourceID(), Method: method, Path: path, Layers: s.layersFor(conf), FailOpen: s.failOpenFor(conf)}
	if conf.forwardAccessToken {
		callOpts.AccessToken = token
	}
	v := s.coaz.CheckMCP(ctx, conf.mcpUpstreamURL, headers["authorization"], rpc,
		claimsForCEL(claims), userContext(uclaims, claims), callOpts)
	switch {
	case !v.Decision:
		log.Printf("[%s] COAZ DENY %q: %s", pep, action, v.Reason)
		return coazDeny(pep, v, action)
	case v.PassThrough && !conf.coazDefaults && rpc.Method == "initialize":
		// A route that opted out of the default mappings keeps the pre-binding coarse
		// check: the handshake is evaluated as access_mcp.
		return s.decide(ctx, conf, mapRequest("mcp", method, path, body), method, path, token, claims, uclaims, id, clientIDOf(claims))
	case v.PassThrough:
		return permit(pep, "mcp:"+action, v.ClientReason, id)
	}
	if len(v.FailedOpen) > 0 {
		log.Printf("[%s] COAZ PERMIT %q FAILED OPEN past %v", pep, action, v.FailedOpen)
	}
	log.Printf("[%s] COAZ PERMIT %q (principal=%q agent=%q)", pep, action, id.sub, id.act)
	return permitWith(pep, action, v.ClientReason, id, v.FailedOpen)
}

// coazDeny relays an engine deny: the JSON-RPC error, with the status the engine chose —
// 200 for a policy denial, as the binding requires, or 400 for a body it would not read.
func coazDeny(pep string, v coaz.Verdict, action string) *authv3.CheckResponse {
	status := typev3.StatusCode_OK
	if v.HTTPStatus != 0 {
		status = typev3.StatusCode(v.HTTPStatus)
	}
	return deniedRaw(status, codes.PermissionDenied, v.JSONRPCError, map[string]string{
		"Content-Type":   "application/json",
		"X-PDP-PEP":      pep,
		"X-PDP-Decision": "DENY",
		"X-PDP-Action":   action,
		"X-PDP-Reason":   v.ClientReason,
	})
}

// rpcRefusal is a JSON-RPC Invalid Request carried at an HTTP status other than 400.
func rpcRefusal(pep string, status typev3.StatusCode, message string) *authv3.CheckResponse {
	v := coaz.Refused(&coaz.ParseError{Code: coaz.CodeInvalidRequest, Message: message})
	v.HTTPStatus = int(status)
	return coazDeny(pep, v, "mcp")
}

func clientIDOf(claims map[string]any) string {
	if id := claimString(claims, "client_id"); id != "" {
		return id
	}
	return claimString(claims, "azp")
}

// decide evaluates one mapped request at the PDP layers and enforces the answer.
func (s *server) decide(ctx context.Context, conf pepConfig, m mapped, method, path, token string, claims, uclaims map[string]any, id identity, clientID string) *authv3.CheckResponse {
	pep := conf.pepLabel
	if m.refusal != "" {
		log.Printf("[%s] 400 %s %q: %s", pep, method, path, m.refusal)
		return denySimple(pep, typev3.StatusCode_BadRequest, codes.InvalidArgument, m.refusal, nil)
	}
	for k, v := range userContext(uclaims, claims) {
		m.ctx[k] = v
	}

	// 4) evaluate at the PDP and enforce (fail closed on PDP error)
	agent := id.act
	if agent == "" {
		agent = clientID
	}
	if agent == "" {
		agent = "unknown-agent"
	}
	// AuthZEN 1.0 names the subject identifier `id`. This PEP historically sent
	// `identity`, which no version of the spec defines, so policies written against it
	// are reading a field we invented. See subjectIdentifier for the migration.
	subject := map[string]any{
		"type": "agent",
		"id":   agent,
		"properties": map[string]any{
			"on_behalf_of": id.sub,
			"agent_type":   "ai_assistant",
			"scope":        id.scope,
			"client_id":    clientID,
		},
	}
	if conf.legacySubjectIdentity {
		subject["identity"] = agent
	}
	// Which PDP, and what it gets to reason with beyond the mapped request: the
	// resource's declared posture as published (scopes, acr, sender-constraint
	// requirements — whatever it said), tagged with whether the federation vouched for
	// it; the endpoint actually hit; and, when the route allows, the raw token. This PEP
	// enforces none of it. Comparing a token's scope or acr to what a resource requires
	// is a policy decision, and policy is offloaded to the PDP, where it can weigh them
	// alongside risk, consent and history — things a gateway never sees. Resolved once,
	// so one decision cannot straddle a PDP that moved.
	layers, err := discovery.ResolveLayers(ctx, s.resolverOrStatic(), conf.resourceID(), s.layersFor(conf), s.failOpenFor(conf))
	if err != nil {
		log.Printf("[%s] PDP call failed: PDP discovery: %v", pep, err)
		return denySimple(pep, typev3.StatusCode_ServiceUnavailable, codes.Unavailable,
			"Authorization service unavailable; denying (fail-closed).", nil)
	}
	for _, why := range layers.SkippedReasons {
		log.Printf("[%s] fail-open layer skipped: %s", pep, why)
	}
	eps := layers.PDPs
	if meta := discovery.ResourceMetadataOf(eps); meta != nil {
		m.ctx["resource_metadata"] = meta.Document
		m.ctx["resource_metadata_source"] = meta.Source
	}
	m.ctx["request"] = map[string]any{"method": method, "path": path}
	if conf.forwardAccessToken && token != "" {
		m.ctx["access_token"] = token
	}

	authzenReq := map[string]any{
		"subject":  subject,
		"action":   map[string]any{"name": m.action},
		"resource": map[string]any{"type": m.rtype, "id": m.rid, "properties": m.rprops},
		"context":  m.ctx,
	}

	out, err := s.evaluateLayers(ctx, eps, authzenReq, layers.Skipped)
	if err != nil {
		log.Printf("[%s] PDP call failed: %v", pep, err)
		return denySimple(pep, typev3.StatusCode_ServiceUnavailable, codes.Unavailable,
			"Authorization service unavailable; denying (fail-closed).", nil)
	}
	if len(out.FailedOpen) > 0 {
		log.Printf("[%s] %s %q FAILED OPEN past %v", pep, m.action, m.rid, out.FailedOpen)
	}
	decision, reason, stepUp, stepUpScope := out.Decision, out.Reason, out.StepUp, out.StepUpScope

	// mDL identity-proofing obligation (account origination): the customer has no
	// verified identity-proofing activity yet. Challenge for an mDL presentation —
	// the app pushes the customer's phone (CIBA) and the wallet presents app2app.
	if out.IdentityReq {
		doctype := out.IdentityDoctype
		if doctype == "" {
			doctype = "org.iso.18013.5.1.mDL"
		}
		log.Printf("[%s] 401 identity proofing required (%q) %s %q", pep, doctype, m.action, m.rid)
		return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
			"error":   "identity_verification_required",
			"doctype": doctype,
			"pep":     pep,
			"reason":  reason,
		}, map[string]string{
			"WWW-Authenticate": `Bearer error="identity_verification_required", doctype=` + quoteParam(doctype),
		})
	}

	// Step-up obligation from the policy: this payment is over the threshold and
	// the user hasn't approved it yet. Challenge for the step-up scope (RFC 9470)
	// so the app can step the customer up, rather than a flat 403.
	if stepUp {
		scope := stepUpScope
		if scope == "" {
			scope = conf.stepupScope
		}
		log.Printf("[%s] 401 step-up required (%q) %s %q", pep, scope, m.action, m.rid)
		return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
			"error":  "insufficient_scope",
			"scope":  scope,
			"pep":    pep,
			"reason": reason,
		}, map[string]string{
			"WWW-Authenticate": `Bearer error="insufficient_scope", scope=` + quoteParam(scope),
		})
	}

	if !decision {
		log.Printf("[%s] DENY %s %q: %q", pep, m.action, m.rid, reason)
		return denySimple(pep, typev3.StatusCode_Forbidden, codes.PermissionDenied, reason,
			map[string]string{
				"X-PDP-PEP":      pep,
				"X-PDP-Decision": "DENY",
				"X-PDP-Action":   m.action,
				"X-PDP-Reason":   reason,
			})
	}

	log.Printf("[%s] PERMIT %s %q (principal=%q agent=%q)", pep, m.action, m.rid, id.sub, agent)
	return permitWith(pep, m.action, reason, id, out.FailedOpen)
}

// quoteParam renders an auth-param value as an RFC 9110 quoted-string: backslash and
// double quote are escaped, and control characters dropped, so a value the PDP chose
// cannot close the parameter and append one of its own (resource_metadata, say, which
// an MCP client would follow).
func quoteParam(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// extractToken parses Authorization: "DPoP <t>" or "Bearer <t>".
func extractToken(auth string) (token, scheme string) {
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return strings.TrimSpace(parts[1]), strings.ToLower(parts[0])
}

// dpopReplay tracks jti values already accepted, for the proof-acceptance window.
var dpopReplay = newReplayCache(dpopMaxAge)

// dpopBound reports whether the token is sender-constrained: it carries cnf.jkt.
func dpopBound(claims map[string]any) bool {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return false
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt != ""
}

// checkDpop enforces the DPoP proof (RFC 9449); nil means pass.
//
// Order matters. The cnf.jkt comparison is cheap and comes first, so a proof carrying a
// key the token was never bound to costs no signature verification — a proof header can
// carry an RSA key big enough to make that expensive. The comparison only MEANS anything
// once the proof's signature verifies under that key: the JWK is public in every proof,
// so without the signature anyone who has observed one proof can mint more.
func checkDpop(pep, scheme, method, path, htuBase, accessToken string, headers map[string]string, claims map[string]any) *authv3.CheckResponse {
	fail := func(reason string) *authv3.CheckResponse {
		log.Printf("[%s] 401 DPoP: %s", pep, reason)
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated, reason, map[string]string{
			"WWW-Authenticate": `DPoP error="invalid_dpop_proof"`,
		})
	}
	if scheme != "dpop" {
		return fail("DPoP-bound token required but Authorization scheme was not DPoP.")
	}
	proof := headers["dpop"]
	if proof == "" {
		return fail("Missing DPoP proof header.")
	}
	phdr := jwtHeader(proof)
	pclaims := jwtClaims(proof)
	if phdr == nil || pclaims == nil {
		return fail("DPoP proof is not a well-formed JWT.")
	}
	if typ := claimString(phdr, "typ"); typ != "dpop+jwt" {
		return fail("DPoP proof typ header is not dpop+jwt.")
	}
	jwk, ok := phdr["jwk"].(map[string]any)
	if !ok {
		return fail("DPoP proof header carries no jwk.")
	}
	// A private-key member in the JWK means the client leaked its key; treat the proof
	// as unusable rather than quietly accepting it.
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, present := jwk[priv]; present {
			return fail("DPoP proof jwk contains private key material.")
		}
	}
	alg := claimString(phdr, "alg")
	if alg == "" || alg == "none" {
		return fail("DPoP proof has no usable alg.")
	}
	jkt := jwkThumbprint(jwk)
	var cnfJkt string
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		cnfJkt, _ = cnf["jkt"].(string)
	}
	if jkt == "" || cnfJkt == "" || !constantTimeEqual(jkt, cnfJkt) {
		return fail("DPoP proof key does not match the token's cnf.jkt binding.")
	}
	if err := verifyProofSignature(proof, jwk, alg); err != nil {
		return fail("DPoP proof signature is invalid.")
	}
	if claimString(pclaims, "htm") != method {
		return fail("DPoP proof htm does not match the request method.")
	}
	if !htuMatches(claimString(pclaims, "htu"), htuBase, path) {
		return fail("DPoP proof htu does not match the request URI.")
	}

	// ath binds this proof to THIS access token. Presence alone is worthless: without
	// the comparison a proof minted for any token replays against any other.
	ath := claimString(pclaims, "ath")
	if ath == "" {
		return fail("DPoP proof missing ath (access-token hash).")
	}
	if accessToken == "" || !constantTimeEqual(ath, accessTokenHash(accessToken)) {
		return fail("DPoP proof ath does not match the presented access token.")
	}

	// Freshness, then single-use. A proof with no iat, or one outside the window, is
	// replayable indefinitely.
	iatClaim, ok := numericClaim(pclaims, "iat")
	if !ok {
		return fail("DPoP proof missing iat.")
	}
	now := time.Now()
	iat := time.Unix(int64(iatClaim), 0)
	if age := now.Sub(iat); age > dpopMaxAge || age < -dpopMaxSkew {
		return fail("DPoP proof iat is outside the acceptance window.")
	}
	if !dpopReplay.observe(jkt, claimString(pclaims, "jti"), iat, now) {
		return fail("DPoP proof jti is missing or has already been used.")
	}
	return nil
}

// htuMatches compares a proof's htu with the request (RFC 9449 §4.3: ignoring query and
// fragment). Behind a gateway the PEP does not see the origin the client used, so with
// DPOP_HTU_BASE set the origin must be exactly that and the path the request's; without
// it only the path is compared — never a substring, which let a proof made for another
// server's /payments pass on this one.
func htuMatches(htu, base, path string) bool {
	u, err := url.Parse(htu)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if p != path {
		return false
	}
	if base == "" {
		return true
	}
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, b.Scheme) && strings.EqualFold(hostPort(u), hostPort(b))
}

// hostPort is host:port with the scheme's default port made explicit.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if strings.EqualFold(u.Scheme, "https") {
		return u.Hostname() + ":443"
	}
	return u.Hostname() + ":80"
}

// numericClaim reads a JSON number claim, which decodes as float64.
func numericClaim(claims map[string]any, key string) (float64, bool) {
	v, ok := claims[key].(float64)
	return v, ok
}

// consentedPayment pulls the amount cap + destination account from the first
// payment_initiation entry of an RFC 9396 authorization_details value (as decoded
// from a JWT claim). Returns (amount, creditorAccount, found).
func consentedPayment(ad any) (float64, string, bool) {
	arr, ok := ad.([]any)
	if !ok {
		return 0, "", false
	}
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t != "payment_initiation" {
			continue
		}
		amt, _ := m["amount"].(float64)
		cred, _ := m["creditorAccount"].(string)
		return amt, cred, true
	}
	return 0, "", false
}

// evaluate POSTs a single AuthZEN evaluation request to the PDP. It returns the
// decision, a human reason, and the step-up obligation (whether the policy asks
// for a step-up challenge, and the scope to challenge for).
// pepOutcome carries the PDP decision plus challenge advice: RFC 9470 scope step-up
// (payments) and/or the mDL identity-proofing requirement (account origination).
type pepOutcome struct {
	Decision        bool
	Reason          string
	StepUp          bool
	StepUpScope     string
	IdentityReq     bool
	IdentityDoctype string
	// FailedOpen names the layers skipped because they failed and were allowed to.
	FailedOpen []string
}

// resolverOrStatic: a server built without a resolver (tests, mostly) behaves as the
// static one.
func (s *server) resolverOrStatic() discovery.Resolver {
	if s.resolver != nil {
		return s.resolver
	}
	return discovery.Static(s.authzenURL, s.authzenAPIKey)
}

// layersFor is the route's layer list, else the service default.
func (s *server) layersFor(conf pepConfig) []discovery.LayerSpec {
	if len(conf.layers) > 0 {
		return conf.layers
	}
	return s.defaultLayers
}

// failOpenFor is the route's failure mode, else the service default.
func (s *server) failOpenFor(conf pepConfig) bool {
	if conf.failOpen != nil {
		return *conf.failOpen
	}
	return s.failOpen
}

// resolveFor finds the PDP for a route's resource.
func (s *server) resolveFor(ctx context.Context, resource string) (discovery.PDPEndpoints, error) {
	ep, err := s.resolverOrStatic().Resolve(ctx, resource)
	if err != nil {
		return ep, fmt.Errorf("PDP discovery: %w", err)
	}
	return ep, nil
}

// mergePermit folds a permitting layer's outcome into the running one.
//
// Only the DECISION is a single answer; the OBLIGATIONS are cumulative. Replacing the
// outcome wholesale let a later layer's plain permit erase an earlier layer's step-up or
// identity-proofing requirement, and the request was then permitted with no challenge
// issued at all — which defeats the point of putting a generic PDP in front of the
// resource's own. The first layer to require something owns its parameter, and its
// reason is what explains the challenge the client sees.
func mergePermit(acc, layer pepOutcome) pepOutcome {
	out := layer
	out.Decision = true
	if acc.IdentityReq {
		out.IdentityReq = true
		if acc.IdentityDoctype != "" {
			out.IdentityDoctype = acc.IdentityDoctype
		}
	}
	if acc.StepUp {
		out.StepUp = true
		if acc.StepUpScope != "" {
			out.StepUpScope = acc.StepUpScope
		}
	}
	if acc.IdentityReq || acc.StepUp {
		out.Reason = acc.Reason
	}
	return out
}

// evaluateLayers asks each PDP in order; every layer must permit, the first that does
// not is the answer. A PDP failure fails closed; only an UNAVAILABLE PDP
// (coaz.ErrPDPUnavailable) on a fail-open layer is skipped and named — a refusal never
// is. If every layer was skipped the request is permitted and marked. A deny is never
// skipped. See the engine's twin.
func (s *server) evaluateLayers(ctx context.Context, eps []discovery.PDPEndpoints, authzenReq map[string]any, skipped []string) (pepOutcome, error) {
	var out pepOutcome
	decided := false
	for _, ep := range eps {
		o, err := s.evaluateAt(ctx, ep, authzenReq)
		if err != nil {
			if !ep.FailOpen || !errors.Is(err, coaz.ErrPDPUnavailable) {
				return out, fmt.Errorf("%s: %w", ep.Identifier, err)
			}
			log.Printf("fail-open layer %s skipped: %v", ep.Identifier, err)
			skipped = append(skipped, ep.Identifier)
			continue
		}
		decided = true
		if !o.Decision {
			return o, nil
		}
		out = mergePermit(out, o)
	}
	out.FailedOpen = coaz.LayerNames(skipped)
	if !decided {
		out.Decision = true
		out.Reason = "fail-open: no policy layer could be reached (" + strings.Join(out.FailedOpen, ", ") + ")"
	}
	return out, nil
}

// evaluate resolves the PDP for resource and asks it. Kept for callers that have only
// a resource; the request path resolves first so the context can carry what was found.
func (s *server) evaluate(ctx context.Context, resource string, authzenReq map[string]any) (pepOutcome, error) {
	ep, err := s.resolveFor(ctx, resource)
	if err != nil {
		return pepOutcome{}, err
	}
	return s.evaluateAt(ctx, ep, authzenReq)
}

func (s *server) evaluateAt(ctx context.Context, ep discovery.PDPEndpoints, authzenReq map[string]any) (out pepOutcome, err error) {
	payload, err := json.Marshal(authzenReq)
	if err != nil {
		return out, fmt.Errorf("PDP request could not be encoded: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.Evaluation, bytes.NewReader(payload))
	if err != nil {
		return out, fmt.Errorf("PDP request could not be built: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ep.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+ep.APIKey)
	}
	started := time.Now()
	defer func() {
		switch {
		case err == nil:
			s.metrics.pdpCall("ok", time.Since(started))
		case errors.Is(err, coaz.ErrPDPUnavailable):
			s.metrics.pdpCall("unavailable", time.Since(started))
		default:
			s.metrics.pdpCall("refused", time.Since(started))
		}
	}()
	resp, err := s.httpc.Do(req)
	if err != nil {
		return out, fmt.Errorf("%w: %v", coaz.ErrPDPUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, fmt.Errorf("%w: reading the answer: %v", coaz.ErrPDPUnavailable, err)
	}
	// AuthZEN answers 200 with a decision, permit or deny. Anything else is not a decision:
	// a PDP that is down and says so in JSON must not be read as a deny, and a PDP that
	// refuses the request (a 4xx) must not be read as down.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, coaz.PDPStatusError(resp.StatusCode)
	}
	var data struct {
		Decision bool `json:"decision"`
		Context  struct {
			Reason           string `json:"reason"`
			StepUpRequired   bool   `json:"step_up_required"`
			StepUpScope      string `json:"step_up_scope"`
			IdentityRequired bool   `json:"identity_proofing_required"`
			IdentityDoctype  string `json:"identity_proofing_doctype"`
		} `json:"context"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return out, fmt.Errorf("bad PDP response (%d): %w", resp.StatusCode, err)
	}
	reason := data.Context.Reason
	if reason == "" {
		if data.Decision {
			reason = "Permitted by policy."
		} else {
			reason = "Denied by policy."
		}
	}
	return pepOutcome{Decision: data.Decision, Reason: reason,
		StepUp: data.Context.StepUpRequired, StepUpScope: data.Context.StepUpScope,
		IdentityReq: data.Context.IdentityRequired, IdentityDoctype: data.Context.IdentityDoctype}, nil
}

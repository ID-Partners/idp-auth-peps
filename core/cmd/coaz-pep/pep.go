package main

// The PEP core: an Envoy External Authorization (ext_authz) implementation
// that enforces delegated-identity policy at an API gateway by consulting an
// AuthZEN PDP, with support for the OpenID AuthZEN MCP profile (COAZ).
//
// For every proxied request it:
//
//   1. extracts the delegated access token (DPoP or Bearer) and reads its
//      claims (sub = principal, act.sub = acting agent, scope, cnf.jkt);
//   2. if DPoP is required, checks the sender-constraint binding (RFC 9449);
//   3. authorizes the request:
//        - MCP routes: `initialize` is evaluated as access_mcp; `tools/call`
//          on a COAZ-declared tool is evaluated per the tool's x-coaz-mapping
//          (discovery, CEL, evaluation/evaluations API, JSON-RPC errors);
//          other MCP traffic passes on a valid token;
//        - REST routes: the request maps to a business action/resource and is
//          evaluated at the PDP;
//   4. PERMIT -> forward with X-Auth-* identity headers and X-PDP-* decision
//      headers; DENY -> the exact challenge or JSON-RPC error passes through.
//
// NOTE (demo honesty): the PEP reads JWT claims and enforces the DPoP key
// binding but does not itself verify the access-token JWS signature — pair it
// with the gateway's JWT/JWKS validation in hardened deployments. The
// authorization decision itself is always made by the AuthZEN PDP.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/ID-Partners/idp-auth-peps/core/coaz"
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
	// coazDefaults applies the binding's default mappings to tools that declare none.
	// Off leaves the non-conformant pass-through that deployed routes expect.
	coazDefaults bool
}

func configFrom(ext map[string]string) pepConfig {
	get := func(k, def string) string {
		if v, ok := ext[k]; ok && v != "" {
			return v
		}
		return def
	}
	isTrue := func(k string) bool { return strings.EqualFold(ext[k], "true") }
	return pepConfig{
		pepLabel:         get("pep_label", "coaz-pep"),
		style:            get("style", "rest"),
		requireToken:     isTrue("require_token"),
		requireDpop:      isTrue("require_dpop"),
		requireUserLogin: isTrue("require_user_login"),
		stepupScope:      ext["stepup_scope"],
		stepupAction:     get("stepup_action", "make_payment"),
		mcpUpstreamURL:   ext["mcp_upstream_url"],
		coazDefaults:     isTrue("coaz_defaults"),
	}
}

type server struct {
	authzenURL    string
	authzenAPIKey string
	httpc         *http.Client
	coaz          *coaz.Engine
	// upstreamAllowlist bounds which MCP servers a caller may point the PEP at.
	// Empty means unrestricted — main() warns when that is so.
	upstreamAllowlist []string
	// accessValidator verifies the Authorization access token; userValidator verifies
	// X-User-Token. Nil means "not configured": claims are decoded as before and
	// main() warns. Non-nil means fail closed.
	accessValidator *Validator
	userValidator   *Validator
}

// userClaims returns the verified claims of the X-User-Token, or nil.
//
// These claims drive user_scope, user_acr, authorization_details and the consented
// amount cap — the step-up and consent gates. A forged token here is a bypass of both,
// so when a validator is configured a token that does not verify yields NO claims
// rather than decoded ones.
func (s *server) userClaims(ctx context.Context, headers map[string]string) map[string]any {
	raw := headers["x-user-token"]
	if raw == "" {
		return nil
	}
	if s.userValidator == nil {
		return jwtClaims(raw)
	}
	claims, err := s.userValidator.Validate(ctx, raw)
	if err != nil {
		log.Printf("X-User-Token rejected: %v", err)
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

// sanitizeHeader keeps policy reasons from breaking the header framing.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
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

// permit lets the request through, tagging the upstream request with the
// delegation identity and the response with the PDP decision.
func permit(pep, action, reason, sub, act, scope string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headerOpts(map[string]string{
					"X-Auth-Principal": sub,
					"X-Auth-Agent":     act,
					"X-Auth-Scope":     scope,
				}),
				ResponseHeadersToAdd: headerOpts(map[string]string{
					"X-PDP-PEP":      pep,
					"X-PDP-Decision": "PERMIT",
					"X-PDP-Action":   action,
					"X-PDP-Reason":   reason,
				}),
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
	return s.check(ctx, conf, httpReq.GetMethod(), path, headers, httpReq.GetBody()), nil
}

// check is the transport-independent pipeline, shared by the ext_authz gRPC
// server and the HTTP check API (used by the Kong plugin).
func (s *server) check(ctx context.Context, conf pepConfig, method, path string, headers map[string]string, body string) *authv3.CheckResponse {
	pep := conf.pepLabel

	// 0) Step-up: require a logged-in END USER (RFC 9470 step-up challenge).
	if conf.requireUserLogin {
		uclaims := s.userClaims(ctx, headers)
		if claimString(uclaims, "sub") == "" {
			log.Printf("[%s] 401 login_required %s %s", pep, method, path)
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
	}

	// 1) token + claims
	token, scheme := extractToken(headers["authorization"])
	if token == "" && conf.requireToken {
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
			"No access token presented to the gateway.", nil)
	}

	// The binding: "The access token ... MUST be validated by the PEP before its claims
	// are used." When a validator is configured this fails closed; when it is not, the
	// token is decoded as before and main() has warned at startup.
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
	act := actorSub(claims)
	scope := scopeString(claims)
	clientID := claimString(claims, "client_id")
	if clientID == "" {
		clientID = claimString(claims, "azp")
	}

	if conf.requireToken && sub == "" {
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
			"Access token missing or unreadable (no subject claim).", nil)
	}

	// 2) DPoP sender-constraint binding (RFC 9449)
	if conf.requireDpop {
		if resp := checkDpop(pep, scheme, method, path, token, headers, claims); resp != nil {
			return resp
		}
	}

	// 2b) COAZ (AuthZEN MCP profile): tools/call on an MCP route with a
	//     declared upstream is evaluated per the tool's x-coaz-mapping.
	if conf.style == "mcp" && conf.mcpUpstreamURL != "" && isToolsCall(body) {
		// The upstream may be caller-supplied over the HTTP check API, so it is
		// checked before anything fetches it.
		if !upstreamAllowed(s.upstreamAllowlist, conf.mcpUpstreamURL) {
			log.Printf("[%s] refusing mcp_upstream_url outside the allowlist: %s", pep, conf.mcpUpstreamURL)
			return denySimple(pep, typev3.StatusCode_Forbidden, codes.PermissionDenied,
				"Configured MCP upstream is not permitted by this PEP.", nil)
		}
		// Carry the logged-in USER's token claims (from X-User-Token) into the COAZ AuthZEN
		// context — the x-coaz-mapping is derived from the AGENT's token + tool params and
		// can't see them. The PDP checks these against the request:
		//   user_scope            — the coarse consented scope (RFC 9068); without it the
		//                           step-up rule's "user hasn't approved" test always trips → loop.
		//   authorization_details — the fine-grained RAR (RFC 9396) the customer consented to, carried
		//                           in their rich JWT (userJwtATM emits it). Lets the policy verify
		//                           THIS payment is within a consented RAR entry, not just the scope.
		uclaims := s.userClaims(ctx, headers)
		extraContext := map[string]any{
			"user_scope": scopeString(uclaims),
			// The agent token's audience (RFC 8707 / FAPI 2.0): the token is minted for THIS
			// resource only. Forwarded so the policy can see + enforce audience-restriction.
			"token_aud": audString(claims),
			// How the user token was authenticated (acr). The autonomous demo's staff channel
			// (the approver, the agent owner, approving out-of-band) is recognised by the policy via a
			// staff-approval acr — PF can't attach the RFC 9396 RAR to an ROPC/CIBA-minted
			// token, so acr + the elevated scope is that channel's step-up evidence.
			"user_acr": strClaim(uclaims, "acr"),
		}
		if ad, ok := uclaims["authorization_details"]; ok && ad != nil {
			extraContext["authorization_details"] = ad
			// Pre-extract the consented payment cap + destination from the RAR so the
			// policy can do a fine-grained match (amount <= consented, account matches)
			// with plain comparisons instead of parsing JSON itself.
			if amt, cred, found := consentedPayment(ad); found {
				extraContext["consented_amount"] = amt
				extraContext["consented_creditor"] = cred
			}
		}
		v := s.coaz.CheckToolCall(ctx, conf.mcpUpstreamURL, headers["authorization"],
			[]byte(body), claimsForCEL(claims), extraContext, coaz.CallOptions{ApplyDefaultMappings: conf.coazDefaults})
		if v.CoazTool {
			toolName := toolCallName(body)
			if v.JSONRPCError != nil {
				log.Printf("[%s] COAZ DENY tools/call %s: %s", pep, toolName, v.Reason)
				// Profile: protocol errors are JSON-RPC error responses
				// (HTTP 200, application/json), not HTTP-level denials.
				return deniedRaw(typev3.StatusCode_OK, codes.PermissionDenied, v.JSONRPCError,
					map[string]string{
						"Content-Type":   "application/json",
						"X-PDP-PEP":      pep,
						"X-PDP-Decision": "DENY",
						"X-PDP-Action":   "tools/call:" + toolName,
						"X-PDP-Reason":   sanitizeHeader(v.Reason),
					})
			}
			log.Printf("[%s] COAZ PERMIT tools/call %s (principal=%s agent=%s)", pep, toolName, sub, act)
			return permit(pep, "tools/call:"+toolName, v.Reason, sub, act, scope)
		}
		// non-COAZ tool: fall through to the legacy MCP-edge behaviour
	}

	// 3) map the HTTP request to an AuthZEN action/resource/context
	m := mapRequest(conf.style, method, path, body)

	// MCP handshake / non-tool traffic: allow on a valid token, skip the PDP.
	if m.action == allowAction {
		return permit(pep, "mcp-handshake",
			"MCP handshake allowed (authenticated); policy applies to tool calls.",
			sub, act, scope)
	}

	// 3b) Carry the USER's consented context (from X-User-Token) into the PDP:
	//     the coarse scope AND the fine-grained RFC 9396 RAR (authorization_details),
	//     pre-extracting the consented amount + destination. This MUST match what the
	//     COAZ/MCP path (PEP #1) sends, or a payment authorized at the MCP edge gets
	//     re-challenged here at the Bank-API edge (PEP #2) because the RAR context is
	//     missing → the payment fails downstream and the whole flow loops on step-up.
	uclaims := s.userClaims(ctx, headers)
	m.ctx["user_scope"] = scopeString(uclaims)
	// The agent token's audience (RFC 8707 / FAPI 2.0) — this token was minted for THIS
	// resource. Forwarded so the policy can see + enforce that a token is audience-restricted.
	m.ctx["token_aud"] = audString(claims)
	// Staff-approval channel marker (see PEP #1) — must match what PEP #1 sends or a payment
	// authorized at the MCP edge gets re-challenged here.
	m.ctx["user_acr"] = strClaim(uclaims, "acr")
	if ad, ok := uclaims["authorization_details"]; ok && ad != nil {
		m.ctx["authorization_details"] = ad
		if amt, cred, found := consentedPayment(ad); found {
			m.ctx["consented_amount"] = amt
			m.ctx["consented_creditor"] = cred
		}
	}

	// 4) evaluate at the PDP and enforce (fail closed on PDP error)
	agent := act
	if agent == "" {
		agent = clientID
	}
	if agent == "" {
		agent = "unknown-agent"
	}
	authzenReq := map[string]any{
		"subject": map[string]any{
			"type":     "agent",
			"identity": agent,
			"properties": map[string]any{
				"on_behalf_of": sub,
				"agent_type":   "ai_assistant",
				"scope":        scope,
				"client_id":    clientID,
			},
		},
		"action":   map[string]any{"name": m.action},
		"resource": map[string]any{"type": m.rtype, "id": m.rid, "properties": m.rprops},
		"context":  m.ctx,
	}

	out, err := s.evaluate(ctx, authzenReq)
	if err != nil {
		log.Printf("[%s] PDP call failed: %v", pep, err)
		return denySimple(pep, typev3.StatusCode_ServiceUnavailable, codes.Unavailable,
			"Authorization service unreachable; denying (fail-closed).", nil)
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
		log.Printf("[%s] 401 identity proofing required (%s) %s %s", pep, doctype, m.action, m.rid)
		return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
			"error":   "identity_verification_required",
			"doctype": doctype,
			"pep":     pep,
			"reason":  reason,
		}, map[string]string{
			"WWW-Authenticate": `Bearer error="identity_verification_required", doctype="` + doctype + `"`,
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
		log.Printf("[%s] 401 step-up required (%s) %s %s", pep, scope, m.action, m.rid)
		return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
			"error":  "insufficient_scope",
			"scope":  scope,
			"pep":    pep,
			"reason": reason,
		}, map[string]string{
			"WWW-Authenticate": `Bearer error="insufficient_scope", scope="` + scope + `"`,
		})
	}

	if !decision {
		log.Printf("[%s] DENY %s %s: %s", pep, m.action, m.rid, reason)
		return denySimple(pep, typev3.StatusCode_Forbidden, codes.PermissionDenied, reason,
			map[string]string{
				"X-PDP-PEP":      pep,
				"X-PDP-Decision": "DENY",
				"X-PDP-Action":   m.action,
				"X-PDP-Reason":   sanitizeHeader(reason),
			})
	}

	log.Printf("[%s] PERMIT %s %s (principal=%s agent=%s)", pep, m.action, m.rid, sub, agent)
	return permit(pep, m.action, reason, sub, act, scope)
}

// isToolsCall cheaply detects a tools/call JSON-RPC body.
func isToolsCall(body string) bool {
	if body == "" {
		return false
	}
	var probe struct {
		Method string `json:"method"`
	}
	return json.Unmarshal([]byte(body), &probe) == nil && probe.Method == "tools/call"
}

func toolCallName(body string) string {
	var probe struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal([]byte(body), &probe)
	return probe.Params.Name
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

// checkDpop enforces the DPoP proof (RFC 9449); nil means pass.
//
// Order matters. The cnf.jkt comparison is only meaningful AFTER the proof's signature
// verifies under the JWK it carries — the JWK is public in every proof, so without that
// step anyone who has observed one proof can mint proofs for a stolen token.
func checkDpop(pep, scheme, method, path, accessToken string, headers map[string]string, claims map[string]any) *authv3.CheckResponse {
	fail := func(reason string) *authv3.CheckResponse {
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated, reason, nil)
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
	if err := verifyProofSignature(proof, jwk, alg); err != nil {
		return fail("DPoP proof signature is invalid: " + err.Error())
	}

	jkt := jwkThumbprint(jwk)
	var cnfJkt string
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		cnfJkt, _ = cnf["jkt"].(string)
	}
	if jkt == "" || cnfJkt == "" || !constantTimeEqual(jkt, cnfJkt) {
		return fail("DPoP proof key does not match the token's cnf.jkt binding.")
	}
	if claimString(pclaims, "htm") != method {
		return fail("DPoP proof htm does not match the request method.")
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
	iat, ok := numericClaim(pclaims, "iat")
	if !ok {
		return fail("DPoP proof missing iat.")
	}
	now := time.Now()
	age := now.Sub(time.Unix(int64(iat), 0))
	if age > dpopMaxAge || age < -dpopMaxAge {
		return fail("DPoP proof iat is outside the acceptance window.")
	}
	if !dpopReplay.observe(claimString(pclaims, "jti"), now) {
		return fail("DPoP proof jti is missing or has already been used.")
	}

	// htu is compared best-effort: hosts get rewritten behind platform proxies, so a
	// path mismatch is logged rather than fatal. The ath + jti + signature checks above
	// are what actually bind the proof.
	if htu := claimString(pclaims, "htu"); htu != "" && !strings.Contains(htu, path) {
		log.Printf("[%s] DPoP htu path mismatch: %s", pep, htu)
	}
	return nil
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
}

func (s *server) evaluate(ctx context.Context, authzenReq map[string]any) (pepOutcome, error) {
	var out pepOutcome
	payload, _ := json.Marshal(authzenReq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.authzenURL+"/access/v1/evaluation", bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.authzenAPIKey)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
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

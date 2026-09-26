package coaz

// Engine ties discovery + mapping + PDP together: given one tools/call
// JSON-RPC request and the caller's token claims, produce a Verdict with the
// profile's JSON-RPC error semantics.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
)

// PDPConfig locates the AuthZEN PDP (e.g. the Ping Authorize authzen-adapter).
type PDPConfig struct {
	// URL is the AuthZEN API base, e.g. http://authzen-adapter:8080 — the
	// engine appends /access/v1/evaluation(s).
	URL string
	// APIKey is sent as a Bearer token to the PDP.
	APIKey string
	// HTTPClient overrides the default (10s timeout) client.
	HTTPClient *http.Client
}

// Options configures an Engine.
type Options struct {
	// PDP is the static PDP. Ignored when Resolver is set, except that callers who only
	// have a URL keep working: a nil Resolver becomes discovery.Static(PDP.URL, PDP.APIKey).
	PDP PDPConfig
	// Resolver finds the PDP for a route's resource. See core/authzen/discovery.
	Resolver discovery.Resolver
	// DiscoveryTTL bounds how long a tools/list snapshot is reused (default 60s).
	DiscoveryTTL time.Duration
	// DiscoveryHTTPClient overrides the client used for tools/list fetches.
	DiscoveryHTTPClient *http.Client
	// ApplyDefaultMappings authorizes tools that declare no mapping against the
	// binding's default tools/call mapping, as the binding requires. Off retains the
	// pre-v2 pass-through — non-conformant, but it is what deployed routes expect, so
	// the switch is theirs to throw.
	ApplyDefaultMappings bool
}

type Engine struct {
	resolver discovery.Resolver
	pdpc     *http.Client
	disco    *discoveryCache
	// applyDefaults turns on the binding's default mappings for tools that declare
	// none. Off leaves the pre-v2 pass-through, which is not conformant.
	applyDefaults bool
}

func NewEngine(opts Options) *Engine {
	ttl := opts.DiscoveryTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	pdpc := opts.PDP.HTTPClient
	if pdpc == nil {
		pdpc = &http.Client{Timeout: 10 * time.Second}
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = discovery.Static(opts.PDP.URL, opts.PDP.APIKey)
	}
	return &Engine{
		resolver:      resolver,
		pdpc:          pdpc,
		disco:         newDiscoveryCache(ttl, opts.DiscoveryHTTPClient),
		applyDefaults: opts.ApplyDefaultMappings,
	}
}

// CheckToolCall runs the COAZ flow for one tools/call JSON-RPC request.
//
//	upstreamURL   — the MCP server whose tools/list declares the mappings
//	authorization — the caller's Authorization header (reused for discovery)
//	rpcBody       — the raw tools/call JSON-RPC request body
//	tokenClaims   — decoded claims of the caller's access token
//	extraContext  — gateway-supplied context the mapping can't derive (e.g. user_scope)
//
// CallOptions carries the per-ROUTE knobs. They cannot live on the Engine: one process
// serves many routes, and whether default mappings apply is a property of the route.
type CallOptions struct {
	// ApplyDefaultMappings authorizes a tool that declares no mapping against the
	// binding's default tools/call mapping, as the binding requires. False retains the
	// non-conformant pass-through that deployed routes expect.
	ApplyDefaultMappings bool
	// Resource is the protected resource's identifier (RFC 8707), used to discover
	// its PDP. "" means the static PDP.
	Resource string
	// AccessToken, when set, is forwarded to the PDP as context.access_token so the PDP
	// can examine it itself. The caller decides whether the PDP connection is one a
	// bearer token may travel over.
	AccessToken string
	// Method and Path are the endpoint actually hit, forwarded as context.request so
	// the PDP can match a resource's declared requirements to it.
	Method, Path string
	// Layers is the ordered list of PDPs to ask — see discovery.ResolveLayers. Empty
	// means the resource's PDP alone.
	Layers []discovery.LayerSpec
	// FailOpen is the route's default failure mode; a layer's own setting overrides
	// it. Off, a PDP that cannot be reached denies the request. On, it is skipped.
	FailOpen bool
}

// forwardedContext is what every PDP call carries beyond the mapped subject, action and
// resource: the resource's declared posture as published (scopes, acr, sender-constraint
// requirements — whatever it said), tagged with its source; the endpoint hit; and, when
// the route allows, the raw token. The engine enforces none of it. Comparing a token's
// scope or acr to what a resource requires is a policy decision, and policy is offloaded
// to the PDP, where it can weigh them alongside things a PEP never sees. Keys the caller
// already set win: explicit context is never overwritten.
func forwardedContext(base map[string]any, meta *discovery.ResourceMetadata, opts CallOptions) map[string]any {
	out := make(map[string]any, len(base)+4)
	if meta != nil {
		out["resource_metadata"] = meta.Document
		out["resource_metadata_source"] = meta.Source
	}
	if opts.Method != "" || opts.Path != "" {
		out["request"] = map[string]any{"method": opts.Method, "path": opts.Path}
	}
	if opts.AccessToken != "" {
		out["access_token"] = opts.AccessToken
	}
	for k, v := range base {
		out[k] = v
	}
	return out
}

// CheckToolCall parses one MCP message strictly and decides it — see CheckMCP. A body
// ParseRequest refuses is denied with a 400, never waved through: a body this PEP reads
// one way and the upstream another is the bypass.
func (e *Engine) CheckToolCall(ctx context.Context, upstreamURL, authorization string, rpcBody []byte, tokenClaims map[string]any, extraContext map[string]any, opts CallOptions) Verdict {
	rpc, err := ParseRequest(rpcBody)
	if err != nil {
		return Refused(err)
	}
	return e.CheckMCP(ctx, upstreamURL, authorization, rpc, tokenClaims, extraContext, opts)
}

// Refused is the verdict for a body ParseRequest would not accept.
func Refused(err error) Verdict {
	var pe *ParseError
	if !errors.As(err, &pe) {
		pe = &ParseError{Code: CodeInvalidRequest, Message: "Invalid Request"}
	}
	return Verdict{CoazTool: true, HTTPStatus: http.StatusBadRequest, JSONRPCError: pe.JSONRPCError(),
		Reason: pe.Message, ClientReason: pe.Message}
}

// passThrough is a message that proceeds without a PDP call.
func passThrough(reason string) Verdict {
	return Verdict{Decision: true, PassThrough: true, Reason: reason, ClientReason: reason}
}

// denied is a deny the engine reached. message is what the client is told; reason, which
// may name internal URLs or upstream errors, is for the logs.
func denied(id any, code int, message, reason string) Verdict {
	return Verdict{CoazTool: true, JSONRPCError: jsonRPCError(id, code, message), Reason: reason, ClientReason: message}
}

// CheckMCP decides one parsed MCP message:
//
//	a response, ping, notifications/*  pass through without a PDP call;
//	server-initiated methods           pass through (out of the binding's scope);
//	tools/call                         the tool's declared mapping, else the default one;
//	any other method                   its default mapping; a method with none is denied.
//
// A route that turns default mappings off passes through everything that is not a
// declared tool call — the pre-binding behaviour, kept only as an explicit opt-out.
// With no upstream URL there is no tools/list to read declarations from, so every
// tools/call gets the default mapping.
func (e *Engine) CheckMCP(ctx context.Context, upstreamURL, authorization string, rpc *Request, tokenClaims map[string]any, extraContext map[string]any, opts CallOptions) Verdict {
	if rpc.Kind == KindResponse {
		return passThrough("a client's response to a server-initiated request")
	}
	if rpc.Method != "tools/call" {
		// Every other method is governed by its own default mapping — tools/call is not
		// special, it is merely the one that can also be declared per tool.
		return e.checkByDefaultMapping(ctx, rpc.ID, rpc.Method, rpc.Params, tokenClaims, extraContext, opts)
	}

	var dt *discoveredTool
	if upstreamURL != "" {
		found, err := e.disco.lookup(ctx, upstreamURL, authorization, rpc.ToolName)
		if err != nil {
			// Cannot know whether the tool is COAZ — fail closed per the
			// profile's PDP-communication semantics.
			return denied(rpc.ID, CodePDPError, "Authorization check unavailable: tool discovery failed",
				fmt.Sprintf("COAZ discovery failed: %v", err))
		}
		dt = found
	}
	if !dt.declared() {
		if !(opts.ApplyDefaultMappings || e.applyDefaults) {
			return passThrough("tool declares no mapping (defaults disabled)")
		}
		def, err := CompiledDefault("tools/call")
		if err != nil {
			msg := fmt.Sprintf("COAZ default mapping error: %v", err)
			return denied(rpc.ID, CodeMappingError, msg, msg)
		}
		dt = &discoveredTool{tool: Tool{Name: rpc.ToolName}, dialect: DialectV2, mappingV2: def}
	}
	// The denial code differs per dialect, so it is resolved once here and used for
	// every deny below.
	deniedCode := dt.dialect.DeniedCode()
	if dt.mappingErr != nil {
		msg := fmt.Sprintf("COAZ mapping error: %v", dt.mappingErr)
		return denied(rpc.ID, CodeMappingError, msg, msg)
	}

	// The PDPs are resolved before the request is built, because part of what they get
	// asked is what the resource's metadata said. Resolved once, so one decision cannot
	// straddle a PDP that moved.
	layers, err := discovery.ResolveLayers(ctx, e.resolver, opts.Resource, opts.Layers, opts.FailOpen)
	if err != nil {
		return denied(rpc.ID, CodePDPError, "Authorization service unavailable", fmt.Sprintf("PDP error: PDP discovery: %v", err))
	}
	eps := layers.PDPs
	extraContext = forwardedContext(extraContext, discovery.ResourceMetadataOf(eps), opts)

	// Both dialects produce the same BuiltRequest; only how they get there differs.
	var built *BuiltRequest
	if dt.mappingV2 != nil {
		built, err = dt.mappingV2.Build(rpc.Params, tokenClaims, extraContext)
	} else {
		built, err = dt.mapping.Build(rpc.Params, tokenClaims, extraContext)
	}
	if err != nil {
		msg := fmt.Sprintf("COAZ mapping error: %v", err)
		return denied(rpc.ID, CodeMappingError, msg, msg)
	}

	out, err := e.evaluateLayers(ctx, eps, built, layers.Skipped)
	if err != nil {
		v := denied(rpc.ID, CodePDPError, "Authorization service unavailable", fmt.Sprintf("PDP error: %v", err))
		v.PDPRequest = built.Body
		return v
	}
	decision, reason := out.Decision, out.Reason
	if !decision {
		if out.IdentityReq {
			// mDL identity-proofing gate (origination) — NOT a hard deny. Encode the
			// requirement + doctype in the JSON-RPC error so the MCP client relays it as an
			// identity challenge: the app pushes the customer's phone (CIBA), the approver
			// opens the wallet app2app, the mDL is presented, and origination resumes.
			doctype := out.IdentityDoctype
			if doctype == "" {
				doctype = "org.iso.18013.5.1.mDL"
			}
			msg := "identity_verification_required doctype=" + doctype
			if reason != "" {
				msg += " :: " + reason
			}
			return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg, ClientReason: msg,
				JSONRPCError: jsonRPCErrorData(rpc.ID, deniedCode, msg, map[string]any{
					"authz_challenge": AuthzChallenge{Type: "identity_proofing", Doctype: doctype,
						Reason: reason, PEP: "mcp-edge"}})}
		}
		if out.StepUp {
			scope := out.StepUpScope
			if scope == "" {
				scope = "banking:payments:transfer"
			}
			// RFC 9470 scope step-up — NOT a hard deny. Encode insufficient_scope + the scope in
			// the JSON-RPC error message so the MCP client relays it as a scope challenge the app
			// can turn into a RAR step-up (sign in + consent), rather than narrating a flat denial.
			msg := "insufficient_scope scope=" + scope
			if reason != "" {
				msg += " :: " + reason
			}
			return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg, ClientReason: msg,
				JSONRPCError: jsonRPCErrorData(rpc.ID, deniedCode, msg, map[string]any{
					"authz_challenge": AuthzChallenge{Type: "resource_authorisation", Scope: scope,
						Reason: reason, PEP: "mcp-edge"}})}
		}
		msg := "Access denied"
		if reason != "" {
			msg = "Access denied: " + reason
		}
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg, ClientReason: msg,
			JSONRPCError: jsonRPCError(rpc.ID, deniedCode, msg)}
	}
	if reason == "" {
		reason = "Permitted by policy."
	}
	return Verdict{CoazTool: true, Decision: true, PDPRequest: built.Body, Reason: reason, ClientReason: reason, FailedOpen: out.FailedOpen}
}

// pdpOutcome carries the PDP decision plus the policy's challenge advice: the RFC 9470
// scope step-up (payments) and/or the mDL identity-proofing requirement (origination).
type pdpOutcome struct {
	Decision        bool
	Reason          string
	StepUp          bool
	StepUpScope     string
	IdentityReq     bool
	IdentityDoctype string
	// FailedOpen names the layers that were skipped because they failed and were
	// allowed to. Non-empty on a permit means the permit rests on fewer opinions than
	// the policy asked for — worth a header and a log line.
	FailedOpen []string
}

// mergePermit folds a permitting layer's outcome into the running one.
//
// Only the DECISION is a single answer; the OBLIGATIONS are cumulative. Replacing the
// outcome wholesale let a later layer's plain permit erase an earlier layer's step-up or
// identity-proofing requirement, and the request was then permitted with no challenge
// issued at all — which defeats the point of putting a generic PDP in front of the
// resource's own. The first layer to require something owns its parameter, and its
// reason is what explains the challenge the client sees.
func mergePermit(acc, layer pdpOutcome) pdpOutcome {
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

// ErrPDPUnavailable marks a PDP call that failed for want of the PDP: a transport error, a
// timeout, a 5xx or a 429. It is the only failure a fail-open layer may skip. Anything
// else that stops a decision — a 3xx or 4xx, an answer that is not a decision, a request
// that could not be built — is a refusal, and fails closed whatever the layer says: a
// rotated key's 401, or a 413 a client provoked with an oversized argument, must not
// switch a layer off.
var ErrPDPUnavailable = errors.New("PDP unavailable")

// PDPStatusError classifies a non-2xx status from a PDP.
func PDPStatusError(status int) error {
	if status >= 500 || status == http.StatusTooManyRequests {
		return fmt.Errorf("%w: PDP returned %d", ErrPDPUnavailable, status)
	}
	return fmt.Errorf("PDP refused the request with %d", status)
}

// LayerNames strips the diagnostic detail from skipped-layer entries ("id (why)"),
// leaving the identifiers a client may see in X-PDP-Fail-Open. The detail belongs in the
// logs: it can carry internal addresses and upstream error text.
func LayerNames(skipped []string) []string {
	if len(skipped) == 0 {
		return nil
	}
	out := make([]string, 0, len(skipped))
	for _, s := range skipped {
		name, _, _ := strings.Cut(s, " (")
		out = append(out, name)
	}
	return out
}

// evaluateLayers asks each PDP in order with the same request. Every layer must
// permit; the first that does not is the answer, advice and all, and later layers are
// not consulted — a generic layer is a gate in front of a specific one.
//
// A PDP failure in a layer fails closed. Only when the PDP was unavailable
// (ErrPDPUnavailable) and the layer is fail-open is it skipped and named. If every layer
// was skipped the request is permitted — that is what fail-open means, and the operator
// chose it per layer — with the permit marked so it can be seen and counted. A deny is
// never skipped: it is a decision, not a failure; nor is a refusal.
func (e *Engine) evaluateLayers(ctx context.Context, eps []discovery.PDPEndpoints, built *BuiltRequest, skipped []string) (pdpOutcome, error) {
	var out pdpOutcome
	decided := false
	for _, ep := range eps {
		o, err := e.evaluate(ctx, ep, built)
		if err != nil {
			if !ep.FailOpen || !errors.Is(err, ErrPDPUnavailable) {
				return out, fmt.Errorf("%s: %w", ep.Identifier, err)
			}
			log.Printf("coaz: fail-open layer %s skipped: %v", ep.Identifier, err)
			skipped = append(skipped, ep.Identifier)
			continue
		}
		decided = true
		if !o.Decision {
			return o, nil
		}
		out = mergePermit(out, o)
	}
	out.FailedOpen = LayerNames(skipped)
	if !decided {
		out.Decision = true
		out.Reason = "fail-open: no policy layer could be reached (" + strings.Join(out.FailedOpen, ", ") + ")"
	}
	return out, nil
}

// evaluate POSTs the built request to the resolved PDP and folds the decision(s):
// every decision must be true for a permit.
func (e *Engine) evaluate(ctx context.Context, ep discovery.PDPEndpoints, built *BuiltRequest) (pdpOutcome, error) {
	var out pdpOutcome
	endpoint := ep.Evaluation
	if built.Batch {
		if ep.Evaluations == "" {
			// The PDP advertises no batch endpoint; guessing a path would send a batch
			// somewhere the PDP never said it would answer one.
			return out, fmt.Errorf("PDP %s advertises no access_evaluations_endpoint", ep.Identifier)
		}
		endpoint = ep.Evaluations
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(built.Body))
	if err != nil {
		return out, fmt.Errorf("PDP request could not be built: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ep.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+ep.APIKey)
	}
	resp, err := e.pdpc.Do(req)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrPDPUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, fmt.Errorf("%w: reading the answer: %v", ErrPDPUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, PDPStatusError(resp.StatusCode)
	}

	type decision struct {
		Decision bool `json:"decision"`
		Context  *struct {
			Reason           string `json:"reason"`
			StepUpRequired   bool   `json:"step_up_required"`
			StepUpScope      string `json:"step_up_scope"`
			IdentityRequired bool   `json:"identity_proofing_required"`
			IdentityDoctype  string `json:"identity_proofing_doctype"`
		} `json:"context"`
	}
	fold := func(d decision) pdpOutcome {
		o := pdpOutcome{Decision: d.Decision}
		if d.Context != nil {
			o.Reason, o.StepUp, o.StepUpScope = d.Context.Reason, d.Context.StepUpRequired, d.Context.StepUpScope
			o.IdentityReq, o.IdentityDoctype = d.Context.IdentityRequired, d.Context.IdentityDoctype
		}
		return o
	}
	if !built.Batch {
		var d decision
		if err := json.Unmarshal(raw, &d); err != nil {
			return out, fmt.Errorf("bad PDP response: %w", err)
		}
		return fold(d), nil
	}
	var batch struct {
		Evaluations []decision `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil {
		return out, fmt.Errorf("bad PDP evaluations response: %w", err)
	}
	// One answer per question, or it is not an answer: a short list would permit the
	// entries the PDP never evaluated.
	if len(batch.Evaluations) != built.Count {
		return out, fmt.Errorf("PDP answered %d evaluations for %d asked", len(batch.Evaluations), built.Count)
	}
	for _, d := range batch.Evaluations {
		if !d.Decision {
			return fold(d), nil
		}
	}
	return pdpOutcome{Decision: true}, nil
}

// checkByDefaultMapping authorizes a non-tools/call MCP method.
//
// The binding's shape: pass-through methods proceed without a PDP call, methods with a
// default mapping are evaluated against it, and anything else MUST be denied so that
// methods from future MCP versions fail closed instead of slipping past.
func (e *Engine) checkByDefaultMapping(
	ctx context.Context,
	id any,
	method string,
	params map[string]any,
	tokenClaims map[string]any,
	extraContext map[string]any,
	opts CallOptions,
) Verdict {
	if IsPassThrough(method) {
		return passThrough("pass-through method: " + method)
	}
	if IsServerInitiated(method) {
		// Out of scope for the binding: authorizing these with the client's token would
		// be asking about the wrong identity.
		return passThrough("server-initiated request, out of scope: " + method)
	}
	if !(opts.ApplyDefaultMappings || e.applyDefaults) {
		// The pre-binding behaviour, kept only as an explicit per-route opt-out.
		return passThrough("defaults disabled: " + method)
	}

	cm, err := CompiledDefault(method)
	if err != nil {
		// Unknown method: "MUST be denied ... This ensures that methods introduced by
		// future MCP versions or extensions fail closed rather than bypassing
		// authorization."
		msg := "Method not permitted: " + method
		return denied(id, CodeDeniedV2, msg, msg)
	}

	layers, err := discovery.ResolveLayers(ctx, e.resolver, opts.Resource, opts.Layers, opts.FailOpen)
	if err != nil {
		return denied(id, CodePDPError, "Authorization service unavailable", fmt.Sprintf("PDP error: PDP discovery: %v", err))
	}
	eps := layers.PDPs
	built, err := cm.Build(params, tokenClaims, forwardedContext(extraContext, discovery.ResourceMetadataOf(eps), opts))
	if err != nil {
		msg := fmt.Sprintf("COAZ mapping error: %v", err)
		return denied(id, CodeMappingError, msg, msg)
	}
	out, err := e.evaluateLayers(ctx, eps, built, layers.Skipped)
	if err != nil {
		v := denied(id, CodePDPError, "Authorization service unavailable", fmt.Sprintf("PDP error: %v", err))
		v.PDPRequest = built.Body
		return v
	}
	if !out.Decision {
		msg := "Access denied"
		if out.Reason != "" {
			msg = "Access denied: " + out.Reason
		}
		v := denied(id, CodeDeniedV2, msg, msg)
		v.PDPRequest = built.Body
		return v
	}
	reason := out.Reason
	if reason == "" {
		reason = "Permitted by policy."
	}
	return Verdict{CoazTool: true, Decision: true, PDPRequest: built.Body, Reason: reason, ClientReason: reason, FailedOpen: out.FailedOpen}
}

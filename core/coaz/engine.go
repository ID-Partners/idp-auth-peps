package coaz

// Engine ties discovery + mapping + PDP together: given one tools/call
// JSON-RPC request and the caller's token claims, produce a Verdict with the
// profile's JSON-RPC error semantics.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
}

func (e *Engine) CheckToolCall(ctx context.Context, upstreamURL, authorization string, rpcBody []byte, tokenClaims map[string]any, extraContext map[string]any, opts CallOptions) Verdict {
	var rpc struct {
		ID     any            `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(rpcBody, &rpc); err != nil {
		return Verdict{CoazTool: false, Decision: true, Reason: "not a JSON-RPC request"}
	}
	if rpc.Method != "tools/call" {
		// Every other method is governed by its own default mapping — tools/call is not
		// special, it is merely the one that can also be declared per tool.
		return e.checkByDefaultMapping(ctx, rpc.ID, rpc.Method, rpc.Params, tokenClaims, extraContext, opts)
	}
	toolName, _ := rpc.Params["name"].(string)
	if toolName == "" {
		return Verdict{CoazTool: false, Decision: true, Reason: "tools/call without a tool name"}
	}

	dt, err := e.disco.lookup(ctx, upstreamURL, authorization, toolName)
	if err != nil {
		// Cannot know whether the tool is COAZ — fail closed per the
		// profile's PDP-communication semantics.
		return Verdict{CoazTool: true, Decision: false,
			Reason:       fmt.Sprintf("COAZ discovery failed: %v", err),
			JSONRPCError: jsonRPCError(rpc.ID, CodePDPError, "Authorization check unavailable: tool discovery failed")}
	}
	if !dt.declared() {
		if !(opts.ApplyDefaultMappings || e.applyDefaults) {
			return Verdict{CoazTool: false, Decision: true, Reason: "tool declares no mapping (defaults disabled)"}
		}
		def, err := CompiledDefault("tools/call")
		if err != nil {
			return Verdict{CoazTool: true, Decision: false,
				Reason:       fmt.Sprintf("COAZ default mapping error: %v", err),
				JSONRPCError: jsonRPCError(rpc.ID, CodeMappingError, fmt.Sprintf("COAZ default mapping error: %v", err))}
		}
		dt = &discoveredTool{tool: dt.tool, dialect: DialectV2, mappingV2: def}
	}
	// The denial code differs per dialect, so it is resolved once here and used for
	// every deny below.
	deniedCode := dt.dialect.DeniedCode()
	if dt.mappingErr != nil {
		return Verdict{CoazTool: true, Decision: false,
			Reason:       fmt.Sprintf("COAZ mapping error: %v", dt.mappingErr),
			JSONRPCError: jsonRPCError(rpc.ID, CodeMappingError, fmt.Sprintf("COAZ mapping error: %v", dt.mappingErr))}
	}

	// Both dialects produce the same BuiltRequest; only how they get there differs.
	var built *BuiltRequest
	if dt.mappingV2 != nil {
		built, err = dt.mappingV2.Build(rpc.Params, tokenClaims, extraContext)
	} else {
		built, err = dt.mapping.Build(rpc.Params, tokenClaims, extraContext)
	}
	if err != nil {
		return Verdict{CoazTool: true, Decision: false,
			Reason:       fmt.Sprintf("COAZ mapping error: %v", err),
			JSONRPCError: jsonRPCError(rpc.ID, CodeMappingError, fmt.Sprintf("COAZ mapping error: %v", err))}
	}

	out, err := e.evaluate(ctx, opts.Resource, built)
	if err != nil {
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body,
			Reason:       fmt.Sprintf("PDP error: %v", err),
			JSONRPCError: jsonRPCError(rpc.ID, CodePDPError, "Authorization service unavailable")}
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
			return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg,
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
			return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg,
				JSONRPCError: jsonRPCErrorData(rpc.ID, deniedCode, msg, map[string]any{
					"authz_challenge": AuthzChallenge{Type: "resource_authorisation", Scope: scope,
						Reason: reason, PEP: "mcp-edge"}})}
		}
		msg := "Access denied"
		if reason != "" {
			msg = "Access denied: " + reason
		}
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg,
			JSONRPCError: jsonRPCError(rpc.ID, deniedCode, msg)}
	}
	if reason == "" {
		reason = "Permitted by policy."
	}
	return Verdict{CoazTool: true, Decision: true, PDPRequest: built.Body, Reason: reason}
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
}

// evaluate resolves the PDP for resource, POSTs the built request and folds the
// decision(s): every decision must be true for a permit. The endpoints are resolved
// once per request, so a PDP moving mid-flight cannot split one decision across two.
func (e *Engine) evaluate(ctx context.Context, resource string, built *BuiltRequest) (pdpOutcome, error) {
	var out pdpOutcome
	ep, err := e.resolver.Resolve(ctx, resource)
	if err != nil {
		return out, fmt.Errorf("PDP discovery: %w", err)
	}
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
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	if ep.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+ep.APIKey)
	}
	resp, err := e.pdpc.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("PDP returned %d", resp.StatusCode)
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
	if len(batch.Evaluations) == 0 {
		return out, fmt.Errorf("PDP evaluations response was empty")
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
		return Verdict{CoazTool: false, Decision: true, Reason: "pass-through method: " + method}
	}
	if IsServerInitiated(method) {
		// Out of scope for the binding: authorizing these with the client's token would
		// be asking about the wrong identity.
		return Verdict{CoazTool: false, Decision: true, Reason: "server-initiated request, out of scope: " + method}
	}
	if !(opts.ApplyDefaultMappings || e.applyDefaults) {
		// Pre-v2 behaviour, retained so enabling defaults is a deliberate migration.
		return Verdict{CoazTool: false, Decision: true, Reason: "defaults disabled: " + method}
	}

	cm, err := CompiledDefault(method)
	if err != nil {
		// Unknown method: "MUST be denied ... This ensures that methods introduced by
		// future MCP versions or extensions fail closed rather than bypassing
		// authorization."
		msg := "Method not permitted: " + method
		return Verdict{CoazTool: true, Decision: false, Reason: msg,
			JSONRPCError: jsonRPCError(id, CodeDeniedV2, msg)}
	}

	built, err := cm.Build(params, tokenClaims, extraContext)
	if err != nil {
		msg := fmt.Sprintf("COAZ mapping error: %v", err)
		return Verdict{CoazTool: true, Decision: false, Reason: msg,
			JSONRPCError: jsonRPCError(id, CodeMappingError, msg)}
	}
	out, err := e.evaluate(ctx, opts.Resource, built)
	if err != nil {
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body,
			Reason:       fmt.Sprintf("PDP error: %v", err),
			JSONRPCError: jsonRPCError(id, CodePDPError, "Authorization service unavailable")}
	}
	if !out.Decision {
		msg := "Access denied"
		if out.Reason != "" {
			msg = "Access denied: " + out.Reason
		}
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg,
			JSONRPCError: jsonRPCError(id, CodeDeniedV2, msg)}
	}
	reason := out.Reason
	if reason == "" {
		reason = "Permitted by policy."
	}
	return Verdict{CoazTool: true, Decision: true, PDPRequest: built.Body, Reason: reason}
}

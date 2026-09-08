// demo-console is the clickable half of the PDP discovery demo: pick a resource and a
// user, and it runs the identical request against all three PEPs at once — one told
// where its PDP is, one that trusts each resource's own metadata, one that trusts the
// federation — then shows the decision each reached and, from the stubs' own event
// feed, which documents were fetched and which PDP actually decided.
//
// Running the three side by side is the point. The same request, the same policy, three
// different answers, and the trace underneath saying why.
//
// Environment:
//
//	LISTEN         address to serve on (default :8088)
//	STUBS_BASE     how this process and the PEPs reach the stubs (default http://localhost)
//	STUBS_CONTROL  the stubs' event feed and control surface (default {STUBS_BASE}:9099)
//	PEP_STATIC     HTTP check API of the no-discovery PEP     (default {…}:9192)
//	PEP_RESOURCE   HTTP check API of the resource-mode PEP    (default {…}:9193)
//	PEP_FEDERATION HTTP check API of the federation-mode PEP  (default {…}:9194)
//	CHECK_API_TOKEN shared secret for those endpoints (default demo)
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed console.html
var consoleHTML []byte

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type pep struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Mode  string `json:"mode"`
	Blurb string `json:"blurb"`
	url   string
}

type resource struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	ID    string `json:"id"`
	Blurb string `json:"blurb"`
}

type action struct {
	Key    string         `json:"key"`
	Name   string         `json:"name"`
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Body   map[string]any `json:"body,omitempty"`
	// Style is the PEP's request-mapping style: "rest", or "mcp" for a JSON-RPC
	// tools/call. An mcp action needs a resource, since the MCP server IS the resource.
	Style string `json:"style"`
	// Note explains what this request is for, in the UI.
	Note string `json:"note,omitempty"`
}

type server struct {
	base      string
	peps      []pep
	resources []resource
	actions   []action
	control   string
	token     string
	client    *http.Client
}

func main() {
	base := strings.TrimRight(env("STUBS_BASE", "http://localhost"), "/")
	s := &server{
		base:    base,
		control: env("STUBS_CONTROL", base+":9099"),
		token:   env("CHECK_API_TOKEN", "demo"),
		client:  &http.Client{Timeout: 15 * time.Second},
		peps: []pep{
			{Key: "static", Name: "pep-static", Mode: "off", url: env("PEP_STATIC", base+":9192"),
				Blurb: "Told where the PDP is. No metadata is fetched at all."},
			{Key: "resource", Name: "pep-resource", Mode: "resource", url: env("PEP_RESOURCE", base+":9193"),
				Blurb: "Reads the resource's own RFC 9728 document to find its PDP."},
			{Key: "federation", Name: "pep-federation", Mode: "federation", url: env("PEP_FEDERATION", base+":9194"),
				Blurb: "Resolves the resource's trust chain to a configured anchor."},
		},
		resources: []resource{
			{Key: "plain", Name: "plain (Bank A)", ID: base + ":9004", Blurb: "Not federated. Its own metadata names Bank A's PDP, which steps up payments over 1000."},
			{Key: "bank-b", Name: "bank-b", ID: base + ":9009", Blurb: "Not federated. Its own metadata names Bank B's PDP — same product, stricter threshold: step-up over 100."},
			{Key: "impostor", Name: "impostor", ID: base + ":9005", Blurb: "Not federated. Its own metadata names the ROGUE PDP."},
			{Key: "member", Name: "member", ID: base + ":9001", Blurb: "Federated. Its own metadata names the rogue PDP first; the anchor's policy allows only Bank A's."},
			{Key: "broken", Name: "broken", ID: base + ":9006", Blurb: "Federated, but signed with a key the anchor never vouched for."},
			{Key: "stray", Name: "stray", ID: base + ":9007", Blurb: "No metadata of any kind."},
			{Key: "none", Name: "(no resource)", ID: "", Blurb: "The route names no resource, so every PEP uses the PDP it was configured with."},
		},
		actions: []action{
			{Key: "balance", Name: "read a balance", Method: "GET", Path: "/accounts/a1/balance", Style: "rest"},
			{Key: "pay50", Name: "pay 50", Method: "POST", Path: "/payments", Style: "rest",
				Body: map[string]any{"from_account": "a1", "to_account": "b2", "amount": 50, "currency": "AUD"}},
			{Key: "pay500", Name: "pay 500", Method: "POST", Path: "/payments", Style: "rest",
				Note: "Under Bank A's step-up threshold, over Bank B's. Same request, two answers.",
				Body: map[string]any{"from_account": "a1", "to_account": "b2", "amount": 500, "currency": "AUD"}},
			{Key: "pay5000", Name: "pay 5000", Method: "POST", Path: "/payments", Style: "rest",
				Body: map[string]any{"from_account": "a1", "to_account": "b2", "amount": 5000, "currency": "AUD"}},
			{Key: "transfer", Name: "MCP transfer (batch)", Method: "POST", Path: "/mcp", Style: "mcp",
				Note: "One tool call, two evaluations. Needs a PDP that advertises a batch endpoint; against one that does not, the PEP refuses rather than guessing a path."},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The page is baked into the binary, so a restarted demo is a changed page.
		// Without this a browser happily shows the previous one.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(consoleHTML)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"peps": s.peps, "resources": s.resources, "actions": s.actions,
			"estate_pdp": base + ":9098", "static_pdp": base + ":9002/tenants/bank-a",
			// Which stub is which PDP, so the page can find a PDP's metadata from the
			// name the trace uses.
			"pdps": map[string]string{
				"pdp-a": base + ":9002/tenants/bank-a", "pdp-b": base + ":9008/tenants/bank-b",
				"rogue-pdp": base + ":9003", "pdp-estate": base + ":9098",
			},
		})
	})
	mux.HandleFunc("/api/run", s.handleRun)
	mux.HandleFunc("/api/fetch", s.handleFetch)
	mux.HandleFunc("/api/control", s.handleControl)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	addr := env("LISTEN", ":8088")
	log.Printf("demo console on http://localhost%s (stubs at %s)", addr, base)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// runRequest is what the browser asks for: one resource, one human, one action, run
// against every PEP.
type runRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	// Client is who the token was issued to — the agent. The estate PDP judges it.
	Client string `json:"client"`
	// Layers is the route's pdp_layers, comma-separated. Empty: the resource's PDP alone.
	Layers string `json:"layers"`
	// ACR is how the human authenticated, as the token will claim it.
	ACR string `json:"acr"`
	// Scope is what the token carries.
	Scope string `json:"scope"`
	// ForwardToken sends the raw token to the PDP (the route's forward_access_token).
	ForwardToken bool `json:"forward_token"`
}

type runResult struct {
	PEP      string `json:"pep"`
	Mode     string `json:"mode"`
	Decision bool   `json:"decision"`
	Status   int    `json:"status"`
	Reason   string `json:"reason"`
	Error    string `json:"error,omitempty"`
	// FailOpen is X-PDP-Fail-Open from the PEP: the layers it skipped, if any.
	FailOpen string  `json:"fail_open,omitempty"`
	Events   []event `json:"events"`
	// Fractional: a cached localhost round trip is well under a millisecond, and an
	// integer would round every column to zero.
	MS float64 `json:"ms"`
}

type event struct {
	Seq    int64  `json:"seq"`
	Entity string `json:"entity"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Note   string `json:"note"`
	// Status and Body are the document a metadata endpoint served, or the request a
	// PDP received, as the stubs recorded them.
	Status int    `json:"status,omitempty"`
	Body   string `json:"body,omitempty"`
}

func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	var req runRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	res, ok := find(s.resources, req.Resource)
	if !ok {
		http.Error(w, `{"error":"unknown resource"}`, http.StatusBadRequest)
		return
	}
	act, ok := findAction(s.actions, req.Action)
	if !ok {
		http.Error(w, `{"error":"unknown action"}`, http.StatusBadRequest)
		return
	}
	out := make([]runResult, 0, len(s.peps))
	for _, p := range s.peps {
		// Each PEP's run gets its own window on the stubs' event feed, so the trace
		// shown under a column is only what that column caused.
		before := s.seq(r.Context())
		result := s.check(r.Context(), p, res, act, req)
		result.Events = s.eventsSince(r.Context(), before)
		out = append(out, result)
	}
	writeJSON(w, map[string]any{"results": out, "resource": res, "action": act})
}

// The return value is named so the deferred timing lands in the value the caller gets.
func (s *server) check(ctx context.Context, p pep, res resource, act action, in runRequest) (out runResult) {
	out = runResult{PEP: p.Name, Mode: p.Mode}
	started := time.Now()
	defer func() { out.MS = float64(time.Since(started).Microseconds()) / 1000 }()

	style := act.Style
	if style == "" {
		style = "rest"
	}
	if style == "mcp" && res.ID == "" {
		out.Error = "an MCP tool call needs a resource: the MCP server is the resource"
		return out
	}
	cfg := map[string]string{"pep_label": p.Name, "style": style, "require_token": "true"}
	if res.ID != "" {
		cfg["resource"] = res.ID
	}
	if in.ForwardToken {
		// The route's own call, not the PEP's default: a bearer token only travels to
		// a PDP over a connection the operator has decided is fit for it.
		cfg["forward_access_token"] = "true"
	}
	if in.Layers != "" {
		cfg["pdp_layers"] = in.Layers
	}
	body := ""
	switch {
	case style == "mcp":
		// The MCP server the tool mapping is discovered from is the resource itself.
		cfg["mcp_upstream_url"] = res.ID + "/mcp"
		raw, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "transfer", "arguments": map[string]any{"from": "a1", "to": "b2"}},
		})
		body = string(raw)
	case act.Body != nil:
		raw, _ := json.Marshal(act.Body)
		body = string(raw)
	}
	payload, _ := json.Marshal(map[string]any{
		"config": cfg, "method": act.Method, "path": act.Path,
		"headers": map[string]string{"authorization": "Bearer " + mintToken(in.Client, in.ACR, in.Scope), "content-type": "application/json"},
		"body":    body,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url+"/v1/mcp/check", bytes.NewReader(payload))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		out.Error = fmt.Sprintf("%s unreachable: %v", p.Name, err)
		return out
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var checked struct {
		Decision        bool              `json:"decision"`
		ResponseHeaders map[string]string `json:"response_headers"`
		Response        *struct {
			Status int    `json:"status"`
			Body   string `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &checked); err != nil {
		out.Error = fmt.Sprintf("unreadable check response: %s", strings.TrimSpace(string(raw)))
		return out
	}
	out.Decision = checked.Decision
	out.FailOpen = checked.ResponseHeaders["X-PDP-Fail-Open"]
	if checked.Decision {
		out.Status = 200
		out.Reason = "permitted"
		if out.FailOpen != "" {
			out.Reason = "permitted — failed open past " + out.FailOpen
		}
		return out
	}
	if checked.Response != nil {
		out.Status = checked.Response.Status
		var denial map[string]any
		if json.Unmarshal([]byte(checked.Response.Body), &denial) == nil {
			if v, ok := denial["reason"].(string); ok {
				out.Reason = v
			}
			if v, ok := denial["error"].(string); ok && v != "authorization_failed" {
				out.Reason = v + ": " + out.Reason
			}
			// An MCP denial is a JSON-RPC error object, per the profile.
			if e, ok := denial["error"].(map[string]any); ok {
				if msg, ok := e["message"].(string); ok {
					out.Reason = msg
				}
			}
		} else {
			out.Reason = checked.Response.Body
		}
	}
	return out
}

// handleFetch fetches one document from the stubs for display. The page shows the
// documents discovery is made of even when a PEP had them cached and fetched nothing.
// Only the stubs' origin is reachable, and the request is marked so the stubs keep it
// out of the trace.
func (s *server) handleFetch(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if !strings.HasPrefix(raw, s.base+":") && !strings.HasPrefix(raw, s.base+"/") {
		http.Error(w, `{"error":"not a stub"}`, http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, raw, nil)
	if err != nil {
		http.Error(w, `{"error":"bad url"}`, http.StatusBadRequest)
		return
	}
	req.Header.Set("X-Demo-Console", "1")
	resp, err := s.client.Do(req)
	if err != nil {
		writeJSON(w, map[string]any{"status": 0, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	writeJSON(w, map[string]any{"status": resp.StatusCode, "content_type": resp.Header.Get("Content-Type"), "body": string(body)})
}

// handleControl relays the console's levers to the stubs: move a PDP's advertised
// endpoint, hand a resource to another bank's PDP, or put everything back.
func (s *server) handleControl(w http.ResponseWriter, r *http.Request) {
	var body io.Reader
	method := http.MethodGet
	if r.Method == http.MethodPost {
		method = http.MethodPost
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(r.Context(), method, s.control+"/control", body)
	if err != nil {
		http.Error(w, `{"error":"bad control request"}`, http.StatusBadRequest)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, "stubs unreachable: "+err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

func (s *server) seq(ctx context.Context) int64 {
	seq, _ := s.fetchEvents(ctx, -1)
	return seq
}

func (s *server) eventsSince(ctx context.Context, since int64) []event {
	_, events := s.fetchEvents(ctx, since)
	return events
}

func (s *server) fetchEvents(ctx context.Context, since int64) (int64, []event) {
	url := s.control + "/events"
	if since >= 0 {
		url = fmt.Sprintf("%s?since=%d", url, since)
	} else {
		url = fmt.Sprintf("%s?since=%d", url, 1<<62) // only the current sequence number
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var doc struct {
		Seq    int64   `json:"seq"`
		Events []event `json:"events"`
	}
	if json.NewDecoder(resp.Body).Decode(&doc) != nil {
		return 0, nil
	}
	return doc.Seq, doc.Events
}

// mintToken builds the unsigned delegation token the demo uses: an agent (the client)
// acting for one fixed customer. Who the customer is never matters here — the demo is
// about which PDP decides and what it was given — so it is always "customer". The PEPs
// decode without verifying (no JWKS is configured) and warn about it at startup.
func mintToken(client, acr, scope string) string {
	seg := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	if client == "" {
		client = "agent-1"
	}
	if acr == "" {
		acr = "urn:idp:loa:password"
	}
	if scope == "" {
		scope = "accounts:read payments:write"
	}
	header := seg(map[string]any{"alg": "none", "typ": "JWT"})
	claims := seg(map[string]any{
		"sub": "customer", "client_id": client, "act": map[string]any{"sub": client},
		"scope": scope, "acr": acr,
	})
	return header + "." + claims + "."
}

func find(list []resource, key string) (resource, bool) {
	for _, r := range list {
		if r.Key == key {
			return r, true
		}
	}
	return resource{}, false
}

func findAction(list []action, key string) (action, bool) {
	for _, a := range list {
		if a.Key == key {
			return a, true
		}
	}
	return action{}, false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

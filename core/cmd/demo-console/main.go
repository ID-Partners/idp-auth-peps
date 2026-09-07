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
//	STUBS_EVENTS   the stubs' event feed (default {STUBS_BASE}:9008)
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
}

type server struct {
	peps      []pep
	resources []resource
	actions   []action
	events    string
	token     string
	client    *http.Client
}

func main() {
	base := strings.TrimRight(env("STUBS_BASE", "http://localhost"), "/")
	s := &server{
		events: env("STUBS_EVENTS", base+":9008"),
		token:  env("CHECK_API_TOKEN", "demo"),
		client: &http.Client{Timeout: 15 * time.Second},
		peps: []pep{
			{Key: "static", Name: "pep-static", Mode: "off", url: env("PEP_STATIC", base+":9192"),
				Blurb: "Told where the PDP is. No metadata is fetched at all."},
			{Key: "resource", Name: "pep-resource", Mode: "resource", url: env("PEP_RESOURCE", base+":9193"),
				Blurb: "Reads the resource's own RFC 9728 document to find its PDP."},
			{Key: "federation", Name: "pep-federation", Mode: "federation", url: env("PEP_FEDERATION", base+":9194"),
				Blurb: "Resolves the resource's trust chain to a configured anchor."},
		},
		resources: []resource{
			{Key: "plain", Name: "plain", ID: base + ":9004", Blurb: "Not federated. Its own metadata names the good PDP."},
			{Key: "impostor", Name: "impostor", ID: base + ":9005", Blurb: "Not federated. Its own metadata names the ROGUE PDP."},
			{Key: "member", Name: "member", ID: base + ":9001", Blurb: "Federated. Its own metadata names the rogue PDP first; the anchor's policy allows only the good one."},
			{Key: "broken", Name: "broken", ID: base + ":9006", Blurb: "Federated, but signed with a key the anchor never vouched for."},
			{Key: "stray", Name: "stray", ID: base + ":9007", Blurb: "No metadata of any kind."},
			{Key: "none", Name: "(no resource)", ID: "", Blurb: "The route names no resource, so every PEP uses its configured PDP."},
		},
		actions: []action{
			{Key: "balance", Name: "read a balance", Method: "GET", Path: "/accounts/a1/balance"},
			{Key: "pay50", Name: "pay 50", Method: "POST", Path: "/payments",
				Body: map[string]any{"from_account": "a1", "to_account": "b2", "amount": 50, "currency": "AUD"}},
			{Key: "pay5000", Name: "pay 5000", Method: "POST", Path: "/payments",
				Body: map[string]any{"from_account": "a1", "to_account": "b2", "amount": 5000, "currency": "AUD"}},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(consoleHTML)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"peps": s.peps, "resources": s.resources, "actions": s.actions})
	})
	mux.HandleFunc("/api/run", s.handleRun)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	addr := env("LISTEN", ":8088")
	log.Printf("demo console on http://localhost%s (stubs at %s)", addr, base)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// runRequest is what the browser asks for: one resource, one human, one action, run
// against every PEP.
type runRequest struct {
	Resource string `json:"resource"`
	Human    string `json:"human"`
	Action   string `json:"action"`
}

type runResult struct {
	PEP      string  `json:"pep"`
	Mode     string  `json:"mode"`
	Decision bool    `json:"decision"`
	Status   int     `json:"status"`
	Reason   string  `json:"reason"`
	Error    string  `json:"error,omitempty"`
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
	human := req.Human
	if human == "" {
		human = "alice"
	}

	out := make([]runResult, 0, len(s.peps))
	for _, p := range s.peps {
		// Each PEP's run gets its own window on the stubs' event feed, so the trace
		// shown under a column is only what that column caused.
		before := s.seq(r.Context())
		result := s.check(r.Context(), p, res, act, human)
		result.Events = s.eventsSince(r.Context(), before)
		out = append(out, result)
	}
	writeJSON(w, map[string]any{"results": out, "resource": res, "action": act, "human": human})
}

// The return value is named so the deferred timing lands in the value the caller gets.
func (s *server) check(ctx context.Context, p pep, res resource, act action, human string) (out runResult) {
	out = runResult{PEP: p.Name, Mode: p.Mode}
	started := time.Now()
	defer func() { out.MS = float64(time.Since(started).Microseconds()) / 1000 }()

	cfg := map[string]string{"pep_label": p.Name, "style": "rest", "require_token": "true"}
	if res.ID != "" {
		cfg["resource"] = res.ID
	}
	body := ""
	if act.Body != nil {
		raw, _ := json.Marshal(act.Body)
		body = string(raw)
	}
	payload, _ := json.Marshal(map[string]any{
		"config": cfg, "method": act.Method, "path": act.Path,
		"headers": map[string]string{"authorization": "Bearer " + mintToken(human), "content-type": "application/json"},
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
		Decision bool `json:"decision"`
		Response *struct {
			Status int    `json:"status"`
			Body   string `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &checked); err != nil {
		out.Error = fmt.Sprintf("unreadable check response: %s", strings.TrimSpace(string(raw)))
		return out
	}
	out.Decision = checked.Decision
	if checked.Decision {
		out.Status = 200
		out.Reason = "permitted"
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
		} else {
			out.Reason = checked.Response.Body
		}
	}
	return out
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
	url := s.events + "/events"
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

// mintToken builds the unsigned delegation token the demo uses: an agent acting for a
// human. The PEPs decode without verifying (no JWKS is configured) and warn about it at
// startup — this demo is about discovery, not token validation.
func mintToken(human string) string {
	seg := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := seg(map[string]any{"alg": "none", "typ": "JWT"})
	claims := seg(map[string]any{
		"sub": human, "client_id": "agent-1", "act": map[string]any{"sub": "agent-1"},
		"scope": "accounts:read payments:write",
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

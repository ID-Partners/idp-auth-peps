package main

// HTTP check API — lets non-Envoy gateways (e.g. the Kong authzen-pdp Lua
// plugin) delegate the COAZ / PDP decision to this service so both gateways
// share ONE spec implementation.
//
//	POST /v1/mcp/check
//	{
//	  "config":        { "pep_label": "...", "style": "mcp", ... },   // same knobs as ext_authz context
//	  "method":        "POST",
//	  "path":          "/mcp",
//	  "headers":       { "authorization": "Bearer ...", "x-user-token": "..." },
//	  "body":          "<raw JSON-RPC request body>"
//	}
//
// Response 200:
//	{
//	  "decision": true|false,
//	  "response": {                       // present when decision=false (or headers on permit)
//	    "status": 200, "headers": {...}, "body": "<verbatim body to return>"
//	  },
//	  "upstream_headers": {...},          // X-Auth-* to set on the upstream request on
//	                                      // permit; an empty value means remove it
//	  "response_headers": {...}           // headers to add to the response (X-PDP-*)
//	}

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type checkRequest struct {
	Config  map[string]string `json:"config"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type checkResponse struct {
	Decision        bool              `json:"decision"`
	Response        *deniedResponse   `json:"response,omitempty"`
	UpstreamHeaders map[string]string `json:"upstream_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

type deniedResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

// maxCheckRequestBytes bounds a check request: the relayed body plus the envelope. A
// gateway relays up to 1 MiB of body, which grows when it is escaped into a JSON string,
// so this leaves room for that. The ext_authz path is bounded by the gateway's
// max_request_bytes; this one by us.
const maxCheckRequestBytes = 4<<20 + 64<<10

func (s *server) handleHTTPCheck(w http.ResponseWriter, r *http.Request) {
	var req checkRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxCheckRequestBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid check request"}`, http.StatusBadRequest)
		return
	}
	lower := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		lower[toLower(k)] = v
	}
	conf := configFrom(req.Config)
	started := time.Now()
	resp := s.check(r.Context(), conf, req.Method, req.Path, lower, req.Body)
	s.audit("http", conf, req.Method, req.Path, lower, resp, started)

	out := checkResponse{}
	switch hr := resp.HttpResponse.(type) {
	case *authv3.CheckResponse_OkResponse:
		out.Decision = true
		out.UpstreamHeaders = flattenHeaders(hr.OkResponse.GetHeaders())
		for _, k := range hr.OkResponse.GetHeadersToRemove() {
			out.UpstreamHeaders[k] = "" // the caller removes the client's copy
		}
		out.ResponseHeaders = flattenHeaders(hr.OkResponse.GetResponseHeadersToAdd())
	case *authv3.CheckResponse_DeniedResponse:
		out.Decision = false
		out.Response = &deniedResponse{
			Status:  int(hr.DeniedResponse.GetStatus().GetCode()),
			Headers: flattenHeaders(hr.DeniedResponse.GetHeaders()),
			Body:    hr.DeniedResponse.GetBody(),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("check response encode failed: %v", err)
	}
}

func flattenHeaders(opts []*corev3.HeaderValueOption) map[string]string {
	out := map[string]string{}
	for _, o := range opts {
		out[o.GetHeader().GetKey()] = o.GetHeader().GetValue()
	}
	return out
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

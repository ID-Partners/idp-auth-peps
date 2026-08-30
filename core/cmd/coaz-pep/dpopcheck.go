package main

// A single-purpose DPoP verification endpoint.
//
//	POST /v1/dpop/verify
//	{ "method": "POST", "path": "/payments",
//	  "headers": { "authorization": "DPoP <token>", "dpop": "<proof>" } }
//
//	200 { "valid": true }
//	200 { "valid": false, "reason": "...", "status": 401 }
//
// It exists for the Kong plugin, which cannot verify a DPoP proof itself: there is no
// usable JOSE verifier in Lua, the same reason COAZ mapping is delegated here. Without
// it, `require_dpop` in Kong compared the proof's JWK thumbprint to cnf.jkt without ever
// checking the proof's signature — and since the proof carries its own public JWK, that
// comparison proves nothing about possession of the private key.
//
// Deliberately NOT /v1/mcp/check: that endpoint runs the whole pipeline including the
// PDP evaluation. A caller that only needs the sender-constraint checked would get a
// second, independent authorization decision as a side effect — one that could disagree
// with the caller's own.

import (
	"encoding/json"
	"log"
	"net/http"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

type dpopVerifyRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	// PepLabel is echoed into log lines so a delegated failure is attributable to the
	// route that asked.
	PepLabel string `json:"pep_label"`
}

type dpopVerifyResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
	Status int    `json:"status,omitempty"`
}

func (s *server) handleDpopVerify(w http.ResponseWriter, r *http.Request) {
	var req dpopVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid dpop verify request"}`, http.StatusBadRequest)
		return
	}
	lower := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		lower[toLower(k)] = v
	}
	pep := req.PepLabel
	if pep == "" {
		pep = "delegated-dpop"
	}

	token, scheme := extractToken(lower["authorization"])
	// Claims are only read for cnf.jkt. The token's own signature is validated by the
	// access-token validator when one is configured; this endpoint answers the narrower
	// question of whether the PROOF is good for this token.
	claims := jwtClaims(token)

	out := dpopVerifyResponse{Valid: true}
	if resp := checkDpop(pep, scheme, req.Method, req.Path, token, lower, claims); resp != nil {
		out.Valid = false
		out.Status = int(typev3.StatusCode_Unauthorized)
		out.Reason = resp.GetDeniedResponse().GetBody()
		if denied := resp.GetDeniedResponse(); denied != nil {
			if r := dpopReasonFrom(denied.GetBody()); r != "" {
				out.Reason = r
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("dpop verify response encode failed: %v", err)
	}
}

// dpopReasonFrom pulls the human reason out of the denial body the PEP renders, so the
// delegating gateway can relay it rather than a nested JSON blob.
func dpopReasonFrom(body string) string {
	var probe struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal([]byte(body), &probe) == nil {
		return probe.Reason
	}
	return ""
}

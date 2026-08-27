package main

// Guards for the HTTP check API.
//
// The ext_authz gRPC port takes its per-route config from the gateway's own
// configuration, which an external caller cannot influence. The HTTP check API is
// different: the CALLER supplies both `config.mcp_upstream_url` and the `authorization`
// header, and coaz-pep will then fetch that URL with that header. That is a
// server-side request forgery and credential-relay primitive unless it is bounded —
// hence a shared secret on the endpoint and an allowlist on the upstream.

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
)

// requireCheckToken wraps a handler with a constant-time bearer check. An empty token
// disables the check — main() warns loudly when that is the case.
func requireCheckToken(token string, next http.HandlerFunc) http.HandlerFunc {
	if token == "" {
		return next
	}
	want := []byte(token)
	return func(w http.ResponseWriter, r *http.Request) {
		presented, _ := extractToken(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare([]byte(presented), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// parseAllowlist reads a comma- or space-separated list of permitted MCP upstream
// prefixes. Entries are normalised to scheme://host[/path].
func parseAllowlist(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, strings.TrimRight(f, "/"))
		}
	}
	return out
}

// upstreamAllowed reports whether this MCP upstream may be fetched.
//
// An empty allowlist permits everything, which is the pre-existing behaviour and is
// warned about at startup. A non-empty allowlist matches on scheme + host + path
// prefix, compared against the PARSED URL so that a crafted string cannot slip past
// a naive prefix test.
func upstreamAllowed(allowlist []string, raw string) bool {
	if len(allowlist) == 0 {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// Compare without credentials, query or fragment: none of them should be able to
	// influence whether a host is permitted.
	candidate := strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/")
	for _, entry := range allowlist {
		if candidate == entry {
			return true
		}
		// A prefix only matches at a path boundary, so an allowlisted
		// https://mcp.example.com does not admit https://mcp.example.com.evil.test.
		if strings.HasPrefix(candidate, entry+"/") {
			return true
		}
	}
	return false
}

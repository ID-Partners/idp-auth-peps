package main

// Minimal JWT/JWK helpers for the demo PEP: decode (NOT verify) compact JWTs
// and compute RFC 7638 JWK thumbprints for the DPoP sender-constraint check.
// Mirrors demo/kong/plugins/authzen-pdp/handler.lua — see the demo-honesty
// note there: token signatures are validated upstream / by the AS, and the
// authorization decision itself is always made by Ping Authorize via the PDP.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// jwtPart decodes segment idx (0=header, 1=claims) of a compact JWT.
func jwtPart(token string, idx int) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 3 || idx >= len(parts) {
		return nil
	}
	raw, err := b64urlDecode(parts[idx])
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func jwtClaims(token string) map[string]any { return jwtPart(token, 1) }
func jwtHeader(token string) map[string]any { return jwtPart(token, 0) }

// jwkThumbprint computes the RFC 7638 SHA-256 thumbprint (base64url) of a JWK
// for EC / RSA / OKP keys, using the canonical member ordering.
func jwkThumbprint(jwk map[string]any) string {
	str := func(k string) string { s, _ := jwk[k].(string); return s }
	var canon string
	switch str("kty") {
	case "EC":
		canon = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, str("crv"), str("x"), str("y"))
	case "RSA":
		canon = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, str("e"), str("n"))
	case "OKP":
		canon = fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, str("crv"), str("x"))
	default:
		return ""
	}
	sum := sha256.Sum256([]byte(canon))
	return b64urlEncode(sum[:])
}

// claimString reads a string claim, tolerating absence.
func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	s, _ := claims[key].(string)
	return s
}

// scopeString normalises a scope claim that may be a string ("a b") or an
// array (["a","b"]) into a space-joined string.
func scopeString(claims map[string]any) string {
	if claims == nil {
		return ""
	}
	v, ok := claims["scope"]
	if !ok {
		v = claims["scp"]
	}
	switch s := v.(type) {
	case string:
		return s
	case []any:
		parts := make([]string, 0, len(s))
		for _, p := range s {
			if ps, ok := p.(string); ok {
				parts = append(parts, ps)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// audString normalises an `aud` claim that may be a string or an array of
// strings (RFC 9068 allows both) into a comma-joined string. Used to forward the
// token's audience to the PDP for RFC 8707 / FAPI 2.0 audience-restriction checks.
func audString(claims map[string]any) string {
	if claims == nil {
		return ""
	}
	switch a := claims["aud"].(type) {
	case string:
		return a
	case []any:
		parts := make([]string, 0, len(a))
		for _, p := range a {
			if ps, ok := p.(string); ok {
				parts = append(parts, ps)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

// strClaim returns a top-level string claim ("" when absent or non-string).
func strClaim(claims map[string]any, name string) string {
	if claims == nil {
		return ""
	}
	if s, ok := claims[name].(string); ok {
		return s
	}
	return ""
}

// claimsForCEL returns the decoded claims normalised for COAZ CEL evaluation:
// object-valued claims that arrive as JSON strings (PingFederate's JWT ATM
// emits `act` that way) are decoded so expressions like `token.act.sub` work
// regardless of issuer encoding.
func claimsForCEL(claims map[string]any) map[string]any {
	if claims == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		if s, ok := v.(string); ok && len(s) > 1 && s[0] == '{' {
			var decoded map[string]any
			if json.Unmarshal([]byte(s), &decoded) == nil {
				out[k] = decoded
				continue
			}
		}
		out[k] = v
	}
	return out
}

// actorSub extracts act.sub (RFC 8693). `act` may be a nested object
// (self-issued tokens) OR a JSON string (PingFederate's JWT ATM emits
// object-valued claims as strings) — handle both, as the Kong plugin does.
func actorSub(claims map[string]any) string {
	if claims == nil {
		return ""
	}
	act := claims["act"]
	if s, ok := act.(string); ok {
		var decoded map[string]any
		if json.Unmarshal([]byte(s), &decoded) == nil {
			act = decoded
		}
	}
	if m, ok := act.(map[string]any); ok {
		sub, _ := m["sub"].(string)
		return sub
	}
	return ""
}

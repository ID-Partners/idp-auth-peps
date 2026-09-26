package main

// Map the HTTP request to an AuthZEN (action, resource, context, resource
// properties). Direct port of map_request in the Kong authzen-pdp plugin so
// both gateways send Ping Authorize identical evaluation requests.
//
// style="rest": Resource Server semantics (fine-grained, e.g. payment amount).
// style="mcp" : the pre-binding coarse check, access_mcp on the `initialize`
//               handshake — used only on a route that opted out of default mappings.

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ID-Partners/idp-auth-peps/core/coaz"
)

type mapped struct {
	action string
	rtype  string
	rid    string
	rprops map[string]any
	ctx    map[string]any
	// refusal, when set, is why the request cannot be mapped at all — a body or path
	// the PEP cannot read the way the upstream will. The request is refused, not sent
	// to the PDP with the fields missing.
	refusal string
}

// The patterns match the END of the path at a segment boundary, so it does not matter
// whether the gateway strips a route prefix like /bank before the PEP sees the request,
// while /payments/x/customers/c1/accounts cannot pass for a payment.
var (
	reCustomerAccounts = regexp.MustCompile(`(?:^|/)customers/([^/]+)/accounts/?$`)
	reAccountBalance   = regexp.MustCompile(`(?:^|/)accounts/([^/]+)/balance/?$`)
	rePayments         = regexp.MustCompile(`(?:^|/)payments/?$`)
	reAccounts         = regexp.MustCompile(`(?:^|/)accounts/?$`)
)

// canonicalPath reports why a path is not in the form every server reads the same way,
// or "". A matrix parameter (;), an empty or dot segment, or an encoded slash, dot or
// backslash lets a PEP and an upstream route one request to two different handlers —
// Tomcat drops `;…` from a segment, other servers resolve `..` — so such a path is
// refused rather than mapped.
func canonicalPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.ContainsAny(path, ";\\"):
		return "matrix parameters and backslashes are not accepted in the path"
	case strings.Contains(path, "//"):
		return "empty path segments are not accepted"
	case strings.Contains(lower, "%2f"), strings.Contains(lower, "%2e"), strings.Contains(lower, "%5c"), strings.Contains(lower, "%3b"):
		return "encoded slashes, dots, backslashes and semicolons are not accepted in the path"
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return "dot segments are not accepted in the path"
		}
	}
	return ""
}

func mapRequest(style, method, path, body string) mapped {
	m := mapped{
		rprops: map[string]any{},
		ctx:    map[string]any{"channel": "ai-agent"},
	}

	if style == "mcp" {
		// The pre-binding coarse check: the agent's ACCESS TO THE MCP SERVICE, evaluated
		// on the `initialize` handshake. Fine-grained policy is the COAZ engine's.
		m.rtype, m.rid, m.action = "mcp-service", "northwind-bank", "access_mcp"
		return m
	}

	if why := canonicalPath(path); why != "" {
		m.refusal = "Request path refused: " + why + "."
		return m
	}
	var bodyObj map[string]any
	// A body the PEP cannot read — or could read one way while the upstream reads it
	// another — is refused. Sending the PDP a payment with no amount would ask it to
	// judge a request nobody made.
	readBody := func(what string) bool {
		if body == "" || coaz.CheckStrictJSON([]byte(body)) != nil || json.Unmarshal([]byte(body), &bodyObj) != nil || bodyObj == nil {
			m.refusal = what + " request body is not a readable JSON object."
			return false
		}
		return true
	}

	switch {
	case reCustomerAccounts.MatchString(path):
		m.action, m.rtype = "list_accounts", "customer"
		m.rid = reCustomerAccounts.FindStringSubmatch(path)[1]
	case reAccountBalance.MatchString(path):
		m.action, m.rtype = "get_balance", "account"
		m.rid = reAccountBalance.FindStringSubmatch(path)[1]
	case reAccounts.MatchString(path) && method == "POST":
		m.action, m.rtype = "open_account", "account"
		if !readBody("Account") {
			return m
		}
		m.rid = "new:savings"
		if at, ok := bodyObj["account_type"].(string); ok && at != "" {
			m.rid = "new:" + at
			m.rprops["account_type"] = at
		}
	case rePayments.MatchString(path) && method == "POST":
		m.action, m.rtype = "make_payment", "account"
		if !readBody("Payment") {
			return m
		}
		from, _ := bodyObj["from_account"].(string)
		m.rid = from
		m.rprops["from_account"] = bodyObj["from_account"]
		m.rprops["to_account"] = bodyObj["to_account"]
		if amt, ok := bodyObj["amount"].(float64); ok {
			m.ctx["amount"] = amt
		}
		if cur, ok := bodyObj["currency"].(string); ok && cur != "" {
			m.ctx["currency"] = cur
		} else {
			m.ctx["currency"] = "AUD"
		}
		if desc, ok := bodyObj["description"]; ok {
			m.ctx["description"] = desc
		}
		if it, ok := bodyObj["internal_transfer"]; ok {
			m.ctx["internal_transfer"] = it
		}
	default:
		m.action, m.rtype, m.rid = "http:"+strings.ToLower(method), "endpoint", path
	}
	return m
}

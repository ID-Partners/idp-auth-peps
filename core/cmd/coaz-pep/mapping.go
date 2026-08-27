package main

// Map the HTTP request to an AuthZEN (action, resource, context, resource
// properties). Direct port of map_request in the Kong authzen-pdp plugin so
// both gateways send Ping Authorize identical evaluation requests.
//
// style="rest": Resource Server semantics (fine-grained, e.g. payment amount).
// style="mcp" : MCP edge (coarse; refine to access_mcp on the JSON-RPC
//               `initialize` handshake, everything else passes on a valid token).

import (
	"encoding/json"
	"regexp"
	"strings"
)

type mapped struct {
	action string
	rtype  string
	rid    string
	rprops map[string]any
	ctx    map[string]any
}

var (
	reCustomerAccounts = regexp.MustCompile(`/customers/([^/]+)/accounts`)
	reAccountBalance   = regexp.MustCompile(`/accounts/([^/]+)/balance`)
)

// allowAction is the sentinel for "authenticated MCP traffic that skips the
// PDP" (non-initialize JSON-RPC, SSE GET, notifications), matching Kong.
const allowAction = "__allow__"

func mapRequest(style, method, path, body string) mapped {
	m := mapped{
		rprops: map[string]any{},
		ctx:    map[string]any{"channel": "ai-agent"},
	}

	if style == "mcp" {
		// PEP #1 authorizes the agent's ACCESS TO THE MCP SERVICE, evaluated once
		// on the MCP `initialize` handshake. Fine-grained per-operation policy is
		// enforced at PEP #2 (the Bank API edge).
		m.rtype, m.rid, m.action = "mcp-service", "northwind-bank", allowAction
		var rpc map[string]any
		if body != "" && json.Unmarshal([]byte(body), &rpc) == nil {
			if rpcMethod, _ := rpc["method"].(string); rpcMethod == "initialize" {
				m.action = "access_mcp"
			}
		}
		return m
	}

	// style == "rest". Patterns are prefix-tolerant: they match anywhere in the
	// path, so it doesn't matter whether the gateway strips the /bank prefix
	// before or after the PEP sees the request.
	var bodyObj map[string]any
	parseBody := func() bool {
		return body != "" && json.Unmarshal([]byte(body), &bodyObj) == nil
	}

	switch {
	case reCustomerAccounts.MatchString(path):
		m.action, m.rtype = "list_accounts", "customer"
		m.rid = reCustomerAccounts.FindStringSubmatch(path)[1]
	case reAccountBalance.MatchString(path):
		m.action, m.rtype = "get_balance", "account"
		m.rid = reAccountBalance.FindStringSubmatch(path)[1]
	case strings.Contains(path, "/accounts") && method == "POST":
		m.action, m.rtype = "open_account", "account"
		m.rid = "new:savings"
		if parseBody() {
			if at, ok := bodyObj["account_type"].(string); ok && at != "" {
				m.rid = "new:" + at
				m.rprops["account_type"] = at
			}
		}
	case strings.Contains(path, "/payments") && method == "POST":
		m.action, m.rtype = "make_payment", "account"
		if parseBody() {
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
		}
	default:
		m.action, m.rtype, m.rid = "http:"+strings.ToLower(method), "endpoint", path
	}
	return m
}

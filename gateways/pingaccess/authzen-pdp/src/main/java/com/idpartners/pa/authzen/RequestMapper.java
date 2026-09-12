package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps the HTTP request to an AuthZEN (action, resource, context, resource properties).
 * A direct port of map_request in the Kong plugin and mapRequest in the Go PEP, so all
 * three send the PDP identical evaluation requests.
 *
 * <p>style="rest": Resource Server semantics (fine-grained, e.g. payment amount).
 * style="mcp": MCP edge (coarse; refine to access_mcp on the JSON-RPC initialize
 * handshake, everything else passes on a valid token).
 */
final class RequestMapper {
    /** Authenticated MCP traffic that skips the PDP: non-initialize JSON-RPC, SSE GET, notifications. */
    static final String ALLOW = "__allow__";

    private static final Pattern CUSTOMER_ACCOUNTS = Pattern.compile("/customers/([^/]+)/accounts");
    private static final Pattern ACCOUNT_BALANCE = Pattern.compile("/accounts/([^/]+)/balance");

    record Mapped(String action, String rtype, String rid, ObjectNode rprops, ObjectNode ctx) {
    }

    private RequestMapper() {
    }

    static Mapped map(String style, String method, String path, byte[] body) {
        ObjectNode rprops = Json.object();
        ObjectNode ctx = Json.object();
        ctx.put("channel", "ai-agent");

        if ("mcp".equals(style)) {
            // PEP #1 authorises the agent's ACCESS TO THE MCP SERVICE, evaluated once on
            // the MCP initialize handshake. Everything else (tools/list, tools/call,
            // notifications, ping, SSE GET) is allowed through on a valid token so the
            // JSON-RPC session is not broken by a mid-stream 403; per-tool-call policy
            // is the engine's, via coaz_url.
            String action = ALLOW;
            JsonNode rpc = Json.parse(body);
            if (rpc instanceof ObjectNode && "initialize".equals(Json.text(rpc, "method"))) {
                action = "access_mcp";
            }
            return new Mapped(action, "mcp-service", "northwind-bank", rprops, ctx);
        }

        // style == "rest". Patterns are prefix-tolerant: they match anywhere in the path,
        // so it does not matter whether the gateway strips an application context root
        // before or after the PEP sees the request.
        Matcher cust = CUSTOMER_ACCOUNTS.matcher(path);
        Matcher acct = ACCOUNT_BALANCE.matcher(path);
        if (cust.find()) {
            return new Mapped("list_accounts", "customer", cust.group(1), rprops, ctx);
        }
        if (acct.find()) {
            return new Mapped("get_balance", "account", acct.group(1), rprops, ctx);
        }
        if (path.contains("/accounts") && "POST".equals(method)) {
            ObjectNode b = Json.parseObject(body);
            String rid = "new:savings";
            if (b != null) {
                JsonNode at = b.get("account_type");
                if (at != null && !at.isNull()) {
                    rid = "new:" + at.asText();
                    rprops.set("account_type", at);
                }
            }
            return new Mapped("open_account", "account", rid, rprops, ctx);
        }
        if (path.contains("/payments") && "POST".equals(method)) {
            ObjectNode b = Json.parseObject(body);
            String rid = null;
            if (b != null) {
                JsonNode from = b.get("from_account");
                rid = from == null || from.isNull() ? "" : from.asText();
                copy(b, rprops, "from_account");
                copy(b, rprops, "to_account");
                JsonNode amount = b.get("amount");
                if (amount != null && amount.isNumber()) {
                    ctx.set("amount", amount);
                } else if (amount != null && amount.isTextual()) {
                    try {
                        ctx.put("amount", Double.parseDouble(amount.asText()));
                    } catch (NumberFormatException e) {
                        // not a number; the PDP sees no amount, as it would from Kong
                    }
                }
                JsonNode cur = b.get("currency");
                if (cur != null && !cur.isNull()) {
                    ctx.set("currency", cur);
                } else {
                    ctx.put("currency", "AUD");
                }
                copy(b, ctx, "description");
                copy(b, ctx, "internal_transfer");
            }
            return new Mapped("make_payment", "account", rid, rprops, ctx);
        }
        return new Mapped("http:" + method.toLowerCase(Locale.ROOT), "endpoint", path, rprops, ctx);
    }

    private static void copy(ObjectNode from, ObjectNode to, String field) {
        JsonNode v = from.get(field);
        if (v != null && !v.isNull()) {
            to.set(field, v);
        }
    }
}

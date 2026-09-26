package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps a REST request to an AuthZEN (action, resource, context, resource properties):
 * Resource Server semantics, fine-grained (a payment carries its amount). A port of
 * map_request in the Kong plugin and mapRequest in the Go PEP, so all three send the PDP
 * identical evaluation requests. An MCP route is never mapped here: every request on one
 * is coaz-pep's to decide.
 */
final class RequestMapper {
    private static final Pattern CUSTOMER_ACCOUNTS = Pattern.compile("/customers/([^/]+)/accounts");
    private static final Pattern ACCOUNT_BALANCE = Pattern.compile("/accounts/([^/]+)/balance");

    record Mapped(String action, String rtype, String rid, ObjectNode rprops, ObjectNode ctx) {
    }

    private RequestMapper() {
    }

    static Mapped map(String method, String path, byte[] body) {
        ObjectNode rprops = Json.object();
        ObjectNode ctx = Json.object();
        ctx.put("channel", "ai-agent");

        // Patterns are prefix-tolerant: they match anywhere in the path,
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

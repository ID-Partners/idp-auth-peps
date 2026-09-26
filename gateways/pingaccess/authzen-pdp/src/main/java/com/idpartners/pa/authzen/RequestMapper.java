package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps a REST request to an AuthZEN (action, resource, context, resource properties):
 * Resource Server semantics, fine-grained (a payment carries its amount). A port of
 * map_request in the Kong plugin and mapRequest in the Go PEP. An MCP route is never
 * mapped here: every request on one is coaz-pep's to decide.
 *
 * <p>What the PDP is asked about must be what the upstream will do, so:
 * <ul>
 *   <li>the path is matched as the upstream routes it, not as it arrived: path
 *       parameters (";jsessionid=...") stripped from every segment, percent-decoding
 *       undone, empty and dot segments resolved. A path that cannot be read one way
 *       only (an encoded slash, a control character, a bad escape) is not mapped at
 *       all;</li>
 *   <li>routes are matched on whole segments at the end of the path, so a context root
 *       in front ("/bank/accounts/a1/balance") still maps and "/xaccounts/a1/balance"
 *       does not;</li>
 *   <li>a read is a read only for GET and HEAD, and a POST that names payments anywhere
 *       in its path is judged as the payment it may be;</li>
 *   <li>a payment or a new account is judged on its body, so a body that cannot be read,
 *       is not one JSON object, or lacks what the policy weighs is not mapped.</li>
 * </ul>
 */
final class RequestMapper {
    /** A JSON number, and nothing Double.parseDouble would also take ("12f", "0x1p3", " 12"). */
    private static final Pattern NUMBER = Pattern.compile("-?(0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?");
    private static final Pattern ABSOLUTE = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(.*)$");

    record Mapped(String action, String rtype, String rid, ObjectNode rprops, ObjectNode ctx, String path) {
    }

    /** A request the rule will not ask the PDP about, and why (for the log). */
    static final class Unmappable extends Exception {
        Unmappable(String message) {
            super(message);
        }
    }

    private RequestMapper() {
    }

    static Mapped map(String method, String rawPath, byte[] body, boolean bodyReadable) throws Unmappable {
        List<String> seg = segments(rawPath);
        String path = "/" + String.join("/", seg);
        ObjectNode rprops = Json.object();
        ObjectNode ctx = Json.object();
        ctx.put("channel", "ai-agent");
        String m = method.toUpperCase(Locale.ROOT);
        int n = seg.size();

        if (m.equals("POST") && seg.contains("payments")) {
            ObjectNode b = object(body, bodyReadable, "payment");
            JsonNode from = b.get("from_account");
            if (from == null || !(from.isTextual() || from.isNumber()) || from.asText().isEmpty()) {
                throw new Unmappable("a payment with no from_account");
            }
            rprops.set("from_account", from);
            copy(b, rprops, "to_account");
            ctx.set("amount", amount(b.get("amount")));
            JsonNode cur = b.get("currency");
            if (cur == null || cur.isNull()) {
                ctx.put("currency", "AUD");
            } else if (cur.isTextual()) {
                ctx.set("currency", cur);
            } else {
                throw new Unmappable("a payment whose currency is not a string");
            }
            copy(b, ctx, "description");
            copy(b, ctx, "internal_transfer");
            return new Mapped("make_payment", "account", from.asText(), rprops, ctx, path);
        }
        if (m.equals("POST") && n > 0 && seg.get(n - 1).equals("accounts")) {
            ObjectNode b = object(body, bodyReadable, "new account");
            JsonNode at = b.get("account_type");
            String rid = "new:savings";
            if (at != null && !at.isNull()) {
                if (!at.isTextual()) {
                    throw new Unmappable("an account_type that is not a string");
                }
                rid = "new:" + at.asText();
                rprops.set("account_type", at);
            }
            return new Mapped("open_account", "account", rid, rprops, ctx, path);
        }
        boolean read = m.equals("GET") || m.equals("HEAD");
        if (read && n >= 3 && seg.get(n - 3).equals("customers") && seg.get(n - 1).equals("accounts")) {
            return new Mapped("list_accounts", "customer", seg.get(n - 2), rprops, ctx, path);
        }
        if (read && n >= 3 && seg.get(n - 3).equals("accounts") && seg.get(n - 1).equals("balance")) {
            return new Mapped("get_balance", "account", seg.get(n - 2), rprops, ctx, path);
        }
        return new Mapped("http:" + m.toLowerCase(Locale.ROOT), "endpoint", path, rprops, ctx, path);
    }

    /**
     * The path's segments as an upstream servlet container would route them: path
     * parameters stripped, percent-decoding undone (strict UTF-8), empty and "."
     * segments dropped, ".." resolved.
     */
    static List<String> segments(String raw) throws Unmappable {
        String p = raw == null ? "" : raw;
        int hash = p.indexOf('#');
        if (hash >= 0) {
            p = p.substring(0, hash);
        }
        if (!p.startsWith("/")) {
            Matcher abs = ABSOLUTE.matcher(p);
            if (!abs.matches()) {
                throw new Unmappable("a request target that is not a path");
            }
            p = abs.group(1);
        }
        List<String> out = new ArrayList<>();
        for (String s : p.split("/", -1)) {
            int semi = s.indexOf(';');
            String d = decode(semi >= 0 ? s.substring(0, semi) : s);
            if (d.isEmpty() || d.equals(".")) {
                continue;
            }
            if (d.equals("..")) {
                if (!out.isEmpty()) {
                    out.remove(out.size() - 1);
                }
                continue;
            }
            out.add(d);
        }
        return out;
    }

    private static String decode(String s) throws Unmappable {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int i = 0;
        while (i < s.length()) {
            if (s.charAt(i) == '%') {
                if (i + 2 >= s.length() || Character.digit(s.charAt(i + 1), 16) < 0 || Character.digit(s.charAt(i + 2), 16) < 0) {
                    throw new Unmappable("a bad percent escape in the path");
                }
                bytes.write(Character.digit(s.charAt(i + 1), 16) * 16 + Character.digit(s.charAt(i + 2), 16));
                i += 3;
            } else {
                int cp = s.codePointAt(i);
                bytes.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                i += Character.charCount(cp);
            }
        }
        String d;
        try {
            d = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
        } catch (CharacterCodingException e) {
            throw new Unmappable("a path that is not UTF-8 once decoded");
        }
        for (int k = 0; k < d.length(); k++) {
            char c = d.charAt(k);
            // A slash or backslash that only appears once decoded is a separator to some
            // upstreams and a character to others: there is no one way to route it.
            if (c == '/' || c == '\\' || c < 0x20 || c == 0x7F) {
                throw new Unmappable("a path segment with an encoded separator or a control character");
            }
        }
        return d;
    }

    /** The write's body: one JSON object, read in full and strictly, or not mapped. */
    private static ObjectNode object(byte[] body, boolean bodyReadable, String what) throws Unmappable {
        if (!bodyReadable || body == null || body.length == 0) {
            throw new Unmappable("a " + what + " whose body could not be read");
        }
        JsonNode n;
        try {
            n = StrictJson.parse(body);
        } catch (StrictJson.Invalid e) {
            throw new Unmappable("a " + what + " whose body is not one unambiguous JSON value: " + e.getMessage());
        }
        if (!n.isObject()) {
            throw new Unmappable("a " + what + " whose body is not a JSON object");
        }
        return (ObjectNode) n;
    }

    /** A finite amount, from a JSON number or a string holding one; anything else is not a payment the PDP can weigh. */
    private static JsonNode amount(JsonNode a) throws Unmappable {
        if (a != null && a.isNumber() && Double.isFinite(a.doubleValue())) {
            return a;
        }
        if (a != null && a.isTextual() && NUMBER.matcher(a.asText()).matches() && Double.isFinite(Double.parseDouble(a.asText()))) {
            return Json.MAPPER.getNodeFactory().numberNode(Double.parseDouble(a.asText()));
        }
        throw new Unmappable("a payment with no finite amount");
    }

    private static void copy(ObjectNode from, ObjectNode to, String field) {
        JsonNode v = from.get(field);
        if (v != null && !v.isNull()) {
            to.set(field, v);
        }
    }
}

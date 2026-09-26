package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Iterator;
import java.util.Set;

/**
 * What an MCP request body is, before coaz-pep is asked about it: one JSON-RPC request or
 * notification with a string method, or one JSON-RPC response (a client's answer to a
 * server-initiated request). Anything else is refused with the JSON-RPC error the
 * contract names for it, and never reaches coaz-pep or the upstream.
 */
final class JsonRpc {
    /** The members of a JSON-RPC message, and the params members the default mappings read. */
    private static final Set<String> MEMBERS = Set.of("jsonrpc", "id", "method", "params", "result", "error");
    private static final Set<String> PARAMS = Set.of("name", "arguments", "uri");

    /** A readable message: its id (for the refusal's echo), its method (null for a response), the tool a tools/call names. */
    record Message(JsonNode id, String method, String tool) {
    }

    /** A body refused before anyone judges it: the HTTP status and the JSON-RPC error to answer with. */
    static final class Refusal extends Exception {
        final int status;
        final int code;
        final transient JsonNode id;

        Refusal(int status, int code, String message, JsonNode id) {
            super(message);
            this.status = status;
            this.code = code;
            this.id = id;
        }
    }

    static final int PARSE_ERROR = -32700;
    static final int INVALID_REQUEST = -32600;

    private JsonRpc() {
    }

    static Message classify(byte[] body) throws Refusal {
        JsonNode root;
        try {
            root = StrictJson.parse(body);
        } catch (StrictJson.Invalid e) {
            if (e.problem == StrictJson.Problem.NOT_JSON) {
                throw new Refusal(400, PARSE_ERROR, "Parse error", null);
            }
            throw new Refusal(400, INVALID_REQUEST, "Invalid Request: " + HeaderValues.brief(e.getMessage(), 80), null);
        }
        if (root.isArray()) {
            throw new Refusal(400, INVALID_REQUEST, "Invalid Request: batch requests are not supported", null);
        }
        if (!root.isObject()) {
            throw new Refusal(400, INVALID_REQUEST, "Invalid Request: not a JSON-RPC object", null);
        }
        JsonNode id = root.get("id");
        if (id != null && !(id.isTextual() || id.isNumber() || id.isNull())) {
            id = null;
        }
        // "Method" with no "method" beside it is no duplicate, but a case-insensitive
        // decoder upstream would still read it as the method. So would "Params", "Name".
        String variant = caseVariant(root, MEMBERS);
        if (variant != null) {
            throw new Refusal(400, INVALID_REQUEST, "Invalid Request: " + HeaderValues.brief(variant, 40) + " is not a JSON-RPC member name", id);
        }
        JsonNode params = root.get("params");
        if (params != null && params.isObject()) {
            variant = caseVariant(params, PARAMS);
            if (variant != null) {
                throw new Refusal(400, INVALID_REQUEST, "Invalid Request: params." + HeaderValues.brief(variant, 40)
                    + " differs only in case from a member the policy reads", id);
            }
        }
        JsonNode method = root.get("method");
        if (method == null) {
            if (root.has("id") && root.has("result") != root.has("error")) {
                return new Message(id, null, null); // a response to a server-initiated request
            }
            throw new Refusal(400, INVALID_REQUEST, "Invalid Request: neither a request nor a response", id);
        }
        if (!method.isTextual()) {
            throw new Refusal(400, INVALID_REQUEST, "Invalid Request: method must be a string", id);
        }
        String tool = null;
        if ("tools/call".equals(method.asText())) {
            JsonNode name = params == null ? null : params.get("name");
            if (name == null || !name.isTextual() || name.asText().isEmpty()) {
                throw new Refusal(400, INVALID_REQUEST, "Invalid Request: tools/call needs a string params.name", id);
            }
            tool = name.asText();
        }
        return new Message(id, method.asText(), tool);
    }

    /** A member of obj whose name equals one of names ignoring case but is not that name exactly. */
    private static String caseVariant(JsonNode obj, Set<String> names) {
        for (Iterator<String> it = obj.fieldNames(); it.hasNext(); ) {
            String n = it.next();
            if (!names.contains(n) && names.contains(StrictJson.fold(n))) {
                return n;
            }
        }
        return null;
    }
}

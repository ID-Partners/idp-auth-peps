package com.idpartners.pa.authzen;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** The one ObjectMapper, and the few JSON helpers the rule needs. */
final class Json {
    static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {
    }

    static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    /** Parses bytes as JSON; null for empty or unparseable input rather than an exception. */
    static JsonNode parse(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return MAPPER.readTree(bytes);
        } catch (IOException e) {
            return null;
        }
    }

    static JsonNode parse(String text) {
        return text == null ? null : parse(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Parses to an object, or null when the input is not a JSON object. */
    static ObjectNode parseObject(byte[] bytes) {
        JsonNode n = parse(bytes);
        return n instanceof ObjectNode ? (ObjectNode) n : null;
    }

    static byte[] bytes(JsonNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (JsonProcessingException e) {
            // A tree of ObjectNodes built here always serialises; this is the defensive
            // branch the coverage notes name, not a reachable one.
            throw new IllegalStateException(e);
        }
    }

    static String string(JsonNode node) {
        return new String(bytes(node), StandardCharsets.UTF_8);
    }

    /** A field's text, or null when it is absent, null, or not a scalar. */
    static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode v = node.get(field);
        return v == null || v.isNull() || v.isContainerNode() ? null : v.asText();
    }

    /** Lua truthiness, which is what the Kong plugin applies to PDP advice: only absent, null and false are false. */
    static boolean truthy(JsonNode node, String field) {
        if (node == null) {
            return false;
        }
        JsonNode v = node.get(field);
        return v != null && !v.isNull() && !(v.isBoolean() && !v.booleanValue());
    }
}

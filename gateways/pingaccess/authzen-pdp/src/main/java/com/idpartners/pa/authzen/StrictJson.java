package com.idpartners.pa.authzen;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * JSON for a request body the rule authorises, read strictly: exactly one JSON value, in
 * valid UTF-8, with no byte order mark and nothing after it, and no object anywhere
 * holding two members whose names are equal ignoring case.
 *
 * <p>The strictness is the point. The upstream reads the same bytes with its own parser,
 * and every leniency is a way for the two to disagree: Jackson takes the last of two
 * duplicate keys, Go's decoder matches member names case-insensitively, Node and Go
 * replace invalid UTF-8 with U+FFFD and carry on. A body that different parsers could
 * read differently is refused rather than judged.
 */
final class StrictJson {
    /** Whether the body is not JSON at all, or JSON that could be read two ways. */
    enum Problem { NOT_JSON, AMBIGUOUS }

    static final class Invalid extends Exception {
        final Problem problem;

        Invalid(Problem problem, String message) {
            super(message);
            this.problem = problem;
        }
    }

    private static final ObjectReader SYNTAX = Json.MAPPER.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final ObjectReader STRICT = SYNTAX.with(StreamReadFeature.STRICT_DUPLICATE_DETECTION);

    private StrictJson() {
    }

    static JsonNode parse(byte[] body) throws Invalid {
        if (body == null || body.length == 0) {
            throw new Invalid(Problem.NOT_JSON, "empty body");
        }
        String text;
        try {
            // The JDK's decoder refuses what Jackson's byte parser lets through:
            // overlong forms, encoded surrogates, truncated sequences.
            text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            throw new Invalid(Problem.NOT_JSON, "not valid UTF-8");
        }
        if (text.startsWith("﻿")) {
            throw new Invalid(Problem.NOT_JSON, "starts with a byte order mark");
        }
        // Syntax first, so a body that is not JSON is always a parse error, whatever
        // duplicate came before the mistake; then duplicates, on a body known to parse.
        JsonNode node;
        try {
            node = SYNTAX.readTree(text);
        } catch (IOException e) {
            throw new Invalid(Problem.NOT_JSON, "not a single JSON value");
        }
        if (node == null || node.isMissingNode()) {
            throw new Invalid(Problem.NOT_JSON, "empty body");
        }
        try {
            node = STRICT.readTree(text);
        } catch (IOException e) {
            throw new Invalid(Problem.AMBIGUOUS, "duplicate member");
        }
        String dup = caseDuplicate(node);
        if (dup != null) {
            throw new Invalid(Problem.AMBIGUOUS, "duplicate member " + dup);
        }
        return node;
    }

    /** The first member name, at any depth, that equals another in the same object ignoring case. */
    static String caseDuplicate(JsonNode node) {
        if (node.isObject()) {
            Set<String> seen = new HashSet<>();
            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> e = it.next();
                if (!seen.add(fold(e.getKey()))) {
                    return e.getKey();
                }
                String inner = caseDuplicate(e.getValue());
                if (inner != null) {
                    return inner;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode v : node) {
                String inner = caseDuplicate(v);
                if (inner != null) {
                    return inner;
                }
            }
        }
        return null;
    }

    /**
     * A member name with case folded out, code point by code point, as
     * String.equalsIgnoreCase compares: "paramſ" (a long s) folds to "params", and the
     * Kelvin sign to "k", which is how Go's decoder would match them too.
     */
    static String fold(String name) {
        StringBuilder b = new StringBuilder(name.length());
        name.codePoints().forEach(cp -> b.appendCodePoint(Character.toLowerCase(Character.toUpperCase(cp))));
        return b.toString();
    }
}

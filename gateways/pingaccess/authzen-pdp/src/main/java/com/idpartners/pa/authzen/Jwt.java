package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads a compact JWT's claims without verifying it. Verification is PingAccess's job for
 * the access token (its access token validators run before any rule does) and
 * {@link UserTokens}' job for X-User-Token; this class only decodes.
 */
final class Jwt {
    private static final Pattern AUTHORIZATION = Pattern.compile("^([A-Za-z]+)\\s+(.+)$");

    private Jwt() {
    }

    static byte[] b64urlDecode(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** The payload of a compact JWS as an object, or null for anything that is not one. */
    static ObjectNode claims(String token) {
        if (token == null) {
            return null;
        }
        int dot1 = token.indexOf('.');
        if (dot1 < 0) {
            return null;
        }
        int dot2 = token.indexOf('.', dot1 + 1);
        if (dot2 < 0) {
            return null;
        }
        byte[] payload = b64urlDecode(token.substring(dot1 + 1, dot2));
        if (payload == null) {
            return null;
        }
        JsonNode n = Json.parse(payload);
        return n instanceof ObjectNode ? (ObjectNode) n : null;
    }

    /** An access token and its scheme, lower-cased: "DPoP <t>" or "Bearer <t>". */
    record Token(String value, String scheme) {
    }

    static Token extractToken(String authorization) {
        if (authorization == null) {
            return null;
        }
        Matcher m = AUTHORIZATION.matcher(authorization);
        if (!m.matches()) {
            return null;
        }
        return new Token(m.group(2), m.group(1).toLowerCase(Locale.ROOT));
    }
}

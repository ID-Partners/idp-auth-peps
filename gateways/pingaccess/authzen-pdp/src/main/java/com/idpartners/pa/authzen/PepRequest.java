package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * What the pipeline needs from a request, detached from PingAccess's Exchange so the
 * decision can be made on another thread and tested without one.
 */
final class PepRequest {
    final String method;
    final String path;
    final Map<String, String> headers;
    final byte[] body;
    /**
     * Claims PingAccess itself established about the caller (from its access token
     * validation) when the application is protected; null when it is not.
     */
    final ObjectNode identityClaims;

    PepRequest(String method, String path, Map<String, String> headers, byte[] body, ObjectNode identityClaims) {
        this.method = method == null ? "" : method;
        this.path = path == null ? "" : path;
        Map<String, String> lower = new LinkedHashMap<>();
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    lower.putIfAbsent(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
                }
            }
        }
        this.headers = Collections.unmodifiableMap(lower);
        this.body = body;
        this.identityClaims = identityClaims;
    }

    String header(String name) {
        return headers.get(name.toLowerCase(Locale.ROOT));
    }
}

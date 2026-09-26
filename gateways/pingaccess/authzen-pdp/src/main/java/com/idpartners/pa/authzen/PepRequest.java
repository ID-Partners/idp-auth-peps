package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * What the pipeline needs from a request, detached from PingAccess's Exchange so the
 * decision can be made on another thread and tested without one.
 */
final class PepRequest {
    /** The largest body the rule will read, judge or hand to coaz-pep. Past it the body is unreadable, and refused wherever it matters. */
    static final int MAX_BODY = 1024 * 1024;

    final String method;
    final String path;
    /** The first value of each header, by lower-cased name. */
    final Map<String, String> headers;
    private final Map<String, List<String>> values;
    /** The whole body; null when there was none or it could not be read in full. */
    final byte[] body;
    /** False when the body was there and could not be read in full: never judge part of a body. */
    final boolean bodyReadable;
    /**
     * Claims PingAccess itself established about the caller (from its access token
     * validation) when the application is protected; null when it is not.
     */
    final ObjectNode identityClaims;

    PepRequest(String method, String path, Map<String, String> headers, byte[] body, ObjectNode identityClaims) {
        this(method, path, single(headers), body, true, identityClaims);
    }

    PepRequest(String method, String path, Map<String, List<String>> headerValues, byte[] body, boolean bodyReadable, ObjectNode identityClaims) {
        this.method = method == null ? "" : method;
        this.path = path == null ? "" : path;
        Map<String, List<String>> all = new LinkedHashMap<>();
        Map<String, String> first = new LinkedHashMap<>();
        if (headerValues != null) {
            for (Map.Entry<String, List<String>> e : headerValues.entrySet()) {
                if (e.getKey() == null || e.getValue() == null) {
                    continue;
                }
                String name = e.getKey().toLowerCase(Locale.ROOT);
                for (String v : e.getValue()) {
                    if (v != null) {
                        all.computeIfAbsent(name, k -> new ArrayList<>()).add(v);
                        first.putIfAbsent(name, v);
                    }
                }
            }
        }
        this.headers = Collections.unmodifiableMap(first);
        this.values = all;
        this.body = bodyReadable ? body : null;
        this.bodyReadable = bodyReadable;
        this.identityClaims = identityClaims;
    }

    private static Map<String, List<String>> single(Map<String, String> headers) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                out.put(e.getKey(), Collections.singletonList(e.getValue()));
            }
        }
        return out;
    }

    String header(String name) {
        return headers.get(name.toLowerCase(Locale.ROOT));
    }

    /** Every value the request carried for the header, in order; a client may send a header twice. */
    List<String> headerValues(String name) {
        return values.getOrDefault(name.toLowerCase(Locale.ROOT), List.of());
    }
}

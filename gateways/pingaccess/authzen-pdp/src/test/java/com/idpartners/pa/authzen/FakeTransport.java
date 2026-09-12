package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * A scripted transport, the counterpart of the Kong spec's router: routes map a URL (or
 * prefix) to a JSON tree (200 with that body), a String (200 raw), an Integer (that
 * status, empty body), Boolean.FALSE (connection refused) or a function of the request.
 * Longest prefix wins, so an exact well-known route beats a host-wide one; anything
 * unmatched is a 404. Every request is recorded.
 */
final class FakeTransport implements Transport {
    final Map<String, Object> routes = new LinkedHashMap<>();
    final List<Request> hits = new ArrayList<>();

    FakeTransport route(String prefix, Object responder) {
        routes.put(prefix, responder);
        return this;
    }

    @Override
    public Response send(Request r) throws IOException {
        hits.add(r);
        List<String> keys = new ArrayList<>(routes.keySet());
        keys.sort(Comparator.comparingInt(String::length).reversed());
        for (String prefix : keys) {
            if (r.url().equals(prefix) || r.url().startsWith(prefix)) {
                return respond(routes.get(prefix), r);
            }
        }
        return new Response(404, Map.of(), new byte[0]);
    }

    @SuppressWarnings("unchecked")
    private static Response respond(Object responder, Request r) throws IOException {
        if (responder instanceof Function) {
            return ((Function<Request, Response>) responder).apply(r);
        }
        if (Boolean.FALSE.equals(responder)) {
            throw new IOException("connection refused");
        }
        if (responder instanceof Integer) {
            return new Response((Integer) responder, Map.of(), new byte[0]);
        }
        if (responder instanceof String) {
            return json(200, (String) responder);
        }
        if (responder instanceof byte[]) {
            return new Response(200, Map.of("Content-Type", "application/json"), (byte[]) responder);
        }
        return json(200, Json.string((JsonNode) responder));
    }

    static Response json(int status, String body) {
        return new Response(status, Map.of("Content-Type", "application/json"), body.getBytes(StandardCharsets.UTF_8));
    }

    static Response json(int status, JsonNode body) {
        return json(status, Json.string(body));
    }

    /** How many recorded requests hit a URL containing the needle. */
    int count(String needle) {
        int n = 0;
        for (Request h : hits) {
            if (h.url().contains(needle)) {
                n++;
            }
        }
        return n;
    }

    Request last() {
        return hits.get(hits.size() - 1);
    }

    List<Request> to(String needle) {
        List<Request> out = new ArrayList<>();
        for (Request h : hits) {
            if (h.url().contains(needle)) {
                out.add(h);
            }
        }
        return out;
    }

    // ---------- tokens and JSON ----------

    static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /** An UNSIGNED compact JWT: the PEP decodes without verifying, which is what these tests exercise. */
    static String jwt(JsonNode claims) {
        return jwt(claims, "{\"alg\":\"none\",\"typ\":\"JWT\"}");
    }

    static String jwt(JsonNode claims, String header) {
        return b64url(header) + "." + b64url(Json.string(claims)) + ".";
    }

    /** {@code obj("sub", "alice", "act", obj("sub", "agent-7"))}: alternating keys and values, values as JSON nodes or scalars. */
    static ObjectNode obj(Object... kv) {
        ObjectNode o = Json.object();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            String k = (String) kv[i];
            Object v = kv[i + 1];
            if (v instanceof JsonNode) {
                o.set(k, (JsonNode) v);
            } else if (v instanceof String) {
                o.put(k, (String) v);
            } else if (v instanceof Boolean) {
                o.put(k, (Boolean) v);
            } else if (v instanceof Integer) {
                o.put(k, (Integer) v);
            } else if (v instanceof Double) {
                o.put(k, (Double) v);
            } else if (v instanceof List) {
                var arr = o.putArray(k);
                for (Object e : (List<?>) v) {
                    arr.add(String.valueOf(e));
                }
            } else if (v == null) {
                o.putNull(k);
            } else {
                throw new IllegalArgumentException("unsupported value " + v);
            }
        }
        return o;
    }

    static JsonNode parse(byte[] body) {
        return Json.parse(body);
    }
}

package com.idpartners.pa.authzen;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What the pipeline decided: let the request through with headers for the upstream, or
 * answer it here with a status, headers and body. Either way {@link #responseHeaders}
 * are the X-PDP-* headers the demo transcript reads, added to whatever response the
 * client eventually sees.
 */
final class Verdict {
    final boolean permit;
    final int status;
    final Map<String, String> headers;
    final byte[] body;
    final Map<String, String> upstreamHeaders;
    final Map<String, String> responseHeaders;

    private Verdict(boolean permit, int status, Map<String, String> headers, byte[] body,
                    Map<String, String> upstreamHeaders, Map<String, String> responseHeaders) {
        this.permit = permit;
        this.status = status;
        this.headers = headers == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        this.body = body == null ? new byte[0] : body;
        this.upstreamHeaders = upstreamHeaders == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(upstreamHeaders));
        this.responseHeaders = responseHeaders == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(responseHeaders));
    }

    static Verdict permit(Map<String, String> upstreamHeaders, Map<String, String> responseHeaders) {
        return new Verdict(true, 0, null, null, upstreamHeaders, responseHeaders);
    }

    static Verdict respond(int status, Map<String, String> headers, byte[] body, Map<String, String> responseHeaders) {
        return new Verdict(false, status, headers, body, null, responseHeaders);
    }

    String bodyText() {
        return new String(body, StandardCharsets.UTF_8);
    }

    /** The response header value, Content-Type say, looked up case-insensitively. */
    String header(String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return null;
    }
}

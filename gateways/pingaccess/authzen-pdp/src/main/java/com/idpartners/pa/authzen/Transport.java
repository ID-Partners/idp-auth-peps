package com.idpartners.pa.authzen;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The one HTTP call shape the rule makes: to the PDP, to coaz-pep, and for metadata.
 * An interface so the pipeline is tested against a scripted transport rather than a
 * socket; {@link JdkTransport} is the real one.
 *
 * <p>Two ways a call fails, and they are never confused, because only one of them may
 * ever open a fail-open layer:
 * <ul>
 *   <li>{@link IOException}: the far end is unavailable. Connect, DNS, TLS handshake,
 *       reset, timeout: an outage.</li>
 *   <li>{@link Refused}: the call could not be made or its answer could not be read. A
 *       URL that cannot be built, a header that cannot be sent, an answer over the size
 *       cap. Nothing about it says the far end is down, so it is never an outage.</li>
 * </ul>
 * An answer that arrives is a {@link Response} whatever its status; the caller decides
 * what a 3xx, 4xx or 5xx means.
 */
interface Transport {
    /** The most any answer may be, unless a request says otherwise. */
    int MAX_RESPONSE = 1024 * 1024;

    Response send(Request request) throws IOException, Refused;

    record Request(String method, String url, Map<String, String> headers, byte[] body, int timeoutMs, boolean verifyTls,
                   int maxResponseBytes) {
        Request(String method, String url, Map<String, String> headers, byte[] body, int timeoutMs, boolean verifyTls) {
            this(method, url, headers, body, timeoutMs, verifyTls, MAX_RESPONSE);
        }
    }

    record Response(int status, Map<String, String> headers, byte[] body) {
        String header(String name) {
            if (headers == null) {
                return null;
            }
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    return e.getValue();
                }
            }
            return null;
        }

        String text() {
            return body == null ? "" : new String(body, StandardCharsets.UTF_8);
        }

        /** 5xx and 429: the far end is there but cannot answer now. The only statuses that count as an outage. */
        boolean unavailable() {
            return (status >= 500 && status <= 599) || status == 429;
        }

        boolean ok() {
            return status >= 200 && status <= 299;
        }
    }

    /** A call that could not be made, or whose answer could not be read. Never an outage. */
    final class Refused extends Exception {
        Refused(String message) {
            super(message);
        }

        Refused(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

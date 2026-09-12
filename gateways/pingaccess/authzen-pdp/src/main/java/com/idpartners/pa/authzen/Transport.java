package com.idpartners.pa.authzen;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The one HTTP call shape the rule makes: to the PDP, to coaz-pep, and for metadata.
 * An interface so the pipeline is tested against a scripted transport rather than a
 * socket; {@link JdkTransport} is the real one.
 */
interface Transport {
    Response send(Request request) throws IOException;

    record Request(String method, String url, Map<String, String> headers, byte[] body, int timeoutMs, boolean verifyTls) {
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
    }
}

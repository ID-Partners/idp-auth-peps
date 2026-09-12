package com.idpartners.pa.authzen;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * {@link Transport} over the JDK's HttpClient. Redirects are never followed: a metadata
 * document that tries to send the PEP elsewhere is a failure, not a hop, and a PDP that
 * redirects a decision is not a PDP.
 *
 * <p>The JDK client rather than PingAccess's own {@code HttpClient} because the
 * latter only reaches administrator-configured Third-Party Services, and the URLs here
 * are discovered at runtime from a resource's metadata.
 */
final class JdkTransport implements Transport {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final JdkTransport SHARED = new JdkTransport();

    private final HttpClient verifying;
    private volatile HttpClient insecure;

    JdkTransport() {
        this.verifying = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(CONNECT_TIMEOUT)
            .build();
    }

    static JdkTransport shared() {
        return SHARED;
    }

    @Override
    public Response send(Request r) throws IOException {
        HttpClient client = r.verifyTls() ? verifying : insecureClient();
        HttpRequest.Builder b;
        try {
            b = HttpRequest.newBuilder(URI.create(r.url()));
        } catch (IllegalArgumentException e) {
            throw new IOException(r.url() + ": " + e.getMessage(), e);
        }
        b.timeout(Duration.ofMillis(Math.max(1, r.timeoutMs())));
        if (r.headers() != null) {
            for (Map.Entry<String, String> h : r.headers().entrySet()) {
                if (h.getValue() != null) {
                    b.header(h.getKey(), h.getValue());
                }
            }
        }
        b.method(r.method(), r.body() == null
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofByteArray(r.body()));
        try {
            HttpResponse<byte[]> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            Map<String, String> headers = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : resp.headers().map().entrySet()) {
                if (!e.getValue().isEmpty()) {
                    headers.put(e.getKey(), e.getValue().get(0));
                }
            }
            return new Response(resp.statusCode(), headers, resp.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while calling " + r.url(), e);
        }
    }

    private HttpClient insecureClient() {
        HttpClient c = insecure;
        if (c == null) {
            synchronized (this) {
                c = insecure;
                if (c == null) {
                    c = Insecure.client();
                    insecure = c;
                }
            }
        }
        return c;
    }

    /**
     * pdp_ssl_verify=false: trust any certificate and skip hostname verification. The JDK
     * client has no per-client hostname switch, only a system property read when the
     * client is first built, so this is process-wide for JDK clients built after it and
     * is for local development only. Excluded from unit coverage: it needs a TLS peer.
     */
    static final class Insecure {
        private Insecure() {
        }

        static HttpClient client() {
            try {
                TrustManager[] trustAll = {new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }};
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, trustAll, null);
                System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
                return HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(CONNECT_TIMEOUT)
                    .sslContext(ctx)
                    .build();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("cannot build a trust-all TLS context", e);
            }
        }
    }
}

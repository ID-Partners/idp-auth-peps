package com.idpartners.pa.authzen;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * {@link Transport} over the JDK's HttpClient. Redirects are never followed: a metadata
 * document that tries to send the PEP elsewhere is a failure, not a hop, and a PDP that
 * redirects a decision is not a PDP.
 *
 * <p>Every call has one deadline, the request's timeout, over the whole exchange. The
 * JDK's own request timeout stops once the response headers arrive, so a server that
 * sends headers and then trickles the body would otherwise hold the calling worker for
 * as long as it liked. The body is read by a subscriber that stops at the size cap, so an
 * answer is never buffered past it.
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
        this(HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(CONNECT_TIMEOUT)
            .build());
    }

    JdkTransport(HttpClient verifying) {
        this.verifying = verifying;
    }

    static JdkTransport shared() {
        return SHARED;
    }

    @Override
    public Response send(Request r) throws IOException, Refused {
        URI uri = Urls.parse(r.url());
        if (uri == null) {
            throw new Refused("not an absolute http(s) URL with a host: " + r.url());
        }
        int timeout = Math.max(1, r.timeoutMs());
        int max = r.maxResponseBytes() > 0 ? r.maxResponseBytes() : MAX_RESPONSE;
        HttpRequest request;
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(Duration.ofMillis(timeout));
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
            request = b.build();
        } catch (IllegalArgumentException | IllegalStateException e) {
            // A restricted or malformed header, or a method the client will not send.
            throw new Refused("the request to " + uri.getHost() + " cannot be built: " + e.getMessage(), e);
        }
        HttpClient client = r.verifyTls() ? verifying : insecureClient();
        CompletableFuture<HttpResponse<byte[]>> f = client.sendAsync(request,
            info -> new Capped(max, info.headers().firstValueAsLong("content-length").orElse(-1)));
        HttpResponse<byte[]> resp;
        try {
            resp = f.get(timeout, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            throw new HttpTimeoutException("no complete answer from " + uri.getHost() + " within " + timeout + " ms");
        } catch (ExecutionException e) {
            Throwable c = e.getCause();
            TooLarge big = find(c, TooLarge.class);
            if (big != null) {
                throw new Refused("the answer from " + uri.getHost() + " " + big.getMessage(), big);
            }
            if (c instanceof IOException) {
                throw (IOException) c;
            }
            throw new Refused("the call to " + uri.getHost() + " failed: " + c, c);
        } catch (InterruptedException e) {
            f.cancel(true);
            Thread.currentThread().interrupt();
            throw new Refused("interrupted while calling " + uri.getHost(), e);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : resp.headers().map().entrySet()) {
            if (!e.getValue().isEmpty()) {
                headers.put(e.getKey(), e.getValue().get(0));
            }
        }
        return new Response(resp.statusCode(), headers, resp.body());
    }

    private static <T extends Throwable> T find(Throwable t, Class<T> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return type.cast(c);
            }
        }
        return null;
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

    /** An answer over the cap. An IOException so the client carries it through, but never an outage: see send. */
    static final class TooLarge extends IOException {
        TooLarge(int max) {
            super("exceeds the " + max + "-byte cap");
        }
    }

    /**
     * Collects a body up to a cap, and gives up as soon as it is passed, or before reading
     * a byte when the declared length already says so.
     */
    static final class Capped implements HttpResponse.BodySubscriber<byte[]> {
        private final int max;
        private final long declared;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        Capped(int max, long declared) {
            this.max = max;
            this.declared = declared;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            if (declared > max) {
                s.cancel();
                result.completeExceptionally(new TooLarge(max));
                return;
            }
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (result.isDone()) {
                return;
            }
            for (ByteBuffer b : items) {
                int n = b.remaining();
                if (buf.size() + (long) n > max) {
                    subscription.cancel();
                    result.completeExceptionally(new TooLarge(max));
                    return;
                }
                byte[] chunk = new byte[n];
                b.get(chunk);
                buf.write(chunk, 0, n);
            }
        }

        @Override
        public void onError(Throwable t) {
            result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            result.complete(buf.toByteArray());
        }
    }

    /**
     * pdp_ssl_verify=false: trust any certificate chain. Hostname verification stays on:
     * the JDK client has no per-client switch for it, only a JVM-wide system property,
     * and a rule has no business changing how every other HTTP client in PingAccess
     * behaves. So the certificate must still name the host the URL does. Development
     * only, and refused without allow_insecure.
     */
    static final class Insecure {
        static final X509TrustManager TRUST_ALL = new X509TrustManager() {
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
        };

        private Insecure() {
        }

        static HttpClient client() {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{TRUST_ALL}, null);
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

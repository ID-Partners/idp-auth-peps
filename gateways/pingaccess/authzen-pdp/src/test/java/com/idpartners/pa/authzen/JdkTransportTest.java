package com.idpartners.pa.authzen;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The real transport against loopback servers: request and response mapping, no
 * redirects, one deadline over the whole exchange, the size cap, and the line between an
 * outage (IOException) and a refusal (Transport.Refused).
 */
class JdkTransportTest {
    static HttpServer server;
    static String base;
    static final AtomicReference<String> seenMethod = new AtomicReference<>();
    static final AtomicReference<String> seenBody = new AtomicReference<>();
    static final AtomicReference<String> seenAuth = new AtomicReference<>();
    static final byte[] BIG = new byte[Transport.MAX_RESPONSE + 1];

    @BeforeAll
    static void start() throws IOException {
        Arrays.fill(BIG, (byte) ' ');
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/echo", ex -> {
            seenMethod.set(ex.getRequestMethod());
            seenBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            seenAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            byte[] b = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.getResponseHeaders().add("X-Two", "first");
            ex.getResponseHeaders().add("X-Two", "second");
            ex.sendResponseHeaders(201, b.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        });
        server.createContext("/redirect", ex -> {
            ex.getResponseHeaders().add("Location", base + "/echo");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        server.createContext("/unavailable", ex -> {
            ex.sendResponseHeaders(503, -1);
            ex.close();
        });
        server.createContext("/slow", ex -> {
            sleep(500);
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        // Headers at once, then a body a byte at a time: the JDK's own timeout has
        // stopped by now, so only the transport's deadline ends it.
        server.createContext("/trickle", ex -> {
            ex.sendResponseHeaders(200, 0);
            try (OutputStream os = ex.getResponseBody()) {
                for (int i = 0; i < 40; i++) {
                    os.write('{');
                    os.flush();
                    sleep(100);
                }
            } catch (IOException gone) {
                // the client hung up, which is the point
            }
        });
        // Over the cap and says so up front, and over the cap without saying.
        server.createContext("/big-declared", ex -> {
            ex.sendResponseHeaders(200, BIG.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(BIG);
            } catch (IOException gone) {
                // refused before it was read
            }
        });
        server.createContext("/big-chunked", ex -> {
            ex.sendResponseHeaders(200, 0);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(BIG);
            } catch (IOException gone) {
                // refused part way
            }
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    static Transport.Request get(String url, int timeoutMs) {
        return new Transport.Request("GET", url, Map.of(), null, timeoutMs, true);
    }

    @Test
    void sendsMethodHeadersAndBodyAndMapsTheResponse() throws Exception {
        Transport t = new JdkTransport();
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("Authorization", "Bearer k");
        headers.put("X-Null", null);
        Transport.Response r = t.send(new Transport.Request("POST", base + "/echo", headers, "{\"a\":1}".getBytes(StandardCharsets.UTF_8), 5000, true));
        assertEquals(201, r.status());
        assertTrue(r.ok());
        assertEquals("{\"ok\":true}", r.text());
        assertEquals("application/json", r.header("content-type"));
        assertEquals("first", r.header("X-Two"), "the first value of a repeated header");
        assertEquals("POST", seenMethod.get());
        assertEquals("{\"a\":1}", seenBody.get());
        assertEquals("Bearer k", seenAuth.get());
        Transport.Response g = t.send(new Transport.Request("GET", base + "/echo", null, null, 5000, true));
        assertEquals("GET", seenMethod.get());
        assertEquals("", seenBody.get());
        assertEquals(201, g.status());
        assertSame(JdkTransport.shared(), JdkTransport.shared());
    }

    @Test
    void neverFollowsARedirectAndReturnsEveryStatusAsAnAnswer() throws Exception {
        Transport.Response r = new JdkTransport().send(get(base + "/redirect", 5000));
        assertEquals(302, r.status());
        assertNotNull(r.header("Location"));
        assertTrue(!r.ok() && !r.unavailable(), "a redirect is neither a success nor an outage");
        Transport.Response u = new JdkTransport().send(get(base + "/unavailable", 5000));
        assertTrue(u.unavailable());
        assertTrue(new Transport.Response(429, Map.of(), null).unavailable());
        assertTrue(!new Transport.Response(600, Map.of(), null).unavailable());
        assertTrue(!new Transport.Response(199, Map.of(), null).ok());
    }

    @Test
    void anOutageIsAnIOException() throws Exception {
        Transport t = new JdkTransport();
        int free;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            free = s.getLocalPort();
        }
        assertThrows(IOException.class, () -> t.send(get("http://127.0.0.1:" + free + "/x", 1000)));
        assertThrows(IOException.class, () -> t.send(get(base + "/slow", 50)));
        // A zero timeout is clamped rather than rejected by the client.
        assertThrows(IOException.class, () -> t.send(get(base + "/slow", 0)));
    }

    @Test
    void theDeadlineCoversTheWholeExchangeNotJustTheHeaders() {
        long t0 = System.nanoTime();
        IOException e = assertThrows(IOException.class, () -> new JdkTransport().send(get(base + "/trickle", 300)));
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(ms < 2000, "a trickled body held the caller for " + ms + " ms");
        assertTrue(e.getMessage().contains("300 ms"), e.getMessage());
    }

    @Test
    void anAnswerOverTheCapIsRefusedNotBuffered() throws Exception {
        Transport t = new JdkTransport();
        Transport.Refused declared = assertThrows(Transport.Refused.class, () -> t.send(get(base + "/big-declared", 5000)));
        assertTrue(declared.getMessage().contains("cap"), declared.getMessage());
        Transport.Refused chunked = assertThrows(Transport.Refused.class, () -> t.send(get(base + "/big-chunked", 5000)));
        assertTrue(chunked.getMessage().contains("cap"), chunked.getMessage());
        // A request may set its own cap.
        assertEquals(201, t.send(new Transport.Request("GET", base + "/echo", Map.of(), null, 5000, true, 64)).status());
        assertThrows(Transport.Refused.class, () -> t.send(new Transport.Request("GET", base + "/echo", Map.of(), null, 5000, true, 4)));
        // Zero means the default cap.
        assertEquals(201, t.send(new Transport.Request("GET", base + "/echo", Map.of(), null, 5000, true, 0)).status());
    }

    @Test
    void aCallThatCannotBeMadeIsARefusalNotAnOutage() {
        Transport t = new JdkTransport();
        for (String bad : new String[]{"not a url", "ftp://example.com/x", "http://authzen_pdp:8080/x", "/relative", "http://u:p@pdp/x", null}) {
            assertThrows(Transport.Refused.class, () -> t.send(get(bad, 1000)), String.valueOf(bad));
        }
        // A header the JDK client will not send, or a value it cannot carry.
        assertThrows(Transport.Refused.class, () -> t.send(new Transport.Request("GET", base + "/echo", Map.of("Host", "elsewhere"), null, 1000, true)));
        assertThrows(Transport.Refused.class, () -> t.send(new Transport.Request("GET", base + "/echo", Map.of("X-A", "a\r\nX-B: b"), null, 1000, true)));
    }

    @Test
    void aFailureTheClientCannotClassifyIsARefusalAndAnInterruptIsToo() throws Exception {
        HttpClient odd = mock(HttpClient.class);
        when(odd.sendAsync(any(), any())).thenReturn(CompletableFuture.failedFuture(new IllegalStateException("odd")));
        assertThrows(Transport.Refused.class, () -> new JdkTransport(odd).send(get(base + "/echo", 1000)));
        HttpClient never = mock(HttpClient.class);
        when(never.sendAsync(any(), any())).thenReturn(new CompletableFuture<>());
        Thread.currentThread().interrupt();
        try {
            assertThrows(Transport.Refused.class, () -> new JdkTransport(never).send(get(base + "/echo", 5000)));
            assertTrue(Thread.interrupted(), "the interrupt is kept for the caller");
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void theCappedReaderStopsAtTheCapAndPassesErrorsOn() throws Exception {
        JdkTransport.Capped declared = new JdkTransport.Capped(4, 10);
        Flow.Subscription s = mock(Flow.Subscription.class);
        declared.onSubscribe(s);
        ExecutionException e = assertThrows(ExecutionException.class, () -> declared.getBody().toCompletableFuture().get());
        assertInstanceOf(JdkTransport.TooLarge.class, e.getCause());
        declared.onNext(List.of(ByteBuffer.wrap(new byte[]{1})));
        JdkTransport.Capped streamed = new JdkTransport.Capped(4, -1);
        streamed.onSubscribe(s);
        streamed.onNext(List.of(ByteBuffer.wrap(new byte[]{1, 2}), ByteBuffer.wrap(new byte[]{3, 4})));
        streamed.onComplete();
        assertEquals(4, streamed.getBody().toCompletableFuture().get().length);
        JdkTransport.Capped failed = new JdkTransport.Capped(4, -1);
        failed.onSubscribe(s);
        failed.onError(new IOException("reset"));
        assertThrows(ExecutionException.class, () -> failed.getBody().toCompletableFuture().get());
        HttpResponse.BodySubscriber<byte[]> over = new JdkTransport.Capped(1, -1);
        over.onSubscribe(s);
        over.onNext(List.of(ByteBuffer.wrap(new byte[]{1, 2})));
        assertTrue(over.getBody().toCompletableFuture().isCompletedExceptionally());
    }

    @Test
    void responseHelpersTolerateMissingHeaders() {
        Transport.Response r = new Transport.Response(200, null, null);
        assertEquals("", r.text());
        assertNull(r.header("x"));
    }

    // ---------- pdp_ssl_verify=false ----------

    static Path keystore(Path dir) throws Exception {
        Path ks = dir.resolve("tls.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "tls", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-validity", "2", "-keystore", ks.toString(),
            "-storepass", "changeit", "-keypass", "changeit", "-storetype", "PKCS12").redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, p.waitFor(), out);
        return ks;
    }

    @Test
    void trustAllStillChecksTheHostNameAndNeverTouchesTheJvmWideSwitch(@TempDir Path dir) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore(dir))) {
            store.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        HttpsServer https = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        https.setHttpsConfigurator(new HttpsConfigurator(ctx));
        https.createContext("/ok", ex -> {
            byte[] b = "{}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        });
        https.start();
        try {
            int port = https.getAddress().getPort();
            JdkTransport t = new JdkTransport();
            Transport.Request byName = new Transport.Request("GET", "https://localhost:" + port + "/ok", Map.of(), null, 5000, false);
            Transport.Request byAddress = new Transport.Request("GET", "https://127.0.0.1:" + port + "/ok", Map.of(), null, 5000, false);
            // A self-signed certificate is accepted with verification off...
            assertEquals(200, t.send(byName).status());
            // ...but only for the name it carries: hostname verification stays on.
            assertThrows(IOException.class, () -> t.send(byAddress));
            // With verification on it is refused at the handshake, which is an outage.
            assertThrows(IOException.class, () -> t.send(new Transport.Request("GET", "https://localhost:" + port + "/ok", Map.of(), null, 5000, true)));
            assertNull(System.getProperty("jdk.internal.httpclient.disableHostnameVerification"),
                "a rule must never change how every other HTTP client in PingAccess verifies hosts");
            // The trust-all manager trusts everything and names no issuers.
            JdkTransport.Insecure.TRUST_ALL.checkClientTrusted(null, "EC");
            JdkTransport.Insecure.TRUST_ALL.checkServerTrusted(null, "EC");
            assertEquals(0, JdkTransport.Insecure.TRUST_ALL.getAcceptedIssuers().length);
        } finally {
            https.stop(0);
        }
    }
}

package com.idpartners.pa.authzen;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The real transport against a loopback server: request and response mapping, no redirects, failures as IOException. */
class JdkTransportTest {
    static HttpServer server;
    static String base;
    static final AtomicReference<String> seenMethod = new AtomicReference<>();
    static final AtomicReference<String> seenBody = new AtomicReference<>();
    static final AtomicReference<String> seenAuth = new AtomicReference<>();

    @BeforeAll
    static void start() throws IOException {
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
        server.createContext("/slow", ex -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    @Test
    void sendsMethodHeadersAndBodyAndMapsTheResponse() throws IOException {
        Transport t = new JdkTransport();
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("Authorization", "Bearer k");
        headers.put("X-Null", null);
        Transport.Response r = t.send(new Transport.Request("POST", base + "/echo", headers, "{\"a\":1}".getBytes(StandardCharsets.UTF_8), 5000, true));
        assertEquals(201, r.status());
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
    void neverFollowsARedirect() throws IOException {
        Transport.Response r = new JdkTransport().send(new Transport.Request("GET", base + "/redirect", Map.of(), null, 5000, true));
        assertEquals(302, r.status());
        assertNotNull(r.header("Location"));
    }

    @Test
    void reportsFailuresAsIOException() throws IOException {
        Transport t = new JdkTransport();
        assertThrows(IOException.class, () -> t.send(new Transport.Request("GET", "not a url", Map.of(), null, 1000, true)));
        int free;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            free = s.getLocalPort();
        }
        assertThrows(IOException.class, () -> t.send(new Transport.Request("GET", "http://127.0.0.1:" + free + "/x", Map.of(), null, 1000, true)));
        IOException slow = assertThrows(IOException.class, () -> t.send(new Transport.Request("GET", base + "/slow", Map.of(), null, 50, true)));
        assertTrue(slow.getMessage() == null || !slow.getMessage().isEmpty());
        // A zero timeout is clamped rather than rejected by the client.
        assertThrows(IOException.class, () -> t.send(new Transport.Request("GET", base + "/slow", Map.of(), null, 0, true)));
    }

    @Test
    void responseHelpersTolerateMissingHeaders() {
        Transport.Response r = new Transport.Response(200, null, null);
        assertEquals("", r.text());
        assertEquals(null, r.header("x"));
    }
}

package com.idpartners.pa.authzen;

import com.pingidentity.pa.sdk.interceptor.Outcome;
import com.sun.net.httpserver.HttpServer;
import jakarta.validation.ValidationException;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.idpartners.pa.authzen.FakeTransport.jwt;
import static com.idpartners.pa.authzen.FakeTransport.obj;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The 0.4.0 production-readiness review's probes, one per finding, kept as they were
 * written against 0.3: every one of them failed there. The detail of each fix is pinned
 * in the suite for its class; this is the list a reviewer can read top to bottom.
 */
class ReviewProbesTest {
    static final String COAZ = "http://coaz-pep:9192";

    // 1. MCP routes classified, then allowed: anything but one tools/call object passed on a token.
    @Test
    void p1_aBatchedToolsCallIsRefusedAndNothingIsAsked() throws Exception {
        FakeTransport t = new FakeTransport().route(COAZ, obj("decision", true)).route("http://pdp:8080", obj("decision", true));
        AuthZenRuleTest.CapturingResponses responses = new AuthZenRuleTest.CapturingResponses();
        AuthZenRule rule = new AuthZenRule(t, AuthZenRuleTest.DIRECT, responses, () -> 0L);
        AuthZenRuleConfiguration c = AuthZenRuleTest.conf();
        c.style = "mcp";
        c.coaz_url = COAZ;
        rule.configure(c);
        String batch = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"make_payment\"}}]";
        AuthZenRuleTest.Fixture f = new AuthZenRuleTest.Fixture("POST", "/mcp",
            AuthZenRuleTest.fields("Authorization", "Bearer " + jwt(obj("sub", "alice"))), batch.getBytes(StandardCharsets.UTF_8), null);
        assertEquals(Outcome.RETURN, rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals(400, responses.last.status);
        assertEquals(0, t.hits.size());
    }

    @Test
    void p1_everyWayRoundTheClassifierIsRefused() {
        byte[][] bodies = {
            b("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"make_payment\"}} x"),
            b("{\"jsonrpc\":\"2.0\",\"id\":1,\"Method\":\"tools/call\",\"params\":{\"name\":\"make_payment\"}}"),
            b("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"a\",\"Name\":\"make_payment\"}}"),
            b("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"method\":\"ping\",\"params\":{\"name\":\"a\"}}"),
            b(""),
            b("not json"),
            "{\"method\":\"tools/call\",\"params\":{\"name\":\"aÿ\"}}".getBytes(StandardCharsets.ISO_8859_1),
        };
        for (byte[] body : bodies) {
            FakeTransport t = PepTest.engine(obj("decision", true));
            Verdict v = PepTest.mcpBody(t, body);
            assertFalse(v.permit, new String(body, StandardCharsets.ISO_8859_1));
            assertEquals(0, t.hits.size());
        }
        FakeTransport gz = PepTest.engine(obj("decision", true));
        assertEquals(415, PepTest.mcpBody(gz, b(PepTest.TOOLS_CALL), "content-encoding", "gzip").status);
        // What used to pass on a token alone now goes to coaz-pep, which decides.
        FakeTransport t = PepTest.engine(obj("decision", false, "response", obj("status", 200, "body", "{}")));
        assertFalse(PepTest.mcpBody(t, b("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}")).permit);
        assertEquals(1, t.count("/v1/mcp/check"));
    }

    @Test
    void p1_styleMcpWithoutCoazUrlIsAConfigurationError() {
        AuthZenRuleConfiguration c = AuthZenRuleTest.conf();
        c.style = "mcp";
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(c));
    }

    // 2. Identity inputs trusted without verification.
    @Test
    void p2_requireUserLoginWithoutAJwksIsRefused() {
        AuthZenRuleConfiguration c = AuthZenRuleTest.secure();
        c.require_user_login = true;
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(c));
    }

    @Test
    void p2_anUnsignedTokenWithNoPingAccessIdentityIsNotAPrincipal() throws Exception {
        FakeTransport t = new FakeTransport().route("https://pdp.example", obj("decision", true));
        AuthZenRule rule = new AuthZenRule(t, AuthZenRuleTest.DIRECT, new AuthZenRuleTest.CapturingResponses(), () -> 0L);
        rule.configure(AuthZenRuleTest.secure());
        AuthZenRuleTest.Fixture f = new AuthZenRuleTest.Fixture("GET", "/accounts/a1/balance",
            AuthZenRuleTest.fields("Authorization", "Bearer " + jwt(obj("sub", "admin"))), null, null);
        assertEquals(Outcome.RETURN, rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        assertNull(f.setHeaders.get("X-Auth-Principal"));
        assertEquals(0, t.hits.size());
    }

    // 3. Fail-open on refusals.
    @Test
    void p3_aRefusalNeverOpensAFailOpenLayer() {
        for (Object r : new Object[]{401, 413, 302, "not json", obj("decision", "true"), new Transport.Refused("bad URL")}) {
            AuthZenRuleConfiguration c = PepTest.discoveryConf();
            c.pdp_layers = List.of(PepTest.DOWN + " fail-open", "resource");
            FakeTransport t = new FakeTransport()
                .route(DiscoveryTest.RES + "/.well-known/oauth-protected-resource", DiscoveryTest.resourceDoc(DiscoveryTest.GOOD))
                .route(DiscoveryTest.GOOD + "/.well-known/authzen-configuration", DiscoveryTest.pdpConfig(DiscoveryTest.GOOD))
                .route(DiscoveryTest.GOOD + "/custom/eval", obj("decision", true))
                .route(PepTest.DOWN + "/.well-known/authzen-configuration", 404)
                .route(PepTest.DOWN + "/access/v1/evaluation", r);
            Verdict v = PepTest.pep(c, t).decide(PepTest.req("GET", "/accounts/a1/balance", Map.of("authorization", PepTest.bearer(obj("sub", "alice"))), null));
            assertFalse(v.permit, "a refusal (" + r + ") must not be skipped");
        }
    }

    // 4. Starvation.
    @Test
    void p4_anErrorInThePipelineStillCompletesTheStage() throws Exception {
        Transport broken = r -> {
            throw new AssertionError("boom");
        };
        AuthZenRule rule = new AuthZenRule(broken, AuthZenRuleTest.DIRECT, new AuthZenRuleTest.CapturingResponses(), () -> 0L);
        rule.configure(AuthZenRuleTest.conf());
        AuthZenRuleTest.Fixture f = new AuthZenRuleTest.Fixture("GET", "/accounts/a1/balance",
            AuthZenRuleTest.fields("Authorization", "Bearer " + jwt(obj("sub", "alice"))), null, null);
        assertEquals(Outcome.RETURN, rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
    }

    @Test
    void p4_aTrickledBodyDoesNotHoldTheWorkerPastTheTimeout() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/trickle", ex -> {
            ex.sendResponseHeaders(200, 0);
            try (OutputStream os = ex.getResponseBody()) {
                for (int i = 0; i < 30; i++) {
                    os.write('{');
                    os.flush();
                    Thread.sleep(100);
                }
            } catch (Exception ignored) {
                // the client hung up
            }
        });
        server.start();
        try {
            long t0 = System.nanoTime();
            assertThrows(java.io.IOException.class, () -> new JdkTransport().send(new Transport.Request("GET",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/trickle", Map.of(), null, 300, true)));
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(ms < 1500, "held for " + ms + " ms");
        } finally {
            server.stop(0);
        }
    }

    // 5. A PDP-metadata blip cached the default paths for a TTL.
    @Test
    void p5_aPdpMetadataBlipDoesNotReplaceTheGoodEntry() throws Exception {
        FakeTransport t = DiscoveryTest.resourceRoutes();
        DiscoveryTest.Clock clock = new DiscoveryTest.Clock();
        Discovery d = new Discovery(t, () -> clock.now);
        assertEquals(DiscoveryTest.GOOD + "/custom/eval", d.resolve(DiscoveryTest.conf(), DiscoveryTest.RES).evaluation);
        t.route(DiscoveryTest.GOOD + "/.well-known/authzen-configuration", 500);
        clock.now += 301;
        assertEquals(DiscoveryTest.GOOD + "/custom/eval", d.resolve(DiscoveryTest.conf(), DiscoveryTest.RES).evaluation);
    }

    // 6. Unbounded bodies.
    @Test
    void p6_anOversizedAnswerIsRefusedNotBuffered() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] big = new byte[3 * 1024 * 1024];
        java.util.Arrays.fill(big, (byte) ' ');
        server.createContext("/big", ex -> {
            ex.sendResponseHeaders(200, big.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(big);
            } catch (java.io.IOException ignored) {
                // refused before it was read
            }
        });
        server.start();
        try {
            assertThrows(Transport.Refused.class, () -> new JdkTransport().send(new Transport.Request("GET",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/big", Map.of(), null, 5000, true)));
        } finally {
            server.stop(0);
        }
    }

    // 7. Headers.
    @Test
    void p7_pdpValuesAreEscapedInWwwAuthenticate() {
        FakeTransport t = new FakeTransport().route("http://pdp:8080", obj("decision", false, "context",
            obj("step_up_required", true, "step_up_scope", "a\" error=\"x\r\nX-Evil: 1")));
        Verdict v = PepTest.pep(PepTest.baseConf(), t).decide(PepTest.req("POST", "/payments",
            Map.of("authorization", PepTest.bearer(obj("sub", "alice"))), "{\"from_account\":\"a\",\"amount\":5}"));
        String www = v.header("WWW-Authenticate");
        assertFalse(www.contains("\r") || www.contains("\n"), www);
        assertTrue(www.contains("\\\""), "quoted-string escaping: " + www);
    }

    // 8. Configuration validation.
    @Test
    void p8_configurationValidation() {
        AuthZenRuleConfiguration host = AuthZenRuleTest.conf();
        host.authzen_url = "http://authzen_pdp:8080";
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(host));
        AuthZenRuleConfiguration nul = AuthZenRuleTest.conf();
        nul.style = null;
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(nul));
        AuthZenRuleConfiguration tls = AuthZenRuleTest.secure();
        tls.pdp_ssl_verify = false;
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(tls));
        assertTrue(new AuthZenRuleConfiguration().coaz_defaults);
    }

    // 9. REST mapping.
    @Test
    void p9_theRestMappingMatchesWhatTheUpstreamRoutes() throws Exception {
        RequestMapper.Mapped m = RequestMapper.map("POST", "/payments;/customers/c1/accounts",
            "{\"from_account\":\"a\",\"amount\":9000}".getBytes(StandardCharsets.UTF_8), true);
        assertEquals("make_payment", m.action());
        assertEquals("get_balance", RequestMapper.map("GET", "/x/../accounts/a1/balance", null, true).action());
        assertThrows(RequestMapper.Unmappable.class, () -> RequestMapper.map("POST", "/payments", b("{}"), true));
    }

    // 10. pdp_ssl_verify=false changed a JVM-wide property.
    @Test
    void p10_insecureTlsDoesNotTouchTheJvmGlobal() {
        JdkTransport.Insecure.client();
        assertNull(System.getProperty("jdk.internal.httpclient.disableHostnameVerification"));
    }

    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}

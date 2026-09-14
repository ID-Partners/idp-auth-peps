package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.pingidentity.pa.sdk.http.Body;
import com.pingidentity.pa.sdk.http.Exchange;
import com.pingidentity.pa.sdk.http.ExchangeProperty;
import com.pingidentity.pa.sdk.http.HeaderField;
import com.pingidentity.pa.sdk.http.Headers;
import com.pingidentity.pa.sdk.http.Method;
import com.pingidentity.pa.sdk.http.Request;
import com.pingidentity.pa.sdk.http.Response;
import com.pingidentity.pa.sdk.identity.Identity;
import com.pingidentity.pa.sdk.identity.OAuthTokenMetadata;
import com.pingidentity.pa.sdk.interceptor.Outcome;
import com.pingidentity.pa.sdk.ui.ConfigurationField;
import jakarta.validation.ValidationException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.idpartners.pa.authzen.FakeTransport.jwt;
import static com.idpartners.pa.authzen.FakeTransport.obj;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The glue between PingAccess's Exchange and the pipeline: configuration validation,
 * what is read off the exchange, how a verdict lands on it, and the fail-closed paths
 * around the worker.
 */
class AuthZenRuleTest {
    static final Executor DIRECT = Runnable::run;

    /** A stand-in for the engine's response builder that keeps what it was asked to build. */
    static final class CapturingResponses implements ResponseFactory {
        Verdict last;
        final Response response = mock(Response.class);

        @Override
        public Response build(Verdict v) {
            last = v;
            return response;
        }
    }

    /** A minimal exchange: properties in a map, a request with headers and a body. */
    static final class Fixture {
        final Exchange exchange = mock(Exchange.class);
        final Request request = mock(Request.class);
        final Headers headers = mock(Headers.class);
        final Body body = mock(Body.class);
        final Map<ExchangeProperty<?>, Object> props = new HashMap<>();
        final Map<String, String> setHeaders = new HashMap<>();
        final AtomicReference<Response> response = new AtomicReference<>();

        Fixture(String method, String uri, List<HeaderField> fields, byte[] content, Identity identity) {
            when(exchange.getRequest()).thenReturn(request);
            when(exchange.getIdentity()).thenReturn(identity);
            when(request.getMethod()).thenReturn(method == null ? null : Method.forName(method));
            when(request.getUri()).thenReturn(uri);
            when(request.getHeaders()).thenReturn(headers);
            when(headers.getHeaderFields()).thenReturn(fields);
            org.mockito.Mockito.doAnswer(inv -> {
                setHeaders.put(inv.getArgument(0), inv.getArgument(1));
                return null;
            }).when(headers).setFirstValue(any(), any());
            when(request.getBody()).thenReturn(body);
            try {
                when(body.isRead()).thenReturn(content != null);
                when(body.getContent()).thenReturn(content);
            } catch (Exception ignored) {
                // mock setup
            }
            org.mockito.Mockito.doAnswer(inv -> {
                props.put(inv.getArgument(0), inv.getArgument(1));
                return null;
            }).when(exchange).setProperty(any(), any());
            when(exchange.getProperty(any())).thenAnswer(inv -> Optional.ofNullable(props.get(inv.getArgument(0))));
            org.mockito.Mockito.doAnswer(inv -> {
                response.set(inv.getArgument(0));
                return null;
            }).when(exchange).setResponse(any());
        }
    }

    static AuthZenRuleConfiguration conf() {
        AuthZenRuleConfiguration c = new AuthZenRuleConfiguration();
        c.authzen_url = "http://pdp:8080";
        c.authzen_api_key = "k";
        c.pep_label = "rule-pep";
        return c;
    }

    static List<HeaderField> fields(String... kv) {
        java.util.ArrayList<HeaderField> out = new java.util.ArrayList<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            out.add(new HeaderField(kv[i], kv[i + 1]));
        }
        return out;
    }

    // ---------- configuration ----------

    @Test
    void validatesTheConfigurationAtConfigureTime() {
        AuthZenRuleConfiguration ok = conf();
        AuthZenRule.validate(ok);

        AuthZenRuleConfiguration noUrl = conf();
        noUrl.authzen_url = "";
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(noUrl));
        AuthZenRuleConfiguration style = conf();
        style.style = "soap";
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(style));
        AuthZenRuleConfiguration disc = conf();
        disc.pdp_discovery = "federation";
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(disc));
        AuthZenRuleConfiguration fail = conf();
        fail.fail_mode = "maybe";
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(fail));
        AuthZenRuleConfiguration ttl = conf();
        ttl.pdp_metadata_ttl = 0;
        assertThrows(ValidationException.class, () -> AuthZenRule.validate(ttl));
        AuthZenRuleConfiguration layers = conf();
        layers.pdp_layers = List.of("resource maybe");
        ValidationException e = assertThrows(ValidationException.class, () -> AuthZenRule.validate(layers));
        assertTrue(e.getMessage().contains("pdp_layers"));
        AuthZenRuleConfiguration nullLayers = conf();
        nullLayers.pdp_layers = null;
        AuthZenRule.validate(nullLayers);

        // require_dpop needs somewhere to verify the proof.
        AuthZenRuleConfiguration dpop = conf();
        dpop.require_dpop = true;
        ValidationException d = assertThrows(ValidationException.class, () -> AuthZenRule.validate(dpop));
        assertTrue(d.getMessage().contains("coaz_url"));
        dpop.coaz_url = "http://coaz-pep:9192";
        AuthZenRule.validate(dpop);
    }

    @Test
    void theConsoleGetsFieldLevelConstraintsThatMatchValidate() throws Exception {
        // PingAccess runs Bean Validation on the configuration and reports a violation on
        // the field in the console; validate() reports the same rule as a banner. The two
        // must agree, so the annotations are pinned here.
        java.lang.reflect.Field style = AuthZenRuleConfiguration.class.getField("style");
        assertEquals("rest|mcp", style.getAnnotation(jakarta.validation.constraints.Pattern.class).regexp());
        assertEquals("off|authzen|resource", AuthZenRuleConfiguration.class.getField("pdp_discovery").getAnnotation(jakarta.validation.constraints.Pattern.class).regexp());
        assertEquals("closed|open", AuthZenRuleConfiguration.class.getField("fail_mode").getAnnotation(jakarta.validation.constraints.Pattern.class).regexp());
        for (String f : new String[]{"pdp_metadata_ttl", "pdp_timeout_ms", "coaz_timeout_ms"}) {
            assertEquals(1, AuthZenRuleConfiguration.class.getField(f).getAnnotation(jakarta.validation.constraints.Min.class).value(), f);
        }
        assertNotNull(AuthZenRuleConfiguration.class.getField("authzen_url").getAnnotation(jakarta.validation.constraints.NotBlank.class));
        // Every field the console shows carries a UIElement with a label naming its JSON key.
        for (java.lang.reflect.Field f : AuthZenRuleConfiguration.class.getDeclaredFields()) {
            com.pingidentity.pa.sdk.ui.UIElement ui = f.getAnnotation(com.pingidentity.pa.sdk.ui.UIElement.class);
            assertNotNull(ui, f.getName());
            assertTrue(ui.label().contains("(" + f.getName() + ")"), f.getName());
        }
    }

    @Test
    void configureBuildsThePipelineAndDescribesEveryKnob() throws Exception {
        AuthZenRule rule = new AuthZenRule(new FakeTransport(), DIRECT, new CapturingResponses(), () -> 0L);
        AuthZenRuleConfiguration c = conf();
        c.pdp_ssl_verify = false; // warned about, not refused
        rule.configure(c);
        assertEquals(c, rule.getConfiguration());
        List<ConfigurationField> fields = rule.getConfigurationFields();
        Set<String> names = new java.util.HashSet<>();
        for (ConfigurationField f : fields) {
            names.add(f.getName());
        }
        // The knob names are the same map every PEP takes.
        for (String knob : new String[]{"authzen_url", "authzen_api_key", "pep_label", "style", "require_token", "require_dpop",
            "require_user_login", "stepup_scope", "coaz_url", "coaz_api_key", "mcp_upstream_url", "federation_entity_url",
            "pdp_ssl_verify", "coaz_defaults", "legacy_subject_identity", "pdp_discovery", "resource", "pdp_metadata_ttl",
            "pdp_allowlist", "resource_metadata_allowlist", "pdp_discovery_insecure", "forward_access_token", "pdp_layers",
            "fail_mode", "user_token_jwks_url", "user_token_issuer", "user_token_audience"}) {
            assertTrue(names.contains(knob), knob);
        }
        // With a JWKS, the user token is verified; the configuration is still accepted.
        AuthZenRuleConfiguration verified = conf();
        verified.user_token_jwks_url = "http://as.example/jwks";
        rule.configure(verified);
        AuthZenRuleConfiguration bad = conf();
        bad.style = "nope";
        assertThrows(ValidationException.class, () -> rule.configure(bad));
    }

    // ---------- handleRequest ----------

    @Test
    void aPermitContinuesWithTheUpstreamHeadersAndTheResponseGetsThePdpHeaders() throws Exception {
        FakeTransport t = new FakeTransport().route("http://pdp:8080/access/v1/evaluation", obj("decision", true));
        CapturingResponses responses = new CapturingResponses();
        AuthZenRule rule = new AuthZenRule(t, DIRECT, responses, () -> 0L);
        rule.configure(conf());
        Fixture f = new Fixture("GET", "/accounts/a1/balance?x=1", fields("Authorization", "Bearer " + jwt(obj("sub", "alice", "act", obj("sub", "agent-7")))), null, null);
        Outcome o = rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
        assertEquals(Outcome.CONTINUE, o);
        assertEquals("alice", f.setHeaders.get("X-Auth-Principal"));
        assertEquals("agent-7", f.setHeaders.get("X-Auth-Agent"));
        assertNull(responses.last, "a permit builds no response");
        // The query string never reaches the mapping.
        assertEquals("/accounts/a1/balance", Json.parse(t.last().body()).get("context").get("request").get("path").asText());
        // The response phase adds the X-PDP-* headers.
        Response r = mock(Response.class);
        Headers rh = mock(Headers.class);
        when(r.getHeaders()).thenReturn(rh);
        when(f.exchange.getResponse()).thenReturn(r);
        rule.handleResponse(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
        verify(rh).setFirstValue("X-PDP-Decision", "PERMIT");
        verify(rh).setFirstValue("X-PDP-PEP", "rule-pep");
        // And copes with there being no response, or no headers, or no verdict.
        when(f.exchange.getResponse()).thenReturn(null);
        rule.handleResponse(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
        Response bare = mock(Response.class);
        when(f.exchange.getResponse()).thenReturn(bare);
        rule.handleResponse(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
        Fixture none = new Fixture("GET", "/x", fields(), null, null);
        rule.handleResponse(none.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
    }

    @Test
    void aDenyStopsTheChainAndTheErrorCallbackWritesTheVerdict() throws Exception {
        FakeTransport t = new FakeTransport().route("http://pdp:8080/access/v1/evaluation", obj("decision", false, "context", obj("reason", "no", "step_up_required", true, "step_up_scope", "s")));
        CapturingResponses responses = new CapturingResponses();
        AuthZenRule rule = new AuthZenRule(t, DIRECT, responses, () -> 0L);
        rule.configure(conf());
        Fixture f = new Fixture("POST", "/payments", fields("authorization", "Bearer " + jwt(obj("sub", "alice")), "Content-Type", "application/json"),
            "{\"from_account\":\"a\",\"amount\":9000}".getBytes(StandardCharsets.UTF_8), null);
        Outcome o = rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
        assertEquals(Outcome.RETURN, o);
        assertNull(responses.last, "the response is the callback's to write");
        assertFalse(f.setHeaders.containsKey("X-Auth-Principal"));
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertNotNull(responses.last);
        assertEquals(401, responses.last.status);
        assertEquals("insufficient_scope", Json.parse(responses.last.body).get("error").asText());
        assertEquals("DENY", responses.last.responseHeaders.get("X-PDP-Decision"));
        assertEquals(responses.response, f.response.get());
        // A deny does not get its headers re-added in the response phase.
        rule.handleResponse(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS);
        verify(f.exchange, never()).getResponse();
    }

    @Test
    void theErrorCallbackFailsClosedWhenTheEngineFailedTheRuleItself() throws Exception {
        CapturingResponses responses = new CapturingResponses();
        AuthZenRule rule = new AuthZenRule(new FakeTransport(), DIRECT, responses, () -> 0L);
        Fixture f = new Fixture("GET", "/x", fields(), null, null);
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals(500, responses.last.status);
        assertEquals("pingaccess-pep", Json.parse(responses.last.body).get("pep").asText());
        rule.configure(conf());
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals("rule-pep", Json.parse(responses.last.body).get("pep").asText());
        // A parked permit is not a deny: the callback still writes the generic one.
        f.props.put(AuthZenRule.VERDICT, Verdict.permit(Map.of(), Map.of()));
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals(500, responses.last.status);
    }

    @Test
    void failsClosedBeforeConfigureWhenSaturatedAndWhenThePipelineThrows() throws Exception {
        CapturingResponses responses = new CapturingResponses();
        AuthZenRule unconfigured = new AuthZenRule(new FakeTransport(), DIRECT, responses, () -> 0L);
        Fixture f = new Fixture("GET", "/x", fields(), null, null);
        assertEquals(Outcome.RETURN, unconfigured.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        unconfigured.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals(500, responses.last.status);
        assertTrue(Json.parse(responses.last.body).get("reason").asText().contains("not configured"));

        Executor rejecting = r -> {
            throw new RejectedExecutionException("full");
        };
        AuthZenRule saturated = new AuthZenRule(new FakeTransport(), rejecting, responses, () -> 0L);
        saturated.configure(conf());
        Fixture g = new Fixture("GET", "/x", fields(), null, null);
        assertEquals(Outcome.RETURN, saturated.handleRequest(g.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        saturated.getErrorHandlingCallback().writeErrorResponse(g.exchange);
        assertEquals(503, responses.last.status);
        assertTrue(Json.parse(responses.last.body).get("reason").asText().contains("saturated"));

        // A transport that throws something other than IOException is a bug, and a deny.
        Transport broken = r -> {
            throw new IllegalStateException("boom");
        };
        AuthZenRule failing = new AuthZenRule(broken, DIRECT, responses, () -> 0L);
        failing.configure(conf());
        Fixture h = new Fixture("GET", "/x", fields("authorization", "Bearer " + jwt(obj("sub", "alice"))), null, null);
        assertEquals(Outcome.RETURN, failing.handleRequest(h.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        failing.getErrorHandlingCallback().writeErrorResponse(h.exchange);
        assertEquals(500, responses.last.status);

        // If parking the verdict itself fails, the stage fails and the engine sees it.
        AuthZenRule ok = new AuthZenRule(new FakeTransport().route("http://pdp:8080", obj("decision", true)), DIRECT, responses, () -> 0L);
        ok.configure(conf());
        Exchange hostile = mock(Exchange.class);
        Request req = mock(Request.class);
        when(hostile.getRequest()).thenReturn(req);
        when(req.getMethod()).thenReturn(Method.GET);
        when(req.getUri()).thenReturn("/x");
        org.mockito.Mockito.doThrow(new IllegalStateException("no")).when(hostile).setProperty(any(), any());
        CompletableFuture<Outcome> out = ok.handleRequest(hostile).toCompletableFuture();
        assertTrue(out.isCompletedExceptionally());
    }

    @Test
    void runsOnItsOwnWorkersAndTheSharedPoolIsBounded() throws Exception {
        ExecutorService pool = AuthZenRule.newExecutor(2);
        try {
            FakeTransport t = new FakeTransport().route("http://pdp:8080", obj("decision", true));
            AuthZenRule rule = new AuthZenRule(t, pool, new CapturingResponses(), () -> 0L);
            rule.configure(conf());
            Fixture f = new Fixture("GET", "/x", fields("authorization", "Bearer " + jwt(obj("sub", "alice"))), null, null);
            assertEquals(Outcome.CONTINUE, rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
            AuthZenRule real = new AuthZenRule();
            assertNotNull(real);
        } finally {
            pool.shutdownNow();
        }
    }

    // ---------- reading the exchange ----------

    @Test
    void readsMethodPathHeadersBodyAndIdentityOffTheExchange() throws Exception {
        AuthZenRule rule = new AuthZenRule(new FakeTransport(), DIRECT, new CapturingResponses(), () -> 0L);
        Identity id = mock(Identity.class);
        OAuthTokenMetadata md = mock(OAuthTokenMetadata.class);
        when(id.getAttributes()).thenReturn(obj("sub", "alice", "act", obj("sub", "agent-1")));
        when(id.getSubject()).thenReturn("ignored-because-attributes-have-sub");
        when(id.getOAuthTokenMetadata()).thenReturn(md);
        when(md.getClientId()).thenReturn("c9");
        when(md.getScopes()).thenReturn(Set.of("a"));
        Fixture f = new Fixture("POST", "/payments?q=1", fields("Authorization", "Bearer t", "X-User-Token", "u", "authorization", "second"),
            "{\"amount\":1}".getBytes(StandardCharsets.UTF_8), id);
        PepRequest r = rule.read(f.exchange);
        assertEquals("POST", r.method);
        assertEquals("/payments", r.path);
        assertEquals("Bearer t", r.header("authorization"), "the first value wins");
        assertEquals("u", r.header("x-user-token"));
        assertEquals("{\"amount\":1}", new String(r.body, StandardCharsets.UTF_8));
        assertEquals("alice", r.identityClaims.get("sub").asText());
        assertEquals("agent-1", r.identityClaims.get("act").get("sub").asText());
        assertEquals("c9", r.identityClaims.get("client_id").asText());
        assertEquals("a", r.identityClaims.get("scope").asText());

        // An unread body is read first; a body that cannot be read is treated as absent.
        Fixture g = new Fixture("POST", "/payments", fields(), null, null);
        when(g.body.isRead()).thenReturn(false);
        org.mockito.Mockito.doThrow(new java.io.IOException("gone")).when(g.body).read();
        assertNull(rule.read(g.exchange).body);
        Fixture h = new Fixture("POST", "/payments", fields(), null, null);
        when(h.body.isRead()).thenReturn(false);
        when(h.body.getContent()).thenReturn("x".getBytes(StandardCharsets.UTF_8));
        assertEquals("x", new String(rule.read(h.exchange).body, StandardCharsets.UTF_8));
        verify(h.body).read();

        // Nothing there at all.
        Exchange empty = mock(Exchange.class);
        Request req = mock(Request.class);
        when(empty.getRequest()).thenReturn(req);
        PepRequest e = rule.read(empty);
        assertEquals("", e.method);
        assertEquals("", e.path);
        assertNull(e.body);
        assertNull(e.identityClaims);
        assertTrue(e.headers.isEmpty());
        // Headers present but without fields.
        Headers hh = mock(Headers.class);
        when(req.getHeaders()).thenReturn(hh);
        assertTrue(rule.read(empty).headers.isEmpty());
    }

    @Test
    void identityClaimsFallBackToTheSubjectAndTokenMetadata() {
        assertNull(AuthZenRule.identityClaims(null));
        Identity id = mock(Identity.class);
        when(id.getAttributes()).thenReturn(null);
        when(id.getSubject()).thenReturn("bob");
        when(id.getOAuthTokenMetadata()).thenReturn(null);
        ObjectNode c = AuthZenRule.identityClaims(id);
        assertEquals("bob", c.get("sub").asText());
        assertFalse(c.has("client_id"));
        // Attributes that already say scp keep it; metadata does not override.
        Identity id2 = mock(Identity.class);
        OAuthTokenMetadata md = mock(OAuthTokenMetadata.class);
        when(id2.getAttributes()).thenReturn(obj("scp", "x", "client_id", "own"));
        when(id2.getOAuthTokenMetadata()).thenReturn(md);
        when(md.getClientId()).thenReturn("c9");
        when(md.getScopes()).thenReturn(Set.of("a"));
        ObjectNode c2 = AuthZenRule.identityClaims(id2);
        assertEquals("own", c2.get("client_id").asText());
        assertFalse(c2.has("scope"));
        assertFalse(c2.has("sub"));
        // Empty metadata adds nothing.
        Identity id3 = mock(Identity.class);
        OAuthTokenMetadata md3 = mock(OAuthTokenMetadata.class);
        when(id3.getAttributes()).thenReturn(obj());
        when(id3.getOAuthTokenMetadata()).thenReturn(md3);
        when(md3.getScopes()).thenReturn(Set.of());
        assertEquals(0, AuthZenRule.identityClaims(id3).size());
    }

    @Test
    void verdictHelpers() {
        Verdict v = Verdict.respond(401, Map.of("Content-Type", "application/json", "WWW-Authenticate", "Bearer"), null, null);
        assertEquals("application/json", v.header("content-type"));
        assertNull(v.header("x-missing"));
        assertEquals("", v.bodyText());
        assertTrue(v.upstreamHeaders.isEmpty());
        ArgumentCaptor<String> unused = ArgumentCaptor.forClass(String.class);
        assertNotNull(unused);
    }
}

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
import static org.junit.jupiter.api.Assertions.assertNotSame;
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
                when(body.isInMemory()).thenReturn(true);
                when(body.getLength()).thenReturn(content == null ? 0 : content.length);
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

    /** The demo's posture: a plain-http PDP with a key, unsigned tokens on an unprotected application. */
    static AuthZenRuleConfiguration conf() {
        AuthZenRuleConfiguration c = new AuthZenRuleConfiguration();
        c.authzen_url = "http://pdp:8080";
        c.authzen_api_key = "k";
        c.pep_label = "rule-pep";
        c.allow_insecure = true;
        return c;
    }

    /** A configuration fit to run without the escape hatch. */
    static AuthZenRuleConfiguration secure() {
        AuthZenRuleConfiguration c = new AuthZenRuleConfiguration();
        c.authzen_url = "https://pdp.example";
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

    static ValidationException refused(AuthZenRuleConfiguration c) {
        return assertThrows(ValidationException.class, () -> AuthZenRule.validate(c));
    }

    @Test
    void validatesTheConfigurationAtConfigureTime() {
        AuthZenRule.validate(conf());
        AuthZenRule.validate(secure());

        AuthZenRuleConfiguration noUrl = conf();
        noUrl.authzen_url = "";
        refused(noUrl);
        AuthZenRuleConfiguration style = conf();
        style.style = "soap";
        refused(style);
        AuthZenRuleConfiguration disc = conf();
        disc.pdp_discovery = "federation";
        refused(disc);
        AuthZenRuleConfiguration fail = conf();
        fail.fail_mode = "maybe";
        refused(fail);
        AuthZenRuleConfiguration ttl = conf();
        ttl.pdp_metadata_ttl = 0;
        refused(ttl);
        for (int[] t : new int[][]{{0, 1}, {1, 0}}) {
            AuthZenRuleConfiguration timeouts = conf();
            timeouts.pdp_timeout_ms = t[0];
            timeouts.coaz_timeout_ms = t[1];
            assertTrue(refused(timeouts).getMessage().contains("timeout"));
        }
        AuthZenRuleConfiguration layers = conf();
        layers.pdp_layers = List.of("resource maybe");
        assertTrue(refused(layers).getMessage().contains("pdp_layers"));
        AuthZenRuleConfiguration nullLayers = conf();
        nullLayers.pdp_layers = null;
        AuthZenRule.validate(nullLayers);

        // require_dpop needs somewhere to verify the proof.
        AuthZenRuleConfiguration dpop = conf();
        dpop.require_dpop = true;
        assertTrue(refused(dpop).getMessage().contains("coaz_url"));
        dpop.coaz_url = "http://coaz-pep:9192";
        AuthZenRule.validate(dpop);
    }

    @Test
    void aJsonNullForAnEnumIsARefusalNotANullPointerException() {
        // PingAccess binds a JSON null onto the field, and Set.of(...).contains(null) throws.
        AuthZenRuleConfiguration style = conf();
        style.style = null;
        assertTrue(refused(style).getMessage().contains("style"));
        AuthZenRuleConfiguration disc = conf();
        disc.pdp_discovery = null;
        assertTrue(refused(disc).getMessage().contains("pdp_discovery"));
        AuthZenRuleConfiguration fail = conf();
        fail.fail_mode = null;
        assertTrue(refused(fail).getMessage().contains("fail_mode"));
    }

    @Test
    void everyUrlMustBeOneTheRuleCanCall() {
        String[][] cases = {
            {"authzen_url", "http://authzen_pdp:8080"}, {"authzen_url", "pdp:8080"}, {"authzen_url", "ftp://pdp.example"},
            {"authzen_url", "https://pdp.example/?tenant=a"}, {"coaz_url", "coaz-pep:9192"}, {"mcp_upstream_url", "mcp"},
            {"federation_entity_url", "http://coaz_pep:9192"}, {"resource", "https://api.example/#x"},
            {"user_token_jwks_url", "/jwks"}, {"pdp_allowlist", "pdp.example"}, {"resource_metadata_allowlist", "https://u:p@api.example"},
            {"pdp_allowlist", ""}, {"pdp_layers", "http://estate_pdp:8080 fail-open"},
        };
        for (String[] c : cases) {
            AuthZenRuleConfiguration conf = conf();
            switch (c[0]) {
                case "authzen_url" -> conf.authzen_url = c[1];
                case "coaz_url" -> conf.coaz_url = c[1];
                case "mcp_upstream_url" -> conf.mcp_upstream_url = c[1];
                case "federation_entity_url" -> conf.federation_entity_url = c[1];
                case "resource" -> conf.resource = c[1];
                case "user_token_jwks_url" -> conf.user_token_jwks_url = c[1];
                case "pdp_allowlist" -> conf.pdp_allowlist = java.util.Arrays.asList(c[1]);
                case "resource_metadata_allowlist" -> conf.resource_metadata_allowlist = List.of(c[1]);
                default -> conf.pdp_layers = List.of(c[1]);
            }
            ValidationException e = refused(conf);
            assertTrue(e.getMessage().startsWith(c[0]), c[0] + " " + c[1] + ": " + e.getMessage());
        }
        AuthZenRuleConfiguration nullEntry = conf();
        nullEntry.pdp_allowlist = java.util.Arrays.asList((String) null);
        assertTrue(refused(nullEntry).getMessage().contains("empty entry"));
        // Endpoints may carry a path and a query; lists may be null.
        AuthZenRuleConfiguration ok = conf();
        ok.coaz_url = "https://coaz-pep.internal:9192";
        ok.coaz_api_key = "s";
        ok.mcp_upstream_url = "https://mcp.internal/mcp?v=1";
        ok.pdp_allowlist = null;
        ok.resource_metadata_allowlist = null;
        ok.pdp_layers = List.of("https://estate.example/tenant fail-open", "static", "resource");
        AuthZenRule.validate(ok);
    }

    @Test
    void anMcpRouteWithoutCoazPepIsAConfigurationErrorEvenWithTheEscapeHatch() {
        AuthZenRuleConfiguration c = conf();
        c.style = "mcp";
        assertTrue(refused(c).getMessage().contains("coaz_url"));
        c.coaz_url = "http://coaz-pep:9192";
        AuthZenRule.validate(c);
    }

    @Test
    void anInsecureSettingIsRefusedUnlessAllowInsecureSaysOtherwise() {
        java.util.Map<String, java.util.function.Consumer<AuthZenRuleConfiguration>> cases = new java.util.LinkedHashMap<>();
        cases.put("require_user_login without user_token_jwks_url", c -> c.require_user_login = true);
        cases.put("without user_token_audience", c -> c.user_token_jwks_url = "https://as.example/jwks");
        cases.put("user_token_jwks_url is not https", c -> {
            c.user_token_jwks_url = "http://as.example/jwks";
            c.user_token_audience = "https://api.example";
        });
        cases.put("authzen_api_key would be sent over plain http", c -> c.authzen_url = "http://pdp.example");
        cases.put("coaz_url without coaz_api_key", c -> c.coaz_url = "https://coaz-pep.example");
        cases.put("coaz_api_key would be sent over plain http", c -> {
            c.coaz_url = "http://coaz-pep.example";
            c.coaz_api_key = "s";
        });
        cases.put("forward_access_token would send the access token over plain http", c -> {
            c.authzen_url = "http://pdp.example";
            c.authzen_api_key = "";
            c.forward_access_token = true;
        });
        cases.put("pdp_allowlist is empty", c -> c.pdp_discovery = "resource");
        cases.put("so a resource could name any PDP", c -> {
            c.pdp_discovery = "authzen";
            c.pdp_allowlist = null;
        });
        cases.put("pdp_discovery_insecure", c -> c.pdp_discovery_insecure = true);
        cases.put("pdp_ssl_verify is off", c -> c.pdp_ssl_verify = false);
        for (java.util.Map.Entry<String, java.util.function.Consumer<AuthZenRuleConfiguration>> e : cases.entrySet()) {
            AuthZenRuleConfiguration c = secure();
            e.getValue().accept(c);
            ValidationException x = refused(c);
            assertTrue(x.getMessage().contains(e.getKey()), e.getKey() + ": " + x.getMessage());
            assertTrue(x.getMessage().contains("allow_insecure"), "the refusal names the escape hatch");
            c.allow_insecure = true;
            AuthZenRule.validate(c);
        }
        // What is fit to run needs nothing.
        AuthZenRuleConfiguration ok = secure();
        ok.pdp_discovery = "resource";
        ok.pdp_allowlist = List.of("https://pdp.example");
        ok.require_user_login = true;
        ok.user_token_jwks_url = "https://as.example/jwks";
        ok.user_token_audience = "https://api.example";
        ok.coaz_url = "https://coaz-pep.example";
        ok.coaz_api_key = "s";
        ok.forward_access_token = true;
        assertTrue(AuthZenRule.insecurities(ok).isEmpty(), String.valueOf(AuthZenRule.insecurities(ok)));
        AuthZenRule.validate(ok);
        // A key with nowhere to send it is not a key sent over http.
        AuthZenRuleConfiguration keyOnly = secure();
        keyOnly.coaz_api_key = "s";
        assertTrue(AuthZenRule.insecurities(keyOnly).isEmpty());
        assertFalse(new AuthZenRuleConfiguration().allow_insecure, "the escape hatch is off unless set");
        assertTrue(new AuthZenRuleConfiguration().coaz_defaults, "the binding's default table is on unless turned off");
    }

    @Test
    void configureWithTheEscapeHatchStillBuildsAWorkingRule() throws Exception {
        AuthZenRule rule = new AuthZenRule(new FakeTransport(), DIRECT, new CapturingResponses(), () -> 0L);
        AuthZenRuleConfiguration c = conf();
        c.pdp_ssl_verify = false;
        c.pdp_discovery_insecure = true;
        rule.configure(c);
        assertEquals(c, rule.getConfiguration());
        // A refused configuration leaves the rule unconfigured: every request is a 500 deny.
        AuthZenRule fresh = new AuthZenRule(new FakeTransport(), DIRECT, new CapturingResponses(), () -> 0L);
        AuthZenRuleConfiguration insecureTls = secure();
        insecureTls.pdp_ssl_verify = false;
        assertThrows(ValidationException.class, () -> fresh.configure(insecureTls));
        assertNull(fresh.getConfiguration(), "validated before it is taken");
        Fixture f = new Fixture("GET", "/x", fields(), null, null);
        assertEquals(Outcome.RETURN, fresh.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
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
        c.pdp_ssl_verify = false; // allowed under allow_insecure, and logged
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
            "fail_mode", "user_token_jwks_url", "user_token_issuer", "user_token_audience", "allow_insecure"}) {
            assertTrue(names.contains(knob), knob);
        }
        // With a JWKS, the user token is verified; without one it is ignored, or decoded
        // under allow_insecure. Each is a configuration the rule accepts.
        AuthZenRuleConfiguration verified = secure();
        verified.user_token_jwks_url = "https://as.example/jwks";
        verified.user_token_audience = "https://api.example";
        rule.configure(verified);
        rule.configure(secure());
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
    void runsOnItsOwnWorkersAndEachRuleHasItsOwnBoundedPool() throws Exception {
        ExecutorService pool = AuthZenRule.newExecutor(2);
        try {
            FakeTransport t = new FakeTransport().route("http://pdp:8080", obj("decision", true));
            AuthZenRule rule = new AuthZenRule(t, pool, new CapturingResponses(), () -> 0L);
            rule.configure(conf());
            Fixture f = new Fixture("GET", "/x", fields("authorization", "Bearer " + jwt(obj("sub", "alice"))), null, null);
            assertEquals(Outcome.CONTINUE, rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        // Two rules, two pools: one rule's stuck PDP cannot starve the other.
        AuthZenRule a = new AuthZenRule();
        AuthZenRule b = new AuthZenRule();
        assertNotSame(a.executor(), b.executor());
        java.util.concurrent.ThreadPoolExecutor ex = (java.util.concurrent.ThreadPoolExecutor) a.executor();
        assertEquals(AuthZenRule.THREADS_PER_RULE, ex.getMaximumPoolSize());
        assertEquals(256, ex.getQueue().remainingCapacity());
        assertTrue(ex.allowsCoreThreadTimeOut(), "an idle rule holds no threads");
    }

    @Test
    void aStuckPdpBehindOneRuleDoesNotStarveAnother() throws Exception {
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        FakeTransport stuck = new FakeTransport().route("http://pdp:8080", (java.util.function.Function<Transport.Request, Transport.Response>) r -> {
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return FakeTransport.json(200, obj("decision", true));
        });
        ExecutorService onePool = AuthZenRule.newExecutor(1);
        ExecutorService otherPool = AuthZenRule.newExecutor(1);
        try {
            AuthZenRule slow = new AuthZenRule(stuck, onePool, new CapturingResponses(), () -> 0L);
            slow.configure(conf());
            AuthZenRule fine = new AuthZenRule(new FakeTransport().route("http://pdp:8080", obj("decision", true)), otherPool, new CapturingResponses(), () -> 0L);
            fine.configure(conf());
            List<HeaderField> auth = fields("authorization", "Bearer " + jwt(obj("sub", "alice")));
            CompletableFuture<Outcome> held = slow.handleRequest(new Fixture("GET", "/x", auth, null, null).exchange).toCompletableFuture();
            assertEquals(Outcome.CONTINUE, fine.handleRequest(new Fixture("GET", "/x", auth, null, null).exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
            assertFalse(held.isDone());
            release.countDown();
            assertEquals(Outcome.CONTINUE, held.get(5, TimeUnit.SECONDS));
        } finally {
            release.countDown();
            onePool.shutdownNow();
            otherPool.shutdownNow();
        }
    }

    @Test
    void anErrorAnywhereStillAnswersTheRequest() throws Exception {
        CapturingResponses responses = new CapturingResponses();
        List<HeaderField> auth = fields("authorization", "Bearer " + jwt(obj("sub", "alice")));
        // An Error from deep in the pipeline: a 500 deny, not a stage that never completes.
        Transport erroring = r -> {
            throw new AssertionError("boom");
        };
        AuthZenRule rule = new AuthZenRule(erroring, DIRECT, responses, () -> 0L);
        rule.configure(conf());
        Fixture f = new Fixture("GET", "/x", auth, null, null);
        CompletableFuture<Outcome> out = rule.handleRequest(f.exchange).toCompletableFuture();
        assertEquals(Outcome.RETURN, out.get(5, TimeUnit.SECONDS));
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals(500, responses.last.status);
        // An Error from the pool itself (no thread to be had).
        Executor noThreads = r -> {
            throw new OutOfMemoryError("unable to create native thread");
        };
        AuthZenRule starved = new AuthZenRule(new FakeTransport(), noThreads, responses, () -> 0L);
        starved.configure(conf());
        Fixture g = new Fixture("GET", "/x", auth, null, null);
        assertEquals(Outcome.RETURN, starved.handleRequest(g.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        starved.getErrorHandlingCallback().writeErrorResponse(g.exchange);
        assertEquals(500, responses.last.status);
        // An exchange that cannot even be read.
        Fixture h = new Fixture("GET", "/x", auth, null, null);
        when(h.request.getHeaders()).thenThrow(new IllegalStateException("gone"));
        assertEquals(Outcome.RETURN, rule.handleRequest(h.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
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

        assertTrue(r.bodyReadable);
        // A header sent twice keeps both values: Content-Encoding is checked on all of them.
        assertEquals(List.of("Bearer t", "second"), r.headerValues("Authorization"));

        // An unread body is read first; a body that cannot be read is not a body at all.
        Fixture g = new Fixture("POST", "/payments", fields(), null, null);
        when(g.body.isRead()).thenReturn(false);
        org.mockito.Mockito.doThrow(new java.io.IOException("gone")).when(g.body).read();
        PepRequest gr = rule.read(g.exchange);
        assertNull(gr.body);
        assertFalse(gr.bodyReadable, "a read error is a partial body, never an empty one");
        Fixture h = new Fixture("POST", "/payments", fields(), null, null);
        when(h.body.isRead()).thenReturn(false);
        when(h.body.getContent()).thenReturn("x".getBytes(StandardCharsets.UTF_8));
        when(h.body.getLength()).thenReturn(1);
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
        assertTrue(e.bodyReadable, "no body is not a partial body");
        assertNull(e.identityClaims);
        assertTrue(e.headers.isEmpty());
        // Headers present but without fields.
        Headers hh = mock(Headers.class);
        when(req.getHeaders()).thenReturn(hh);
        assertTrue(rule.read(empty).headers.isEmpty());
    }

    @Test
    void aPepRequestToleratesWhatAnExchangeMightNotHave() {
        java.util.Map<String, List<String>> odd = new java.util.LinkedHashMap<>();
        odd.put(null, List.of("x"));
        odd.put("X-Null", null);
        odd.put("X-Values", java.util.Arrays.asList("a", null, "b"));
        PepRequest r = new PepRequest(null, null, odd, null, true, null);
        assertEquals("", r.method);
        assertEquals("", r.path);
        assertEquals(List.of("a", "b"), r.headerValues("x-values"));
        assertEquals("a", r.header("X-VALUES"));
        assertTrue(r.headerValues("x-null").isEmpty());
        assertTrue(new PepRequest("GET", "/", (java.util.Map<String, List<String>>) null, null, true, null).headers.isEmpty());
        assertTrue(new PepRequest("GET", "/", (java.util.Map<String, String>) null, null, null).headers.isEmpty());
        // A body marked unreadable is never kept, whatever was passed.
        assertNull(new PepRequest("POST", "/", java.util.Map.<String, List<String>>of(), new byte[]{1}, false, null).body);
    }

    @Test
    void aBodyNotReadInFullIsNeverPassedOffAsTheBody() throws Exception {
        AuthZenRule rule = new AuthZenRule(new FakeTransport(), DIRECT, new CapturingResponses(), () -> 0L);
        byte[] call = "{\"method\":\"ping\"}".getBytes(StandardCharsets.UTF_8);
        // Not held in memory, or shorter than PingAccess says it is.
        Fixture spilled = new Fixture("POST", "/mcp", fields(), call, null);
        when(spilled.body.isInMemory()).thenReturn(false);
        assertFalse(rule.read(spilled.exchange).bodyReadable);
        Fixture shortened = new Fixture("POST", "/mcp", fields(), call, null);
        when(shortened.body.getLength()).thenReturn(call.length + 100);
        assertFalse(rule.read(shortened.exchange).bodyReadable);
        // Shorter than the client declared it.
        Fixture declared = new Fixture("POST", "/mcp", fields("Content-Length", String.valueOf(call.length + 100)), call, null);
        assertFalse(rule.read(declared.exchange).bodyReadable);
        Fixture garbled = new Fixture("POST", "/mcp", fields("Content-Length", "lots"), call, null);
        assertFalse(rule.read(garbled.exchange).bodyReadable);
        Fixture honest = new Fixture("POST", "/mcp", fields("content-length", " " + call.length + " "), call, null);
        assertTrue(rule.read(honest.exchange).bodyReadable);
        // An unknown length is fine when the declared one matches, or there is none.
        Fixture unknown = new Fixture("POST", "/mcp", fields(), call, null);
        when(unknown.body.getLength()).thenReturn(-1);
        assertTrue(rule.read(unknown.exchange).bodyReadable);
        // Over the rule's own cap.
        byte[] big = new byte[PepRequest.MAX_BODY + 1];
        Fixture huge = new Fixture("POST", "/mcp", fields(), big, null);
        assertFalse(rule.read(huge.exchange).bodyReadable);
        // An empty body that is empty all the way through is readable, and empty.
        Fixture none = new Fixture("GET", "/mcp", fields("Content-Length", "0"), new byte[0], null);
        PepRequest n = rule.read(none.exchange);
        assertTrue(n.bodyReadable);
        assertEquals(0, n.body.length);
        // A body PingAccess never produced, though one was declared.
        Fixture missing = new Fixture("POST", "/mcp", fields("Content-Length", "10"), null, null);
        when(missing.request.getBody()).thenReturn(null);
        assertFalse(rule.read(missing.exchange).bodyReadable);
    }

    @Test
    void theReviewersProbeABatchedToolsCallIsRefusedAndNothingIsAsked() throws Exception {
        FakeTransport t = new FakeTransport().route("http://coaz-pep:9192", obj("decision", true)).route("http://pdp:8080", obj("decision", true));
        CapturingResponses responses = new CapturingResponses();
        AuthZenRule rule = new AuthZenRule(t, DIRECT, responses, () -> 0L);
        AuthZenRuleConfiguration c = conf();
        c.style = "mcp";
        c.coaz_url = "http://coaz-pep:9192";
        rule.configure(c);
        byte[] batch = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"make_payment\"}}]".getBytes(StandardCharsets.UTF_8);
        Fixture f = new Fixture("POST", "/mcp", fields("Authorization", "Bearer " + jwt(obj("sub", "alice"))), batch, null);
        assertEquals(Outcome.RETURN, rule.handleRequest(f.exchange).toCompletableFuture().get(5, TimeUnit.SECONDS));
        rule.getErrorHandlingCallback().writeErrorResponse(f.exchange);
        assertEquals(400, responses.last.status);
        assertEquals(-32600, Json.parse(responses.last.body).get("error").get("code").intValue());
        assertEquals(0, t.hits.size(), "neither coaz-pep nor the PDP was asked");
        assertFalse(f.setHeaders.containsKey("X-Auth-Principal"));
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

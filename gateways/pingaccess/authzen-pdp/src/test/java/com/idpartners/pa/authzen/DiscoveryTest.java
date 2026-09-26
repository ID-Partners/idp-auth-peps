package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.idpartners.pa.authzen.FakeTransport.obj;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PDP discovery: resource -> PDP -> endpoints, against the scripted transport. Mirrors
 * the Kong and Go discovery suites so the three PEPs agree on every rule.
 */
class DiscoveryTest {
    static final String STATIC = "https://static.example";
    static final String GOOD = "https://good.example";
    static final String ROGUE = "https://rogue.example";
    static final String RES = "https://api.example";
    static final String ESTATE = "https://estate.example";

    /** A settable clock, in seconds. */
    static final class Clock {
        long now = 1_000_000;
    }

    static ObjectNode pdpConfig(String self, String eval, String evals) {
        ObjectNode o = obj("policy_decision_point", self, "access_evaluation_endpoint", eval == null ? self + "/custom/eval" : eval);
        if (evals != null) {
            o.put("access_evaluations_endpoint", evals);
        }
        o.putArray("capabilities").add("urn:x:batch");
        return o;
    }

    static ObjectNode pdpConfig(String self) {
        return pdpConfig(self, null, null);
    }

    static AuthZenRuleConfiguration conf() {
        AuthZenRuleConfiguration c = new AuthZenRuleConfiguration();
        c.authzen_url = STATIC;
        c.authzen_api_key = "static-key";
        c.pdp_discovery = "resource";
        c.pdp_metadata_ttl = 300;
        return c;
    }

    static FakeTransport resourceRoutes() {
        ObjectNode doc = obj("resource", RES, "ignored", true);
        doc.putArray(Discovery.PARAM).add(GOOD + "/");
        return new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", doc)
            .route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD))
            .route(ROGUE + "/.well-known/authzen-configuration", pdpConfig(ROGUE));
    }

    static ObjectNode resourceDoc(String... pdps) {
        ObjectNode doc = obj("resource", RES);
        var arr = doc.putArray(Discovery.PARAM);
        for (String p : pdps) {
            arr.add(p);
        }
        return doc;
    }

    private static Discovery discovery(FakeTransport t, Clock clock) {
        return new Discovery(t, () -> clock.now);
    }

    private static Discovery discovery(FakeTransport t) {
        return discovery(t, new Clock());
    }

    // ---------- URLs ----------

    @Test
    void derivesWellKnownUrlsWithTheInsertionRule() throws Exception {
        Map<String, String> cases = Map.of(
            "https://pdp.example", "https://pdp.example/.well-known/authzen-configuration",
            "https://pdp.example/", "https://pdp.example/.well-known/authzen-configuration",
            "https://pdp.example/tenant1", "https://pdp.example/.well-known/authzen-configuration/tenant1",
            "https://pdp.example/t/1/", "https://pdp.example/.well-known/authzen-configuration/t/1",
            "https://PDP.example:8443/x", "https://pdp.example:8443/.well-known/authzen-configuration/x");
        for (Map.Entry<String, String> c : cases.entrySet()) {
            assertEquals(c.getValue(), Discovery.wellKnownUrl(c.getKey(), "authzen-configuration"));
        }
        for (String bad : new String[]{"pdp.example", "/relative", "https://pdp.example/?x=1", "https://pdp.example/#f", "https:///x", null}) {
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> Discovery.wellKnownUrl(bad, "authzen-configuration"), String.valueOf(bad));
            assertEquals(Discovery.Kind.INVALID, f.kind);
        }
    }

    @Test
    void matchesAllowlistPrefixesOnlyAtAPathBoundary() {
        List<String> list = List.of("https://a.example/mcp", "https://b.example/");
        assertTrue(Discovery.allowed(list, "https://a.example/mcp"));
        assertTrue(Discovery.allowed(list, "https://a.example/mcp/x"));
        assertFalse(Discovery.allowed(list, "https://a.example/mcpx"));
        assertFalse(Discovery.allowed(list, "https://a.example/"));
        assertTrue(Discovery.allowed(list, "https://b.example/anything"));
        assertFalse(Discovery.allowed(list, "http://a.example/mcp"));
        assertFalse(Discovery.allowed(list, "garbage"));
        assertTrue(Discovery.allowed(null, "https://x"));
        assertTrue(Discovery.allowed(List.of(), "https://x"));
        assertFalse(Discovery.allowed(List.of("not a url"), "https://x"));
    }

    @Test
    void appliesTheUrlPolicy() throws Exception {
        Discovery.Policy open = new Discovery.Policy(false, null, null, true, 5000);
        Discovery.checkUrl("https://ok.example/x", open);
        assertNotAllowed("http://ok.example/x", open);
        Discovery.checkUrl("http://ok.example/x", new Discovery.Policy(true, null, null, true, 5000));
        Discovery.checkUrl("http://pdp:8080/.well-known/x", new Discovery.Policy(false, "http://pdp:8080", null, true, 5000));
        assertNotAllowed("http://other:8080/x", new Discovery.Policy(false, "http://pdp:8080", null, true, 5000));
        assertNotAllowed("http://pdp:8080/x", new Discovery.Policy(false, "://bad", null, true, 5000));
        assertNotAllowed("ftp://ok.example/x", open);
        assertNotAllowed("/x", open);
        assertNotAllowed("https://no.example/x", new Discovery.Policy(false, null, List.of("https://ok.example"), true, 5000));
        Discovery.checkUrl("https://ok.example/x", new Discovery.Policy(false, null, List.of("https://ok.example"), true, 5000));
        // A URL the transport could not call is refused here, where the reason is clear.
        assertNotAllowed("http://authzen_pdp:8080/x", new Discovery.Policy(true, null, null, true, 5000));
        assertNotAllowed("https://user:pw@ok.example/x", open);
    }

    private static void assertNotAllowed(String url, Discovery.Policy p) {
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> Discovery.checkUrl(url, p), url);
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
    }

    @Test
    void picksTheResourceIdentifierForARoute() {
        AuthZenRuleConfiguration c = new AuthZenRuleConfiguration();
        c.resource = "https://api.example/";
        assertEquals("https://api.example", Discovery.resourceId(c));
        AuthZenRuleConfiguration m = new AuthZenRuleConfiguration();
        m.style = "mcp";
        m.mcp_upstream_url = "http://mcp:8090/mcp";
        assertEquals("http://mcp:8090/mcp", Discovery.resourceId(m));
        m.resource = "https://r";
        assertEquals("https://r", Discovery.resourceId(m));
        assertEquals("", Discovery.resourceId(new AuthZenRuleConfiguration()));
        AuthZenRuleConfiguration e = new AuthZenRuleConfiguration();
        e.style = "mcp";
        e.mcp_upstream_url = "";
        assertEquals("", Discovery.resourceId(e));
    }

    // ---------- off and authzen modes ----------

    @Test
    void offMakesNoRequestsAndKeepsTheStaticKey() throws Exception {
        FakeTransport t = new FakeTransport();
        AuthZenRuleConfiguration c = conf();
        c.pdp_discovery = "off";
        Discovery.Endpoints ep = discovery(t).resolve(c, "https://any");
        assertEquals(STATIC, ep.identifier);
        assertEquals(STATIC + "/access/v1/evaluation", ep.evaluation);
        assertEquals(STATIC + "/access/v1/evaluations", ep.evaluations);
        assertEquals("static-key", ep.apiKey);
        assertEquals("static", ep.source);
        assertNull(ep.resource);
        assertEquals(0, t.hits.size());
        c.authzen_url = "";
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, ""));
        assertEquals(Discovery.Kind.TRANSIENT, f.kind);
        // A null or empty mode is off.
        c.authzen_url = STATIC;
        c.pdp_discovery = null;
        assertEquals("static", discovery(t).resolve(c, "https://any").source);
    }

    @Test
    void authzenReadsTheStaticPdpMetadataOnceAndBindsTheKey() throws Exception {
        FakeTransport t = new FakeTransport().route(STATIC + "/.well-known/authzen-configuration", pdpConfig(STATIC, STATIC + "/custom/eval", STATIC + "/custom/evals"));
        Discovery d = discovery(t);
        AuthZenRuleConfiguration c = conf();
        c.pdp_discovery = "authzen";
        for (int i = 0; i < 2; i++) {
            Discovery.Endpoints ep = d.resolve(c, "https://ignored");
            assertEquals(STATIC + "/custom/eval", ep.evaluation);
            assertEquals(STATIC + "/custom/evals", ep.evaluations);
            assertEquals("static-key", ep.apiKey);
            assertEquals("urn:x:batch", ep.capabilities.get(0).asText());
        }
        assertEquals(1, t.hits.size());
        assertEquals("application/json", t.hits.get(0).headers().get("Accept"));
        c.authzen_url = "";
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, ""));
        assertEquals(Discovery.Kind.TRANSIENT, f.kind);
    }

    @Test
    void usesTheDefaultPathsOnlyWhenThePdpPublishesNothing() throws Exception {
        FakeTransport none = new FakeTransport().route(STATIC, 404);
        AuthZenRuleConfiguration c = conf();
        c.pdp_discovery = "authzen";
        assertEquals(STATIC + "/access/v1/evaluation", discovery(none).resolve(c, "").evaluation);
        // An outage is an outage, not "this PDP has no metadata": cached as the answer it
        // would stand in for the PDP's own endpoints for a whole TTL.
        for (Object r : new Object[]{500, 503, 429, Boolean.FALSE}) {
            FakeTransport t = new FakeTransport().route(STATIC, r);
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, ""), String.valueOf(r));
            assertEquals(Discovery.Kind.TRANSIENT, f.kind, String.valueOf(r));
        }
    }

    @Test
    void rejectsADocumentAboutAnotherPdpOrWithoutAnEvaluationEndpointOrNotJson() {
        Object[][] cases = {
            {pdpConfig("https://other.example"), "policy_decision_point"},
            {obj("policy_decision_point", STATIC), "access_evaluation_endpoint"},
            {"<html>", "not JSON"},
            {"[1,2]", "not JSON"},
        };
        for (Object[] c : cases) {
            FakeTransport t = new FakeTransport().route(STATIC + "/.well-known/authzen-configuration", c[0]);
            AuthZenRuleConfiguration conf = conf();
            conf.pdp_discovery = "authzen";
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(conf, ""));
            assertEquals(Discovery.Kind.REFUSED, f.kind, "every candidate answered, and none usably: a refusal, not an outage");
            assertTrue(f.getMessage().contains((String) c[1]), f.getMessage());
        }
    }

    @Test
    void aPdpMetadataBlipServesTheLastGoodEntryNotTheDefaults() throws Exception {
        for (Object blip : new Object[]{500, Boolean.FALSE, 302, "<html>"}) {
            FakeTransport t = resourceRoutes();
            Clock clock = new Clock();
            Discovery d = discovery(t, clock);
            assertEquals(GOOD + "/custom/eval", d.resolve(conf(), RES).evaluation);
            t.route(GOOD + "/.well-known/authzen-configuration", blip);
            clock.now += 301;
            assertEquals(GOOD + "/custom/eval", d.resolve(conf(), RES).evaluation, String.valueOf(blip));
        }
        // Cold, an outage fails the resolution rather than caching the default paths, and
        // is not retried on every request.
        FakeTransport cold = resourceRoutes().route(GOOD + "/.well-known/authzen-configuration", 503);
        Clock c2 = new Clock();
        Discovery d2 = discovery(cold, c2);
        assertThrows(Discovery.Failure.class, () -> d2.resolve(conf(), RES));
        int before = cold.count(GOOD);
        assertThrows(Discovery.Failure.class, () -> d2.resolve(conf(), RES));
        assertEquals(before, cold.count(GOOD), "negatively cached");
        cold.route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD));
        c2.now += Discovery.MIN_REFRESH + 1;
        assertEquals(GOOD + "/custom/eval", d2.resolve(conf(), RES).evaluation);
    }

    @Test
    void aRefreshRunsOutsideTheLockAndEveryoneElseGetsTheStaleValue() throws Exception {
        java.util.concurrent.CountDownLatch inFetch = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        FakeTransport t = resourceRoutes();
        Clock clock = new Clock();
        Discovery d = discovery(t, clock);
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
        t.route(RES + "/.well-known/oauth-protected-resource", (Function<Transport.Request, Transport.Response>) r -> {
            inFetch.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return FakeTransport.json(200, resourceDoc(GOOD));
        });
        clock.now += 301;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            java.util.concurrent.Future<String> refresher = pool.submit(() -> d.resolve(conf(), RES).identifier);
            assertTrue(inFetch.await(5, java.util.concurrent.TimeUnit.SECONDS));
            // The refresh is stuck on the network; this request is not stuck behind it.
            long t0 = System.nanoTime();
            assertEquals(GOOD, d.resolve(conf(), RES).identifier);
            assertTrue((System.nanoTime() - t0) / 1_000_000 < 1000, "served stale without waiting");
            release.countDown();
            assertEquals(GOOD, refresher.get(5, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void aColdFetchIsSharedByTheRequestsThatArriveWhileItRuns() throws Exception {
        java.util.concurrent.CountDownLatch inFetch = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger fetches = new java.util.concurrent.atomic.AtomicInteger();
        FakeTransport t = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", (Function<Transport.Request, Transport.Response>) r -> {
            fetches.incrementAndGet();
            inFetch.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return FakeTransport.json(200, resourceDoc(GOOD));
        });
        Discovery d = discovery(t);
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Future<String> first = pool.submit(() -> d.resolve(conf(), RES).identifier);
            assertTrue(inFetch.await(5, java.util.concurrent.TimeUnit.SECONDS));
            java.util.concurrent.Future<String> second = pool.submit(() -> d.resolve(conf(), RES).identifier);
            Thread.sleep(100);
            release.countDown();
            assertEquals(GOOD, first.get(5, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(GOOD, second.get(5, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(1, fetches.get(), "one fetch for both");
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
        // A waiter gets the fetch's failure, not a hang.
        java.util.concurrent.CountDownLatch in2 = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch rel2 = new java.util.concurrent.CountDownLatch(1);
        FakeTransport failing = resourceRoutes()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD))
            .route(GOOD + "/.well-known/authzen-configuration", (Function<Transport.Request, Transport.Response>) r -> {
                in2.countDown();
                try {
                    rel2.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return FakeTransport.json(200, "<html>");
            });
        AuthZenRuleConfiguration noStatic = conf();
        noStatic.authzen_url = "";
        Discovery d2 = discovery(failing);
        java.util.concurrent.ExecutorService pool2 = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Future<Object> a = pool2.submit(() -> d2.resolve(noStatic, RES));
            assertTrue(in2.await(5, java.util.concurrent.TimeUnit.SECONDS));
            java.util.concurrent.Future<Object> b = pool2.submit(() -> d2.resolve(noStatic, RES));
            Thread.sleep(100);
            rel2.countDown();
            for (java.util.concurrent.Future<Object> f : List.of(a, b)) {
                java.util.concurrent.ExecutionException x = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> f.get(5, java.util.concurrent.TimeUnit.SECONDS));
                assertTrue(x.getCause() instanceof Discovery.Failure);
            }
        } finally {
            rel2.countDown();
            pool2.shutdownNow();
        }
    }

    @Test
    void aWaiterGivesUpAfterItsBoundOrWhenInterrupted() throws Exception {
        java.util.concurrent.CountDownLatch inFetch = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        FakeTransport t = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", (Function<Transport.Request, Transport.Response>) r -> {
            inFetch.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return FakeTransport.json(200, resourceDoc(GOOD));
        });
        AuthZenRuleConfiguration noStatic = conf();
        noStatic.authzen_url = "";
        Discovery d = discovery(t);
        d.waitMs = 100;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            pool.submit(() -> d.resolve(noStatic, RES));
            assertTrue(inFetch.await(5, java.util.concurrent.TimeUnit.SECONDS));
            Discovery.Failure timedOut = assertThrows(Discovery.Failure.class, () -> d.resolve(noStatic, RES));
            assertEquals(Discovery.Kind.TRANSIENT, timedOut.kind);
            assertTrue(timedOut.getMessage().contains("timed out waiting"), timedOut.getMessage());
            d.waitMs = 5000;
            Thread.currentThread().interrupt();
            Discovery.Failure interrupted = assertThrows(Discovery.Failure.class, () -> d.resolve(noStatic, RES));
            assertEquals(Discovery.Kind.REFUSED, interrupted.kind, "not an outage, so never skipped");
            assertTrue(Thread.interrupted(), "the interrupt is kept");
        } finally {
            Thread.interrupted();
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void aPathBearingAllowlistEntryAdmitsItsOwnWellKnownDocument() throws Exception {
        String tenant = GOOD + "/tenants/bank-a";
        ObjectNode doc = obj("resource", RES + "/api");
        doc.putArray(Discovery.PARAM).add(tenant);
        FakeTransport t = new FakeTransport()
            .route("https://api.example/.well-known/oauth-protected-resource/api", doc)
            .route(GOOD + "/.well-known/authzen-configuration/tenants/bank-a", pdpConfig(tenant, tenant + "/eval", null));
        AuthZenRuleConfiguration c = conf();
        c.pdp_allowlist = List.of(tenant);
        c.resource_metadata_allowlist = List.of(RES + "/api");
        Discovery.Endpoints ep = discovery(t).resolve(c, RES + "/api");
        assertEquals(tenant, ep.identifier);
        assertEquals(tenant + "/eval", ep.evaluation);
        // The identifiers themselves are still held to the lists.
        c.pdp_allowlist = List.of(GOOD + "/tenants/bank-b");
        assertEquals(Discovery.Kind.NOT_ALLOWED, assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, RES + "/api")).kind);
    }

    @Test
    void aFetchThatThrowsSomethingUnexpectedFreesItsEntry() throws Exception {
        FakeTransport t = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", (Function<Transport.Request, Transport.Response>) r -> {
            throw new IllegalStateException("bug");
        });
        Discovery d = discovery(t);
        assertThrows(IllegalStateException.class, () -> d.resolve(conf(), RES));
        assertNull(d.resourceEntry(RES).inflight, "the next request may fetch");
        t.route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD));
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
    }

    @Test
    void refusesAnAdvertisedEndpointOutsideTheAllowlist() {
        FakeTransport t = new FakeTransport().route(STATIC + "/.well-known/authzen-configuration", pdpConfig(STATIC, STATIC + "/eval", "https://elsewhere.example/evals"));
        AuthZenRuleConfiguration c = conf();
        c.pdp_discovery = "authzen";
        c.pdp_allowlist = List.of("https://pdp.example");
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, ""));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
    }

    @Test
    void trustsTheStaticPdpOverHttpOnItsOwnOriginAndNothingElse() throws Exception {
        FakeTransport t = new FakeTransport().route("http://pdp:8080/.well-known/authzen-configuration", pdpConfig("http://pdp:8080", "http://pdp:8080/eval", "http://other:8080/evals"));
        AuthZenRuleConfiguration c = conf();
        c.pdp_discovery = "authzen";
        c.authzen_url = "http://pdp:8080/";
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, ""));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
        c.pdp_discovery_insecure = true;
        assertEquals("http://other:8080/evals", discovery(t).resolve(c, "").evaluations);
    }

    @Test
    void aRedirectAnAnswerOverTheCapOrNoBodyIsARefusalNotTheDefaultPaths() {
        byte[] big = new byte[Discovery.MAX_BODY + 1];
        Object[] responders = {
            302,
            403,
            new Transport.Refused("cannot be built"),
            (Function<Transport.Request, Transport.Response>) r -> new Transport.Response(200, Map.of(), big),
            (Function<Transport.Request, Transport.Response>) r -> new Transport.Response(200, Map.of(), null),
        };
        for (Object r : responders) {
            FakeTransport t = new FakeTransport().route(STATIC, r);
            AuthZenRuleConfiguration c = conf();
            c.pdp_discovery = "authzen";
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, ""), String.valueOf(r));
            assertEquals(Discovery.Kind.REFUSED, f.kind, String.valueOf(r));
            assertEquals(Discovery.MAX_BODY, t.hits.get(0).maxResponseBytes(), "metadata is read under its own cap");
        }
    }

    @Test
    void aResourceMetadataFetchThatFailsNeverReplacesTheLastGoodList() throws Exception {
        Map<Object, Discovery.Kind> blips = Map.<Object, Discovery.Kind>of(
            500, Discovery.Kind.TRANSIENT, Boolean.FALSE, Discovery.Kind.TRANSIENT,
            403, Discovery.Kind.REFUSED, 302, Discovery.Kind.REFUSED, "<html>", Discovery.Kind.INVALID);
        for (Map.Entry<Object, Discovery.Kind> blip : blips.entrySet()) {
            String name = String.valueOf(blip.getKey());
            FakeTransport t = resourceRoutes();
            Clock clock = new Clock();
            Discovery d = discovery(t, clock);
            assertEquals(GOOD, d.resolve(conf(), RES).identifier);
            t.route(RES + "/.well-known/oauth-protected-resource", blip.getKey());
            clock.now += 301;
            assertEquals(GOOD, d.resolve(conf(), RES).identifier, name);
            // Cold, with nothing stale to serve, the resource's layer is unavailable. It is
            // never the static PDP's, and the failure is not cached as the answer.
            FakeTransport cold = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", blip.getKey());
            Discovery dc = discovery(cold);
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> dc.resolve(conf(), RES), name);
            assertEquals(blip.getValue(), f.kind, name);
            assertTrue(f.getMessage().contains("unavailable and none is cached"), f.getMessage());
            assertFalse(dc.resourceEntry(RES).ok, name);
            assertEquals(0, cold.count(STATIC), name + ": the static PDP does not stand in");
        }
    }

    @Test
    void theLastGoodListIsServedForOneMoreTtlAndNoLonger() throws Exception {
        FakeTransport t = resourceRoutes();
        Clock clock = new Clock();
        Discovery d = discovery(t, clock);
        long start = clock.now;
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
        t.route(RES + "/.well-known/oauth-protected-resource", 503);
        clock.now = start + 301;
        assertEquals(GOOD, d.resolve(conf(), RES).identifier, "stale, past the TTL");
        clock.now = start + 599;
        assertEquals(GOOD, d.resolve(conf(), RES).identifier, "stale, just inside one more TTL");
        clock.now = start + 600;
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> d.resolve(conf(), RES));
        assertEquals(Discovery.Kind.TRANSIENT, f.kind);
        assertFalse(d.resourceEntry(RES).ok, "the stale list is gone, not parked");
        // Its layer is unavailable: fail-closed it fails the request; fail-open it is
        // skipped and named. Either way [static, resource] never becomes [static].
        Discovery.Failure layered = assertThrows(Discovery.Failure.class,
            () -> d.resolveLayers(conf(), RES, List.of("static", "resource"), false));
        assertTrue(layered.getMessage().contains("layer resource"), layered.getMessage());
        Discovery.Layers open = d.resolveLayers(conf(), RES, List.of("static", "resource fail-open"), false);
        assertEquals(1, open.pdps().size());
        assertEquals(STATIC, open.pdps().get(0).identifier);
        assertEquals(List.of("resource"), open.skipped());
        // Recovery, once the retry window has passed.
        t.route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD));
        clock.now += Discovery.MIN_REFRESH + 1;
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
    }

    @Test
    void aRefusalOnRefreshEndsTheStaleEntryAtOnce() throws Exception {
        AuthZenRuleConfiguration c = conf();
        c.pdp_allowlist = List.of(GOOD);
        FakeTransport t = resourceRoutes();
        Clock clock = new Clock();
        Discovery d = discovery(t, clock);
        assertEquals(GOOD + "/custom/eval", d.resolve(c, RES).evaluation);
        // The PDP now advertises an endpoint the allowlist refuses: an answer, not an
        // outage, so the entry it replaces is not served on.
        t.route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD, "https://elsewhere.example/eval", null));
        clock.now += 301;
        assertEquals(Discovery.Kind.NOT_ALLOWED, assertThrows(Discovery.Failure.class, () -> d.resolve(c, RES)).kind);
        // Nothing is left to ride out an outage on.
        t.route(GOOD + "/.well-known/authzen-configuration", 503);
        assertEquals(Discovery.Kind.TRANSIENT, assertThrows(Discovery.Failure.class, () -> d.resolve(c, RES)).kind);
    }

    // ---------- resource mode ----------

    @Test
    void followsTheResourceToItsPdpAndNeverRelaysTheStaticKey() throws Exception {
        FakeTransport t = resourceRoutes();
        Discovery d = discovery(t);
        Discovery.Endpoints ep = d.resolve(conf(), RES);
        assertEquals(GOOD, ep.identifier);
        assertEquals(GOOD + "/custom/eval", ep.evaluation);
        assertNull(ep.apiKey);
        assertEquals("rfc9728", ep.source);
        // The whole document rides along, verbatim, tagged with where it came from.
        assertEquals("rfc9728", ep.resource.source());
        assertEquals(RES, ep.resource.document().get("resource").asText());
        assertTrue(ep.resource.document().get("ignored").booleanValue());
        assertEquals(0, t.count(STATIC));
        d.resolve(conf(), RES);
        assertEquals(1, t.count(RES), "resource metadata is cached");
        assertEquals(1, t.count(GOOD), "pdp metadata is cached");
    }

    @Test
    void usesTheStaticPdpForAnEmptyResourceAndKeepsItsKey() throws Exception {
        FakeTransport t = resourceRoutes();
        Discovery.Endpoints ep = discovery(t).resolve(conf(), "");
        assertEquals(STATIC, ep.identifier);
        assertEquals("static-key", ep.apiKey);
        assertNull(ep.resource, "nothing was read, so nothing is forwarded");
        assertEquals(0, t.count(RES));
        assertEquals(STATIC, discovery(t).resolve(conf(), null).identifier);
    }

    @Test
    void fallsToTheStaticPdpWhenTheResourcePublishesNothing() throws Exception {
        ObjectNode empty = obj("resource", RES);
        empty.putArray(Discovery.PARAM);
        Map<String, Object> cases = Map.of(
            "404", 404,
            "no parameter", obj("resource", RES),
            "empty list", empty,
            "parameter not a list", obj("resource", RES, Discovery.PARAM, GOOD));
        for (Map.Entry<String, Object> c : cases.entrySet()) {
            FakeTransport t = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", c.getValue());
            Discovery d = discovery(t);
            Discovery.Endpoints ep = d.resolve(conf(), RES);
            assertEquals(STATIC, ep.identifier, c.getKey());
            assertEquals("static-key", ep.apiKey, c.getKey());
            assertNull(ep.resource, c.getKey() + ": falling to static forwards no document");
            assertTrue(d.resourceEntry(RES).ok, c.getKey() + ": an answer, cached like any other");
        }
    }

    @Test
    void aResourceDocumentThatDoesNotValidateIsNotTheStaticPdps() {
        ObjectNode badEntries = obj("resource", RES);
        badEntries.putArray(Discovery.PARAM).add("not a url").add(1);
        ObjectNode withQuery = obj("resource", RES);
        withQuery.putArray(Discovery.PARAM).add(GOOD + "/?x");
        Map<String, Object> cases = Map.of(
            "echo mismatch", resourceDoc(GOOD).put("resource", "https://impostor.example"),
            "bad entries", badEntries,
            "entry with query", withQuery,
            "not JSON", "<html>");
        for (Map.Entry<String, Object> c : cases.entrySet()) {
            FakeTransport t = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", c.getValue());
            Discovery d = discovery(t);
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> d.resolve(conf(), RES), c.getKey());
            assertEquals(Discovery.Kind.INVALID, f.kind, c.getKey());
            assertFalse(d.resourceEntry(RES).ok, c.getKey() + ": not cached as the answer");
            assertEquals(0, t.count(STATIC), c.getKey());
        }
        // An identifier that cannot have metadata at all.
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(resourceRoutes()).resolve(conf(), "https://r.example/?x"));
        assertEquals(Discovery.Kind.INVALID, f.kind);
    }

    @Test
    void aResourceOutageFailsItsLayerAndIsNotRetriedOnEveryRequest() throws Exception {
        FakeTransport t = resourceRoutes().route(RES + "/.well-known/oauth-protected-resource", 500);
        Clock clock = new Clock();
        Discovery d = discovery(t, clock);
        assertEquals(Discovery.Kind.TRANSIENT, assertThrows(Discovery.Failure.class, () -> d.resolve(conf(), RES)).kind);
        Discovery.Entry e = d.resourceEntry(RES);
        assertFalse(e.ok);
        assertTrue(e.negUntil > 0);
        // Within the negative window the resource is not re-fetched.
        int before = t.hits.size();
        assertThrows(Discovery.Failure.class, () -> d.resolve(conf(), RES));
        assertEquals(before, t.hits.size());
        // Past it, it is.
        clock.now += 31;
        assertThrows(Discovery.Failure.class, () -> d.resolve(conf(), RES));
        assertTrue(t.hits.size() > before);
        assertEquals(0, t.count(STATIC));
    }

    @Test
    void servesTheStaleListWhileTheResourceIsDownAfterTheTtl() throws Exception {
        FakeTransport t = resourceRoutes();
        Clock clock = new Clock();
        Discovery d = discovery(t, clock);
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
        t.route(RES + "/.well-known/oauth-protected-resource", 500);
        clock.now += 301;
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
        // Throttled: a second attempt inside MIN_REFRESH does not refetch.
        int before = t.hits.size();
        d.resolve(conf(), RES);
        assertEquals(before, t.hits.size());
        // Recovery clears the error.
        t.route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD));
        clock.now += 31;
        assertEquals(GOOD, d.resolve(conf(), RES).identifier);
        assertNull(d.resourceEntry(RES).err);
    }

    @Test
    void failsClosedOnADisallowedResourceWithoutFetchingIt() {
        FakeTransport t = resourceRoutes();
        AuthZenRuleConfiguration c = conf();
        c.resource_metadata_allowlist = List.of("https://only.example");
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, RES));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
        assertEquals(0, t.hits.size());
    }

    @Test
    void failsClosedWhenTheNamedPdpIsOutsideTheAllowlistEvenFromAnotherRoutesCache() throws Exception {
        FakeTransport t = resourceRoutes();
        Discovery d = discovery(t);
        assertEquals(GOOD, d.resolve(conf(), RES).identifier); // a permissive route fills the cache
        AuthZenRuleConfiguration strict = conf();
        strict.pdp_allowlist = List.of("https://pdp.example");
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> d.resolve(strict, RES));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
        assertEquals(1, t.count(GOOD), "the strict route must not fetch the PDP again either");
        // The static PDP is always permitted.
        assertEquals(STATIC, d.resolve(strict, "").identifier);
    }

    @Test
    void reChecksCachedEndpointsAgainstTheCallingRoutesAllowlist() throws Exception {
        FakeTransport t = resourceRoutes().route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD, GOOD + "/eval", "https://batch.example/evals"));
        Discovery d = discovery(t);
        assertEquals(GOOD + "/eval", d.resolve(conf(), RES).evaluation);
        AuthZenRuleConfiguration c = conf();
        c.pdp_allowlist = List.of(GOOD);
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> d.resolve(c, RES));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
    }

    @Test
    void refusesHttpForADiscoveredResourceUnlessInsecure() throws Exception {
        ObjectNode doc = obj("resource", "http://r.example");
        doc.putArray(Discovery.PARAM).add(GOOD);
        FakeTransport t = new FakeTransport()
            .route("http://r.example/.well-known/oauth-protected-resource", doc)
            .route(GOOD, pdpConfig(GOOD));
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(conf(), "http://r.example"));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
        AuthZenRuleConfiguration c = conf();
        c.pdp_discovery_insecure = true;
        assertEquals(GOOD, discovery(t).resolve(c, "http://r.example").identifier);
    }

    @Test
    void triesTheNextCandidateWhenTheFirstPdpIsUnusable() throws Exception {
        FakeTransport t = resourceRoutes()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(ROGUE, GOOD))
            .route(ROGUE + "/.well-known/authzen-configuration", pdpConfig("https://x.example"));
        assertEquals(GOOD, discovery(t).resolve(conf(), RES).identifier);
    }

    @Test
    void reportsNoPdpWhenEveryCandidateFailsAndThereIsNoStaticOne() {
        FakeTransport t = new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(ROGUE))
            .route(ROGUE + "/.well-known/authzen-configuration", pdpConfig("https://x.example"));
        AuthZenRuleConfiguration c = conf();
        c.authzen_url = "";
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, RES));
        assertEquals(Discovery.Kind.REFUSED, f.kind, "the one candidate answered, unusably");
        assertTrue(f.getMessage().contains("no PDP could be resolved"));
        // An outage among the candidates is an outage.
        FakeTransport down = new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(ROGUE, GOOD))
            .route(ROGUE + "/.well-known/authzen-configuration", pdpConfig("https://x.example"))
            .route(GOOD + "/.well-known/authzen-configuration", 503);
        assertEquals(Discovery.Kind.TRANSIENT, assertThrows(Discovery.Failure.class, () -> discovery(down).resolve(c, RES)).kind);
        // No metadata and no static PDP either.
        Discovery.Failure f2 = assertThrows(Discovery.Failure.class, () -> discovery(new FakeTransport()).resolve(c, RES));
        assertEquals(Discovery.Kind.TRANSIENT, f2.kind);
        // Transient failure and no static PDP.
        Discovery.Failure f3 = assertThrows(Discovery.Failure.class, () -> discovery(new FakeTransport().route(RES, 500)).resolve(c, RES));
        assertEquals(Discovery.Kind.TRANSIENT, f3.kind);
        // A candidate whose metadata is invalid, and no static PDP: the failure names it.
        FakeTransport t4 = new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD))
            .route(GOOD + "/.well-known/authzen-configuration", "<html>");
        Discovery.Failure f4 = assertThrows(Discovery.Failure.class, () -> discovery(t4).resolve(c, RES));
        assertTrue(f4.getMessage().contains("not JSON"), f4.getMessage());
    }

    @Test
    void keepsServingAPdpEntryWhoseRefreshFailsAfterAGoodRead() throws Exception {
        FakeTransport t = resourceRoutes();
        Clock clock = new Clock();
        Discovery d = discovery(t, clock);
        assertEquals(GOOD + "/custom/eval", d.resolve(conf(), RES).evaluation);
        t.route(GOOD + "/.well-known/authzen-configuration", pdpConfig("https://x.example"));
        clock.now += 301;
        assertEquals(GOOD + "/custom/eval", d.resolve(conf(), RES).evaluation);
    }

    @Test
    void refusesAPdpMetadataEndpointOutsideTheAllowlistOrNotAString() {
        FakeTransport t = resourceRoutes().route(GOOD + "/.well-known/authzen-configuration",
            pdpConfig(GOOD, GOOD + "/eval", "https://elsewhere.example/evals"));
        AuthZenRuleConfiguration c = conf();
        c.pdp_allowlist = List.of(GOOD);
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(t).resolve(c, RES));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
        ObjectNode numeric = pdpConfig(GOOD, GOOD + "/eval", null).put("access_evaluations_endpoint", 42);
        FakeTransport t2 = resourceRoutes().route(GOOD + "/.well-known/authzen-configuration", numeric);
        Discovery.Failure f2 = assertThrows(Discovery.Failure.class, () -> discovery(t2).resolve(conf(), RES));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f2.kind);
    }

    // ---------- layers ----------

    static FakeTransport layerRoutes() {
        return new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD))
            .route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD))
            .route(ESTATE + "/.well-known/authzen-configuration", pdpConfig(ESTATE));
    }

    @Test
    void resolvesEveryLayerInOrderDuplicatesCollapsedWithTheResourceDocument() throws Exception {
        Discovery d = discovery(layerRoutes());
        Discovery.Layers r = d.resolveLayers(conf(), RES, List.of(ESTATE, "static", "resource"), false);
        assertEquals(3, r.pdps().size());
        assertEquals(ESTATE, r.pdps().get(0).identifier);
        assertEquals("layer", r.pdps().get(0).source);
        assertNull(r.pdps().get(0).apiKey);
        assertEquals(STATIC, r.pdps().get(1).identifier);
        assertEquals("static-key", r.pdps().get(1).apiKey);
        assertEquals(GOOD, r.pdps().get(2).identifier);
        assertEquals("rfc9728", r.meta().source());
        assertTrue(r.skipped().isEmpty());
        assertFalse(r.pdps().get(0).failOpen);
        Discovery.Layers one = d.resolveLayers(conf(), RES, null, false);
        assertEquals(1, one.pdps().size());
        assertEquals(GOOD, one.pdps().get(0).identifier);
        Discovery.Layers dup = d.resolveLayers(conf(), RES, List.of(GOOD, "resource"), false);
        assertEquals(1, dup.pdps().size());
        assertEquals(0, d.resolveLayers(conf(), RES, List.of(), false).skipped().size());
    }

    @Test
    void parsesALayerEntryWithItsFailureModeAndRefusesWhatItCannotRead() throws Exception {
        assertEquals(new Discovery.LayerSpec(ESTATE, true), Discovery.parseLayer(ESTATE + "/ fail-open"));
        assertEquals(new Discovery.LayerSpec("resource", false), Discovery.parseLayer("resource FAIL-CLOSED"));
        assertEquals(new Discovery.LayerSpec("static", null), Discovery.parseLayer(" static "));
        for (String bad : new String[]{"resource maybe", "bogus", "", null}) {
            Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> Discovery.parseLayer(bad), String.valueOf(bad));
            assertEquals(Discovery.Kind.INVALID, f.kind);
        }
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> discovery(layerRoutes()).resolveLayers(conf(), RES, List.of("resource maybe"), false));
        assertEquals(Discovery.Kind.INVALID, f.kind);
    }

    @Test
    void aFailOpenLayerThatIsDownIsSkippedARefusalNeverIs() throws Exception {
        String down = "https://down.example"; // its metadata is unavailable: an outage
        Discovery d = discovery(layerRoutes().route(down + "/.well-known/authzen-configuration", 503));
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> d.resolveLayers(conf(), RES, List.of(down, "resource"), false));
        assertTrue(f.getMessage().contains("layer"));
        Discovery.Layers r = d.resolveLayers(conf(), RES, List.of(down + " fail-open", "resource"), false);
        assertEquals(1, r.pdps().size());
        assertEquals(GOOD, r.pdps().get(0).identifier);
        assertFalse(r.pdps().get(0).failOpen);
        // Named by its identifier alone: the error is in the log, not on the wire.
        assertEquals(List.of(down), r.skipped());
        // The route default applies to layers that say nothing; the layer's own word wins.
        r = d.resolveLayers(conf(), RES, List.of(down, "resource fail-closed"), true);
        assertEquals(1, r.skipped().size());
        assertFalse(r.pdps().get(0).failOpen);
        assertThrows(Discovery.Failure.class, () -> d.resolveLayers(conf(), RES, List.of(down + " fail-closed"), true));
        // Everything skipped is still a resolution, with nothing to ask.
        r = d.resolveLayers(conf(), RES, List.of(down), true);
        assertTrue(r.pdps().isEmpty());
        assertEquals(1, r.skipped().size());
        // A layer that cannot be resolved for any other reason is never skipped: an
        // identifier that cannot be one, metadata that answers unusably.
        String bad = "https://p.example/?x=1";
        Discovery.Failure invalid = assertThrows(Discovery.Failure.class, () -> d.resolveLayers(conf(), RES, List.of(bad + " fail-open", "resource"), true));
        assertEquals(Discovery.Kind.INVALID, invalid.kind);
        Discovery refusing = discovery(layerRoutes().route(down + "/.well-known/authzen-configuration", 401));
        Discovery.Failure refused = assertThrows(Discovery.Failure.class, () -> refusing.resolveLayers(conf(), RES, List.of(down + " fail-open", "resource"), true));
        assertEquals(Discovery.Kind.REFUSED, refused.kind);
        // A duplicate takes the stricter mode.
        r = d.resolveLayers(conf(), RES, List.of(GOOD + " fail-open", "resource fail-closed"), false);
        assertEquals(1, r.pdps().size());
        assertFalse(r.pdps().get(0).failOpen);
        r = d.resolveLayers(conf(), RES, List.of(GOOD + " fail-open", "resource fail-open"), false);
        assertTrue(r.pdps().get(0).failOpen);
        // The allowlist is a refusal, not an outage.
        AuthZenRuleConfiguration strict = conf();
        strict.pdp_allowlist = List.of("https://pdp.example");
        Discovery.Failure nf = assertThrows(Discovery.Failure.class, () -> d.resolveLayers(strict, RES, List.of(ESTATE + " fail-open"), true));
        assertEquals(Discovery.Kind.NOT_ALLOWED, nf.kind);
    }

    @Test
    void anExplicitLayerObeysTheAllowlistNamesItselfOnFailureAndReadsNothingInOffMode() throws Exception {
        Discovery d = discovery(layerRoutes());
        AuthZenRuleConfiguration strict = conf();
        strict.pdp_allowlist = List.of("https://pdp.example");
        Discovery.Failure f = assertThrows(Discovery.Failure.class, () -> d.resolveLayers(strict, RES, List.of(ESTATE), false));
        assertEquals(Discovery.Kind.NOT_ALLOWED, f.kind);
        assertTrue(f.getMessage().contains("layer"));
        FakeTransport none = new FakeTransport();
        AuthZenRuleConfiguration off = conf();
        off.pdp_discovery = "off";
        Discovery.Endpoints ep = discovery(none).resolvePdp(off, ESTATE + "/");
        assertEquals(ESTATE + "/access/v1/evaluation", ep.evaluation);
        assertEquals("layer", ep.source);
        assertNull(ep.apiKey);
        Discovery.Endpoints sk = discovery(none).resolvePdp(off, STATIC);
        assertEquals("static-key", sk.apiKey);
        assertEquals(0, none.hits.size());
        // With discovery on, an explicit layer's advertised endpoints are checked against the allowlist.
        FakeTransport t = new FakeTransport().route(ESTATE + "/.well-known/authzen-configuration", pdpConfig(ESTATE, ESTATE + "/eval", "https://batch.example/evals"));
        AuthZenRuleConfiguration c = conf();
        c.pdp_allowlist = List.of(ESTATE);
        Discovery.Failure nf = assertThrows(Discovery.Failure.class, () -> discovery(t).resolvePdp(c, ESTATE));
        assertEquals(Discovery.Kind.NOT_ALLOWED, nf.kind);
        // And a layer that is the static PDP keeps the key, with metadata read.
        FakeTransport t2 = new FakeTransport().route(STATIC + "/.well-known/authzen-configuration", pdpConfig(STATIC));
        Discovery.Endpoints st = discovery(t2).resolvePdp(conf(), STATIC);
        assertEquals("static-key", st.apiKey);
        assertEquals(STATIC + "/custom/eval", st.evaluation);
        assertNotNull(st.evaluations == null ? "" : st.evaluations);
    }
}

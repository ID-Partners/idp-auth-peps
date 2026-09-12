package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.idpartners.pa.authzen.DiscoveryTest.ESTATE;
import static com.idpartners.pa.authzen.DiscoveryTest.GOOD;
import static com.idpartners.pa.authzen.DiscoveryTest.RES;
import static com.idpartners.pa.authzen.DiscoveryTest.STATIC;
import static com.idpartners.pa.authzen.DiscoveryTest.pdpConfig;
import static com.idpartners.pa.authzen.DiscoveryTest.resourceDoc;
import static com.idpartners.pa.authzen.FakeTransport.jwt;
import static com.idpartners.pa.authzen.FakeTransport.obj;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The decision path, against the scripted transport: no token (denied before the PDP is
 * ever called), permit (delegation chain forwarded as X-Auth-*), deny (403 with the
 * policy reason), PDP unreachable (which MUST fail closed), DPoP and COAZ delegation,
 * the challenge shapes shared with the other PEPs, layers and failing open.
 */
class PepTest {
    static final String PDP = "http://pdp:8080";
    static final String EVAL = PDP + "/access/v1/evaluation";
    static final String COAZ = "http://coaz-pep:9192";

    static AuthZenRuleConfiguration baseConf() {
        AuthZenRuleConfiguration c = new AuthZenRuleConfiguration();
        c.authzen_url = PDP;
        c.authzen_api_key = "k";
        c.pep_label = "test-pep";
        c.style = "rest";
        c.require_token = true;
        c.require_dpop = false;
        c.require_user_login = false;
        c.stepup_action = "make_payment";
        c.pdp_ssl_verify = true;
        return c;
    }

    static Pep pep(AuthZenRuleConfiguration c, FakeTransport t) {
        return new Pep(c, t, new Discovery(t, () -> 1_000_000L), UserTokens.decodeOnly());
    }

    static PepRequest req(String method, String path, Map<String, String> headers, String body) {
        return new PepRequest(method, path, headers, body == null ? null : body.getBytes(StandardCharsets.UTF_8), null);
    }

    static String bearer(ObjectNode claims) {
        return "Bearer " + jwt(claims);
    }

    static FakeTransport pdp(Object responder) {
        return new FakeTransport().route(EVAL, responder);
    }

    static ObjectNode sent(FakeTransport t) {
        return (ObjectNode) Json.parse(t.to("/access/v1/evaluation").get(0).body());
    }

    static JsonNode body(Verdict v) {
        return Json.parse(v.body);
    }

    // ---------- the decision path ----------

    @Test
    void deniesARequestWithNoTokenWhenOneIsRequired() {
        FakeTransport t = pdp(obj("decision", true));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of(), null));
        assertFalse(v.permit);
        assertEquals(401, v.status);
        assertEquals("authorization_failed", body(v).get("error").asText());
        assertEquals("application/json", v.header("content-type"));
        assertEquals(0, t.hits.size(), "never reached the PDP");
        assertTrue(v.responseHeaders.isEmpty(), "no decision was made, so no X-PDP headers");
    }

    @Test
    void letsAnAnonymousRequestThroughToThePdpWhenNoTokenIsRequired() {
        FakeTransport t = pdp(obj("decision", true));
        AuthZenRuleConfiguration c = baseConf();
        c.require_token = false;
        Verdict v = pep(c, t).decide(req("GET", "/accounts/a/balance", Map.of(), null));
        assertTrue(v.permit);
        assertEquals("unknown-agent", sent(t).get("subject").get("id").asText());
        assertEquals("", v.upstreamHeaders.get("X-Auth-Principal"));
        assertFalse(sent(t).get("subject").get("properties").has("on_behalf_of"));
    }

    @Test
    void forwardsTheDelegationChainUpstreamOnAPermit() {
        FakeTransport t = pdp(obj("decision", true));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance",
            Map.of("Authorization", bearer(obj("sub", "alice", "act", obj("sub", "agent-7"), "scope", "accounts:read", "acr", "urn:mfa"))), null));
        assertTrue(v.permit);
        assertEquals("alice", v.upstreamHeaders.get("X-Auth-Principal"));
        assertEquals("agent-7", v.upstreamHeaders.get("X-Auth-Agent"));
        assertEquals("accounts:read", v.upstreamHeaders.get("X-Auth-Scope"));
        // acr comes from the token, not from a username comparison
        assertEquals("urn:mfa", v.upstreamHeaders.get("X-Auth-Acr"));
        assertEquals("PERMIT", v.responseHeaders.get("X-PDP-Decision"));
        assertEquals("test-pep", v.responseHeaders.get("X-PDP-PEP"));
        assertEquals("get_balance", v.responseHeaders.get("X-PDP-Action"));
        assertEquals("Permitted by policy.", v.responseHeaders.get("X-PDP-Reason"));
        assertNull(v.responseHeaders.get("X-PDP-Fail-Open"));
        // The static PDP gets its key, and the mapped context.
        assertEquals("Bearer k", t.last().headers().get("Authorization"));
        assertEquals("GET", sent(t).get("context").get("request").get("method").asText());
        assertEquals("/accounts/a/balance", sent(t).get("context").get("request").get("path").asText());
        assertFalse(sent(t).get("context").has("access_token"));
        assertFalse(sent(t).get("context").has("resource_metadata"));
    }

    @Test
    void honoursAPdpDeny() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("reason", "not your account")));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals(403, v.status);
        assertTrue(body(v).get("reason").asText().contains("not your account"));
        assertEquals("DENY", v.responseHeaders.get("X-PDP-Decision"));
        assertEquals("not your account", v.responseHeaders.get("X-PDP-Reason"));
    }

    @Test
    void failsClosedWhenThePdpIsUnreachableOrUnusable() {
        for (Object r : new Object[]{Boolean.FALSE, 500, 302}) {
            Verdict v = pep(baseConf(), pdp(r)).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
            assertEquals(503, v.status, String.valueOf(r));
            assertTrue(body(v).get("reason").asText().contains("unreachable"));
        }
        // A 200 that is not a decision is a deny, never a permit.
        Verdict junk = pep(baseConf(), pdp("not json")).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals(403, junk.status);
        assertEquals("Denied by policy.", body(junk).get("reason").asText());
        Verdict str = pep(baseConf(), pdp(obj("decision", "true"))).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals(403, str.status, "a string is not a boolean decision");
    }

    @Test
    void verifiesTlsToThePdpByDefaultAndOnlyOffExplicitly() {
        FakeTransport t = pdp(obj("decision", true));
        pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals(1, t.hits.size());
        assertTrue(t.hits.get(0).verifyTls());
        AuthZenRuleConfiguration c = baseConf();
        c.pdp_ssl_verify = false;
        FakeTransport t2 = pdp(obj("decision", true));
        pep(c, t2).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertFalse(t2.hits.get(0).verifyTls());
    }

    @Test
    void sendsThePdpASubjectBuiltFromTheTokenNotFromTheRequest() {
        FakeTransport t = pdp(obj("decision", true));
        pep(baseConf(), t).decide(req("GET", "/customers/cust-1/accounts",
            Map.of("authorization", bearer(obj("sub", "alice", "act", obj("sub", "agent-7"), "client_id", "c1"))), null));
        ObjectNode s = sent(t);
        assertEquals("list_accounts", s.get("action").get("name").asText());
        assertEquals("customer", s.get("resource").get("type").asText());
        assertEquals("cust-1", s.get("resource").get("id").asText());
        assertEquals("ai-agent", s.get("context").get("channel").asText());
    }

    @Test
    void usesADefaultLabelWhenNoneIsConfigured() {
        AuthZenRuleConfiguration c = baseConf();
        c.pep_label = "";
        Verdict v = pep(c, pdp(obj("decision", true))).decide(req("GET", "/x", Map.of(), null));
        assertEquals("pingaccess-pep", body(v).get("pep").asText());
    }

    // ---------- DPoP is delegated, and fails closed ----------

    private static Object[] withVerifier(Object verdictOrFn, String coazUrl) {
        FakeTransport t = pdp(obj("decision", true)).route(COAZ + "/v1/dpop/verify", verdictOrFn);
        AuthZenRuleConfiguration c = baseConf();
        c.require_dpop = true;
        c.coaz_url = coazUrl;
        c.coaz_api_key = "secret";
        Verdict v = pep(c, t).decide(req("GET", "/accounts/a/balance", Map.of(
            "authorization", "DPoP " + jwt(obj("sub", "alice", "cnf", obj("jkt", "THUMB"))),
            "dpop", jwt(obj("htm", "GET", "ath", "AAA"), "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}")), null));
        return new Object[]{v, t};
    }

    @Test
    void permitsWhenTheVerifierSaysTheProofIsValid() {
        Object[] r = withVerifier(obj("valid", true), COAZ);
        Verdict v = (Verdict) r[0];
        FakeTransport t = (FakeTransport) r[1];
        assertTrue(v.permit);
        assertEquals(1, t.count("/v1/dpop/verify"), "the proof should be sent for verification");
        assertEquals(1, t.count("/access/v1/evaluation"), "a valid proof should let the request reach the PDP");
        Transport.Request verify = t.to("/v1/dpop/verify").get(0);
        assertEquals("Bearer secret", verify.headers().get("Authorization"));
        JsonNode sent = Json.parse(verify.body());
        assertEquals("GET", sent.get("method").asText());
        assertEquals("/accounts/a/balance", sent.get("path").asText());
        assertEquals("test-pep", sent.get("pep_label").asText());
        assertTrue(sent.get("headers").get("authorization").asText().startsWith("DPoP "));
        assertTrue(sent.get("headers").has("dpop"));
    }

    @Test
    void relaysTheVerifierReasonOnAnInvalidProof() {
        Verdict v = (Verdict) withVerifier(obj("valid", false, "reason", "DPoP proof signature is invalid"), COAZ)[0];
        assertEquals(401, v.status);
        assertTrue(body(v).get("reason").asText().contains("signature is invalid"));
        Verdict noReason = (Verdict) withVerifier(obj("valid", false), COAZ)[0];
        assertEquals("DPoP proof is not valid for this request.", body(noReason).get("reason").asText());
    }

    @Test
    void failsClosedWhenTheVerifierIsUnreachableErrorsOrIsUnusable() {
        Verdict down = (Verdict) withVerifier(Boolean.FALSE, COAZ)[0];
        assertEquals(401, down.status);
        assertTrue(body(down).get("reason").asText().contains("unreachable"));
        Verdict err = (Verdict) withVerifier((Function<Transport.Request, Transport.Response>) r -> FakeTransport.json(500, "boom"), COAZ)[0];
        assertEquals(401, err.status);
        Verdict junk = (Verdict) withVerifier("not json", COAZ)[0];
        assertEquals(401, junk.status);
    }

    @Test
    void failsClosedRatherThanFallingBackWhenCoazUrlIsUnset() {
        // configure() forbids this combination, so it should be unreachable; a route
        // that demands sender-constrained tokens and cannot verify them must deny.
        Object[] r = withVerifier(obj("valid", true), "");
        Verdict v = (Verdict) r[0];
        assertEquals(401, v.status);
        assertTrue(body(v).get("reason").asText().contains("verification is unavailable"));
        assertEquals(0, ((FakeTransport) r[1]).hits.size());
    }

    @Test
    void neverSendsTheProofAnywhereWhenTheRouteDoesNotRequireDpop() {
        FakeTransport t = pdp(obj("decision", true));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertTrue(v.permit);
        assertEquals(0, t.count("/v1/dpop/verify"));
    }

    // ---------- step-up and PDP advice ----------

    @Test
    void relaysAStepUpChallengeRatherThanAFlatDeny() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("reason", "over threshold", "step_up_required", true, "step_up_scope", "payments:approve")));
        Verdict v = pep(baseConf(), t).decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice", "scope", "accounts:read"))),
            "{\"from_account\":\"a\",\"to_account\":\"b\",\"amount\":9000}"));
        assertEquals(401, v.status);
        assertTrue(v.bodyText().contains("payments:approve"), "the client needs to know WHICH scope to go and get");
        assertEquals("DENY", v.responseHeaders.get("X-PDP-Decision"));
        assertEquals("make_payment", v.responseHeaders.get("X-PDP-Action"));
    }

    @Test
    void fallsBackToTheRoutesStepUpScopeWhenTheAdviceNamesNone() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("step_up_required", true)));
        AuthZenRuleConfiguration c = baseConf();
        c.stepup_scope = "route:scope";
        Verdict v = pep(c, t).decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice"))), "{}"));
        assertEquals("route:scope", body(v).get("scope").asText());
        AuthZenRuleConfiguration none = baseConf();
        Verdict empty = pep(none, pdp(obj("decision", false, "context", obj("step_up_required", true)))).decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice"))), "{}"));
        assertEquals("", body(empty).get("scope").asText());
    }

    @Test
    void relaysAnIdentityProofingRequirementWithItsDoctype() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("identity_proofing_required", true, "identity_proofing_doctype", "org.iso.18013.5.1.mDL")));
        Verdict v = pep(baseConf(), t).decide(req("POST", "/accounts", Map.of("authorization", bearer(obj("sub", "alice", "scope", "accounts:read"))), "{\"account_type\":\"savings\"}"));
        assertEquals(401, v.status);
        assertTrue(v.bodyText().contains("mDL"));
    }

    @Test
    void requiresALoggedInUserWhenTheRouteSaysSo() {
        FakeTransport t = pdp(obj("decision", true));
        AuthZenRuleConfiguration c = baseConf();
        c.require_user_login = true;
        Verdict v = pep(c, t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice", "scope", "accounts:read"))), null));
        assertEquals(401, v.status);
        assertEquals("login_required", body(v).get("error").asText());
        assertEquals(0, t.hits.size(), "challenged before the PDP is consulted");
        // A user token without a subject is no user.
        Verdict noSub = pep(c, t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice")), "x-user-token", jwt(obj("scope", "x"))), null));
        assertEquals(401, noSub.status);
    }

    @Test
    void carriesTheUserTokenScopeIntoThePdpContext() {
        FakeTransport t = pdp(obj("decision", true));
        AuthZenRuleConfiguration c = baseConf();
        c.require_user_login = true;
        Verdict v = pep(c, t).decide(req("POST", "/payments", Map.of(
            "authorization", bearer(obj("sub", "alice", "scope", "accounts:read")),
            "x-user-token", jwt(obj("sub", "alice", "scope", "payments:approve", "acr", "urn:mfa"))), "{\"from_account\":\"a\",\"amount\":50}"));
        assertTrue(v.permit);
        assertEquals("payments:approve", sent(t).get("context").get("user_scope").asText());
        // Without a user token the scope is empty, not absent.
        FakeTransport t2 = pdp(obj("decision", true));
        pep(baseConf(), t2).decide(req("GET", "/x", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals("", sent(t2).get("context").get("user_scope").asText());
    }

    // ---------- challenge parity with the other PEPs ----------

    @Test
    void rendersAStepUpIdenticallyToTheGoPep() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("reason", "approve it", "step_up_required", true, "step_up_scope", "pay:approve")));
        Verdict v = pep(baseConf(), t).decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice"))), "{\"from_account\":\"a\",\"amount\":9000}"));
        JsonNode b = body(v);
        assertEquals(401, v.status);
        assertEquals("insufficient_scope", b.get("error").asText());
        assertEquals("resource_authorisation", b.get("authz_challenge").get("type").asText());
        assertEquals("pay:approve", b.get("authz_challenge").get("scope").asText());
        assertEquals("approve it", b.get("authz_challenge").get("reason").asText());
        assertEquals("test-pep", b.get("authz_challenge").get("pep").asText());
        assertEquals("Bearer error=\"insufficient_scope\", scope=\"pay:approve\"", v.header("WWW-Authenticate"));
    }

    @Test
    void rendersIdentityProofingIdenticallyToTheGoPep() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("identity_proofing_required", true, "identity_proofing_doctype", "org.iso.18013.5.1.mDL")));
        Verdict v = pep(baseConf(), t).decide(req("POST", "/accounts", Map.of("authorization", bearer(obj("sub", "alice"))), "{}"));
        JsonNode b = body(v);
        assertEquals(401, v.status);
        assertEquals("identity_verification_required", b.get("error").asText());
        assertEquals("identity_proofing", b.get("authz_challenge").get("type").asText());
        assertEquals("org.iso.18013.5.1.mDL", b.get("authz_challenge").get("doctype").asText());
        assertEquals("Bearer error=\"identity_verification_required\", doctype=\"org.iso.18013.5.1.mDL\"", v.header("WWW-Authenticate"));
    }

    @Test
    void defaultsTheDoctypeWhenThePolicyNamesNone() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("identity_proofing_required", true)));
        Verdict v = pep(baseConf(), t).decide(req("POST", "/accounts", Map.of("authorization", bearer(obj("sub", "alice"))), "{}"));
        assertEquals("org.iso.18013.5.1.mDL", body(v).get("doctype").asText());
    }

    @Test
    void resolvesIdentityBeforeStepUpWhenAPolicyAsksForBoth() {
        FakeTransport t = pdp(obj("decision", false, "context", obj("identity_proofing_required", true, "step_up_required", true, "step_up_scope", "s")));
        Verdict v = pep(baseConf(), t).decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice"))), "{\"from_account\":\"a\",\"amount\":9000}"));
        assertEquals("identity_verification_required", body(v).get("error").asText());
    }

    // ---------- COAZ delegation on an MCP route ----------

    static final String TOOLS_CALL = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_customer\",\"arguments\":{\"id\":\"c1\"}}}";

    private static Object[] mcpRoute(Object engine, AuthZenRuleConfiguration over) {
        FakeTransport t = pdp(obj("decision", true)).route(COAZ + "/v1/mcp/check", engine);
        AuthZenRuleConfiguration c = over != null ? over : baseConf();
        c.style = "mcp";
        if (over == null) {
            c.coaz_url = COAZ;
            c.mcp_upstream_url = "http://mcp:8090/mcp";
        }
        Verdict v = pep(c, t).decide(req("POST", "/mcp", Map.of("authorization", bearer(obj("sub", "alice", "act", obj("sub", "agent-1"))),
            "x-user-token", "ut", "content-type", "application/json"), TOOLS_CALL));
        return new Object[]{v, t};
    }

    @Test
    void delegatesAToolsCallToTheEngineAndForwardsItsUpstreamHeaders() {
        Object[] r = mcpRoute(obj("decision", true, "upstream_headers", obj("X-Auth-Principal", "alice", "X-Coaz", "permit"),
            "response_headers", obj("X-PDP-Action", "tools/call:get_customer", "X-PDP-Reason", "ok")), null);
        Verdict v = (Verdict) r[0];
        FakeTransport t = (FakeTransport) r[1];
        assertTrue(v.permit);
        assertTrue(t.hits.get(0).url().contains("/v1/mcp/check"), "the tools/call should go to the engine");
        assertEquals("permit", v.upstreamHeaders.get("X-Coaz"));
        assertEquals("tools/call:get_customer", v.responseHeaders.get("X-PDP-Action"));
        assertEquals("ok", v.responseHeaders.get("X-PDP-Reason"));
        assertEquals(0, t.count("/access/v1/evaluation"), "the engine asked the PDP, not this rule");
        JsonNode sentBody = Json.parse(t.hits.get(0).body());
        assertEquals("mcp", sentBody.get("config").get("style").asText());
        assertEquals("http://mcp:8090/mcp", sentBody.get("config").get("mcp_upstream_url").asText());
        assertEquals("false", sentBody.get("config").get("coaz_defaults").asText());
        assertEquals("test-pep", sentBody.get("config").get("pep_label").asText());
        assertEquals("resource", sentBody.get("config").get("pdp_layers").asText());
        assertFalse(sentBody.get("config").has("fail_mode"));
        assertFalse(sentBody.get("config").has("resource"));
        assertFalse(sentBody.get("config").has("forward_access_token"));
        assertEquals("ut", sentBody.get("headers").get("x-user-token").asText());
        assertEquals(TOOLS_CALL, sentBody.get("body").asText());
        assertEquals("POST", sentBody.get("method").asText());
        assertEquals("/mcp", sentBody.get("path").asText());
    }

    @Test
    void relaysTheEngineJsonRpcErrorBodyVerbatimOnADeny() {
        String rpcError = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32001,\"message\":\"denied by policy\"}}";
        Verdict v = (Verdict) mcpRoute(obj("decision", false, "response", obj("status", 200, "body", rpcError,
            "headers", obj("Content-Type", "application/json", "X-PDP-Reason", "no"))), null)[0];
        assertFalse(v.permit);
        // Relayed as-is: two renderings of one decision would drift.
        assertEquals(200, v.status);
        assertEquals(rpcError, v.bodyText());
        assertEquals("application/json", v.header("Content-Type"));
        assertEquals("DENY", v.responseHeaders.get("X-PDP-Decision"));
        assertEquals("tools/call:get_customer", v.responseHeaders.get("X-PDP-Action"));
        assertEquals("no", v.responseHeaders.get("X-PDP-Reason"));
        // An engine verdict with nothing usable in it is still a deny, with defaults.
        Verdict bare = (Verdict) mcpRoute(obj("decision", false), null)[0];
        assertEquals(200, bare.status);
        assertEquals("", bare.bodyText());
        Verdict junk = (Verdict) mcpRoute("[]", null)[0];
        assertFalse(junk.permit);
    }

    @Test
    void failsClosedWhenTheEngineIsUnreachableOrErrors() {
        Verdict down = (Verdict) mcpRoute(Boolean.FALSE, null)[0];
        assertEquals(503, down.status);
        assertTrue(body(down).get("reason").asText().contains("unreachable"));
        Verdict err = (Verdict) mcpRoute((Function<Transport.Request, Transport.Response>) r -> FakeTransport.json(500, "boom"), null)[0];
        assertEquals(503, err.status);
    }

    @Test
    void doesNotDelegateJsonRpcThatIsNotAToolsCallOrWhenCoazUrlIsUnset() {
        FakeTransport t = pdp(obj("decision", true)).route(COAZ, obj("decision", true));
        AuthZenRuleConfiguration c = baseConf();
        c.style = "mcp";
        c.coaz_url = COAZ;
        Verdict v = pep(c, t).decide(req("POST", "/mcp", Map.of("authorization", bearer(obj("sub", "alice"))), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"));
        assertTrue(v.permit);
        assertEquals(0, t.count("/v1/mcp/check"), "only tools/call is delegated");
        assertEquals("mcp-handshake", v.responseHeaders.get("X-PDP-Action"));
        assertEquals("alice", v.upstreamHeaders.get("X-Auth-Principal"));
        assertEquals(0, t.count("/access/v1/evaluation"));

        AuthZenRuleConfiguration noEngine = baseConf();
        noEngine.style = "mcp";
        FakeTransport t2 = pdp(obj("decision", true)).route(COAZ, obj("decision", true));
        Verdict v2 = pep(noEngine, t2).decide(req("POST", "/mcp", Map.of("authorization", bearer(obj("sub", "alice"))), TOOLS_CALL));
        assertTrue(v2.permit);
        assertEquals(0, t2.count("/v1/mcp/check"));

        // The initialize handshake is a PDP question: access to the MCP service.
        FakeTransport t3 = pdp(obj("decision", true));
        pep(noEngine, t3).decide(req("POST", "/mcp", Map.of("authorization", bearer(obj("sub", "alice"))), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"));
        assertEquals("access_mcp", sent(t3).get("action").get("name").asText());
        assertEquals("mcp-service", sent(t3).get("resource").get("type").asText());
    }

    @Test
    void passesThePolicyAndFailModeAndResourceToTheEngine() {
        AuthZenRuleConfiguration c = baseConf();
        c.coaz_url = COAZ;
        c.mcp_upstream_url = "http://mcp:8090/mcp";
        c.pdp_layers = List.of("https://down.example fail-open", "resource");
        c.fail_mode = "open";
        c.resource = "https://api.example";
        c.forward_access_token = true;
        c.coaz_defaults = true;
        Object[] r = mcpRoute(obj("decision", true), c);
        assertTrue(((Verdict) r[0]).permit);
        JsonNode cfg = Json.parse(((FakeTransport) r[1]).hits.get(0).body()).get("config");
        assertEquals("https://down.example fail-open,resource", cfg.get("pdp_layers").asText());
        assertEquals("open", cfg.get("fail_mode").asText());
        assertEquals("https://api.example", cfg.get("resource").asText());
        assertEquals("true", cfg.get("forward_access_token").asText());
        assertEquals("true", cfg.get("coaz_defaults").asText());
        // Header sanity: the engine call is authenticated when a key is configured.
        c.coaz_api_key = "demo";
        Object[] r2 = mcpRoute(obj("decision", true), c);
        assertEquals("Bearer demo", ((FakeTransport) r2[1]).hits.get(0).headers().get("Authorization"));
        // And a tools/call without a name still gets an action.
        FakeTransport t = pdp(obj("decision", true)).route(COAZ + "/v1/mcp/check", obj("decision", true));
        Verdict v = pep(c, t).decide(req("POST", "/mcp", Map.of("authorization", bearer(obj("sub", "alice"))), "{\"method\":\"tools/call\"}"));
        assertEquals("tools/call:?", v.responseHeaders.get("X-PDP-Action"));
    }

    // ---------- claim handling and remaining denials ----------

    @Test
    void deniesATokenWithNoReadableSubject() {
        FakeTransport t = pdp(obj("decision", true));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("scope", "a"))), null));
        assertEquals(401, v.status);
        assertTrue(body(v).get("reason").asText().contains("no subject claim"));
        Verdict opaque = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", "Bearer opaque"), null));
        assertEquals(401, opaque.status);
    }

    @Test
    void decodesAnActClaimThatArrivedAsAJsonString() {
        // PingFederate serialises act as a string; read naively, every delegated call
        // looks direct and the agent disappears from the audit trail.
        FakeTransport t = pdp(obj("decision", true));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice", "act", "{\"sub\":\"agent-9\"}"))), null));
        assertEquals("agent-9", v.upstreamHeaders.get("X-Auth-Agent"));
        Verdict junk = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice", "act", "{{"))), null));
        assertEquals("", junk.upstreamHeaders.get("X-Auth-Agent"));
    }

    @Test
    void joinsArrayValuedScopeAndAcr() {
        FakeTransport t = pdp(obj("decision", true));
        Verdict v = pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization",
            bearer(obj("sub", "alice", "scp", List.of("a", "b"), "acr", List.of("urn:x", "urn:y"), "azp", "client-z"))), null));
        assertEquals("a b", v.upstreamHeaders.get("X-Auth-Scope"));
        assertEquals("urn:x urn:y", v.upstreamHeaders.get("X-Auth-Acr"));
        assertEquals("client-z", sent(t).get("subject").get("properties").get("client_id").asText());
    }

    @Test
    void sendsALoginChallengeWithAnAcrHintWhenNoUserIsPresent() {
        AuthZenRuleConfiguration c = baseConf();
        c.require_user_login = true;
        Verdict v = pep(c, pdp(obj("decision", true))).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals(401, v.status);
        assertTrue(v.header("WWW-Authenticate").contains("insufficient_user_authentication"));
        assertEquals("urn:pingidentity:loa:password", body(v).get("acr_values").asText());
    }

    @Test
    void carriesAnInternalTransferFlagAndADefaultAccountTypeIntoTheRequest() {
        FakeTransport t = pdp(obj("decision", true));
        pep(baseConf(), t).decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice"))),
            "{\"from_account\":\"a\",\"to_account\":\"b\",\"amount\":5,\"internal_transfer\":true}"));
        assertTrue(sent(t).get("context").get("internal_transfer").booleanValue());
        FakeTransport t2 = pdp(obj("decision", true));
        pep(baseConf(), t2).decide(req("POST", "/accounts", Map.of("authorization", bearer(obj("sub", "alice"))), "{}"));
        assertEquals("new:savings", sent(t2).get("resource").get("id").asText());
    }

    // ---------- subject.identity -> subject.id migration ----------

    private static ObjectNode sentSubject(AuthZenRuleConfiguration c) {
        FakeTransport t = pdp(obj("decision", true));
        pep(c, t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice", "act", obj("sub", "agent-7"), "client_id", "c1"))), null));
        return (ObjectNode) sent(t).get("subject");
    }

    @Test
    void sendsAuthzenIdAndTheLegacyIdentityByDefault() {
        ObjectNode s = sentSubject(baseConf());
        assertEquals("agent-7", s.get("id").asText());
        assertEquals("alice", s.get("properties").get("on_behalf_of").asText());
        assertEquals("agent-7", s.get("identity").asText());
        assertEquals("agent", s.get("type").asText());
        assertEquals("ai_assistant", s.get("properties").get("agent_type").asText());
        assertEquals("c1", s.get("properties").get("client_id").asText());
    }

    @Test
    void dropsTheLegacyIdentityWhenTurnedOff() {
        AuthZenRuleConfiguration c = baseConf();
        c.legacy_subject_identity = false;
        ObjectNode s = sentSubject(c);
        assertFalse(s.has("identity"));
        assertEquals("agent-7", s.get("id").asText());
    }

    @Test
    void fallsBackToClientIdThenAPlaceholder() {
        FakeTransport t = pdp(obj("decision", true));
        pep(baseConf(), t).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice", "client_id", "c1"))), null));
        assertEquals("c1", sent(t).get("subject").get("id").asText());
        FakeTransport t2 = pdp(obj("decision", true));
        pep(baseConf(), t2).decide(req("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals("unknown-agent", sent(t2).get("subject").get("id").asText());
    }

    // ---------- what PingAccess established wins ----------

    @Test
    void prefersTheIdentityPingAccessValidatedOverTheTokensOwnPayload() {
        FakeTransport t = pdp(obj("decision", true));
        // The application is protected: PingAccess validated an opaque token by
        // introspection and handed the rule what it learned.
        PepRequest r = new PepRequest("GET", "/accounts/a/balance", Map.of("authorization", "Bearer opaque-token"), null,
            obj("sub", "alice", "client_id", "c9", "scope", "accounts:read", "act", obj("sub", "agent-3")));
        Verdict v = pep(baseConf(), t).decide(r);
        assertTrue(v.permit);
        assertEquals("alice", v.upstreamHeaders.get("X-Auth-Principal"));
        assertEquals("agent-3", v.upstreamHeaders.get("X-Auth-Agent"));
        assertEquals("c9", sent(t).get("subject").get("properties").get("client_id").asText());
        // A JWT whose payload disagrees with what PingAccess established loses.
        FakeTransport t2 = pdp(obj("decision", true));
        PepRequest r2 = new PepRequest("GET", "/accounts/a/balance", Map.of("authorization", bearer(obj("sub", "mallory", "scope", "everything"))), null,
            obj("sub", "alice", "scope", "accounts:read"));
        Verdict v2 = pep(baseConf(), t2).decide(r2);
        assertEquals("alice", v2.upstreamHeaders.get("X-Auth-Principal"));
        assertEquals("accounts:read", v2.upstreamHeaders.get("X-Auth-Scope"));
    }

    // ---------- discovery through decide() ----------

    static AuthZenRuleConfiguration discoveryConf() {
        AuthZenRuleConfiguration c = baseConf();
        c.authzen_url = STATIC;
        c.pdp_discovery = "resource";
        c.resource = RES;
        return c;
    }

    @Test
    void forwardsTheResourceDocumentAndTheRawTokenWhenAsked() {
        ObjectNode doc = resourceDoc(GOOD);
        doc.putArray("scopes_supported").add("accounts:read");
        FakeTransport t = new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", doc)
            .route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD))
            .route(GOOD + "/custom/eval", obj("decision", true));
        AuthZenRuleConfiguration c = discoveryConf();
        c.forward_access_token = true;
        String token = jwt(obj("sub", "alice"));
        Verdict v = pep(c, t).decide(req("GET", "/accounts/a1/balance", Map.of("authorization", "Bearer " + token), null));
        assertTrue(v.permit);
        ObjectNode ctx = (ObjectNode) Json.parse(t.to("/custom/eval").get(0).body()).get("context");
        assertEquals("rfc9728", ctx.get("resource_metadata_source").asText());
        assertEquals("accounts:read", ctx.get("resource_metadata").get("scopes_supported").get(0).asText());
        assertEquals(token, ctx.get("access_token").asText());
        assertNull(t.to("/custom/eval").get(0).headers().get("Authorization"), "a discovered PDP never receives the static key");
    }

    @Test
    void everyLayerIsAskedInOrderAndTheFirstDenyIsTheAnswer() {
        List<String> calls = new ArrayList<>();
        FakeTransport t = new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD))
            .route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD))
            .route(ESTATE + "/.well-known/authzen-configuration", pdpConfig(ESTATE))
            .route(ESTATE + "/custom/eval", (Function<Transport.Request, Transport.Response>) r -> {
                calls.add("estate");
                JsonNode b = Json.parse(r.body());
                if ("risky".equals(b.get("subject").get("properties").get("client_id").asText())) {
                    return FakeTransport.json(200, obj("decision", false, "context", obj("reason", "client on the watch list")));
                }
                return FakeTransport.json(200, obj("decision", true));
            })
            .route(GOOD + "/custom/eval", (Function<Transport.Request, Transport.Response>) r -> {
                calls.add("resource");
                return FakeTransport.json(200, obj("decision", true));
            });
        AuthZenRuleConfiguration c = discoveryConf();
        c.pdp_layers = List.of(ESTATE, "resource");
        Pep p = pep(c, t);
        Verdict ok = p.decide(req("GET", "/accounts/a1/balance", Map.of("authorization", bearer(obj("sub", "alice", "client_id", "good-client"))), null));
        assertTrue(ok.permit);
        assertEquals(List.of("estate", "resource"), calls);
        calls.clear();
        Verdict denied = p.decide(req("GET", "/accounts/a1/balance", Map.of("authorization", bearer(obj("sub", "alice", "client_id", "risky"))), null));
        assertEquals(403, denied.status);
        assertTrue(body(denied).get("reason").asText().contains("watch list"));
        assertEquals(List.of("estate"), calls);
    }

    @Test
    void aDiscoveryFailureIsA503() {
        FakeTransport t = new FakeTransport().route(RES + "/.well-known/oauth-protected-resource", resourceDoc("https://forbidden.example"))
            .route("https://forbidden.example", pdpConfig("https://forbidden.example"));
        AuthZenRuleConfiguration c = discoveryConf();
        c.pdp_allowlist = List.of("https://pdp.example");
        Verdict v = pep(c, t).decide(req("GET", "/accounts/a1/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
        assertEquals(503, v.status);
        assertTrue(body(v).get("reason").asText().contains("could not be resolved"));
    }

    static final String DOWN = "https://down.example";

    private static FakeTransport failOpenRoutes(Object goodEval) {
        return new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD))
            .route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD))
            .route(GOOD + "/custom/eval", goodEval)
            .route(DOWN + "/.well-known/authzen-configuration", 404)
            .route(DOWN + "/access/v1/evaluation", 503);
    }

    private static Verdict drive(AuthZenRuleConfiguration c, FakeTransport t) {
        return pep(c, t).decide(req("GET", "/accounts/a1/balance", Map.of("authorization", bearer(obj("sub", "alice"))), null));
    }

    @Test
    void closedByDefaultAFailingLayerIsA503() {
        AuthZenRuleConfiguration c = discoveryConf();
        c.pdp_layers = List.of(DOWN, "resource");
        assertEquals(503, drive(c, failOpenRoutes(obj("decision", true))).status);
    }

    @Test
    void openOnTheLayerSkippedTheRestDecidesAndThePermitIsMarked() {
        AuthZenRuleConfiguration c = discoveryConf();
        c.pdp_layers = List.of(DOWN + " fail-open", "resource");
        FakeTransport t = failOpenRoutes(obj("decision", true));
        Verdict v = drive(c, t);
        assertTrue(v.permit);
        assertEquals(GOOD + "/custom/eval", t.last().url());
        assertTrue(v.responseHeaders.get("X-PDP-Fail-Open").startsWith(DOWN));
        assertEquals("PERMIT", v.responseHeaders.get("X-PDP-Decision"));
        // Nothing skipped, no marker.
        AuthZenRuleConfiguration clean = discoveryConf();
        clean.pdp_layers = List.of("resource");
        Verdict cv = drive(clean, failOpenRoutes(obj("decision", true)));
        assertTrue(cv.permit);
        assertNull(cv.responseHeaders.get("X-PDP-Fail-Open"));
    }

    @Test
    void failModeOnTheRouteIsTheDefaultTheLayersOwnWordWinsEverythingSkippedIsAMarkedPermit() {
        AuthZenRuleConfiguration c = discoveryConf();
        c.fail_mode = "open";
        c.pdp_layers = List.of(DOWN, "resource");
        Verdict v = drive(c, failOpenRoutes(obj("decision", true)));
        assertTrue(v.permit);
        assertNotEquals(null, v.responseHeaders.get("X-PDP-Fail-Open"));
        AuthZenRuleConfiguration strict = discoveryConf();
        strict.fail_mode = "open";
        strict.pdp_layers = List.of(DOWN + " fail-closed", "resource");
        assertEquals(503, drive(strict, failOpenRoutes(obj("decision", true))).status);
        AuthZenRuleConfiguration all = discoveryConf();
        all.fail_mode = "open";
        all.pdp_layers = List.of(DOWN);
        Verdict av = drive(all, failOpenRoutes(obj("decision", true)));
        assertTrue(av.permit);
        assertTrue(av.responseHeaders.get("X-PDP-Reason").contains("fail-open"));
    }

    @Test
    void aDenyIsADecisionNeverSkippedAnUnreadablePolicyFailsClosed() {
        AuthZenRuleConfiguration c = discoveryConf();
        c.fail_mode = "open";
        c.pdp_layers = List.of("resource fail-open");
        Verdict v = drive(c, failOpenRoutes(obj("decision", false, "context", obj("reason", "no"))));
        assertEquals(403, v.status);
        assertEquals("no", body(v).get("reason").asText());
        AuthZenRuleConfiguration bad = discoveryConf();
        bad.fail_mode = "open";
        bad.pdp_layers = List.of("resource maybe");
        assertEquals(503, drive(bad, failOpenRoutes(obj("decision", true))).status);
    }

    // ---------- federation entity relay ----------

    @Test
    void servesTheTwoWellKnownDocumentsFromCoazPepAndNothingElse() {
        FakeTransport t = pdp(obj("decision", true))
            .route(COAZ + "/.well-known/openid-federation", (Function<Transport.Request, Transport.Response>) r ->
                new Transport.Response(200, Map.of("Content-Type", "application/entity-statement+jwt"), "eyJ.a.b".getBytes(StandardCharsets.UTF_8)))
            .route(COAZ + "/.well-known/oauth-protected-resource/bank", (Function<Transport.Request, Transport.Response>) r ->
                new Transport.Response(200, Map.of("content-type", "application/json"), "{\"resource\":\"x\"}".getBytes(StandardCharsets.UTF_8)))
            .route(COAZ + "/.well-known/oauth-protected-resource", Boolean.FALSE)
            .route(COAZ + "/api/.well-known/openid-federation", (Function<Transport.Request, Transport.Response>) r ->
                new Transport.Response(200, Map.of(), "no-type".getBytes(StandardCharsets.UTF_8)));
        AuthZenRuleConfiguration c = baseConf();
        c.federation_entity_url = COAZ;
        Pep p = pep(c, t);
        Verdict fed = p.decide(req("GET", "/.well-known/openid-federation", Map.of(), null));
        assertEquals(200, fed.status);
        assertEquals("eyJ.a.b", fed.bodyText());
        assertEquals("application/entity-statement+jwt", fed.header("Content-Type"));
        assertEquals("no-cache", fed.header("Cache-Control"));
        Verdict res = p.decide(req("GET", "/.well-known/oauth-protected-resource/bank", Map.of(), null));
        assertEquals("{\"resource\":\"x\"}", res.bodyText());
        assertEquals("application/json", res.header("Content-Type"));
        Verdict down = p.decide(req("GET", "/.well-known/oauth-protected-resource", Map.of(), null));
        assertEquals(503, down.status);
        assertEquals("federation_entity_unavailable", body(down).get("error").asText());
        // An identifier with a path: the federation document sits under it.
        Verdict sub = p.decide(req("GET", "/api/.well-known/openid-federation", Map.of(), null));
        assertEquals("no-type", sub.bodyText());
        assertEquals("application/json", sub.header("Content-Type"), "defaulted when the relay names none");
        // Everything else on the route is untouched: no token, so the ordinary deny.
        Verdict other = p.decide(req("GET", "/.well-known/other", Map.of(), null));
        assertEquals(401, other.status);
        assertEquals(0, t.count("/.well-known/other"));
        // Without the knob the well-known path is an ordinary request.
        Verdict plain = pep(baseConf(), t).decide(req("GET", "/.well-known/openid-federation", Map.of(), null));
        assertEquals(401, plain.status);
    }

    // ---------- X-User-Token verification ----------

    @Test
    void verifiesTheUserTokenWhenAJwksIsConfiguredAndClosesTheGatesWhenItFails() throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("k1");
        EllipticCurveJsonWebKey other = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        other.setKeyId("k1");
        String jwks = new JsonWebKeySet(key).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", ex -> {
            byte[] b = jwks.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        });
        server.start();
        try {
            String jwksUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
            UserTokens.Reader reader = UserTokens.verified(jwksUrl, "https://as.example", "https://api.example");
            AuthZenRuleConfiguration c = baseConf();
            c.require_user_login = true;
            FakeTransport t = pdp(obj("decision", true));
            Pep p = new Pep(c, t, new Discovery(t, () -> 1_000_000L), reader);

            String good = sign(key, "{\"sub\":\"alice\",\"scope\":\"payments:approve\",\"iss\":\"https://as.example\",\"aud\":\"https://api.example\"}");
            Verdict ok = p.decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice")), "x-user-token", good), "{\"amount\":5}"));
            assertTrue(ok.permit);
            assertEquals("payments:approve", sent(t).get("context").get("user_scope").asText());

            String forged = sign(other, "{\"sub\":\"alice\",\"scope\":\"payments:approve\",\"iss\":\"https://as.example\",\"aud\":\"https://api.example\"}");
            assertEquals(401, p.decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice")), "x-user-token", forged), "{}")).status);
            String wrongIssuer = sign(key, "{\"sub\":\"alice\",\"iss\":\"https://evil.example\",\"aud\":\"https://api.example\"}");
            assertEquals(401, p.decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice")), "x-user-token", wrongIssuer), "{}")).status);
            String none = jwt(obj("sub", "alice", "iss", "https://as.example", "aud", "https://api.example"));
            assertEquals(401, p.decide(req("POST", "/payments", Map.of("authorization", bearer(obj("sub", "alice")), "x-user-token", none), "{}")).status, "alg none is refused");
            assertNull(reader.claims(null));

            // Without an expected issuer or audience, only the signature and times gate.
            UserTokens.Reader lax = UserTokens.verified(jwksUrl, null, null);
            assertEquals("alice", lax.claims(sign(key, "{\"sub\":\"alice\"}")).get("sub").asText());
        } finally {
            server.stop(0);
        }
    }

    private static String sign(EllipticCurveJsonWebKey key, String payload) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        return jws.getCompactSerialization();
    }

    // A permitting layer's obligation must survive a later layer's plain permit.
    //
    // This is the test that was missing. Each layer was individually correct; the defect
    // lived in how two correct permits combined, so the estate PDP's "permit, but step up"
    // was erased by the resource PDP's permit and the request was forwarded with no
    // challenge at all.
    private static FakeTransport twoLayers(Object estateEval, Object resourceEval) {
        return new FakeTransport()
            .route(RES + "/.well-known/oauth-protected-resource", resourceDoc(GOOD))
            .route(GOOD + "/.well-known/authzen-configuration", pdpConfig(GOOD))
            .route(ESTATE + "/.well-known/authzen-configuration", pdpConfig(ESTATE))
            .route(ESTATE + "/custom/eval", estateEval)
            .route(GOOD + "/custom/eval", resourceEval);
    }

    private static Verdict layered(Object estateEval, Object resourceEval) {
        AuthZenRuleConfiguration c = discoveryConf();
        c.pdp_layers = List.of(ESTATE, "resource");
        return drive(c, twoLayers(estateEval, resourceEval));
    }

    @Test
    void aPermittingLayersStepUpSurvivesALaterPlainPermit() {
        Verdict v = layered(
            obj("decision", true, "context", obj("reason", "step up for this amount",
                "step_up_required", true, "step_up_scope", "banking:payments:transfer")),
            obj("decision", true, "context", obj("reason", "resource is fine")));
        assertEquals(401, v.status, "the estate layer required a step-up; the resource layer's permit must not erase it");
        assertEquals("insufficient_scope", body(v).get("error").asText());
        assertEquals("banking:payments:transfer", body(v).get("scope").asText());
        assertEquals("step up for this amount", body(v).get("reason").asText());
    }

    @Test
    void aPermittingLayersIdentityProofingSurvivesALaterPlainPermit() {
        Verdict v = layered(
            obj("decision", true, "context", obj("reason", "prove who you are",
                "identity_proofing_required", true, "identity_proofing_doctype", "org.iso.18013.5.1.mDL")),
            obj("decision", true, "context", obj("reason", "resource is fine")));
        assertEquals(401, v.status);
        assertEquals("identity_verification_required", body(v).get("error").asText());
        assertEquals("org.iso.18013.5.1.mDL", body(v).get("doctype").asText());
    }

    @Test
    void anObligationFromTheLastLayerSurvivesToo() {
        Verdict v = layered(
            obj("decision", true, "context", obj("reason", "estate is fine")),
            obj("decision", true, "context", obj("reason", "step up", "step_up_required", true, "step_up_scope", "s")));
        assertEquals(401, v.status);
        assertEquals("s", body(v).get("scope").asText());
    }

    @Test
    void theRequiringLayerOwnsTheParameterWhenBothAskForOne() {
        Verdict v = layered(
            obj("decision", true, "context", obj("reason", "first", "step_up_required", true, "step_up_scope", "first-scope")),
            obj("decision", true, "context", obj("reason", "second", "step_up_required", true, "step_up_scope", "second-scope")));
        assertEquals("first-scope", body(v).get("scope").asText());
        assertEquals("first", body(v).get("reason").asText());
    }

    @Test
    void twoPlainPermitsAreStillAPlainPermit() {
        Verdict v = layered(obj("decision", true), obj("decision", true));
        assertTrue(v.permit, "nothing was required, so nothing should be challenged");
    }

}

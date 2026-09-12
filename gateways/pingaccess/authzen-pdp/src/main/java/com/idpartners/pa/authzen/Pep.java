package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The Policy Enforcement Point: a port of the Kong plugin's access() phase, so a client
 * gets the same decision and the same challenge from PingAccess as from Kong, Envoy or
 * the Node SDK. For every request it:
 *
 * <ol>
 *   <li>extracts the delegated access token (DPoP or Bearer) and reads its claims (sub =
 *       principal, act.sub = acting agent, scope, acr), preferring what PingAccess itself
 *       established when the application is protected;</li>
 *   <li>if DPoP is required, delegates the sender-constraint check to coaz-pep, which
 *       verifies the proof's signature, iat, jti and the cnf.jkt/htm/ath binding
 *       (RFC 9449);</li>
 *   <li>on an MCP route with coaz_url, delegates tools/call to the COAZ engine and relays
 *       its verdict verbatim;</li>
 *   <li>builds an AuthZEN evaluation request (subject = agent on behalf of principal,
 *       action + resource + context from the HTTP request), resolves which PDPs decide
 *       for this resource, and asks each layer in order;</li>
 *   <li>PERMIT: lets the request through with X-Auth-* headers for the resource server's
 *       audit trail; DENY: 403 with the policy reason, or a 401 challenge when the policy
 *       says what would resolve it.</li>
 * </ol>
 *
 * <p>Everything fails closed: an unreachable PDP, verifier or engine is a deny, never a
 * pass.
 */
final class Pep {
    private static final Logger log = LoggerFactory.getLogger(Pep.class);
    private static final String FED_WK = "/.well-known/openid-federation";
    private static final String RES_WK = "/.well-known/oauth-protected-resource";
    private static final String JSON = "application/json";
    private static final String DEFAULT_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String LOGIN_ACR = "urn:pingidentity:loa:password";

    private final AuthZenRuleConfiguration conf;
    private final Transport transport;
    private final Discovery discovery;
    private final UserTokens.Reader userTokens;

    Pep(AuthZenRuleConfiguration conf, Transport transport, Discovery discovery, UserTokens.Reader userTokens) {
        this.conf = conf;
        this.transport = transport;
        this.discovery = discovery;
        this.userTokens = userTokens;
    }

    String label() {
        return blank(conf.pep_label) ? "pingaccess-pep" : conf.pep_label;
    }

    Verdict decide(PepRequest req) {
        String pep = label();

        // The resource's federation face, before any token is looked at: these
        // documents are public by definition.
        if (!blank(conf.federation_entity_url) && isWellKnown(req.path)) {
            return relayWellKnown(req.path);
        }

        // 0) Step-up: require a logged-in END USER (RFC 9470). The principal
        //    authenticates at the AS; the app forwards their token down the agent chain
        //    as X-User-Token. Without a valid one, push back a login challenge.
        if (conf.require_user_login) {
            ObjectNode user = userClaims(req);
            if (user == null || !user.hasNonNull("sub")) {
                ObjectNode body = Json.object();
                body.put("error", "login_required");
                body.put("pep", pep);
                body.put("reason", "The gateway requires an authenticated user (no valid X-User-Token).");
                body.put("acr_values", LOGIN_ACR);
                return Verdict.respond(401, headers(JSON,
                        "WWW-Authenticate", "Bearer error=\"insufficient_user_authentication\", "
                            + "error_description=\"Login required\", acr_values=\"" + LOGIN_ACR + "\""),
                    Json.bytes(body), null);
            }
        }

        // 1) token + claims
        Jwt.Token token = Jwt.extractToken(req.header("authorization"));
        if (token == null && conf.require_token) {
            return deny(pep, 401, "No access token presented to the gateway.", null);
        }
        ObjectNode claims = mergeClaims(token == null ? null : Jwt.claims(token.value()), req.identityClaims);
        String sub = Json.text(claims, "sub");
        String act = actSub(claims);
        String scope = joined(claims, "scope", "scp");
        String clientId = first(claims, "client_id", "azp");
        // The authentication context the AS asserted, forwarded so a resource server can
        // decide "is this a staff channel?" from a claim rather than a username list.
        String acr = joined(claims, "acr");

        if (conf.require_token && sub == null) {
            return deny(pep, 401, "Access token missing or unreadable (no subject claim).", null);
        }

        // 2) DPoP sender-constraint binding, delegated
        if (conf.require_dpop) {
            Verdict v = verifyDpop(req, pep);
            if (v != null) {
                return v;
            }
        }

        // 2b) COAZ: tools/call on an MCP route goes to the engine, which discovers the
        //     tool's mapping, evaluates it, asks the PDP and returns either a permit or
        //     the profile's JSON-RPC error to relay verbatim.
        if ("mcp".equals(conf.style) && !blank(conf.coaz_url)) {
            JsonNode rpc = Json.parse(req.body);
            if (rpc instanceof ObjectNode && "tools/call".equals(Json.text(rpc, "method"))) {
                return coazCheck(req, pep, rpc);
            }
        }

        // 3) build the AuthZEN evaluation request
        RequestMapper.Mapped m = RequestMapper.map(conf.style, req.method, req.path, req.body);
        Map<String, String> upstream = authHeaders(sub, act, scope, acr);

        // MCP handshake / non-tool traffic: allow on a valid token, skip the PDP.
        if (RequestMapper.ALLOW.equals(m.action())) {
            return Verdict.permit(upstream, pdpHeaders(pep, "PERMIT", "mcp-handshake",
                "MCP handshake allowed (authenticated); policy applies to tool calls.", null));
        }

        // 3b) Carry the USER's consented scope into the context. The step-up decision is
        //     the PDP's: it compares the amount to its threshold and checks whether this
        //     scope already satisfies it, then returns advice honoured below.
        ObjectNode user = userClaims(req);
        String uscope = user == null ? null : joined(user, "scope", "scp");
        m.ctx().put("user_scope", uscope == null ? "" : uscope);

        // AuthZEN 1.0 names the subject identifier `id`. The legacy `identity` is sent
        // beside it while legacy_subject_identity is on, in lockstep with the other PEPs.
        String agentId = act != null ? act : clientId != null ? clientId : "unknown-agent";
        ObjectNode subject = Json.object();
        subject.put("type", "agent");
        subject.put("id", agentId);
        ObjectNode props = subject.putObject("properties");
        putIf(props, "on_behalf_of", sub);
        props.put("agent_type", "ai_assistant");
        putIf(props, "scope", scope);
        putIf(props, "client_id", clientId);
        if (conf.legacy_subject_identity) {
            subject.put("identity", agentId);
        }

        ObjectNode authzenReq = Json.object();
        authzenReq.set("subject", subject);
        authzenReq.putObject("action").put("name", m.action());
        ObjectNode resource = authzenReq.putObject("resource");
        resource.put("type", m.rtype());
        putIf(resource, "id", m.rid());
        resource.set("properties", m.rprops());
        authzenReq.set("context", m.ctx());

        // 3c) which PDPs, and where. A discovery failure is a 503, like an unreachable
        //     PDP: a request whose decider cannot be found is not one to let through.
        Discovery.Layers layers;
        try {
            layers = discovery.resolveLayers(conf, Discovery.resourceId(conf), conf.pdp_layers, "open".equals(conf.fail_mode));
        } catch (Discovery.Failure e) {
            log.error("PDP discovery failed: {}", e.getMessage());
            return deny(pep, 503, "Authorization service could not be resolved; denying (fail-closed).", null);
        }

        // 3d) What the PDP gets to reason with beyond the mapped action and resource:
        //     the resource's declared posture verbatim, with its source; the endpoint
        //     actually hit; the raw token when the route allows it. The rule enforces
        //     none of these: what a resource requires is the PDP's to match.
        if (layers.meta() != null) {
            m.ctx().set("resource_metadata", layers.meta().document());
            m.ctx().put("resource_metadata_source", layers.meta().source());
        }
        ObjectNode request = m.ctx().putObject("request");
        request.put("method", req.method);
        request.put("path", req.path);
        if (conf.forward_access_token && token != null) {
            m.ctx().put("access_token", token.value());
        }

        // 4) ask each layer in order. Every layer must permit; the first that does not
        //    is the answer, advice and all. A PDP error fails closed unless the layer is
        //    fail-open, in which case it is skipped and named. A deny is never skipped.
        byte[] body = Json.bytes(authzenReq);
        List<String> skipped = new ArrayList<>(layers.skipped());
        boolean decided = false;
        boolean decision = false;
        ObjectNode dctx = Json.object();
        String reason = null;
        for (Discovery.Endpoints ep : layers.pdps()) {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("Content-Type", JSON);
            if (ep.apiKey != null) {
                h.put("Authorization", "Bearer " + ep.apiKey); // bound to the PDP it was configured for
            }
            Transport.Response res = null;
            String failure = null;
            try {
                res = transport.send(new Transport.Request("POST", ep.evaluation, h, body, conf.pdp_timeout_ms, conf.pdp_ssl_verify));
                if (res.status() < 200 || res.status() >= 300) {
                    failure = "returned " + res.status();
                }
            } catch (IOException e) {
                failure = String.valueOf(e.getMessage());
            }
            if (failure != null) {
                if (!ep.failOpen) {
                    log.error("PDP call failed ({}): {}", ep.identifier, failure);
                    return deny(pep, 503, "Authorization service unreachable; denying (fail-closed).", null);
                }
                log.warn("PDP layer {} failed open: {}", ep.identifier, failure);
                skipped.add(ep.identifier + " (" + failure + ")");
                continue;
            }
            decided = true;
            JsonNode data = Json.parse(res.body());
            JsonNode d = data == null ? Json.object() : data;
            JsonNode dec = d.get("decision");
            decision = dec != null && dec.isBoolean() && dec.booleanValue();
            JsonNode c = d.get("context");
            ObjectNode lctx = c instanceof ObjectNode ? (ObjectNode) c : Json.object();
            String r = Json.text(lctx, "reason");
            String lreason = r != null ? r : decision ? "Permitted by policy." : "Denied by policy.";
            if (!decision) {
                // A deny is reported with its own advice; later layers are not consulted.
                dctx = lctx;
                reason = lreason;
                break;
            }
            // A permit: obligations accumulate. See mergePermit.
            if (!hasObligation(dctx)) {
                reason = lreason;
            }
            dctx = mergePermit(dctx, lctx);
        }
        if (!decided) {
            decision = true;
            dctx = Json.object();
            reason = "fail-open: no policy layer could be reached (" + String.join("; ", skipped) + ")";
        }
        String failOpen = null;
        if (!skipped.isEmpty()) {
            failOpen = String.join(", ", skipped);
            log.warn("permit failed open past: {}", failOpen);
        }
        Map<String, String> rh = pdpHeaders(pep, decision ? "PERMIT" : "DENY", m.action(), reason, failOpen);

        // Identity-proofing advice: challenge for a credential presentation rather than a
        // flat deny. Ordered before step-up because identity is the more fundamental
        // gate: resolve it first and let the retry surface any step-up.
        if (Json.truthy(dctx, "identity_proofing_required")) {
            String doctype = Json.text(dctx, "identity_proofing_doctype");
            if (doctype == null) {
                doctype = DEFAULT_DOCTYPE;
            }
            ObjectNode out = Json.object();
            out.put("error", "identity_verification_required");
            out.put("doctype", doctype);
            out.put("pep", pep);
            out.put("reason", reason);
            ObjectNode ch = out.putObject("authz_challenge");
            ch.put("type", "identity_proofing");
            ch.put("doctype", doctype);
            ch.put("reason", reason);
            ch.put("pep", pep);
            return Verdict.respond(401, headers(JSON, "WWW-Authenticate",
                "Bearer error=\"identity_verification_required\", doctype=\"" + doctype + "\""), Json.bytes(out), rh);
        }

        // Step-up advice: this payment is over the threshold and the user has not
        // approved it yet. Challenge for the step-up scope (RFC 9470).
        if (Json.truthy(dctx, "step_up_required")) {
            String scopeReq = Json.text(dctx, "step_up_scope");
            if (scopeReq == null) {
                scopeReq = conf.stepup_scope == null ? "" : conf.stepup_scope;
            }
            ObjectNode out = Json.object();
            out.put("error", "insufficient_scope");
            out.put("scope", scopeReq);
            out.put("pep", pep);
            out.put("reason", reason);
            ObjectNode ch = out.putObject("authz_challenge");
            ch.put("type", "resource_authorisation");
            ch.put("scope", scopeReq);
            ch.put("reason", reason);
            ch.put("pep", pep);
            return Verdict.respond(401, headers(JSON, "WWW-Authenticate",
                "Bearer error=\"insufficient_scope\", scope=\"" + scopeReq + "\""), Json.bytes(out), rh);
        }

        if (!decision) {
            return deny(pep, 403, reason, rh);
        }

        // PERMIT: pass the delegation identity to the upstream for its audit trail.
        return Verdict.permit(upstream, rh);
    }

    // ---------- the delegated checks ----------

    private Verdict verifyDpop(PepRequest req, String pep) {
        // The rule cannot verify a proof itself with any honesty: a thumbprint comparison
        // proves nothing when the proof carries the very JWK being compared. configure()
        // refuses require_dpop without coaz_url, so this is unreachable; it is kept
        // because a route that demands sender-constrained tokens and cannot verify them
        // must fail closed, never fall back to a weaker check.
        if (blank(conf.coaz_url)) {
            log.error("require_dpop is set but coaz_url is not: cannot verify DPoP proofs, denying");
            return deny(pep, 401, "DPoP verification is unavailable on this route (no coaz_url configured); "
                + "denying rather than accepting an unverified sender-constraint.", null);
        }
        ObjectNode body = Json.object();
        body.put("method", req.method);
        body.put("path", req.path);
        body.put("pep_label", pep);
        ObjectNode h = body.putObject("headers");
        putIf(h, "authorization", req.header("authorization"));
        putIf(h, "dpop", req.header("dpop"));
        Transport.Response res;
        try {
            res = transport.send(new Transport.Request("POST", conf.coaz_url + "/v1/dpop/verify",
                coazHeaders(), Json.bytes(body), 5000, conf.pdp_ssl_verify));
        } catch (IOException e) {
            log.error("DPoP verification call failed: {}", e.getMessage());
            return deny(pep, 401, "DPoP verification service unreachable; denying (fail-closed).", null);
        }
        if (res.status() != 200) {
            log.error("DPoP verification returned {}", res.status());
            return deny(pep, 401, "DPoP verification failed; denying (fail-closed).", null);
        }
        JsonNode verdict = Json.parse(res.body());
        JsonNode valid = verdict == null ? null : verdict.get("valid");
        if (!(verdict instanceof ObjectNode) || valid == null || !valid.isBoolean() || !valid.booleanValue()) {
            String reason = Json.text(verdict, "reason");
            return deny(pep, 401, reason != null ? reason : "DPoP proof is not valid for this request.", null);
        }
        return null;
    }

    private Verdict coazCheck(PepRequest req, String pep, JsonNode rpc) {
        ObjectNode config = Json.object();
        config.put("pep_label", pep);
        config.put("style", "mcp");
        putIf(config, "mcp_upstream_url", conf.mcp_upstream_url);
        config.put("coaz_defaults", conf.coaz_defaults ? "true" : "false");
        // The engine runs its own PDP discovery (federation included); an explicit
        // resource identifier is passed so both PEPs key off the same one.
        if (!blank(conf.resource)) {
            config.put("resource", conf.resource);
        }
        if (conf.forward_access_token) {
            config.put("forward_access_token", "true");
        }
        if (conf.pdp_layers != null && !conf.pdp_layers.isEmpty()) {
            config.put("pdp_layers", String.join(",", conf.pdp_layers));
        }
        if (conf.fail_mode != null && !conf.fail_mode.equals("closed")) {
            config.put("fail_mode", conf.fail_mode);
        }
        ObjectNode body = Json.object();
        body.set("config", config);
        body.put("method", req.method);
        body.put("path", req.path);
        ObjectNode h = body.putObject("headers");
        putIf(h, "authorization", req.header("authorization"));
        putIf(h, "x-user-token", req.header("x-user-token"));
        body.put("body", req.body == null ? "" : new String(req.body, StandardCharsets.UTF_8));

        JsonNode params = rpc.get("params");
        String toolName = Json.text(params, "name");
        String fallbackAction = "tools/call:" + (toolName == null ? "?" : toolName);

        Transport.Response res;
        try {
            res = transport.send(new Transport.Request("POST", conf.coaz_url + "/v1/mcp/check",
                coazHeaders(), Json.bytes(body), conf.coaz_timeout_ms, conf.pdp_ssl_verify));
        } catch (IOException e) {
            log.error("coaz-pep engine call failed: {}", e.getMessage());
            return deny(pep, 503, "COAZ authorization engine unreachable; denying (fail-closed).", null);
        }
        if (res.status() != 200) {
            log.error("coaz-pep engine call failed: {}", res.status());
            return deny(pep, 503, "COAZ authorization engine unreachable; denying (fail-closed).", null);
        }
        JsonNode verdict = Json.parse(res.body());
        if (!(verdict instanceof ObjectNode)) {
            verdict = Json.object();
        }
        JsonNode dec = verdict.get("decision");
        if (dec != null && dec.isBoolean() && dec.booleanValue()) {
            Map<String, String> rh = stringMap(verdict.get("response_headers"));
            String action = rh.getOrDefault("X-PDP-Action", fallbackAction);
            return Verdict.permit(stringMap(verdict.get("upstream_headers")),
                pdpHeaders(pep, "PERMIT", action, rh.get("X-PDP-Reason"), null));
        }
        JsonNode resp = verdict.get("response");
        Map<String, String> rh = resp == null ? new LinkedHashMap<>() : stringMap(resp.get("headers"));
        String action = rh.getOrDefault("X-PDP-Action", fallbackAction);
        int status = resp != null && resp.get("status") != null && resp.get("status").isInt() ? resp.get("status").intValue() : 200;
        String respBody = resp == null ? null : Json.text(resp, "body");
        return Verdict.respond(status, rh, (respBody == null ? "" : respBody).getBytes(StandardCharsets.UTF_8),
            pdpHeaders(pep, "DENY", action, rh.get("X-PDP-Reason"), null));
    }

    /**
     * Serves the resource's federation face from coaz-pep, which holds the key: the
     * entity configuration a trust controller onboards, and the RFC 9728 document that
     * republishes what the federation resolved. PingAccess cannot sign, so it relays.
     */
    private Verdict relayWellKnown(String path) {
        Transport.Response res;
        try {
            res = transport.send(new Transport.Request("GET", conf.federation_entity_url + path, Map.of(), null, 5000, conf.pdp_ssl_verify));
        } catch (IOException e) {
            log.error("federation entity relay failed: {}", e.getMessage());
            return Verdict.respond(503, headers(JSON), "{\"error\":\"federation_entity_unavailable\"}".getBytes(StandardCharsets.UTF_8), null);
        }
        String ct = res.header("Content-Type");
        return Verdict.respond(res.status(), headers(ct == null ? JSON : ct, "Cache-Control", "no-cache"), res.body(), null);
    }

    static boolean isWellKnown(String path) {
        return path.equals(FED_WK) || path.equals(RES_WK) || path.endsWith(FED_WK) || path.startsWith(RES_WK + "/");
    }

    // ---------- claims ----------

    private ObjectNode userClaims(PepRequest req) {
        String ut = req.header("x-user-token");
        return ut == null ? null : userTokens.claims(ut);
    }

    /**
     * The token's own payload, overlaid with what PingAccess established about it. When
     * PingAccess validated the token its view wins; when the application is unprotected
     * there is only the payload, decoded and not verified, exactly as in Kong.
     */
    static ObjectNode mergeClaims(ObjectNode fromToken, ObjectNode fromIdentity) {
        ObjectNode out = Json.object();
        if (fromToken != null) {
            out.setAll(fromToken);
        }
        if (fromIdentity != null) {
            out.setAll(fromIdentity);
        }
        return out;
    }

    /** act (RFC 8693) may be a nested object or, from PingFederate's JWT ATM, a JSON string. */
    static String actSub(ObjectNode claims) {
        JsonNode act = claims.get("act");
        if (act != null && act.isTextual()) {
            act = Json.parse(act.asText());
        }
        return act instanceof ObjectNode ? Json.text(act, "sub") : null;
    }

    /** The first present of the named claims, joined with spaces when it is an array. */
    static String joined(ObjectNode claims, String... names) {
        for (String name : names) {
            JsonNode v = claims.get(name);
            if (v == null || v.isNull()) {
                continue;
            }
            if (v.isArray()) {
                List<String> parts = new ArrayList<>();
                for (Iterator<JsonNode> it = ((ArrayNode) v).elements(); it.hasNext(); ) {
                    parts.add(it.next().asText());
                }
                return String.join(" ", parts);
            }
            return v.asText();
        }
        return null;
    }

    private static String first(ObjectNode claims, String... names) {
        for (String name : names) {
            String v = Json.text(claims, name);
            if (v != null) {
                return v;
            }
        }
        return null;
    }

    // ---------- rendering ----------

    static Verdict deny(String pep, int status, String reason, Map<String, String> responseHeaders) {
        ObjectNode body = Json.object();
        body.put("error", "authorization_failed");
        body.put("pep", pep);
        body.put("reason", reason);
        return Verdict.respond(status, headers(JSON), Json.bytes(body), responseHeaders);
    }

    /** The response headers the demo transcript reads. Present only once a decision was made. */
    static Map<String, String> pdpHeaders(String pep, String decision, String action, String reason, String failOpen) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("X-PDP-PEP", pep);
        h.put("X-PDP-Decision", decision);
        if (failOpen != null) {
            h.put("X-PDP-Fail-Open", failOpen);
        }
        h.put("X-PDP-Action", action == null ? "" : action);
        if (reason != null) {
            h.put("X-PDP-Reason", reason);
        }
        return h;
    }

    private static Map<String, String> authHeaders(String sub, String act, String scope, String acr) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("X-Auth-Principal", sub == null ? "" : sub);
        h.put("X-Auth-Agent", act == null ? "" : act);
        h.put("X-Auth-Scope", scope == null ? "" : scope);
        h.put("X-Auth-Acr", acr == null ? "" : acr);
        return h;
    }

    private Map<String, String> coazHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", JSON);
        // Matches CHECK_API_TOKEN on the coaz-pep side. That endpoint takes a
        // caller-supplied upstream URL and relays a caller-supplied Authorization header,
        // so it authenticates its callers.
        if (!blank(conf.coaz_api_key)) {
            h.put("Authorization", "Bearer " + conf.coaz_api_key);
        }
        return h;
    }

    private static Map<String, String> headers(String contentType, String... rest) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", contentType);
        for (int i = 0; i + 1 < rest.length; i += 2) {
            h.put(rest[i], rest[i + 1]);
        }
        return h;
    }

    private static Map<String, String> stringMap(JsonNode node) {
        Map<String, String> out = new LinkedHashMap<>();
        if (node instanceof ObjectNode) {
            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> e = it.next();
                if (!e.getValue().isNull()) {
                    out.put(e.getKey(), e.getValue().asText());
                }
            }
        }
        return out;
    }

    private static void putIf(ObjectNode node, String field, String value) {
        if (value != null) {
            node.put(field, value);
        }
    }

    static boolean blank(String s) {
        return s == null || s.isEmpty();
    }

    /** Does this folded context already carry a challenge? */
    private static boolean hasObligation(ObjectNode ctx) {
        return Json.truthy(ctx, "identity_proofing_required") || Json.truthy(ctx, "step_up_required");
    }

    /**
     * Fold a permitting layer's context into the running one.
     *
     * Only the DECISION is a single answer; the OBLIGATIONS are cumulative. Replacing the
     * context wholesale let a later layer's plain permit erase an earlier layer's step-up
     * or identity-proofing requirement, and the request was then forwarded with no
     * challenge issued at all -- which defeats the point of putting a generic PDP in front
     * of the resource's own. The first layer to require something owns its parameter.
     */
    private static ObjectNode mergePermit(ObjectNode acc, ObjectNode layer) {
        ObjectNode out = layer.deepCopy();
        carry(out, acc, "identity_proofing_required", "identity_proofing_doctype");
        carry(out, acc, "step_up_required", "step_up_scope");
        return out;
    }

    private static void carry(ObjectNode out, ObjectNode acc, String flag, String param) {
        if (!Json.truthy(acc, flag)) {
            return;
        }
        out.put(flag, true);
        String v = Json.text(acc, param);
        if (v != null) {
            out.put(param, v);
        }
    }

}

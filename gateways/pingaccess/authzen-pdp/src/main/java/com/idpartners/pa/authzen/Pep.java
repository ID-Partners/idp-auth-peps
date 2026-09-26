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
import java.util.Locale;
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
    /** The largest evaluation request the rule will send: well over any real one, and under what a client could pad one to. */
    static final int MAX_EVALUATION = 2 * 1024 * 1024;
    static final String UNREACHABLE = "Authorization service unreachable; denying (fail-closed).";
    static final String REFUSED = "Authorization service refused the request; denying (fail-closed).";

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
        // 1a) Whose word is the token? On a protected application PingAccess validated it
        //     before this rule ran and hands over an identity. With none (an unprotected
        //     application) its claims are the client's own, and an unsigned token would
        //     become the subject and X-Auth-Principal. Refused, unless allow_insecure.
        if (token != null && req.identityClaims == null && !conf.allow_insecure) {
            log.warn("authzen-pdp '{}': an access token arrived that PingAccess did not validate (is the application "
                + "unprotected?); denying", pep);
            return deny(pep, 401, "The access token was not validated by the gateway.", null);
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

        // 2b) MCP: every request on the route is coaz-pep's to decide, whatever its
        //     method, once the rule is sure coaz-pep will judge exactly what the upstream
        //     would run. Nothing on an MCP route is let through on a token alone.
        if ("mcp".equals(conf.style)) {
            return mcp(req, pep);
        }

        // 3) build the AuthZEN evaluation request
        RequestMapper.Mapped m = RequestMapper.map(req.method, req.path, req.body);
        Map<String, String> upstream = authHeaders(sub, act, scope, acr);

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
        //    is the answer, advice and all. An unavailable PDP fails closed unless the
        //    layer is fail-open, in which case it is skipped and named. A deny is never
        //    skipped, and neither is a refusal: a 4xx, a redirect or an answer that is not
        //    a decision says nothing about the PDP being down, and a client must not be
        //    able to switch a layer off by provoking one.
        byte[] body = Json.bytes(authzenReq);
        if (body.length > MAX_EVALUATION) {
            log.error("the evaluation request is {} bytes, over the {}-byte bound; refusing to send it", body.length, MAX_EVALUATION);
            return deny(pep, 413, "The request is too large for the gateway to authorise.", null);
        }
        List<String> skipped = new ArrayList<>(layers.skipped());
        boolean decided = false;
        boolean decision = false;
        ObjectNode dctx = Json.object();
        String reason = null;
        for (Discovery.Endpoints ep : layers.pdps()) {
            Answer a = ask(ep, body);
            if (a.refused != null) {
                log.error("PDP layer {} refused: {}; denying (a refusal never fails open)", ep.identifier, a.refused);
                return deny(pep, 503, REFUSED, null);
            }
            if (a.unavailable != null) {
                if (!ep.failOpen) {
                    log.error("PDP layer {} unavailable: {}; denying (fail-closed)", ep.identifier, a.unavailable);
                    return deny(pep, 503, UNREACHABLE, null);
                }
                log.warn("PDP layer {} unavailable, failing open: {}", ep.identifier, a.unavailable);
                skipped.add(ep.identifier);
                continue;
            }
            decided = true;
            decision = a.decision;
            ObjectNode lctx = a.context;
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
            reason = "fail-open: no policy layer could be reached";
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

    // ---------- asking a PDP ----------

    /**
     * One layer's answer. Exactly one of three: a decision with its context, unavailable
     * (a transport failure, a timeout, a 5xx or a 429: the only thing a fail-open layer
     * may skip), or refused (a 3xx or another 4xx, an answer that is not a decision, a
     * call that could not be made).
     */
    record Answer(boolean decision, ObjectNode context, String unavailable, String refused) {
    }

    private Answer ask(Discovery.Endpoints ep, byte[] body) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", JSON);
        if (ep.apiKey != null) {
            h.put("Authorization", "Bearer " + ep.apiKey); // bound to the PDP it was configured for
        }
        Transport.Response res;
        try {
            res = transport.send(new Transport.Request("POST", ep.evaluation, h, body, conf.pdp_timeout_ms, conf.pdp_ssl_verify));
        } catch (IOException e) {
            return new Answer(false, null, String.valueOf(e.getMessage()), null);
        } catch (Transport.Refused e) {
            return new Answer(false, null, null, e.getMessage());
        }
        if (res.unavailable()) {
            return new Answer(false, null, "HTTP " + res.status(), null);
        }
        if (!res.ok()) {
            return new Answer(false, null, null, "HTTP " + res.status());
        }
        // A permit is the JSON boolean true and nothing else; an answer without a boolean
        // decision is not a deny either, it is not an answer.
        JsonNode d = Json.parse(res.body());
        JsonNode dec = d instanceof ObjectNode ? d.get("decision") : null;
        if (dec == null || !dec.isBoolean()) {
            return new Answer(false, null, null, "the answer is not a decision");
        }
        JsonNode c = d.get("context");
        return new Answer(dec.booleanValue(), c instanceof ObjectNode ? (ObjectNode) c : Json.object(), null, null);
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
            log.error("DPoP verification unavailable: {}", e.getMessage());
            return deny(pep, 401, "DPoP verification service unreachable; denying (fail-closed).", null);
        } catch (Transport.Refused e) {
            log.error("DPoP verification call refused: {}", e.getMessage());
            return deny(pep, 401, "DPoP verification failed; denying (fail-closed).", null);
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

    /**
     * An MCP request. A body is judged only when it is exactly one JSON-RPC message the
     * rule has read in full, in plain JSON; anything else is refused here with the
     * JSON-RPC error the contract names, and neither coaz-pep nor the upstream sees it.
     * Then coaz-pep decides, every method, every time.
     */
    private Verdict mcp(PepRequest req, String pep) {
        JsonRpc.Message msg = null;
        boolean hasBody = req.body != null && req.body.length > 0;
        if ("POST".equalsIgnoreCase(req.method) || hasBody || !req.bodyReadable) {
            if (!identityEncoding(req.headerValues("content-encoding"))) {
                return refusal(pep, 415, JsonRpc.INVALID_REQUEST, "Invalid Request: Content-Encoding not supported by the PEP", null);
            }
            if (!req.bodyReadable) {
                return refusal(pep, 413, JsonRpc.INVALID_REQUEST, "Invalid Request: request body too large for the PEP to authorise", null);
            }
            try {
                msg = JsonRpc.classify(req.body);
            } catch (JsonRpc.Refusal r) {
                log.warn("authzen-pdp '{}': refused an MCP body: {}", pep, r.getMessage());
                return refusal(pep, r.status, r.code, r.getMessage(), r.id);
            }
        }
        return coazCheck(req, pep, msg);
    }

    /** Absent, empty or identity, and nothing else: a body the rule cannot read as sent is not one it can judge. */
    static boolean identityEncoding(List<String> values) {
        for (String v : values) {
            for (String coding : v.split(",")) {
                String c = coding.trim();
                if (!c.isEmpty() && !c.equalsIgnoreCase("identity")) {
                    return false;
                }
            }
        }
        return true;
    }

    /** The contract's refusal: a JSON-RPC error with the request's id when it was readable, and X-PDP-Decision: DENY. */
    static Verdict refusal(String pep, int status, int code, String message, JsonNode id) {
        ObjectNode body = Json.object();
        body.put("jsonrpc", "2.0");
        body.set("id", id == null ? Json.MAPPER.nullNode() : id);
        ObjectNode err = body.putObject("error");
        err.put("code", code);
        err.put("message", message);
        return Verdict.respond(status, headers(JSON), Json.bytes(body), pdpHeaders(pep, "DENY", "mcp", message, null));
    }

    private Verdict coazCheck(PepRequest req, String pep, JsonRpc.Message msg) {
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
        putIf(h, "dpop", req.header("dpop"));
        putIf(h, "content-type", req.header("content-type"));
        List<String> encodings = req.headerValues("content-encoding");
        if (!encodings.isEmpty()) {
            h.put("content-encoding", String.join(", ", encodings));
        }
        // The body as the upstream will read it: validated UTF-8, so this is lossless.
        body.put("body", req.body == null ? "" : new String(req.body, StandardCharsets.UTF_8));

        String fallbackAction = msg == null ? "mcp:" + req.method.toLowerCase(Locale.ROOT)
            : msg.tool() != null ? "tools/call:" + msg.tool()
            : msg.method() != null ? msg.method() : "jsonrpc-response";

        Transport.Response res;
        try {
            res = transport.send(new Transport.Request("POST", conf.coaz_url + "/v1/mcp/check",
                coazHeaders(), Json.bytes(body), conf.coaz_timeout_ms, conf.pdp_ssl_verify));
        } catch (IOException e) {
            log.error("coaz-pep engine unavailable: {}", e.getMessage());
            return deny(pep, 503, "COAZ authorization engine unreachable; denying (fail-closed).", null);
        } catch (Transport.Refused e) {
            log.error("coaz-pep engine call refused: {}", e.getMessage());
            return deny(pep, 503, "COAZ authorization engine refused the request; denying (fail-closed).", null);
        }
        if (res.status() != 200) {
            log.error("coaz-pep engine returned {}", res.status());
            return deny(pep, 503, res.unavailable() ? "COAZ authorization engine unreachable; denying (fail-closed)."
                : "COAZ authorization engine refused the request; denying (fail-closed).", null);
        }
        JsonNode verdict = Json.parse(res.body());
        JsonNode dec = verdict instanceof ObjectNode ? verdict.get("decision") : null;
        if (dec == null || !dec.isBoolean()) {
            log.error("coaz-pep engine answered without a boolean decision");
            return deny(pep, 503, "COAZ authorization engine refused the request; denying (fail-closed).", null);
        }
        if (dec.booleanValue()) {
            // Every X-Auth-* header the client sent goes; coaz-pep's upstream_headers say
            // which come back, an empty value meaning "leave it off".
            Map<String, String> upstream = authHeaders(null, null, null, null);
            upstream.putAll(stringMap(verdict.get("upstream_headers")));
            Map<String, String> rh = stringMap(verdict.get("response_headers"));
            Map<String, String> out = pdpHeaders(pep, "PERMIT", headerOr(rh, "X-PDP-Action", fallbackAction),
                headerOr(rh, "X-PDP-Reason", null), headerOr(rh, "X-PDP-Fail-Open", null));
            relayable(rh).forEach(out::putIfAbsent);
            return Verdict.permit(upstream, out);
        }
        // A deny is coaz-pep's rendering, relayed as it is (for a tools/call, the COAZ
        // JSON-RPC error at HTTP 200); one with no rendering is a plain deny.
        JsonNode resp = verdict.get("response");
        if (!(resp instanceof ObjectNode)) {
            return deny(pep, 403, "Denied by policy.", pdpHeaders(pep, "DENY", fallbackAction, null, null));
        }
        Map<String, String> rh = stringMap(resp.get("headers"));
        JsonNode s = resp.get("status");
        int status = s != null && s.isInt() && s.intValue() >= 200 && s.intValue() <= 599 ? s.intValue() : 403;
        String respBody = Json.text(resp, "body");
        return Verdict.respond(status, relayable(rh), (respBody == null ? "" : respBody).getBytes(StandardCharsets.UTF_8),
            pdpHeaders(pep, "DENY", headerOr(rh, "X-PDP-Action", fallbackAction), headerOr(rh, "X-PDP-Reason", null), null));
    }

    private static String headerOr(Map<String, String> headers, String name, String otherwise) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return otherwise;
    }

    /** Headers that decide how a message is framed or routed belong to this hop, never to a relayed answer. */
    private static final java.util.Set<String> HOP = java.util.Set.of("content-length", "transfer-encoding", "connection",
        "keep-alive", "upgrade", "te", "trailer", "proxy-connection", "host");

    /**
     * What of a coaz-pep header map may be put on a response: not the framing headers,
     * and not X-PDP-*, which the rule sets itself so each appears once.
     */
    private static Map<String, String> relayable(Map<String, String> in) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : in.entrySet()) {
            String k = e.getKey().toLowerCase(Locale.ROOT);
            if (!HOP.contains(k) && !k.startsWith("x-pdp-")) {
                out.put(e.getKey(), e.getValue());
            }
        }
        return out;
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
        } catch (IOException | Transport.Refused e) {
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
     * there is only the payload, decoded and not verified, which decide() accepts only
     * under allow_insecure.
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

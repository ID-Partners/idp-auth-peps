package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.pingidentity.pa.sdk.http.Body;
import com.pingidentity.pa.sdk.http.Exchange;
import com.pingidentity.pa.sdk.http.ExchangeProperty;
import com.pingidentity.pa.sdk.http.HeaderField;
import com.pingidentity.pa.sdk.http.Headers;
import com.pingidentity.pa.sdk.http.Request;
import com.pingidentity.pa.sdk.http.Response;
import com.pingidentity.pa.sdk.identity.Identity;
import com.pingidentity.pa.sdk.identity.OAuthTokenMetadata;
import com.pingidentity.pa.sdk.interceptor.Outcome;
import com.pingidentity.pa.sdk.policy.AsyncRuleInterceptorBase;
import com.pingidentity.pa.sdk.policy.ErrorHandlingCallback;
import com.pingidentity.pa.sdk.policy.Rule;
import com.pingidentity.pa.sdk.policy.RuleInterceptorCategory;
import com.pingidentity.pa.sdk.policy.RuleInterceptorSupportedDestination;
import com.pingidentity.pa.sdk.ui.ConfigurationBuilder;
import com.pingidentity.pa.sdk.ui.ConfigurationField;
import jakarta.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

/**
 * The PingAccess rule: the glue between the engine's Exchange and {@link Pep}, which
 * does the deciding. handleRequest hands the request to a worker so the engine's I/O
 * thread is never blocked on a PDP call, then applies the verdict: on a permit the
 * X-Auth-* headers go on the request and the X-PDP-* headers are held for the response;
 * on anything else the verdict is parked for the rule's error callback, which writes the
 * response, and processing stops.
 *
 * <p>Registered through META-INF/services as an AsyncRuleInterceptor. Attach it to an
 * application or resource's API policy; when the application is protected, PingAccess
 * validates the access token before this rule sees it.
 */
@Rule(type = "AuthZenPdpRule", label = "AuthZEN PDP", category = RuleInterceptorCategory.AccessControl,
    destination = {RuleInterceptorSupportedDestination.Site, RuleInterceptorSupportedDestination.Agent},
    expectedConfiguration = AuthZenRuleConfiguration.class, agentCachingDisabled = true)
public class AuthZenRule extends AsyncRuleInterceptorBase<AuthZenRuleConfiguration> {
    private static final Logger log = LoggerFactory.getLogger(AuthZenRule.class);
    static final ExchangeProperty<Verdict> VERDICT = ExchangeProperty.create("com.idpartners.authzen", "verdict", Verdict.class);
    private static final Set<String> STYLES = Set.of("rest", "mcp");
    private static final Set<String> DISCOVERY = Set.of("off", "authzen", "resource");
    private static final Set<String> FAIL_MODES = Set.of("closed", "open");
    private static final AtomicInteger THREADS = new AtomicInteger();
    /** Workers per rule instance. Each rule has its own pool, so one rule's stuck PDP cannot starve another's. */
    static final int THREADS_PER_RULE = Integer.getInteger("authzen.pdp.threads", 64);
    static final String FAILED = "The authorization rule failed; denying (fail-closed).";

    private final Transport transport;
    private final Executor executor;
    private final ResponseFactory responses;
    private final LongSupplier clock;
    private volatile Pep pep;

    public AuthZenRule() {
        this(JdkTransport.shared(), newExecutor(THREADS_PER_RULE), new PaResponses(), () -> System.currentTimeMillis() / 1000);
    }

    AuthZenRule(Transport transport, Executor executor, ResponseFactory responses, LongSupplier clockSeconds) {
        this.transport = transport;
        this.executor = executor;
        this.responses = responses;
        this.clock = clockSeconds;
    }

    /**
     * A bounded pool of daemon threads; saturation is a 503, not a queue that grows
     * without end. Threads start on demand and die when idle, so a rule instance that
     * never decides (PingAccess builds one on the admin node too) costs nothing.
     */
    static ExecutorService newExecutor(int threads) {
        ThreadPoolExecutor ex = new ThreadPoolExecutor(threads, threads, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>(256), r -> {
            Thread t = new Thread(r, "authzen-pdp-" + THREADS.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        ex.allowCoreThreadTimeOut(true);
        return ex;
    }

    @Override
    public void configure(AuthZenRuleConfiguration c) throws ValidationException {
        validate(c);
        super.configure(c);
        if (c.allow_insecure) {
            // The escape hatch is explicit and loud: every relaxation it is covering, once
            // per rule instance, at configure time.
            List<String> relaxed = new ArrayList<>();
            relaxed.add("an access token PingAccess did not validate is used as it comes (an unprotected application)");
            relaxed.addAll(insecurities(c));
            log.warn("authzen-pdp '{}': allow_insecure is on, for development only. Relaxed: {}", c.getName(), String.join("; ", relaxed));
        }
        UserTokens.Reader reader;
        if (!Pep.blank(c.user_token_jwks_url)) {
            reader = UserTokens.verified(c.user_token_jwks_url, c.user_token_issuer, c.user_token_audience, transport, c.pdp_ssl_verify);
        } else if (c.allow_insecure) {
            reader = UserTokens.decodeOnly();
        } else {
            // Nothing to verify it against, and no permission to take it on trust: the
            // token is ignored, so it can open no gate and carry no user_scope.
            reader = UserTokens.ignored();
        }
        pep = new Pep(c, transport, new Discovery(transport, clock), reader);
    }

    /**
     * Failing at configuration time is far better than discovering a bad route per
     * request, and a missing security setting is a configuration error, not a warning:
     * the rule refuses it unless allow_insecure says otherwise.
     */
    static void validate(AuthZenRuleConfiguration c) throws ValidationException {
        // Set.of(...).contains(null) throws, and PingAccess binds a JSON null to a null field.
        if (c.style == null || !STYLES.contains(c.style)) {
            throw new ValidationException("style must be rest or mcp");
        }
        if (c.pdp_discovery == null || !DISCOVERY.contains(c.pdp_discovery)) {
            throw new ValidationException("pdp_discovery must be off, authzen or resource");
        }
        if (c.fail_mode == null || !FAIL_MODES.contains(c.fail_mode)) {
            throw new ValidationException("fail_mode must be closed or open");
        }
        if (c.pdp_metadata_ttl <= 0) {
            throw new ValidationException("pdp_metadata_ttl must be greater than zero");
        }
        if (c.pdp_timeout_ms <= 0 || c.coaz_timeout_ms <= 0) {
            throw new ValidationException("pdp_timeout_ms and coaz_timeout_ms must be greater than zero");
        }
        if (Pep.blank(c.authzen_url)) {
            throw new ValidationException("authzen_url is required");
        }
        url("authzen_url", c.authzen_url, true);
        url("coaz_url", c.coaz_url, false);
        url("mcp_upstream_url", c.mcp_upstream_url, false);
        url("federation_entity_url", c.federation_entity_url, false);
        url("resource", c.resource, true);
        url("user_token_jwks_url", c.user_token_jwks_url, false);
        urls("pdp_allowlist", c.pdp_allowlist);
        urls("resource_metadata_allowlist", c.resource_metadata_allowlist);
        if (c.pdp_layers != null) {
            for (String layer : c.pdp_layers) {
                Discovery.LayerSpec spec;
                try {
                    spec = Discovery.parseLayer(layer);
                } catch (Discovery.Failure e) {
                    throw new ValidationException("pdp_layers: " + e.getMessage());
                }
                if (spec.name().contains("://")) {
                    url("pdp_layers entry", spec.name(), true);
                }
            }
        }
        if ("mcp".equals(c.style) && Pep.blank(c.coaz_url)) {
            // Every request on an MCP route is decided by coaz-pep. Without it there is no
            // decision engine, and a route that cannot decide must not start.
            throw new ValidationException("style mcp needs coaz_url: every request on an MCP route is decided by coaz-pep");
        }
        if (c.require_dpop && Pep.blank(c.coaz_url)) {
            // The rule cannot verify a DPoP proof signature itself, and a thumbprint
            // comparison proves nothing: the proof carries the very JWK being compared.
            throw new ValidationException("require_dpop needs coaz_url: this rule cannot verify a DPoP proof signature itself, "
                + "so verification is delegated to coaz-pep");
        }
        List<String> insecure = insecurities(c);
        if (!c.allow_insecure && !insecure.isEmpty()) {
            throw new ValidationException("insecure configuration refused: " + String.join("; ", insecure)
                + ". Fix it, or set allow_insecure for development only");
        }
    }

    /** Every setting in c that allow_insecure would have to cover. Empty is a configuration fit to run. */
    static List<String> insecurities(AuthZenRuleConfiguration c) {
        List<String> out = new ArrayList<>();
        boolean jwks = !Pep.blank(c.user_token_jwks_url);
        if (c.require_user_login && !jwks) {
            out.add("require_user_login without user_token_jwks_url would take X-User-Token on trust");
        }
        if (jwks && Pep.blank(c.user_token_audience)) {
            out.add("user_token_jwks_url without user_token_audience would accept a user token minted for any audience");
        }
        if (jwks && !Urls.https(c.user_token_jwks_url)) {
            out.add("user_token_jwks_url is not https");
        }
        if (!Pep.blank(c.authzen_api_key) && !Urls.https(c.authzen_url)) {
            out.add("authzen_api_key would be sent over plain http");
        }
        if (!Pep.blank(c.coaz_url) && Pep.blank(c.coaz_api_key)) {
            out.add("coaz_url without coaz_api_key: coaz-pep's check API requires its CHECK_API_TOKEN");
        }
        if (!Pep.blank(c.coaz_api_key) && !Pep.blank(c.coaz_url) && !Urls.https(c.coaz_url)) {
            out.add("coaz_api_key would be sent over plain http");
        }
        if (c.forward_access_token && !Urls.https(c.authzen_url)) {
            out.add("forward_access_token would send the access token over plain http");
        }
        if (!"off".equals(c.pdp_discovery) && (c.pdp_allowlist == null || c.pdp_allowlist.isEmpty())) {
            out.add("pdp_discovery is on and pdp_allowlist is empty, so a resource could name any PDP");
        }
        if (c.pdp_discovery_insecure) {
            out.add("pdp_discovery_insecure allows plain http for discovered URLs");
        }
        if (!c.pdp_ssl_verify) {
            out.add("pdp_ssl_verify is off (certificates are not verified; host names still are)");
        }
        return out;
    }

    private static void url(String field, String value, boolean identifier) throws ValidationException {
        if (Pep.blank(value)) {
            return;
        }
        String problem = Urls.problem(value, identifier);
        if (problem != null) {
            throw new ValidationException(field + " " + value + " " + problem);
        }
    }

    private static void urls(String field, List<String> values) throws ValidationException {
        if (values == null) {
            return;
        }
        for (String v : values) {
            if (Pep.blank(v)) {
                throw new ValidationException(field + " has an empty entry");
            }
            url(field + " entry", v, true);
        }
    }

    @Override
    public List<ConfigurationField> getConfigurationFields() {
        return ConfigurationBuilder.from(AuthZenRuleConfiguration.class).toConfigurationFields();
    }

    /**
     * Where a deny is written. PingAccess's contract for a rule is that Outcome.RETURN
     * means "this rule rejects the request; call its error handling callback for the
     * response", exactly as its own Redirect and PingAuthorize rules do, so the verdict
     * is parked on the exchange by {@link #apply} and rendered here. Without one (the
     * engine failed the rule itself) it is still a fail-closed JSON deny.
     */
    @Override
    public ErrorHandlingCallback getErrorHandlingCallback() {
        return exchange -> {
            Verdict v = exchange.getProperty(VERDICT).filter(x -> !x.permit)
                .orElseGet(() -> Pep.deny(labelOf(exchange), 500, FAILED, null));
            exchange.setResponse(responses.build(v));
        };
    }

    /**
     * Hands the decision to this rule's workers. Whatever happens, the stage completes:
     * with the verdict, with a deny when the pipeline threw anything at all (an Error
     * included), or exceptionally when the verdict cannot even be parked on the exchange.
     * A stage that never completes is a request that hangs.
     */
    @Override
    public CompletionStage<Outcome> handleRequest(Exchange exchange) {
        CompletableFuture<Outcome> out = new CompletableFuture<>();
        Pep p = pep;
        if (p == null) {
            log.error("authzen-pdp: handleRequest before configure; denying");
            settle(out, exchange, Pep.deny("pingaccess-pep", 500, "The authorization rule is not configured; denying (fail-closed).", null));
            return out;
        }
        try {
            PepRequest req = read(exchange);
            Runnable task = () -> {
                Verdict v;
                try {
                    v = p.decide(req);
                } catch (Throwable e) {
                    log.error("authzen-pdp '{}': unexpected failure, denying", p.label(), e);
                    v = Pep.deny(p.label(), 500, FAILED, null);
                }
                settle(out, exchange, v);
            };
            executor.execute(task);
        } catch (RejectedExecutionException e) {
            log.error("authzen-pdp '{}': worker pool saturated, denying", p.label());
            settle(out, exchange, Pep.deny(p.label(), 503, "The authorization rule is saturated; denying (fail-closed).", null));
        } catch (Throwable e) {
            log.error("authzen-pdp '{}': the rule failed before it could decide, denying", p.label(), e);
            settle(out, exchange, Pep.deny(p.label(), 500, FAILED, null));
        }
        return out;
    }

    private void settle(CompletableFuture<Outcome> out, Exchange exchange, Verdict v) {
        try {
            out.complete(apply(exchange, v));
        } catch (Throwable e) {
            out.completeExceptionally(e);
        }
    }

    /** Test seam: this rule's own worker pool. */
    Executor executor() {
        return executor;
    }

    @Override
    public CompletionStage<Void> handleResponse(Exchange exchange) {
        exchange.getProperty(VERDICT).filter(v -> v.permit).ifPresent(v -> {
            Response r = exchange.getResponse();
            if (r != null && r.getHeaders() != null) {
                v.responseHeaders.forEach((k, val) -> r.getHeaders().setFirstValue(k, val));
            }
        });
        return CompletableFuture.completedFuture(null);
    }

    /**
     * A permit puts the X-Auth-* headers on the request and continues; the X-PDP-*
     * headers wait for {@link #handleResponse}. Anything else is parked for the error
     * callback and the chain is stopped.
     */
    Outcome apply(Exchange exchange, Verdict v) {
        exchange.setProperty(VERDICT, v);
        if (v.permit) {
            Headers h = exchange.getRequest().getHeaders();
            v.upstreamHeaders.forEach(h::setFirstValue);
            return Outcome.CONTINUE;
        }
        return Outcome.RETURN;
    }

    /** Everything the pipeline needs, taken from the Exchange on the engine's thread. */
    PepRequest read(Exchange exchange) {
        Request request = exchange.getRequest();
        String method = request.getMethod() == null ? "" : request.getMethod().getName();
        String uri = request.getUri() == null ? "" : request.getUri();
        int q = uri.indexOf('?');
        String path = q >= 0 ? uri.substring(0, q) : uri;
        Map<String, String> headers = new LinkedHashMap<>();
        Headers h = request.getHeaders();
        if (h != null && h.getHeaderFields() != null) {
            for (HeaderField f : h.getHeaderFields()) {
                headers.putIfAbsent(f.getHeaderName().toString(), f.getValue());
            }
        }
        byte[] body = null;
        Body b = request.getBody();
        if (b != null) {
            try {
                if (!b.isRead()) {
                    b.read();
                }
                body = b.getContent();
            } catch (Exception e) {
                log.warn("authzen-pdp: request body could not be read: {}", e.getMessage());
            }
        }
        return new PepRequest(method, path, headers, body, identityClaims(exchange.getIdentity()));
    }

    /**
     * What PingAccess established about the caller when the application is protected:
     * the validated token's attributes, its subject and its OAuth metadata. Null when
     * there is no identity, which is what an unprotected application yields.
     */
    static ObjectNode identityClaims(Identity id) {
        if (id == null) {
            return null;
        }
        ObjectNode out = Json.object();
        JsonNode attrs = id.getAttributes();
        if (attrs instanceof ObjectNode) {
            out.setAll((ObjectNode) attrs);
        }
        if (id.getSubject() != null && !out.hasNonNull("sub")) {
            out.put("sub", id.getSubject());
        }
        OAuthTokenMetadata md = id.getOAuthTokenMetadata();
        if (md != null) {
            if (md.getClientId() != null && !out.hasNonNull("client_id")) {
                out.put("client_id", md.getClientId());
            }
            if (md.getScopes() != null && !md.getScopes().isEmpty() && !out.has("scope") && !out.has("scp")) {
                out.put("scope", String.join(" ", md.getScopes()));
            }
        }
        return out;
    }

    private String labelOf(Exchange exchange) {
        Pep p = pep;
        return p == null ? "pingaccess-pep" : p.label();
    }
}

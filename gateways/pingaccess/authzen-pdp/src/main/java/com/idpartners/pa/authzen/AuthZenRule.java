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
    private static final ExecutorService SHARED_EXECUTOR = newExecutor(Integer.getInteger("authzen.pdp.threads", 64));

    private final Transport transport;
    private final Executor executor;
    private final ResponseFactory responses;
    private final LongSupplier clock;
    private volatile Pep pep;

    public AuthZenRule() {
        this(JdkTransport.shared(), SHARED_EXECUTOR, new PaResponses(), () -> System.currentTimeMillis() / 1000);
    }

    AuthZenRule(Transport transport, Executor executor, ResponseFactory responses, LongSupplier clockSeconds) {
        this.transport = transport;
        this.executor = executor;
        this.responses = responses;
        this.clock = clockSeconds;
    }

    /** A bounded pool of daemon threads; saturation is a 503, not a queue that grows without end. */
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
        super.configure(c);
        validate(c);
        if (!c.pdp_ssl_verify) {
            log.warn("authzen-pdp '{}': pdp_ssl_verify is off; outbound TLS is not verified (development only)", c.getName());
        }
        UserTokens.Reader reader;
        if (Pep.blank(c.user_token_jwks_url)) {
            log.warn("authzen-pdp '{}': user_token_jwks_url is unset; X-User-Token is decoded, not verified", c.getName());
            reader = UserTokens.decodeOnly();
        } else {
            reader = UserTokens.verified(c.user_token_jwks_url, c.user_token_issuer, c.user_token_audience);
        }
        pep = new Pep(c, transport, new Discovery(transport, clock), reader);
    }

    /** Failing at configuration time is far better than discovering a bad route per request. */
    static void validate(AuthZenRuleConfiguration c) throws ValidationException {
        if (Pep.blank(c.authzen_url)) {
            throw new ValidationException("authzen_url is required");
        }
        if (!STYLES.contains(c.style)) {
            throw new ValidationException("style must be rest or mcp");
        }
        if (!DISCOVERY.contains(c.pdp_discovery)) {
            throw new ValidationException("pdp_discovery must be off, authzen or resource");
        }
        if (!FAIL_MODES.contains(c.fail_mode)) {
            throw new ValidationException("fail_mode must be closed or open");
        }
        if (c.pdp_metadata_ttl <= 0) {
            throw new ValidationException("pdp_metadata_ttl must be greater than zero");
        }
        if (c.require_dpop && Pep.blank(c.coaz_url)) {
            // The rule cannot verify a DPoP proof signature itself, and a thumbprint
            // comparison proves nothing: the proof carries the very JWK being compared.
            throw new ValidationException("require_dpop needs coaz_url: this rule cannot verify a DPoP proof signature itself, "
                + "so verification is delegated to coaz-pep");
        }
        if (c.pdp_layers != null) {
            for (String layer : c.pdp_layers) {
                try {
                    Discovery.parseLayer(layer);
                } catch (Discovery.Failure e) {
                    throw new ValidationException("pdp_layers: " + e.getMessage());
                }
            }
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
                .orElseGet(() -> Pep.deny(labelOf(exchange), 500, "The authorization rule failed; denying (fail-closed).", null));
            exchange.setResponse(responses.build(v));
        };
    }

    @Override
    public CompletionStage<Outcome> handleRequest(Exchange exchange) {
        Pep p = pep;
        if (p == null) {
            log.error("authzen-pdp: handleRequest before configure; denying");
            return CompletableFuture.completedFuture(apply(exchange,
                Pep.deny("pingaccess-pep", 500, "The authorization rule is not configured; denying (fail-closed).", null)));
        }
        PepRequest req = read(exchange);
        CompletableFuture<Outcome> out = new CompletableFuture<>();
        Runnable task = () -> {
            Verdict v;
            try {
                v = p.decide(req);
            } catch (RuntimeException e) {
                log.error("authzen-pdp '{}': unexpected failure, denying", p.label(), e);
                v = Pep.deny(p.label(), 500, "The authorization rule failed; denying (fail-closed).", null);
            }
            try {
                out.complete(apply(exchange, v));
            } catch (RuntimeException e) {
                out.completeExceptionally(e);
            }
        };
        try {
            executor.execute(task);
        } catch (RejectedExecutionException e) {
            log.error("authzen-pdp '{}': worker pool saturated, denying", p.label());
            out.complete(apply(exchange, Pep.deny(p.label(), 503, "The authorization rule is saturated; denying (fail-closed).", null)));
        }
        return out;
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

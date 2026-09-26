package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PDP discovery: resource -> PDP identifier -> PDP metadata -> evaluation endpoint. A
 * port of the Kong plugin's discovery.lua, which is itself a port of
 * core/authzen/discovery minus the federation branch: resolving an OpenID Federation
 * Trust Chain means verifying Entity Statement signatures against configured anchors,
 * and that lives in coaz-pep alone so it cannot drift. A route that must take the
 * federation's word over the resource's own belongs behind coaz-pep.
 *
 * <pre>
 *   resource identifier (conf.resource, or mcp_upstream_url on an mcp route)
 *     +- resource: {resource}/.well-known/oauth-protected-resource (RFC 9728), self-asserted
 *     +- static:   conf.authzen_url, the fallback
 *   PDP identifier
 *     +- {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 s9)
 *     +- 404 / unreachable -> {pdp}/access/v1/evaluation, the spec's default paths
 * </pre>
 *
 * <p>The parameter naming the PDPs, {@code authzen_policy_decision_points}, is minted by
 * this repository (no spec defines one) and shared with the Go PEP byte for byte.
 *
 * <p>Two rules are never relaxed: a URL outside an allowlist fails closed rather than
 * falling to a weaker source, and a discovered PDP never receives the static API key.
 */
final class Discovery {
    static final String PARAM = "authzen_policy_decision_points";
    static final int MAX_BODY = 1048576;
    static final long MIN_REFRESH = 30;
    static final int FETCH_TIMEOUT_MS = 5000;

    private static final Logger log = LoggerFactory.getLogger(Discovery.class);
    private static final Pattern URL = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+)(.*)$");
    private static final Pattern SPACES = Pattern.compile("\\s+");

    /**
     * Error kinds. NOT_ALLOWED is the one the chain never swallows. TRANSIENT is the only
     * outage (a network failure, a timeout, a 5xx or a 429) and the only kind a fail-open
     * layer may skip. REFUSED is an answer that arrived and cannot be used (a 3xx or
     * another 4xx, an answer over the size cap, a URL that cannot be called), INVALID a
     * document that says the wrong thing; neither is ever skipped.
     */
    enum Kind { NOT_ALLOWED, INVALID, NO_METADATA, TRANSIENT, REFUSED }

    static final class Failure extends Exception {
        final Kind kind;

        Failure(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }
    }

    record Url(String scheme, String host, String path, String query, String fragment) {
    }

    /** URL policy for one kind of fetch: https unless insecure or same-origin as the trusted (static) PDP, then the allowlist. */
    record Policy(boolean insecure, String trustedOrigin, List<String> allowlist, boolean sslVerify, int timeoutMs) {
        /**
         * For an identifier's own well-known document, once the identifier has passed the
         * allowlist: the document sits on the identifier's origin by construction, and a
         * path-bearing entry ("https://pdp.example/tenant1") would otherwise refuse the
         * very document it allows (".../.well-known/authzen-configuration/tenant1").
         */
        Policy wellKnown() {
            return new Policy(insecure, trustedOrigin, null, sslVerify, timeoutMs);
        }
    }

    /** The resource's metadata as published, when a document named the PDP; forwarded to the PDP verbatim and read by nothing here. */
    record ResourceMeta(String source, JsonNode document) {
    }

    /** A resource's PDP list, as cached: the list this module uses, the document the rule forwards. */
    record Meta(List<String> pdps, JsonNode document, String source) {
    }

    /** Where to post an evaluation, and what came with the answer. */
    static final class Endpoints {
        String identifier;
        String evaluation;
        String evaluations;
        JsonNode capabilities;
        String apiKey;
        String source;
        ResourceMeta resource;
        boolean failOpen;

        /** A copy without key, source or resource: what a cache entry hands out. */
        Endpoints bare() {
            Endpoints e = new Endpoints();
            e.identifier = identifier;
            e.evaluation = evaluation;
            e.evaluations = evaluations;
            e.capabilities = capabilities;
            return e;
        }
    }

    /** One layer of a route's policy: a name and, optionally, its own failure mode. */
    record LayerSpec(String name, Boolean failOpen) {
    }

    record Layers(List<Endpoints> pdps, List<String> skipped, ResourceMeta meta) {
    }

    private record Options(String staticPdp, long ttl, Policy resourcePolicy, Policy pdpPolicy) {
    }

    interface Fetch<T> {
        T get(String key) throws Failure;
    }

    /**
     * A cache entry, keyed by identifier: the documents are public, so no credential in
     * the key. Serves stale while a refresh fails or is under way, throttles retries,
     * negatively caches a failure so a down resource does not put a fetch in every
     * request's path, and lets one request fetch while the others use the stale value
     * or, when there is none yet, wait for that one fetch.
     */
    static final class Entry {
        boolean ok;
        Object val;
        Failure err;
        long expires;
        long negUntil;
        long lastAttempt;
        CompletableFuture<Object> inflight;
    }

    private final Transport transport;
    private final LongSupplier clock;
    private final Map<String, Entry> resources = new ConcurrentHashMap<>();
    private final Map<String, Entry> pdps = new ConcurrentHashMap<>();
    /** How long a request waits for another's fetch of the same document: the fetch's own timeout, and a margin. */
    long waitMs = FETCH_TIMEOUT_MS + 1000L;

    Discovery(Transport transport, LongSupplier clockSeconds) {
        this.transport = transport;
        this.clock = clockSeconds;
    }

    // ---------- URLs ----------

    static Url parseUrl(String raw) {
        if (raw == null) {
            return null;
        }
        Matcher m = URL.matcher(raw);
        if (!m.matches()) {
            return null;
        }
        String path = m.group(3);
        String query = null;
        String fragment = null;
        int f = path.indexOf('#');
        if (f >= 0) {
            fragment = path.substring(f + 1);
            path = path.substring(0, f);
        }
        int q = path.indexOf('?');
        if (q >= 0) {
            query = path.substring(q + 1);
            path = path.substring(0, q);
        }
        return new Url(m.group(1).toLowerCase(Locale.ROOT), m.group(2).toLowerCase(Locale.ROOT), path, query, fragment);
    }

    static String trimSlash(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return s.substring(0, end);
    }

    /** RFC 8414 / RFC 9728 / AuthZEN rule: insert /.well-known/{suffix} after the host. */
    static String wellKnownUrl(String identifier, String suffix) throws Failure {
        Url u = parseUrl(identifier);
        if (u == null) {
            throw new Failure(Kind.INVALID, identifier + " is not an absolute URL");
        }
        if (u.query != null || u.fragment != null) {
            throw new Failure(Kind.INVALID, identifier + " must not have a query or fragment");
        }
        return u.scheme + "://" + u.host + "/.well-known/" + suffix + trimSlash(u.path);
    }

    /**
     * Prefix allowlist that only matches at a path boundary (the same rule as the Go
     * PEP's upstreamAllowed): "https://a.example/mcp" permits ".../mcp" and ".../mcp/x",
     * never ".../mcpx".
     */
    static boolean allowed(List<String> list, String raw) {
        if (list == null || list.isEmpty()) {
            return true;
        }
        Url u = parseUrl(raw);
        if (u == null) {
            return false;
        }
        String target = u.scheme + "://" + u.host + u.path;
        for (String entry : list) {
            Url e = parseUrl(entry);
            if (e == null) {
                continue;
            }
            String prefix = trimSlash(e.scheme + "://" + e.host + e.path);
            if (target.equals(prefix) || target.startsWith(prefix + "/")) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameOrigin(Url u, String trusted) {
        Url t = parseUrl(trusted);
        return t != null && u.scheme.equals(t.scheme) && u.host.equals(t.host);
    }

    static void checkUrl(String raw, Policy p) throws Failure {
        Url u = parseUrl(raw);
        if (u == null) {
            throw new Failure(Kind.NOT_ALLOWED, raw + " is not an absolute URL");
        }
        if (u.scheme.equals("http")) {
            if (!(p.insecure || sameOrigin(u, p.trustedOrigin))) {
                throw new Failure(Kind.NOT_ALLOWED, raw + " is not https");
            }
        } else if (!u.scheme.equals("https")) {
            throw new Failure(Kind.NOT_ALLOWED, raw + " has scheme " + u.scheme);
        }
        String problem = Urls.problem(raw, false);
        if (problem != null) {
            throw new Failure(Kind.NOT_ALLOWED, raw + " " + problem);
        }
        if (!allowed(p.allowlist, raw)) {
            throw new Failure(Kind.NOT_ALLOWED, raw + " is outside the allowlist");
        }
    }

    // ---------- fetch ----------

    /** GET a JSON document under the policy. */
    private JsonNode getJson(String url, Policy p) throws Failure {
        checkUrl(url, p);
        Transport.Response res;
        try {
            res = transport.send(new Transport.Request("GET", url, Map.of("Accept", "application/json"), null, p.timeoutMs, p.sslVerify, MAX_BODY));
        } catch (IOException e) {
            throw new Failure(Kind.TRANSIENT, "GET " + url + ": " + e.getMessage());
        } catch (Transport.Refused e) {
            throw new Failure(Kind.REFUSED, "GET " + url + ": " + e.getMessage());
        }
        if (res.status() == 404) {
            throw new Failure(Kind.NO_METADATA, url + " returned 404");
        }
        if (res.unavailable()) {
            throw new Failure(Kind.TRANSIENT, "GET " + url + " returned " + res.status());
        }
        // Redirects are not followed, so a 3xx lands here: a document that tries to send
        // the PEP elsewhere is a failure, never a hop.
        if (!res.ok()) {
            throw new Failure(Kind.REFUSED, "GET " + url + " returned " + res.status());
        }
        if (res.body() == null) {
            throw new Failure(Kind.REFUSED, url + " has no body");
        }
        JsonNode doc = Json.parse(res.body());
        if (!(doc instanceof ObjectNode)) {
            throw new Failure(Kind.INVALID, url + " is not JSON");
        }
        return doc;
    }

    // ---------- cache ----------

    /**
     * The cached value for key, fetched when it is missing or due. The fetch runs outside
     * the entry's lock: while one request refreshes, the others are served the stale
     * value or, when there is none yet, wait (bounded) for that one fetch rather than
     * start their own.
     */
    @SuppressWarnings("unchecked")
    private <T> T cacheGet(Map<String, Entry> store, String key, long ttl, long negativeTtl, Fetch<T> fetch) throws Failure {
        Entry e = store.computeIfAbsent(key, k -> new Entry());
        CompletableFuture<Object> mine = null;
        CompletableFuture<Object> theirs = null;
        synchronized (e) {
            long t = clock.getAsLong();
            if (e.ok && t < e.expires) {
                return (T) e.val;
            }
            if (!e.ok && e.err != null && t < e.negUntil) {
                throw e.err;
            }
            if (e.ok && e.err != null && (t - e.lastAttempt) < MIN_REFRESH) {
                return (T) e.val;
            }
            if (e.inflight == null) {
                mine = new CompletableFuture<>();
                e.inflight = mine;
                e.lastAttempt = t;
            } else if (e.ok) {
                return (T) e.val; // stale while another request refreshes it
            } else {
                theirs = e.inflight;
            }
        }
        if (theirs != null) {
            return (T) await(theirs, key);
        }
        T val = null;
        Failure err = null;
        boolean fetched = false;
        try {
            val = fetch.get(key);
            fetched = true;
        } catch (Failure f) {
            err = f;
            fetched = true;
        } finally {
            if (!fetched) {
                // A bug in the fetch: let it surface, but never leave the entry claimed.
                synchronized (e) {
                    e.inflight = null;
                }
                mine.completeExceptionally(new Failure(Kind.REFUSED, "the metadata fetch for " + key + " failed"));
            }
        }
        synchronized (e) {
            e.inflight = null;
            long t = clock.getAsLong();
            if (err == null) {
                e.val = val;
                e.ok = true;
                e.expires = t + ttl;
                e.err = null;
                e.negUntil = 0;
                mine.complete(val);
                return val;
            }
            e.err = err;
            if (e.ok) {
                mine.complete(e.val);
                return (T) e.val; // stale beats failing every request
            }
            // A policy refusal cost no fetch and belongs to one route's allowlist;
            // another route sharing this cache must not inherit it.
            if (negativeTtl > 0 && err.kind != Kind.NOT_ALLOWED) {
                e.negUntil = t + negativeTtl;
            }
            mine.completeExceptionally(err);
            throw err;
        }
    }

    /** Wait, bounded, for another request's fetch of the same key. */
    private Object await(CompletableFuture<Object> f, String key) throws Failure {
        try {
            return f.get(waitMs, TimeUnit.MILLISECONDS);
        } catch (ExecutionException x) {
            // The fetching request completes its future with a value or a Failure, never
            // anything else: see cacheGet.
            throw (Failure) x.getCause();
        } catch (TimeoutException x) {
            throw new Failure(Kind.TRANSIENT, "timed out waiting for the metadata fetch for " + key);
        } catch (InterruptedException x) {
            Thread.currentThread().interrupt();
            throw new Failure(Kind.REFUSED, "interrupted waiting for the metadata fetch for " + key);
        }
    }

    /** Test seam: the cache entry for a resource identifier. */
    Entry resourceEntry(String key) {
        return resources.get(key);
    }

    // ---------- sources ----------

    private static List<String> pdpList(JsonNode raw, String from) throws Failure {
        if (raw == null || !raw.isArray()) {
            throw new Failure(Kind.NO_METADATA, from + " names no PDP");
        }
        List<String> out = new ArrayList<>();
        for (JsonNode v : raw) {
            Url u = v.isTextual() ? parseUrl(v.asText()) : null;
            if (u == null || u.query != null || u.fragment != null) {
                throw new Failure(Kind.INVALID, from + " lists " + v + ", which is not a PDP identifier");
            }
            out.add(trimSlash(v.asText()));
        }
        if (out.isEmpty()) {
            throw new Failure(Kind.NO_METADATA, from + " names no PDP");
        }
        return out;
    }

    /**
     * RFC 9728: the resource's own protected resource metadata. Nothing here interprets
     * scopes_supported or an acr requirement: what a resource requires is policy input,
     * and policy is the PDP's.
     */
    private Meta rfc9728Lookup(String resource, Options o) throws Failure {
        String wk = wellKnownUrl(resource, "oauth-protected-resource");
        JsonNode doc = getJson(wk, o.resourcePolicy.wellKnown());
        // s3.3: the echoed identifier MUST be identical, or whoever answers at that path
        // has just named a PDP for someone else's resource.
        if (!resource.equals(Json.text(doc, "resource"))) {
            throw new Failure(Kind.INVALID, wk + " says resource is " + Json.text(doc, "resource") + ", expected " + resource);
        }
        return new Meta(pdpList(doc.get(PARAM), wk), doc, "rfc9728");
    }

    /**
     * AuthZEN 1.0 s9: the PDP's own metadata, or the default paths when it has none (a
     * 404). Any other failure stays a failure: cached as the answer, the default paths
     * would stand in for the PDP's own for a whole TTL. The cache serves the last good
     * entry instead or, with none, the layer fails according to its mode.
     */
    private Endpoints fetchConfig(String pdp, Options o) throws Failure {
        checkUrl(pdp, o.pdpPolicy);
        String wk = wellKnownUrl(pdp, "authzen-configuration");
        JsonNode doc;
        try {
            doc = getJson(wk, o.pdpPolicy.wellKnown());
        } catch (Failure ferr) {
            if (ferr.kind != Kind.NO_METADATA) {
                throw ferr;
            }
            return defaultEndpoints(pdp);
        }
        String declared = Json.text(doc, "policy_decision_point");
        if (!trimSlash(declared == null ? "" : declared).equals(trimSlash(pdp))) {
            throw new Failure(Kind.INVALID, wk + " says policy_decision_point is " + declared + ", expected " + pdp);
        }
        String evaluation = Json.text(doc, "access_evaluation_endpoint");
        if (evaluation == null || evaluation.isEmpty()) {
            throw new Failure(Kind.INVALID, wk + " has no access_evaluation_endpoint");
        }
        JsonNode evaluationsNode = doc.get("access_evaluations_endpoint");
        String evaluations = evaluationsNode == null || evaluationsNode.isNull() ? null : evaluationsNode.asText();
        checkUrl(evaluation, o.pdpPolicy);
        if (evaluations != null) {
            checkUrl(evaluations, o.pdpPolicy);
        }
        Endpoints ep = new Endpoints();
        ep.identifier = trimSlash(pdp);
        ep.evaluation = evaluation;
        ep.evaluations = evaluations;
        ep.capabilities = doc.get("capabilities");
        return ep;
    }

    static Endpoints defaultEndpoints(String pdp) {
        pdp = trimSlash(pdp);
        Endpoints ep = new Endpoints();
        ep.identifier = pdp;
        ep.evaluation = pdp + "/access/v1/evaluation";
        ep.evaluations = pdp + "/access/v1/evaluations";
        return ep;
    }

    // ---------- resolve ----------

    /** The identifier discovery starts from for this route. */
    static String resourceId(AuthZenRuleConfiguration conf) {
        if (conf.resource != null && !conf.resource.isEmpty()) {
            return trimSlash(conf.resource);
        }
        if ("mcp".equals(conf.style) && conf.mcp_upstream_url != null && !conf.mcp_upstream_url.isEmpty()) {
            return conf.mcp_upstream_url;
        }
        return "";
    }

    private static Options options(AuthZenRuleConfiguration conf) {
        String staticPdp = trimSlash(conf.authzen_url == null ? "" : conf.authzen_url);
        boolean insecure = conf.pdp_discovery_insecure;
        long ttl = conf.pdp_metadata_ttl > 0 ? conf.pdp_metadata_ttl : 300;
        List<String> pdpAllow = null;
        if (conf.pdp_allowlist != null && !conf.pdp_allowlist.isEmpty()) {
            // The static PDP's own origin is trusted over http; the allowlist bounds what
            // a resource may add to it, and the static PDP is always on it.
            pdpAllow = new ArrayList<>();
            pdpAllow.add(staticPdp);
            pdpAllow.addAll(conf.pdp_allowlist);
        }
        return new Options(staticPdp, ttl,
            new Policy(insecure, null, conf.resource_metadata_allowlist, conf.pdp_ssl_verify, FETCH_TIMEOUT_MS),
            new Policy(insecure, staticPdp, pdpAllow, conf.pdp_ssl_verify, FETCH_TIMEOUT_MS));
    }

    private static Endpoints withKey(Endpoints ep, String source, AuthZenRuleConfiguration conf, Options o) {
        boolean hasKey = conf.authzen_api_key != null && !conf.authzen_api_key.isEmpty();
        ep.apiKey = ep.identifier.equals(o.staticPdp) && hasKey ? conf.authzen_api_key : null;
        if (ep.source == null) {
            ep.source = source;
        }
        return ep;
    }

    private static String mode(AuthZenRuleConfiguration conf) {
        return conf.pdp_discovery == null || conf.pdp_discovery.isEmpty() ? "off" : conf.pdp_discovery;
    }

    /**
     * Resolve an explicitly named PDP: an operator-configured layer. The PDP allowlist
     * applies; a layer URL in route config is as caller-supplied as anything else there.
     */
    Endpoints resolvePdp(AuthZenRuleConfiguration conf, String pdp) throws Failure {
        Options o = options(conf);
        pdp = trimSlash(pdp);
        if (mode(conf).equals("off")) {
            Endpoints ep = defaultEndpoints(pdp);
            ep.source = "layer";
            return withKey(ep, "layer", conf, o);
        }
        checkUrl(pdp, o.pdpPolicy);
        Endpoints cached = cacheGet(pdps, pdp, o.ttl, MIN_REFRESH, key -> fetchConfig(key, o));
        checkUrl(cached.evaluation, o.pdpPolicy);
        if (cached.evaluations != null) {
            checkUrl(cached.evaluations, o.pdpPolicy);
        }
        Endpoints ep = cached.bare();
        ep.source = "layer";
        return withKey(ep, "layer", conf, o);
    }

    /**
     * Parse one layer entry: a name, optionally followed by "fail-open" or "fail-closed".
     * An unknown modifier is an error: a policy that cannot be read must not be silently
     * narrowed.
     */
    static LayerSpec parseLayer(String entry) throws Failure {
        String[] fields = entry == null ? new String[0] : SPACES.split(entry.trim());
        if (fields.length == 0 || fields[0].isEmpty()) {
            throw new Failure(Kind.INVALID, "empty layer");
        }
        String name = trimSlash(fields[0]);
        if (!name.equals("resource") && !name.equals("static") && !name.contains("://")) {
            throw new Failure(Kind.INVALID, "layer " + name + " is neither static, resource nor a PDP identifier");
        }
        Boolean open = null;
        for (int i = 1; i < fields.length; i++) {
            String m = fields[i].toLowerCase(Locale.ROOT);
            if (m.equals("fail-open")) {
                open = Boolean.TRUE;
            } else if (m.equals("fail-closed")) {
                open = Boolean.FALSE;
            } else {
                throw new Failure(Kind.INVALID, "layer " + name + ": unknown modifier " + fields[i]);
            }
        }
        return new LayerSpec(name, open);
    }

    /**
     * Resolve every layer of a route's policy, in order, duplicates collapsed. Layering
     * is what lets a generic PDP that judges the token and the client sit in front of
     * the resource's own. defaultOpen is the route's fail_mode; a layer's own setting
     * wins. A layer that cannot be resolved fails the request unless it is fail-open and
     * the failure is an outage, in which case it is skipped and named. A refusal, an
     * invalid document or an allowlist miss is never skipped.
     */
    Layers resolveLayers(AuthZenRuleConfiguration conf, String resource, List<String> layers, boolean defaultOpen) throws Failure {
        if (layers == null || layers.isEmpty()) {
            layers = List.of("resource");
        }
        List<Endpoints> out = new ArrayList<>();
        Map<String, Integer> seen = new HashMap<>();
        ResourceMeta meta = null;
        List<String> skipped = new ArrayList<>();
        for (String entry : layers) {
            LayerSpec spec = parseLayer(entry);
            boolean open = spec.failOpen != null ? spec.failOpen : defaultOpen;
            Endpoints ep;
            try {
                if (spec.name.equals("resource")) {
                    ep = resolve(conf, resource);
                } else if (spec.name.equals("static")) {
                    ep = resolve(conf, "");
                } else {
                    ep = resolvePdp(conf, spec.name);
                }
            } catch (Failure err) {
                if (err.kind != Kind.TRANSIENT || !open) {
                    throw new Failure(err.kind, "layer " + spec.name + ": " + err.getMessage());
                }
                log.warn("pdp discovery: layer {} unavailable, failing open: {}", spec.name, err.getMessage());
                skipped.add(spec.name);
                continue;
            }
            ep.failOpen = open;
            if (ep.resource != null && meta == null) {
                meta = ep.resource;
            }
            Integer at = seen.get(ep.identifier);
            if (at != null) {
                out.get(at).failOpen = out.get(at).failOpen && open; // the stricter mode wins
            } else {
                seen.put(ep.identifier, out.size());
                out.add(ep);
            }
        }
        return new Layers(out, skipped, meta);
    }

    /**
     * Resolve the PDP endpoints for {@code resource} under {@code conf}. The returned
     * endpoints carry the resource's metadata as published when a document named the
     * PDP; the rule forwards it to the PDP and reads nothing from it.
     */
    Endpoints resolve(AuthZenRuleConfiguration conf, String resource) throws Failure {
        String mode = mode(conf);
        Options o = options(conf);

        if (mode.equals("off")) {
            if (o.staticPdp.isEmpty()) {
                throw new Failure(Kind.TRANSIENT, "no PDP configured");
            }
            return withKey(defaultEndpoints(o.staticPdp), "static", conf, o);
        }

        List<String> candidates;
        ResourceMeta from = null;
        if (resource == null || resource.isEmpty() || mode.equals("authzen")) {
            if (o.staticPdp.isEmpty()) {
                throw new Failure(Kind.TRANSIENT, "no PDP configured");
            }
            candidates = List.of(o.staticPdp);
        } else {
            // Checked here as well as at fetch time: a cached list may have been fetched
            // under another route's allowlist.
            checkUrl(resource, o.resourcePolicy);
            Meta meta;
            try {
                meta = cacheGet(resources, resource, o.ttl, MIN_REFRESH, key -> {
                    try {
                        return rfc9728Lookup(key, o);
                    } catch (Failure perr) {
                        // Only "publishes nothing" (a 404) and a document that says the
                        // wrong thing are an answer; a fetch that failed must not replace
                        // the last good list with the static PDP.
                        if (perr.kind == Kind.NOT_ALLOWED || perr.kind == Kind.TRANSIENT || perr.kind == Kind.REFUSED) {
                            throw perr;
                        }
                        if (perr.kind == Kind.INVALID) {
                            log.warn("pdp discovery: {}", perr.getMessage());
                        }
                        if (o.staticPdp.isEmpty()) {
                            throw perr;
                        }
                        return new Meta(List.of(o.staticPdp), null, null);
                    }
                });
            } catch (Failure err) {
                if (err.kind == Kind.NOT_ALLOWED) {
                    throw err;
                }
                if (o.staticPdp.isEmpty()) {
                    throw new Failure(Kind.TRANSIENT, "no PDP could be resolved for " + resource + ": " + err.getMessage());
                }
                log.warn("pdp discovery: {}; using the static PDP", err.getMessage());
                meta = new Meta(List.of(o.staticPdp), null, null);
            }
            candidates = meta.pdps;
            if (meta.document != null) {
                from = new ResourceMeta(meta.source, meta.document);
            }
        }

        Failure last = null;
        boolean outage = false;
        for (String pdp : candidates) {
            checkUrl(pdp, o.pdpPolicy);
            Endpoints cached;
            try {
                cached = cacheGet(pdps, pdp, o.ttl, MIN_REFRESH, key -> fetchConfig(key, o));
            } catch (Failure err) {
                if (err.kind == Kind.NOT_ALLOWED) {
                    throw err;
                }
                log.warn("pdp discovery: {}: {}", pdp, err.getMessage());
                outage |= err.kind == Kind.TRANSIENT;
                last = err;
                continue;
            }
            checkUrl(cached.evaluation, o.pdpPolicy);
            if (cached.evaluations != null) {
                checkUrl(cached.evaluations, o.pdpPolicy);
            }
            // A copy: the cached entry must not carry a key or a source.
            Endpoints ep = cached.bare();
            ep.resource = from;
            return withKey(ep, pdp.equals(o.staticPdp) ? "static" : "rfc9728", conf, o);
        }
        // An outage among the candidates may have hidden the one that works, so it is an
        // outage; candidates that all answered, and were all unusable, are a refusal.
        throw new Failure(outage ? Kind.TRANSIENT : Kind.REFUSED, "no PDP could be resolved: " + last.getMessage());
    }
}

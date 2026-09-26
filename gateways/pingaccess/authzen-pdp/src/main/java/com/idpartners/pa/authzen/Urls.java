package com.idpartners.pa.authzen;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * What counts as a usable URL, in one place: absolute, http or https, with a host the JDK
 * can connect to, and no user info. {@code http://authzen_pdp:8080} parses as a URI but
 * has no host (an underscore is not legal in a host name), so it is refused here rather
 * than failing on every request.
 */
final class Urls {
    private Urls() {
    }

    /** The URI, or null when it is not an absolute http(s) URL with a host and no user info. */
    static URI parse(String raw) {
        return problem(raw, false) == null ? URI.create(raw) : null;
    }

    /**
     * Why the URL is unusable, or null when it is fine. An identifier (a PDP, a resource)
     * also may not carry a query or a fragment: the well-known rules have nowhere to put
     * them.
     */
    static String problem(String raw, boolean identifier) {
        if (raw == null || raw.isEmpty()) {
            return "is empty";
        }
        URI u;
        try {
            u = new URI(raw);
        } catch (URISyntaxException e) {
            return "is not a URL";
        }
        if (!u.isAbsolute() || u.isOpaque()) {
            return "is not an absolute URL";
        }
        String scheme = u.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return "is not http or https";
        }
        if (u.getHost() == null || u.getHost().isEmpty()) {
            return "has no host name the JDK can use (an underscore in it?)";
        }
        if (u.getRawUserInfo() != null) {
            return "carries user info";
        }
        if (identifier && (u.getRawQuery() != null || u.getRawFragment() != null)) {
            return "must not have a query or fragment";
        }
        return null;
    }

    static boolean https(String raw) {
        return raw != null && raw.regionMatches(true, 0, "https://", 0, 8);
    }
}

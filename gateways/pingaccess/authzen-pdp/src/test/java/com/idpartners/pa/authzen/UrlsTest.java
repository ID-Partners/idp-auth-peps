package com.idpartners.pa.authzen;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlsTest {
    @Test
    void acceptsAbsoluteHttpAndHttpsUrlsWithAHost() {
        for (String ok : new String[]{"https://pdp.example", "http://pdp:8080/x?y=1", "HTTPS://PDP.example/", "http://[::1]:8080/", "http://127.0.0.1:9002"}) {
            assertNull(Urls.problem(ok, false), ok);
            assertNotNull(Urls.parse(ok), ok);
        }
        assertNull(Urls.problem("https://pdp.example/tenants/a", true));
    }

    @Test
    void namesWhatIsWrongWithAUrlItCannotUse() {
        assertEquals("is empty", Urls.problem(null, false));
        assertEquals("is empty", Urls.problem("", false));
        assertEquals("is not a URL", Urls.problem("http://pdp:8080/a b", false));
        assertEquals("is not an absolute URL", Urls.problem("/relative", false));
        assertEquals("is not an absolute URL", Urls.problem("mailto:a@b.example", false));
        assertEquals("is not http or https", Urls.problem("ftp://pdp.example/", false));
        // Parses as a URI, but an underscore is not legal in a host name, so there is no host.
        assertTrue(Urls.problem("http://authzen_pdp:8080", false).startsWith("has no host"));
        assertTrue(Urls.problem("http:///x", false).startsWith("has no host"));
        assertEquals("carries user info", Urls.problem("https://u:p@pdp.example/", false));
        // An identifier may not carry a query or a fragment; an endpoint may.
        assertEquals("must not have a query or fragment", Urls.problem("https://pdp.example/?x=1", true));
        assertEquals("must not have a query or fragment", Urls.problem("https://pdp.example/#f", true));
        assertNull(Urls.problem("https://pdp.example/?x=1", false));
        assertNull(Urls.parse("http://authzen_pdp:8080"));
    }

    @Test
    void tellsHttpsFromEverythingElse() {
        assertTrue(Urls.https("https://pdp.example"));
        assertTrue(Urls.https("HTTPS://pdp.example"));
        assertFalse(Urls.https("http://pdp.example"));
        assertFalse(Urls.https("https:"));
        assertFalse(Urls.https(null));
    }
}

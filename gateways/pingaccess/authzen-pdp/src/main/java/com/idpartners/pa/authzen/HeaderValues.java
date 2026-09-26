package com.idpartners.pa.authzen;

/**
 * What may go into an HTTP header. Values built from a PDP's answer, coaz-pep's answer or
 * a token's claims are someone else's text, and a header value is Latin-1 with no
 * control characters: a CR or LF would end the header and start another, and anything
 * past U+00FF is not carried faithfully at all.
 */
final class HeaderValues {
    private HeaderValues() {
    }

    /** The value with control characters and anything past Latin-1 removed. */
    static String clean(String v) {
        if (v == null) {
            return null;
        }
        StringBuilder b = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c >= 0x20 && c != 0x7F && c <= 0xFF) {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** The value as the content of a quoted-string (RFC 9110 5.6.4), for a WWW-Authenticate parameter. */
    static String quoted(String v) {
        String c = clean(v);
        return c == null ? "" : c.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** True when the value survives cleaning unchanged: an identity that cannot is not forwarded in a mangled form. */
    static boolean faithful(String v) {
        return v == null || v.equals(clean(v));
    }

    /** An RFC 9110 token: the only thing a header name may be. */
    static boolean name(String n) {
        if (n == null || n.isEmpty()) {
            return false;
        }
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            boolean alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alnum && "!#$%&'*+-.^_`|~".indexOf(c) < 0) {
                return false;
            }
        }
        return true;
    }

    /** Text from a request for a log line or a short reason: cleaned, and cut to a length a person reads. */
    static String brief(String v, int max) {
        String c = v == null ? "" : clean(v);
        return c.length() <= max ? c : c.substring(0, max) + "...";
    }
}

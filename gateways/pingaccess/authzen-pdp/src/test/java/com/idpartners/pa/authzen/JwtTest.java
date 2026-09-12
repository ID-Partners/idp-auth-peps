package com.idpartners.pa.authzen;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JwtTest {
    @Test
    void roundTripsBase64urlWithoutPadding() {
        for (String s : new String[]{"a", "ab", "abc", "abcd", "hello world"}) {
            assertEquals(s, new String(Jwt.b64urlDecode(FakeTransport.b64url(s)), StandardCharsets.UTF_8));
        }
        assertNull(Jwt.b64urlDecode(null));
        assertNull(Jwt.b64urlDecode(""));
        assertNull(Jwt.b64urlDecode("not*base64"));
    }

    @Test
    void decodesClaimsAndRefusesMalformedTokens() {
        String token = FakeTransport.jwt(FakeTransport.obj("sub", "alice@example.com", "scope", "a b"), "{\"alg\":\"ES256\",\"kid\":\"k1\"}");
        assertEquals("alice@example.com", Jwt.claims(token).get("sub").asText());
        for (String bad : new String[]{"nodots", "only.one", "a.!!!.c", "a." + FakeTransport.b64url("[1]") + ".c"}) {
            assertNull(Jwt.claims(bad), bad);
        }
        assertNull(Jwt.claims(null));
    }

    @Test
    void extractsTheTokenAndLowerCasesTheScheme() {
        Jwt.Token t = Jwt.extractToken("Bearer abc.def.ghi");
        assertEquals("abc.def.ghi", t.value());
        assertEquals("bearer", t.scheme());
        assertEquals("dpop", Jwt.extractToken("DPoP xyz").scheme());
        assertNull(Jwt.extractToken(null));
        assertNull(Jwt.extractToken("Malformed"));
    }
}

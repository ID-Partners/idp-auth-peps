package com.idpartners.pa.authzen;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderValuesTest {
    @Test
    void cleansControlCharactersAndAnythingPastLatin1() {
        assertEquals("ab", HeaderValues.clean("a\r\nb"));
        assertEquals("ab", HeaderValues.clean("a\u0000\tb\u007F"));
        assertEquals("zoë", HeaderValues.clean("zoë"));
        assertEquals("ab", HeaderValues.clean("a一b😀"));
        assertNull(HeaderValues.clean(null));
    }

    @Test
    void quotesForAWwwAuthenticateParameter() {
        assertEquals("a\\\"b\\\\c", HeaderValues.quoted("a\"b\\c"));
        assertEquals("", HeaderValues.quoted(null));
    }

    @Test
    void anIdentityIsFaithfulOnlyWhenCleaningLeavesItAlone() {
        assertTrue(HeaderValues.faithful("alice@example.com"));
        assertTrue(HeaderValues.faithful(""));
        assertTrue(HeaderValues.faithful(null));
        assertFalse(HeaderValues.faithful("ad一min"));
        assertFalse(HeaderValues.faithful("a\nb"));
    }

    @Test
    void knowsAHeaderNameFromSomethingThatIsNot() {
        assertTrue(HeaderValues.name("X-Auth-Principal"));
        assertTrue(HeaderValues.name("x_custom.1!#$%&'*+^`|~"));
        assertFalse(HeaderValues.name("Bad Header"));
        assertFalse(HeaderValues.name("a:b"));
        assertFalse(HeaderValues.name("é"));
        assertFalse(HeaderValues.name(""));
        assertFalse(HeaderValues.name(null));
    }

    @Test
    void keepsWhatGoesIntoALogLineShort() {
        assertEquals("abc", HeaderValues.brief("a\nbc", 5));
        assertEquals("abcde...", HeaderValues.brief("abcdefgh", 5));
        assertEquals("", HeaderValues.brief(null, 5));
    }
}

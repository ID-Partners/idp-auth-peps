package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTest {
    @Test
    void parsesLenientlyAndReadsScalars() {
        assertNull(Json.parse((byte[]) null));
        assertNull(Json.parse(new byte[0]));
        assertNull(Json.parse("{not json"));
        assertNull(Json.parseObject("[1]".getBytes()));
        ObjectNode o = FakeTransport.obj("s", "x", "n", 1, "nested", FakeTransport.obj("a", "b"));
        o.putNull("z");
        assertEquals("x", Json.text(o, "s"));
        assertEquals("1", Json.text(o, "n"));
        assertNull(Json.text(o, "nested"));
        assertNull(Json.text(o, "z"));
        assertNull(Json.text(o, "missing"));
        assertNull(Json.text(null, "s"));
        assertEquals("{\"a\":\"b\"}", Json.string(o.get("nested")));
    }

    @Test
    void truthinessIsLuaStyle() {
        ObjectNode o = FakeTransport.obj("t", true, "f", false, "s", "false", "n", 0);
        o.putNull("z");
        assertTrue(Json.truthy(o, "t"));
        assertFalse(Json.truthy(o, "f"));
        assertTrue(Json.truthy(o, "s"));
        assertTrue(Json.truthy(o, "n"));
        assertFalse(Json.truthy(o, "z"));
        assertFalse(Json.truthy(o, "missing"));
        assertFalse(Json.truthy(null, "t"));
    }
}

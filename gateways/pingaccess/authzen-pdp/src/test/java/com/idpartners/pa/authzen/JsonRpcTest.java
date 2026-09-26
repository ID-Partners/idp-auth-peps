package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The MCP body gate: exactly one JSON-RPC message, read the one way every parser reads
 * it, or a refusal with the contract's status and JSON-RPC code.
 */
class JsonRpcTest {
    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static JsonRpc.Refusal refused(byte[] body) {
        return assertThrows(JsonRpc.Refusal.class, () -> JsonRpc.classify(body));
    }

    static JsonRpc.Refusal refused(String body) {
        return refused(b(body));
    }

    @Test
    void readsARequestANotificationAndAResponse() throws Exception {
        JsonRpc.Message call = JsonRpc.classify(b("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"get_balance\",\"arguments\":{\"id\":\"a1\"}}}"));
        assertEquals("tools/call", call.method());
        assertEquals("get_balance", call.tool());
        assertEquals(7, call.id().intValue());
        JsonRpc.Message note = JsonRpc.classify(b("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
        assertEquals("notifications/initialized", note.method());
        assertNull(note.id());
        assertNull(note.tool());
        // A client's answer to a server-initiated request (sampling, elicitation).
        JsonRpc.Message answer = JsonRpc.classify(b("{\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"result\":{\"content\":[]}}"));
        assertNull(answer.method());
        assertEquals("s1", answer.id().asText());
        assertNull(JsonRpc.classify(b("{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-1,\"message\":\"no\"}}")).method());
        // Non-ASCII in values is fine; it is valid UTF-8.
        assertEquals("zoë", JsonRpc.classify(b("{\"method\":\"tools/call\",\"params\":{\"name\":\"zoë\"}}")).tool());
        // Members the protocol does not name are the upstream's business, as is params that is not an object.
        assertEquals("ping", JsonRpc.classify(b("{\"method\":\"ping\",\"_meta\":{\"progressToken\":1},\"params\":[1]}")).method());
        assertEquals("tools/call", JsonRpc.classify(b("{\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"_meta\":{}}}")).method());
    }

    @Test
    void anythingThatIsNotJsonIsAParseError() {
        byte[] bom = b("﻿{\"method\":\"ping\"}");
        byte[] latin1 = "{\"method\":\"tools/call\",\"params\":{\"name\":\"aÿ\"}}".getBytes(StandardCharsets.ISO_8859_1);
        byte[] overlong = {'{', '"', 'm', '"', ':', '"', (byte) 0xC0, (byte) 0xAF, '"', '}'};
        byte[] surrogate = {'{', '"', 'm', '"', ':', '"', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '"', '}'};
        byte[] utf16 = "{\"method\":\"ping\"}".getBytes(StandardCharsets.UTF_16LE);
        for (byte[] body : new byte[][]{null, new byte[0], b("   "), b("not json"), b("{\"method\":\"ping\"} x"),
            b("{\"method\":\"ping\"}{\"method\":\"tools/call\"}"), b("{\"method\":'ping'}"), b("{\"a\":01}"), b("{\"a\":NaN}"),
            b("{\"a\":1,}"), b("{\"a\":\"x\ny\"}"), b("{\"method\":\"ping\" /* c */}"), bom, latin1, overlong, surrogate, utf16}) {
            JsonRpc.Refusal r = refused(body);
            assertEquals(400, r.status);
            assertEquals(JsonRpc.PARSE_ERROR, r.code);
            assertEquals("Parse error", r.getMessage());
            assertNull(r.id, "no id can be read from a body that is not JSON");
        }
    }

    @Test
    void anythingThatIsNotOneJsonRpcMessageIsAnInvalidRequest() {
        String[][] cases = {
            {"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"make_payment\"}}]", "batch requests are not supported"},
            {"[]", "batch"},
            {"\"tools/call\"", "not a JSON-RPC object"},
            {"42", "not a JSON-RPC object"},
            {"null", "not a JSON-RPC object"},
            // Duplicates, exact and case-variant, at any depth: parsers disagree on which wins.
            {"{\"method\":\"ping\",\"method\":\"tools/call\"}", "duplicate member"},
            {"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"Method\":\"ping\",\"params\":{\"name\":\"a\"}}", "duplicate member"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"get_balance\"},\"Params\":{\"name\":\"make_payment\"}}", "duplicate member"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"get_balance\",\"Name\":\"make_payment\"}}", "duplicate member"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"arguments\":{\"account\":\"a1\",\"Account\":\"b2\"}}}", "duplicate member"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"arguments\":{\"list\":[{\"to\":\"a\",\"TO\":\"b\"}]}}}", "duplicate member"},
            // A long s folds to s and the Kelvin sign to k, as a case-insensitive decoder reads them.
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"a\"},\"paramſ\":{\"name\":\"b\"}}", "duplicate member"},
            // A case variant with no twin is still read as the member by a case-insensitive decoder.
            {"{\"jsonrpc\":\"2.0\",\"id\":1,\"Method\":\"tools/call\",\"params\":{\"name\":\"make_payment\"}}", "Method is not a JSON-RPC member name"},
            {"{\"id\":1,\"result\":{},\"METHOD\":\"tools/call\"}", "METHOD is not a JSON-RPC member name"},
            {"{\"method\":\"tools/call\",\"params\":{\"Name\":\"make_payment\"}}", "params.Name differs only in case"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"Arguments\":{}}}", "params.Arguments"},
            {"{\"method\":\"resources/read\",\"params\":{\"URI\":\"file:///etc/passwd\"}}", "params.URI"},
            {"{\"method\":42}", "method must be a string"},
            {"{\"method\":null,\"id\":1}", "method must be a string"},
            {"{\"method\":{\"name\":\"tools/call\"}}", "method must be a string"},
            {"{\"method\":\"tools/call\"}", "tools/call needs a string params.name"},
            {"{\"method\":\"tools/call\",\"params\":{}}", "tools/call needs a string params.name"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":\"\"}}", "tools/call needs a string params.name"},
            {"{\"method\":\"tools/call\",\"params\":{\"name\":7}}", "tools/call needs a string params.name"},
            {"{\"method\":\"tools/call\",\"params\":[\"make_payment\"]}", "tools/call needs a string params.name"},
            {"{\"jsonrpc\":\"2.0\",\"id\":1}", "neither a request nor a response"},
            {"{\"id\":1,\"result\":{},\"error\":{}}", "neither a request nor a response"},
            {"{\"result\":{}}", "neither a request nor a response"},
            {"{}", "neither a request nor a response"},
        };
        for (String[] c : cases) {
            JsonRpc.Refusal r = refused(c[0]);
            assertEquals(400, r.status, c[0]);
            assertEquals(JsonRpc.INVALID_REQUEST, r.code, c[0]);
            assertTrue(r.getMessage().startsWith("Invalid Request: "), r.getMessage());
            assertTrue(r.getMessage().contains(c[1]), c[0] + " -> " + r.getMessage());
        }
    }

    @Test
    void aRefusalEchoesTheRequestsIdWhenItCouldBeRead() {
        assertEquals(9, refused("{\"id\":9,\"method\":\"tools/call\"}").id.intValue());
        assertEquals("x", refused("{\"id\":\"x\",\"method\":7}").id.asText());
        JsonNode nullId = refused("{\"id\":null,\"method\":7}").id;
        assertTrue(nullId.isNull());
        // An id that cannot be one, and a body whose members are ambiguous: no echo.
        assertNull(refused("{\"id\":{\"a\":1},\"method\":7}").id);
        assertNull(refused("{\"id\":1,\"id\":2,\"method\":\"ping\"}").id);
        assertNull(refused("[{\"id\":1,\"method\":\"ping\"}]").id);
    }

    @Test
    void foldsCaseTheWayCaseInsensitiveDecodersDo() {
        assertEquals(StrictJson.fold("params"), StrictJson.fold("PARAMS"));
        assertEquals(StrictJson.fold("params"), StrictJson.fold("paramſ"));
        assertEquals(StrictJson.fold("key"), StrictJson.fold("Key"));
        assertEquals("name", StrictJson.fold("Name"));
        assertNull(StrictJson.caseDuplicate(Json.parse("[1,{\"a\":1,\"b\":{\"c\":2}}]")));
    }
}

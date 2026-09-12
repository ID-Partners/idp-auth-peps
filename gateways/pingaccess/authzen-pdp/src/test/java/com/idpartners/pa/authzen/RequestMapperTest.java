package com.idpartners.pa.authzen;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestMapperTest {
    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void mapsRestBankingRoutesToActionsAndResources() {
        RequestMapper.Mapped list = RequestMapper.map("rest", "GET", "/customers/cust-1/accounts", null);
        assertEquals("list_accounts", list.action());
        assertEquals("customer", list.rtype());
        assertEquals("cust-1", list.rid());

        RequestMapper.Mapped bal = RequestMapper.map("rest", "GET", "/accounts/acc-9/balance", null);
        assertEquals("get_balance", bal.action());
        assertEquals("account", bal.rtype());
        assertEquals("acc-9", bal.rid());
    }

    @Test
    void matchesRoutesRegardlessOfAnApplicationContextRoot() {
        // The patterns are prefix-tolerant on purpose: it must not matter whether the
        // gateway strips /bank before or after the PEP sees the request.
        RequestMapper.Mapped m = RequestMapper.map("rest", "GET", "/bank/accounts/acc-9/balance", null);
        assertEquals("get_balance", m.action());
        assertEquals("acc-9", m.rid());
    }

    @Test
    void treatsAnMcpInitializeHandshakeDifferentlyFromOtherJsonRpc() {
        assertEquals("access_mcp", RequestMapper.map("mcp", "POST", "/mcp", b("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")).action());
        RequestMapper.Mapped other = RequestMapper.map("mcp", "POST", "/mcp", b("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}"));
        assertNotEquals("access_mcp", other.action());
        assertEquals(RequestMapper.ALLOW, other.action());
        assertEquals("mcp-service", other.rtype());
        assertEquals("northwind-bank", other.rid());
        assertEquals(RequestMapper.ALLOW, RequestMapper.map("mcp", "GET", "/mcp", null).action());
        assertEquals(RequestMapper.ALLOW, RequestMapper.map("mcp", "POST", "/mcp", b("not json")).action());
    }

    @Test
    void alwaysTagsTheChannelSoPolicyCanSeeItIsAgentTraffic() {
        RequestMapper.Mapped m = RequestMapper.map("rest", "GET", "/anything", null);
        assertEquals("ai-agent", m.ctx().get("channel").asText());
        assertEquals("http:get", m.action());
        assertEquals("endpoint", m.rtype());
        assertEquals("/anything", m.rid());
        assertEquals("ai-agent", RequestMapper.map("mcp", "GET", "/mcp", null).ctx().get("channel").asText());
    }

    @Test
    void carriesPaymentDetailsIntoResourceAndContext() {
        RequestMapper.Mapped m = RequestMapper.map("rest", "POST", "/payments",
            b("{\"from_account\":\"a\",\"to_account\":\"b\",\"amount\":50,\"currency\":\"NZD\",\"description\":\"rent\",\"internal_transfer\":true}"));
        assertEquals("make_payment", m.action());
        assertEquals("account", m.rtype());
        assertEquals("a", m.rid());
        assertEquals("a", m.rprops().get("from_account").asText());
        assertEquals("b", m.rprops().get("to_account").asText());
        assertEquals(50, m.ctx().get("amount").intValue());
        assertEquals("NZD", m.ctx().get("currency").asText());
        assertEquals("rent", m.ctx().get("description").asText());
        assertTrue(m.ctx().get("internal_transfer").booleanValue());

        // Defaults and tolerance: no currency is AUD, a numeric string amount is read,
        // a non-numeric one is dropped, a missing from_account is an empty id.
        RequestMapper.Mapped d = RequestMapper.map("rest", "POST", "/payments", b("{\"amount\":\"12.5\"}"));
        assertEquals("", d.rid());
        assertEquals("AUD", d.ctx().get("currency").asText());
        assertEquals(12.5, d.ctx().get("amount").doubleValue());
        assertFalse(d.ctx().has("description"));
        assertFalse(d.ctx().has("internal_transfer"));
        RequestMapper.Mapped bad = RequestMapper.map("rest", "POST", "/payments", b("{\"amount\":\"lots\"}"));
        assertFalse(bad.ctx().has("amount"));
        // No usable body at all: the action still maps, the id is unknown.
        RequestMapper.Mapped none = RequestMapper.map("rest", "POST", "/payments", b("[]"));
        assertEquals("make_payment", none.action());
        assertNull(none.rid());
    }

    @Test
    void defaultsTheAccountTypeWhenOpeningAnAccount() {
        RequestMapper.Mapped m = RequestMapper.map("rest", "POST", "/accounts", b("{}"));
        assertEquals("open_account", m.action());
        assertEquals("new:savings", m.rid());
        assertFalse(m.rprops().has("account_type"));
        RequestMapper.Mapped t = RequestMapper.map("rest", "POST", "/accounts", b("{\"account_type\":\"term\"}"));
        assertEquals("new:term", t.rid());
        assertEquals("term", t.rprops().get("account_type").asText());
        assertEquals("new:savings", RequestMapper.map("rest", "POST", "/accounts", null).rid());
        // A GET on /accounts is not an open_account.
        assertEquals("http:get", RequestMapper.map("rest", "GET", "/accounts", null).action());
    }
}

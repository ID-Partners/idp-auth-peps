package com.idpartners.pa.authzen;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestMapperTest {
    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static RequestMapper.Mapped map(String method, String path, String body) throws RequestMapper.Unmappable {
        return RequestMapper.map(method, path, body == null ? null : b(body), true);
    }

    static RequestMapper.Unmappable unmappable(String method, String path, String body) {
        return assertThrows(RequestMapper.Unmappable.class, () -> map(method, path, body), method + " " + path + " " + body);
    }

    static final String PAY = "{\"from_account\":\"a\",\"to_account\":\"b\",\"amount\":50}";

    @Test
    void mapsRestBankingRoutesToActionsAndResources() throws Exception {
        RequestMapper.Mapped list = map("GET", "/customers/cust-1/accounts", null);
        assertEquals("list_accounts", list.action());
        assertEquals("customer", list.rtype());
        assertEquals("cust-1", list.rid());

        RequestMapper.Mapped bal = map("GET", "/accounts/acc-9/balance", null);
        assertEquals("get_balance", bal.action());
        assertEquals("account", bal.rtype());
        assertEquals("acc-9", bal.rid());
        assertEquals("/accounts/acc-9/balance", bal.path());
        assertEquals("get_balance", map("HEAD", "/accounts/acc-9/balance/", null).action());
    }

    @Test
    void matchesRoutesRegardlessOfAnApplicationContextRoot() throws Exception {
        // Anchored at the end, on whole segments: it must not matter whether the gateway
        // strips /bank before or after the PEP sees the request.
        RequestMapper.Mapped m = map("GET", "/bank/accounts/acc-9/balance", null);
        assertEquals("get_balance", m.action());
        assertEquals("acc-9", m.rid());
        // A segment that merely ends like a route is not the route.
        assertEquals("http:get", map("GET", "/xaccounts/acc-9/balance", null).action());
        assertEquals("http:get", map("GET", "/accounts/acc-9/balance/history", null).action());
        assertEquals("http:get", map("GET", "/mycustomers/c1/accounts", null).action());
    }

    @Test
    void matchesThePathTheUpstreamRoutesNotThePathAsItArrived() throws Exception {
        // Path parameters, dot segments, empty segments and percent-encoding, undone as a
        // servlet container undoes them before it routes.
        assertEquals("a1", map("GET", "/x/../accounts/a1/balance", null).rid());
        assertEquals("a1", map("GET", "/accounts;jsessionid=1/a1;v=2/balance;x", null).rid());
        assertEquals("a1", map("GET", "//accounts//a1/./balance", null).rid());
        assertEquals("a1", map("GET", "/%61ccounts/%61%31/balance", null).rid());
        assertEquals("a1", map("GET", "/%2e%2e/accounts/a1/balance", null).rid());
        assertEquals("get_balance", map("GET", "/../../accounts/a1/balance", null).action());
        assertEquals("zoë", map("GET", "/accounts/zo%C3%AB/balance", null).rid());
        assertEquals("/accounts/a1/balance", map("GET", "/accounts/a1/./balance/", null).path());
        // An absolute-form request target is routed by its path.
        assertEquals("get_balance", map("GET", "https://api.example/accounts/a1/balance", null).action());
        assertEquals("/", map("GET", "https://api.example", null).path());
        // Unmappable: no one way to route it.
        for (String bad : new String[]{"/accounts/a%2Fb/balance", "/accounts/a%5Cb/balance", "/accounts/a%00/balance",
            "/accounts/%ZZ/balance", "/accounts/a%2/balance", "/accounts/%C0%AF/balance", "*", "accounts/a1/balance"}) {
            unmappable("GET", bad, null);
        }
    }

    @Test
    void aReadIsOnlyEverAGetOrAHead() throws Exception {
        // POST /customers/c1/accounts was list_accounts: a write judged as a read.
        assertEquals("open_account", map("POST", "/customers/c1/accounts", "{}").action());
        assertEquals("http:put", map("PUT", "/accounts/a1/balance", null).action());
        assertEquals("http:delete", map("DELETE", "/customers/c1/accounts", null).action());
    }

    @Test
    void aPostThatNamesPaymentsAnywhereIsJudgedAsThePaymentItMayBe() throws Exception {
        // The reviewer's probe: this was list_accounts while an upstream routing /payments/**
        // would take it as a payment.
        RequestMapper.Mapped m = map("POST", "/payments;/customers/c1/accounts", "{\"from_account\":\"a\",\"amount\":9000}");
        assertEquals("make_payment", m.action());
        assertEquals(9000, m.ctx().get("amount").intValue());
        assertEquals("make_payment", map("POST", "/v1/payments/", PAY).action());
        unmappable("POST", "/payments;/customers/c1/accounts", "{}");
    }

    @Test
    void alwaysTagsTheChannelSoPolicyCanSeeItIsAgentTraffic() throws Exception {
        RequestMapper.Mapped m = map("GET", "/anything", null);
        assertEquals("ai-agent", m.ctx().get("channel").asText());
        assertEquals("http:get", m.action());
        assertEquals("endpoint", m.rtype());
        assertEquals("/anything", m.rid());
    }

    @Test
    void carriesPaymentDetailsIntoResourceAndContext() throws Exception {
        RequestMapper.Mapped m = map("POST", "/payments",
            "{\"from_account\":\"a\",\"to_account\":\"b\",\"amount\":50,\"currency\":\"NZD\",\"description\":\"rent\",\"internal_transfer\":true}");
        assertEquals("make_payment", m.action());
        assertEquals("account", m.rtype());
        assertEquals("a", m.rid());
        assertEquals("a", m.rprops().get("from_account").asText());
        assertEquals("b", m.rprops().get("to_account").asText());
        assertEquals(50, m.ctx().get("amount").intValue());
        assertEquals("NZD", m.ctx().get("currency").asText());
        assertEquals("rent", m.ctx().get("description").asText());
        assertTrue(m.ctx().get("internal_transfer").booleanValue());

        // Defaults and tolerance: no currency is AUD, a numeric string amount is read, a
        // numeric account id is an id.
        RequestMapper.Mapped d = map("POST", "/payments", "{\"from_account\":7,\"amount\":\"12.5\",\"currency\":null}");
        assertEquals("7", d.rid());
        assertEquals("AUD", d.ctx().get("currency").asText());
        assertEquals(12.5, d.ctx().get("amount").doubleValue());
        assertFalse(d.ctx().has("description"));
        assertFalse(d.ctx().has("internal_transfer"));
        assertFalse(d.rprops().has("to_account"));
    }

    @Test
    void aPaymentThePdpCannotWeighIsNotSentToIt() {
        // No amount the PDP can compare against its threshold, no account to debit, or a
        // body that is not one unambiguous JSON object: each would have gone to the PDP
        // as a payment with nothing in it.
        String[] bodies = {
            null, "", "not json", "[]", "\"pay\"",
            "{\"from_account\":\"a\"}",
            "{\"from_account\":\"a\",\"amount\":\"lots\"}",
            "{\"from_account\":\"a\",\"amount\":\"5,000\"}",
            "{\"from_account\":\"a\",\"amount\":\"12f\"}",
            "{\"from_account\":\"a\",\"amount\":\" 12\"}",
            "{\"from_account\":\"a\",\"amount\":\"1e999\"}",
            "{\"from_account\":\"a\",\"amount\":1e999}",
            "{\"from_account\":\"a\",\"amount\":true}",
            "{\"from_account\":\"a\",\"amount\":{\"value\":5}}",
            "{\"amount\":5}",
            "{\"from_account\":\"\",\"amount\":5}",
            "{\"from_account\":{\"id\":\"a\"},\"amount\":5}",
            "{\"from_account\":\"a\",\"amount\":5,\"currency\":{\"code\":\"AUD\"}}",
            // Parsers disagree on which of two amounts is the amount.
            "{\"from_account\":\"a\",\"amount\":10,\"amount\":5000}",
            "{\"from_account\":\"a\",\"amount\":10,\"Amount\":5000}",
            "{\"from_account\":\"a\",\"amount\":10} {\"amount\":5000}",
        };
        for (String body : bodies) {
            unmappable("POST", "/payments", body);
        }
        assertThrows(RequestMapper.Unmappable.class, () -> RequestMapper.map("POST", "/payments", b(PAY), false), "a body read in part");
    }

    @Test
    void defaultsTheAccountTypeWhenOpeningAnAccount() throws Exception {
        RequestMapper.Mapped m = map("POST", "/accounts", "{}");
        assertEquals("open_account", m.action());
        assertEquals("new:savings", m.rid());
        assertFalse(m.rprops().has("account_type"));
        RequestMapper.Mapped t = map("POST", "/accounts", "{\"account_type\":\"term\"}");
        assertEquals("new:term", t.rid());
        assertEquals("term", t.rprops().get("account_type").asText());
        assertEquals("new:savings", map("POST", "/accounts", "{\"account_type\":null}").rid());
        // No body, or one that cannot be read, or an account type that is not a name.
        for (String body : new String[]{null, "[]", "{\"account_type\":7}", "{\"account_type\":\"term\",\"Account_Type\":\"x\"}"}) {
            unmappable("POST", "/accounts", body);
        }
        // A GET on /accounts is not an open_account.
        assertEquals("http:get", map("GET", "/accounts", null).action());
    }

    @Test
    void segmentsAreThePathAsTheUpstreamSeesIt() throws Exception {
        assertEquals(List.of("a", "b"), RequestMapper.segments("/a;x/./b/"));
        assertEquals(List.of(), RequestMapper.segments("/"));
        assertEquals(List.of(), RequestMapper.segments("/#frag"));
        assertEquals(List.of("a"), RequestMapper.segments("/a#/../b"));
        assertThrows(RequestMapper.Unmappable.class, () -> RequestMapper.segments(null));
    }
}

import { describe, expect, it, vi } from 'vitest';

import { CODE_DENIED_V2, CODE_INVALID_REQUEST, CODE_MAPPING_ERROR, CODE_PARSE_ERROR, CODE_PDP_ERROR, McpGuard, type McpGuardOptions } from '../src/mcp.js';

const CHECK = 'http://coaz-pep:9192/v1/mcp/check';
const UPSTREAM = 'https://mcp.bank.example/mcp';

interface Sent {
  url: string;
  init: RequestInit;
  body: { config: Record<string, string>; method: string; path: string; headers: Record<string, string>; body: string };
}

/** coaz-pep's check API, answering with `answer` (a value is JSON-encoded; a function builds the Response). */
function coazPep(answer: unknown | ((sent: Sent) => Response | Promise<Response>)) {
  const sent: Sent[] = [];
  const fetch = vi.fn(async (u: unknown, init?: RequestInit) => {
    const s: Sent = { url: String(u), init: init ?? {}, body: JSON.parse(String(init?.body)) as Sent['body'] };
    sent.push(s);
    if (typeof answer === 'function') return (answer as (s: Sent) => Response)(s);
    return new Response(typeof answer === 'string' ? answer : JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, sent };
}

function delegated(answer: unknown, over: Partial<McpGuardOptions> = {}) {
  const c = coazPep(answer);
  const guard = new McpGuard({
    client: { url: 'http://pdp' },
    upstreamUrl: UPSTREAM,
    delegate: { url: 'http://coaz-pep:9192/', apiKey: 'check-secret' },
    fetch: c.fetch,
    ...over,
  });
  return { guard, sent: c.sent };
}

const call = { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'make_payment', arguments: { amount: 10 } } };
const raw = (rpc: unknown = call, headers: Record<string, string | string[]> = { authorization: 'Bearer agent-token', 'content-type': 'application/json' }) => ({
  method: 'POST',
  path: '/mcp',
  headers,
  body: typeof rpc === 'string' ? rpc : JSON.stringify(rpc),
});
const token = { sub: 'alice' };

// ---------------------------------------------------------------------------

describe('delegate mode refuses to start misconfigured', () => {
  const base = { client: { url: 'http://pdp' }, upstreamUrl: UPSTREAM };

  it('needs upstreamUrl: coaz-pep runs COAZ against that server', () => {
    expect(() => new McpGuard({ client: { url: 'http://pdp' }, delegate: { url: 'http://coaz-pep:9192', apiKey: 'k' } })).toThrow(/upstreamUrl/);
  });

  it('needs the check API token, unless allowInsecure', () => {
    expect(() => new McpGuard({ ...base, delegate: { url: 'http://coaz-pep:9192' } })).toThrow(/apiKey/);
    const warnings: string[] = [];
    expect(() => new McpGuard({ ...base, delegate: { url: 'http://coaz-pep:9192' }, allowInsecure: true, onWarning: (m) => warnings.push(m) })).not.toThrow();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/allowInsecure/);
  });

  it('needs a usable check API URL', () => {
    expect(() => new McpGuard({ ...base, delegate: { url: 'coaz-pep:9192', apiKey: 'k' } })).toThrow(/http/);
  });

  it('will not let config contradict what the guard says', () => {
    const d = (config: Record<string, string>) => new McpGuard({ ...base, delegate: { url: 'http://coaz-pep:9192', apiKey: 'k', config } });
    expect(() => d({ style: 'rest' })).toThrow(/style/);
    expect(() => d({ mcp_upstream_url: 'https://elsewhere.example/mcp' })).toThrow(/mcp_upstream_url/);
    expect(() => d({ coaz_defaults: 'false' })).toThrow(/coaz_defaults/);
    expect(() => d({ style: 'MCP', mcp_upstream_url: `${UPSTREAM}/`, coaz_defaults: 'TRUE', require_token: 'true' })).not.toThrow();
    expect(() => new McpGuard({ ...base, applyDefaultMappings: false, delegate: { url: 'http://coaz-pep:9192', apiKey: 'k', config: { coaz_defaults: 'false' } } })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------

describe('every MCP request goes to coaz-pep', () => {
  const messages: Array<[string, unknown]> = [
    ['tools/call', call],
    ['ping', { jsonrpc: '2.0', id: 1, method: 'ping' }],
    ['a notification', { jsonrpc: '2.0', method: 'notifications/initialized' }],
    ['tools/list', { jsonrpc: '2.0', id: 2, method: 'tools/list' }],
    ['initialize', { jsonrpc: '2.0', id: 3, method: 'initialize', params: {} }],
    ['a response', { jsonrpc: '2.0', id: 9, result: {} }],
    ['a batch', [call]],
    ['an unknown method', { jsonrpc: '2.0', id: 5, method: 'future/thing' }],
    ['garbage', 'not json at all'],
  ];

  for (const [name, rpc] of messages) {
    it(`asks about ${name}, and a deny is a deny`, async () => {
      const engineError = { jsonrpc: '2.0', id: null, error: { code: CODE_DENIED_V2, message: 'Access denied.' } };
      const { guard, sent } = delegated({ decision: false, response: { status: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(engineError) } });
      const v = await guard.checkToolCall({ raw: raw(rpc), claims: token });
      expect(sent, name).toHaveLength(1);
      expect(v.allow, name).toBe(false);
    });
  }

  it('sends the knobs coaz-pep needs to run COAZ, and nothing it should not see', async () => {
    const { guard, sent } = delegated({ decision: true }, {
      resource: 'https://mcp.bank.example',
      forwardAccessToken: true,
      failMode: 'closed',
      delegate: { url: 'http://coaz-pep:9192/', apiKey: 'check-secret', config: { require_token: 'true', pdp_layers: 'resource' } },
    });
    await guard.checkToolCall({
      raw: raw(call, {
        Authorization: 'Bearer agent-token',
        'X-User-Token': 'user-token',
        DPoP: 'proof',
        'Content-Type': 'application/json',
        'Content-Encoding': 'identity',
        Cookie: 'session=secret',
        'X-Forwarded-For': '10.0.0.1',
        'X-Auth-Principal': 'mallory',
      }),
      claims: token,
    });
    const s = sent[0]!;
    expect(s.url).toBe(CHECK);
    expect((s.init.headers as Record<string, string>)['authorization']).toBe('Bearer check-secret');
    expect(s.init.redirect).toBe('manual');
    expect(s.body.config).toEqual({
      pep_label: 'mcp-edge',
      style: 'mcp',
      mcp_upstream_url: UPSTREAM,
      coaz_defaults: 'true',
      resource: 'https://mcp.bank.example',
      forward_access_token: 'true',
      fail_mode: 'closed',
      require_token: 'true',
      pdp_layers: 'resource',
    });
    expect(s.body.headers).toEqual({
      authorization: 'Bearer agent-token',
      'x-user-token': 'user-token',
      dpop: 'proof',
      'content-type': 'application/json',
      'content-encoding': 'identity',
    });
    expect(s.body).toMatchObject({ method: 'POST', path: '/mcp', body: JSON.stringify(call) });
  });

  it('tells coaz-pep when default mappings are off', async () => {
    const { guard, sent } = delegated({ decision: true }, { applyDefaultMappings: false });
    await guard.checkToolCall({ raw: raw(), claims: token });
    expect(sent[0]!.body.config['coaz_defaults']).toBe('false');
  });

  it('forwards a GET or DELETE on the MCP endpoint too', async () => {
    const { guard, sent } = delegated({ decision: true });
    expect((await guard.checkToolCall({ raw: { method: 'GET', path: '/mcp', headers: { authorization: 'Bearer t' }, body: '' }, claims: token })).allow).toBe(true);
    expect(sent[0]!.body).toMatchObject({ method: 'GET', body: '' });
  });

  it('sends bytes as the text they are, and refuses bytes that are not UTF-8', async () => {
    const { guard, sent } = delegated({ decision: true });
    await guard.checkToolCall({ raw: { headers: {}, body: new TextEncoder().encode(JSON.stringify(call)) }, claims: token });
    expect(sent[0]!.body.body).toBe(JSON.stringify(call));
    const bad = await guard.checkToolCall({ raw: { headers: {}, body: new Uint8Array([0x7b, 0xff, 0x7d]) }, claims: token });
    expect(bad.jsonRpcError?.error.code).toBe(CODE_PARSE_ERROR);
    expect(sent).toHaveLength(1);
  });

  it('needs the raw request, and says so without asking', async () => {
    const { guard, sent } = delegated({ decision: true });
    const v = await guard.checkToolCall({ rpc: call, claims: token });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_MAPPING_ERROR);
    expect(v.jsonRpcError?.id).toBe(4);
    expect(sent).toHaveLength(0);
  });

  it('refuses an rpc that is not what the raw body says', async () => {
    const { guard, sent } = delegated({ decision: true });
    const other = { ...call, params: { name: 'get_balance' } };
    const v = await guard.checkToolCall({ rpc: other, raw: raw(call), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_INVALID_REQUEST);
    expect(sent).toHaveLength(0);
    expect((await guard.checkToolCall({ rpc: call, raw: raw(call), claims: token })).allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe('a delegated permit is decision === true, and carries its headers', () => {
  it('relays upstream_headers and response_headers, so X-PDP-Fail-Open survives', async () => {
    const { guard } = delegated({
      decision: true,
      upstream_headers: { 'X-Auth-Principal': 'alice', 'X-Auth-Agent': 'agent-1', 'X-Auth-Scope': 'payments', 'X-Auth-Acr': '' },
      response_headers: { 'X-PDP-Decision': 'PERMIT', 'X-PDP-Fail-Open': 'https://estate.example' },
    });
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.allow).toBe(true);
    expect(v.upstreamHeaders).toEqual({ 'X-Auth-Principal': 'alice', 'X-Auth-Agent': 'agent-1', 'X-Auth-Scope': 'payments', 'X-Auth-Acr': '' });
    expect(v.responseHeaders).toEqual({ 'X-PDP-Decision': 'PERMIT', 'X-PDP-Fail-Open': 'https://estate.example' });
    expect(v.message).toEqual(call);
  });

  it('removes the client copies of X-Auth-* that coaz-pep did not mention', async () => {
    const { guard } = delegated({ decision: true, upstream_headers: { 'x-auth-principal': 'alice' } });
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.upstreamHeaders).toEqual({ 'x-auth-principal': 'alice', 'X-Auth-Agent': '', 'X-Auth-Scope': '', 'X-Auth-Acr': '' });
  });

  for (const answer of [{ decision: 'true' }, { decision: 1 }, { decision: {} }, { decision: null }, {}, 'true', 'false', '1', '[true]', 'not json']) {
    it(`does not permit on ${JSON.stringify(answer)}`, async () => {
      const { guard } = delegated(answer);
      const handler = vi.fn(async () => 'ran');
      const v = await guard.checkToolCall({ raw: raw(), claims: token });
      expect(v.allow).toBe(false);
      expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
      expect(await guard.wrap(handler)(call, token, { raw: raw() })).toMatchObject({ error: { code: CODE_PDP_ERROR } });
      expect(handler).not.toHaveBeenCalled();
    });
  }

  it('does not permit when the headers it must apply are malformed', async () => {
    for (const bad of [{ decision: true, upstream_headers: { 'X-Auth-Principal': 5 } }, { decision: true, response_headers: ['x'] }, { decision: true, upstream_headers: 'X-Auth-Principal: alice' }]) {
      const { guard } = delegated(bad);
      expect((await guard.checkToolCall({ raw: raw(), claims: token })).allow, JSON.stringify(bad)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------

describe('a delegated deny is relayed verbatim', () => {
  it('a COAZ deny: HTTP 200 and the engine\'s JSON-RPC error', async () => {
    const engineError = { jsonrpc: '2.0', id: 4, error: { code: CODE_DENIED_V2, message: 'Access denied: over limit', data: { authz_challenge: { type: 'resource_authorisation', scope: 'pay' } } } };
    const response = { status: 200, headers: { 'Content-Type': 'application/json', 'X-PDP-Decision': 'DENY' }, body: JSON.stringify(engineError) };
    const { guard } = delegated({ decision: false, response });
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.response).toEqual(response);
    expect(v.jsonRpcError).toEqual(engineError);
    expect(v.verdict).toMatchObject({ allow: false, kind: 'step_up_required', reason: 'Access denied: over limit' });
  });

  it('a 401 challenge keeps its status and WWW-Authenticate, and wrap() still gets a JSON-RPC error', async () => {
    const response = { status: 401, headers: { 'WWW-Authenticate': 'Bearer error="login_required"', 'Content-Type': 'application/json' }, body: '{"error":"login_required","reason":"The gateway requires an authenticated user."}' };
    const { guard } = delegated({ decision: false, response });
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.response).toEqual(response);
    expect(v.verdict.kind).toBe('unauthenticated');
    expect(v.jsonRpcError).toMatchObject({ id: 4, error: { code: CODE_DENIED_V2 } });
    const handler = vi.fn(async () => 'ran');
    expect(await guard.wrap(handler)(call, token, { raw: raw() })).toMatchObject({ error: { code: CODE_DENIED_V2 } });
    expect(handler).not.toHaveBeenCalled();
  });

  it('a refusal keeps its 400 or 415', async () => {
    const refusal = { jsonrpc: '2.0', id: null, error: { code: CODE_INVALID_REQUEST, message: 'Invalid Request: JSON-RPC batches are not supported' } };
    const { guard } = delegated({ decision: false, response: { status: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(refusal) } });
    const v = await guard.checkToolCall({ raw: raw([call]), claims: token });
    expect(v.response?.status).toBe(400);
    expect(v.jsonRpcError).toEqual(refusal);
    expect(v.verdict.kind).toBe('mapping_error');
  });

  it('a deny with no rendering still denies, with one of its own', async () => {
    const { guard } = delegated({ decision: false });
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.allow).toBe(false);
    expect(v.response).toMatchObject({ status: 200 });
    expect(v.jsonRpcError).toMatchObject({ id: 4, error: { code: CODE_DENIED_V2 } });
  });

  it('a deny whose rendering is malformed is rendered here', async () => {
    const { guard } = delegated({ decision: false, response: { status: 'teapot', headers: { a: 1 }, body: 7 } });
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.allow).toBe(false);
    expect(v.response).toMatchObject({ status: 200 });
  });
});

// ---------------------------------------------------------------------------

describe('coaz-pep unavailable is a fail-closed -32603, generic on the wire', () => {
  const failures: Array<[string, (s: Sent) => Response | Promise<Response>, RegExp]> = [
    ['a 401', () => new Response('', { status: 401 }), /CHECK_API_TOKEN/],
    ['a 500', () => new Response('panic at pep.go:42', { status: 500 }), /500/],
    ['a redirect', () => new Response('', { status: 307, headers: { location: 'http://evil.example/v1/mcp/check' } }), /307/],
    ['a network failure', () => { throw new TypeError('fetch failed'); }, /fetch failed/],
    ['an oversized answer', () => new Response(`{"decision":true,"pad":"${'x'.repeat(1_048_576)}"}`, { status: 200 }), /exceeds/],
  ];
  for (const [name, answer, detail] of failures) {
    it(name, async () => {
      const { guard, sent } = delegated(answer);
      const v = await guard.checkToolCall({ raw: raw(), claims: token });
      expect(v.allow).toBe(false);
      expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
      expect(v.jsonRpcError?.error.message).toBe('Authorization service unreachable; denying (fail-closed).');
      expect(v.verdict.detail).toMatch(detail);
      expect(sent).toHaveLength(1);
    });
  }

  it('a timeout', async () => {
    const { guard } = delegated(
      (s: Sent) =>
        new Promise<Response>((_r, reject) => {
          s.init.signal?.addEventListener('abort', () => {
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
      { delegate: { url: 'http://coaz-pep:9192', apiKey: 'k', timeoutMs: 5 } },
    );
    const v = await guard.checkToolCall({ raw: raw(), claims: token });
    expect(v.verdict.detail).toMatch(/timed out/);
  });
});

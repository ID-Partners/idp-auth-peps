import { describe, expect, it, vi } from 'vitest';

import { CODE_DENIED_V2, CODE_INVALID_REQUEST, CODE_MAPPING_ERROR, CODE_PARSE_ERROR, CODE_PDP_ERROR, McpGuard, buildRequest, type ToolDefinition } from '../src/mcp.js';
import { extractClaims } from '../src/claims.js';

/** A PDP stub that records every request it is asked. */
function pdp(answer: unknown = { decision: true }) {
  const asked: Array<Record<string, unknown>> = [];
  const fetch = vi.fn(async (_u: unknown, init?: RequestInit) => {
    asked.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, asked };
}

const token = { sub: 'alice', client_id: 'agent-1', aud: 'https://mcp.example.com' };
const declared: ToolDefinition = {
  name: 'make_payment',
  inputSchema: {
    'x-authzen-mapping': {
      evaluation: {
        subject: { type: 'identity', id: '$token.sub' },
        action: { name: 'make_payment' },
        resource: { type: 'payment', id: '$params.arguments.payment_id', properties: { amount: '$params.arguments.amount' } },
      },
    },
  },
};
const call = (name: unknown, args: Record<string, unknown> = { payment_id: 'p1', amount: 10 }) => ({
  jsonrpc: '2.0',
  id: 7,
  method: 'tools/call',
  params: { name, arguments: args },
});

function guard(answer: unknown = { decision: true }, over: Record<string, unknown> = {}) {
  const p = pdp(answer);
  const g = new McpGuard({ client: { url: 'http://pdp', fetch: p.fetch }, tools: [declared, { name: 'weather' }], ...over });
  return { g, asked: p.asked };
}

// ---------------------------------------------------------------------------

describe('the local guard refuses what it cannot positively read', () => {
  const refused: Array<[string, unknown]> = [
    ['undefined', undefined],
    ['null', null],
    ['a batch', [call('make_payment'), call('make_payment')]],
    ['an empty array', []],
    ['a string', 'tools/call'],
    ['a number', 42],
    ['a boolean', true],
    ['a Buffer', Buffer.from(JSON.stringify(call('make_payment')))],
    ['an empty object', {}],
    ['a non-string method', { jsonrpc: '2.0', id: 1, method: 5 }],
    ['a name that is an array', call(['make_payment'])],
    ['a name that is a number', call(123)],
    ['an empty name', call('')],
    ['no params', { jsonrpc: '2.0', id: 1, method: 'tools/call' }],
    ['params that are an array', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: ['make_payment'] }],
    ['params that are null', { jsonrpc: '2.0', id: 1, method: 'ping', params: null }],
    ['Method beside method', { ...call('make_payment'), Method: 'ping' }],
    ['Params beside params', { ...call('weather'), Params: { name: 'make_payment' } }],
    ['Name beside name', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'weather', Name: 'make_payment' } }],
    ['ID beside id', { ...call('make_payment'), ID: 8 }],
    ['JSONRPC beside jsonrpc', { ...call('make_payment'), JSONRPC: '1.0' }],
    ['a long-s variant of params', { ...call('weather'), 'paramſ': { name: 'make_payment' } }],
    ['a Kelvin-sign variant inside params', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'weather', kind: 'a', 'Kind': 'b' } }],
    ['an id that is an object', { jsonrpc: '2.0', id: {}, method: 'ping' }],
    ['a response with both result and error', { jsonrpc: '2.0', id: 1, result: {}, error: { code: 1, message: 'x' } }],
    ['a result with no id', { jsonrpc: '2.0', result: {} }],
  ];

  for (const [name, rpc] of refused) {
    it(`refuses ${name} without asking the PDP`, async () => {
      const { g, asked } = guard();
      const v = await g.checkToolCall({ rpc, claims: token });
      expect(v.allow, name).toBe(false);
      expect(v.jsonRpcError?.error.code, name).toBe(CODE_INVALID_REQUEST);
      expect(v.response?.status, name).toBe(400);
      expect(v.response?.headers['X-PDP-Decision']).toBe('DENY');
      expect(v.response?.headers['Content-Type']).toBe('application/json');
      expect(JSON.parse(v.response!.body)).toEqual(v.jsonRpcError);
      expect(v.jsonRpcError?.error.message).toMatch(/^Invalid Request: /);
      expect(asked, name).toHaveLength(0);
    });
  }

  it('uses the request id when it was readable', async () => {
    const { g } = guard();
    expect((await g.checkToolCall({ rpc: call(123), claims: token })).jsonRpcError?.id).toBe(7);
    expect((await g.checkToolCall({ rpc: [call('x')], claims: token })).jsonRpcError?.id).toBeNull();
  });

  it('never throws, whatever it is handed', async () => {
    const { g } = guard();
    for (const args of [{ rpc: undefined, claims: undefined }, { rpc: call('make_payment'), claims: undefined }, {}, { rpc: call('make_payment'), claims: null }] as never[]) {
      await expect(g.checkToolCall(args)).resolves.toMatchObject({ allow: false });
    }
    await expect(g.checkToolCall(undefined as never)).resolves.toMatchObject({ allow: false });
  });

  it('passes a JSON-RPC response through: it answers the server, it asks nothing', async () => {
    const { g, asked } = guard({ decision: false });
    for (const rpc of [{ jsonrpc: '2.0', id: 3, result: { content: [] } }, { jsonrpc: '2.0', id: 'x', error: { code: -1, message: 'declined' } }]) {
      const v = await g.checkToolCall({ rpc, claims: token });
      expect(v).toMatchObject({ allow: true, coazTool: false });
    }
    expect(asked).toHaveLength(0);
  });

  it('a declared tool cannot be dodged by a name the tool map does not recognise', async () => {
    // name: ["make_payment"] used to miss the declared tool and fall through as undeclared.
    const { g, asked } = guard({ decision: false }, { applyDefaultMappings: false });
    expect((await g.checkToolCall({ rpc: call(['make_payment']), claims: token })).allow).toBe(false);
    expect(asked).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------

describe('default mappings are on unless turned off', () => {
  it('judges an undeclared tool against the binding default', async () => {
    const { g, asked } = guard({ decision: false, context: { reason: 'not for you' } });
    const v = await g.checkToolCall({ rpc: call('weather'), claims: token });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED_V2);
    expect(asked[0]).toMatchObject({ action: { name: 'tools/call' }, resource: { type: 'tool', id: 'weather' } });
  });

  it('judges every other method, and denies one it does not know', async () => {
    const { g, asked } = guard({ decision: true });
    expect((await g.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'tools/list' }, claims: token })).allow).toBe(true);
    expect(asked[0]).toMatchObject({ action: { name: 'tools/list' }, resource: { type: 'mcp_server', id: 'https://mcp.example.com' } });
    const unknown = await g.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'future/thing' }, claims: token });
    expect(unknown.allow).toBe(false);
    expect(unknown.response?.status).toBe(200);
    expect(asked).toHaveLength(1);
  });

  it('an explicit false keeps the old pass-through', async () => {
    const { g, asked } = guard({ decision: false }, { applyDefaultMappings: false });
    expect((await g.checkToolCall({ rpc: call('weather'), claims: token })).allow).toBe(true);
    expect((await g.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'tools/list' }, claims: token })).allow).toBe(true);
    expect(asked).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------

describe('a policy deny and a permit say what to do with the HTTP exchange', () => {
  it('a deny is HTTP 200 with the JSON-RPC error as the body', async () => {
    const { g } = guard({ decision: false, context: { reason: 'over limit', step_up_required: true, step_up_scope: 'pay' } });
    const v = await g.checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.response).toMatchObject({ status: 200, headers: { 'Content-Type': 'application/json', 'X-PDP-Decision': 'DENY' } });
    expect(JSON.parse(v.response!.body)).toEqual(v.jsonRpcError);
    expect(v.jsonRpcError?.error.data?.['authz_challenge']).toMatchObject({ type: 'resource_authorisation', scope: 'pay' });
  });

  it('a permit carries the identity to assert upstream, with an empty value meaning remove', async () => {
    const { g } = guard();
    const v = await g.checkToolCall({ rpc: call('make_payment'), claims: extractClaims({ sub: 'alice', scope: 'a b', acr: 'urn:mfa' }) });
    expect(v.upstreamHeaders).toEqual({ 'X-Auth-Principal': 'alice', 'X-Auth-Agent': '', 'X-Auth-Scope': 'a b', 'X-Auth-Acr': 'urn:mfa' });
  });

  it('a fail-open permit says so on the response', async () => {
    const fetch = vi.fn(async (url: unknown) =>
      String(url).startsWith('http://down') ? new Response('', { status: 503 }) : new Response('{"decision":true}', { status: 200 }),
    ) as unknown as typeof globalThis.fetch;
    const g = new McpGuard({ client: { url: 'http://pdp', fetch, layers: ['http://down fail-open', 'static'] }, tools: [declared] });
    const v = await g.checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.allow).toBe(true);
    expect(v.responseHeaders).toEqual({ 'X-PDP-Fail-Open': 'http://down' });
  });

  it('a PDP failure is generic on the wire', async () => {
    const fetch = vi.fn(async () => new Response('db exploded at 10.0.0.1', { status: 500 })) as unknown as typeof globalThis.fetch;
    const g = new McpGuard({ client: { url: 'http://pdp.internal', fetch }, tools: [declared] });
    const v = await g.checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(v.response!.body).not.toMatch(/pdp\.internal|10\.0\.0\.1|500/);
    expect(v.verdict.detail).toMatch(/500/);
  });
});

// ---------------------------------------------------------------------------

describe('with the raw body, the guard judges the bytes, not a parse of them', () => {
  const raw = (body: string | Uint8Array, headers: Record<string, string> = {}) => ({ headers: { 'content-type': 'application/json', ...headers }, body });

  const parseErrors: Array<[string, string | Uint8Array]> = [
    ['not JSON', 'tools/call please'],
    ['an empty body', ''],
    ['a BOM', `﻿${JSON.stringify(call('make_payment'))}`],
    ['a BOM in bytes', new Uint8Array([0xef, 0xbb, 0xbf, ...Buffer.from(JSON.stringify(call('make_payment')))])],
    ['invalid UTF-8', new Uint8Array([...Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"'), 0xff, ...Buffer.from('"}}')])],
    ['trailing data', `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' })} ${JSON.stringify(call('make_payment'))}`],
    ['a truncated body', JSON.stringify(call('make_payment')).slice(0, 40)],
    ['a bad escape', '{"jsonrpc":"2.0","id":1,"method":"tools/\\qcall"}'],
    ['a raw control character', '{"jsonrpc":"2.0","id":1,"method":"pi\u0001ng"}'],
  ];
  for (const [name, body] of parseErrors) {
    it(`answers ${name} with a parse error`, async () => {
      const { g, asked } = guard();
      const v = await g.checkToolCall({ raw: raw(body), claims: token });
      expect(v.allow, name).toBe(false);
      expect(v.jsonRpcError, name).toEqual({ jsonrpc: '2.0', id: null, error: { code: CODE_PARSE_ERROR, message: 'Parse error' } });
      expect(v.response?.status, name).toBe(400);
      expect(asked).toHaveLength(0);
    });
  }

  const invalid: Array<[string, string]> = [
    ['an exact duplicate params', '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather"},"params":{"name":"make_payment"}}'],
    ['an exact duplicate method', '{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"make_payment"}}'],
    ['an escaped duplicate', '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather"},"\\u0070arams":{"name":"make_payment"}}'],
    ['a duplicate inside arguments', '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"make_payment","arguments":{"amount":1,"amount":1000000}}}'],
    ['a case variant of params', '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather"},"Params":{"name":"make_payment"}}'],
    ['a batch', `[${JSON.stringify(call('make_payment'))}]`],
    ['a bare string', '"tools/call"'],
  ];
  for (const [name, body] of invalid) {
    it(`answers ${name} with an invalid request`, async () => {
      const { g, asked } = guard();
      const v = await g.checkToolCall({ raw: raw(body), claims: token });
      expect(v.allow, name).toBe(false);
      expect(v.jsonRpcError?.error.code, name).toBe(CODE_INVALID_REQUEST);
      expect(v.response?.status, name).toBe(400);
      expect(asked).toHaveLength(0);
    });
  }

  it('refuses a body nested deeper than it will read, without falling over', async () => {
    const { g } = guard();
    const deep = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather","arguments":${'['.repeat(5000)}${']'.repeat(5000)}}}`;
    const v = await g.checkToolCall({ raw: raw(deep), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_INVALID_REQUEST);
  });

  it('refuses a Content-Encoding it cannot read, and accepts identity', async () => {
    const { g, asked } = guard();
    const body = JSON.stringify(call('make_payment'));
    for (const encoding of ['gzip', 'deflate', 'br', 'gzip, identity']) {
      const v = await g.checkToolCall({ raw: raw(body, { 'content-encoding': encoding }), claims: token });
      expect(v.response?.status, encoding).toBe(415);
      expect(v.jsonRpcError?.error).toEqual({ code: CODE_INVALID_REQUEST, message: 'Invalid Request: Content-Encoding not supported by the PEP' });
    }
    expect(asked).toHaveLength(0);
    expect((await g.checkToolCall({ raw: raw(body, { 'Content-Encoding': 'identity' }), claims: token })).allow).toBe(true);
    expect((await g.checkToolCall({ raw: { headers: { 'content-encoding': ['identity'] }, body }, claims: token })).allow).toBe(true);
  });

  it('judges the raw body, and refuses an rpc that does not match it', async () => {
    const { g, asked } = guard();
    const body = JSON.stringify(call('make_payment', { payment_id: 'p9', amount: 5 }));
    const v = await g.checkToolCall({ raw: raw(body), claims: token });
    expect(v.allow).toBe(true);
    expect(asked[0]).toMatchObject({ resource: { id: 'p9' } });
    expect(v.message).toEqual(JSON.parse(body));
    const same = await g.checkToolCall({ rpc: JSON.parse(body), raw: raw(body), claims: token });
    expect(same.allow).toBe(true);
    const other = await g.checkToolCall({ rpc: call('weather'), raw: raw(body), claims: token });
    expect(other).toMatchObject({ allow: false, jsonRpcError: { error: { code: CODE_INVALID_REQUEST } } });
  });

  it('accepts bytes as well as a string', async () => {
    const { g } = guard();
    const v = await g.checkToolCall({ raw: raw(new TextEncoder().encode(JSON.stringify(call('make_payment')))), claims: token });
    expect(v.allow).toBe(true);
  });

  it('refuses an argument JSON cannot carry to the PDP', async () => {
    const { g, asked } = guard();
    const v = await g.checkToolCall({ raw: raw('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"make_payment","arguments":{"payment_id":"p1","amount":1e999}}}'), claims: token });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(asked).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------

describe('wrap() runs the handler only on an explicit allow', () => {
  it('returns the refusal and never runs the handler for anything unreadable', async () => {
    const { g } = guard();
    const handler = vi.fn(async () => 'ran');
    const wrapped = g.wrap(handler);
    for (const rpc of [undefined, [call('make_payment')], call(['make_payment']), 'x']) {
      const out = await wrapped(rpc as never, token);
      expect(out).toMatchObject({ error: { code: CODE_INVALID_REQUEST } });
    }
    expect(handler).not.toHaveBeenCalled();
  });

  it('hands the handler the judged message and the verdict', async () => {
    const { g } = guard();
    const handler = vi.fn(async (_rpc: unknown, v: { upstreamHeaders?: Record<string, string> }) => v.upstreamHeaders?.['X-Auth-Principal']);
    const body = JSON.stringify(call('make_payment'));
    expect(await g.wrap(handler)(undefined as never, token, { raw: { headers: {}, body } })).toBe('alice');
    expect(handler.mock.calls[0]?.[0]).toEqual(JSON.parse(body));
  });
});

// ---------------------------------------------------------------------------

describe('a token with several audiences', () => {
  const list = { jsonrpc: '2.0', id: 1, method: 'tools/list' };

  it('names this server when the guard knows its own identifier', async () => {
    const { g, asked } = guard({ decision: true }, { resource: 'https://mcp.example.com/' });
    const v = await g.checkToolCall({ rpc: list, claims: { ...token, aud: ['https://other.example', 'https://mcp.example.com'] } });
    expect(v.allow).toBe(true);
    expect(asked[0]).toMatchObject({ resource: { type: 'mcp_server', id: 'https://mcp.example.com' } });
  });

  it('takes the only one there is', async () => {
    const { g, asked } = guard();
    expect((await g.checkToolCall({ rpc: list, claims: { ...token, aud: ['https://mcp.example.com'] } })).allow).toBe(true);
    expect(asked[0]).toMatchObject({ resource: { id: 'https://mcp.example.com' } });
  });

  it('is a mapping error when it cannot tell which one is this server', async () => {
    const { g, asked } = guard();
    const v = await g.checkToolCall({ rpc: list, claims: { ...token, aud: ['https://a.example', 'https://b.example'] } });
    expect(v.jsonRpcError?.error.code).toBe(CODE_MAPPING_ERROR);
    expect(asked).toHaveLength(0);
  });

  it('does not matter to a method that is not about the server', async () => {
    const { g } = guard();
    expect((await g.checkToolCall({ rpc: call('make_payment'), claims: { ...token, aud: ['https://a.example', 'https://b.example'] } })).allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe('a v1 mapping may not drop an identifying field', () => {
  const v1 = {
    subject: [{ type: "'user'", id: 'token.sub' }],
    resource: [{ type: "'payment'", id: 'params.arguments.payment_id' }],
    context: [{ agent: 'token.client_id' }],
  };

  it('an absent subject is a mapping error', () => {
    expect(() => buildRequest('make_payment', v1, { arguments: { payment_id: 'p1' } }, { client_id: 'agent-1' })).toThrow(/subject\.id/);
  });

  it('an absent declared resource.id is a mapping error', () => {
    expect(() => buildRequest('make_payment', v1, { arguments: {} }, token)).toThrow(/resource\.id/);
  });

  it('a boxcar entry that loses its id is a mapping error too', () => {
    const boxcar = { ...v1, resource: [{ type: "'account'", id: 'params.arguments.from' }, { type: "'account'", id: 'params.arguments.to' }] };
    expect(() => buildRequest('transfer', boxcar, { arguments: { from: 'a1' } }, token)).toThrow(/evaluations\[1\]\.resource\.id/);
    expect(buildRequest('transfer', boxcar, { arguments: { from: 'a1', to: 'a2' } }, token).batch).toBe(true);
  });

  it('through the guard, the PDP is never asked', async () => {
    const p = pdp();
    const g = new McpGuard({ client: { url: 'http://pdp', fetch: p.fetch }, tools: [{ name: 'legacy', coaz: true, 'x-coaz-mapping': v1 }] });
    const v = await g.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'legacy', arguments: {} } }, claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_MAPPING_ERROR);
    expect(p.asked).toHaveLength(0);
  });
});

import { describe, expect, it, vi } from 'vitest';

import { CODE_DENIED_V2, CODE_PDP_ERROR, McpGuard, type ToolDefinition } from '../src/mcp.js';

const UPSTREAM = 'http://mcp.internal/mcp';
const token = { sub: 'alice', client_id: 'agent-1' };

const declared: ToolDefinition = {
  name: 'make_payment',
  inputSchema: {
    'x-authzen-mapping': {
      evaluation: {
        subject: { type: 'identity', id: '$token.sub' },
        action: { name: 'make_payment' },
        resource: { type: 'payment', id: '$params.arguments.payment_id' },
      },
    },
  },
};
const call = (name: string) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { payment_id: 'p1' } } });

interface Seen {
  method: string;
  params?: Record<string, unknown>;
  headers: Record<string, string>;
  redirect?: RequestRedirect;
}

/**
 * An MCP server and a PDP behind one fetch. `serve` answers each JSON-RPC message the
 * guard sends upstream; the PDP permits and records what it was asked.
 */
function world(serve: (msg: { method: string; id?: unknown; params?: Record<string, unknown> }, headers: Record<string, string>) => Response | Promise<Response>) {
  const upstream: Seen[] = [];
  const asked: Array<Record<string, unknown>> = [];
  const fetch = vi.fn(async (u: unknown, init?: RequestInit) => {
    if (String(u).startsWith('http://pdp')) {
      asked.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response('{"decision":true}', { status: 200 });
    }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers as Record<string, string>) ?? {})) headers[k.toLowerCase()] = v;
    const msg = JSON.parse(String(init?.body)) as { method: string; id?: unknown; params?: Record<string, unknown> };
    upstream.push({ method: msg.method, ...(msg.params ? { params: msg.params } : {}), headers, ...(init?.redirect ? { redirect: init.redirect } : {}) });
    return serve(msg, headers);
  }) as unknown as typeof globalThis.fetch;
  return { fetch, upstream, asked };
}

const result = (id: unknown, r: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ jsonrpc: '2.0', id, result: r }), { status: 200, headers: { 'content-type': 'application/json', ...headers } });

function gateway(fetch: typeof globalThis.fetch, over: Record<string, unknown> = {}) {
  return new McpGuard({ client: { url: 'http://pdp', fetch }, upstreamUrl: UPSTREAM, fetch, ...over });
}

// ---------------------------------------------------------------------------

describe('gateway discovery follows nextCursor', () => {
  it('finds a declared tool on the second page and enforces its declaration', async () => {
    const w = world((msg) => {
      const cursor = msg.params?.['cursor'];
      if (cursor === undefined) return result(msg.id, { tools: [{ name: 'weather' }], nextCursor: 'page-2' });
      if (cursor === 'page-2') return result(msg.id, { tools: [declared] });
      return new Response('', { status: 400 });
    });
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.allow).toBe(true);
    // The declared question, not the default one a page-1 view would have asked.
    expect(w.asked[0]).toMatchObject({ action: { name: 'make_payment' }, resource: { type: 'payment', id: 'p1' } });
    expect(w.upstream.map((s) => s.params?.['cursor'])).toEqual([undefined, 'page-2']);
  });

  it('gives up, closed, past the page cap', async () => {
    let n = 0;
    const w = world((msg) => result(msg.id, { tools: [{ name: `t${n}` }], nextCursor: `c${++n}` }));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(v.verdict.detail).toMatch(/32 pages/);
    expect(w.asked).toHaveLength(0);
  });

  it('gives up, closed, on a cursor it has seen before', async () => {
    const w = world((msg) => result(msg.id, { tools: [{ name: 'weather' }], nextCursor: 'same' }));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.verdict.detail).toMatch(/cursor/);
  });

  it('refuses a tool listed twice, differently', async () => {
    const other = { ...declared, inputSchema: { 'x-authzen-mapping': { evaluation: { subject: { type: 'identity', id: '$token.sub' }, action: { name: 'noop' }, resource: { type: 'x', id: '1' } } } } };
    const w = world((msg) => (msg.params?.['cursor'] === 'p2' ? result(msg.id, { tools: [other] }) : result(msg.id, { tools: [declared], nextCursor: 'p2' })));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.verdict.detail).toMatch(/twice/);
    const same = world((msg) => (msg.params?.['cursor'] === 'p2' ? result(msg.id, { tools: [declared] }) : result(msg.id, { tools: [declared], nextCursor: 'p2' })));
    expect((await gateway(same.fetch).checkToolCall({ rpc: call('make_payment'), claims: token })).allow).toBe(true);
  });

  it('refuses a nextCursor that is not a string', async () => {
    const w = world((msg) => result(msg.id, { tools: [], nextCursor: 7 }));
    expect((await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token })).verdict.detail).toMatch(/nextCursor/);
  });

  it('skips a listed tool with no usable name', async () => {
    const w = world((msg) => result(msg.id, { tools: [{ name: '' }, { title: 'nameless' }, 'junk', declared] }));
    expect((await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token })).allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe('gateway discovery is bounded', () => {
  it('times out a server that never answers', async () => {
    const fetch = vi.fn(async (u: unknown, init?: RequestInit) => {
      if (String(u).startsWith('http://pdp')) return new Response('{"decision":true}');
      return new Promise<Response>((_r, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    }) as unknown as typeof globalThis.fetch;
    const started = Date.now();
    const v = await gateway(fetch, { discoveryTimeoutMs: 20 }).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(v.verdict.detail).toMatch(/timed out/);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('refuses an answer over 4 MiB', async () => {
    const w = world((msg) => result(msg.id, { tools: [declared], pad: 'x'.repeat(4 * 1_048_576) }));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
  });

  it('shares one discovery between concurrent calls', async () => {
    let lists = 0;
    const w = world(async (msg) => {
      if (msg.method === 'tools/list') lists++;
      await new Promise((r) => setTimeout(r, 5));
      return result(msg.id, { tools: [declared] });
    });
    const g = gateway(w.fetch);
    const all = await Promise.all(Array.from({ length: 5 }, () => g.checkToolCall({ rpc: call('make_payment'), claims: token })));
    expect(all.every((v) => v.allow)).toBe(true);
    expect(lists).toBe(1);
  });

  it('does not follow a redirect', async () => {
    const w = world(() => new Response('', { status: 307, headers: { location: 'http://evil.example/mcp' } }));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(w.upstream.every((s) => s.redirect === 'manual')).toBe(true);
  });

  it('treats a JSON-RPC error as a failure', async () => {
    const w = world((msg) => new Response(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'no' } }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(v.verdict.detail).toMatch(/-32601/);
  });
});

// ---------------------------------------------------------------------------

describe('gateway discovery opens a session when the server wants one', () => {
  function sessionful() {
    return world((msg, headers) => {
      if (msg.method === 'initialize') return result(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 's', version: '1' } }, { 'mcp-session-id': 'sess-1' });
      if (headers['mcp-session-id'] !== 'sess-1') return new Response('{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Bad Request: No valid session ID provided"}}', { status: 400 });
      if (msg.method === 'notifications/initialized') return new Response(null, { status: 202 });
      if (msg.params?.['cursor'] === 'p2') return result(msg.id, { tools: [declared] });
      return result(msg.id, { tools: [{ name: 'weather' }], nextCursor: 'p2' });
    });
  }

  it('initializes, says so, and lists every page in the session', async () => {
    const w = sessionful();
    const v = await gateway(w.fetch, { discoveryHeaders: { authorization: 'Bearer gateway' } }).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.allow).toBe(true);
    expect(w.upstream.map((s) => s.method)).toEqual(['tools/list', 'initialize', 'notifications/initialized', 'tools/list', 'tools/list']);
    const init = w.upstream[1]!;
    expect(init.params).toMatchObject({ protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: '@id-partners/authzen-pep' } });
    for (const s of w.upstream.slice(2)) expect(s.headers['mcp-session-id']).toBe('sess-1');
    for (const s of w.upstream) {
      expect(s.headers['mcp-protocol-version']).toBe('2025-06-18');
      expect(s.headers['authorization']).toBe('Bearer gateway');
      expect(s.headers['accept']).toBe('application/json, text/event-stream');
    }
  });

  it('fails closed when the handshake fails too', async () => {
    const w = world(() => new Response('', { status: 400 }));
    const v = await gateway(w.fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(w.upstream.map((s) => s.method)).toEqual(['tools/list', 'initialize']);
  });

  it('a deny is still a deny once discovered', async () => {
    const fetch = vi.fn(async (u: unknown, init?: RequestInit) => {
      if (String(u).startsWith('http://pdp')) return new Response('{"decision":false,"context":{"reason":"no"}}', { status: 200 });
      const msg = JSON.parse(String(init?.body)) as { id?: unknown };
      return result(msg.id, { tools: [declared] });
    }) as unknown as typeof globalThis.fetch;
    const v = await gateway(fetch).checkToolCall({ rpc: call('make_payment'), claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED_V2);
  });
});

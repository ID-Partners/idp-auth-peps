import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { AuthzenClient } from '../src/client.js';
import { toHttpChallenge } from '../src/challenge.js';
import { decodeJwtSegment, extractClaims, hasScope } from '../src/claims.js';
import { PdpDiscovery } from '../src/discovery.js';
import { authzenMiddleware, pathMapper } from '../src/express.js';
import { FederationEntity } from '../src/federation.js';
import { BodyTooLargeError, discard, readCapped } from '../src/http.js';
import { CODE_INVALID_REQUEST, CODE_MAPPING_ERROR, CODE_PARSE_ERROR, CODE_PDP_ERROR, McpGuard, buildRequest, buildRequestV2, evaluateExpression, isAnchoredSubject } from '../src/mcp.js';

/** A body that errors on its first read, with an error of the given name. */
const breaking = (name = 'Error') =>
  new ReadableStream<Uint8Array>({
    pull(controller) {
      const err = new Error(name === 'AbortError' ? 'The operation was aborted' : 'socket hang up');
      err.name = name;
      controller.error(err);
    },
  });

const token = { sub: 'alice', client_id: 'agent-1' };

// ---------------------------------------------------------------------------

describe('reading bodies', () => {
  it('refuses a declared length over the cap without reading', async () => {
    const res = { headers: new Headers({ 'content-length': '5000000' }), body: new Response('x').body } as unknown as Response;
    await expect(readCapped(res, 1024)).rejects.toBeInstanceOf(BodyTooLargeError);
  });

  it('reads a body-less response as empty', async () => {
    expect(await readCapped(new Response(null, { status: 200 }), 10)).toBe('');
  });

  it('lets go of a body it cannot cancel', async () => {
    const res = new Response('locked');
    res.body!.getReader(); // a locked stream refuses cancel()
    await expect(discard(res)).resolves.toBeUndefined();
  });
});

describe('claims and challenges at the edges', () => {
  it('handles an empty segment, an empty wanted scope and an act string that is not JSON', () => {
    expect(decodeJwtSegment('.b.c', 0)).toBeNull();
    expect(hasScope('a b', '')).toBe(true);
    expect(extractClaims({ sub: 'u', act: '{not json' }).actor).toBe('');
  });

  it('leaves out a parameter with no value', () => {
    const out = toHttpChallenge({ allow: false, kind: 'unauthenticated', reason: '', context: { acr_values: 'urn:mfa' } });
    expect(out.headers['WWW-Authenticate']).toBe('Bearer error="login_required", acr_values="urn:mfa"');
  });
});

// ---------------------------------------------------------------------------

describe('client edges', () => {
  const req = { subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } };

  it('a PDP answer cut off by the timeout is unavailable', async () => {
    const fetch = vi.fn(async (u: unknown) =>
      String(u).startsWith('http://slow') ? new Response(breaking('AbortError'), { status: 200 }) : new Response('{"decision":true}'),
    ) as unknown as typeof globalThis.fetch;
    const client = new AuthzenClient({ url: 'http://ok', fetch, layers: ['http://slow fail-open', 'static'] });
    const v = await client.evaluate(req);
    expect(v).toMatchObject({ allow: true, failedOpen: ['http://slow'] });
    expect(v.detail).toMatch(/timed out/);
  });

  it('keeps an identity-proofing obligation through a later plain permit', async () => {
    const fetch = vi.fn(async (u: unknown) =>
      String(u).startsWith('http://first')
        ? new Response(JSON.stringify({ decision: true, context: { reason: 'prove it', identity_proofing_required: true, identity_proofing_doctype: 'org.iso.18013.5.1.mDL' } }))
        : new Response('{"decision":true}'),
    ) as unknown as typeof globalThis.fetch;
    const client = new AuthzenClient({ url: 'http://second', fetch, layers: ['http://first', 'static'] });
    const v = await client.evaluate(req);
    expect(v).toMatchObject({ allow: true, reason: 'prove it', context: { identity_proofing_required: true, identity_proofing_doctype: 'org.iso.18013.5.1.mDL' } });
  });
});

// ---------------------------------------------------------------------------

describe('discovery edges', () => {
  const quiet = { onWarning: () => {} };

  it('refuses a resource that is not an absolute URL', async () => {
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: 'https://static.example', fetch: vi.fn() as never, pdpAllowlist: ['https://p.example'], resourceAllowlist: ['https://r.example'], ...quiet });
    await expect(d.resolve('not a url')).rejects.toMatchObject({ kind: 'not_allowed' });
  });

  it('a metadata body that breaks off is an outage', async () => {
    const fetch = vi.fn(async () => new Response(breaking(), { status: 200 })) as unknown as typeof globalThis.fetch;
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: 'https://static.example', fetch, pdpAllowlist: ['https://p.example'], resourceAllowlist: ['https://r.example'], ...quiet });
    await expect(d.resolve('https://r.example')).rejects.toMatchObject({ kind: 'transient' });
  });

  it('forgets old warnings rather than remembering every subject forever', async () => {
    const warnings: string[] = [];
    const fetch = vi.fn(async () => new Response('', { status: 503 })) as unknown as typeof globalThis.fetch;
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: 'https://static.example', fetch, pdpAllowlist: ['https://p.example'], resourceAllowlist: ['https://r.example'], maxEntries: 4, onWarning: (m) => warnings.push(m) });
    for (let i = 0; i < 1030; i++) await d.resolve(`https://r.example/${i}`).catch(() => {});
    expect(warnings.length).toBe(1030);
    await d.resolve('https://r.example/0').catch(() => {});
    expect(warnings.length).toBe(1031);
  });
});

// ---------------------------------------------------------------------------

describe('construction warnings go to the console by default', () => {
  it('the middleware, the federation entity and the guard', async () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      authzenMiddleware({ client: { url: 'http://pdp' }, allowInsecure: true, map: () => null });
      new FederationEntity({ entityId: 'http://localhost', key: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey, authorityHints: ['http://localhost:9000'], allowInsecure: true });
      const guard = new McpGuard({
        client: { url: 'http://pdp', fetch: vi.fn(async () => new Response('{"decision":true}')) as never },
        tools: [{ name: 't', inputSchema: { 'x-authzen-mapping': { evaluation: { subject: { id: '$params.arguments.who' }, action: { name: 't' }, resource: { type: 'x', id: '1' } } } } } as never],
      });
      await guard.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 't', arguments: { who: 'bob' } } }, claims: token });
      expect(spy.mock.calls.map((c) => String(c[0]))).toEqual([
        expect.stringMatching(/allowInsecure/),
        expect.stringMatching(/allowInsecure/),
        expect.stringMatching(/^\[coaz\] tool t sets subject\.id/),
      ]);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('an error downstream is the router\'s, not the PEP\'s', () => {
  it('is not turned into a 502, and is not a second decision', async () => {
    const decisions: string[] = [];
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: vi.fn(async () => new Response('{"decision":true}')) as never },
      verifyToken: async () => ({ sub: 'u' }),
      onDecision: ({ verdict }) => decisions.push(verdict.kind),
      map: () => ({ subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } }),
    });
    const res = { status: vi.fn(), set: vi.fn(), json: vi.fn() };
    const boom = new Error('handler failed');
    await expect(mw({ method: 'GET', path: '/x', headers: { authorization: 'Bearer t' } }, res as never, () => { throw boom; })).rejects.toBe(boom);
    expect(res.status).not.toHaveBeenCalled();
    expect(decisions).toEqual(['ok']);
  });
});

describe('pathMapper keeps a pattern literal it cannot decode as written', () => {
  it('and still matches the request that encodes it', () => {
    const map = pathMapper([{ pattern: '/files%zz/:id', action: 'read', resourceType: 'file', resourceId: (p) => p['id']! }], { fallthrough: 'allow' });
    expect(map({ method: 'GET', path: '/files%25zz/7', headers: {} }, extractClaims({ sub: 'u' }))?.resource.id).toBe('7');
  });
});

// ---------------------------------------------------------------------------

describe('the strict reader, token by token', () => {
  const guard = () => new McpGuard({ client: { url: 'http://pdp', fetch: vi.fn(async () => new Response('{"decision":true}')) as never }, tools: [] });
  const check = (body: unknown) => guard().checkToolCall({ raw: { headers: {}, body: body as string }, claims: token });

  it('reads every kind of JSON value', async () => {
    const body = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":[],"b":[1,-2.5e3,false,null,true,"x\\n\\"y\\u00e9"],"c":{},"d":{"e":{"f":[{}]}}}}';
    expect((await check(body)).allow).toBe(true);
  });

  const broken = [
    '{"id":1,"method":"ping","params":{"a":"\\u12G4"}}',
    '{"id":1,"method":"ping","params":{"a":tru}}',
    '{"id":1,"method":"ping","params":{"a":-}}',
    '{"id":1,"method":"ping","params":{"a":01}}',
    '{,}',
    '{"method" "ping"}',
    '{"method":"ping" "id":1}',
    '{"method":"ping","params":{"a":[1 2]}}',
    '{"method":"ping","params":{"a":[1,',
    '{"method":"ping",',
  ];
  for (const body of broken) {
    it(`a parse error: ${body}`, async () => {
      expect((await check(body)).jsonRpcError?.error.code).toBe(CODE_PARSE_ERROR);
    });
  }

  it('a duplicate in a body that is broken further on has no id to give', async () => {
    const v = await check('{"id":7,"method":"ping","a":1,"a":2 garbage');
    expect(v.jsonRpcError).toMatchObject({ id: null, error: { code: CODE_INVALID_REQUEST } });
    const readable = await check('{"id":7,"method":"ping","a":1,"a":2}');
    expect(readable.jsonRpcError).toMatchObject({ id: 7, error: { code: CODE_INVALID_REQUEST } });
    const aboutId = await check('{"id":7,"ID":8,"method":"ping"}');
    expect(aboutId.jsonRpcError?.id).toBeNull();
  });

  it('a body that is neither text nor bytes cannot be read', async () => {
    expect((await check(42)).jsonRpcError?.error.code).toBe(CODE_INVALID_REQUEST);
  });

  it('an rpc JSON cannot say never matches the raw body', async () => {
    const rpc = { jsonrpc: '2.0', id: 1, method: 'ping', big: 10n };
    const v = await guard().checkToolCall({ rpc, raw: { headers: {}, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' }, claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_INVALID_REQUEST);
  });
});

// ---------------------------------------------------------------------------

describe('guard edges', () => {
  const tools = [{ name: 'weather' }];
  const fetch = vi.fn(async () => new Response('{"decision":true}')) as unknown as typeof globalThis.fetch;

  it('passes a server-initiated method through', async () => {
    const g = new McpGuard({ client: { url: 'http://pdp', fetch }, tools });
    expect(await g.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'sampling/createMessage' }, claims: token })).toMatchObject({ allow: true, coazTool: false });
  });

  it('never throws, even when the arguments do', async () => {
    const g = new McpGuard({ client: { url: 'http://pdp', fetch }, tools });
    const hostile = {
      claims: token,
      get rpc(): unknown {
        throw new Error('getter exploded');
      },
    };
    const v = await g.checkToolCall(hostile);
    expect(v).toMatchObject({ allow: false, jsonRpcError: { error: { code: CODE_PDP_ERROR } } });
    expect(v.verdict.detail).toMatch(/getter exploded/);
  });
});

describe('delegate edges', () => {
  const UP = 'http://mcp/mcp';
  const call = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 't' } };
  const delegate = (answer: () => Response) =>
    new McpGuard({ client: { url: 'http://pdp' }, upstreamUrl: UP, delegate: { url: 'http://coaz-pep:9192', apiKey: 'k' }, fetch: vi.fn(async () => answer()) as never });
  const raw = { headers: {}, body: JSON.stringify(call) };
  const deny = (response: unknown) => () => new Response(JSON.stringify({ decision: false, response }));

  it('an answer that breaks off is unavailable', async () => {
    const v = await delegate(() => new Response(breaking(), { status: 200 })).checkToolCall({ raw, claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    expect(v.verdict.detail).toMatch(/socket hang up/);
  });

  it('a body that is neither text nor bytes is a parse error', async () => {
    const v = await delegate(() => new Response('{"decision":true}')).checkToolCall({ raw: { headers: {}, body: 7 as never }, claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_PARSE_ERROR);
  });

  it('reads the kind of a relayed deny from its code, its challenge or its status', async () => {
    const rpcError = (code: number, data?: Record<string, unknown>) => JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code, message: 'm', ...(data ? { data } : {}) } });
    const cases: Array<[unknown, string]> = [
      [{ status: 200, body: rpcError(CODE_PDP_ERROR) }, 'pdp_error'],
      [{ status: 200, body: rpcError(CODE_MAPPING_ERROR) }, 'mapping_error'],
      [{ status: 200, body: rpcError(-32001, { authz_challenge: { type: 'identity_proofing' } }) }, 'identity_proofing_required'],
      [{ status: 200, body: rpcError(-32001, { authz_challenge: { type: 'authn' } }) }, 'unauthenticated'],
      [{ status: 200, body: rpcError(-32001, { authz_challenge: 'odd' }) }, 'denied'],
      [{ status: 413, body: '{"error":"too big"}' }, 'mapping_error'],
      [{ status: 415, body: 'unsupported' }, 'mapping_error'],
      [{ status: 503, body: '{"reason":"Authorization policy for this route could not be read."}' }, 'pdp_error'],
      [{ status: 403, body: '{"error":{"code":"x","message":"m"}}' }, 'denied'],
      [{ status: 403, headers: {}, body: 7 }, 'denied'],
    ];
    for (const [response, kind] of cases) {
      const v = await delegate(deny(response)).checkToolCall({ raw, claims: token });
      expect(v.verdict.kind, JSON.stringify(response)).toBe(kind);
      expect(v.allow).toBe(false);
    }
    const reasoned = await delegate(deny({ status: 503, body: '{"reason":"Authorization policy for this route could not be read."}' })).checkToolCall({ raw, claims: token });
    expect(reasoned.verdict.reason).toBe('Authorization policy for this route could not be read.');
  });

  it('the handshake needs initialize to answer', async () => {
    const f = vi.fn(async (u: unknown, init?: RequestInit) => {
      if (String(u).startsWith('http://pdp')) return new Response('{"decision":true}');
      const msg = JSON.parse(String(init?.body)) as { id?: unknown; method: string };
      if (msg.method === 'initialize') return new Response(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: null }));
      return new Response('', { status: 400 });
    }) as unknown as typeof globalThis.fetch;
    const g = new McpGuard({ client: { url: 'http://pdp', fetch: f }, upstreamUrl: UP, fetch: f });
    const v = await g.checkToolCall({ rpc: call, claims: token });
    expect(v.verdict.detail).toMatch(/initialize returned no result/);
  });
});

// ---------------------------------------------------------------------------

describe('mapping edges', () => {
  it('v2: an envelope that is not an object, a padded anchor, an empty boxcar, a non-string id', () => {
    expect(() => buildRequestV2({ evaluation: 'x' } as never, {}, token)).toThrow(/must contain an object/);
    expect(() => buildRequestV2({ evaluation: { subject: { id: ' $token.sub ' }, action: { name: 'a' }, resource: { type: 'r' } } } as never, {}, token)).toThrow(/does not match/);
    expect(() => buildRequestV2({ evaluations: { subject: { id: '$token.sub' }, action: { name: 'a' }, evaluations: [] } } as never, {}, token)).toThrow(/empty evaluations/);
    expect(() => buildRequestV2({ evaluation: { subject: { id: 5 }, action: { name: 'a' }, resource: { type: 'r' } } } as never, {}, token)).toThrow(/subject\.id must be a string/);
    const withNumber = buildRequestV2({ evaluation: { action: { name: 'a' }, resource: { type: 'r', properties: { limit: 5, on: true } } } } as never, {}, token);
    expect((withNumber.body as unknown as { resource: { properties: unknown } }).resource.properties).toEqual({ limit: 5, on: true });
  });

  it('isAnchoredSubject reads what was written', () => {
    expect(isAnchoredSubject({ evaluation: 'x' } as never)).toBe(false);
    expect(isAnchoredSubject({ evaluation: { subject: { id: '' } } } as never)).toBe(true);
    expect(isAnchoredSubject({ evaluation: { subject: { id: null } } } as never)).toBe(true);
  });

  it('v1: required fields, mismatched lengths, arrays and numbers in a declaration', () => {
    const ok = { subject: [{ type: "'user'", id: 'token.sub' }], resource: [{ type: "'r'", id: "'1'" }], context: [{ a: 'token.sub' }] };
    for (const missing of ['subject', 'resource', 'context'] as const) {
      const m = { ...ok } as Record<string, unknown>;
      delete m[missing];
      expect(() => buildRequest('t', m as never, {}, token), missing).toThrow(new RegExp(`${missing} is required`));
    }
    expect(() => buildRequest('t', { ...ok, resource: [{ type: "'r'", id: "'1'" }, { type: "'r'", id: "'2'" }], context: [{ a: 'token.sub' }, { a: "'x'" }, { a: "'y'" }] }, {}, token)).toThrow(/mismatched/);
    const built = buildRequest('t', { subject: [{ level: 5, type: "'user'", id: 'token.sub' }], resource: [{ type: "'r'", id: "'1'", tags: ["'a'", 'token.client_id'] }], context: ['token.sub'] as never }, {}, token, { channel: 'x' });
    expect(built.body).toMatchObject({ subject: { level: 5, id: 'alice' }, resource: { tags: ['a', 'agent-1'] }, context: 'alice' });
  });

  it('the CEL subset: literals, empty input, a conditional with no else, escapes, a path through a scalar', () => {
    expect(evaluateExpression('true', {}, {})).toBe(true);
    expect(evaluateExpression('false', {}, {})).toBe(false);
    expect(evaluateExpression('null', {}, {})).toBeNull();
    expect(evaluateExpression('42', {}, {})).toBe(42);
    expect(evaluateExpression('-1.5', {}, {})).toBe(-1.5);
    expect(() => evaluateExpression('', {}, {})).toThrow(/empty expression/);
    expect(() => evaluateExpression("params.a == 'x' ? 'y'", { a: 'x' }, {})).toThrow(/missing its ':'/);
    expect(evaluateExpression("params.a == 'it\\'s' ? 'y' : 'n'", { a: "it's" }, {})).toBe('y');
    expect(evaluateExpression("'a\\'b' + 'c'", {}, {})).toBe("a'bc");
    expect(evaluateExpression('params.a.b', { a: 5 }, {})).toBeUndefined();
  });
});

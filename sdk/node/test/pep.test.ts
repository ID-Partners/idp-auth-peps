import { describe, expect, it, vi } from 'vitest';

import { AuthzenClient } from '../src/client.js';
import { toHttpChallenge } from '../src/challenge.js';
import { claimsFromToken, extractClaims, hasScope, jwkThumbprint } from '../src/claims.js';
import { authzenMiddleware, pathMapper, type PepRequest } from '../src/express.js';
import { CODE_DENIED, CODE_DENIED_V2, CODE_MAPPING_ERROR, CODE_PDP_ERROR, McpGuard, buildRequest, buildRequestV2, evaluateExpression } from '../src/mcp.js';
import type { ToolDefinition } from '../src/mcp.js';

/** A fetch stub that answers the PDP with a fixed body. */
function pdp(body: unknown, init: { status?: number; delayMs?: number } = {}) {
  return vi.fn(async (_url: unknown, opts?: { signal?: AbortSignal }) => {
    if (init.delayMs) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, init.delayMs);
        opts?.signal?.addEventListener('abort', () => {
          clearTimeout(t);
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    }
    return new Response(JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof globalThis.fetch;
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: 'none' })}.${b64(claims)}.sig`;

// ---------------------------------------------------------------------------

describe('AuthzenClient', () => {
  it('permits when the PDP says decision:true', async () => {
    const client = new AuthzenClient({ url: 'http://pdp', fetch: pdp({ decision: true }) });
    const v = await client.evaluate({
      subject: { type: 'user', id: 'u1' },
      action: { name: 'read' },
      resource: { type: 'account', id: 'a1' },
    });
    expect(v).toMatchObject({ allow: true, kind: 'ok' });
  });

  it('folds step-up advice into a typed verdict', async () => {
    const client = new AuthzenClient({
      url: 'http://pdp',
      fetch: pdp({
        decision: false,
        context: { reason: 'Over threshold', step_up_required: true, step_up_scope: 'payment:approve' },
      }),
    });
    const v = await client.evaluate({
      subject: { type: 'user', id: 'u1' },
      action: { name: 'make_payment' },
      resource: { type: 'payment' },
    });
    expect(v.allow).toBe(false);
    expect(v.kind).toBe('step_up_required');
    expect(v.context?.step_up_scope).toBe('payment:approve');
  });

  it('fails closed on a PDP 500', async () => {
    const client = new AuthzenClient({ url: 'http://pdp', fetch: pdp({}, { status: 500 }) });
    const v = await client.evaluate({ subject: { type: 'user', id: 'u' }, action: { name: 'x' }, resource: { type: 'r' } });
    expect(v).toMatchObject({ allow: false, kind: 'pdp_error' });
  });

  it('fails closed on timeout', async () => {
    const client = new AuthzenClient({ url: 'http://pdp', timeoutMs: 10, fetch: pdp({ decision: true }, { delayMs: 200 }) });
    const v = await client.evaluate({ subject: { type: 'user', id: 'u' }, action: { name: 'x' }, resource: { type: 'r' } });
    expect(v.allow).toBe(false);
    expect(v.kind).toBe('pdp_error');
    expect(v.reason).toMatch(/timed out/);
  });

  it('reports the first deny in a boxcar so its advice survives', async () => {
    const client = new AuthzenClient({
      url: 'http://pdp',
      fetch: pdp({
        evaluations: [
          { decision: true },
          { decision: false, context: { reason: 'no', step_up_required: true, step_up_scope: 's' } },
          { decision: false, context: { reason: 'other' } },
        ],
      }),
    });
    const v = await client.evaluateAll({ evaluations: [{}, {}, {}] });
    expect(v.kind).toBe('step_up_required');
    expect(v.reason).toBe('no');
  });
});

// ---------------------------------------------------------------------------

describe('challenges', () => {
  it('renders a step-up as 401 insufficient_scope with a structured challenge', () => {
    const out = toHttpChallenge(
      {
        allow: false,
        kind: 'step_up_required',
        reason: 'Approve this payment',
        context: { step_up_required: true, step_up_scope: 'payment:approve' },
      },
      'api-edge',
    );
    expect(out.status).toBe(401);
    expect(out.headers['WWW-Authenticate']).toContain('error="insufficient_scope"');
    expect(out.headers['WWW-Authenticate']).toContain('scope="payment:approve"');
    expect(out.body['authz_challenge']).toMatchObject({
      type: 'resource_authorisation',
      scope: 'payment:approve',
      pep: 'api-edge',
    });
  });

  it('renders identity proofing as its own challenge type', () => {
    const out = toHttpChallenge({
      allow: false,
      kind: 'identity_proofing_required',
      reason: 'Verify identity',
      context: { identity_proofing_required: true, identity_proofing_doctype: 'org.iso.18013.5.1.mDL' },
    });
    expect(out.status).toBe(401);
    expect(out.body['authz_challenge']).toMatchObject({ type: 'identity_proofing', doctype: 'org.iso.18013.5.1.mDL' });
  });

  it('separates a policy no (403) from a PDP failure (502)', () => {
    expect(toHttpChallenge({ allow: false, kind: 'denied', reason: 'no' }).status).toBe(403);
    expect(toHttpChallenge({ allow: false, kind: 'pdp_error', reason: 'down' }).status).toBe(502);
  });

  it('cannot be used to inject response headers via a policy reason', () => {
    // Policy text reaches this header, so a reason carrying CRLF must not be able to
    // start a second header. The text may survive — inert, inside the quoted value.
    const out = toHttpChallenge({
      allow: false,
      kind: 'step_up_required',
      reason: 'bad\r\nX-Injected: yes',
      context: { step_up_required: true, step_up_scope: 's' },
    });
    const header = out.headers['WWW-Authenticate']!;
    expect(header).not.toMatch(/[\r\n]/);
    expect(header).toContain('error_description="bad X-Injected: yes"');
  });

  it('escapes quotes in a reason rather than closing the quoted-string early', () => {
    const out = toHttpChallenge({
      allow: false,
      kind: 'step_up_required',
      reason: 'say "no"',
      context: { step_up_required: true, step_up_scope: 's' },
    });
    expect(out.headers['WWW-Authenticate']).toContain('error_description="say \\"no\\""');
  });
});

// ---------------------------------------------------------------------------

describe('claims', () => {
  it('normalises scope, act and cnf', () => {
    const c = claimsFromToken(
      jwt({
        sub: 'user-1',
        scp: ['a', 'b'],
        act: { sub: 'agent-1' },
        cnf: { jkt: 'thumb' },
        client_id: 'client-1',
        acr: 'urn:staff',
      }),
    );
    expect(c).toMatchObject({ sub: 'user-1', scope: 'a b', actor: 'agent-1', jkt: 'thumb', clientId: 'client-1' });
  });

  it('decodes an act claim that arrived as a JSON string', () => {
    // PingFederate does this; a naive claims.act.sub would read undefined and every
    // delegated call would look direct.
    const c = extractClaims({ sub: 'u', act: '{"sub":"agent-9"}' });
    expect(c.actor).toBe('agent-9');
  });

  it('matches scope by element, not substring', () => {
    expect(hasScope('payments:read payments:write', 'payments:read')).toBe(true);
    expect(hasScope('payments:readonly', 'payments:read')).toBe(false);
  });

  it('computes an RFC 7638 thumbprint for the spec example key', () => {
    // RFC 7638 §3.1.
    expect(
      jwkThumbprint({
        kty: 'RSA',
        n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
        e: 'AQAB',
      }),
    ).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });
});

// ---------------------------------------------------------------------------

describe('express middleware', () => {
  function mockRes() {
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as unknown,
      status(code: number) {
        res.statusCode = code;
        return res;
      },
      set(k: string, v: string) {
        res.headers[k] = v;
        return res;
      },
      json(b: unknown) {
        res.body = b;
        return res;
      },
    };
    return res;
  }

  const req = (over: Partial<PepRequest> = {}): PepRequest => ({
    method: 'GET',
    path: '/accounts/acc-1/balance',
    headers: { authorization: `Bearer ${jwt({ sub: 'user-1', scope: 'accounts:read' })}` },
    ...over,
  });

  it('permits and exposes the decision on req.authz', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      map: pathMapper([
        { method: 'GET', pattern: '/accounts/:id/balance', action: 'get_balance', resourceType: 'account', resourceId: (p) => p['id']! },
      ]),
    });
    const r = req();
    const res = mockRes();
    const next = vi.fn();
    await mw(r, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(r.authz?.request.resource.id).toBe('acc-1');
  });

  it('denies with the PDP challenge and never calls next', async () => {
    const mw = authzenMiddleware({
      client: {
        url: 'http://pdp',
        fetch: pdp({ decision: false, context: { reason: 'Approve it', step_up_required: true, step_up_scope: 'pay' } }),
      },
      pep: 'api-edge',
      map: pathMapper([{ method: 'GET', pattern: '/accounts/:id/balance', action: 'get_balance', resourceType: 'account' }]),
    });
    const res = mockRes();
    const next = vi.fn();
    await mw(req(), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.headers['WWW-Authenticate']).toContain('insufficient_scope');
  });

  it('denies when no token is presented', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      map: () => null,
    });
    const res = mockRes();
    const next = vi.fn();
    await mw(req({ headers: {} }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it('denies an unmapped route rather than letting it through', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      map: pathMapper([{ method: 'GET', pattern: '/accounts/:id/balance', action: 'get_balance', resourceType: 'account' }]),
    });
    const res = mockRes();
    const next = vi.fn();
    await mw(req({ path: '/admin/secrets' }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('rejects a token the verifier refuses', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      verifyToken: async () => null,
      map: () => null,
    });
    const res = mockRes();
    const next = vi.fn();
    await mw(req(), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });
});

// ---------------------------------------------------------------------------

describe('COAZ mapping', () => {
  // Straight from the profile's single-valued example: static values are CEL string
  // literals, and `params` is the JSON-RPC params member (arguments nested under it).
  const mapping = {
    subject: [{ type: "'user'", id: 'token.sub' }],
    resource: [{ type: "'customer'", id: 'params.arguments.id' }],
    context: [{ agent: 'token.client_id', case: 'params.arguments.case' }],
  };

  it('builds the spec-shaped single evaluation request', () => {
    const built = buildRequest(
      'get_customer',
      mapping,
      { name: 'get_customer', arguments: { id: 'cust-12345', case: 'case-67890' } },
      { sub: 'alice@example.com', client_id: 'http://agentprovider.com/agent-app-id' },
    );
    expect(built.batch).toBe(false);
    expect(built.body).toEqual({
      subject: { type: 'user', id: 'alice@example.com' },
      action: { name: 'get_customer' }, // default when the mapping omits action
      resource: { type: 'customer', id: 'cust-12345' },
      context: { agent: 'http://agentprovider.com/agent-app-id', case: 'case-67890' },
    });
  });

  it('switches to the boxcar API when a field is multi-element', () => {
    const built = buildRequest(
      'get_two',
      {
        subject: [{ type: "'user'", id: 'token.sub' }],
        resource: [{ type: "'account'", id: "'a1'" }, { type: "'account'", id: "'a2'" }],
        context: [{ agent: 'token.client_id' }],
      },
      {},
      { sub: 'u', client_id: 'c' },
    );
    expect(built.batch).toBe(true);
    const body = built.body as Record<string, unknown>;
    expect(body['subject']).toEqual({ type: 'user', id: 'u' });
    expect(body['evaluations']).toEqual([
      { resource: { type: 'account', id: 'a1' } },
      { resource: { type: 'account', id: 'a2' } },
    ]);
  });

  it('refuses a mapping that derives nothing from the token', () => {
    expect(() =>
      buildRequest('t', { subject: [{ id: "'anyone'" }], resource: [{ type: "'r'" }], context: [{ a: "'b'" }] }, {}, {}),
    ).toThrow(/derived from the token/);
  });

  it('lets gateway context fill only keys the mapping did not set', () => {
    const built = buildRequest('t', mapping, { arguments: { id: 'c1', case: 'k' } }, { sub: 'u', client_id: 'c' }, {
      agent: 'IGNORED',
      channel: 'ai-agent',
    });
    const ctx = (built.body as Record<string, Record<string, unknown>>)['context']!;
    expect(ctx['agent']).toBe('c');
    expect(ctx['channel']).toBe('ai-agent');
  });

  it('evaluates the documented subset and refuses the rest', () => {
    const p = { amount: 250, name: 'ann' };
    const t = { sub: 'u1', act: '{"sub":"agent-7"}' };
    expect(evaluateExpression("'literal'", p, t)).toBe('literal');
    expect(evaluateExpression('params.amount', p, t)).toBe(250);
    expect(evaluateExpression('token.act.sub', p, t)).toBe('agent-7');
    expect(evaluateExpression("'acct:' + params.name", p, t)).toBe('acct:ann');
    expect(evaluateExpression('string(params.amount)', p, t)).toBe('250');
    expect(() => evaluateExpression('params.amount > 100 ? "a" : "b"', p, t)).toThrow(/unsupported expression/);
  });
});

// ---------------------------------------------------------------------------

describe('McpGuard', () => {
  const tools: ToolDefinition[] = [
    {
      name: 'make_payment',
      coaz: true,
      'x-coaz-mapping': {
        subject: [{ type: "'user'", id: 'token.sub' }],
        resource: [{ type: "'payment'", id: 'params.arguments.payment_id' }],
        context: [{ agent: 'token.client_id' }],
      },
    },
    { name: 'ping' },
  ];

  const call = (name: string, args: Record<string, unknown> = {}) => ({
    jsonrpc: '2.0',
    id: 7,
    method: 'tools/call',
    params: { name, arguments: args },
  });

  it('permits a governed tool the PDP allows', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({ decision: true }) }, tools });
    const v = await guard.checkToolCall({ rpc: call('make_payment', { payment_id: 'p1' }), claims: { sub: 'u', client_id: 'c' } });
    expect(v.allow).toBe(true);
    expect(v.coazTool).toBe(true);
  });

  it('denies with -32401 and a structured challenge in error.data', async () => {
    const guard = new McpGuard({
      client: {
        url: 'http://pdp',
        fetch: pdp({ decision: false, context: { reason: 'Approve it', step_up_required: true, step_up_scope: 'pay:approve' } }),
      },
      tools,
      pep: 'mcp-edge',
    });
    const v = await guard.checkToolCall({ rpc: call('make_payment', { payment_id: 'p1' }), claims: { sub: 'u', client_id: 'c' } });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED);
    expect(v.jsonRpcError?.error.data?.['authz_challenge']).toMatchObject({
      type: 'resource_authorisation',
      scope: 'pay:approve',
      pep: 'mcp-edge',
    });
    expect(v.jsonRpcError?.id).toBe(7);
  });

  it('lets a tool without coaz:true through', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({ decision: false }) }, tools });
    const v = await guard.checkToolCall({ rpc: call('ping'), claims: { sub: 'u' } });
    expect(v.allow).toBe(true);
    expect(v.coazTool).toBe(false);
  });

  it('returns -32603 and denies when the PDP is unreachable', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({}, { status: 503 }) }, tools });
    const v = await guard.checkToolCall({ rpc: call('make_payment', { payment_id: 'p1' }), claims: { sub: 'u', client_id: 'c' } });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
  });

  it('returns -32602 when the mapping cannot be evaluated', async () => {
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      tools: [{ name: 'bad', coaz: true, 'x-coaz-mapping': { subject: [{ id: 'token.sub' }], resource: [{ id: 'params.arguments.x > 1' }], context: [{ a: 'token.sub' }] } }],
    });
    const v = await guard.checkToolCall({ rpc: call('bad'), claims: { sub: 'u' } });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_MAPPING_ERROR);
  });

  it('wrap() short-circuits the handler on a deny', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { reason: 'no' } }) }, tools });
    const handler = vi.fn(async () => ({ ok: true }));
    const wrapped = guard.wrap(handler);
    const out = await wrapped(call('make_payment', { payment_id: 'p1' }), { sub: 'u', client_id: 'c' });
    expect(handler).not.toHaveBeenCalled();
    expect((out as { error: { code: number } }).error.code).toBe(CODE_DENIED);
  });
});

// ---------------------------------------------------------------------------

describe('COAZ v2 (current binding)', () => {
  const specMapping = {
    evaluation: {
      subject: { type: 'identity', id: '$token.sub' },
      action: { name: 'get_customer' },
      resource: { type: 'customer', id: '$params.arguments.id' },
      context: { agent: '$token.?client_id', case: '$params.arguments.case' },
    },
  } as const;

  const token = { sub: 'alice@example.com', client_id: 'http://agentprovider.com/agent-app-id' };

  it('builds the binding worked example', () => {
    const built = buildRequestV2(
      specMapping as never,
      { name: 'get_customer', arguments: { id: 'cust-12345', case: 'case-67890' } },
      token,
    );
    expect(built.batch).toBe(false);
    expect(built.body).toEqual({
      // Unprefixed strings are LITERALS in v2 — the whole point of the discriminator.
      subject: { type: 'identity', id: 'alice@example.com' },
      action: { name: 'get_customer' },
      resource: { type: 'customer', id: 'cust-12345' },
      context: { agent: 'http://agentprovider.com/agent-app-id', case: 'case-67890' },
    });
  });

  it('treats $$ as an escaped literal $ and a mid-string $ as nothing special', () => {
    const built = buildRequestV2(
      { evaluation: { subject: { id: '$token.sub' }, context: { price: '$$9.99', note: 'a$b' } } } as never,
      {},
      token,
    );
    const ctx = (built.body as Record<string, Record<string, unknown>>)['context']!;
    expect(ctx['price']).toBe('$9.99');
    expect(ctx['note']).toBe('a$b');
  });

  it('rejects an envelope that is not exactly one of evaluation/evaluations', () => {
    for (const bad of [{}, { subject: {} }, { evaluate: {} }, { evaluation: {}, evaluations: {} }]) {
      expect(() => buildRequestV2(bad as never, {}, token)).toThrow();
    }
  });

  it('does not fan out on a list value — the envelope alone decides', () => {
    const built = buildRequestV2(
      { evaluation: { subject: { id: '$token.sub' }, resource: { type: 'account', properties: { tags: ['x', 'y'] } } } } as never,
      {},
      token,
    );
    expect(built.batch).toBe(false);
  });

  it('rejects a subject inside an evaluations entry (identity smuggling)', () => {
    expect(() =>
      buildRequestV2(
        {
          evaluations: {
            subject: { id: '$token.sub' },
            evaluations: [{ subject: { id: 'someone-else' }, action: { name: 'debit' } }],
          },
        } as never,
        {},
        token,
      ),
    ).toThrow(/only the top-level subject/);
  });

  it('supplies the default token-anchored subject when the mapping omits one', () => {
    const built = buildRequestV2({ evaluation: { resource: { type: 'customer', id: 'c1' } } } as never, {}, token);
    expect((built.body as Record<string, Record<string, unknown>>)['subject']).toEqual({ id: 'alice@example.com' });
  });

  it('rejects an anchored subject the token cannot back', () => {
    expect(() => buildRequestV2(specMapping as never, { arguments: {} }, { client_id: 'c' })).toThrow(/no sub claim/);
  });

  it('omits an absent optional claim rather than sending null', () => {
    const built = buildRequestV2(specMapping as never, { arguments: {} }, { sub: 'alice@example.com' });
    const ctx = (built.body as Record<string, Record<string, unknown>>)['context']!;
    expect('agent' in ctx).toBe(false);
  });

  it('denies a v2 tool with -32001, not the non-conformant -32401', async () => {
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { reason: 'no' } }) },
      tools: [{ name: 'get_customer', inputSchema: { 'x-authzen-mapping': specMapping } } as never],
    });
    const v = await guard.checkToolCall({
      rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_customer', arguments: { id: 'c1' } } },
      claims: token,
    });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED_V2);
    expect(v.jsonRpcError?.error.code).not.toBe(CODE_DENIED);
  });

  it('still emits -32401 for a tool declared against v1', async () => {
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { reason: 'no' } }) },
      tools: [
        {
          name: 'legacy',
          coaz: true,
          'x-coaz-mapping': {
            subject: [{ type: "'user'", id: 'token.sub' }],
            resource: [{ type: "'customer'", id: 'params.arguments.id' }],
            context: [{ agent: 'token.client_id' }],
          },
        },
      ],
    });
    const v = await guard.checkToolCall({
      rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'legacy', arguments: { id: 'c1' } } },
      claims: token,
    });
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED);
  });
});

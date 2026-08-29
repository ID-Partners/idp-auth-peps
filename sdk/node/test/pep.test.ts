import { describe, expect, it, vi } from 'vitest';

import { AuthzenClient, PdpError } from '../src/client.js';
import { foldDecision, toChallenge, toHttpChallenge } from '../src/challenge.js';
import { bearerToken, claimsFromToken, decodeJwtHeader, decodeJwtSegment, extractClaims, hasScope, jwkThumbprint } from '../src/claims.js';
import { authzenMiddleware, pathMapper, type PepRequest } from '../src/express.js';
import { CODE_DENIED, CODE_DENIED_V2, CODE_MAPPING_ERROR, CODE_PDP_ERROR, McpGuard, buildRequest, buildRequestV2, defaultMappingFor, defaultToolsCallMapping, evaluateExpression, isAnchoredSubject, isPassThroughMethod, isServerInitiatedMethod } from '../src/mcp.js';
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
    // Conditionals are evaluated, but only with == / != — ordering is still refused.
    expect(evaluateExpression("params.name == 'ann' ? 'yes' : 'no'", p, t)).toBe('yes');
    expect(evaluateExpression("params.name != 'ann' ? 'yes' : 'no'", p, t)).toBe('no');
    expect(() => evaluateExpression('params.amount > 100 ? "a" : "b"', p, t)).toThrow(/unsupported condition/);
    expect(() => evaluateExpression('params.foo.bar()', p, t)).toThrow(/unsupported expression/);
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
      { evaluation: { subject: { id: '$token.sub' }, action: { name: 't' }, resource: { type: 'r' }, context: { price: '$$9.99', note: 'a$b' } } } as never,
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
      { evaluation: { subject: { id: '$token.sub' }, action: { name: 't' }, resource: { type: 'account', properties: { tags: ['x', 'y'] } } } } as never,
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
            evaluations: [{ subject: { id: 'someone-else' }, action: { name: 'debit' }, resource: { type: 'account' } }],
          },
        } as never,
        {},
        token,
      ),
    ).toThrow(/only the top-level subject/);
  });

  it('supplies the default token-anchored subject when the mapping omits one', () => {
    const built = buildRequestV2({ evaluation: { action: { name: 't' }, resource: { type: 'customer', id: 'c1' } } } as never, {}, token);
    // AuthZEN requires a subject type; the binding's defaults use "identity".
    expect((built.body as Record<string, Record<string, unknown>>)['subject']).toEqual({
      type: 'identity',
      id: 'alice@example.com',
    });
  });

  it('rejects an anchored subject the token cannot back', () => {
    expect(() => buildRequestV2(specMapping as never, { arguments: {} }, { client_id: 'c' })).toThrow(/no sub claim/);
  });

  it('omits an absent optional context claim rather than sending null', () => {
    // Only the optional context claim is absent here; resource.id resolves.
    const built = buildRequestV2(specMapping as never, { arguments: { id: 'c1' } }, { sub: 'alice@example.com' });
    const ctx = (built.body as Record<string, Record<string, unknown>>)['context']!;
    expect('agent' in ctx).toBe(false);
  });

  it('is a mapping error, not a silently broadened request, when resource.id goes absent', () => {
    // The trap this guards: dropping an absent resource.id would turn "this customer"
    // into every customer, and the PDP would be asked a different question entirely.
    expect(() => buildRequestV2(specMapping as never, { arguments: {} }, token)).toThrow(
      /resource\.id resolved to absent/,
    );
  });

  it('requires subject, action and resource', () => {
    const base = { subject: { id: '$token.sub' }, action: { name: 't' }, resource: { type: 'r', id: 'x' } };
    for (const drop of ['action', 'resource'] as const) {
      const m = { evaluation: { ...base } } as Record<string, Record<string, unknown>>;
      delete m['evaluation']![drop];
      expect(() => buildRequestV2(m as never, {}, token)).toThrow(new RegExp(`${drop} is missing`));
    }
  });

  it('checks required fields per boxcar entry, against the top-level defaults', () => {
    expect(() =>
      buildRequestV2(
        {
          evaluations: {
            subject: { id: '$token.sub' },
            action: { name: 'transfer' },
            evaluations: [
              { resource: { type: 'account', id: 'a1' } },
              { resource: { type: 'account', id: '$params.arguments.missing' } },
            ],
          },
        } as never,
        { arguments: {} },
        token,
      ),
    ).toThrow(/evaluations\[1\]\.resource\.id/);
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

// ---------------------------------------------------------------------------

describe('COAZ v2 — defaults and anchoring warnings', () => {
  const token = { sub: 'alice@example.com', client_id: 'agent-1' };
  const call = (name: string) => ({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name, arguments: {} } });

  it('passes an undeclared tool through when defaults are off', async () => {
    const fetchMock = pdp({ decision: false });
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: fetchMock }, tools: [{ name: 'weather' }] });
    const v = await guard.checkToolCall({ rpc: call('weather'), claims: token });
    expect(v.allow).toBe(true);
    expect(v.coazTool).toBe(false);
  });

  it('authorizes an undeclared tool against the binding default when defaults are on', async () => {
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { reason: 'nope' } }) },
      tools: [{ name: 'weather' }],
      applyDefaultMappings: true,
    });
    const v = await guard.checkToolCall({ rpc: call('weather'), claims: token });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED_V2);
    // The default mapping asks about the TOOL, named from params.name.
    expect(v.pdpRequest).toMatchObject({
      subject: { type: 'identity', id: 'alice@example.com' },
      action: { name: 'tools/call' },
      resource: { type: 'tool', id: 'weather' },
    });
  });

  it('builds the binding default mapping exactly', () => {
    const built = buildRequestV2(defaultToolsCallMapping(), { name: 'get_local_weather' }, token);
    expect(built.batch).toBe(false);
    expect(built.body).toEqual({
      subject: { type: 'identity', id: 'alice@example.com' },
      context: { agent: 'agent-1' },
      action: { name: 'tools/call' },
      resource: { type: 'tool', id: 'get_local_weather' },
    });
  });

  it('warns when a declared mapping asserts a subject it cannot anchor', async () => {
    const warnings: string[] = [];
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      onWarning: (m) => warnings.push(m),
      tools: [
        {
          name: 'asserted',
          inputSchema: {
            'x-authzen-mapping': {
              evaluation: {
                subject: { type: 'identity', id: '$params.arguments.on_behalf_of' },
                action: { name: 'x' },
                resource: { type: 'r', id: 'r1' },
              },
            },
          },
        } as never,
      ],
    });
    await guard.checkToolCall({
      rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'asserted', arguments: { on_behalf_of: 'bob' } } },
      claims: token,
    });
    expect(warnings.join(' ')).toMatch(/asserted by the mapping author/);
  });

  it('does not warn for a token-anchored mapping, including an omitted subject', () => {
    expect(isAnchoredSubject({ evaluation: { subject: { id: '$token.sub' } } } as never)).toBe(true);
    expect(isAnchoredSubject({ evaluation: { action: { name: 'x' } } } as never)).toBe(true);
    expect(isAnchoredSubject({ evaluation: { subject: { id: '$params.arguments.x' } } } as never)).toBe(false);
    expect(isAnchoredSubject({ evaluation: { subject: { id: "$token.sub + '-x'" } } } as never)).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('COAZ v2 — structure must be literal', () => {
  const token = { sub: 'alice@example.com', client_id: 'agent-1' };

  // Regression for a real bypass: an expression-valued `evaluations` deferred the
  // structure to evaluation time, where it is built from caller-controlled params — so
  // entries could carry their own subjects and the compile-time check saw nothing.
  it('rejects an expression-valued evaluations or subject', () => {
    const cases: Array<[string, unknown]> = [
      ['evaluations from an expression', {
        evaluations: {
          subject: { type: 'identity', id: '$token.sub' },
          action: { name: 't' },
          evaluations: '$params.arguments.smuggled',
        },
      }],
      ['subject from an expression', {
        evaluation: { subject: '$params.arguments.whoever', action: { name: 't' }, resource: { type: 'r', id: 'r1' } },
      }],
      ['entry not an object', {
        evaluations: {
          subject: { type: 'identity', id: '$token.sub' },
          action: { name: 't' },
          evaluations: ['$params.arguments.x'],
        },
      }],
      ['evaluations missing', {
        evaluations: { subject: { type: 'identity', id: '$token.sub' }, action: { name: 't' } },
      }],
    ];
    for (const [name, mapping] of cases) {
      expect(() =>
        buildRequestV2(mapping as never, { arguments: { smuggled: [{ subject: { id: 'victim' } }] } }, token),
        name,
      ).toThrow();
    }
  });

  it('does not let a smuggled subject reach the PDP', () => {
    // The concrete attack: the entry subject comes from tool arguments the caller controls.
    expect(() =>
      buildRequestV2(
        {
          evaluations: {
            subject: { type: 'identity', id: '$token.sub' },
            action: { name: 't' },
            evaluations: '$params.arguments.smuggled',
          },
        } as never,
        { arguments: { smuggled: [{ subject: { type: 'identity', id: 'victim@example.com' }, resource: { type: 'a', id: '1' } }] } },
        token,
      ),
    ).toThrow(/literal array/);
  });
});

// ---------------------------------------------------------------------------

describe('COAZ v2 — default mappings for every method', () => {
  const token = { sub: 'alice@example.com', client_id: 'agent-1', aud: 'https://mcp.example.com' };
  const rpc = (method: string, params: Record<string, unknown> = {}) => ({ jsonrpc: '2.0', id: 9, method, params });
  const guard = (fetchImpl: ReturnType<typeof pdp>) =>
    new McpGuard({ client: { url: 'http://pdp', fetch: fetchImpl }, tools: [], applyDefaultMappings: true });

  it('defines the binding default for every governed method', () => {
    const methods = [
      'tools/call', 'tools/list', 'resources/list', 'resources/read', 'resources/subscribe',
      'resources/unsubscribe', 'prompts/list', 'prompts/get', 'completion/complete',
      'logging/setLevel', 'tasks/get', 'tasks/result', 'tasks/cancel', 'tasks/list', 'initialize',
    ];
    for (const m of methods) expect(defaultMappingFor(m), m).toBeDefined();
    expect(defaultMappingFor('future/method')).toBeUndefined();
  });

  it('builds each default to the documented resource shape', () => {
    const shapes: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
      ['tools/list', {}, { type: 'mcp_server', id: 'https://mcp.example.com' }],
      ['resources/read', { uri: 'file:///a' }, { type: 'resource', id: 'file:///a' }],
      ['prompts/get', { name: 'greet' }, { type: 'prompt', id: 'greet' }],
      ['tasks/cancel', { taskId: 't-1' }, { type: 'task', id: 't-1' }],
      // The binding's one conditional default, both branches.
      ['completion/complete', { ref: { type: 'ref/prompt', name: 'p1' } }, { type: 'prompt', id: 'p1' }],
      ['completion/complete', { ref: { type: 'ref/resource', uri: 'file:///b' } }, { type: 'resource', id: 'file:///b' }],
    ];
    for (const [method, params, want] of shapes) {
      const built = buildRequestV2(defaultMappingFor(method)!, params, token);
      expect((built.body as Record<string, unknown>)['resource'], method).toEqual(want);
    }
  });

  it('denies an unknown method so future MCP versions fail closed', async () => {
    const v = await guard(pdp({ decision: true })).checkToolCall({ rpc: rpc('future/method'), claims: token });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError?.error.code).toBe(CODE_DENIED_V2);
  });

  it('lets ping and notifications through without asking the PDP', async () => {
    // A PDP that denies everything — these must not reach it.
    const denying = guard(pdp({ decision: false }));
    for (const m of ['ping', 'notifications/initialized']) {
      const v = await denying.checkToolCall({ rpc: rpc(m), claims: token });
      expect(v.allow, m).toBe(true);
    }
    expect(isPassThroughMethod('tools/call')).toBe(false);
    expect(isServerInitiatedMethod('sampling/createMessage')).toBe(true);
  });

  it('governs a non-tools/call method against its default', async () => {
    const v = await guard(pdp({ decision: false, context: { reason: 'no' } })).checkToolCall({
      rpc: rpc('resources/read', { uri: 'file:///secret' }),
      claims: token,
    });
    expect(v.allow).toBe(false);
    expect(v.pdpRequest).toMatchObject({
      action: { name: 'resources/read' },
      resource: { type: 'resource', id: 'file:///secret' },
    });
  });
});

// ---------------------------------------------------------------------------

describe('AuthzenClient — the paths that only matter when things go wrong', () => {
  const req = { subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } };

  it('sends the api key and extra headers, and traces the exchange', async () => {
    const seen: Array<Record<string, string>> = [];
    const traces: unknown[] = [];
    const fetchImpl = vi.fn(async (_u: unknown, init?: { headers?: Record<string, string> }) => {
      seen.push(init?.headers ?? {});
      return new Response(JSON.stringify({ decision: true }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    const client = new AuthzenClient({
      url: 'http://pdp/',
      apiKey: 'secret',
      headers: { 'x-tenant': 't1' },
      fetch: fetchImpl,
      onTrace: (t) => traces.push(t),
    });
    await client.evaluate(req);
    expect(seen[0]!['authorization']).toBe('Bearer secret');
    expect(seen[0]!['x-tenant']).toBe('t1');
    expect(traces).toHaveLength(1);
  });

  it('does not let a broken tracer break the request', async () => {
    const client = new AuthzenClient({
      url: 'http://pdp',
      fetch: pdp({ decision: true }),
      onTrace: () => {
        throw new Error('tracer exploded');
      },
    });
    await expect(client.evaluate(req)).resolves.toMatchObject({ allow: true });
  });

  it('fails closed on a body that is not JSON', async () => {
    const fetchImpl = vi.fn(async () => new Response('<html>gateway error</html>', { status: 200 })) as unknown as typeof globalThis.fetch;
    const v = await new AuthzenClient({ url: 'http://pdp', fetch: fetchImpl }).evaluate(req);
    expect(v).toMatchObject({ allow: false, kind: 'pdp_error' });
  });

  it('fails closed when fetch itself throws', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof globalThis.fetch;
    const v = await new AuthzenClient({ url: 'http://pdp', fetch: fetchImpl }).evaluate(req);
    expect(v.allow).toBe(false);
    expect(v.reason).toMatch(/ECONNREFUSED/);
  });

  it('rejects construction without a url, and strips a trailing slash', async () => {
    expect(() => new AuthzenClient({ url: '' })).toThrow(/requires a PDP url/);
    const urls: string[] = [];
    const fetchImpl = vi.fn(async (u: unknown) => {
      urls.push(String(u));
      return new Response(JSON.stringify({ decision: true }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    await new AuthzenClient({ url: 'http://pdp///', fetch: fetchImpl }).evaluate(req);
    expect(urls[0]).toBe('http://pdp/access/v1/evaluation');
  });

  it('surfaces search results and throws PdpError on a search failure', async () => {
    const ok = new AuthzenClient({ url: 'http://pdp', fetch: pdp({ results: [{ type: 'user', id: 'u1' }] }) });
    await expect(ok.searchSubject({ action: { name: 'a' }, resource: { type: 'r' } })).resolves.toMatchObject({
      results: [{ id: 'u1' }],
    });
    await expect(ok.searchResource({ subject: { type: 'user', id: 'u' }, action: { name: 'a' } })).resolves.toBeTruthy();

    const bad = new AuthzenClient({ url: 'http://pdp', fetch: pdp({}, { status: 403 }) });
    await expect(bad.searchSubject({ action: { name: 'a' }, resource: { type: 'r' } })).rejects.toThrow(PdpError);
  });

  it('returns each decision from evaluations() without folding them', async () => {
    const client = new AuthzenClient({
      url: 'http://pdp',
      fetch: pdp({ evaluations: [{ decision: true }, { decision: false }] }),
    });
    const res = await client.evaluations({ evaluations: [{}, {}] });
    expect(res.evaluations).toHaveLength(2);
  });

  it('fails closed when a boxcar response is unusable', async () => {
    const empty = new AuthzenClient({ url: 'http://pdp', fetch: pdp({ evaluations: [] }) });
    await expect(empty.evaluateAll({ evaluations: [] })).resolves.toMatchObject({ kind: 'pdp_error' });
    const junk = new AuthzenClient({ url: 'http://pdp', fetch: pdp({}, { status: 500 }) });
    await expect(junk.evaluateAll({ evaluations: [{}] })).resolves.toMatchObject({ allow: false });
  });
});

describe('challenge and claims edges', () => {
  it('folds an authn_required advice into an unauthenticated verdict', () => {
    const v = foldDecision({ decision: false, context: { authn_required: true, acr_values: 'urn:mfa' } });
    expect(v.kind).toBe('unauthenticated');
    const out = toHttpChallenge(v, 'edge');
    expect(out.status).toBe(401);
    expect(out.headers['WWW-Authenticate']).toContain('login_required');
    expect(out.headers['WWW-Authenticate']).toContain('urn:mfa');
  });

  it('folds a bare permit and a bare deny', () => {
    expect(foldDecision({ decision: true })).toMatchObject({ allow: true, kind: 'ok' });
    expect(foldDecision({ decision: false })).toMatchObject({ allow: false, kind: 'denied' });
    expect(foldDecision(undefined)).toMatchObject({ allow: false });
  });

  it('resolves identity proofing before step-up when a policy asks for both', () => {
    // Identity is the more fundamental gate: resolve it first and let the retry
    // surface the step-up.
    const v = foldDecision({
      decision: false,
      context: { identity_proofing_required: true, step_up_required: true, step_up_scope: 's' },
    });
    expect(v.kind).toBe('identity_proofing_required');
  });

  it('returns no challenge for denials nothing can resolve', () => {
    expect(toChallenge({ allow: false, kind: 'denied', reason: 'no' })).toBeNull();
    expect(toChallenge({ allow: false, kind: 'pdp_error', reason: 'down' })).toBeNull();
    expect(toHttpChallenge({ allow: false, kind: 'mapping_error', reason: 'bad' }).status).toBe(400);
  });

  it('reads a bearer token out of either scheme, and nothing out of neither', () => {
    expect(bearerToken('Bearer abc')).toBe('abc');
    expect(bearerToken('DPoP xyz')).toBe('xyz');
    expect(bearerToken('bearer lower')).toBe('lower');
    for (const bad of ['', undefined, null, 'Basic abc', 'nonsense']) {
      expect(bearerToken(bad as string)).toBe('');
    }
  });

  it('decodes headers and refuses malformed segments', () => {
    const tok = jwt({ sub: 'a' });
    expect(decodeJwtHeader(tok)).toMatchObject({ alg: 'none' });
    expect(decodeJwtSegment('a.b', 1)).toBeNull();
    expect(decodeJwtSegment('', 1)).toBeNull();
    // A segment that is valid base64url but not JSON.
    expect(decodeJwtSegment('aGk.aGk.x', 1)).toBeNull();
  });

  it('thumbprints EC and OKP keys and refuses the rest', () => {
    expect(jwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB' })).toMatch(/^[\w-]+$/);
    expect(jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: 'AA' })).toMatch(/^[\w-]+$/);
    expect(jwkThumbprint({ kty: 'oct', k: 's' })).toBe('');
  });
});

describe('express middleware — remaining branches', () => {
  function mockRes() {
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as unknown,
      status(code: number) { res.statusCode = code; return res; },
      set(k: string, v: string) { res.headers[k] = v; return res; },
      json(b: unknown) { res.body = b; return res; },
    };
    return res;
  }

  it('lets an unauthenticated request through when a token is not required', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      requireToken: false,
      map: () => null,
    });
    const next = vi.fn();
    await mw({ method: 'GET', path: '/public', headers: {} }, mockRes(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('denies a token with no subject claim', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      map: () => null,
    });
    const res = mockRes();
    const next = vi.fn();
    await mw(
      { method: 'GET', path: '/x', headers: { authorization: `Bearer ${jwt({ scope: 'a' })}` } },
      res,
      next,
    );
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it('honours a custom getToken and reports every decision', async () => {
    const decisions: string[] = [];
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      getToken: (r) => String((r.headers['x-token'] as string) ?? ''),
      onDecision: ({ verdict }) => decisions.push(verdict.kind),
      map: (_r, claims) => ({
        subject: { type: 'user', id: claims.sub },
        action: { name: 'read' },
        resource: { type: 'thing' },
      }),
    });
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: { 'x-token': jwt({ sub: 'alice' }) } }, mockRes(), next);
    expect(next).toHaveBeenCalledOnce();
    expect(decisions).toEqual(['ok']);
  });

  it('does not let a broken onDecision hook open the gate', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { reason: 'no' } }) },
      onDecision: () => { throw new Error('audit sink down'); },
      map: () => ({ subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } }),
    });
    const res = mockRes();
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${jwt({ sub: 'u' })}` } }, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it('treats an unexpected throw as a deny, not an allow', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      getToken: () => { throw new Error('exploded'); },
      map: () => null,
    });
    const res = mockRes();
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: {} }, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(502);
  });

  it('pathMapper can be told to skip the PDP for unmatched paths', async () => {
    const map = pathMapper([{ method: 'GET', pattern: '/a', action: 'x', resourceType: 't' }], {
      fallthrough: 'allow',
    });
    expect(map({ method: 'GET', path: '/healthz', headers: {} }, extractClaims({ sub: 'u' }))).toBeNull();
  });

  it('pathMapper builds context and resource properties from the request', () => {
    const map = pathMapper([
      {
        method: 'POST',
        pattern: '/accounts/:id/payments',
        action: 'make_payment',
        resourceType: 'account',
        resourceId: (p) => p['id']!,
        resourceProperties: (_p, req) => ({ amount: (req.body as { amount: number }).amount }),
        context: (_p, _r, claims) => ({ tenant: claims.clientId }),
      },
    ]);
    const out = map(
      { method: 'POST', path: '/accounts/acc-1/payments?x=1', headers: {}, body: { amount: 50 } },
      extractClaims({ sub: 'alice', client_id: 'c1', act: { sub: 'agent' }, scope: 's', acr: 'r' }),
    );
    expect(out).toMatchObject({
      resource: { type: 'account', id: 'acc-1', properties: { amount: 50 } },
      context: { agent: 'agent', scope: 's', acr: 'r', tenant: 'c1' },
    });
  });

  it('matches a wildcard segment', () => {
    const map = pathMapper([{ pattern: '/files/*', action: 'read', resourceType: 'file' }]);
    expect(map({ method: 'GET', path: '/files/a/b/c', headers: {} }, extractClaims({ sub: 'u' }))).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------

describe('McpGuard — discovery and delegation', () => {
  const token = { sub: 'alice@example.com', client_id: 'agent-1' };
  const toolsList = (tools: unknown[]) =>
    JSON.stringify({ jsonrpc: '2.0', id: 'coaz-discovery', result: { tools } });
  const declared = {
    name: 'get_customer',
    inputSchema: {
      'x-authzen-mapping': {
        evaluation: {
          subject: { type: 'identity', id: '$token.sub' },
          action: { name: 'get_customer' },
          resource: { type: 'customer', id: '$params.arguments.id' },
        },
      },
    },
  };
  const call = {
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'get_customer', arguments: { id: 'c1' } },
  };

  function upstream(body: string, contentType = 'application/json') {
    return vi.fn(async (url: unknown) => {
      if (String(url).includes('/access/v1/')) {
        return new Response(JSON.stringify({ decision: true }), { status: 200 });
      }
      return new Response(body, { status: 200, headers: { 'content-type': contentType } });
    }) as unknown as typeof globalThis.fetch;
  }

  it('discovers tools/list over JSON', async () => {
    const fetchImpl = upstream(toolsList([declared]));
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: fetchImpl },
      upstreamUrl: 'http://mcp/mcp',
      fetch: fetchImpl,
    });
    const v = await guard.checkToolCall({ rpc: call, claims: token });
    expect(v.coazTool).toBe(true);
    expect(v.allow).toBe(true);
  });

  it('discovers tools/list over an SSE stream', async () => {
    const sse = `event: message\ndata: ${toolsList([declared])}\n\n`;
    const fetchImpl = upstream(sse, 'text/event-stream');
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: fetchImpl },
      upstreamUrl: 'http://mcp/mcp',
      fetch: fetchImpl,
    });
    const v = await guard.checkToolCall({ rpc: call, claims: token });
    expect(v.coazTool).toBe(true);
  });

  it('caches discovery and re-fetches after invalidate()', async () => {
    let discoveries = 0;
    const fetchImpl = vi.fn(async (url: unknown) => {
      if (String(url).includes('/access/v1/')) {
        return new Response(JSON.stringify({ decision: true }), { status: 200 });
      }
      discoveries++;
      return new Response(toolsList([declared]), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof globalThis.fetch;

    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: fetchImpl },
      upstreamUrl: 'http://mcp/mcp',
      fetch: fetchImpl,
    });
    await guard.checkToolCall({ rpc: call, claims: token });
    await guard.checkToolCall({ rpc: call, claims: token });
    expect(discoveries).toBe(1);
    guard.invalidate();
    await guard.checkToolCall({ rpc: call, claims: token });
    expect(discoveries).toBe(2);
  });

  it('fails closed with -32603 when discovery fails', async () => {
    for (const body of ['{"jsonrpc":"2.0","id":1,"result":{}}', 'not json']) {
      const fetchImpl = upstream(body);
      const guard = new McpGuard({
        client: { url: 'http://pdp', fetch: fetchImpl },
        upstreamUrl: 'http://mcp/mcp',
        fetch: fetchImpl,
      });
      const v = await guard.checkToolCall({ rpc: call, claims: token });
      expect(v.allow).toBe(false);
      expect(v.jsonRpcError?.error.code).toBe(CODE_PDP_ERROR);
    }
  });

  it('accepts tools from a function, re-evaluated per check', async () => {
    let list: unknown[] = [];
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      tools: () => list as never,
    });
    expect((await guard.checkToolCall({ rpc: call, claims: token })).coazTool).toBe(false);
    list = [declared];
    expect((await guard.checkToolCall({ rpc: call, claims: token })).coazTool).toBe(true);
  });

  it('needs tools, an upstream, or a delegate', () => {
    expect(() => new McpGuard({ client: { url: 'http://pdp' } })).toThrow(/tools.*upstreamUrl.*delegate/);
  });

  it('relays a delegated deny verbatim rather than re-deriving it', async () => {
    const engineError = {
      jsonrpc: '2.0', id: 1,
      error: { code: CODE_DENIED_V2, message: 'denied by the engine', data: { authz_challenge: { type: 'authn' } } },
    };
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ decision: false, response: { status: 200, body: JSON.stringify(engineError) } }), { status: 200 }),
    ) as unknown as typeof globalThis.fetch;

    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: fetchImpl },
      delegate: { url: 'http://coaz-pep:9192/', apiKey: 'k' },
      fetch: fetchImpl,
    });
    const v = await guard.checkToolCall({ rpc: call, claims: token, raw: { headers: {}, body: '{}' } });
    expect(v.allow).toBe(false);
    expect(v.jsonRpcError).toEqual(engineError);
  });

  it('permits on a delegated permit', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ decision: true }), { status: 200 })) as unknown as typeof globalThis.fetch;
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: fetchImpl }, delegate: { url: 'http://coaz-pep:9192' }, fetch: fetchImpl });
    const v = await guard.checkToolCall({ rpc: call, claims: token, raw: { headers: {}, body: '{}' } });
    expect(v.allow).toBe(true);
  });

  it('needs the raw request in delegate mode, and says so', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({ decision: true }) }, delegate: { url: 'http://coaz-pep:9192' } });
    const v = await guard.checkToolCall({ rpc: call, claims: token });
    expect(v.jsonRpcError?.error.code).toBe(CODE_MAPPING_ERROR);
    expect(v.verdict.reason).toMatch(/raw request/);
  });

  it('points at the shared secret when the engine answers 401', async () => {
    const fetchImpl = vi.fn(async () => new Response('', { status: 401 })) as unknown as typeof globalThis.fetch;
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: fetchImpl }, delegate: { url: 'http://coaz-pep:9192' }, fetch: fetchImpl });
    const v = await guard.checkToolCall({ rpc: call, claims: token, raw: { headers: {}, body: '{}' } });
    expect(v.verdict.reason).toMatch(/CHECK_API_TOKEN/);
  });

  it('accepts PepClaims as well as a bare claims map', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({ decision: true }) }, tools: [declared as never] });
    const v = await guard.checkToolCall({ rpc: call, claims: claimsFromToken(jwt(token)) });
    expect(v.allow).toBe(true);
    expect(v.pdpRequest).toMatchObject({ subject: { id: 'alice@example.com' } });
  });

  it('reports decisions and survives a broken reporter', async () => {
    const seen: string[] = [];
    const ok = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      tools: [declared as never],
      onDecision: ({ tool }) => seen.push(tool),
    });
    await ok.checkToolCall({ rpc: call, claims: token });
    expect(seen).toEqual(['get_customer']);

    const broken = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      tools: [declared as never],
      onDecision: () => { throw new Error('sink down'); },
    });
    await expect(broken.checkToolCall({ rpc: call, claims: token })).resolves.toMatchObject({ allow: true });
  });

  it('ignores a declared mapping error and reports it as -32602', async () => {
    const guard = new McpGuard({
      client: { url: 'http://pdp', fetch: pdp({ decision: true }) },
      tools: [{ name: 'broken', coaz: true } as never],
    });
    const v = await guard.checkToolCall({
      rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'broken', arguments: {} } },
      claims: token,
    });
    expect(v.jsonRpcError?.error.code).toBe(CODE_MAPPING_ERROR);
  });

  it('wrap() runs the handler on a permit and forwards raw/extraContext', async () => {
    const guard = new McpGuard({ client: { url: 'http://pdp', fetch: pdp({ decision: true }) }, tools: [declared as never] });
    const handler = vi.fn(async () => ({ ok: true }));
    const out = await guard.wrap(handler)(call, token, { extraContext: { channel: 'ai-agent' } });
    expect(handler).toHaveBeenCalledOnce();
    expect(out).toEqual({ ok: true });
  });
});

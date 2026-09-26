import { IncomingMessage, ServerResponse } from 'node:http';
import { Socket } from 'node:net';
import { describe, expect, it, vi } from 'vitest';

import { toHttpChallenge } from '../src/challenge.js';
import { decodeJwtClaims, extractClaims } from '../src/claims.js';
import { authzenMiddleware, pathMapper, type PepRequest, type PepResponse } from '../src/express.js';
import type { Verdict } from '../src/types.js';

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const unsigned = (claims: Record<string, unknown>) => `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.`;

/** A PDP stub that records what it was asked. */
function pdp(answer: unknown = { decision: true }) {
  const asked: Array<Record<string, unknown>> = [];
  const fetch = vi.fn(async (_u: unknown, init?: RequestInit) => {
    asked.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
    return new Response(JSON.stringify(answer), { status: 200 });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, asked };
}

/** An Express-shaped response over a real Node ServerResponse, so header validation is Node's own. */
function realRes() {
  const sr = new ServerResponse(new IncomingMessage(new Socket()));
  let body: unknown;
  const res: PepResponse & { sr: ServerResponse; body: () => unknown } = {
    sr,
    body: () => body,
    status(code: number) {
      sr.statusCode = code;
      return res;
    },
    set(field: string, value: string) {
      sr.setHeader(field, value);
      return res;
    },
    json(b: unknown) {
      body = b;
      return res;
    },
  };
  return res;
}

const verify = async (t: string) => decodeJwtClaims(t);
const rule = { method: 'GET', pattern: '/accounts/:id/balance', action: 'get_balance', resourceType: 'account', resourceId: (p: Record<string, string>) => p['id']! };

// ---------------------------------------------------------------------------

describe('the middleware does not trust a token nobody verified', () => {
  it('refuses to be built without verifyToken', () => {
    expect(() => authzenMiddleware({ client: { url: 'http://pdp' }, map: () => null })).toThrow(/verifyToken/);
    expect(() => authzenMiddleware({ client: { url: 'http://pdp' }, map: () => null })).toThrow(/allowInsecure/);
  });

  it('an alg:none token claiming to be admin never reaches the PDP', async () => {
    const p = pdp();
    // A real verifier refuses an unsigned token; that is the only configuration that builds.
    const mw = authzenMiddleware({ client: { url: 'http://pdp', fetch: p.fetch }, verifyToken: async () => null, map: () => ({ subject: { type: 'user', id: 'x' }, action: { name: 'a' }, resource: { type: 'r' } }) });
    const res = realRes();
    const next = vi.fn();
    await mw({ method: 'GET', path: '/admin', headers: { authorization: `Bearer ${unsigned({ sub: 'admin' })}` } }, res, next);
    expect(res.sr.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
    expect(p.asked).toHaveLength(0);
  });

  it('decodes without verifying only on allowInsecure, and says so once, at construction', async () => {
    const warnings: string[] = [];
    const p = pdp();
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: p.fetch },
      allowInsecure: true,
      onWarning: (m) => warnings.push(m),
      map: (_r, c) => ({ subject: { type: 'user', id: c.sub }, action: { name: 'a' }, resource: { type: 'r' } }),
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/allowInsecure/);
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'alice' })}` } }, realRes(), next);
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'alice' })}` } }, realRes(), next);
    expect(next).toHaveBeenCalledTimes(2);
    expect(warnings).toHaveLength(1);
    expect(p.asked[0]).toMatchObject({ subject: { id: 'alice' } });
  });

  it('a verifier that throws is a 401, reported once', async () => {
    const decisions: Verdict[] = [];
    const p = pdp();
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: p.fetch },
      verifyToken: async () => {
        throw new Error('JWSSignatureVerificationFailed: signature verification failed');
      },
      onDecision: ({ verdict }) => decisions.push(verdict),
      map: () => null,
    });
    const res = realRes();
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: { authorization: 'Bearer abc.def.ghi' } }, res, next);
    expect(res.sr.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ kind: 'unauthenticated', reason: 'Access token failed verification.' });
    expect(decisions[0]!.detail).toMatch(/signature/);
    expect(JSON.stringify(res.body())).not.toMatch(/JWSSignature/);
  });

  it('a verifier that answers with something that is not claims is a 401', async () => {
    for (const answer of ['alice', 42, ['sub']]) {
      const mw = authzenMiddleware({ client: { url: 'http://pdp', fetch: pdp().fetch }, verifyToken: async () => answer as never, map: () => null });
      const res = realRes();
      const next = vi.fn();
      await mw({ method: 'GET', path: '/x', headers: { authorization: 'Bearer t' } }, res, next);
      expect(res.sr.statusCode, JSON.stringify(answer)).toBe(401);
      expect(next).not.toHaveBeenCalled();
    }
  });
});

// ---------------------------------------------------------------------------

describe('X-Auth-* go upstream on the request, never back to the client', () => {
  const claims = { sub: 'alice', act: { sub: 'agent-1' }, scope: 'a b', acr: 'urn:mfa' };

  it('replaces client copies on the request, and leaves the response alone', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp().fetch },
      verifyToken: async () => claims,
      forwardHeaders: true,
      map: (_r, c) => ({ subject: { type: 'user', id: c.sub }, action: { name: 'x' }, resource: { type: 'r' } }),
    });
    const req: PepRequest = { method: 'GET', path: '/x', headers: { authorization: 'Bearer t', 'x-auth-principal': 'mallory', 'X-Auth-Scope': 'admin', 'x-auth-acr': ['urn:forged'] } };
    const res = realRes();
    const next = vi.fn();
    await mw(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.headers).toMatchObject({ 'x-auth-principal': 'alice', 'x-auth-agent': 'agent-1', 'x-auth-scope': 'a b', 'x-auth-acr': 'urn:mfa' });
    expect(req.headers['X-Auth-Scope']).toBeUndefined();
    for (const h of ['X-Auth-Principal', 'X-Auth-Agent', 'X-Auth-Scope', 'X-Auth-Acr']) expect(res.sr.getHeader(h)).toBeUndefined();
  });

  it('asserts nothing it does not have: an empty claim leaves the header absent', async () => {
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp().fetch },
      verifyToken: async () => ({ sub: 'alice' }),
      forwardHeaders: true,
      map: (_r, c) => ({ subject: { type: 'user', id: c.sub }, action: { name: 'x' }, resource: { type: 'r' } }),
    });
    const req: PepRequest = { method: 'GET', path: '/x', headers: { authorization: 'Bearer t', 'x-auth-agent': 'forged-agent' } };
    await mw(req, realRes(), vi.fn());
    expect(req.headers['x-auth-principal']).toBe('alice');
    expect('x-auth-agent' in req.headers).toBe(false);
  });

  it('strips client copies even when it asserts none, and on a map() opt-out', async () => {
    for (const map of [() => null, () => ({ subject: { type: 'user', id: 'alice' }, action: { name: 'x' }, resource: { type: 'r' } })]) {
      const mw = authzenMiddleware({ client: { url: 'http://pdp', fetch: pdp().fetch }, verifyToken: async () => ({ sub: 'alice' }), map });
      const req: PepRequest = { method: 'GET', path: '/x', headers: { authorization: 'Bearer t', 'X-Auth-Principal': 'mallory' } };
      const next = vi.fn();
      await mw(req, realRes(), next);
      expect(next).toHaveBeenCalledOnce();
      expect(Object.keys(req.headers).some((k) => k.toLowerCase() === 'x-auth-principal')).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------

describe('map() opts out only with an explicit null', () => {
  it('undefined is a mapping error: no PDP call, nothing downstream', async () => {
    for (const map of [() => undefined, async () => undefined, () => 'accounts' as never, () => 42 as never]) {
      const p = pdp();
      const mw = authzenMiddleware({ client: { url: 'http://pdp', fetch: p.fetch }, verifyToken: verify, map: map as never });
      const res = realRes();
      const next = vi.fn();
      await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, next);
      expect(res.sr.statusCode).toBe(400);
      expect(next).not.toHaveBeenCalled();
      expect(p.asked).toHaveLength(0);
    }
  });

  it('null lets the request through without the PDP', async () => {
    const p = pdp();
    const mw = authzenMiddleware({ client: { url: 'http://pdp', fetch: p.fetch }, verifyToken: verify, map: () => null });
    const next = vi.fn();
    await mw({ method: 'GET', path: '/healthz', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, realRes(), next);
    expect(next).toHaveBeenCalledOnce();
    expect(p.asked).toHaveLength(0);
  });

  it('a mapper that throws is a generic 400; the detail goes to onDecision', async () => {
    const decisions: Verdict[] = [];
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp().fetch },
      verifyToken: verify,
      onDecision: ({ verdict }) => decisions.push(verdict),
      map: () => {
        throw new Error('ECONNREFUSED accounts-db.internal:5432');
      },
    });
    const res = realRes();
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, vi.fn());
    expect(res.sr.statusCode).toBe(400);
    expect(JSON.stringify(res.body())).not.toMatch(/accounts-db|ECONNREFUSED/);
    expect(decisions[0]!.detail).toMatch(/accounts-db/);
  });
});

// ---------------------------------------------------------------------------

describe('pathMapper matches the path the router sees', () => {
  const claims = extractClaims({ sub: 'u' });
  const map = pathMapper([rule], { fallthrough: 'allow' });

  it('decodes a captured segment, as Express does for req.params', () => {
    expect(map({ method: 'GET', path: '/accounts/%31%32%33/balance', headers: {} }, claims)?.resource.id).toBe('123');
    expect(map({ method: 'GET', path: '/accounts/a%2Fb/balance', headers: {} }, claims)?.resource.id).toBe('a/b');
  });

  it('is case-insensitive by default, as Express routing is, and can be told otherwise', () => {
    expect(map({ method: 'GET', path: '/ACCOUNTS/1/Balance', headers: {} }, claims)?.resource.id).toBe('1');
    const strict = pathMapper([rule], { fallthrough: 'allow', caseSensitive: true });
    expect(strict({ method: 'GET', path: '/ACCOUNTS/1/balance', headers: {} }, claims)).toBeNull();
    expect(strict({ method: 'GET', path: '/accounts/1/balance', headers: {} }, claims)).not.toBeNull();
  });

  it('treats HEAD as the GET it is routed to', () => {
    expect(map({ method: 'HEAD', path: '/accounts/1/balance', headers: {} }, claims)?.action.name).toBe('get_balance');
    const headOnly = pathMapper([{ ...rule, method: 'HEAD', action: 'peek' }], { fallthrough: 'allow' });
    expect(headOnly({ method: 'GET', path: '/accounts/1/balance', headers: {} }, claims)).toBeNull();
    expect(headOnly({ method: 'HEAD', path: '/accounts/1/balance', headers: {} }, claims)?.action.name).toBe('peek');
  });

  it('matches an encoded literal segment rather than skipping the PDP for it', () => {
    expect(map({ method: 'GET', path: '/%61ccounts/1/balance', headers: {} }, claims)?.action.name).toBe('get_balance');
  });

  it('tolerates one trailing slash and ignores the query, as Express does, and nothing looser', () => {
    expect(map({ method: 'GET', path: '/accounts/1/balance/', headers: {} }, claims)).not.toBeNull();
    expect(map({ method: 'GET', originalUrl: '/accounts/1/balance?x=%2F', headers: {} }, claims)).not.toBeNull();
    expect(map({ method: 'GET', path: '/accounts/1/balance//', headers: {} }, claims)).toBeNull();
    expect(map({ method: 'GET', path: '/accounts//balance', headers: {} }, claims)).toBeNull();
  });

  it('refuses a path it cannot decode', () => {
    expect(() => map({ method: 'GET', path: '/accounts/%E0%A4%A/balance', headers: {} }, claims)).toThrow();
  });

  it('keeps wildcards, and takes parameter names a RegExp group would not', () => {
    const files = pathMapper([{ pattern: '/files/*', action: 'read', resourceType: 'file' }]);
    expect(files({ method: 'GET', path: '/files/a/b/c', headers: {} }, claims)).toBeTruthy();
    expect(files({ method: 'GET', path: '/FILES/a', headers: {} }, claims)).toBeTruthy();
    const mid = pathMapper([{ pattern: '/a/*/z', action: 'x', resourceType: 't' }], { fallthrough: 'allow' });
    expect(mid({ method: 'GET', path: '/a/b/c/z', headers: {} }, claims)).toBeTruthy();
    expect(mid({ method: 'GET', path: '/a/b/c', headers: {} }, claims)).toBeNull();
    const dashed = pathMapper([{ pattern: '/accounts/:account-id', action: 'x', resourceType: 'account', resourceId: (p) => p['account-id']! }]);
    expect(dashed({ method: 'GET', path: '/accounts/a%20b', headers: {} }, claims)?.resource.id).toBe('a b');
    const root = pathMapper([{ pattern: '/', action: 'home', resourceType: 'site' }], { fallthrough: 'allow' });
    expect(root({ method: 'GET', path: '/', headers: {} }, claims)?.action.name).toBe('home');
    expect(root({ method: 'GET', path: '/x', headers: {} }, claims)).toBeNull();
  });

  it('through the middleware, an upper-case path still asks the PDP', async () => {
    const p = pdp({ decision: false });
    const mw = authzenMiddleware({ client: { url: 'http://pdp', fetch: p.fetch }, verifyToken: verify, map: pathMapper([rule], { fallthrough: 'allow' }) });
    const next = vi.fn();
    const res = realRes();
    await mw({ method: 'GET', path: '/ACCOUNTS/9/balance', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.sr.statusCode).toBe(403);
    expect(p.asked[0]).toMatchObject({ resource: { id: '9' } });
  });
});

// ---------------------------------------------------------------------------

describe('challenge headers survive whatever the PDP says', () => {
  it('a non-Latin-1 reason is still a 401 step-up, reported once', async () => {
    const decisions: Verdict[] = [];
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { reason: 'Approve 支付 of ¥500 ✓', step_up_required: true, step_up_scope: 'pay✓' } }).fetch },
      verifyToken: verify,
      onDecision: ({ verdict }) => decisions.push(verdict),
      map: () => ({ subject: { type: 'user', id: 'u' }, action: { name: 'pay' }, resource: { type: 'payment' } }),
    });
    const res = realRes();
    await mw({ method: 'POST', path: '/payments', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, vi.fn());
    expect(res.sr.statusCode).toBe(401);
    const header = String(res.sr.getHeader('WWW-Authenticate'));
    expect(header).toContain('error="insufficient_scope"');
    expect(header).toMatch(/^[\t\x20-\x7e\x80-\xff]*$/);
    expect(header).toContain('¥500');
    expect(decisions).toHaveLength(1);
  });

  it('control characters are dropped and quotes escaped inside the quoted-string', () => {
    const out = toHttpChallenge({ allow: false, kind: 'step_up_required', reason: 'a\u0000b\u007fc "q" \\ d\r\ne', context: { step_up_scope: 's' } });
    expect(out.headers['WWW-Authenticate']).toContain('error_description="abc \\"q\\" \\\\ d e"');
  });

  it('a fail-open marker is identifiers only, and safe to set', async () => {
    const fetch = vi.fn(async (u: unknown) =>
      String(u).startsWith('http://down') ? new Response('', { status: 503 }) : new Response('{"decision":true}', { status: 200 }),
    ) as unknown as typeof globalThis.fetch;
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch, layers: ['http://down fail-open', 'static'] },
      verifyToken: verify,
      map: () => ({ subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } }),
    });
    const res = realRes();
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(res.sr.getHeader('X-PDP-Fail-Open')).toBe('http://down');
  });

  it('a PDP failure is a generic 502', async () => {
    const fetch = vi.fn(async () => new Response('stack at /srv/pdp.js', { status: 500 })) as unknown as typeof globalThis.fetch;
    const mw = authzenMiddleware({ client: { url: 'http://pdp.internal:8080', fetch }, verifyToken: verify, map: () => ({ subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } }) });
    const res = realRes();
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, vi.fn());
    expect(res.sr.statusCode).toBe(502);
    expect(JSON.stringify(res.body())).not.toMatch(/pdp\.internal|srv|500/);
  });

  it('a response that will not take a header still denies, and reports once', async () => {
    const decisions: Verdict[] = [];
    const mw = authzenMiddleware({
      client: { url: 'http://pdp', fetch: pdp({ decision: false, context: { step_up_required: true, step_up_scope: 's' } }).fetch },
      verifyToken: verify,
      onDecision: ({ verdict }) => decisions.push(verdict),
      map: () => ({ subject: { type: 'user', id: 'u' }, action: { name: 'a' }, resource: { type: 'r' } }),
    });
    const sent: Array<[number, unknown]> = [];
    const res: PepResponse = {
      status(c) {
        return { ...res, json: (b: unknown) => sent.push([c, b]) } as PepResponse;
      },
      set() {
        throw new Error('ERR_HTTP_HEADERS_SENT');
      },
      json() {
        return undefined;
      },
    };
    const next = vi.fn();
    await mw({ method: 'GET', path: '/x', headers: { authorization: `Bearer ${unsigned({ sub: 'u' })}` } }, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(sent.map(([c]) => c)).toEqual([401]);
    expect(decisions).toHaveLength(1);
  });
});

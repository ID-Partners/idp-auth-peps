import { describe, expect, it, vi } from 'vitest';

import { AuthzenClient } from '../src/client.js';
import {
  DiscoveryError,
  PARAM_POLICY_DECISION_POINTS,
  PdpDiscovery,
  Rfc9728Source,
  allowedByPrefix,
  defaultEndpoints,
  wellKnownUrl,
  type MetadataSource,
  type PdpEndpoints,
} from '../src/discovery.js';
import { authzenMiddleware, type PepRequest } from '../src/express.js';
import { McpGuard } from '../src/mcp.js';

const STATIC = 'https://static.example';
const GOOD = 'https://good.example';
const ROGUE = 'https://rogue.example';
const RES = 'https://api.example';

type Route = unknown | string | number | false | ((url: string, init?: RequestInit) => Response | Promise<Response>);

/** A fetch stub routed by URL prefix (longest wins) that records every call. */
function router(routes: Record<string, Route>) {
  const hits: { url: string; method: string; headers: Record<string, string> }[] = [];
  const fetch = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers as Record<string, string>) ?? {})) headers[k.toLowerCase()] = v;
    hits.push({ url, method: init?.method ?? 'GET', headers });
    const keys = Object.keys(routes).sort((a, b) => b.length - a.length);
    for (const prefix of keys) {
      if (url !== prefix && !url.startsWith(prefix)) continue;
      const r = routes[prefix];
      if (typeof r === 'function') return (r as (u: string, i?: RequestInit) => Response)(url, init);
      if (r === false) throw new TypeError('fetch failed');
      if (typeof r === 'number') return new Response('', { status: r });
      if (typeof r === 'string') return new Response(r, { status: 200 });
      return new Response(JSON.stringify(r), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('', { status: 404 });
  }) as unknown as typeof globalThis.fetch;
  const count = (needle: string) => hits.filter((h) => h.url.includes(needle)).length;
  return { fetch, hits, count };
}

const pdpConfig = (self: string, evaluation = `${self}/custom/eval`, evaluations?: string) => ({
  policy_decision_point: self,
  access_evaluation_endpoint: evaluation,
  ...(evaluations ? { access_evaluations_endpoint: evaluations } : {}),
  capabilities: ['urn:x:batch', 42],
});

const quiet = { onWarning: () => {} };

function disco(routes: Record<string, Route>, over: Partial<ConstructorParameters<typeof PdpDiscovery>[0]> = {}) {
  const r = router(routes);
  const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, apiKeys: { [STATIC]: 'static-key' }, fetch: r.fetch, ...quiet, ...over });
  return { d, ...r };
}

async function kind(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (err) {
    return err instanceof DiscoveryError ? err.kind : `other:${String(err)}`;
  }
}

describe('discovery: URLs', () => {
  it('derives well-known URLs with the insertion rule', () => {
    const cases: Record<string, string> = {
      'https://pdp.example': 'https://pdp.example/.well-known/authzen-configuration',
      'https://pdp.example/': 'https://pdp.example/.well-known/authzen-configuration',
      'https://pdp.example/tenant1': 'https://pdp.example/.well-known/authzen-configuration/tenant1',
      'https://pdp.example/t/1/': 'https://pdp.example/.well-known/authzen-configuration/t/1',
      'https://PDP.example:8443/x': 'https://pdp.example:8443/.well-known/authzen-configuration/x',
    };
    for (const [input, want] of Object.entries(cases)) expect(wellKnownUrl(input, 'authzen-configuration')).toBe(want);
    for (const bad of ['pdp.example', '/relative', 'https://pdp.example/?x=1', 'https://pdp.example/#f', 'https://']) {
      expect(() => wellKnownUrl(bad, 'authzen-configuration')).toThrow(DiscoveryError);
    }
  });

  it('matches allowlist prefixes only at a path boundary', () => {
    const list = ['https://a.example/mcp', 'https://b.example/', 'not a url'];
    expect(allowedByPrefix(list, 'https://a.example/mcp')).toBe(true);
    expect(allowedByPrefix(list, 'https://a.example/mcp/x')).toBe(true);
    expect(allowedByPrefix(list, 'https://a.example/mcpx')).toBe(false);
    expect(allowedByPrefix(list, 'https://a.example/')).toBe(false);
    expect(allowedByPrefix(list, 'https://b.example/anything')).toBe(true);
    expect(allowedByPrefix(list, 'http://a.example/mcp')).toBe(false);
    expect(allowedByPrefix(list, 'garbage')).toBe(false);
    expect(allowedByPrefix(undefined, 'https://x')).toBe(true);
    expect(allowedByPrefix([], 'https://x')).toBe(true);
  });

  it('shapes default endpoints', () => {
    expect(defaultEndpoints('https://p/')).toEqual({
      identifier: 'https://p', evaluation: 'https://p/access/v1/evaluation', evaluations: 'https://p/access/v1/evaluations', source: 'static',
    });
  });
});

describe('discovery: off and authzen modes', () => {
  it('off makes no requests and keeps the static key', async () => {
    const { d, hits } = disco({}, { mode: 'off' });
    await expect(d.resolve('https://any')).resolves.toEqual({ ...defaultEndpoints(STATIC), apiKey: 'static-key' });
    expect(hits).toHaveLength(0);
    expect(d.status()).toMatchObject({ mode: 'off', sources: [] });
    await expect(new PdpDiscovery({ mode: 'off', staticPdp: '', ...quiet }).resolve()).rejects.toThrow('no PDP configured');
  });

  it('off works without any fetch at all', async () => {
    const saved = globalThis.fetch;
    // @ts-expect-error simulate a runtime without fetch
    globalThis.fetch = undefined;
    try {
      expect(new PdpDiscovery({ staticPdp: STATIC }).mode).toBe('off');
      expect(() => new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC })).toThrow('fetch');
    } finally {
      globalThis.fetch = saved;
    }
  });

  it('authzen reads the static PDP metadata once and binds the key', async () => {
    const { d, hits, count } = disco({ [`${STATIC}/.well-known/authzen-configuration`]: pdpConfig(STATIC, `${STATIC}/custom/eval`, `${STATIC}/custom/evals`) }, { mode: 'authzen' });
    for (let i = 0; i < 2; i++) {
      const ep = await d.resolve('https://ignored');
      expect(ep).toEqual({
        identifier: STATIC, evaluation: `${STATIC}/custom/eval`, evaluations: `${STATIC}/custom/evals`,
        capabilities: ['urn:x:batch'], apiKey: 'static-key', source: 'static',
      });
    }
    expect(count(STATIC)).toBe(1);
    expect(hits[0]?.headers['accept']).toBe('application/json');
    await expect(d.warm()).resolves.toMatchObject({ identifier: STATIC });
    expect(d.status().pdps[STATIC]).toMatchObject({ cached: true, stale: false });
    await expect(new PdpDiscovery({ mode: 'authzen', staticPdp: '', fetch: router({}).fetch, ...quiet }).resolve()).rejects.toThrow('no PDP configured');
  });

  it('falls back to the default paths on 404, 500 and a network failure', async () => {
    for (const r of [404, 500, false] as Route[]) {
      const { d } = disco({ [STATIC]: r }, { mode: 'authzen' });
      expect((await d.resolve()).evaluation).toBe(`${STATIC}/access/v1/evaluation`);
    }
  });

  it('warns by default through console.warn', async () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const r = router({ [STATIC]: 500 });
      const d = new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC, fetch: r.fetch });
      await d.resolve();
      expect(spy).toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('rejects a document about another PDP, without an evaluation endpoint, or not JSON', async () => {
    const cases: [Route, string][] = [
      [pdpConfig('https://other.example'), 'policy_decision_point'],
      [{ policy_decision_point: STATIC }, 'access_evaluation_endpoint'],
      ['<html>', 'not JSON'],
      ['"just a string"', 'not JSON'],
    ];
    for (const [doc, want] of cases) {
      const warnings: string[] = [];
      const { d } = disco({ [`${STATIC}/.well-known/authzen-configuration`]: doc }, { mode: 'authzen', onWarning: (m) => warnings.push(m) });
      await expect(d.resolve()).rejects.toThrow(want);
      expect(warnings.length).toBeGreaterThan(0);
    }
  });

  it('refuses an advertised endpoint outside the allowlist', async () => {
    const { d } = disco({ [`${STATIC}/.well-known/authzen-configuration`]: pdpConfig(STATIC, `${STATIC}/eval`, 'https://elsewhere.example/evals') }, { mode: 'authzen', pdpAllowlist: ['https://pdp.example'] });
    expect(await kind(d.resolve())).toBe('not_allowed');
  });

  it('trusts the static PDP over http on its own origin, and nothing else', async () => {
    const routes = { 'http://pdp:8080/.well-known/authzen-configuration': pdpConfig('http://pdp:8080', 'http://pdp:8080/eval', 'http://other:8080/evals') };
    const { d } = disco(routes, { mode: 'authzen', staticPdp: 'http://pdp:8080/' });
    expect(await kind(d.resolve())).toBe('not_allowed');
    const { d: insecure } = disco(routes, { mode: 'authzen', staticPdp: 'http://pdp:8080/', allowInsecure: true });
    expect((await insecure.resolve()).evaluations).toBe('http://other:8080/evals');
    const { d: ftp } = disco({}, { mode: 'authzen', staticPdp: 'ftp://pdp' });
    expect(await kind(ftp.resolve())).toBe('not_allowed');
  });

  it('treats a redirect or an oversized body as a transport failure', async () => {
    const big = 'x'.repeat(1_048_577);
    for (const r of [302, () => new Response(big, { status: 200 })] as Route[]) {
      const { d } = disco({ [STATIC]: r }, { mode: 'authzen' });
      expect((await d.resolve()).evaluation).toBe(`${STATIC}/access/v1/evaluation`);
    }
  });

  it('times out a slow metadata fetch and uses the defaults', async () => {
    const slow = (_u: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    const { d } = disco({ [STATIC]: slow }, { mode: 'authzen', timeoutMs: 5 });
    expect((await d.resolve()).evaluation).toBe(`${STATIC}/access/v1/evaluation`);
  });
});

describe('discovery: resource mode', () => {
  const routes = (over: Record<string, Route> = {}) => ({
    [`${RES}/.well-known/oauth-protected-resource`]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [`${GOOD}/`], ignored: true },
    [`${GOOD}/.well-known/authzen-configuration`]: pdpConfig(GOOD),
    [`${ROGUE}/.well-known/authzen-configuration`]: pdpConfig(ROGUE),
    ...over,
  });

  it('follows the resource to its PDP and never relays the static key', async () => {
    const { d, count } = disco(routes());
    const ep = await d.resolve(RES);
    expect(ep).toMatchObject({ identifier: GOOD, evaluation: `${GOOD}/custom/eval`, source: 'rfc9728' });
    expect(ep.apiKey).toBeUndefined();
    expect(count(STATIC)).toBe(0);
    await d.resolve(RES);
    expect(count(RES)).toBe(1);
    expect(count(GOOD)).toBe(1);
    expect(d.status()).toMatchObject({ mode: 'resource', sources: ['rfc9728'] });
    expect(d.status().resources[RES]).toMatchObject({ cached: true });
  });

  it('uses the static PDP for an empty resource, and keeps its key', async () => {
    const { d, count } = disco(routes());
    expect(await d.resolve()).toMatchObject({ identifier: STATIC, apiKey: 'static-key', source: 'static' });
    expect(count(RES)).toBe(0);
  });

  it('falls to the static PDP when the resource has no usable metadata', async () => {
    const cases: Record<string, Route> = {
      '404': 404,
      'no parameter': { resource: RES },
      'echo mismatch': { resource: 'https://impostor.example', [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
      'bad entries': { resource: RES, [PARAM_POLICY_DECISION_POINTS]: ['not a url', 1] },
      'entry with query': { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [`${GOOD}/?x`] },
      'empty list': { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [] },
      'not JSON': '<html>',
    };
    for (const [name, doc] of Object.entries(cases)) {
      const { d } = disco(routes({ [`${RES}/.well-known/oauth-protected-resource`]: doc }));
      expect((await d.resolve(RES)).identifier, name).toBe(STATIC);
      expect((await d.resolve(RES)).apiKey, name).toBe('static-key');
    }
    const { d } = disco(routes());
    expect(await kind(d.resolve('https://r.example/?x'))).toBe('ok');
    expect((await d.resolve('https://r.example/?x')).identifier).toBe(STATIC);
  });

  it('falls to the static PDP on a transient failure without caching it as the answer', async () => {
    let now = 1_700_000_000_000;
    const { d, hits } = disco(routes({ [`${RES}/.well-known/oauth-protected-resource`]: 500 }), { now: () => now });
    expect((await d.resolve(RES)).identifier).toBe(STATIC);
    expect(d.status().resources[RES]).toMatchObject({ cached: false, lastError: expect.stringContaining('500') });
    const before = hits.length;
    await d.resolve(RES);
    expect(hits.length).toBe(before); // negatively cached
    now += 31_000;
    await d.resolve(RES);
    expect(hits.length).toBeGreaterThan(before);
  });

  it('serves the stale list while the resource is down after the TTL', async () => {
    let now = 1_700_000_000_000;
    const r = routes();
    const { d, hits } = disco(r, { now: () => now });
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
    r[`${RES}/.well-known/oauth-protected-resource`] = 500;
    now += 301_000;
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
    expect(d.status().resources[RES]).toMatchObject({ cached: true, stale: true });
    const before = hits.length;
    await d.resolve(RES); // throttled
    expect(hits.length).toBe(before);
    r[`${RES}/.well-known/oauth-protected-resource`] = { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [GOOD] };
    now += 31_000;
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
    expect(d.status().resources[RES]?.lastError).toBeUndefined();
  });

  it('fails closed on a disallowed resource without fetching it', async () => {
    const { d, hits } = disco(routes(), { resourceAllowlist: ['https://only.example'] });
    expect(await kind(d.resolve(RES))).toBe('not_allowed');
    expect(hits).toHaveLength(0);
  });

  it('fails closed when the named PDP is outside the allowlist, even from another caller\'s cache', async () => {
    const { d, count } = disco(routes());
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
    const strict = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: router(routes()).fetch, pdpAllowlist: ['https://pdp.example'], ...quiet });
    expect(await kind(strict.resolve(RES))).toBe('not_allowed');
    expect(count(GOOD)).toBe(1);
    expect((await strict.resolve()).identifier).toBe(STATIC); // always permitted
  });

  it('re-checks cached endpoints against a stricter allowlist', async () => {
    const shared = router(routes({ [`${GOOD}/.well-known/authzen-configuration`]: pdpConfig(GOOD, `${GOOD}/eval`, 'https://batch.example/evals') }));
    const lax = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: shared.fetch, ...quiet });
    expect((await lax.resolve(RES)).evaluations).toBe('https://batch.example/evals');
    const strict = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: shared.fetch, pdpAllowlist: [GOOD], ...quiet });
    expect(await kind(strict.resolve(RES))).toBe('not_allowed');
  });

  it('refuses http for a discovered resource unless insecure', async () => {
    const r = {
      'http://r.example/.well-known/oauth-protected-resource': { resource: 'http://r.example', [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
      [`${GOOD}/.well-known/authzen-configuration`]: pdpConfig(GOOD),
    };
    const { d } = disco(r);
    expect(await kind(d.resolve('http://r.example'))).toBe('not_allowed');
    const { d: insecure } = disco(r, { allowInsecure: true });
    expect((await insecure.resolve('http://r.example')).identifier).toBe(GOOD);
  });

  it('tries the next candidate when the first PDP is unusable', async () => {
    const { d } = disco(routes({
      [`${RES}/.well-known/oauth-protected-resource`]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [ROGUE, GOOD] },
      [`${ROGUE}/.well-known/authzen-configuration`]: pdpConfig('https://x.example'),
    }));
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
  });

  it('reports no PDP when every candidate fails and there is no static one', async () => {
    const { d } = disco({
      [`${RES}/.well-known/oauth-protected-resource`]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [ROGUE] },
      [`${ROGUE}/.well-known/authzen-configuration`]: pdpConfig('https://x.example'),
    }, { staticPdp: '' });
    await expect(d.resolve(RES)).rejects.toThrow('no PDP could be resolved');
    const { d: nothing } = disco({}, { staticPdp: '' });
    await expect(nothing.resolve(RES)).rejects.toThrow('no PDP could be resolved');
    const { d: down } = disco({ [RES]: 500 }, { staticPdp: '' });
    await expect(down.resolve(RES)).rejects.toThrow('no PDP could be resolved');
    await expect(nothing.resolve()).rejects.toThrow('no PDP configured');
  });

  it('keeps serving a cached PDP whose metadata later goes bad', async () => {
    let now = 1_700_000_000_000;
    const r = routes();
    const { d } = disco(r, { now: () => now });
    expect((await d.resolve(RES)).evaluation).toBe(`${GOOD}/custom/eval`);
    r[`${GOOD}/.well-known/authzen-configuration`] = pdpConfig('https://x.example');
    now += 301_000;
    expect((await d.resolve(RES)).evaluation).toBe(`${GOOD}/custom/eval`);
  });

  it('shares one in-flight fetch between concurrent callers', async () => {
    const { d, count } = disco(routes());
    const all = await Promise.all([d.resolve(RES), d.resolve(RES), d.resolve(RES)]);
    expect(all.map((e) => e.identifier)).toEqual([GOOD, GOOD, GOOD]);
    expect(count(RES)).toBe(1);
    expect(count(GOOD)).toBe(1);
  });

  it('serves uncached when the cache is full of live entries', async () => {
    const { d, count } = disco(routes({
      'https://r2.example/.well-known/oauth-protected-resource': { resource: 'https://r2.example', [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
    }), { maxEntries: 1 });
    await d.resolve(RES);
    await d.resolve('https://r2.example');
    await d.resolve('https://r2.example');
    expect(count('r2.example')).toBe(2);
    expect(Object.keys(d.status().resources)).toEqual([RES]);
  });

  it('evicts expired entries to make room', async () => {
    let now = 1_700_000_000_000;
    const { d } = disco(routes({
      'https://r2.example/.well-known/oauth-protected-resource': { resource: 'https://r2.example', [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
      'https://r3.example/.well-known/oauth-protected-resource': 500,
    }), { maxEntries: 1, now: () => now });
    await d.resolve(RES);
    now += 301_000;
    await d.resolve('https://r2.example');
    expect(Object.keys(d.status().resources)).toEqual(['https://r2.example']);
    // A negative entry past its window is evictable too.
    now += 301_000;
    await d.resolve('https://r3.example');
    now += 31_000;
    await d.resolve(RES);
    expect(Object.keys(d.status().resources)).toEqual([RES]);
  });

  it('accepts custom sources', async () => {
    const src: MetadataSource = { name: 'fake', pdps: async () => [GOOD] };
    const { d } = disco(routes(), { sources: [src] });
    expect(d.status().sources).toEqual(['fake']);
    expect((await d.resolve(RES)).identifier).toBe(GOOD);

    const boom: MetadataSource = { name: 'boom', pdps: async () => { throw new Error('boom'); } };
    const { d: transient } = disco(routes(), { sources: [boom] });
    expect((await transient.resolve(RES)).identifier).toBe(STATIC);
    expect(transient.status().resources[RES]).toMatchObject({ cached: false });

    const empty: MetadataSource = { name: 'empty', pdps: async () => [] };
    const { d: viaEmpty } = disco(routes(), { sources: [empty] });
    expect((await viaEmpty.resolve(RES)).identifier).toBe(STATIC);
    expect(viaEmpty.status().resources[RES]).toMatchObject({ cached: true });
  });

  it('exposes the RFC 9728 source on its own', async () => {
    const src = new Rfc9728Source(async () => ({ resource: RES, [PARAM_POLICY_DECISION_POINTS]: [GOOD] }));
    expect(await src.pdps(RES)).toEqual([GOOD]);
    expect(src.name).toBe('rfc9728');
  });
});

describe('discovery: through the client, middleware and guard', () => {
  const routes = () => ({
    [`${RES}/.well-known/oauth-protected-resource`]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
    [`${GOOD}/.well-known/authzen-configuration`]: pdpConfig(GOOD, `${GOOD}/custom/eval`, `${GOOD}/custom/evals`),
    [`${GOOD}/custom/eval`]: { decision: true },
    [`${GOOD}/custom/evals`]: { evaluations: [{ decision: true }] },
    [`${STATIC}/access/v1/evaluation`]: { decision: true },
  });
  const req = { subject: { type: 'user', id: 'u1' }, action: { name: 'read' }, resource: { type: 'account', id: 'a1' } };

  it('the client resolves per call and sends the key only to the static PDP', async () => {
    const { fetch, hits } = router(routes());
    const client = new AuthzenClient({ url: STATIC, apiKey: 'k', fetch, discovery: { mode: 'resource', ...quiet } });
    expect((await client.evaluate(req, { resource: RES })).allow).toBe(true);
    const evalHit = hits.find((h) => h.url === `${GOOD}/custom/eval`);
    expect(evalHit?.headers['authorization']).toBeUndefined();
    expect((await client.evaluate(req)).allow).toBe(true);
    expect(hits.find((h) => h.url === `${STATIC}/access/v1/evaluation`)?.headers['authorization']).toBe('Bearer k');
    expect((await client.evaluateAll({ evaluations: [req] }, { resource: RES })).allow).toBe(true);
    expect(hits.some((h) => h.url === `${GOOD}/custom/evals`)).toBe(true);
  });

  it('without discovery the client is byte-for-byte static', async () => {
    const { fetch, hits } = router(routes());
    const client = new AuthzenClient({ url: `${STATIC}/`, apiKey: 'k', fetch });
    await client.evaluate(req, { resource: RES });
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ url: `${STATIC}/access/v1/evaluation`, headers: { authorization: 'Bearer k' } });
  });

  it('a batch to a PDP without an evaluations endpoint is a pdp_error, not a guessed path', async () => {
    const { fetch, hits } = router({
      [`${STATIC}/.well-known/authzen-configuration`]: { policy_decision_point: STATIC, access_evaluation_endpoint: `${STATIC}/e` },
    });
    const client = new AuthzenClient({ url: STATIC, fetch, discovery: { mode: 'authzen', ...quiet } });
    const v = await client.evaluateAll({ evaluations: [req] });
    expect(v).toMatchObject({ allow: false, kind: 'pdp_error', reason: expect.stringContaining('access_evaluations_endpoint') });
    expect(hits.filter((h) => h.method === 'POST')).toHaveLength(0);
  });

  it('a discovery failure is a pdp_error verdict', async () => {
    const { fetch } = router(routes());
    const client = new AuthzenClient({ url: STATIC, fetch, discovery: { mode: 'resource', resourceAllowlist: ['https://only.example'], ...quiet } });
    expect(await client.evaluate(req, { resource: RES })).toMatchObject({ allow: false, kind: 'pdp_error', reason: expect.stringContaining('PDP discovery') });
  });

  it('accepts a resolver of its own', async () => {
    const { fetch, hits } = router({ 'https://mine.example/eval': { decision: true } });
    const resolver = { resolve: async (): Promise<PdpEndpoints> => ({ identifier: 'https://mine.example', evaluation: 'https://mine.example/eval', apiKey: 'mine', source: 'custom' }) };
    const client = new AuthzenClient({ url: STATIC, fetch, discovery: resolver });
    expect(client.resolver).toBe(resolver);
    expect((await client.evaluate(req)).allow).toBe(true);
    expect(hits[0]?.headers['authorization']).toBe('Bearer mine');
  });

  it('the middleware passes a static or per-request resource', async () => {
    const { fetch, hits } = router(routes());
    const client = new AuthzenClient({ url: STATIC, fetch, discovery: { mode: 'resource', ...quiet } });
    const run = async (resource: AuthzenMiddlewareResource) => {
      const mw = authzenMiddleware({ client, map: () => req, resource });
      const res = { status: vi.fn().mockReturnThis(), set: vi.fn(), json: vi.fn() };
      const next = vi.fn();
      const r: PepRequest = { method: 'GET', path: '/x', headers: { authorization: `Bearer ${jwt({ sub: 'u1' })}` } };
      await mw(r, res, next);
      return next.mock.calls.length === 1;
    };
    expect(await run(RES)).toBe(true);
    expect(hits.some((h) => h.url === `${GOOD}/custom/eval`)).toBe(true);
    expect(await run((r) => (r.path === '/x' ? RES : undefined))).toBe(true);
    expect(await run(undefined)).toBe(true);
    expect(hits.some((h) => h.url === `${STATIC}/access/v1/evaluation`)).toBe(true);
  });

  it('the guard keys discovery off its upstream and passes an explicit resource to the delegate', async () => {
    const mcp = 'https://mcp.example/mcp';
    const tools = [{ name: 't', inputSchema: { 'x-authzen-mapping': { evaluation: { subject: { type: 'user', id: '$token.sub' }, action: { name: 't' }, resource: { type: 'x', id: '1' } } } } }];
    const { fetch, hits } = router({
      'https://mcp.example/.well-known/oauth-protected-resource/mcp': { resource: mcp, [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
      ...routes(),
    });
    const client = new AuthzenClient({ url: STATIC, fetch, discovery: { mode: 'resource', ...quiet } });
    const guard = new McpGuard({ client, tools, upstreamUrl: mcp });
    const v = await guard.checkToolCall({ rpc: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 't', arguments: {} } }, claims: { sub: 'u1' } });
    expect(v.allow).toBe(true);
    expect(hits.some((h) => h.url === `${GOOD}/custom/eval`)).toBe(true);

    const delegated = router({ 'http://coaz-pep:9192/v1/mcp/check': { decision: true } });
    const g2 = new McpGuard({ client, delegate: { url: 'http://coaz-pep:9192' }, resource: RES, fetch: delegated.fetch });
    const raw = { headers: {}, body: '{}' };
    const rpc = { jsonrpc: '2.0' as const, id: 1, method: 'tools/call', params: { name: 't', arguments: {} } };
    expect((await g2.checkToolCall({ rpc, claims: { sub: 'u1' }, raw })).allow).toBe(true);
    const sent = JSON.parse(String((delegated.fetch as unknown as { mock: { calls: [unknown, RequestInit][] } }).mock.calls[0]?.[1]?.body)) as { config: Record<string, string> };
    expect(sent.config.resource).toBe(RES);
    const g3 = new McpGuard({ client, delegate: { url: 'http://coaz-pep:9192' }, fetch: delegated.fetch });
    await g3.checkToolCall({ rpc, claims: { sub: 'u1' }, raw });
    const sent2 = JSON.parse(String((delegated.fetch as unknown as { mock: { calls: [unknown, RequestInit][] } }).mock.calls[1]?.[1]?.body)) as { config: Record<string, string> };
    expect(sent2.config.resource).toBeUndefined();
  });
});

type AuthzenMiddlewareResource = string | ((req: PepRequest) => string | undefined) | undefined;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: 'none' })}.${b64(claims)}.sig`;

import { describe, expect, it, vi } from 'vitest';

import { AuthzenClient } from '../src/client.js';
import { DiscoveryError, PARAM_POLICY_DECISION_POINTS, PdpDiscovery, parseLayer, resolveLayers, type MetadataSource } from '../src/discovery.js';
import type { EvaluationRequest } from '../src/types.js';

const STATIC = 'https://static.example';
const GOOD = 'https://good.example';
const RES = 'https://api.example';

type Route = unknown | number | false | ((url: string, init?: RequestInit) => Response | Promise<Response>);

/** A fetch stub routed by URL prefix (longest wins) that records every call. */
function router(routes: Record<string, Route>) {
  const hits: string[] = [];
  const fetch = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    hits.push(`${init?.method ?? 'GET'} ${url}`);
    for (const prefix of Object.keys(routes).sort((a, b) => b.length - a.length)) {
      if (!url.startsWith(prefix)) continue;
      const r = routes[prefix];
      if (typeof r === 'function') return (r as (u: string, i?: RequestInit) => Response)(url, init);
      if (r === false) throw new TypeError('fetch failed');
      if (typeof r === 'number') return new Response('', { status: r });
      if (typeof r === 'string') return new Response(r, { status: 200 });
      return new Response(JSON.stringify(r), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('', { status: 404 });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, hits, count: (needle: string) => hits.filter((h) => h.includes(needle)).length };
}

const quiet = { onWarning: () => {} };
const allow = { pdpAllowlist: [GOOD], resourceAllowlist: [RES] };
const req: EvaluationRequest = { subject: { type: 'user', id: 'u1' }, action: { name: 'read' }, resource: { type: 'account', id: 'a1' } };
const RES_WK = `${RES}/.well-known/oauth-protected-resource`;

/** Every PDP permits; the resource names GOOD unless a route says otherwise. */
const routes = (over: Record<string, Route> = {}): Record<string, Route> => ({
  [RES_WK]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
  [`${GOOD}/.well-known/authzen-configuration`]: 404,
  [`${GOOD}/access/v1/evaluation`]: { decision: true },
  [`${STATIC}/.well-known/authzen-configuration`]: 404,
  [`${STATIC}/access/v1/evaluation`]: { decision: true },
  ...over,
});

// ---------------------------------------------------------------------------

describe('a resource layer that cannot be read fails by its own mode, never into the static layer', () => {
  const outages: Array<[string, Route]> = [
    ['a 503', 503],
    ['a 429', 429],
    ['a network failure', false],
    ['an invalid document (echo mismatch)', { resource: 'https://impostor.example', [PARAM_POLICY_DECISION_POINTS]: [GOOD] }],
    ['an invalid document (not JSON)', '<html>'],
    ['an invalid document (bad entries)', { resource: RES, [PARAM_POLICY_DECISION_POINTS]: ['not a url'] }],
    ['a redirect', () => new Response('', { status: 302, headers: { location: 'https://elsewhere.example/doc' } })],
  ];

  for (const [name, route] of outages) {
    it(`[static, resource] with ${name}: closed by default`, async () => {
      const r = router(routes({ [RES_WK]: route }));
      const client = new AuthzenClient({ url: STATIC, fetch: r.fetch, layers: ['static', 'resource'], discovery: { mode: 'resource', ...allow, ...quiet } });
      const v = await client.evaluate(req, { resource: RES });
      expect(v, name).toMatchObject({ allow: false, kind: 'pdp_error' });
      // The estate PDP alone must not have decided a call the resource's PDP never saw.
      expect(r.count(`POST ${STATIC}`), name).toBe(0);
    });

    it(`[static, resource fail-open] with ${name}: skipped, and marked`, async () => {
      const r = router(routes({ [RES_WK]: route }));
      const client = new AuthzenClient({ url: STATIC, fetch: r.fetch, layers: ['static', 'resource fail-open'], discovery: { mode: 'resource', ...allow, ...quiet } });
      const v = await client.evaluate(req, { resource: RES });
      expect(v, name).toMatchObject({ allow: true, failedOpen: ['resource'] });
      expect(r.count(`POST ${STATIC}`), name).toBe(1);
    });
  }

  it('the default layer list fails closed the same way, and opens only when told', async () => {
    const r = router(routes({ [RES_WK]: 503 }));
    const closed = new AuthzenClient({ url: STATIC, fetch: r.fetch, discovery: { mode: 'resource', ...allow, ...quiet } });
    expect(await closed.evaluate(req, { resource: RES })).toMatchObject({ allow: false, kind: 'pdp_error' });
    const r2 = router(routes({ [RES_WK]: 503 }));
    const opened = new AuthzenClient({ url: STATIC, fetch: r2.fetch, failMode: 'open', discovery: { mode: 'resource', ...allow, ...quiet } });
    expect(await opened.evaluate(req, { resource: RES })).toMatchObject({ allow: true, failedOpen: ['resource'] });
    expect(r2.count('POST')).toBe(0);
  });

  it('a 404 is a resource that publishes nothing: the static PDP, by design, unmarked', async () => {
    for (const doc of [404, 410, { resource: RES }, { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [] }] as Route[]) {
      const r = router(routes({ [RES_WK]: doc }));
      const client = new AuthzenClient({ url: STATIC, fetch: r.fetch, layers: ['static', 'resource'], discovery: { mode: 'resource', ...allow, ...quiet } });
      const v = await client.evaluate(req, { resource: RES });
      expect(v, JSON.stringify(doc)).toMatchObject({ allow: true, kind: 'ok' });
      expect(v.failedOpen).toBeUndefined();
      expect(r.count(`POST ${STATIC}`)).toBe(1);
    }
  });

  it('a stale list still serves while the resource is down', async () => {
    let now = 1_700_000_000_000;
    const table = routes();
    const r = router(table);
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: r.fetch, now: () => now, ...allow, ...quiet });
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
    table[RES_WK] = 503;
    now += 301_000;
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
  });

  it('an outage is not re-fetched in every request, and not remembered past the retry window', async () => {
    let now = 1_700_000_000_000;
    const table = routes({ [RES_WK]: 503 });
    const r = router(table);
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: r.fetch, now: () => now, ...allow, ...quiet });
    await expect(d.resolve(RES)).rejects.toMatchObject({ kind: 'transient' });
    await expect(d.resolve(RES)).rejects.toMatchObject({ kind: 'transient' });
    expect(r.count(RES_WK)).toBe(1);
    table[RES_WK] = { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [GOOD] };
    now += 31_000;
    expect((await d.resolve(RES)).identifier).toBe(GOOD);
  });

  it('an invalid document from one source is not rescued by a quiet one', async () => {
    const invalid: MetadataSource = { name: 'bad', lookup: async () => { throw new DiscoveryError('invalid', 'bad signature'); } };
    const empty: MetadataSource = { name: 'empty', lookup: async () => { throw new DiscoveryError('no_metadata', 'nothing'); } };
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: router(routes()).fetch, sources: [invalid, empty], ...allow, ...quiet });
    await expect(d.resolve(RES)).rejects.toMatchObject({ kind: 'invalid' });
    const nothing = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: router(routes()).fetch, sources: [empty], ...allow, ...quiet });
    expect((await nothing.resolve(RES)).identifier).toBe(STATIC);
  });

  it('a resource identifier that cannot name a document is invalid, not static', async () => {
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: router(routes()).fetch, pdpAllowlist: [GOOD], resourceAllowlist: ['https://r.example'], ...quiet });
    await expect(d.resolve('https://r.example/?x')).rejects.toMatchObject({ kind: 'invalid' });
  });
});

// ---------------------------------------------------------------------------

describe('resource mode needs both allowlists', () => {
  it('refuses to start without them', () => {
    const base = { mode: 'resource' as const, staticPdp: STATIC, fetch: router({}).fetch, ...quiet };
    expect(() => new PdpDiscovery(base)).toThrow(/pdpAllowlist.*resourceAllowlist|resourceAllowlist.*pdpAllowlist/);
    expect(() => new PdpDiscovery({ ...base, pdpAllowlist: [GOOD] })).toThrow(/resourceAllowlist/);
    expect(() => new PdpDiscovery({ ...base, resourceAllowlist: [RES] })).toThrow(/pdpAllowlist/);
    expect(() => new PdpDiscovery({ ...base, pdpAllowlist: [], resourceAllowlist: [RES] })).toThrow(/pdpAllowlist/);
    expect(() => new AuthzenClient({ url: STATIC, discovery: { mode: 'resource' } })).toThrow(/allowInsecure/);
    expect(() => new PdpDiscovery({ ...base, ...allow })).not.toThrow();
  });

  it('starts without them only on allowInsecure, and says so once', () => {
    const warnings: string[] = [];
    new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: router({}).fetch, allowInsecure: true, onWarning: (m) => warnings.push(m) });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/allowInsecure/);
  });

  it('other modes do not need them', () => {
    expect(() => new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC, fetch: router({}).fetch, ...quiet })).not.toThrow();
    expect(() => new PdpDiscovery({ staticPdp: STATIC, ...quiet })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------

describe('PDP metadata that goes missing serves the last good copy', () => {
  const custom = { policy_decision_point: STATIC, access_evaluation_endpoint: `${STATIC}/custom/eval`, access_evaluations_endpoint: `${STATIC}/custom/evals` };

  for (const [name, outage] of [['a 503', 503], ['a network failure', false], ['a 429', 429]] as Array<[string, Route]>) {
    it(`keeps the advertised endpoints through ${name}`, async () => {
      let now = 1_700_000_000_000;
      const table: Record<string, Route> = { [`${STATIC}/.well-known/authzen-configuration`]: custom };
      const r = router(table);
      const d = new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC, fetch: r.fetch, now: () => now, ...quiet });
      expect((await d.resolve()).evaluation).toBe(`${STATIC}/custom/eval`);
      table[`${STATIC}/.well-known/authzen-configuration`] = outage;
      now += 301_000;
      expect((await d.resolve()).evaluation).toBe(`${STATIC}/custom/eval`);
      now += 31_000;
      expect((await d.resolve()).evaluation).toBe(`${STATIC}/custom/eval`);
      expect(d.status().pdps[STATIC]).toMatchObject({ cached: true, stale: true });
    });
  }

  it('with no good copy yet, uses the default paths for now without caching them as the answer', async () => {
    let now = 1_700_000_000_000;
    const table: Record<string, Route> = { [`${STATIC}/.well-known/authzen-configuration`]: 503 };
    const r = router(table);
    const d = new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC, fetch: r.fetch, now: () => now, ...quiet });
    expect((await d.resolve()).evaluation).toBe(`${STATIC}/access/v1/evaluation`);
    expect(d.status().pdps[STATIC]).toMatchObject({ cached: false });
    // Within the retry window nothing is fetched again.
    expect((await d.resolve()).evaluation).toBe(`${STATIC}/access/v1/evaluation`);
    expect(r.count('authzen-configuration')).toBe(1);
    table[`${STATIC}/.well-known/authzen-configuration`] = custom;
    now += 31_000;
    expect((await d.resolve()).evaluation).toBe(`${STATIC}/custom/eval`);
  });

  it('a 404 is still the default paths, remembered', async () => {
    const r = router({ [`${STATIC}/.well-known/authzen-configuration`]: 404 });
    const d = new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC, fetch: r.fetch, ...quiet });
    expect((await d.resolve()).evaluation).toBe(`${STATIC}/access/v1/evaluation`);
    expect(d.status().pdps[STATIC]).toMatchObject({ cached: true });
  });

  it('a redirected, forbidden or oversized metadata document is not an outage', async () => {
    for (const route of [
      () => new Response('', { status: 302, headers: { location: 'https://elsewhere.example/' } }),
      403,
      () => new Response('x'.repeat(1_048_577), { status: 200 }),
    ] as Route[]) {
      const r = router({ [`${STATIC}/.well-known/authzen-configuration`]: route });
      const d = new PdpDiscovery({ mode: 'authzen', staticPdp: STATIC, fetch: r.fetch, ...quiet });
      await expect(d.resolve()).rejects.toThrow(DiscoveryError);
    }
  });
});

// ---------------------------------------------------------------------------

describe('an allowlist entry with a path permits its own well-known', () => {
  it('for a PDP', async () => {
    const TENANT = 'https://pdp.example/tenant1';
    const r = router({
      [RES_WK]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: [TENANT] },
      'https://pdp.example/.well-known/authzen-configuration/tenant1': { policy_decision_point: TENANT, access_evaluation_endpoint: `${TENANT}/eval` },
    });
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: r.fetch, pdpAllowlist: [TENANT], resourceAllowlist: [RES], ...quiet });
    expect(await d.resolve(RES)).toMatchObject({ identifier: TENANT, evaluation: `${TENANT}/eval` });
    // Still bounded: a sibling tenant is not the allowlisted one.
    const sibling = router({ [RES_WK]: { resource: RES, [PARAM_POLICY_DECISION_POINTS]: ['https://pdp.example/tenant2'] } });
    const d2 = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: sibling.fetch, pdpAllowlist: [TENANT], resourceAllowlist: [RES], ...quiet });
    await expect(d2.resolve(RES)).rejects.toMatchObject({ kind: 'not_allowed' });
  });

  it('for a resource', async () => {
    const BANK = 'https://api.example/bank';
    const r = router({
      'https://api.example/.well-known/oauth-protected-resource/bank': { resource: BANK, [PARAM_POLICY_DECISION_POINTS]: [GOOD] },
      [`${GOOD}/.well-known/authzen-configuration`]: 404,
    });
    const d = new PdpDiscovery({ mode: 'resource', staticPdp: STATIC, fetch: r.fetch, pdpAllowlist: [GOOD], resourceAllowlist: [BANK], ...quiet });
    expect((await d.resolve(BANK)).identifier).toBe(GOOD);
  });
});

// ---------------------------------------------------------------------------

describe('a layer entry is read strictly', () => {
  it('refuses an object whose failOpen is not a boolean, or whose name is not a layer', () => {
    for (const bad of [
      { name: 'resource', failOpen: 'false' },
      { name: 'resource', failOpen: 1 },
      { name: 5 },
      { name: 'somewhere' },
      { name: 'https://p.example/?x=1' },
      null,
    ]) {
      expect(() => parseLayer(bad as never), JSON.stringify(bad)).toThrow(DiscoveryError);
    }
    expect(parseLayer({ name: 'https://p.example/', failOpen: false })).toEqual({ name: 'https://p.example', failOpen: false });
    expect(parseLayer({ name: 'static' })).toEqual({ name: 'static' });
  });

  it('refuses a PDP identifier that is not an http(s) URL without a query or fragment', () => {
    for (const bad of ['ftp://pdp.example', 'https://p.example/?x=1', 'https://p.example/#f', 'https://', 'mailto://x']) {
      expect(() => parseLayer(bad), bad).toThrow(DiscoveryError);
    }
  });

  it('a layer that cannot be read is never skipped, fail-open or not', async () => {
    const d = new PdpDiscovery({ staticPdp: STATIC, ...quiet });
    await expect(resolveLayers(d, undefined, [{ name: 'resource', failOpen: 'false' } as never], true)).rejects.toThrow(DiscoveryError);
    const client = new AuthzenClient({ url: STATIC, fetch: router(routes()).fetch, failMode: 'open', layers: [{ name: 'static', failOpen: 'true' } as never] });
    expect(await client.evaluate(req)).toMatchObject({ allow: false, kind: 'pdp_error' });
  });
});

import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { AuthzenClient, PdpError, type PdpTrace } from '../src/client.js';
import type { EvaluationRequest } from '../src/types.js';

/** A fetch stub that records every call and answers through `handler`. */
function stub(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetch = vi.fn(async (u: unknown, init?: RequestInit) => {
    calls.push({ url: String(u), init: init ?? {} });
    return handler(String(u), init ?? {});
  }) as unknown as typeof globalThis.fetch;
  return { fetch, calls };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const req: EvaluationRequest = { subject: { type: 'user', id: 'u1' }, action: { name: 'read' }, resource: { type: 'account', id: 'a1' } };

// ---------------------------------------------------------------------------

describe('a permit is the JSON boolean true, and nothing else', () => {
  for (const decision of ['true', 1, {}, 'no', [], null, 'false']) {
    it(`does not permit on decision ${JSON.stringify(decision)}`, async () => {
      const client = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ decision })).fetch });
      const v = await client.evaluate(req);
      expect(v.allow).toBe(false);
      expect(v.kind).toBe('pdp_error');
    });
  }

  it('does not permit a body that is not an object at all', async () => {
    for (const body of [[{ decision: true }], true, 'permit', null]) {
      const client = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json(body)).fetch });
      expect((await client.evaluate(req)).allow, JSON.stringify(body)).toBe(false);
    }
  });

  it('still permits true and denies false, and ignores a context that is not an object', async () => {
    const yes = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ decision: true, context: 'noise' })).fetch });
    expect(await yes.evaluate(req)).toMatchObject({ allow: true, kind: 'ok' });
    const no = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ decision: false, context: ['noise'] })).fetch });
    expect(await no.evaluate(req)).toMatchObject({ allow: false, kind: 'denied' });
  });

  for (const entry of [{ decision: 'false' }, { decision: 1 }, {}, { decision: 'no' }, 'x', null]) {
    it(`evaluateAll does not permit on ${JSON.stringify(entry)}`, async () => {
      const client = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ evaluations: [{ decision: true }, entry] })).fetch });
      const v = await client.evaluateAll({ evaluations: [{}, {}] });
      expect(v.allow).toBe(false);
      expect(v.kind).toBe('pdp_error');
    });
  }

  it('evaluateAll needs exactly one answer per request', async () => {
    const short = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ evaluations: [{ decision: true }] })).fetch });
    expect(await short.evaluateAll({ evaluations: [{}, {}] })).toMatchObject({ allow: false, kind: 'pdp_error' });
    const long = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ evaluations: [{ decision: true }, { decision: true }] })).fetch });
    expect(await long.evaluateAll({ evaluations: [{}] })).toMatchObject({ allow: false, kind: 'pdp_error' });
    const exact = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ evaluations: [{ decision: true }, { decision: true }] })).fetch });
    expect(await exact.evaluateAll({ evaluations: [{}, {}] })).toMatchObject({ allow: true, kind: 'ok' });
  });

  it('evaluateAll refuses an empty or malformed batch before sending it', async () => {
    const s = stub(() => json({ evaluations: [] }));
    const client = new AuthzenClient({ url: 'http://pdp', fetch: s.fetch });
    expect(await client.evaluateAll({ evaluations: [] })).toMatchObject({ allow: false, kind: 'pdp_error' });
    expect(await client.evaluateAll({ evaluations: 'x' } as never)).toMatchObject({ allow: false, kind: 'pdp_error' });
    expect(s.calls).toHaveLength(0);
    const noList = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => json({ results: [] })).fetch });
    expect(await noList.evaluateAll({ evaluations: [{}] })).toMatchObject({ allow: false, kind: 'pdp_error' });
  });

  it('evaluateAll reports the first deny with its advice', async () => {
    const client = new AuthzenClient({
      url: 'http://pdp',
      fetch: stub(() => json({ evaluations: [{ decision: true }, { decision: false, context: { reason: 'over limit', step_up_required: true, step_up_scope: 's' } }] })).fetch,
    });
    expect(await client.evaluateAll({ evaluations: [{}, {}] })).toMatchObject({ allow: false, kind: 'step_up_required', reason: 'over limit' });
  });
});

// ---------------------------------------------------------------------------

describe('fail-open covers unavailability only', () => {
  const DOWN = 'http://down';
  const OK = 'http://ok';
  /** A layered client whose first layer is fail-open and answers with `first`. */
  function layered(first: (url: string, init: RequestInit) => Response | Promise<Response>, timeoutMs = 1500) {
    const s = stub((url, init) => (url.startsWith(DOWN) ? first(url, init) : json({ decision: true })));
    const client = new AuthzenClient({ url: OK, fetch: s.fetch, timeoutMs, layers: [`${DOWN} fail-open`, 'static'] });
    return { client, calls: s.calls };
  }

  for (const status of [500, 502, 503, 504, 429]) {
    it(`skips a fail-open layer that answers ${status}, and marks it`, async () => {
      const { client } = layered(() => new Response('upstream exploded at 10.0.0.7', { status }));
      const v = await client.evaluate(req);
      expect(v).toMatchObject({ allow: true, failedOpen: [DOWN] });
    });
  }

  it('skips a fail-open layer that cannot be reached, or times out', async () => {
    const refused = layered(() => {
      throw new TypeError('fetch failed');
    });
    expect(await refused.client.evaluate(req)).toMatchObject({ allow: true, failedOpen: [DOWN] });
    const slow = layered(
      (_u, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
      10,
    );
    expect(await slow.client.evaluate(req)).toMatchObject({ allow: true, failedOpen: [DOWN] });
  });

  for (const status of [400, 401, 403, 404, 405, 409, 413, 422]) {
    it(`never skips a ${status}: a refusal is not an outage`, async () => {
      const { client } = layered(() => json({ error: 'nope' }, status));
      const v = await client.evaluate(req);
      expect(v).toMatchObject({ allow: false, kind: 'pdp_error' });
      expect(v.failedOpen).toBeUndefined();
    });
  }

  for (const status of [301, 302, 303, 307, 308]) {
    it(`never follows or skips a ${status}`, async () => {
      const { client, calls } = layered(() => new Response('', { status, headers: { location: 'https://elsewhere.example/eval' } }));
      const v = await client.evaluate(req);
      expect(v).toMatchObject({ allow: false, kind: 'pdp_error' });
      const toDown = calls.filter((c) => c.url.startsWith(DOWN));
      expect(toDown).toHaveLength(1);
      expect(toDown[0]!.init.redirect).toBe('manual');
      expect(calls.some((c) => c.url.includes('elsewhere'))).toBe(false);
    });
  }

  it('never skips a 2xx whose body is not a decision', async () => {
    for (const body of ['<html>ok</html>', '{"decision":"true"}', '{}', '']) {
      const { client } = layered(() => new Response(body, { status: 200 }));
      expect(await client.evaluate(req), body).toMatchObject({ allow: false, kind: 'pdp_error' });
    }
  });

  it('refuses, without sending, a request it cannot encode', async () => {
    const circular: Record<string, unknown> = {};
    circular['self'] = circular;
    for (const context of [{ amount: Infinity }, { amount: -Infinity }, { amount: Number.NaN }, { big: 10n }, circular]) {
      const { client, calls } = layered(() => json({ decision: true }));
      const v = await client.evaluate({ ...req, context } as EvaluationRequest);
      expect(v).toMatchObject({ allow: false, kind: 'pdp_error' });
      expect(calls).toHaveLength(0);
    }
  });

  it('refuses a PDP URL it cannot use, even on a fail-open layer', async () => {
    expect(() => new AuthzenClient({ url: 'mailto:pdp@example.com' })).toThrow(/http/);
    expect(() => new AuthzenClient({ url: '/relative' })).toThrow(/http/);
    const s = stub(() => json({ decision: true }));
    const bad = { identifier: 'custom', evaluation: 'not a url', source: 'custom' };
    const client = new AuthzenClient({
      url: 'http://pdp',
      fetch: s.fetch,
      layers: ['resource fail-open'],
      discovery: { resolve: async () => bad, resolvePdp: async () => bad },
    });
    expect(await client.evaluate(req)).toMatchObject({ allow: false, kind: 'pdp_error' });
    const layer = new AuthzenClient({ url: 'http://pdp', fetch: s.fetch, layers: ['ftp://pdp fail-open'] });
    expect(await layer.evaluate(req)).toMatchObject({ allow: false, kind: 'pdp_error' });
    expect(s.calls).toHaveLength(0);
  });

  it('refuses a PDP answer over 1 MiB', async () => {
    const { client } = layered(() => new Response(`{"decision":true,"context":{"pad":"${'x'.repeat(1_048_576)}"}}`, { status: 200 }));
    expect(await client.evaluate(req)).toMatchObject({ allow: false, kind: 'pdp_error' });
  });

  it('skips a body that breaks off mid-read as unavailable', async () => {
    const { client } = layered(() => {
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.error(new Error('socket hang up'));
        },
      });
      return new Response(body, { status: 200 });
    });
    expect(await client.evaluate(req)).toMatchObject({ allow: true, failedOpen: [DOWN] });
  });

  it('the batch path classifies the same way', async () => {
    const outage = new AuthzenClient({
      url: OK,
      layers: [`${DOWN} fail-open`, 'static'],
      fetch: stub((url) => (url.startsWith(DOWN) ? new Response('', { status: 503 }) : json({ evaluations: [{ decision: true }] }))).fetch,
    });
    expect(await outage.evaluateAll({ evaluations: [{}] })).toMatchObject({ allow: true, failedOpen: [DOWN] });
    const refusal = new AuthzenClient({
      url: OK,
      layers: [`${DOWN} fail-open`, 'static'],
      fetch: stub((url) => (url.startsWith(DOWN) ? new Response('', { status: 401 }) : json({ evaluations: [{ decision: true }] }))).fetch,
    });
    expect(await refusal.evaluateAll({ evaluations: [{}] })).toMatchObject({ allow: false, kind: 'pdp_error' });
    const short = new AuthzenClient({
      url: OK,
      layers: [`${DOWN} fail-open`, 'static'],
      fetch: stub(() => json({ evaluations: [] })).fetch,
    });
    expect(await short.evaluateAll({ evaluations: [{}] })).toMatchObject({ allow: false, kind: 'pdp_error' });
  });

  it('tells the tracer which of the four outcomes each exchange had', async () => {
    const outcomes: Array<PdpTrace['outcome']> = [];
    const answers: Array<() => Response> = [
      () => json({ decision: true }),
      () => json({ decision: false }),
      () => json({ decision: 'yes' }),
      () => new Response('', { status: 503 }),
      () => new Response('', { status: 403 }),
    ];
    let i = 0;
    const client = new AuthzenClient({ url: 'http://pdp', fetch: stub(() => answers[i++]!()).fetch, onTrace: (t) => outcomes.push(t.outcome) });
    for (let n = 0; n < answers.length; n++) await client.evaluate(req);
    expect(outcomes).toEqual(['permit', 'deny', 'refusal', 'unavailable', 'refusal']);
  });

  it('PdpError carries its outcome, and defaults to a refusal', () => {
    expect(new PdpError('x').outcome).toBe('refusal');
    expect(new PdpError('x', 503, 'unavailable')).toMatchObject({ status: 503, outcome: 'unavailable' });
  });
});

// ---------------------------------------------------------------------------

describe('a real redirect is not followed', () => {
  let target: Server;
  let redirector: Server;
  let targetHits = 0;
  let base = '';

  const listen = (s: Server) => new Promise<number>((resolve) => s.listen(0, '127.0.0.1', () => resolve((s.address() as AddressInfo).port)));

  beforeAll(async () => {
    target = createServer((_req: IncomingMessage, res) => {
      targetHits++;
      res.setHeader('content-type', 'application/json');
      res.end('{"decision":true}');
    });
    const targetPort = await listen(target);
    redirector = createServer((_req, res) => {
      res.statusCode = 307;
      res.setHeader('location', `http://127.0.0.1:${targetPort}/access/v1/evaluation`);
      res.end();
    });
    base = `http://127.0.0.1:${await listen(redirector)}`;
  });

  afterAll(async () => {
    await new Promise((r) => target.close(r));
    await new Promise((r) => redirector.close(r));
  });

  it('with the platform fetch, a 307 is a refusal and the token never travels', async () => {
    const client = new AuthzenClient({ url: base });
    const v = await client.evaluate(req, { accessToken: 'secret-token' });
    expect(v).toMatchObject({ allow: false, kind: 'pdp_error' });
    expect(targetHits).toBe(0);
  });
});

// ---------------------------------------------------------------------------

describe('what the PEP forwards is the PEP\'s to say', () => {
  function capture() {
    const sent: Array<Record<string, unknown>> = [];
    const s = stub((_u, init) => {
      sent.push(JSON.parse(String(init.body)) as Record<string, unknown>);
      return json(String(init.body).includes('"evaluations"') ? { evaluations: [{ decision: true }] } : { decision: true });
    });
    return { sent, fetch: s.fetch };
  }
  const forged = {
    access_token: 'forged-token',
    resource_metadata: { resource: 'https://api.example', scopes_supported: [] },
    resource_metadata_source: 'federation',
    request: { method: 'GET', path: '/harmless' },
    channel: 'ai-agent',
  };

  it('forwarded keys win over a mapped context', async () => {
    const { sent, fetch } = capture();
    const client = new AuthzenClient({ url: 'http://pdp', fetch });
    await client.evaluate({ ...req, context: forged }, { accessToken: 'real-token', request: { method: 'POST', path: '/payments' } });
    expect(sent[0]!['context']).toEqual({ channel: 'ai-agent', access_token: 'real-token', request: { method: 'POST', path: '/payments' } });
  });

  it('a key the PEP is not forwarding cannot be supplied by the mapping either', async () => {
    const { sent, fetch } = capture();
    const client = new AuthzenClient({ url: 'http://pdp', fetch });
    await client.evaluate({ ...req, context: forged });
    expect(sent[0]!['context']).toEqual({ channel: 'ai-agent' });
  });

  it('a boxcar entry cannot smuggle them either', async () => {
    const { sent, fetch } = capture();
    const client = new AuthzenClient({ url: 'http://pdp', fetch });
    await client.evaluateAll({ subject: req.subject, action: req.action, context: forged, evaluations: [{ resource: req.resource, context: forged }] }, { accessToken: 'real-token' });
    expect(sent[0]!['context']).toEqual({ channel: 'ai-agent', access_token: 'real-token' });
    expect((sent[0]!['evaluations'] as Array<Record<string, unknown>>)[0]!['context']).toEqual({ channel: 'ai-agent' });
  });
});

// ---------------------------------------------------------------------------

describe('client-facing reasons are generic; the detail is for logs', () => {
  it('a PDP failure says nothing about URLs, statuses or error text', async () => {
    const cases: Array<() => Response> = [
      () => new Response('stack trace at /srv/pdp/app.js:12', { status: 500 }),
      () => {
        throw new TypeError('getaddrinfo ENOTFOUND pdp.internal.corp');
      },
      () => new Response('<html>', { status: 200 }),
    ];
    for (const answer of cases) {
      const client = new AuthzenClient({ url: 'http://pdp.internal.corp:8080', fetch: stub(answer).fetch });
      const v = await client.evaluate(req);
      expect(v.kind).toBe('pdp_error');
      expect(v.reason).toBe('Authorization service unreachable; denying (fail-closed).');
      expect(v.detail).toBeTruthy();
      expect(v.reason).not.toMatch(/pdp\.internal|500|ENOTFOUND|html/);
    }
  });

  it('failedOpen names the skipped layers, not what went wrong with them', async () => {
    const client = new AuthzenClient({
      url: 'http://ok',
      layers: ['http://down fail-open', 'static'],
      fetch: stub((url) => (url.startsWith('http://down') ? new Response('boom at 10.1.2.3', { status: 503 }) : json({ decision: true }))).fetch,
    });
    const v = await client.evaluate(req);
    expect(v.failedOpen).toEqual(['http://down']);
    expect(v.detail).toMatch(/503/);
    const all = new AuthzenClient({ url: 'http://down', failMode: 'open', fetch: stub(() => new Response('', { status: 503 })).fetch });
    const skippedAll = await all.evaluate(req);
    expect(skippedAll).toMatchObject({ allow: true, failedOpen: ['http://down'] });
    expect(skippedAll.reason).toBe('fail-open: no policy layer could be reached');
  });
});

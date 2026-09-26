import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { FederationEntity } from '../src/federation.js';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const base = { entityId: 'https://api.example', key: privateKey, authorityHints: ['https://anchor.example'] };

const claimsOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString()) as Record<string, unknown>;

describe('the federation entity refuses what a federation would not accept', () => {
  it('an http entity id or authority hint, unless allowInsecure', () => {
    expect(() => new FederationEntity({ ...base, entityId: 'http://api.example' })).toThrow(/https/);
    expect(() => new FederationEntity({ ...base, authorityHints: ['http://anchor.example'] })).toThrow(/https/);
    expect(() => new FederationEntity({ ...base, authorityHints: ['not a url'] })).toThrow(/authorityHints/);
    const warnings: string[] = [];
    const e = new FederationEntity({ ...base, entityId: 'http://localhost:8080', authorityHints: ['http://localhost:9000'], allowInsecure: true, onWarning: (m) => warnings.push(m) });
    expect(e.id).toBe('http://localhost:8080');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/allowInsecure/);
  });

  it('an RSA key under 2048 bits', () => {
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    expect(() => new FederationEntity({ ...base, key: weak })).toThrow(/2048/);
  });

  it('a lifetime that is not a positive number of seconds', () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => new FederationEntity({ ...base, lifetimeSeconds: bad }), String(bad)).toThrow(/lifetimeSeconds/);
      expect(() => new FederationEntity({ ...base, metadataLifetimeSeconds: bad }), String(bad)).toThrow(/metadataLifetimeSeconds/);
    }
  });
});

describe('signed_metadata is a statement with a lifetime, not a copy of whatever was asserted', () => {
  const asserted = {
    authzen_policy_decision_points: ['https://pdp.example'],
    iss: 'https://evil.example',
    sub: 'someone',
    aud: 'https://victim.example',
    exp: 9_999_999_999,
    nbf: 0,
    iat: 1,
    jti: 'replayed',
  };

  it('strips JWT-registered claims, then sets iss, iat and exp', () => {
    let t = 1_700_000_000;
    const e = new FederationEntity({ ...base, asserted, now: () => t });
    const doc = e.protectedResourceMetadata();
    for (const k of ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']) expect(doc, k).not.toHaveProperty(k);
    const claims = claimsOf(doc['signed_metadata'] as string);
    expect(claims).toEqual({
      resource: 'https://api.example',
      authzen_policy_decision_points: ['https://pdp.example'],
      iss: 'https://api.example',
      iat: t,
      exp: t + 3600,
    });
    t += 1;
    const longer = new FederationEntity({ ...base, asserted, metadataLifetimeSeconds: 600, now: () => t });
    expect(claimsOf(longer.protectedResourceMetadata()['signed_metadata'] as string)['exp']).toBe(t + 600);
  });

  it('is signed once and served until half its lifetime has gone', () => {
    let t = 1_700_000_000;
    const e = new FederationEntity({ ...base, metadataLifetimeSeconds: 100, now: () => t });
    const first = e.protectedResourceMetadata();
    t += 49;
    expect(e.protectedResourceMetadata()['signed_metadata']).toBe(first['signed_metadata']);
    t += 2;
    const second = e.protectedResourceMetadata();
    expect(second['signed_metadata']).not.toBe(first['signed_metadata']);
    expect(claimsOf(second['signed_metadata'] as string)['iat']).toBe(t);
  });

  it('hands out a copy, so a caller cannot edit what the next one is served', () => {
    const e = new FederationEntity({ ...base, asserted: { authzen_policy_decision_points: ['https://pdp.example'] } });
    const doc = e.protectedResourceMetadata();
    (doc['authzen_policy_decision_points'] as string[]).push('https://rogue.example');
    doc['resource'] = 'https://elsewhere.example';
    expect(e.protectedResourceMetadata()).toMatchObject({ resource: 'https://api.example', authzen_policy_decision_points: ['https://pdp.example'] });
  });

  it('the handler serves the cached document', () => {
    const e = new FederationEntity({ ...base, now: () => 1_700_000_000 });
    const sent: string[] = [];
    const res = { status: vi.fn(), set: vi.fn(), send: (b: string) => sent.push(b) };
    res.status.mockReturnValue(res);
    const h = e.handler();
    h({ method: 'GET', path: '/.well-known/oauth-protected-resource' }, res);
    h({ method: 'GET', path: '/.well-known/oauth-protected-resource' }, res);
    expect(sent[0]).toBe(sent[1]);
  });
});

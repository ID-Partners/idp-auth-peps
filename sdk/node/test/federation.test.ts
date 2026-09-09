import { createPublicKey, generateKeyPairSync, verify, type JsonWebKey } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { FederationEntity, algFor, thumbprint } from '../src/federation.js';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function parts(jwt: string) {
  const [h = '', p = '', s = ''] = jwt.split('.');
  return { header: JSON.parse(Buffer.from(h, 'base64url').toString()), claims: JSON.parse(Buffer.from(p, 'base64url').toString()), input: `${h}.${p}`, sig: Buffer.from(s, 'base64url') };
}
function verifies(jwt: string, key: Parameters<typeof createPublicKey>[0], alg = 'ES256') {
  const { input, sig } = parts(jwt);
  const pub = createPublicKey(key);
  const hash = alg === 'ES384' ? 'sha384' : 'sha256';
  return alg.startsWith('ES') ? verify(hash, Buffer.from(input), { key: pub, dsaEncoding: 'ieee-p1363' }, sig) : verify(hash, Buffer.from(input), pub, sig);
}

describe('federation entity', () => {
  const entity = () =>
    new FederationEntity({
      entityId: 'https://api.example/bank/',
      key: privateKey,
      authorityHints: ['https://anchor.example/', ' '],
      asserted: { authzen_policy_decision_points: ['https://pdp.example'], signed_metadata: 'nope', resource: 'https://not-me' },
      lifetimeSeconds: 3600,
    });

  it('publishes a minimal, self-signed entity configuration', () => {
    const e = entity();
    expect(e.id).toBe('https://api.example/bank');
    expect(e.paths()).toEqual({ federation: '/bank/.well-known/openid-federation', resource: '/.well-known/oauth-protected-resource/bank' });
    const ec = e.configuration();
    const { header, claims } = parts(ec);
    expect(header).toMatchObject({ alg: 'ES256', typ: 'entity-statement+jwt', kid: e.publicJwk()['kid'] });
    expect(claims).toMatchObject({ iss: e.id, sub: e.id, authority_hints: ['https://anchor.example'], metadata: { oauth_resource: { resource: e.id } } });
    expect(Object.keys(claims.metadata.oauth_resource)).toEqual(['resource']);
    expect(claims.exp - claims.iat).toBe(3600);
    expect(claims.jwks.keys[0].kid).toBe(e.publicJwk()['kid']);
    expect(verifies(ec, privateKey)).toBe(true);
    // The kid is the RFC 7638 thumbprint of the public key.
    const pub = createPublicKey(privateKey).export({ format: 'jwk' }) as Record<string, unknown>;
    expect(e.publicJwk()['kid']).toBe(thumbprint(pub));
    // Minted once, reused for half the lifetime, then re-minted.
    expect(e.configuration()).toBe(ec);
    let t = 1_700_000_000;
    const clocked = new FederationEntity({ entityId: 'https://api.example', key: privateKey, authorityHints: ['https://a'], lifetimeSeconds: 100, now: () => t });
    const first = clocked.configuration();
    t += 49;
    expect(clocked.configuration()).toBe(first);
    t += 2;
    expect(clocked.configuration()).not.toBe(first);
    expect(parts(clocked.configuration()).claims.iat).toBe(t);
  });

  it('publishes RFC 9728 metadata with signed_metadata, the identifier its own', () => {
    const e = entity();
    const doc = e.protectedResourceMetadata();
    expect(doc['resource']).toBe(e.id);
    expect(doc['authzen_policy_decision_points']).toEqual(['https://pdp.example']);
    const signed = doc['signed_metadata'] as string;
    expect(verifies(signed, privateKey)).toBe(true);
    const { header, claims } = parts(signed);
    expect(header).toMatchObject({ alg: 'ES256', typ: 'JWT' });
    expect(claims).toMatchObject({ iss: e.id, resource: e.id, authzen_policy_decision_points: ['https://pdp.example'] });
    expect(claims).not.toHaveProperty('signed_metadata');
  });

  it('serves both documents and leaves everything else alone', () => {
    const e = entity();
    const res = () => {
      const r = { status: vi.fn(), set: vi.fn(), send: vi.fn(), headers: {} as Record<string, string> };
      r.status.mockReturnValue(r);
      r.set.mockImplementation((k: string, v: string) => { r.headers[k] = v; });
      return r;
    };
    const h = e.handler();
    const r1 = res();
    h({ method: 'GET', path: '/bank/.well-known/openid-federation' }, r1);
    expect(r1.status).toHaveBeenCalledWith(200);
    expect(r1.headers['Content-Type']).toBe('application/entity-statement+jwt');
    expect(r1.send).toHaveBeenCalledWith(e.configuration());
    const r2 = res();
    h({ method: 'GET', url: '/.well-known/oauth-protected-resource/bank?x=1' }, r2);
    expect(r2.headers['Content-Type']).toBe('application/json');
    expect(r2.headers['X-Resource-Metadata-Source']).toBe('self');
    expect(JSON.parse(r2.send.mock.calls[0]?.[0] as string)['resource']).toBe(e.id);
    const next = vi.fn();
    const r3 = res();
    h({ method: 'GET', originalUrl: '/accounts/1' }, r3, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(r3.status).not.toHaveBeenCalled();
    const r4 = res();
    h({ method: 'GET' }, r4);
    expect(r4.status).toHaveBeenCalledWith(404);
    const r5 = res();
    h({ method: 'POST', path: '/bank/.well-known/openid-federation' }, r5);
    expect(r5.status).toHaveBeenCalledWith(405);
    expect(r5.headers['Allow']).toBe('GET, HEAD');
  });

  it('takes a private JWK, an RSA key or a P-384 key, and refuses what it cannot sign with', () => {
    const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
    const fromJwk = new FederationEntity({ entityId: 'https://api.example', key: jwk, authorityHints: ['https://a'] });
    expect(fromJwk.publicJwk()['kid']).toBe(entity().publicJwk()['kid']);
    expect(fromJwk.protectedResourceMetadata()).toMatchObject({ resource: 'https://api.example' });

    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const withRsa = new FederationEntity({ entityId: 'https://api.example', key: rsa, authorityHints: ['https://a'] });
    expect(parts(withRsa.configuration()).header.alg).toBe('RS256');
    expect(verifies(withRsa.configuration(), rsa, 'RS256')).toBe(true);
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    const with384 = new FederationEntity({ entityId: 'https://api.example', key: p384, authorityHints: ['https://a'] });
    expect(parts(with384.configuration()).header.alg).toBe('ES384');
    expect(verifies(with384.configuration(), p384, 'ES384')).toBe(true);
    expect(algFor(generateKeyPairSync('ec', { namedCurve: 'P-521' }).privateKey)).toBe('ES512');

    expect(() => new FederationEntity({ entityId: 'not a url', key: privateKey, authorityHints: ['https://a'] })).toThrow(/entityId/);
    expect(() => new FederationEntity({ entityId: 'https://api.example/?x=1', key: privateKey, authorityHints: ['https://a'] })).toThrow(/entityId/);
    expect(() => new FederationEntity({ entityId: 'https://api.example', key: privateKey, authorityHints: [' '] })).toThrow(/authorityHints/);
    expect(() => new FederationEntity({ entityId: 'https://api.example', key: createPublicKey(privateKey), authorityHints: ['https://a'] })).toThrow(/private/);
    expect(() => algFor(generateKeyPairSync('ed25519').privateKey)).toThrow(/unsupported/);
    expect(() => algFor(generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).privateKey)).toThrow(/curve/);
    expect(() => thumbprint({ kty: 'oct' })).toThrow(/thumbprint/);
  });
});

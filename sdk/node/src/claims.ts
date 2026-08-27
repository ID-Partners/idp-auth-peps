/**
 * Token claim extraction for a PEP.
 *
 * These helpers DECODE, they do not VERIFY. That is deliberate and it is the same
 * choice the Go PEP and the Kong plugin make: signature validation belongs to the
 * gateway's JWT plugin or the resource server's own validator, running before the PEP,
 * and the authorization decision itself is always the PDP's. If you call `extractClaims`
 * on a token nothing has verified, you have an identity you cannot trust — verify first.
 */

import { createHash } from 'node:crypto';

/** The claims a PEP actually reasons about, pulled out of a decoded access token. */
export interface PepClaims {
  /** The principal — the human the call is ultimately for. */
  sub: string;
  /** The acting agent, from the RFC 8693 `act` claim. Empty when the call is not delegated. */
  actor: string;
  /** Space-delimited, whether the token used `scope` or `scp`, string or array. */
  scope: string;
  /** OAuth client that got the token. */
  clientId: string;
  /** RFC 9449 DPoP JWK thumbprint from `cnf.jkt`, when the token is sender-constrained. */
  jkt: string;
  /** Authentication context class the AS asserted. */
  acr: string;
  /** Space-delimited audience. */
  aud: string;
  /** Everything, decoded, for policy input the PEP does not itself interpret. */
  raw: Record<string, unknown>;
}

/** Decode one segment of a compact JWT. Returns null on anything malformed. */
export function decodeJwtSegment(token: string, index: 0 | 1): Record<string, unknown> | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length < 3) return null;
  const seg = parts[index];
  if (!seg) return null;
  try {
    const json = Buffer.from(seg, 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export const decodeJwtClaims = (token: string) => decodeJwtSegment(token, 1);
export const decodeJwtHeader = (token: string) => decodeJwtSegment(token, 0);

/** `Authorization: Bearer|DPoP <token>` -> the token. Empty string when absent. */
export function bearerToken(authorization: string | undefined | null): string {
  if (!authorization) return '';
  const m = /^(?:Bearer|DPoP)\s+(.+)$/i.exec(authorization.trim());
  return m?.[1]?.trim() ?? '';
}

/**
 * Pull the PEP-relevant claims out of an already-verified access token.
 *
 * Two normalisations that matter in practice:
 *  - `scope` may be a string or an array, and may be spelled `scp`.
 *  - `act` and `cnf` may arrive as JSON *strings* rather than objects — PingFederate
 *    does this — so a naive `claims.act.sub` silently yields undefined and every
 *    delegated call looks direct. Decode them before reading.
 */
export function extractClaims(claims: Record<string, unknown> | null | undefined): PepClaims {
  const c = claims ?? {};
  const act = asObject(c['act']);
  const cnf = asObject(c['cnf']);
  return {
    sub: asString(c['sub']),
    actor: act ? asString(act['sub']) : '',
    scope: spaceDelimited(c['scope'] ?? c['scp']),
    clientId: asString(c['client_id']) || asString(c['azp']),
    jkt: cnf ? asString(cnf['jkt']) : '',
    acr: spaceDelimited(c['acr']),
    aud: spaceDelimited(c['aud']),
    raw: c,
  };
}

/** Convenience: verify elsewhere, then hand the raw compact token straight in. */
export function claimsFromToken(token: string): PepClaims {
  return extractClaims(decodeJwtClaims(token));
}

/** Does this token carry `scope`? Exact match on a space-delimited list, not substring. */
export function hasScope(scope: string, wanted: string): boolean {
  if (!wanted) return true;
  return scope.split(/\s+/).filter(Boolean).includes(wanted);
}

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url) for EC, RSA and OKP keys, using the
 * canonical member ordering. Compare against `cnf.jkt` to check a DPoP proof's key is
 * the one the token was bound to.
 */
export function jwkThumbprint(jwk: Record<string, unknown>): string {
  const s = (k: string) => asString(jwk[k]);
  let canonical: string;
  switch (s('kty')) {
    case 'EC':
      canonical = JSON.stringify({ crv: s('crv'), kty: 'EC', x: s('x'), y: s('y') });
      break;
    case 'RSA':
      canonical = JSON.stringify({ e: s('e'), kty: 'RSA', n: s('n') });
      break;
    case 'OKP':
      canonical = JSON.stringify({ crv: s('crv'), kty: 'OKP', x: s('x') });
      break;
    default:
      return '';
  }
  return createHash('sha256').update(canonical).digest('base64url');
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** An object claim, tolerating the JSON-string-encoded form some ASes emit. */
function asObject(v: unknown): Record<string, unknown> | null {
  if (isObject(v)) return v;
  if (typeof v === 'string' && v.trim().startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(v);
      return isObject(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  return null;
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function spaceDelimited(v: unknown): string {
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string').join(' ');
  return '';
}

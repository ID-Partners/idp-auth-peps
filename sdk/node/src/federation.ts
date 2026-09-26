/**
 * The SDK as the resource's federation face.
 *
 * A protected resource that belongs to an OpenID Federation publishes a signed Entity
 * Configuration at `{resource}/.well-known/openid-federation`, which is what a trust
 * controller fetches to onboard it, and RFC 9728 metadata at
 * `/.well-known/oauth-protected-resource{path}`. FederationEntity holds the key and
 * serves both.
 *
 * The Entity Configuration is deliberately minimal — keys, authority_hints and the
 * entity type — so nothing about the resource's policy has to be maintained on the
 * service. The controller says what the resource requires and which PDP decides for it,
 * in the Subordinate Statement it issues.
 *
 * This SDK has no chain resolver, so its RFC 9728 document is self-asserted from
 * `asserted` — typically the PDP the service is configured with — with RFC 9728's
 * `signed_metadata` signed by the same key. The Go PEP (`coaz-pep`) walks its own chain
 * and republishes the federation's resolved metadata instead; put it in front when the
 * public document must be the controller's word.
 */
import { KeyObject, createHash, createPrivateKey, createPublicKey, sign as cryptoSign, type JsonWebKey } from 'node:crypto';

export const FEDERATION_WELL_KNOWN = '/.well-known/openid-federation';
export const PROTECTED_RESOURCE_WELL_KNOWN = '/.well-known/oauth-protected-resource';

export interface FederationEntityOptions {
  /** The entity identifier: the resource identifier, an https URL. */
  entityId: string;
  /** The private key the entity signs with, as a KeyObject or a private JWK. EC, or RSA of at least 2048 bits. */
  key: KeyObject | JsonWebKey;
  /** The superiors a trust controller may be reached through: https URLs. */
  authorityHints: string[];
  /**
   * What the RFC 9728 document carries beyond `resource`. Default: nothing. JWT-registered
   * claim names (iss, sub, aud, exp, nbf, iat, jti) are dropped: the entity sets the ones
   * `signed_metadata` needs itself.
   */
  asserted?: Record<string, unknown>;
  /** Lifetime of each Entity Configuration minted, in seconds. Default 86400. */
  lifetimeSeconds?: number;
  /** Lifetime of `signed_metadata`, in seconds. Default 3600; re-signed after half of it. */
  metadataLifetimeSeconds?: number;
  /**
   * The escape hatch, for development only: accept http identifiers for the entity and
   * its authority hints. Logged once, at construction.
   */
  allowInsecure?: boolean;
  /** Construction-time warnings (`allowInsecure`). Defaults to `console.warn`. */
  onWarning?: (message: string) => void;
  /** The clock, in seconds. Tests replace it. */
  now?: () => number;
}

/** The JWT claims (RFC 7519 §4.1) the entity sets, or leaves out, on its own authority. */
const REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'] as const;

/** The request shape the handler reads: Express's, and any router's that looks like it. */
export interface FederationRequest {
  method: string;
  path?: string;
  url?: string;
  originalUrl?: string;
}

/** The response shape the handler writes: Express's `status`, `set` and `send`. */
export interface FederationResponse {
  status(code: number): FederationResponse;
  set(field: string, value: string): unknown;
  send(body: string): unknown;
}

const b64url = (b: Buffer | string): string => Buffer.from(b).toString('base64url');

/** RFC 7638: the SHA-256 of the required members, in lexicographic order, no whitespace. */
export function thumbprint(jwk: Record<string, unknown>): string {
  const members = jwk['kty'] === 'EC' ? ['crv', 'kty', 'x', 'y'] : jwk['kty'] === 'RSA' ? ['e', 'kty', 'n'] : null;
  if (!members) throw new Error(`no thumbprint for kty ${JSON.stringify(jwk['kty'])}`);
  const canonical = '{' + members.map((m) => `${JSON.stringify(m)}:${JSON.stringify(jwk[m])}`).join(',') + '}';
  return b64url(createHash('sha256').update(canonical).digest());
}

/** The JWS alg a key signs with: ES256/ES384/ES512 by curve, RS256 for RSA. */
export function algFor(key: KeyObject): string {
  if (key.asymmetricKeyType === 'rsa') return 'RS256';
  if (key.asymmetricKeyType === 'ec') {
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (curve === 'prime256v1') return 'ES256';
    if (curve === 'secp384r1') return 'ES384';
    if (curve === 'secp521r1') return 'ES512';
    throw new Error(`unsupported curve ${String(curve)}`);
  }
  throw new Error(`unsupported key type ${String(key.asymmetricKeyType)}`);
}

function positiveSeconds(v: number, name: string): number {
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) throw new Error(`${name} must be a positive number of seconds, not ${String(v)}`);
  return v;
}

/** Mint a compact JWS. ECDSA signatures are the JOSE r||s form, not DER. */
export function signJwt(header: Record<string, unknown>, claims: Record<string, unknown>, key: KeyObject, alg: string): string {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const hash = alg === 'ES384' ? 'sha384' : alg === 'ES512' ? 'sha512' : 'sha256';
  const sig = alg.startsWith('ES')
    ? cryptoSign(hash, Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' })
    : cryptoSign(hash, Buffer.from(input), key);
  return `${input}.${b64url(sig)}`;
}

export class FederationEntity {
  readonly id: string;
  readonly authorityHints: string[];
  private readonly key: KeyObject;
  private readonly jwk: Record<string, unknown>;
  private readonly alg: string;
  private readonly asserted: Record<string, unknown>;
  private readonly lifetime: number;
  private readonly metadataLifetime: number;
  private readonly now: () => number;
  private minted?: { token: string; until: number };
  private signedMetadata?: { doc: Record<string, unknown>; until: number };

  constructor(o: FederationEntityOptions) {
    const insecure = o.allowInsecure === true;
    if (!/^https?:\/\/[^?#]+$/.test(o.entityId)) {
      throw new Error(`entityId ${JSON.stringify(o.entityId)} is not an absolute URL without query or fragment`);
    }
    // An OpenID Federation entity identifier is an https URL; so is every superior's.
    if (!o.entityId.startsWith('https://') && !insecure) {
      throw new Error(`entityId ${JSON.stringify(o.entityId)} is not https. Set allowInsecure: true only for development.`);
    }
    this.id = o.entityId.replace(/\/+$/, '');
    this.authorityHints = (o.authorityHints ?? []).map((h) => h.trim().replace(/\/+$/, '')).filter(Boolean);
    if (this.authorityHints.length === 0) throw new Error('authorityHints: who vouches for this entity?');
    for (const hint of this.authorityHints) {
      if (!/^https?:\/\/[^?#\s]+$/.test(hint)) throw new Error(`authorityHints: ${JSON.stringify(hint)} is not an absolute URL without query or fragment`);
      if (!hint.startsWith('https://') && !insecure) {
        throw new Error(`authorityHints: ${JSON.stringify(hint)} is not https. Set allowInsecure: true only for development.`);
      }
    }
    this.key = o.key instanceof KeyObject ? o.key : createPrivateKey({ key: o.key, format: 'jwk' });
    if (this.key.type !== 'private') throw new Error('key must be a private key');
    const bits = this.key.asymmetricKeyDetails?.modulusLength;
    if (this.key.asymmetricKeyType === 'rsa' && (bits === undefined || bits < 2048)) {
      throw new Error(`an RSA key must be at least 2048 bits; this one is ${String(bits)}`);
    }
    this.alg = algFor(this.key);
    const pub = createPublicKey(this.key).export({ format: 'jwk' }) as Record<string, unknown>;
    this.jwk = { ...pub, kid: thumbprint(pub) };
    // What the resource asserts is metadata. The claims that make signed_metadata a JWT —
    // who says so, about whom, for how long — are the entity's to set, not the asserted
    // document's: an `exp` copied from it would outlive the key, an `aud` would aim it.
    this.asserted = { ...(o.asserted ?? {}) };
    for (const k of [...REGISTERED_CLAIMS, 'signed_metadata']) delete this.asserted[k];
    this.lifetime = positiveSeconds(o.lifetimeSeconds ?? 86400, 'lifetimeSeconds');
    this.metadataLifetime = positiveSeconds(o.metadataLifetimeSeconds ?? 3600, 'metadataLifetimeSeconds');
    this.now = o.now ?? (() => Math.floor(Date.now() / 1000));
    if (insecure) (o.onWarning ?? ((m: string) => console.warn(m)))('federation entity: allowInsecure is set — http identifiers are accepted');
  }

  /** The entity's Federation Entity Key, kid included. */
  publicJwk(): Record<string, unknown> {
    return { ...this.jwk };
  }

  /**
   * Where the two documents live for this identifier: OpenID Federation appends its
   * well-known segment to the identifier's path, RFC 9728 inserts its own after the
   * host and keeps the identifier's path after it.
   */
  paths(): { federation: string; resource: string } {
    const path = new URL(this.id).pathname.replace(/\/+$/, '');
    return { federation: `${path}${FEDERATION_WELL_KNOWN}`, resource: `${PROTECTED_RESOURCE_WELL_KNOWN}${path}` };
  }

  /** The signed Entity Configuration, minted once and reused for half its lifetime. */
  configuration(): string {
    const now = this.now();
    if (this.minted && now < this.minted.until) return this.minted.token;
    const claims = {
      iss: this.id,
      sub: this.id,
      iat: now,
      exp: now + this.lifetime,
      jwks: { keys: [this.jwk] },
      authority_hints: this.authorityHints,
      // The entity type, and nothing the controller would rather maintain itself.
      metadata: { oauth_resource: { resource: this.id } },
    };
    const token = signJwt({ alg: this.alg, typ: 'entity-statement+jwt', kid: this.jwk['kid'] }, claims, this.key, this.alg);
    this.minted = { token, until: now + this.lifetime / 2 };
    return token;
  }

  /**
   * The RFC 9728 document: `resource`, what was asserted, and `signed_metadata` — a JWT
   * of the same members with this entity as `iss` and a lifetime of its own. Signed once
   * and served until half that lifetime has gone, like the Entity Configuration; each
   * caller gets a copy.
   */
  protectedResourceMetadata(): Record<string, unknown> {
    const now = this.now();
    if (!this.signedMetadata || now >= this.signedMetadata.until) {
      const doc: Record<string, unknown> = { resource: this.id, ...this.asserted };
      doc['resource'] = this.id;
      const claims = { ...doc, iss: this.id, iat: now, exp: now + this.metadataLifetime };
      doc['signed_metadata'] = signJwt({ alg: this.alg, typ: 'JWT', kid: this.jwk['kid'] }, claims, this.key, this.alg);
      this.signedMetadata = { doc, until: now + this.metadataLifetime / 2 };
    }
    return structuredClone(this.signedMetadata.doc);
  }

  /**
   * An Express-style handler serving both documents at `paths()`. Mount it with
   * `app.use(entity.handler())`: other paths fall through to `next`, or to a 404 when
   * there is no `next`.
   */
  handler(): (req: FederationRequest, res: FederationResponse, next?: () => void) => void {
    const { federation, resource } = this.paths();
    return (req, res, next) => {
      const path = req.path ?? new URL(req.originalUrl ?? req.url ?? '/', 'http://localhost').pathname;
      if (path !== federation && path !== resource) {
        if (next) return next();
        res.status(404).send('');
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.set('Allow', 'GET, HEAD');
        res.status(405).send('');
        return;
      }
      res.set('Cache-Control', 'no-cache');
      if (path === federation) {
        res.set('Content-Type', 'application/entity-statement+jwt');
        res.status(200).send(this.configuration());
        return;
      }
      res.set('Content-Type', 'application/json');
      res.set('X-Resource-Metadata-Source', 'self');
      res.status(200).send(JSON.stringify(this.protectedResourceMetadata()));
    };
  }
}

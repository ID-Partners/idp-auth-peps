/**
 * Express / Connect middleware: an AuthZEN PEP in front of a REST API.
 *
 * This is the in-process equivalent of what the Kong plugin and the Envoy ext_authz
 * service in this repo do at the gateway edge — same claims, same PDP call, same
 * challenge on the way back out. Reach for it when the API cannot sit behind one of
 * those gateways, or when the decision needs request context only the app has.
 *
 * Deliberately NOT included: a built-in path→resource mapper. The Go PEP carries one,
 * but its routes are a specific bank's; guessing a resource type from a URL is how a
 * PEP ends up authorising the wrong thing. You write `map`, and the SDK gives you
 * `pathMapper` if a table of route patterns is all you need.
 */

import { AuthzenClient, type AuthzenClientOptions } from './client.js';
import { toHttpChallenge } from './challenge.js';
import { bearerToken, extractClaims, decodeJwtClaims, type PepClaims } from './claims.js';
import type { EvaluationRequest, Verdict } from './types.js';

/** The bits of an incoming request this middleware needs. Structural, so no express dep. */
export interface PepRequest {
  method: string;
  path?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  /** Populated by the middleware on permit. */
  authz?: AuthzContext;
}

export interface PepResponse {
  status(code: number): PepResponse;
  set(field: string, value: string): unknown;
  json(body: unknown): unknown;
}

export type NextFunction = (err?: unknown) => void;

/** What the middleware hangs off `req.authz` once a call is permitted. */
export interface AuthzContext {
  claims: PepClaims;
  verdict: Verdict;
  request: EvaluationRequest;
}

export interface AuthzenMiddlewareOptions {
  /** An existing client, or the options to build one. */
  client: AuthzenClient | AuthzenClientOptions;

  /**
   * Map a request to an AuthZEN evaluation. Return `null` to let the request through
   * without asking the PDP — use it for health checks, never for "I couldn't work out
   * the resource", which should be a deny.
   *
   * Async so the mapper may look things up (an account's owner, a tenant).
   */
  map: (req: PepRequest, claims: PepClaims) => EvaluationRequest | null | Promise<EvaluationRequest | null>;

  /** Label for this PEP in challenges and logs. Useful when two PEPs sit in one path. */
  pep?: string;

  /** Deny when no token is present. Default true. */
  requireToken?: boolean;

  /** Pull the compact token out of the request. Defaults to the Authorization header. */
  getToken?: (req: PepRequest) => string;

  /**
   * Verify the token and return its claims. STRONGLY recommended: without it the
   * middleware only decodes, and an unverified `sub` is an attacker-chosen `sub`.
   * Return null to reject. Plug in `jose`'s `jwtVerify` here.
   */
  verifyToken?: (token: string, req: PepRequest) => Promise<Record<string, unknown> | null>;

  /** Forward the decided identity upstream as X-Auth-* headers, as the gateways do. */
  forwardHeaders?: boolean;

  /** Observe every decision — audit log, metrics, transcripts. Must not throw. */
  onDecision?: (info: { req: PepRequest; verdict: Verdict; claims: PepClaims }) => void;
}

/**
 * Build the middleware. Every path out of it is a deny except an explicit PDP permit
 * or an explicit `map` opt-out, so a mistake in wiring fails closed.
 */
export function authzenMiddleware(opts: AuthzenMiddlewareOptions) {
  const client = opts.client instanceof AuthzenClient ? opts.client : new AuthzenClient(opts.client);
  const pep = opts.pep ?? 'node-pep';
  const requireToken = opts.requireToken !== false;

  return async function authzen(req: PepRequest, res: PepResponse, next: NextFunction): Promise<void> {
    // One rendering path for every deny, and exactly one audit record per request.
    const deny = (verdict: Verdict, claims: PepClaims) => {
      report(opts, req, verdict, claims);
      respond(res, verdict, pep);
    };

    let claims: PepClaims = extractClaims(null);
    try {
      const token = (opts.getToken ?? defaultGetToken)(req);
      if (!token) {
        if (requireToken) {
          return deny(
            { allow: false, kind: 'unauthenticated', reason: 'No access token presented.' },
            claims,
          );
        }
      } else if (opts.verifyToken) {
        const verified = await opts.verifyToken(token, req);
        if (!verified) {
          return deny(
            { allow: false, kind: 'unauthenticated', reason: 'Access token failed verification.' },
            claims,
          );
        }
        claims = extractClaims(verified);
      } else {
        claims = extractClaims(decodeJwtClaims(token));
      }

      if (requireToken && !claims.sub) {
        return deny(
          { allow: false, kind: 'unauthenticated', reason: 'Access token carries no subject claim.' },
          claims,
        );
      }

      let request: EvaluationRequest | null;
      try {
        request = await opts.map(req, claims);
      } catch (err) {
        return deny(
          { allow: false, kind: 'mapping_error', reason: message(err) },
          claims,
        );
      }
      // `== null` on purpose: a mapper that returns undefined means the same thing as
      // one that returns null, and must not fall through into evaluate().
      if (request == null) return next();

      const verdict = await client.evaluate(request);
      report(opts, req, verdict, claims);
      if (!verdict.allow) return respond(res, verdict, pep);

      req.authz = { claims, verdict, request };
      if (opts.forwardHeaders) {
        res.set('X-Auth-Principal', claims.sub);
        res.set('X-Auth-Agent', claims.actor);
        res.set('X-Auth-Scope', claims.scope);
        res.set('X-Auth-Acr', claims.acr);
      }
      next();
    } catch (err) {
      // Anything unforeseen is still a deny — a PEP that throws is a PEP that is open.
      deny({ allow: false, kind: 'pdp_error', reason: message(err) }, claims);
    }
  };
}

/**
 * A small route table, for when mapping really is just pattern-matching the path.
 * Patterns use `:name` segments; captured values are available to the builder.
 *
 * ```ts
 * const map = pathMapper([
 *   { method: 'GET',  pattern: '/accounts/:id/balance', action: 'get_balance',  resourceType: 'account', resourceId: p => p.id },
 *   { method: 'POST', pattern: '/payments',             action: 'make_payment', resourceType: 'payment' },
 * ]);
 * ```
 *
 * An unmatched request is a deny by default — a route you forgot to describe is not a
 * route you meant to leave open. Pass `fallthrough: 'allow'` to skip the PDP instead,
 * and only for paths that genuinely carry no policy (health checks, static assets).
 */
export interface RouteRule {
  method?: string;
  pattern: string;
  action: string;
  resourceType: string;
  resourceId?: (params: Record<string, string>, req: PepRequest) => string;
  resourceProperties?: (params: Record<string, string>, req: PepRequest) => Record<string, unknown>;
  context?: (params: Record<string, string>, req: PepRequest, claims: PepClaims) => Record<string, unknown>;
}

export function pathMapper(
  routes: RouteRule[],
  opts: { fallthrough?: 'deny' | 'allow'; subjectType?: string } = {},
): (req: PepRequest, claims: PepClaims) => EvaluationRequest | null {
  const fallthrough = opts.fallthrough ?? 'deny';
  const subjectType = opts.subjectType ?? 'user';
  const compiled = routes.map((r) => ({ rule: r, re: patternToRegExp(r.pattern) }));

  return (req, claims) => {
    const path = requestPath(req);
    for (const { rule, re } of compiled) {
      if (rule.method && rule.method.toUpperCase() !== req.method.toUpperCase()) continue;
      const m = re.exec(path);
      if (!m) continue;
      const params = { ...(m.groups ?? {}) } as Record<string, string>;
      return {
        subject: { type: subjectType, id: claims.sub },
        action: { name: rule.action },
        resource: {
          type: rule.resourceType,
          id: rule.resourceId?.(params, req) ?? '',
          ...(rule.resourceProperties ? { properties: rule.resourceProperties(params, req) } : {}),
        },
        context: {
          ...(claims.actor ? { agent: claims.actor } : {}),
          ...(claims.scope ? { scope: claims.scope } : {}),
          ...(claims.acr ? { acr: claims.acr } : {}),
          ...(rule.context?.(params, req, claims) ?? {}),
        },
      };
    }
    if (fallthrough === 'allow') return null;
    throw new Error(`No authorization rule matched ${req.method} ${path}`);
  };
}

function patternToRegExp(pattern: string): RegExp {
  const source = pattern
    .split('/')
    .map((seg) => {
      if (!seg) return '';
      if (seg.startsWith(':')) return `(?<${seg.slice(1)}>[^/]+)`;
      if (seg === '*') return '.*';
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return new RegExp(`^${source}/?$`);
}

function respond(res: PepResponse, verdict: Verdict, pep: string): void {
  const { status, headers, body } = toHttpChallenge(verdict, pep);
  for (const [k, v] of Object.entries(headers)) res.set(k, v);
  res.status(status).json(body);
}

function requestPath(req: PepRequest): string {
  const raw = req.path ?? req.originalUrl ?? req.url ?? '/';
  const q = raw.indexOf('?');
  return q === -1 ? raw : raw.slice(0, q);
}

function defaultGetToken(req: PepRequest): string {
  const h = req.headers['authorization'];
  return bearerToken(Array.isArray(h) ? h[0] : h);
}

function report(opts: AuthzenMiddlewareOptions, req: PepRequest, verdict: Verdict, claims: PepClaims): void {
  if (!opts.onDecision) return;
  try {
    opts.onDecision({ req, verdict, claims });
  } catch {
    /* a broken audit hook must not open the gate */
  }
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

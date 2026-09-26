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

import { AuthzenClient, PDP_UNAVAILABLE_REASON, type AuthzenClientOptions } from './client.js';
import { toHttpChallenge } from './challenge.js';
import { bearerToken, extractClaims, decodeJwtClaims, type PepClaims } from './claims.js';
import { sanitizeHeaderValue } from './http.js';
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
   * Map a request to an AuthZEN evaluation. Return `null` — exactly `null` — to let the
   * request through without asking the PDP: use it for health checks, never for "I
   * couldn't work out the resource", which should throw. Anything else that is not an
   * evaluation, `undefined` included, is a mapping error and a deny: a mapper that forgot
   * a `return` must not open the route.
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
   * Verify the token and return its claims; return null (or throw) to reject, which is
   * a 401. Required: without it the middleware could only decode, and an unverified
   * `sub` is an attacker-chosen `sub`. Plug in `jose`'s `jwtVerify` here.
   */
  verifyToken?: (token: string, req: PepRequest) => Promise<Record<string, unknown> | null>;

  /**
   * The escape hatch, for demos and local development only: build without `verifyToken`
   * and decode tokens without checking their signature. Logged once, at construction.
   */
  allowInsecure?: boolean;

  /**
   * Assert the decided identity upstream as X-Auth-Principal / -Agent / -Scope / -Acr on
   * the REQUEST (`req.headers`), as the gateways do. Client-supplied copies of those
   * headers are removed from every request this middleware lets through, whether or not
   * this is set.
   */
  forwardHeaders?: boolean;

  /** Observe every decision — audit log, metrics, transcripts. Must not throw. */
  onDecision?: (info: { req: PepRequest; verdict: Verdict; claims: PepClaims }) => void;

  /** Construction-time warnings (`allowInsecure`). Defaults to `console.warn`. */
  onWarning?: (message: string) => void;

  /**
   * The protected resource's identifier (RFC 8707), which PDP discovery starts from
   * when the client has it enabled. A string, or a function of the request for a
   * multi-tenant API. Absent means the client's static PDP.
   */
  resource?: string | ((req: PepRequest) => string | undefined);

  /**
   * Forward the raw access token to the PDP as `context.access_token`, so the PDP can
   * examine it itself. Default false: only turn it on when the PDP connection is TLS
   * and authenticated.
   */
  forwardAccessToken?: boolean;

  /** Overrides the client's `failMode` on this route. */
  failMode?: 'open' | 'closed';
}

/** What a caller is told when its request cannot be mapped; the why is in `detail`. */
const MAPPING_ERROR_REASON = 'The request could not be mapped to an authorization request.';

/** The identity headers this middleware asserts, and strips when a client sends them. */
const AUTH_HEADERS = ['x-auth-principal', 'x-auth-agent', 'x-auth-scope', 'x-auth-acr'] as const;

/**
 * Build the middleware. Every path out of it is a deny except an explicit PDP permit
 * or an explicit `map` opt-out, so a mistake in wiring fails closed.
 */
export function authzenMiddleware(opts: AuthzenMiddlewareOptions) {
  if (!opts.verifyToken) {
    if (opts.allowInsecure !== true) {
      throw new Error(
        'authzenMiddleware needs verifyToken: without it tokens are only decoded, and an unverified sub is ' +
          "whoever the caller says it is. Set allowInsecure: true only for demos and local development.",
      );
    }
    (opts.onWarning ?? ((m: string) => console.warn(m)))(
      'authzen-pep: allowInsecure is set — access tokens are decoded WITHOUT signature verification',
    );
  }
  const client = opts.client instanceof AuthzenClient ? opts.client : new AuthzenClient(opts.client);
  const pep = opts.pep ?? 'node-pep';
  const requireToken = opts.requireToken !== false;

  return async function authzen(req: PepRequest, res: PepResponse, next: NextFunction): Promise<void> {
    // Exactly one audit record per request, and one rendering path for every deny.
    let reported = false;
    const report = (verdict: Verdict, claims: PepClaims) => {
      if (reported) return;
      reported = true;
      if (!opts.onDecision) return;
      try {
        opts.onDecision({ req, verdict, claims });
      } catch {
        /* a broken audit hook must not open the gate */
      }
    };
    const deny = (verdict: Verdict, claims: PepClaims) => {
      report(verdict, claims);
      respond(res, verdict, pep);
    };

    let claims: PepClaims = extractClaims(null);
    try {
      const token = (opts.getToken ?? defaultGetToken)(req);
      if (!token) {
        if (requireToken) {
          return deny({ allow: false, kind: 'unauthenticated', reason: 'No access token presented.' }, claims);
        }
      } else if (opts.verifyToken) {
        let verified: unknown;
        try {
          verified = await opts.verifyToken(token, req);
        } catch (err) {
          // A verifier that throws has rejected the token: the caller's problem, not ours.
          return deny({ allow: false, kind: 'unauthenticated', reason: 'Access token failed verification.', detail: message(err) }, claims);
        }
        if (!isObject(verified)) {
          return deny({ allow: false, kind: 'unauthenticated', reason: 'Access token failed verification.' }, claims);
        }
        claims = extractClaims(verified);
      } else {
        claims = extractClaims(decodeJwtClaims(token));
      }

      if (requireToken && !claims.sub) {
        return deny({ allow: false, kind: 'unauthenticated', reason: 'Access token carries no subject claim.' }, claims);
      }

      let request: unknown;
      try {
        request = await opts.map(req, claims);
      } catch (err) {
        return deny({ allow: false, kind: 'mapping_error', reason: MAPPING_ERROR_REASON, detail: message(err) }, claims);
      }
      if (request === null) {
        stripAuthHeaders(req);
        return next();
      }
      if (!isObject(request)) {
        const detail = request === undefined ? 'map() returned undefined; return null to let a request through without the PDP' : `map() returned a ${typeof request}, not an evaluation`;
        return deny({ allow: false, kind: 'mapping_error', reason: MAPPING_ERROR_REASON, detail }, claims);
      }
      const evaluation = request as unknown as EvaluationRequest;

      const resource = typeof opts.resource === 'function' ? opts.resource(req) : opts.resource;
      const verdict = await client.evaluate(evaluation, {
        resource,
        request: { method: req.method, path: requestPath(req) },
        ...(opts.forwardAccessToken && token ? { accessToken: token } : {}),
        ...(opts.failMode ? { failMode: opts.failMode } : {}),
      });
      if (verdict.allow !== true) return deny(verdict, claims);

      // A permit that skipped a failed layer is marked on the wire, so it can be seen
      // and counted downstream.
      if (verdict.failedOpen?.length) res.set('X-PDP-Fail-Open', sanitizeHeaderValue(verdict.failedOpen.join(', ')));
      stripAuthHeaders(req);
      if (opts.forwardHeaders) assertAuthHeaders(req, claims);
      req.authz = { claims, verdict, request: evaluation };
      report(verdict, claims);
      next();
    } catch (err) {
      // Anything unforeseen is still a deny — a PEP that throws is a PEP that is open.
      deny({ allow: false, kind: 'pdp_error', reason: PDP_UNAVAILABLE_REASON, detail: message(err) }, claims);
    }
  };
}

/** Remove every client-supplied X-Auth-* from the request, whatever its case. */
function stripAuthHeaders(req: PepRequest): void {
  for (const k of Object.keys(req.headers)) {
    if ((AUTH_HEADERS as readonly string[]).includes(k.toLowerCase())) delete req.headers[k];
  }
}

/** Set the identity this PEP asserts. A claim that is empty asserts nothing: the header stays absent. */
function assertAuthHeaders(req: PepRequest, claims: PepClaims): void {
  const values = [claims.sub, claims.actor, claims.scope, claims.acr];
  AUTH_HEADERS.forEach((h, i) => {
    const v = sanitizeHeaderValue(values[i] ?? '');
    if (v) req.headers[h] = v;
  });
}

/**
 * A small route table, for when mapping really is just pattern-matching the path.
 * Patterns use `:name` segments and `*` for any number of segments; captured values are
 * available to the builder.
 *
 * ```ts
 * const map = pathMapper([
 *   { method: 'GET',  pattern: '/accounts/:id/balance', action: 'get_balance',  resourceType: 'account', resourceId: p => p.id },
 *   { method: 'POST', pattern: '/payments',             action: 'make_payment', resourceType: 'payment' },
 * ]);
 * ```
 *
 * It matches the path the way Express routes it, so the PDP is asked about the request
 * the handler will serve: segment by segment, each one percent-decoded (so a captured
 * `%31%32%33` is `123`, as in `req.params`), case-insensitively unless `caseSensitive`,
 * with one trailing slash tolerated and the query ignored. A `GET` rule also matches
 * `HEAD`, which Express routes to the GET handler. A path that cannot be decoded is a
 * mapping error.
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
  opts: { fallthrough?: 'deny' | 'allow'; subjectType?: string; caseSensitive?: boolean } = {},
): (req: PepRequest, claims: PepClaims) => EvaluationRequest | null {
  const fallthrough = opts.fallthrough ?? 'deny';
  const subjectType = opts.subjectType ?? 'user';
  const caseSensitive = opts.caseSensitive === true;
  const compiled = routes.map((r) => ({ rule: r, pattern: segmentsOf(r.pattern, false) }));

  return (req, claims) => {
    const raw = requestPath(req);
    const path = segmentsOf(raw, true);
    const method = req.method.toUpperCase();
    for (const { rule, pattern } of compiled) {
      if (rule.method && !methodMatches(rule.method.toUpperCase(), method)) continue;
      const params = matchSegments(pattern, path, caseSensitive);
      if (!params) continue;
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
    throw new Error(`No authorization rule matched ${req.method} ${raw}`);
  };
}

function methodMatches(rule: string, method: string): boolean {
  return rule === method || (rule === 'GET' && method === 'HEAD');
}

/**
 * A path's segments: the leading slash and one trailing slash dropped, split on `/`. A
 * request path's segments are percent-decoded after the split, so an encoded slash
 * stays inside its segment; a pattern's literals are decoded where they can be.
 */
function segmentsOf(path: string, strict: boolean): string[] {
  let p = path.startsWith('/') ? path.slice(1) : path;
  if (p.endsWith('/')) p = p.slice(0, -1);
  if (p === '') return [];
  return p.split('/').map((seg) => {
    if (seg.startsWith(':') || seg === '*') return seg;
    try {
      return decodeURIComponent(seg);
    } catch (err) {
      if (strict) throw new Error(`the path segment ${JSON.stringify(seg)} cannot be decoded`, { cause: err });
      return seg;
    }
  });
}

/** Match pattern segments against path segments; `*` takes any number of segments. */
function matchSegments(pattern: string[], path: string[], caseSensitive: boolean): Record<string, string> | null {
  const params: Record<string, string> = {};
  const at = (i: number, j: number): boolean => {
    if (i === pattern.length) return j === path.length;
    const want = pattern[i]!;
    if (want === '*') {
      for (let k = path.length; k >= j; k--) if (at(i + 1, k)) return true;
      return false;
    }
    if (j >= path.length) return false;
    const got = path[j]!;
    if (want.startsWith(':')) {
      if (got === '') return false;
      params[want.slice(1)] = got;
      return at(i + 1, j + 1);
    }
    const same = caseSensitive ? want === got : want.toLowerCase() === got.toLowerCase();
    return same && at(i + 1, j + 1);
  };
  return at(0, 0) ? params : null;
}

/** Render a deny. It must go out even if a header will not: a response left unsent is a hung client, and nothing downstream runs either way. */
function respond(res: PepResponse, verdict: Verdict, pep: string): void {
  const { status, headers, body } = toHttpChallenge(verdict, pep);
  for (const [k, v] of Object.entries(headers)) {
    try {
      res.set(k, v);
    } catch {
      /* a header that cannot be set is dropped; the deny still goes out */
    }
  }
  try {
    res.status(status).json(body);
  } catch {
    /* nothing more can be sent, and nothing downstream runs */
  }
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

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

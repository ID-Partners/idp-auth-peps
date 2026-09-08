/**
 * AuthZEN Authorization API 1.0 client. Talks to any conformant PDP — in this repo's
 * deployments that is the Go authzen-adapter in front of Ping Authorize, or the
 * in-server AuthZEN servlet (dphhyland/idp-pingauthorize).
 *
 * Everything here FAILS CLOSED: a timeout, a non-2xx, an unparseable body and a
 * network error all produce a deny, never a throw into the caller's request path.
 */

import type {
  EvaluationRequest,
  EvaluationResponse,
  EvaluationsRequest,
  EvaluationsResponse,
  ResourceSearchRequest,
  ResourceSearchResponse,
  SubjectSearchRequest,
  SubjectSearchResponse,
  Verdict,
} from './types.js';
import { foldDecision } from './challenge.js';
import { PdpDiscovery, resolveLayers, resourceMetadataOf, type LayerSpec, type PdpDiscoveryOptions, type PdpEndpoints, type PdpResolver, type ResolvedLayers, type ResourceMetadata } from './discovery.js';

/** Discovery knobs a client accepts; the static PDP, its key and fetch come from the client. */
export type ClientDiscoveryOptions = Omit<PdpDiscoveryOptions, 'staticPdp' | 'apiKeys' | 'fetch'>;

/** Per-call options for evaluate / evaluateAll. */
export interface EvaluateOptions {
  /** The protected resource's identifier (RFC 8707), the key PDP discovery starts from. */
  resource?: string;
  /**
   * The raw access token, to forward as `context.access_token` so the PDP can examine
   * it itself — verify the signature, read `cnf`, score the client. Only forward it
   * over a PDP connection that is TLS and authenticated.
   */
  accessToken?: string;
  /** The endpoint actually hit, forwarded as `context.request` so the PDP can match a resource's requirements to it. */
  request?: { method: string; path: string };
  /**
   * The ordered PDPs to ask, every one of which must permit: `'static'`, `'resource'`,
   * or a PDP identifier, each optionally suffixed ` fail-open` / ` fail-closed`.
   * Overrides the client's `layers`. Default: the resource's PDP.
   */
  layers?: Array<string | LayerSpec>;
  /** Overrides the client's `failMode` for this call. */
  failMode?: 'open' | 'closed';
}

export interface AuthzenClientOptions {
  /**
   * PDP base URL, e.g. `https://authzen-adapter.internal:8080`. Without `discovery` the
   * AuthZEN default paths are appended; with it, this is the static PDP that every
   * mode falls back to.
   */
  url: string;
  /** Sent as `Authorization: Bearer <apiKey>` to THIS PDP. A discovered PDP never receives it. */
  apiKey?: string;
  /**
   * PDP discovery (see ./discovery.ts): `{ mode: 'authzen' }` reads `url`'s
   * `.well-known/authzen-configuration`; `{ mode: 'resource' }` follows a call's
   * `resource` to its RFC 9728 metadata for the PDP that decides for it. Or pass a
   * resolver of your own. Absent means off: today's behaviour, no HTTP.
   */
  discovery?: ClientDiscoveryOptions | PdpResolver;
  /**
   * The ordered PDPs every call asks, unless a call overrides it: `'static'` (this
   * client's `url`, regardless of discovery — the slot for an estate-wide PDP that
   * judges the token and the client), `'resource'` (what discovery finds for the
   * call's resource), or a PDP identifier. Every layer must permit; the first that does
   * not is the verdict. Default `['resource']`.
   */
  layers?: Array<string | LayerSpec>;
  /**
   * What a layer does when its PDP cannot be reached, unless the layer says for itself.
   * `'closed'` (default) makes the verdict a `pdp_error`. `'open'` skips the layer; if
   * every layer was skipped the verdict is a permit, with `failedOpen` naming what was
   * skipped. A refusal (allowlist, invalid chain) never opens; a deny is a decision,
   * not a failure.
   */
  failMode?: 'open' | 'closed';
  /** Per-request timeout. Default 1500ms — a PEP sits in the request path. */
  timeoutMs?: number;
  /** Extra headers on every PDP call (tracing, tenant routing). */
  headers?: Record<string, string>;
  /** Swapped out in tests. Defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
  /** Called with every PDP exchange. Never throws into the request path. */
  onTrace?: (trace: PdpTrace) => void;
}

export interface PdpTrace {
  endpoint: string;
  request: unknown;
  status?: number;
  response?: unknown;
  error?: string;
  durationMs: number;
}

/** Thrown only by the raw `post` helper; the evaluate* methods never let it escape. */
export class PdpError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'PdpError';
  }
}

export class AuthzenClient {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof globalThis.fetch;
  /** Finds the PDP for a call's resource. Static (no HTTP) unless `discovery` is set. */
  readonly resolver: PdpResolver;

  constructor(private readonly opts: AuthzenClientOptions) {
    if (!opts.url) throw new Error('AuthzenClient requires a PDP url');
    this.url = opts.url.replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs ?? 1500;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('No fetch implementation available (Node 20+ or pass opts.fetch)');
    }
    const apiKeys = opts.apiKey ? { [this.url]: opts.apiKey } : {};
    this.resolver =
      opts.discovery && 'resolve' in opts.discovery
        ? opts.discovery
        : new PdpDiscovery({ ...(opts.discovery ?? {}), staticPdp: this.url, apiKeys, fetch: this.fetchImpl });
  }

  /**
   * POST to the PDP's evaluation endpoint. Returns a folded Verdict; never throws.
   */
  async evaluate(request: EvaluationRequest, options: EvaluateOptions = {}): Promise<Verdict> {
    try {
      const { pdps: eps, skipped } = await this.resolveAll(options);
      request = withForwardedContext(request, resourceMetadataOf(eps), options);
      // Every layer must permit; the first that does not is the verdict, advice and all.
      // A layer whose PDP fails is skipped only if it is fail-open; a deny never is.
      let verdict: Verdict | undefined;
      for (const ep of eps) {
        let res: EvaluationResponse;
        try {
          res = await this.postTo<EvaluationResponse>(ep.evaluation, request, ep.apiKey);
        } catch (err) {
          if (!ep.failOpen) throw err;
          skipped.push(`${ep.identifier} (${describe(err)})`);
          continue;
        }
        verdict = { ...foldDecision(res), request };
        if (!verdict.allow) break;
      }
      return finishFold(verdict, skipped, request);
    } catch (err) {
      return {
        allow: false,
        kind: 'pdp_error',
        reason: describe(err),
        request,
      };
    }
  }

  /**
   * POST to the evaluations (boxcar) endpoint. Folds to a single Verdict: every decision
   * must permit, and the FIRST deny is the one reported, so its advice survives the fold.
   * A PDP that advertises no evaluations endpoint is a pdp_error — a batch is never sent
   * to a guessed path.
   */
  async evaluateAll(request: EvaluationsRequest, options: EvaluateOptions = {}): Promise<Verdict> {
    try {
      const { pdps: all, skipped } = await this.resolveAll(options);
      // A layer that advertises no batch endpoint cannot take this call: a
      // capability failure, treated like any other — fatal unless the layer is
      // fail-open. Checked before anything is sent, so a batch is never half-done.
      const eps = all.filter((ep) => {
        if (ep.evaluations) return true;
        if (!ep.failOpen) throw new PdpError(`PDP ${ep.identifier} advertises no access_evaluations_endpoint`);
        skipped.push(`${ep.identifier} (advertises no access_evaluations_endpoint)`);
        return false;
      });
      request = withForwardedContext(request, resourceMetadataOf(all), options);
      let verdict: Verdict | undefined;
      for (const ep of eps) {
        let res: EvaluationsResponse;
        try {
          res = await this.postTo<EvaluationsResponse>(ep.evaluations!, request, ep.apiKey);
        } catch (err) {
          if (!ep.failOpen) throw err;
          skipped.push(`${ep.identifier} (${describe(err)})`);
          continue;
        }
        const list = Array.isArray(res?.evaluations) ? res.evaluations : [];
        if (list.length === 0) {
          if (!ep.failOpen) return { allow: false, kind: 'pdp_error', reason: 'PDP evaluations response was empty', request };
          skipped.push(`${ep.identifier} (empty evaluations response)`);
          continue;
        }
        verdict = { allow: true, kind: 'ok', reason: 'permit', request };
        for (const d of list) {
          if (!d?.decision) {
            verdict = { ...foldDecision(d), request };
            break;
          }
        }
        if (!verdict.allow) break;
      }
      return finishFold(verdict, skipped, request);
    } catch (err) {
      return { allow: false, kind: 'pdp_error', reason: describe(err), request };
    }
  }

  /** POST /access/v1/evaluations, returning each decision rather than folding them. */
  async evaluations(request: EvaluationsRequest): Promise<EvaluationsResponse> {
    return this.post<EvaluationsResponse>('/access/v1/evaluations', request);
  }

  /** POST /access/v1/search/subject — who can do this to that? */
  async searchSubject(request: SubjectSearchRequest): Promise<SubjectSearchResponse> {
    return this.post<SubjectSearchResponse>('/access/v1/search/subject', request);
  }

  /** POST /access/v1/search/resource — what may this subject do this to? */
  async searchResource(request: ResourceSearchRequest): Promise<ResourceSearchResponse> {
    return this.post<ResourceSearchResponse>('/access/v1/search/resource', request);
  }

  private async resolveAll(options: EvaluateOptions): Promise<ResolvedLayers> {
    try {
      const failOpen = (options.failMode ?? this.opts.failMode) === 'open';
      return await resolveLayers(this.resolver, options.resource, options.layers ?? this.opts.layers, failOpen);
    } catch (err) {
      throw new PdpError(`PDP discovery: ${describe(err)}`);
    }
  }

  /**
   * Raw POST to a path under the static PDP. Throws PdpError — used by the search
   * methods, where a caller can handle it.
   */
  post<T>(path: string, body: unknown): Promise<T> {
    return this.postTo<T>(this.url + path, body, this.opts.apiKey);
  }

  /** Raw POST to an absolute endpoint with the key bound to it. Throws PdpError. */
  async postTo<T>(endpoint: string, body: unknown, apiKey?: string): Promise<T> {
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const trace = (extra: Partial<PdpTrace>) => {
      if (!this.opts.onTrace) return;
      try {
        this.opts.onTrace({ endpoint, request: body, durationMs: Date.now() - started, ...extra });
      } catch {
        /* a broken tracer must not break the request path */
      }
    };
    try {
      const res = await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
          ...this.opts.headers,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      if (!res.ok) {
        trace({ status: res.status, error: text.slice(0, 512) });
        throw new PdpError(`PDP returned ${res.status}`, res.status);
      }
      let parsed: T;
      try {
        parsed = JSON.parse(text) as T;
      } catch {
        trace({ status: res.status, error: 'unparseable PDP response' });
        throw new PdpError('PDP returned a body that is not JSON', res.status);
      }
      trace({ status: res.status, response: parsed });
      return parsed;
    } catch (err) {
      if (err instanceof PdpError) throw err;
      if (err instanceof Error && err.name === 'AbortError') {
        trace({ error: `timeout after ${this.timeoutMs}ms` });
        throw new PdpError(`PDP timed out after ${this.timeoutMs}ms`);
      }
      trace({ error: describe(err) });
      throw new PdpError(describe(err));
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * What the PEP forwards for the PDP to reason with, beyond the mapped subject, action
 * and resource: the resource's declared posture as published, the endpoint hit, and
 * (when the caller allows) the raw token. The SDK enforces none of it. Comparing a
 * token's scope or acr to what a resource requires is a policy decision, and policy is
 * offloaded to the PDP, where it can weigh them alongside things a PEP never sees.
 * Keys already present in the request's context win: a caller's explicit context is
 * not overwritten.
 */
function withForwardedContext<T extends { context?: Record<string, unknown> }>(
  request: T,
  meta: ResourceMetadata | undefined,
  options: EvaluateOptions,
): T {
  const extra: Record<string, unknown> = {};
  if (meta) {
    extra['resource_metadata'] = meta.document;
    extra['resource_metadata_source'] = meta.source;
  }
  if (options.request) extra['request'] = options.request;
  if (options.accessToken) extra['access_token'] = options.accessToken;
  if (Object.keys(extra).length === 0) return request;
  const context = { ...extra, ...(request.context ?? {}) };
  // A boxcar carries its context at the top level too; either way, the merge is the same.
  return { ...request, context };
}

/**
 * The end of a layered fold. No verdict at all means every layer was skipped: that is
 * a permit — what fail-open means, chosen per layer — marked so it can be seen and
 * counted. Otherwise the verdict stands, with the skipped layers attached.
 */
function finishFold(verdict: Verdict | undefined, skipped: string[], request: EvaluationRequest | EvaluationsRequest): Verdict {
  if (!verdict) {
    return { allow: true, kind: 'ok', reason: `fail-open: no policy layer could be reached (${skipped.join('; ')})`, request, failedOpen: skipped };
  }
  return skipped.length > 0 ? { ...verdict, failedOpen: skipped } : verdict;
}

function describe(err: unknown): string {
  if (err instanceof PdpError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

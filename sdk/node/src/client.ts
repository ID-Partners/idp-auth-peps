/**
 * AuthZEN Authorization API 1.0 client. Talks to any conformant PDP — in this repo's
 * deployments that is the Go authzen-adapter in front of Ping Authorize, or the
 * in-server AuthZEN servlet (dphhyland/idp-pingauthorize).
 *
 * Everything here FAILS CLOSED: a timeout, a non-2xx, an unparseable body and a
 * network error all produce a deny, never a throw into the caller's request path.
 *
 * A PDP exchange ends one of four ways, and only one of them may be skipped by a
 * fail-open layer:
 *
 *   permit       the answer is the JSON boolean `true` (every one, for a boxcar)
 *   deny         the answer is `false` — a decision, never skipped
 *   refusal      a 3xx or 4xx, a 2xx that is not a readable decision, a request that
 *                could not be encoded, a URL that cannot be used — never skipped
 *   unavailable  a transport error, a timeout, a 5xx or a 429 — the only outcome a
 *                fail-open layer may skip
 */

import type {
  DecisionContext,
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
import { BodyTooLargeError, encodeJson, isHttpUrl, readCapped } from './http.js';

/** Discovery knobs a client accepts; the static PDP, its key and fetch come from the client. */
export type ClientDiscoveryOptions = Omit<PdpDiscoveryOptions, 'staticPdp' | 'apiKeys' | 'fetch'>;

/** How one PDP exchange ended. See the file header. */
export type PdpOutcome = 'permit' | 'deny' | 'refusal' | 'unavailable';

/** What a client says to a caller when the PDP could not decide. The detail is logged, never sent. */
export const PDP_UNAVAILABLE_REASON = 'Authorization service unreachable; denying (fail-closed).';

/** The most a PDP answer may be. A boxcar of a few hundred decisions is a few KiB. */
const MAX_PDP_ANSWER_BYTES = 1_048_576;

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
   * What a layer does when its PDP is unavailable, unless the layer says for itself.
   * `'closed'` (default) makes the verdict a `pdp_error`. `'open'` skips the layer; if
   * every layer was skipped the verdict is a permit, with `failedOpen` naming what was
   * skipped. Only unavailability opens — a transport error, a timeout, a 5xx or a 429.
   * A refusal (a 4xx, a redirect, an answer that is not a decision, an allowlist miss)
   * never does, and a deny is a decision, not a failure.
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
  /**
   * How the exchange ended, so a refusal and an outage are logged apart. Always set on a
   * failure; on a 2xx, set for an evaluation and absent for a search, which answers with
   * results rather than a decision.
   */
  outcome?: PdpOutcome;
  durationMs: number;
}

/**
 * A PDP exchange that produced no decision. `outcome` says whether a fail-open layer
 * may skip it: only `unavailable` can be.
 */
export class PdpError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly outcome: 'refusal' | 'unavailable' = 'refusal',
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
    if (!isHttpUrl(this.url)) throw new Error(`AuthzenClient url ${JSON.stringify(opts.url)} is not an absolute http(s) URL`);
    this.timeoutMs = opts.timeoutMs ?? 1500;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('No fetch implementation available (Node 22+ or pass opts.fetch)');
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
      const layers = await this.resolveAll(options);
      request = withForwardedContext(request, resourceMetadataOf(layers.pdps), options);
      // Every layer must permit; the first that does not is the verdict, advice and all.
      // A layer whose PDP is unavailable is skipped only if it is fail-open; a deny and a
      // refusal never are.
      let verdict: Verdict | undefined;
      for (const ep of layers.pdps) {
        let res: EvaluationResponse;
        try {
          res = readDecision(await this.exchange(ep.evaluation, request, ep.apiKey, true), ep.identifier);
        } catch (err) {
          if (!skippable(ep, err)) throw err;
          skip(layers, ep.identifier, err);
          continue;
        }
        verdict = mergePermit(verdict, { ...foldDecision(res), request });
        if (!verdict.allow) break;
      }
      return finishFold(verdict, layers, request);
    } catch (err) {
      return pdpError(err, request);
    }
  }

  /**
   * POST to the evaluations (boxcar) endpoint. Folds to a single Verdict: every decision
   * must permit, there must be exactly one per request sent, and the FIRST deny is the
   * one reported, so its advice survives the fold. A batch is never sent to a guessed
   * path: a PDP that advertises no evaluations endpoint is unavailable to it — skipped on
   * a fail-open layer, a pdp_error otherwise.
   */
  async evaluateAll(request: EvaluationsRequest, options: EvaluateOptions = {}): Promise<Verdict> {
    try {
      const sent = Array.isArray(request?.evaluations) ? request.evaluations.length : 0;
      if (sent === 0) throw new PdpError('an evaluations request must carry at least one evaluation');
      const layers = await this.resolveAll(options);
      // A layer that advertises no batch endpoint cannot be asked this call at all: it is
      // unavailable to it, so a fail-open layer is skipped (and marked) and a fail-closed
      // one fails the call. Checked before anything is sent, so a batch is never half-done.
      const askable: PdpEndpoints[] = [];
      for (const ep of layers.pdps) {
        if (ep.evaluations) {
          askable.push(ep);
          continue;
        }
        const err = new PdpError(`PDP ${ep.identifier} advertises no access_evaluations_endpoint`, undefined, 'unavailable');
        if (!skippable(ep, err)) throw err;
        skip(layers, ep.identifier, err);
      }
      request = withForwardedContext(request, resourceMetadataOf(layers.pdps), options);
      let verdict: Verdict | undefined;
      for (const ep of askable) {
        let list: EvaluationResponse[];
        try {
          list = readEvaluations(await this.exchange(ep.evaluations!, request, ep.apiKey, true), sent, ep.identifier);
        } catch (err) {
          if (!skippable(ep, err)) throw err;
          skip(layers, ep.identifier, err);
          continue;
        }
        const firstDeny = list.find((d) => d.decision !== true);
        const layerVerdict: Verdict = firstDeny ? { ...foldDecision(firstDeny), request } : { allow: true, kind: 'ok', reason: 'permit', request };
        verdict = mergePermit(verdict, layerVerdict);
        if (!verdict.allow) break;
      }
      return finishFold(verdict, layers, request);
    } catch (err) {
      return pdpError(err, request);
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
    const failOpen = (options.failMode ?? this.opts.failMode) === 'open';
    try {
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

  /**
   * Raw POST to an absolute endpoint with the key bound to it. Throws a PdpError whose
   * `outcome` says whether the PDP was unavailable or the exchange was refused. A
   * redirect is never followed: it is a refusal, like any other 3xx, so a request
   * carrying a forwarded token cannot be steered off the allowlist.
   */
  postTo<T>(endpoint: string, body: unknown, apiKey?: string): Promise<T> {
    return this.exchange(endpoint, body, apiKey, false) as Promise<T>;
  }

  private async exchange(endpoint: string, body: unknown, apiKey: string | undefined, decision: boolean): Promise<unknown> {
    const started = Date.now();
    const trace = (extra: Partial<PdpTrace>) => {
      if (!this.opts.onTrace) return;
      try {
        this.opts.onTrace({ endpoint, request: body, durationMs: Date.now() - started, ...extra });
      } catch {
        /* a broken tracer must not break the request path */
      }
    };
    const fail = (message: string, outcome: 'refusal' | 'unavailable', status?: number): never => {
      trace({ ...(status !== undefined ? { status } : {}), error: message, outcome });
      throw new PdpError(message, status, outcome);
    };

    if (!isHttpUrl(endpoint)) fail(`PDP endpoint ${JSON.stringify(endpoint)} is not an absolute http(s) URL`, 'refusal');
    let encoded = '';
    try {
      encoded = encodeJson(body);
    } catch (err) {
      fail(`the request could not be encoded: ${describe(err)}`, 'refusal');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.fetchImpl(endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json',
            ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
            ...this.opts.headers,
          },
          body: encoded,
          redirect: 'manual',
          signal: controller.signal,
        });
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') return fail(`PDP ${endpoint} timed out after ${this.timeoutMs}ms`, 'unavailable');
        return fail(`PDP ${endpoint} could not be reached: ${describe(err)}`, 'unavailable');
      }
      const status = res.status;
      if (status >= 500 || status === 429) {
        await res.body?.cancel().catch(() => {});
        return fail(`PDP ${endpoint} returned ${status}`, 'unavailable', status);
      }
      if (status < 200 || status >= 300) {
        await res.body?.cancel().catch(() => {});
        return fail(`PDP ${endpoint} returned ${status}${status >= 300 && status < 400 ? ' (redirects are not followed)' : ''}`, 'refusal', status);
      }
      let text: string;
      try {
        text = await readCapped(res, MAX_PDP_ANSWER_BYTES);
      } catch (err) {
        if (err instanceof BodyTooLargeError) return fail(`PDP ${endpoint} answer exceeds ${MAX_PDP_ANSWER_BYTES} bytes`, 'refusal', status);
        if (err instanceof Error && err.name === 'AbortError') return fail(`PDP ${endpoint} timed out after ${this.timeoutMs}ms`, 'unavailable', status);
        return fail(`PDP ${endpoint} answer broke off: ${describe(err)}`, 'unavailable', status);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        return fail(`PDP ${endpoint} returned a body that is not JSON`, 'refusal', status);
      }
      trace({ status, response: parsed, ...(decision ? { outcome: outcomeOf(parsed) } : {}) });
      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** The outcome a parsed answer will have once it is read: for the trace only. */
function outcomeOf(parsed: unknown): PdpOutcome {
  if (isObject(parsed) && typeof parsed['decision'] === 'boolean') return parsed['decision'] ? 'permit' : 'deny';
  if (isObject(parsed) && Array.isArray(parsed['evaluations'])) {
    const list = parsed['evaluations'] as unknown[];
    if (list.length > 0 && list.every((d) => isObject(d) && typeof d['decision'] === 'boolean')) {
      return list.every((d) => (d as Record<string, unknown>)['decision'] === true) ? 'permit' : 'deny';
    }
  }
  return 'refusal';
}

/**
 * One AuthZEN decision, read strictly: an object whose `decision` is a JSON boolean.
 * Anything else — `"true"`, `1`, `{}`, a missing member — is a refusal. A `context` that
 * is not an object is advice nobody can read, so it is dropped rather than trusted.
 */
function readDecision(raw: unknown, pdp: string): EvaluationResponse {
  if (!isObject(raw) || typeof raw['decision'] !== 'boolean') {
    throw new PdpError(`PDP ${pdp} answered without a boolean decision`);
  }
  const context = raw['context'];
  return isObject(context) ? { decision: raw['decision'], context: context as DecisionContext } : { decision: raw['decision'] };
}

/** A boxcar answer, read strictly: exactly one boolean decision per evaluation sent. */
function readEvaluations(raw: unknown, sent: number, pdp: string): EvaluationResponse[] {
  const list = isObject(raw) ? raw['evaluations'] : undefined;
  if (!Array.isArray(list)) throw new PdpError(`PDP ${pdp} answered without an evaluations array`);
  if (list.length !== sent) throw new PdpError(`PDP ${pdp} answered ${list.length} evaluations for ${sent} sent`);
  return list.map((d) => readDecision(d, pdp));
}

/** May this layer be skipped for this error? Only an unavailable PDP on a fail-open layer. */
function skippable(ep: PdpEndpoints, err: unknown): boolean {
  return Boolean(ep.failOpen) && err instanceof PdpError && err.outcome === 'unavailable';
}

function skip(layers: ResolvedLayers, identifier: string, err: unknown): void {
  layers.skipped.push(identifier);
  layers.detail.push(`${identifier}: ${describe(err)}`);
}

function pdpError(err: unknown, request: EvaluationRequest | EvaluationsRequest): Verdict {
  return { allow: false, kind: 'pdp_error', reason: PDP_UNAVAILABLE_REASON, detail: describe(err), request };
}

/** The context keys the PEP owns. Nothing a caller or a mapping supplies may set them. */
const FORWARDED_KEYS = ['access_token', 'resource_metadata', 'resource_metadata_source', 'request'] as const;

/**
 * What the PEP forwards for the PDP to reason with, beyond the mapped subject, action
 * and resource: the resource's declared posture as published, the endpoint hit, and
 * (when the caller allows) the raw token. The SDK enforces none of it. Comparing a
 * token's scope or acr to what a resource requires is a policy decision, and policy is
 * offloaded to the PDP, where it can weigh them alongside things a PEP never sees.
 *
 * Those keys are the PEP's alone. A mapping's context is built from tool arguments the
 * caller controls, so a key it supplies is removed — at the top level and in every
 * boxcar entry, where an entry's context would otherwise override the top level's —
 * and only what the PEP itself forwards is set. Every other key passes through.
 */
function withForwardedContext<T extends { context?: Record<string, unknown>; evaluations?: unknown }>(
  request: T,
  meta: ResourceMetadata | undefined,
  options: EvaluateOptions,
): T {
  const forwarded: Record<string, unknown> = {};
  if (meta) {
    forwarded['resource_metadata'] = meta.document;
    forwarded['resource_metadata_source'] = meta.source;
  }
  if (options.request) forwarded['request'] = options.request;
  if (options.accessToken) forwarded['access_token'] = options.accessToken;

  const out: Record<string, unknown> = { ...request };
  if (request.context !== undefined || Object.keys(forwarded).length > 0) {
    out['context'] = { ...withoutForwarded(request.context), ...forwarded };
  }
  if (Array.isArray(request.evaluations)) {
    out['evaluations'] = request.evaluations.map((e: unknown) =>
      isObject(e) && isObject(e['context']) ? { ...e, context: withoutForwarded(e['context']) } : e,
    );
  }
  return out as T;
}

function withoutForwarded(context: unknown): Record<string, unknown> {
  if (!isObject(context)) return {};
  const out = { ...context };
  for (const k of FORWARDED_KEYS) delete out[k];
  return out;
}

/**
 * Fold a permitting layer's verdict into the running one.
 *
 * Only the DECISION is a single answer; the OBLIGATIONS a policy attaches are cumulative.
 * Replacing the verdict wholesale let a later layer's plain permit erase an earlier
 * layer's step-up or identity-proofing advice, so a caller reading `context` could not
 * see a requirement a PDP had in fact asserted. A deny is returned untouched: it short
 * circuits the fold and carries its own advice. The first layer to require something owns
 * its parameter.
 */
function mergePermit(acc: Verdict | undefined, layer: Verdict): Verdict {
  if (!layer.allow || !acc?.allow) return layer;
  const a = acc.context;
  if (!a?.identity_proofing_required && !a?.step_up_required) return layer;
  const context: DecisionContext = { ...(layer.context ?? {}) };
  if (a.identity_proofing_required) {
    context.identity_proofing_required = true;
    context.identity_proofing_doctype = a.identity_proofing_doctype ?? context.identity_proofing_doctype;
  }
  if (a.step_up_required) {
    context.step_up_required = true;
    context.step_up_scope = a.step_up_scope ?? context.step_up_scope;
  }
  // The obligation's own reason explains the challenge; a later plain permit's does not.
  return { ...layer, context, reason: acc.reason };
}

/**
 * The end of a layered fold. No verdict at all means every layer was skipped: that is
 * a permit — what fail-open means, chosen per layer — marked so it can be seen and
 * counted. Otherwise the verdict stands, with the skipped layers attached.
 */
function finishFold(verdict: Verdict | undefined, layers: ResolvedLayers, request: EvaluationRequest | EvaluationsRequest): Verdict {
  const { skipped, detail } = layers;
  if (!verdict) {
    return { allow: true, kind: 'ok', reason: 'fail-open: no policy layer could be reached', detail: detail.join('; '), request, failedOpen: skipped };
  }
  return skipped.length > 0 ? { ...verdict, failedOpen: skipped, detail: detail.join('; ') } : verdict;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function describe(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

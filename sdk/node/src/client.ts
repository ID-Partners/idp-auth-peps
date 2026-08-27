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

export interface AuthzenClientOptions {
  /** PDP base URL, e.g. `https://authzen-adapter.internal:8080`. `/access/v1/...` is appended. */
  url: string;
  /** Sent as `Authorization: Bearer <apiKey>` when set. */
  apiKey?: string;
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

  constructor(private readonly opts: AuthzenClientOptions) {
    if (!opts.url) throw new Error('AuthzenClient requires a PDP url');
    this.url = opts.url.replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs ?? 1500;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('No fetch implementation available (Node 20+ or pass opts.fetch)');
    }
  }

  /**
   * POST /access/v1/evaluation. Returns a folded Verdict; never throws.
   */
  async evaluate(request: EvaluationRequest): Promise<Verdict> {
    try {
      const res = await this.post<EvaluationResponse>('/access/v1/evaluation', request);
      return { ...foldDecision(res), request };
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
   * POST /access/v1/evaluations (boxcar). Folds to a single Verdict: every decision must
   * permit, and the FIRST deny is the one reported, so its advice survives the fold.
   */
  async evaluateAll(request: EvaluationsRequest): Promise<Verdict> {
    try {
      const res = await this.post<EvaluationsResponse>('/access/v1/evaluations', request);
      const list = Array.isArray(res?.evaluations) ? res.evaluations : [];
      if (list.length === 0) {
        return { allow: false, kind: 'pdp_error', reason: 'PDP evaluations response was empty', request };
      }
      for (const d of list) {
        if (!d?.decision) return { ...foldDecision(d), request };
      }
      return { allow: true, kind: 'ok', reason: 'permit', request };
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

  /** Raw POST. Throws PdpError — used by the search methods, where a caller can handle it. */
  async post<T>(path: string, body: unknown): Promise<T> {
    const endpoint = this.url + path;
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
          ...(this.opts.apiKey ? { authorization: `Bearer ${this.opts.apiKey}` } : {}),
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

function describe(err: unknown): string {
  if (err instanceof PdpError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

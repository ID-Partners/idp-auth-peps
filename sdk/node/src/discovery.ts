/**
 * PDP discovery: resource -> PDP identifier -> PDP metadata -> endpoints.
 *
 * The same chain the Go PEP (`core/authzen/discovery`) and the Kong plugin walk:
 *
 *   resource identifier
 *     ├─ resource: {resource}/.well-known/oauth-protected-resource (RFC 9728) — self-asserted
 *     └─ static:   the configured PDP URL                                    — the fallback
 *   PDP identifier
 *     ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9)
 *     └─ 404 / unreachable -> {pdp}/access/v1/evaluation, the spec's default paths
 *
 * The parameter naming the PDPs, `authzen_policy_decision_points`, is minted by this
 * repo — no spec defines one — and is the same bytes in an RFC 9728 document and under
 * `metadata.oauth_resource` in an OpenID Federation Entity Statement. There is no
 * federation source here; `sources` is the seam for one.
 *
 * Two rules never relax: a URL outside an allowlist fails closed rather than falling
 * to a weaker source, and a discovered PDP never receives the static API key.
 */

export const PARAM_POLICY_DECISION_POINTS = 'authzen_policy_decision_points';

export type DiscoveryMode = 'off' | 'authzen' | 'resource';

export type DiscoveryErrorKind = 'not_allowed' | 'invalid' | 'no_metadata' | 'transient';

/** A discovery failure. `not_allowed` is the one kind the chain never swallows. */
export class DiscoveryError extends Error {
  constructor(
    readonly kind: DiscoveryErrorKind,
    message: string,
  ) {
    super(message);
    this.name = 'DiscoveryError';
  }
}

/** What a PEP needs to call one PDP. */
export interface PdpEndpoints {
  /** The PDP's `policy_decision_point` value. */
  identifier: string;
  /** `access_evaluation_endpoint`; always set. */
  evaluation: string;
  /** `access_evaluations_endpoint`; undefined when the PDP advertises none. */
  evaluations?: string;
  capabilities?: string[];
  /** The bearer bound to this identifier; undefined for a discovered PDP. */
  apiKey?: string;
  source: string;
}

export interface PdpResolver {
  resolve(resource?: string): Promise<PdpEndpoints>;
}

/** Yields the ordered PDP identifiers for a resource. Throw a DiscoveryError. */
export interface MetadataSource {
  readonly name: string;
  pdps(resource: string): Promise<string[]>;
}

export interface PdpDiscoveryOptions {
  /** Default `off`: static PDP, default paths, no HTTP. */
  mode?: DiscoveryMode;
  /** The configured PDP base URL — always the fallback, always permitted. */
  staticPdp: string;
  /** PDP identifier -> bearer. Seed `{ [staticPdp]: apiKey }`. */
  apiKeys?: Record<string, string>;
  fetch?: typeof globalThis.fetch;
  /** Per metadata fetch. Default 3000ms. */
  timeoutMs?: number;
  /** Cache TTL for resource and PDP metadata. Default 5 minutes. */
  ttlMs?: number;
  /** Retry throttle while a refresh keeps failing. Default 30s. */
  minRefreshMs?: number;
  maxEntries?: number;
  /** Allow http for discovered URLs. Same-origin http as `staticPdp` is always allowed. */
  allowInsecure?: boolean;
  /** Permitted discovered-PDP prefixes; `staticPdp` is always permitted. Empty: any https. */
  pdpAllowlist?: string[];
  /** Permitted `resource` prefixes for metadata fetches. Empty: any. */
  resourceAllowlist?: string[];
  /** Overrides the mode-derived sources. */
  sources?: MetadataSource[];
  /** One line per degraded step. Default `console.warn`. */
  onWarning?: (message: string) => void;
  /** The clock; tests replace it. */
  now?: () => number;
}

// ---------- URLs ----------

/**
 * The RFC 8414 / RFC 9728 / AuthZEN rule: insert `/.well-known/<suffix>` between the
 * host and any path. An identifier with a query or fragment is not one.
 */
export function wellKnownUrl(identifier: string, suffix: string): string {
  const u = parseAbsolute(identifier);
  if (!u) throw new DiscoveryError('invalid', `${identifier} is not an absolute URL`);
  if (u.search || u.hash) throw new DiscoveryError('invalid', `${identifier} must not have a query or fragment`);
  const path = u.pathname.replace(/\/+$/, '');
  return `${u.protocol}//${u.host}/.well-known/${suffix}${path}`;
}

/**
 * A prefix allowlist that matches only at a path boundary — the Go PEP's rule.
 * `https://a.example/mcp` permits `.../mcp` and `.../mcp/x`, never `.../mcpx`.
 */
export function allowedByPrefix(list: string[] | undefined, raw: string): boolean {
  if (!list || list.length === 0) return true;
  const u = parseAbsolute(raw);
  if (!u) return false;
  const target = `${u.protocol}//${u.host}${u.pathname}`;
  for (const entry of list) {
    const e = parseAbsolute(entry);
    if (!e) continue;
    const prefix = `${e.protocol}//${e.host}${e.pathname}`.replace(/\/+$/, '');
    if (target === prefix || target.startsWith(prefix + '/')) return true;
  }
  return false;
}

function parseAbsolute(raw: string): URL | null {
  try {
    const u = new URL(raw);
    return u.host ? u : null;
  } catch {
    return null;
  }
}

interface UrlPolicy {
  allowInsecure: boolean;
  trustedOrigin?: string;
  allowlist?: string[];
}

function checkUrl(raw: string, policy: UrlPolicy): void {
  const u = parseAbsolute(raw);
  if (!u) throw new DiscoveryError('not_allowed', `${raw} is not an absolute URL`);
  if (u.protocol === 'http:') {
    if (!policy.allowInsecure && !sameOrigin(u, policy.trustedOrigin)) {
      throw new DiscoveryError('not_allowed', `${raw} is not https`);
    }
  } else if (u.protocol !== 'https:') {
    throw new DiscoveryError('not_allowed', `${raw} has scheme ${u.protocol}`);
  }
  if (!allowedByPrefix(policy.allowlist, raw)) {
    throw new DiscoveryError('not_allowed', `${raw} is outside the allowlist`);
  }
}

function sameOrigin(u: URL, trusted?: string): boolean {
  const t = trusted ? parseAbsolute(trusted) : null;
  return t !== null && u.origin === t.origin;
}

// ---------- cache ----------

interface Entry<T> {
  val?: T;
  ok: boolean;
  expires: number;
  lastAttempt: number;
  lastErr?: DiscoveryError;
  negUntil: number;
  inflight?: Promise<T>;
}

/**
 * Bounded TTL cache: serves a stale value while a refresh fails, throttles retries,
 * negatively caches a transient failure, and shares one in-flight fetch per key.
 */
class TtlCache<T> {
  private readonly entries = new Map<string, Entry<T>>();

  constructor(
    private readonly ttl: number,
    private readonly minRefresh: number,
    private readonly negativeTtl: number,
    private readonly maxEntries: number,
    private readonly now: () => number,
  ) {}

  async get(key: string, fetch: (key: string) => Promise<T>): Promise<T> {
    const e = this.entryFor(key);
    if (!e) return fetch(key); // full of live entries: serve uncached
    const t = this.now();
    if (e.ok && t < e.expires) return e.val as T;
    if (!e.ok && e.lastErr && t < e.negUntil) throw e.lastErr;
    if (e.ok && e.lastErr && t - e.lastAttempt < this.minRefresh) return e.val as T;
    if (e.inflight) return e.inflight;

    e.lastAttempt = t;
    e.inflight = fetch(key).then(
      (val) => {
        e.val = val;
        e.ok = true;
        e.expires = this.now() + this.ttl;
        e.lastErr = undefined;
        e.negUntil = 0;
        e.inflight = undefined;
        return val;
      },
      (err: unknown) => {
        e.inflight = undefined;
        const derr = err instanceof DiscoveryError ? err : new DiscoveryError('transient', String(err));
        e.lastErr = derr;
        if (e.ok) return e.val as T; // stale beats failing every request
        // A policy refusal cost no fetch and belongs to the caller's allowlist; do not
        // let it stand in for the next caller.
        if (this.negativeTtl > 0 && derr.kind !== 'not_allowed') e.negUntil = this.now() + this.negativeTtl;
        throw derr;
      },
    );
    return e.inflight;
  }

  private entryFor(key: string): Entry<T> | null {
    const existing = this.entries.get(key);
    if (existing) return existing;
    if (this.entries.size >= this.maxEntries) {
      const t = this.now();
      for (const [k, e] of this.entries) {
        if ((e.ok && t >= e.expires) || (!e.ok && t >= e.negUntil && !e.inflight)) this.entries.delete(k);
      }
      if (this.entries.size >= this.maxEntries) return null;
    }
    const e: Entry<T> = { ok: false, expires: 0, lastAttempt: 0, negUntil: 0 };
    this.entries.set(key, e);
    return e;
  }

  status(): Record<string, { cached: boolean; stale: boolean; lastError?: string }> {
    const t = this.now();
    const out: Record<string, { cached: boolean; stale: boolean; lastError?: string }> = {};
    for (const [k, e] of this.entries) {
      out[k] = { cached: e.ok, stale: e.ok && t >= e.expires, ...(e.lastErr ? { lastError: e.lastErr.message } : {}) };
    }
    return out;
  }
}

// ---------- sources ----------

function pdpList(raw: unknown, from: string): string[] {
  if (!Array.isArray(raw) || raw.length === 0) throw new DiscoveryError('no_metadata', `${from} names no PDP`);
  return raw.map((v) => {
    const u = typeof v === 'string' ? parseAbsolute(v) : null;
    if (!u || u.search || u.hash) {
      throw new DiscoveryError('invalid', `${from} lists ${JSON.stringify(v)}, which is not a PDP identifier`);
    }
    return (v as string).replace(/\/+$/, '');
  });
}

/** RFC 9728: the resource's own protected resource metadata. */
export class Rfc9728Source implements MetadataSource {
  readonly name = 'rfc9728';
  constructor(private readonly getJson: (url: string) => Promise<unknown>) {}

  async pdps(resource: string): Promise<string[]> {
    const wk = wellKnownUrl(resource, 'oauth-protected-resource');
    const doc = (await this.getJson(wk)) as Record<string, unknown>;
    // §3.3: the echoed identifier MUST be identical, or whoever answers at that path
    // has just named a PDP for someone else's resource.
    if (doc['resource'] !== resource) {
      throw new DiscoveryError('invalid', `${wk} says resource is ${JSON.stringify(doc['resource'])}, expected ${resource}`);
    }
    return pdpList(doc[PARAM_POLICY_DECISION_POINTS], wk);
  }
}

export function defaultEndpoints(pdp: string): PdpEndpoints {
  const base = pdp.replace(/\/+$/, '');
  return { identifier: base, evaluation: `${base}/access/v1/evaluation`, evaluations: `${base}/access/v1/evaluations`, source: 'static' };
}

// ---------- the chain ----------

export class PdpDiscovery implements PdpResolver {
  readonly mode: DiscoveryMode;
  private readonly staticPdp: string;
  private readonly apiKeys: Record<string, string>;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;
  private readonly warn: (message: string) => void;
  private readonly resourcePolicy: UrlPolicy;
  private readonly pdpPolicy: UrlPolicy;
  private readonly sources: MetadataSource[];
  private readonly resources: TtlCache<string[]>;
  private readonly pdps: TtlCache<PdpEndpoints>;

  constructor(opts: PdpDiscoveryOptions) {
    this.mode = opts.mode ?? 'off';
    this.staticPdp = (opts.staticPdp ?? '').replace(/\/+$/, '');
    this.apiKeys = opts.apiKeys ?? {};
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (this.mode !== 'off' && typeof this.fetchImpl !== 'function') {
      throw new Error('PdpDiscovery needs a fetch implementation (Node 20+ or pass opts.fetch)');
    }
    this.timeoutMs = opts.timeoutMs ?? 3000;
    this.warn = opts.onWarning ?? ((m) => console.warn(m));
    const now = opts.now ?? (() => Date.now());
    const ttl = opts.ttlMs ?? 300_000;
    const minRefresh = opts.minRefreshMs ?? 30_000;
    const max = opts.maxEntries ?? 1024;
    this.resourcePolicy = { allowInsecure: opts.allowInsecure === true, allowlist: opts.resourceAllowlist };
    // The static PDP is always permitted; the allowlist bounds what a resource may add.
    this.pdpPolicy = {
      allowInsecure: opts.allowInsecure === true,
      trustedOrigin: this.staticPdp || undefined,
      allowlist: opts.pdpAllowlist && opts.pdpAllowlist.length > 0 ? [...opts.pdpAllowlist, this.staticPdp] : undefined,
    };
    // A resource whose metadata cannot be fetched is served by the static PDP for a
    // while rather than re-fetched in every request's path.
    this.resources = new TtlCache<string[]>(ttl, minRefresh, minRefresh, max, now);
    this.pdps = new TtlCache<PdpEndpoints>(ttl, minRefresh, 0, max, now);
    this.sources =
      opts.sources ??
      (this.mode === 'resource' ? [new Rfc9728Source((url) => this.getJson(url, this.resourcePolicy))] : []);
  }

  async resolve(resource?: string): Promise<PdpEndpoints> {
    if (this.mode === 'off') {
      if (!this.staticPdp) throw new DiscoveryError('transient', 'no PDP configured');
      return this.withKey(defaultEndpoints(this.staticPdp));
    }

    let candidates: string[];
    if (!resource || this.mode === 'authzen') {
      if (!this.staticPdp) throw new DiscoveryError('transient', 'no PDP configured');
      candidates = [this.staticPdp];
    } else {
      // Checked on every call, not only at fetch time: the cache is shared, the policy
      // belongs to this caller.
      checkUrl(resource, this.resourcePolicy);
      try {
        candidates = await this.resources.get(resource, (key) => this.lookupPdps(key));
      } catch (err) {
        const derr = asDiscoveryError(err);
        if (derr.kind === 'not_allowed') throw derr;
        if (!this.staticPdp) throw new DiscoveryError('transient', `no PDP could be resolved for ${resource}: ${derr.message}`);
        this.warn(`pdp discovery: ${resource}: ${derr.message}; using the static PDP`);
        candidates = [this.staticPdp];
      }
    }

    let last: DiscoveryError | undefined;
    for (const pdp of candidates) {
      checkUrl(pdp, this.pdpPolicy);
      try {
        const ep = await this.pdps.get(pdp, (key) => this.fetchConfig(key));
        for (const u of [ep.evaluation, ep.evaluations]) if (u) checkUrl(u, this.pdpPolicy);
        return this.withKey({ ...ep, source: pdp === this.staticPdp ? 'static' : 'rfc9728' });
      } catch (err) {
        const derr = asDiscoveryError(err);
        if (derr.kind === 'not_allowed') throw derr;
        this.warn(`pdp discovery: ${pdp}: ${derr.message}`);
        last = derr;
      }
    }
    throw new DiscoveryError('transient', `no PDP could be resolved${last ? `: ${last.message}` : ''}`);
  }

  /** Resolve the static PDP so a bad configuration is loud early. */
  warm(): Promise<PdpEndpoints> {
    return this.resolve();
  }

  status() {
    return { mode: this.mode, sources: this.sources.map((s) => s.name), resources: this.resources.status(), pdps: this.pdps.status() };
  }

  private withKey(ep: PdpEndpoints): PdpEndpoints {
    const key = this.apiKeys[ep.identifier];
    return key ? { ...ep, apiKey: key } : { ...ep, apiKey: undefined };
  }

  /** Sources in order; no metadata anywhere resolves to the static PDP, cached. */
  private async lookupPdps(resource: string): Promise<string[]> {
    for (const src of this.sources) {
      try {
        const list = await src.pdps(resource);
        if (list.length > 0) return list;
      } catch (err) {
        const derr = asDiscoveryError(err);
        if (derr.kind === 'not_allowed' || derr.kind === 'transient') throw derr;
        if (derr.kind === 'invalid') this.warn(`pdp discovery: ${src.name} for ${resource}: ${derr.message}`);
      }
    }
    if (!this.staticPdp) throw new DiscoveryError('no_metadata', `no metadata names a PDP for ${resource}`);
    return [this.staticPdp];
  }

  /** AuthZEN 1.0 §9: the PDP's metadata, or the default paths when it has none. */
  private async fetchConfig(pdp: string): Promise<PdpEndpoints> {
    const wk = wellKnownUrl(pdp, 'authzen-configuration');
    let doc: Record<string, unknown>;
    try {
      doc = (await this.getJson(wk, this.pdpPolicy)) as Record<string, unknown>;
    } catch (err) {
      const derr = asDiscoveryError(err);
      if (derr.kind === 'not_allowed' || derr.kind === 'invalid') throw derr;
      if (derr.kind !== 'no_metadata') this.warn(`pdp discovery: ${derr.message}; using default AuthZEN paths`);
      return defaultEndpoints(pdp);
    }
    const id = String(doc['policy_decision_point'] ?? '').replace(/\/+$/, '');
    if (id !== pdp.replace(/\/+$/, '')) {
      throw new DiscoveryError('invalid', `${wk} says policy_decision_point is ${JSON.stringify(doc['policy_decision_point'])}, expected ${pdp}`);
    }
    const evaluation = doc['access_evaluation_endpoint'];
    if (typeof evaluation !== 'string' || !evaluation) {
      throw new DiscoveryError('invalid', `${wk} has no access_evaluation_endpoint`);
    }
    const evaluations = typeof doc['access_evaluations_endpoint'] === 'string' ? (doc['access_evaluations_endpoint'] as string) : undefined;
    for (const u of [evaluation, evaluations]) if (u) checkUrl(u, this.pdpPolicy);
    const capabilities = Array.isArray(doc['capabilities']) ? (doc['capabilities'] as unknown[]).filter((c): c is string => typeof c === 'string') : undefined;
    return { identifier: pdp.replace(/\/+$/, ''), evaluation, ...(evaluations ? { evaluations } : {}), ...(capabilities ? { capabilities } : {}), source: 'static' };
  }

  /** Policy-checked, bounded GET. 404 -> no_metadata; redirects are not followed. */
  private async getJson(url: string, policy: UrlPolicy): Promise<unknown> {
    checkUrl(url, policy);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.fetchImpl(url, { method: 'GET', headers: { accept: 'application/json' }, redirect: 'manual', signal: controller.signal });
      } catch (err) {
        throw new DiscoveryError('transient', `GET ${url}: ${err instanceof Error ? err.message : String(err)}`);
      }
      if (res.status === 404) throw new DiscoveryError('no_metadata', `${url} returned 404`);
      if (!res.ok) throw new DiscoveryError('transient', `GET ${url} returned ${res.status}`);
      const text = await res.text();
      if (text.length > 1_048_576) throw new DiscoveryError('transient', `${url} body exceeds 1 MiB`);
      try {
        const parsed: unknown = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object') throw new Error('not an object');
        return parsed;
      } catch {
        throw new DiscoveryError('invalid', `${url} is not JSON`);
      }
    } finally {
      clearTimeout(timer);
    }
  }
}

function asDiscoveryError(err: unknown): DiscoveryError {
  return err instanceof DiscoveryError ? err : new DiscoveryError('transient', err instanceof Error ? err.message : String(err));
}

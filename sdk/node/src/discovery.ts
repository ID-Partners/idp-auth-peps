/**
 * PDP discovery: resource -> PDP identifier -> PDP metadata -> endpoints.
 *
 * The same chain the Go PEP (`core/authzen/discovery`) and the Kong plugin walk:
 *
 *   resource identifier
 *     ├─ resource: {resource}/.well-known/oauth-protected-resource (RFC 9728) — self-asserted
 *     └─ static:   the configured PDP URL — when the resource publishes nothing (404)
 *   PDP identifier
 *     ├─ {pdp}/.well-known/authzen-configuration (AuthZEN 1.0 §9)
 *     └─ 404 -> {pdp}/access/v1/evaluation, the spec's default paths
 *
 * A resource whose document cannot be read (an outage, or a document that is invalid)
 * is not the same as one that publishes nothing: its layer is unavailable and fails by
 * its own mode, rather than quietly becoming the static PDP. An outage serves the last
 * good copy of either document while there is one.
 *
 * The parameter naming the PDPs, `authzen_policy_decision_points`, is minted by this
 * repo — no spec defines one — and is the same bytes in an RFC 9728 document and under
 * `metadata.oauth_resource` in an OpenID Federation Entity Statement. There is no
 * federation source here; `sources` is the seam for one.
 *
 * Two rules never relax: a URL outside an allowlist fails closed rather than falling
 * to a weaker source, and a discovered PDP never receives the static API key.
 */

import { BodyTooLargeError, readCapped } from './http.js';

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

/**
 * A resource's declared posture: its RFC 9728 document, or the federation-resolved
 * `oauth_resource` metadata, as published. The PEP reads the PDP list out of it and
 * forwards the rest to the PDP as context — it decides nothing from it. What a resource
 * requires (scopes, acr, sender-constrained tokens) is policy input, and policy lives in
 * the PDP.
 */
export interface ResourceMetadata {
  source: string;
  document: Record<string, unknown>;
  /** The ordered PDP identifiers read out of the document, first preferred. */
  pdps: string[];
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
  /**
   * This layer's effective failure mode. When true an AVAILABILITY failure — unreachable,
   * erroring, unresolvable — skips the layer instead of failing the call. A refusal
   * (allowlist, invalid chain) is never skipped; a deny is a decision, not a failure.
   */
  failOpen?: boolean;
  /** The resource's own metadata, when a document named this PDP. Forwarded, never read. */
  resource?: ResourceMetadata;
}

export interface PdpResolver {
  /** The PDP that decides for a resource (undefined: the static one). */
  resolve(resource?: string): Promise<PdpEndpoints>;
  /** The metadata of an explicitly named PDP — a configured layer rather than a discovered one. */
  resolvePdp(pdp: string): Promise<PdpEndpoints>;
}

/** Layer names; anything else in a layer list is a PDP identifier. */
export const LAYER_RESOURCE = 'resource';
export const LAYER_STATIC = 'static';

/** One entry of a route's policy. `failOpen` undefined inherits the caller's default. */
export interface LayerSpec {
  name: string;
  failOpen?: boolean;
}

/**
 * Parse a layer entry: a name, optionally followed by `fail-open` or `fail-closed`
 * (`'https://estate.example fail-open'`), or `{ name, failOpen }`. Anything that cannot
 * be read throws — an unknown modifier, a `failOpen` that is not a boolean (`'false'` is
 * truthy), a name that is not a layer or a usable PDP identifier: a policy that cannot
 * be read must not be silently narrowed, or silently opened.
 */
export function parseLayer(entry: string | LayerSpec): LayerSpec {
  if (typeof entry === 'string') {
    const [name = '', ...mods] = entry.trim().split(/\s+/);
    const spec: LayerSpec = { name: layerName(name) };
    for (const mod of mods) {
      if (mod.toLowerCase() === 'fail-open') spec.failOpen = true;
      else if (mod.toLowerCase() === 'fail-closed') spec.failOpen = false;
      else throw new DiscoveryError('invalid', `layer ${spec.name}: unknown modifier ${JSON.stringify(mod)} (fail-open, fail-closed)`);
    }
    return spec;
  }
  if (typeof entry !== 'object' || entry === null || typeof entry.name !== 'string') {
    throw new DiscoveryError('invalid', `layer ${JSON.stringify(entry)} is neither a string nor { name, failOpen }`);
  }
  const spec: LayerSpec = { name: layerName(entry.name) };
  if (entry.failOpen !== undefined) {
    if (typeof entry.failOpen !== 'boolean') {
      throw new DiscoveryError('invalid', `layer ${spec.name}: failOpen must be a boolean, not ${JSON.stringify(entry.failOpen)}`);
    }
    spec.failOpen = entry.failOpen;
  }
  return spec;
}

/** `static`, `resource`, or an absolute http(s) PDP identifier with no query or fragment. */
function layerName(raw: string): string {
  const name = raw.trim().replace(/\/+$/, '');
  if (name === LAYER_RESOURCE || name === LAYER_STATIC) return name;
  const u = parseAbsolute(name);
  if (!u || (u.protocol !== 'https:' && u.protocol !== 'http:') || name.includes('?') || name.includes('#')) {
    throw new DiscoveryError('invalid', `layer ${JSON.stringify(name)} is neither static, resource nor a PDP identifier`);
  }
  return name;
}

/** What resolving a layer list produced: the PDPs to ask, and the fail-open layers that were skipped. */
export interface ResolvedLayers {
  pdps: PdpEndpoints[];
  /** The identifiers of the skipped layers — safe to put on the wire. */
  skipped: string[];
  /** One line per skipped layer saying why, for logs. */
  detail: string[];
}

/**
 * Resolve every layer of a route's policy, in order, duplicates collapsed. Layering is
 * what lets a generic PDP that judges the token and the client sit in front of the
 * resource's own: every layer must permit, the first that does not is the answer.
 *
 * `failOpen` is the caller's default; a layer's own setting wins. A layer that cannot
 * be resolved fails the call unless it is fail-open, in which case it is skipped and
 * named. A refusal (`not_allowed`, which also carries an invalid federation chain) is
 * never skipped: fail-open is about availability, and a refusal is not an outage.
 */
export async function resolveLayers(
  r: PdpResolver,
  resource: string | undefined,
  layers: Array<string | LayerSpec> | undefined,
  failOpen = false,
): Promise<ResolvedLayers> {
  const specs = (layers && layers.length > 0 ? layers : [LAYER_RESOURCE]).map(parseLayer);
  const out: PdpEndpoints[] = [];
  const skipped: string[] = [];
  const detail: string[] = [];
  const seen = new Map<string, number>();
  for (const spec of specs) {
    const open = spec.failOpen ?? failOpen;
    let ep: PdpEndpoints;
    try {
      ep = spec.name === LAYER_RESOURCE ? await r.resolve(resource) : spec.name === LAYER_STATIC ? await r.resolve() : await r.resolvePdp(spec.name);
    } catch (err) {
      const derr = asDiscoveryError(err);
      if (derr.kind === 'not_allowed' || !open) throw new DiscoveryError(derr.kind, `layer ${spec.name}: ${derr.message}`);
      skipped.push(spec.name);
      detail.push(`${spec.name}: ${derr.message}`);
      continue;
    }
    const at = seen.get(ep.identifier);
    if (at !== undefined) {
      const prev = out[at]!;
      out[at] = { ...prev, ...(prev.resource ? {} : ep.resource ? { resource: ep.resource } : {}), failOpen: Boolean(prev.failOpen) && open };
      continue;
    }
    seen.set(ep.identifier, out.length);
    out.push({ ...ep, failOpen: open });
  }
  return { pdps: out, skipped, detail };
}

/** The one resource document to forward for a layered call: whichever layer read it. */
export function resourceMetadataOf(eps: PdpEndpoints[]): ResourceMetadata | undefined {
  return eps.find((e) => e.resource)?.resource;
}

/** Yields a resource's metadata: the PDPs that decide for it, and the document that named them. */
export interface MetadataSource {
  readonly name: string;
  lookup(resource: string): Promise<ResourceMetadata>;
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
  /**
   * The escape hatch, for development only: allow http for discovered URLs (same-origin
   * http as `staticPdp` is always allowed), and let resource mode start without its
   * allowlists. Logged once, at construction.
   */
  allowInsecure?: boolean;
  /**
   * Permitted PDP prefixes, matched at a path boundary; `staticPdp` is always permitted.
   * Required in resource mode — without it any resource could name any https PDP — and
   * it bounds configured layers too.
   */
  pdpAllowlist?: string[];
  /** Permitted `resource` prefixes for metadata fetches. Required in resource mode. */
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

  async lookup(resource: string): Promise<ResourceMetadata> {
    const wk = wellKnownUrl(resource, 'oauth-protected-resource');
    const doc = (await this.getJson(wk)) as Record<string, unknown>;
    // §3.3: the echoed identifier MUST be identical, or whoever answers at that path
    // has just named a PDP for someone else's resource.
    if (doc['resource'] !== resource) {
      throw new DiscoveryError('invalid', `${wk} says resource is ${JSON.stringify(doc['resource'])}, expected ${resource}`);
    }
    // The whole document travels to the PDP; this source does not know or care which
    // other members are in it.
    return { source: 'rfc9728', document: doc, pdps: pdpList(doc[PARAM_POLICY_DECISION_POINTS], wk) };
  }
}

export function defaultEndpoints(pdp: string): PdpEndpoints {
  const base = pdp.replace(/\/+$/, '');
  return { identifier: base, evaluation: `${base}/access/v1/evaluation`, evaluations: `${base}/access/v1/evaluations`, source: 'static' };
}

// ---------- the chain ----------

/** The most a metadata document may be. */
const MAX_METADATA_BYTES = 1_048_576;

export class PdpDiscovery implements PdpResolver {
  readonly mode: DiscoveryMode;
  private readonly staticPdp: string;
  private readonly apiKeys: Record<string, string>;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;
  private readonly warn: (message: string) => void;
  private readonly now: () => number;
  private readonly minRefresh: number;
  private readonly warnedAt = new Map<string, number>();
  private readonly resourcePolicy: UrlPolicy;
  private readonly pdpPolicy: UrlPolicy;
  private readonly sources: MetadataSource[];
  private readonly resources: TtlCache<ResourceMetadata>;
  private readonly pdps: TtlCache<PdpEndpoints>;

  constructor(opts: PdpDiscoveryOptions) {
    this.mode = opts.mode ?? 'off';
    this.staticPdp = (opts.staticPdp ?? '').replace(/\/+$/, '');
    this.apiKeys = opts.apiKeys ?? {};
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (this.mode !== 'off' && typeof this.fetchImpl !== 'function') {
      throw new Error('PdpDiscovery needs a fetch implementation (Node 22+ or pass opts.fetch)');
    }
    this.timeoutMs = opts.timeoutMs ?? 3000;
    this.warn = opts.onWarning ?? ((m) => console.warn(m));
    this.now = opts.now ?? (() => Date.now());
    const ttl = opts.ttlMs ?? 300_000;
    this.minRefresh = opts.minRefreshMs ?? 30_000;
    const max = opts.maxEntries ?? 1024;
    const insecure = opts.allowInsecure === true;

    // Resource mode takes a PDP's name from a document the resource publishes. Without
    // a PDP allowlist any resource could name any https PDP, and without a resource
    // allowlist anything that can influence the resource identifier could point the
    // PEP at a document of its choosing. Missing either is a configuration error.
    const missing = this.mode === 'resource' ? ([!opts.pdpAllowlist?.length && 'pdpAllowlist', !opts.resourceAllowlist?.length && 'resourceAllowlist'].filter(Boolean) as string[]) : [];
    if (missing.length > 0 && !insecure) {
      throw new Error(
        `resource-mode discovery needs ${missing.join(' and ')}: without them any resource can name any PDP. ` +
          'Set allowInsecure: true only for development.',
      );
    }
    if (insecure) {
      const relaxed = ['http is permitted for discovered URLs', ...(missing.length ? [`resource mode is running without ${missing.join(' and ')}`] : [])];
      this.warn(`pdp discovery: allowInsecure is set — ${relaxed.join('; ')}`);
    }

    this.resourcePolicy = { allowInsecure: insecure, allowlist: opts.resourceAllowlist };
    // The static PDP is always permitted; the allowlist bounds what a resource may add.
    this.pdpPolicy = {
      allowInsecure: insecure,
      trustedOrigin: this.staticPdp || undefined,
      allowlist: opts.pdpAllowlist && opts.pdpAllowlist.length > 0 ? [...opts.pdpAllowlist, this.staticPdp] : undefined,
    };
    // A failure is remembered for the retry window rather than re-fetched in every
    // request's path; a last good value is served through it.
    this.resources = new TtlCache<ResourceMetadata>(ttl, this.minRefresh, this.minRefresh, max, this.now);
    this.pdps = new TtlCache<PdpEndpoints>(ttl, this.minRefresh, this.minRefresh, max, this.now);
    this.sources =
      opts.sources ??
      (this.mode === 'resource' ? [new Rfc9728Source((url) => this.getJson(url, this.resourcePolicy))] : []);
  }

  /**
   * The PDP that decides for a resource. A resource that publishes nothing (a 404, or a
   * document that names no PDP) is decided by the static PDP, by design. A resource whose
   * metadata cannot be read — an outage, or a document that is invalid — has no PDP: the
   * error is thrown, so its layer fails by its own mode instead of quietly becoming the
   * static layer. A last good document is served through an outage.
   */
  async resolve(resource?: string): Promise<PdpEndpoints> {
    if (this.mode === 'off') {
      if (!this.staticPdp) throw new DiscoveryError('transient', 'no PDP configured');
      return this.withKey(defaultEndpoints(this.staticPdp));
    }

    let candidates: string[];
    let from: ResourceMetadata | undefined;
    if (!resource || this.mode === 'authzen') {
      if (!this.staticPdp) throw new DiscoveryError('transient', 'no PDP configured');
      candidates = [this.staticPdp];
    } else {
      // Checked on every call, not only at fetch time: the cache is shared, the policy
      // belongs to this caller.
      checkUrl(resource, this.resourcePolicy);
      let meta: ResourceMetadata;
      try {
        meta = await this.resources.get(resource, (key) => this.lookupResource(key));
      } catch (err) {
        const derr = asDiscoveryError(err);
        if (derr.kind !== 'not_allowed') this.warnOnce(`resource ${resource}`, `pdp discovery: ${resource}: ${derr.message}; its layer is unavailable`);
        throw derr;
      }
      candidates = meta.pdps;
      if (meta.document) from = meta;
    }

    let last: DiscoveryError | undefined;
    for (const pdp of candidates) {
      checkUrl(pdp, this.pdpPolicy);
      try {
        const ep = await this.pdpEndpoints(pdp);
        for (const u of [ep.evaluation, ep.evaluations]) if (u) checkUrl(u, this.pdpPolicy);
        return this.withKey({ ...ep, source: pdp === this.staticPdp ? 'static' : 'rfc9728', ...(from ? { resource: from } : {}) });
      } catch (err) {
        const derr = asDiscoveryError(err);
        if (derr.kind === 'not_allowed') throw derr;
        this.warn(`pdp discovery: ${pdp}: ${derr.message}`);
        last = derr;
      }
    }
    throw new DiscoveryError('transient', `no PDP could be resolved${last ? `: ${last.message}` : ''}`);
  }

  /** An explicitly named PDP. Off mode reads nothing; otherwise the PDP allowlist applies. */
  async resolvePdp(pdp: string): Promise<PdpEndpoints> {
    pdp = pdp.replace(/\/+$/, '');
    if (this.mode === 'off') return this.withKey({ ...defaultEndpoints(pdp), source: 'layer' });
    checkUrl(pdp, this.pdpPolicy);
    const ep = await this.pdpEndpoints(pdp);
    for (const u of [ep.evaluation, ep.evaluations]) if (u) checkUrl(u, this.pdpPolicy);
    return this.withKey({ ...ep, source: 'layer' });
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

  /** One warning per subject per retry window: an outage is one event, not one line per request. */
  private warnOnce(subject: string, message: string): void {
    const t = this.now();
    const at = this.warnedAt.get(subject);
    if (at !== undefined && t - at < this.minRefresh) return;
    if (this.warnedAt.size >= 1024) this.warnedAt.clear();
    this.warnedAt.set(subject, t);
    this.warn(message);
  }

  /**
   * A PDP's endpoints. A transient failure serves the last good metadata (the cache does
   * that); with none yet, this call uses the spec's default paths and nothing is cached,
   * so the next call after the retry window reads the metadata again rather than living
   * with a guess for a whole TTL.
   */
  private async pdpEndpoints(pdp: string): Promise<PdpEndpoints> {
    try {
      return await this.pdps.get(pdp, (key) => this.fetchConfig(key));
    } catch (err) {
      const derr = asDiscoveryError(err);
      if (derr.kind !== 'transient') throw derr;
      this.warnOnce(`pdp ${pdp}`, `pdp discovery: ${derr.message}; using the default AuthZEN paths until ${pdp}'s metadata can be read`);
      return defaultEndpoints(pdp);
    }
  }

  /**
   * Sources in order. Metadata from the first that has some wins. A source that says the
   * resource publishes nothing falls through to the next, and nothing anywhere resolves
   * to the static PDP, cached. An outage stops the walk; so does an invalid document once
   * no source has answered — a quiet source must not paper over one that answered wrong.
   */
  private async lookupResource(resource: string): Promise<ResourceMetadata> {
    let invalid: DiscoveryError | undefined;
    for (const src of this.sources) {
      try {
        const meta = await src.lookup(resource);
        if (meta.pdps.length > 0) return meta;
      } catch (err) {
        const derr = asDiscoveryError(err);
        if (derr.kind === 'not_allowed' || derr.kind === 'transient') throw derr;
        if (derr.kind === 'invalid') {
          this.warn(`pdp discovery: ${src.name} for ${resource}: ${derr.message}`);
          invalid ??= derr;
        }
      }
    }
    if (invalid) throw invalid;
    if (!this.staticPdp) throw new DiscoveryError('no_metadata', `no metadata names a PDP for ${resource}`);
    return { source: 'static', document: undefined as unknown as Record<string, unknown>, pdps: [this.staticPdp] };
  }

  /**
   * AuthZEN 1.0 §9: the PDP's metadata. A PDP that publishes none (404) gets the default
   * paths, cached; an outage is thrown so the cache can serve the last good copy.
   */
  private async fetchConfig(pdp: string): Promise<PdpEndpoints> {
    const wk = wellKnownUrl(pdp, 'authzen-configuration');
    let doc: Record<string, unknown>;
    try {
      doc = (await this.getJson(wk, this.pdpPolicy)) as Record<string, unknown>;
    } catch (err) {
      const derr = asDiscoveryError(err);
      if (derr.kind === 'no_metadata') return defaultEndpoints(pdp);
      throw derr;
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

  /**
   * A bounded GET of a well-known document. The identifier it was derived from has
   * already passed the caller's allowlist, and the well-known URL shares its origin, so
   * only the scheme is checked here — a prefix check would refuse the document of an
   * allowlist entry that has a path, since the well-known segment goes before it.
   *
   *   404, 410          no_metadata  (publishes nothing)
   *   5xx, 429, a network failure, a timeout   transient
   *   3xx, any other 4xx, over 1 MiB, not a JSON object   invalid
   *
   * Redirects are not followed.
   */
  private async getJson(url: string, policy: UrlPolicy): Promise<unknown> {
    checkUrl(url, { ...policy, allowlist: undefined });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.fetchImpl(url, { method: 'GET', headers: { accept: 'application/json' }, redirect: 'manual', signal: controller.signal });
      } catch (err) {
        throw new DiscoveryError('transient', `GET ${url}: ${err instanceof Error ? err.message : String(err)}`);
      }
      if (res.status === 404 || res.status === 410) throw new DiscoveryError('no_metadata', `${url} returned ${res.status}`);
      if (res.status >= 500 || res.status === 429) throw new DiscoveryError('transient', `GET ${url} returned ${res.status}`);
      if (res.status < 200 || res.status >= 300) throw new DiscoveryError('invalid', `GET ${url} returned ${res.status}`);
      let text: string;
      try {
        text = await readCapped(res, MAX_METADATA_BYTES);
      } catch (err) {
        if (err instanceof BodyTooLargeError) throw new DiscoveryError('invalid', `${url} body exceeds 1 MiB`);
        throw new DiscoveryError('transient', `GET ${url}: ${err instanceof Error ? err.message : String(err)}`);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new DiscoveryError('invalid', `${url} is not JSON`);
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new DiscoveryError('invalid', `${url} is not JSON: expected an object`);
      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }
}

function asDiscoveryError(err: unknown): DiscoveryError {
  return err instanceof DiscoveryError ? err : new DiscoveryError('transient', err instanceof Error ? err.message : String(err));
}

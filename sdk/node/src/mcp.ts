/**
 * COAZ — the OpenID AuthZEN MCP profile — for Node MCP servers and gateways.
 *
 * Spec: https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md
 *
 * A tool declares `coaz: true` and an `x-coaz-mapping` saying how its parameters and the
 * caller's token become an AuthZEN request. Mapping leaves are expressions over two input
 * variables: `params` (the JSON-RPC `params` member — so arguments are at
 * `params.arguments.x`) and `token` (the caller's claims). This guard reads that declaration, builds the
 * request, asks the PDP, and enforces the answer with the profile's JSON-RPC semantics:
 *
 *   -32401  the PDP denied            (carries `data.authz_challenge` when resolvable)
 *   -32602  the mapping could not be evaluated
 *   -32603  the PDP could not be reached — fail closed
 *
 * Tools that do not declare `coaz: true` fall through untouched; whatever governs them
 * already (a gateway PEP, a scope check) still governs them.
 *
 * ## On expressions
 *
 * The profile compiles mapping leaves as CEL. There is no credible CEL evaluator for
 * Node, so this guard implements a documented SUBSET — literals, `params`/`token` field
 * access, `string()`/`int()`/`double()` casts, and `+` concatenation — and REFUSES
 * anything outside it with a mapping error rather than guessing. A mapping that needs
 * full CEL should be evaluated by the Go engine in `core/`, which this guard can call
 * instead: set the `delegate` option to a running `coaz-pep` HTTP check API.
 */

import { AuthzenClient, type AuthzenClientOptions } from './client.js';
import { toChallenge } from './challenge.js';
import type { PepClaims } from './claims.js';
import type { EvaluationRequest, EvaluationsRequest, Verdict } from './types.js';

/** JSON-RPC error codes the profile defines or adopts. */
export const CODE_DENIED = -32401;
export const CODE_MAPPING_ERROR = -32602;
export const CODE_PDP_ERROR = -32603;

/** One AuthZEN object as declared in a mapping: leaves are expressions. */
export type MappingElement = Record<string, unknown>;

export interface CoazMapping {
  subject: MappingElement[];
  action?: MappingElement[];
  resource: MappingElement[];
  context: MappingElement[];
}

/** The subset of an MCP tools/list entry the guard needs. */
export interface ToolDefinition {
  name: string;
  coaz?: boolean;
  'x-coaz-mapping'?: CoazMapping;
  inputSchema?: Record<string, unknown>;
  [key: string]: unknown;
}

/** A JSON-RPC 2.0 tools/call request. */
export interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: { name?: string; arguments?: Record<string, unknown>; [key: string]: unknown };
}

export interface McpVerdict {
  /** May the call proceed? */
  allow: boolean;
  /** False when the tool does not declare `coaz: true` — apply your own rules. */
  coazTool: boolean;
  verdict: Verdict;
  /** The JSON-RPC error body to return verbatim (HTTP 200) when `allow` is false. */
  jsonRpcError?: JsonRpcErrorResponse;
  /** What was sent to the PDP, for transcripts and tests. */
  pdpRequest?: EvaluationRequest | EvaluationsRequest;
}

export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data?: Record<string, unknown> };
}

export interface McpGuardOptions {
  client: AuthzenClient | AuthzenClientOptions;
  /**
   * The tool definitions. Pass them directly when this process IS the MCP server —
   * it already knows its tools, and discovery would only be a round trip to itself.
   */
  tools?: ToolDefinition[] | (() => ToolDefinition[] | Promise<ToolDefinition[]>);
  /**
   * MCP streamable-HTTP endpoint to discover tools from, when acting as a gateway in
   * front of someone else's server. Ignored when `tools` is set.
   */
  upstreamUrl?: string;
  /** How long a discovered tools/list is reused. Default 60s. */
  discoveryTtlMs?: number;
  /** Headers for the discovery call (auth to the upstream MCP server). */
  discoveryHeaders?: Record<string, string>;
  /** Label for this PEP in challenges and logs. */
  pep?: string;
  /**
   * Hand the whole check to a running Go `coaz-pep` (this repo's `core/`) over its HTTP
   * check API. Use this when a mapping needs CEL beyond the subset above — it is exactly
   * what the Kong plugin does, and for the same reason. Requires `raw` on each check.
   */
  delegate?: {
    /** Base URL of the coaz-pep HTTP check API, e.g. `http://coaz-pep:9192`. */
    url: string;
    /** Per-route knobs, the same map the ext_authz `context_extensions` carries. */
    config?: Record<string, string>;
    timeoutMs?: number;
  };
  fetch?: typeof globalThis.fetch;
  onDecision?: (info: { tool: string; verdict: Verdict }) => void;
}

export class McpGuard {
  private readonly client: AuthzenClient;
  private readonly pep: string;
  private readonly ttl: number;
  private readonly fetchImpl: typeof globalThis.fetch;
  private cache: { at: number; tools: Map<string, ToolDefinition> } | null = null;

  constructor(private readonly opts: McpGuardOptions) {
    this.client = opts.client instanceof AuthzenClient ? opts.client : new AuthzenClient(opts.client);
    this.pep = opts.pep ?? 'mcp-edge';
    this.ttl = opts.discoveryTtlMs ?? 60_000;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (!opts.tools && !opts.upstreamUrl && !opts.delegate) {
      throw new Error('McpGuard needs `tools`, `upstreamUrl`, or `delegate`');
    }
  }

  /**
   * Run the COAZ flow for one `tools/call`. Never throws — every failure is a verdict
   * with the JSON-RPC error the profile mandates.
   */
  async checkToolCall(args: {
    rpc: JsonRpcRequest;
    claims: PepClaims | Record<string, unknown>;
    /** Context the mapping cannot derive itself (a user token's scope, a channel). */
    extraContext?: Record<string, unknown>;
    /** The untouched HTTP request. Required when `delegate` is configured. */
    raw?: { method?: string; path?: string; headers: Record<string, string>; body: string };
  }): Promise<McpVerdict> {
    const { rpc } = args;
    const id = rpc.id ?? null;
    const toolName = rpc.params?.name ?? '';
    const token = isPepClaims(args.claims) ? args.claims.raw : (args.claims as Record<string, unknown>);

    if (rpc.method !== 'tools/call' || !toolName) {
      // Not a tool call — not this guard's business.
      return { allow: true, coazTool: false, verdict: { allow: true, kind: 'ok', reason: 'not a tools/call' } };
    }

    if (this.opts.delegate) {
      if (!args.raw) {
        return this.fail(id, CODE_MAPPING_ERROR, 'mapping_error',
          'delegate mode needs the raw request (headers + body) to forward');
      }
      return this.checkViaDelegate(id, toolName, args.raw);
    }

    let tool: ToolDefinition | undefined;
    try {
      tool = (await this.resolveTools()).get(toolName);
    } catch (err) {
      return this.fail(id, CODE_PDP_ERROR, 'pdp_error', `Tool discovery failed: ${message(err)}`);
    }

    if (!tool?.coaz) {
      return {
        allow: true,
        coazTool: false,
        verdict: { allow: true, kind: 'ok', reason: `${toolName} does not declare coaz:true` },
      };
    }

    const mapping = tool['x-coaz-mapping'];
    if (!mapping) {
      return this.fail(id, CODE_MAPPING_ERROR, 'mapping_error', `${toolName} declares coaz:true but has no x-coaz-mapping`);
    }

    let built: BuiltRequest;
    try {
      // `params` binds to the whole JSON-RPC params member, so mappings read
      // `params.arguments.id` — matching the profile and the Go engine in core/.
      built = buildRequest(toolName, mapping, (rpc.params ?? {}) as Record<string, unknown>, token, args.extraContext);
    } catch (err) {
      return this.fail(id, CODE_MAPPING_ERROR, 'mapping_error', message(err));
    }

    const verdict = built.batch
      ? await this.client.evaluateAll(built.body as EvaluationsRequest)
      : await this.client.evaluate(built.body as EvaluationRequest);

    this.report(toolName, verdict);

    if (verdict.allow) {
      return { allow: true, coazTool: true, verdict, pdpRequest: built.body };
    }
    const code = verdict.kind === 'pdp_error' ? CODE_PDP_ERROR : CODE_DENIED;
    return {
      allow: false,
      coazTool: true,
      verdict,
      pdpRequest: built.body,
      jsonRpcError: jsonRpcError(id, code, verdict.reason, this.challengeData(verdict)),
    };
  }

  /**
   * Wrap an MCP tool handler so a deny short-circuits it. The wrapper returns the
   * JSON-RPC error response, which a streamable-HTTP transport sends with HTTP 200.
   */
  wrap<T>(
    handler: (rpc: JsonRpcRequest) => Promise<T>,
  ): (
    rpc: JsonRpcRequest,
    claims: PepClaims | Record<string, unknown>,
    opts?: { extraContext?: Record<string, unknown>; raw?: { method?: string; path?: string; headers: Record<string, string>; body: string } },
  ) => Promise<T | JsonRpcErrorResponse> {
    return async (rpc, claims, o) => {
      const v = await this.checkToolCall({ rpc, claims, ...(o?.extraContext ? { extraContext: o.extraContext } : {}), ...(o?.raw ? { raw: o.raw } : {}) });
      if (!v.allow && v.jsonRpcError) return v.jsonRpcError;
      return handler(rpc);
    };
  }

  /** Force the next check to re-discover. */
  invalidate(): void {
    this.cache = null;
  }

  private challengeData(verdict: Verdict): Record<string, unknown> | undefined {
    const challenge = toChallenge(verdict, this.pep);
    return challenge ? { authz_challenge: challenge } : undefined;
  }

  private fail(id: string | number | null, code: number, kind: Verdict['kind'], reason: string): McpVerdict {
    const verdict: Verdict = { allow: false, kind, reason };
    return { allow: false, coazTool: true, verdict, jsonRpcError: jsonRpcError(id, code, reason) };
  }

  private report(tool: string, verdict: Verdict): void {
    if (!this.opts.onDecision) return;
    try {
      this.opts.onDecision({ tool, verdict });
    } catch {
      /* a broken audit hook must not open the gate */
    }
  }

  /**
   * Forward to the Go engine's HTTP check API and relay its verdict. On a deny the
   * engine has already rendered the profile's JSON-RPC error body, so it is passed
   * through verbatim rather than re-derived here — two renderings would drift.
   */
  private async checkViaDelegate(
    id: string | number | null,
    toolName: string,
    raw: { method?: string; path?: string; headers: Record<string, string>; body: string },
  ): Promise<McpVerdict> {
    const d = this.opts.delegate!;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), d.timeoutMs ?? 2000);
    try {
      const res = await this.fetchImpl(`${d.url.replace(/\/+$/, '')}/v1/mcp/check`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          config: { pep_label: this.pep, style: 'mcp', ...d.config },
          method: raw.method ?? 'POST',
          path: raw.path ?? '/mcp',
          headers: raw.headers,
          body: raw.body,
        }),
        signal: controller.signal,
      });
      if (!res.ok) {
        return this.fail(id, CODE_PDP_ERROR, 'pdp_error', `coaz-pep check returned ${res.status}`);
      }
      const out = (await res.json()) as {
        decision?: boolean;
        response?: { status?: number; body?: string };
      };
      if (out.decision) {
        const verdict: Verdict = { allow: true, kind: 'ok', reason: 'permit (delegated)' };
        this.report(toolName, verdict);
        return { allow: true, coazTool: true, verdict };
      }
      const relayed = safeJson(out.response?.body ?? '') as JsonRpcErrorResponse | null;
      const reason = relayed?.error?.message ?? 'Access denied.';
      const verdict: Verdict = { allow: false, kind: 'denied', reason };
      this.report(toolName, verdict);
      return {
        allow: false,
        coazTool: true,
        verdict,
        jsonRpcError: relayed ?? jsonRpcError(id, CODE_DENIED, reason),
      };
    } catch (err) {
      const why = err instanceof Error && err.name === 'AbortError' ? 'coaz-pep check timed out' : message(err);
      return this.fail(id, CODE_PDP_ERROR, 'pdp_error', why);
    } finally {
      clearTimeout(timer);
    }
  }

  private async resolveTools(): Promise<Map<string, ToolDefinition>> {
    if (this.opts.tools) {
      const list = typeof this.opts.tools === 'function' ? await this.opts.tools() : this.opts.tools;
      return new Map(list.map((t) => [t.name, t]));
    }
    const now = Date.now();
    if (this.cache && now - this.cache.at < this.ttl) return this.cache.tools;
    const list = await this.discover();
    this.cache = { at: now, tools: new Map(list.map((t) => [t.name, t])) };
    return this.cache.tools;
  }

  /** `tools/list` over MCP streamable HTTP. Handles both a JSON body and an SSE stream. */
  private async discover(): Promise<ToolDefinition[]> {
    const res = await this.fetchImpl(this.opts.upstreamUrl!, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...this.opts.discoveryHeaders,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'coaz-discovery', method: 'tools/list', params: {} }),
    });
    if (!res.ok) throw new Error(`tools/list returned ${res.status}`);
    const text = await res.text();
    const payload = (res.headers.get('content-type') ?? '').includes('text/event-stream')
      ? parseSse(text)
      : safeJson(text);
    const tools = (payload as { result?: { tools?: ToolDefinition[] } } | null)?.result?.tools;
    if (!Array.isArray(tools)) throw new Error('tools/list response carried no result.tools array');
    return tools;
  }
}

// ---------------------------------------------------------------------------
// The profile's processing rules
// ---------------------------------------------------------------------------

interface BuiltRequest {
  batch: boolean;
  body: EvaluationRequest | EvaluationsRequest;
}

/**
 * Evaluate a mapping and assemble the AuthZEN request:
 *  - every field single-element -> the evaluation API, fields at the top level;
 *  - any field multi-element    -> the evaluations API, single-element fields sitting at
 *    the top level as defaults and multi-element fields zipped element-wise.
 */
export function buildRequest(
  toolName: string,
  mapping: CoazMapping,
  params: Record<string, unknown>,
  token: Record<string, unknown>,
  extraContext?: Record<string, unknown>,
): BuiltRequest {
  if (!Array.isArray(mapping.subject) || mapping.subject.length === 0) {
    throw new Error('x-coaz-mapping.subject is required');
  }
  if (!Array.isArray(mapping.resource) || mapping.resource.length === 0) {
    throw new Error('x-coaz-mapping.resource is required');
  }
  if (!Array.isArray(mapping.context) || mapping.context.length === 0) {
    throw new Error('x-coaz-mapping.context is required');
  }

  // "At least one field across subject and context MUST be derived from the token input
  // variable." Without it the mapping could authorise a request nobody authenticated.
  const derivesFromToken = [...mapping.subject, ...mapping.context].some(usesToken);
  if (!derivesFromToken) {
    throw new Error('no subject or context field is derived from the token input variable');
  }

  const evalField = (elements: MappingElement[], field: string): unknown[] =>
    elements.map((el, i) => {
      try {
        return evaluateNode(el, params, token);
      } catch (err) {
        throw new Error(`${field}[${i}]: ${message(err)}`);
      }
    });

  const subject = evalField(mapping.subject, 'subject');
  const resource = evalField(mapping.resource, 'resource');
  const context = evalField(mapping.context, 'context');
  // A missing action means a single-element `{"name": "<tool name>"}`.
  const action = mapping.action?.length ? evalField(mapping.action, 'action') : [{ name: toolName }];

  // Gateway-supplied context fills only keys the mapping did not set, so a declared
  // mapping always wins over an ambient default.
  if (extraContext && Object.keys(extraContext).length > 0) {
    for (const c of context) {
      if (!isObject(c)) continue;
      for (const [k, v] of Object.entries(extraContext)) {
        if (!(k in c)) c[k] = v;
      }
    }
  }

  const fields: Array<[string, unknown[]]> = [
    ['subject', subject],
    ['action', action],
    ['resource', resource],
    ['context', context],
  ];

  let batchLen = 1;
  for (const [, values] of fields) {
    if (values.length > 1) {
      if (batchLen !== 1 && values.length !== batchLen) {
        throw new Error('multi-valued mapping fields have mismatched element counts');
      }
      batchLen = values.length;
    }
  }

  if (batchLen === 1) {
    const body: Record<string, unknown> = {};
    for (const [name, values] of fields) body[name] = values[0];
    return { batch: false, body: body as unknown as EvaluationRequest };
  }

  const evaluations: Array<Record<string, unknown>> = Array.from({ length: batchLen }, () => ({}));
  const body: Record<string, unknown> = {};
  for (const [name, values] of fields) {
    if (values.length === 1) {
      body[name] = values[0];
    } else {
      values.forEach((v, i) => {
        evaluations[i]![name] = v;
      });
    }
  }
  body['evaluations'] = evaluations;
  return { batch: true, body: body as unknown as EvaluationsRequest };
}

function usesToken(node: unknown): boolean {
  if (typeof node === 'string') return /(^|[^A-Za-z0-9_])token\s*[.[]/.test(node);
  if (Array.isArray(node)) return node.some(usesToken);
  if (isObject(node)) return Object.values(node).some(usesToken);
  return false;
}

/** Walk a mapping element, replacing every string leaf with its evaluated value. */
function evaluateNode(node: unknown, params: Record<string, unknown>, token: Record<string, unknown>): unknown {
  if (typeof node === 'string') return evaluateExpression(node, params, token);
  if (Array.isArray(node)) return node.map((n) => evaluateNode(n, params, token));
  if (isObject(node)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) out[k] = evaluateNode(v, params, token);
    return out;
  }
  return node;
}

/**
 * The supported expression subset. Anything else throws, so an unsupported mapping is a
 * loud -32602 rather than a quiet wrong answer.
 *
 *   'literal'  "literal"        string literals
 *   123  1.5  true  false  null  scalars
 *   params.a.b   params["a"]    tool arguments
 *   token.sub    token.act.sub  token claims
 *   string(x)  int(x)  double(x)
 *   a + b + 'c'                 concatenation / addition
 */
export function evaluateExpression(
  expr: string,
  params: Record<string, unknown>,
  token: Record<string, unknown>,
): unknown {
  const terms = splitTopLevel(expr.trim(), '+');
  if (terms.length === 0) throw new Error(`empty expression`);
  const values = terms.map((t) => evaluateTerm(t.trim(), params, token));
  if (values.length === 1) return values[0];
  // `+` over a mixed list is string concatenation; over all-numbers it is addition.
  if (values.every((v) => typeof v === 'number')) {
    return (values as number[]).reduce((a, b) => a + b, 0);
  }
  return values.map((v) => (v === null || v === undefined ? '' : String(v))).join('');
}

function evaluateTerm(term: string, params: Record<string, unknown>, token: Record<string, unknown>): unknown {
  if (term === 'true') return true;
  if (term === 'false') return false;
  if (term === 'null') return null;
  if (/^-?\d+$/.test(term)) return Number.parseInt(term, 10);
  if (/^-?\d*\.\d+$/.test(term)) return Number.parseFloat(term);

  const quoted = /^'((?:[^'\\]|\\.)*)'$|^"((?:[^"\\]|\\.)*)"$/.exec(term);
  if (quoted) return unescape(quoted[1] ?? quoted[2] ?? '');

  const cast = /^(string|int|double)\s*\((.*)\)$/s.exec(term);
  if (cast) {
    const inner = evaluateExpression(cast[2]!, params, token);
    switch (cast[1]) {
      case 'string':
        return inner === null || inner === undefined ? '' : String(inner);
      case 'int': {
        const n = Number.parseInt(String(inner), 10);
        if (Number.isNaN(n)) throw new Error(`int(${cast[2]}) is not an integer`);
        return n;
      }
      default: {
        const n = Number.parseFloat(String(inner));
        if (Number.isNaN(n)) throw new Error(`double(${cast[2]}) is not a number`);
        return n;
      }
    }
  }

  const pathMatch = /^(params|token)((?:\.[A-Za-z_$][\w$]*|\[(?:'[^']*'|"[^"]*")\])*)$/.exec(term);
  if (pathMatch) {
    const root = pathMatch[1] === 'params' ? params : token;
    return readPath(root, pathMatch[2] ?? '');
  }

  throw new Error(
    `unsupported expression: ${term} — this SDK evaluates a documented CEL subset; ` +
      `use the Go engine in core/ for full CEL`,
  );
}

function readPath(root: Record<string, unknown>, accessors: string): unknown {
  let cur: unknown = root;
  const re = /\.([A-Za-z_$][\w$]*)|\['([^']*)'\]|\["([^"]*)"\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(accessors)) !== null) {
    const key = m[1] ?? m[2] ?? m[3] ?? '';
    if (!isObject(cur)) return undefined;
    cur = cur[key];
    // Some ASes serialise object claims as JSON strings (PingFederate's `act`); decode
    // so `token.act.sub` resolves rather than silently yielding undefined.
    if (typeof cur === 'string' && cur.trim().startsWith('{')) {
      const parsed = safeJson(cur);
      if (isObject(parsed)) cur = parsed;
    }
  }
  return cur;
}

/** Split on `sep` at nesting/quoting depth zero. */
function splitTopLevel(expr: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    else if (ch === sep && depth === 0) {
      out.push(expr.slice(start, i));
      start = i + 1;
    }
  }
  out.push(expr.slice(start));
  return out.filter((s) => s.trim() !== '');
}

function unescape(s: string): string {
  return s.replace(/\\(.)/g, '$1');
}

export function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: Record<string, unknown>,
): JsonRpcErrorResponse {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } };
}

/** Last `data:` payload of an SSE stream that parses as JSON. */
function parseSse(text: string): unknown {
  let last: unknown = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith('data:')) continue;
    const parsed = safeJson(line.slice(5).trim());
    if (parsed !== null) last = parsed;
  }
  return last;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Tell a PepClaims from a bare claims map. Checks several PepClaims-only fields, because
 * a token that happens to carry a `raw` claim would otherwise be unwrapped into nothing.
 */
function isPepClaims(v: unknown): v is PepClaims {
  return isObject(v) && 'raw' in v && 'actor' in v && 'jkt' in v && isObject(v['raw']);
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

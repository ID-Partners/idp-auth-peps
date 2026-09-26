/**
 * COAZ — the OpenID AuthZEN MCP profile — for Node MCP servers and gateways.
 *
 * Spec: https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md
 *
 * A tool declares how its call becomes an AuthZEN request in its `inputSchema`
 * (`x-authzen-mapping`; the superseded v1 form is `coaz: true` + `x-coaz-mapping`).
 * Mapping leaves are expressions over two input variables: `params` (the JSON-RPC
 * `params` member — so arguments are at `params.arguments.x`) and `token` (the caller's
 * claims). This guard reads the message, builds the request, asks the PDP, and enforces
 * the answer with the profile's JSON-RPC semantics:
 *
 *   -32001  the PDP denied            (carries `data.authz_challenge` when resolvable;
 *                                      -32401 for a tool still declared against v1)
 *   -32602  the mapping could not be evaluated
 *   -32603  the PDP could not be reached — fail closed
 *   -32600  the message is not one the PEP will read (HTTP 400; 415 for an encoding)
 *   -32700  the body is not JSON (HTTP 400)
 *
 * Every MCP method is governed: the binding's default mapping applies wherever no
 * declaration does, `ping`, notifications, server-initiated methods and JSON-RPC
 * responses pass through, and anything else is denied. `applyDefaultMappings: false`
 * restores the old pass-through for methods other than a declared tool's call.
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

import { AuthzenClient, PDP_UNAVAILABLE_REASON, type AuthzenClientOptions } from './client.js';
import { toChallenge } from './challenge.js';
import { extractClaims, type PepClaims } from './claims.js';
import { sanitizeHeaderValue } from './http.js';
import { CODE_INVALID_REQUEST, CODE_PARSE_ERROR, parseBody, readMessage, type RpcId, type RpcRefusal } from './jsonrpc.js';
import type { EvaluationRequest, EvaluationsRequest, Verdict } from './types.js';

export { CODE_INVALID_REQUEST, CODE_PARSE_ERROR };

/**
 * JSON-RPC error codes.
 *
 * v2 says of -32401: "a code outside that range, such as -32401, is non-conformant with
 * JSON-RPC and MUST NOT be used". It is emitted only for tools still declared against
 * the superseded v1 profile, whose clients may string-match on it.
 */
export const CODE_DENIED_V2 = -32001;
/** @deprecated v1 only — superseded by {@link CODE_DENIED_V2}. */
export const CODE_DENIED = -32401;
export const CODE_MAPPING_ERROR = -32602;
export const CODE_PDP_ERROR = -32603;

/** Which COAZ draft a tool's mapping is written against. */
export type Dialect = 'v1' | 'v2';

/**
 * A v2 mapping: an envelope with exactly one member naming the AuthZEN API to call.
 * The envelope alone decides single vs boxcar — a list value never fans out.
 */
export type AuthzenMapping =
  | { evaluation: Record<string, unknown>; evaluations?: never }
  | { evaluations: Record<string, unknown>; evaluation?: never };

/** One AuthZEN object as declared in a mapping: leaves are expressions. */
export type MappingElement = Record<string, unknown>;

export interface CoazMapping {
  subject: MappingElement[];
  action?: MappingElement[];
  resource: MappingElement[];
  context: MappingElement[];
}

/**
 * The subset of an MCP tools/list entry the guard needs.
 *
 * v2 declares by putting `x-authzen-mapping` in the tool's `inputSchema`; there is no
 * marker field. v1's `coaz: true` + `x-coaz-mapping` still works for tools that have not
 * migrated. Both forms are accepted here; `x-authzen-mapping` wins where both appear.
 */
export interface ToolDefinition {
  name: string;
  /** @deprecated v1 only. */
  coaz?: boolean;
  /** @deprecated v1 only — superseded by `inputSchema['x-authzen-mapping']`. */
  'x-coaz-mapping'?: CoazMapping;
  inputSchema?: Record<string, unknown> & { 'x-authzen-mapping'?: AuthzenMapping };
  [key: string]: unknown;
}

/** One default mapping, from the parts that vary between methods. */
function defaultEnvelope(
  action: string,
  resource: Record<string, unknown>,
  extraContext?: Record<string, unknown>,
): AuthzenMapping {
  return {
    evaluation: {
      subject: { type: 'identity', id: '$token.sub' },
      context: { agent: '$token.?client_id', ...extraContext },
      action: { name: action },
      resource,
    },
  };
}

/** This MCP server, identified from the audience-bound token (RFC 8707). */
const SERVER_RESOURCE = { type: 'mcp_server', id: '$token.aud' };

/**
 * The binding's default mapping for an MCP method, or undefined if it defines none.
 *
 * "A PEP MUST apply the default mapping for a method unless a declared mapping applies."
 * Only `ping` and `notifications/*` are pass-through; anything with neither a default nor
 * a declaration MUST be denied, so future MCP methods fail closed.
 */
export function defaultMappingFor(method: string): AuthzenMapping | undefined {
  switch (method) {
    case 'tools/call':
      return defaultEnvelope(method, { type: 'tool', id: '$params.name' });
    case 'tools/list':
    case 'resources/list':
    case 'prompts/list':
    case 'tasks/list':
      return defaultEnvelope(method, { ...SERVER_RESOURCE });
    case 'resources/read':
    case 'resources/subscribe':
    case 'resources/unsubscribe':
      return defaultEnvelope(method, { type: 'resource', id: '$params.uri' });
    case 'prompts/get':
      return defaultEnvelope(method, { type: 'prompt', id: '$params.name' });
    case 'completion/complete':
      // SPEC INCONSISTENCY, reported upstream: the binding prints this with a `$` on
      // every reference, but the framework strips only the LEADING `$` and says a `$`
      // elsewhere has no special meaning — so the printed form is not valid CEL. Written
      // here the way the framework's rule requires.
      return defaultEnvelope(method, {
        type: "$params.ref.type == 'ref/prompt' ? 'prompt' : 'resource'",
        id: "$params.ref.type == 'ref/prompt' ? params.ref.name : params.ref.uri",
      });
    case 'logging/setLevel':
      return defaultEnvelope(method, { ...SERVER_RESOURCE }, { level: '$params.level' });
    case 'tasks/get':
    case 'tasks/result':
    case 'tasks/cancel':
      return defaultEnvelope(method, { type: 'task', id: '$params.taskId' });
    case 'initialize':
      // DELIBERATE DEVIATION. `initialize` appears nowhere in the binding, so the
      // Unknown Methods rule would deny it — which denies every MCP handshake. Reads as
      // a gap in the draft. Governed like the other server-scoped methods instead of
      // either breaking the protocol or leaving the handshake unauthorized.
      return defaultEnvelope(method, { ...SERVER_RESOURCE });
    default:
      return undefined;
  }
}

/** Kept as a named entry point; `defaultMappingFor` is the source of truth. */
export function defaultToolsCallMapping(): AuthzenMapping {
  return defaultMappingFor('tools/call')!;
}

/** "The PEP MUST NOT call the PDP for them and MUST allow them to proceed." */
export function isPassThroughMethod(method: string): boolean {
  return method === 'ping' || method.startsWith('notifications/');
}

/**
 * Server-initiated requests, which the binding puts out of scope: they would be
 * authorized with the client's token, "which is not the appropriate identity".
 */
export function isServerInitiatedMethod(method: string): boolean {
  return method === 'sampling/createMessage' || method === 'elicitation/create' || method === 'roots/list';
}

/** The token claim `subject.id` anchors to. */
const SUBJECT_IDENTITY_CLAIM = 'sub';
const DEFAULT_SUBJECT_EXPR = `$token.${SUBJECT_IDENTITY_CLAIM}`;
/** The subject type the binding's own default mappings use. */
const DEFAULT_SUBJECT_TYPE = 'identity';

/** A JSON-RPC 2.0 request, as the guard reads it once it has passed the checks in jsonrpc.ts. */
export interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: { name?: string; arguments?: Record<string, unknown>; [key: string]: unknown };
}

/** An HTTP response to send as it is: status, headers and body. */
export interface McpHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface McpVerdict {
  /** May the call proceed? Only `true` means yes. */
  allow: boolean;
  /** True when a mapping — declared or default — was evaluated, or the call was refused. */
  coazTool: boolean;
  verdict: Verdict;
  /** On deny: the JSON-RPC error, which is also the body of `response`. */
  jsonRpcError?: JsonRpcErrorResponse;
  /**
   * On deny: the whole HTTP response to send, verbatim. A policy deny is HTTP 200 with
   * the JSON-RPC error (the profile's rule); a message the PEP will not read is 400 (415
   * for a Content-Encoding); in delegate mode it is whatever coaz-pep rendered, a 401
   * challenge included.
   */
  response?: McpHttpResponse;
  /**
   * On permit: headers to set on the request forwarded upstream — the identity this PEP
   * asserts. An empty value means remove the header: a client's own copy must not
   * survive to the upstream.
   */
  upstreamHeaders?: Record<string, string>;
  /** On permit: headers to add to the client's response (`X-PDP-Fail-Open` among them). */
  responseHeaders?: Record<string, string>;
  /** The JSON-RPC message that was judged. */
  message?: JsonRpcRequest;
  /** What was sent to the PDP, for transcripts and tests. */
  pdpRequest?: EvaluationRequest | EvaluationsRequest;
}

export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data?: Record<string, unknown> };
}

/** The untouched HTTP request, as the guard reads it. */
export interface McpRawRequest {
  method?: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  /** The body exactly as received. Bytes let the guard refuse invalid UTF-8 as well. */
  body: string | Uint8Array;
}

/** One check. */
export interface McpCheckArgs {
  /** The parsed JSON-RPC message. Optional when `raw` is given; checked against it when both are. */
  rpc?: unknown;
  /** The caller's claims — verified by you: the guard never decodes a token. */
  claims?: PepClaims | Record<string, unknown>;
  /** Context the mapping cannot derive itself (a user token's scope, a channel). */
  extraContext?: Record<string, unknown>;
  /**
   * The untouched HTTP request. Required in delegate mode. In local mode, pass it to have
   * the bytes judged: exact duplicate keys, a byte-order mark, trailing data and a
   * Content-Encoding are only visible here.
   */
  raw?: McpRawRequest;
  /** The raw access token, forwarded to the PDP when `forwardAccessToken` is on. */
  accessToken?: string;
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
   * Govern every method with the binding's default mappings, as it requires: "A PEP
   * MUST apply the default mapping for a method unless a declared mapping applies."
   * Default true. Only an explicit `false` opts out, which restores the old pass-through
   * for tools that declare no mapping and for methods other than tools/call — not
   * conformant, and a change you should time rather than discover.
   */
  applyDefaultMappings?: boolean;
  /**
   * Called for conditions worth surfacing but not failing on — chiefly a declared
   * mapping that overrides `subject.id`, where the identity is then asserted by the
   * mapping author rather than anchored to the token. Defaults to `console.warn`.
   */
  onWarning?: (message: string) => void;
  /**
   * Hand the whole check to a running Go `coaz-pep` (this repo's `core/`) over its HTTP
   * check API. Use this when a mapping needs CEL beyond the subset above — it is exactly
   * what the Kong plugin does, and for the same reason. Requires `raw` on each check.
   */
  delegate?: {
    /** Base URL of the coaz-pep HTTP check API, e.g. `http://coaz-pep:9192`. */
    url: string;
    /**
     * Shared secret for that endpoint — its `CHECK_API_TOKEN`. Set it: the endpoint
     * takes a caller-supplied upstream URL and relays a caller-supplied Authorization
     * header, so it authenticates its callers.
     */
    apiKey?: string;
    /** Per-route knobs, the same map the ext_authz `context_extensions` carries. */
    config?: Record<string, string>;
    timeoutMs?: number;
  };
  fetch?: typeof globalThis.fetch;
  onDecision?: (info: { tool: string; verdict: Verdict }) => void;
  /**
   * The MCP server's identifier (RFC 8707), which PDP discovery starts from when the
   * client has it enabled. Defaults to `upstreamUrl`; passed to `coaz-pep` in delegate
   * mode so both PEPs key off one identifier. Also how the guard picks this server out of
   * a token whose `aud` names several.
   */
  resource?: string;
  /**
   * Forward the raw access token to the PDP as `context.access_token` (pass it per call
   * as `accessToken`). Default false: only when the PDP connection is TLS and
   * authenticated. In delegate mode the flag is passed to coaz-pep instead.
   */
  forwardAccessToken?: boolean;
  /** Overrides the client's `failMode` for this guard. In delegate mode it is passed to coaz-pep. */
  failMode?: 'open' | 'closed';
}

/** The methods whose default mapping names this MCP server from the token's `aud`. */
const SERVER_SCOPED_METHODS = new Set(['tools/list', 'resources/list', 'prompts/list', 'tasks/list', 'logging/setLevel', 'initialize']);

/** The identity headers a PEP asserts upstream, and removes when a client sends them. */
const AUTH_HEADERS = ['X-Auth-Principal', 'X-Auth-Agent', 'X-Auth-Scope', 'X-Auth-Acr'] as const;

export class McpGuard {
  private readonly client: AuthzenClient;
  private readonly pep: string;
  private readonly ttl: number;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly defaults: boolean;
  private cache: { at: number; tools: Map<string, ToolDefinition> } | null = null;

  private readonly resource: string | undefined;

  constructor(private readonly opts: McpGuardOptions) {
    this.client = opts.client instanceof AuthzenClient ? opts.client : new AuthzenClient(opts.client);
    this.pep = opts.pep ?? 'mcp-edge';
    this.resource = opts.resource ?? opts.upstreamUrl;
    this.ttl = opts.discoveryTtlMs ?? 60_000;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.defaults = opts.applyDefaultMappings !== false;
    if (!opts.tools && !opts.upstreamUrl && !opts.delegate) {
      throw new Error('McpGuard needs `tools`, `upstreamUrl`, or `delegate`');
    }
  }

  /**
   * Judge one MCP message. Never throws — every failure is a verdict carrying the
   * JSON-RPC error and the HTTP response to send.
   */
  async checkToolCall(args: McpCheckArgs): Promise<McpVerdict> {
    try {
      return await this.check(args ?? {});
    } catch (err) {
      // A guard that throws is a guard that is open.
      return this.deny(null, CODE_PDP_ERROR, { allow: false, kind: 'pdp_error', reason: PDP_UNAVAILABLE_REASON, detail: message(err) }, '');
    }
  }

  /**
   * Wrap an MCP handler so only an explicit allow runs it. Anything else returns the
   * JSON-RPC error, which a streamable-HTTP transport sends with HTTP 200 — for the
   * status and headers of a refusal or a delegated challenge, use `checkToolCall` and
   * send `verdict.response`. The handler receives the judged message and the verdict,
   * whose `upstreamHeaders` a gateway applies to what it forwards.
   */
  wrap<T>(
    handler: (rpc: JsonRpcRequest, verdict: McpVerdict) => Promise<T>,
  ): (rpc: unknown, claims?: PepClaims | Record<string, unknown>, opts?: Omit<McpCheckArgs, 'rpc' | 'claims'>) => Promise<T | JsonRpcErrorResponse> {
    return async (rpc, claims, o) => {
      const v = await this.checkToolCall({ ...(o ?? {}), rpc, ...(claims !== undefined ? { claims } : {}) });
      if (v.allow !== true) return v.jsonRpcError ?? jsonRpcError(null, CODE_PDP_ERROR, v.verdict.reason || PDP_UNAVAILABLE_REASON);
      return handler(v.message ?? (rpc as JsonRpcRequest), v);
    };
  }

  /** Force the next check to re-discover. */
  invalidate(): void {
    this.cache = null;
  }

  private async check(args: McpCheckArgs): Promise<McpVerdict> {
    const token = claimsMap(args.claims);

    let value: unknown = args.rpc;
    if (args.raw && !this.opts.delegate) {
      const parsed = parseBody(args.raw.body, args.raw.headers);
      if (!parsed.ok) return this.refuse(parsed.refusal, '');
      // The rpc a caller hands the handler must be the message that was judged.
      if (args.rpc !== undefined && !sameJson(args.rpc, parsed.value)) {
        return this.refuse({ status: 400, code: CODE_INVALID_REQUEST, message: 'Invalid Request: the parsed request does not match the raw body', id: null }, '');
      }
      value = parsed.value;
    }
    const read = readMessage(value);
    if (read.kind === 'refused') return this.refuse(read.refusal, '');
    if (read.kind === 'response') {
      return this.permit({ allow: true, kind: 'ok', reason: 'JSON-RPC response: passed through' }, token, read.message, false, '');
    }
    const { method, id } = read;
    const params = read.params ?? {};
    const rpc = read.message as JsonRpcRequest;

    if (method !== 'tools/call') {
      // Every other method is governed by its own default mapping. tools/call is not
      // special — it is merely the one that can also be declared per tool.
      if (isPassThroughMethod(method)) return this.permit({ allow: true, kind: 'ok', reason: `pass-through: ${method}` }, token, rpc, false, method);
      if (isServerInitiatedMethod(method)) {
        return this.permit({ allow: true, kind: 'ok', reason: `server-initiated, out of scope: ${method}` }, token, rpc, false, method);
      }
      if (!this.defaults) return this.permit({ allow: true, kind: 'ok', reason: `defaults disabled: ${method}` }, token, rpc, false, method);
      const def = defaultMappingFor(method);
      if (!def) {
        // "MUST be denied ... so that methods introduced by future MCP versions or
        // extensions fail closed rather than bypassing authorization."
        return this.deny(id, CODE_DENIED_V2, { allow: false, kind: 'denied', reason: `Method not permitted: ${method}` }, method, rpc);
      }
      return this.checkAgainst(id, def, rpc, params, token, args, CODE_DENIED_V2, method);
    }

    const toolName = params['name'] as string;
    if (this.opts.delegate) {
      if (!args.raw) {
        return this.deny(id, CODE_MAPPING_ERROR, { allow: false, kind: 'mapping_error', reason: 'delegate mode needs the raw request (headers + body) to forward' }, toolName, rpc);
      }
      return this.checkViaDelegate(id, toolName, args.raw, token, rpc);
    }

    let tool: ToolDefinition | undefined;
    try {
      tool = (await this.resolveTools()).get(toolName);
    } catch (err) {
      return this.deny(id, CODE_PDP_ERROR, { allow: false, kind: 'pdp_error', reason: PDP_UNAVAILABLE_REASON, detail: `tool discovery failed: ${message(err)}` }, toolName, rpc);
    }

    // v2 first: `x-authzen-mapping` in the inputSchema is the current declaration and
    // has no marker field, so its presence is what selects the dialect. v1's
    // `coaz: true` only still matters for tools that have not migrated.
    const v2Mapping = tool?.inputSchema?.['x-authzen-mapping'];
    const dialect: Dialect = v2Mapping ? 'v2' : 'v1';
    const deniedCode = dialect === 'v2' ? CODE_DENIED_V2 : CODE_DENIED;

    if (!v2Mapping && !tool?.coaz) {
      if (!this.defaults) {
        return this.permit({ allow: true, kind: 'ok', reason: `${toolName} declares no mapping (defaults disabled)` }, token, rpc, false, toolName);
      }
      // Fall through to the binding's default mapping rather than skipping the PDP.
      return this.checkAgainst(id, defaultToolsCallMapping(), rpc, params, token, args, CODE_DENIED_V2, toolName);
    }

    let built: BuiltRequest;
    try {
      if (v2Mapping) {
        // A gateway enforcing a mapping the MCP server authored: if subject.id is not
        // anchored to the token, that server is asserting who the caller is.
        if (!isAnchoredSubject(v2Mapping)) {
          this.warn(
            `tool ${toolName} sets subject.id from a source that cannot be verified against ` +
              `the token; its identity is asserted by the mapping author`,
          );
        }
        // `params` binds to the whole JSON-RPC params member, so mappings read
        // `params.arguments.id` — matching the binding and the Go engine in core/.
        built = buildRequestV2(v2Mapping, params, token, args.extraContext);
      } else {
        const mapping = tool!['x-coaz-mapping'];
        if (!mapping) {
          return this.deny(id, CODE_MAPPING_ERROR, { allow: false, kind: 'mapping_error', reason: `${toolName} declares coaz:true but has no x-coaz-mapping` }, toolName, rpc);
        }
        built = buildRequest(toolName, mapping, params, token, args.extraContext);
      }
    } catch (err) {
      return this.deny(id, CODE_MAPPING_ERROR, { allow: false, kind: 'mapping_error', reason: message(err) }, toolName, rpc);
    }
    return this.decide(id, built, token, args, deniedCode, toolName, rpc);
  }

  private warn(message: string): void {
    try {
      (this.opts.onWarning ?? ((m: string) => console.warn(`[coaz] ${m}`)))(message);
    } catch {
      /* a broken warning sink must not break the check */
    }
  }

  /** What every PDP call carries beyond the mapped request; see client.ts. */
  private evaluateOptions(accessToken?: string) {
    return {
      resource: this.resource,
      ...(this.opts.forwardAccessToken && accessToken ? { accessToken } : {}),
      ...(this.opts.failMode ? { failMode: this.opts.failMode } : {}),
    };
  }

  /** Build from a default mapping, ask the PDP, and render the verdict. */
  private checkAgainst(
    id: RpcId,
    mapping: AuthzenMapping,
    rpc: JsonRpcRequest,
    params: Record<string, unknown>,
    token: Record<string, unknown>,
    args: McpCheckArgs,
    deniedCode: number,
    method: string,
  ): Promise<McpVerdict> | McpVerdict {
    let built: BuiltRequest;
    try {
      built = buildRequestV2(mapping, params, this.tokenFor(method, token), args.extraContext);
    } catch (err) {
      return this.deny(id, CODE_MAPPING_ERROR, { allow: false, kind: 'mapping_error', reason: message(err) }, method, rpc);
    }
    return this.decide(id, built, token, args, deniedCode, method, rpc);
  }

  /** Ask the PDP the built question and render its answer. */
  private async decide(
    id: RpcId,
    built: BuiltRequest,
    token: Record<string, unknown>,
    args: McpCheckArgs,
    deniedCode: number,
    tool: string,
    rpc: JsonRpcRequest,
  ): Promise<McpVerdict> {
    const verdict = built.batch
      ? await this.client.evaluateAll(built.body as EvaluationsRequest, this.evaluateOptions(args.accessToken))
      : await this.client.evaluate(built.body as EvaluationRequest, this.evaluateOptions(args.accessToken));
    if (verdict.allow === true) return { ...this.permit(verdict, token, rpc, true, tool), pdpRequest: built.body };
    const code = verdict.kind === 'pdp_error' ? CODE_PDP_ERROR : deniedCode;
    return { ...this.deny(id, code, verdict, tool, rpc), pdpRequest: built.body };
  }

  /**
   * The token a default mapping reads. A server-scoped default names this server from
   * `aud`, which RFC 7519 lets be an array: pick the entry that is this server's own
   * identifier, or the only entry there is. An array it cannot choose from is a mapping
   * error — `resource.id` must name one server, not a list of them.
   */
  private tokenFor(method: string, token: Record<string, unknown>): Record<string, unknown> {
    const aud = token['aud'];
    if (!SERVER_SCOPED_METHODS.has(method) || !Array.isArray(aud)) return token;
    const auds = aud.filter((a): a is string => typeof a === 'string' && a !== '');
    const me = this.resource?.replace(/\/+$/, '');
    const mine = me ? auds.find((a) => a.replace(/\/+$/, '') === me) : undefined;
    if (mine !== undefined) return { ...token, aud: mine };
    if (auds.length === 1) return { ...token, aud: auds[0] };
    throw new Error(`the token's aud names ${auds.length} audiences and none is this server's identifier (set \`resource\`)`);
  }

  private challengeData(verdict: Verdict): Record<string, unknown> | undefined {
    const challenge = toChallenge(verdict, this.pep);
    return challenge ? { authz_challenge: challenge } : undefined;
  }

  /** A permit: the identity to assert upstream, and the fail-open marker when layers were skipped. */
  private permit(verdict: Verdict, token: Record<string, unknown>, rpc: JsonRpcRequest, coazTool: boolean, tool: string): McpVerdict {
    this.report(tool, verdict);
    const failedOpen = verdict.failedOpen ?? [];
    return {
      allow: true,
      coazTool,
      verdict,
      message: rpc,
      upstreamHeaders: assertedHeaders(token),
      ...(failedOpen.length > 0 ? { responseHeaders: { 'X-PDP-Fail-Open': sanitizeHeaderValue(failedOpen.join(', ')) } } : {}),
    };
  }

  /** A deny with the profile's JSON-RPC error, sent with HTTP 200. */
  private deny(id: RpcId, code: number, verdict: Verdict, tool: string, rpc?: JsonRpcRequest): McpVerdict {
    this.report(tool, verdict);
    const error = jsonRpcError(id, code, verdict.reason, code === CODE_PDP_ERROR || code === CODE_MAPPING_ERROR ? undefined : this.challengeData(verdict));
    return { allow: false, coazTool: true, verdict, jsonRpcError: error, response: jsonResponse(200, error), ...(rpc ? { message: rpc } : {}) };
  }

  /** A message the PEP will not read: -32700 or -32600, with the HTTP status the contract gives it. */
  private refuse(r: RpcRefusal, tool: string): McpVerdict {
    const verdict: Verdict = { allow: false, kind: 'mapping_error', reason: r.message };
    this.report(tool, verdict);
    const error = jsonRpcError(r.id, r.code, r.message);
    return { allow: false, coazTool: true, verdict, jsonRpcError: error, response: jsonResponse(r.status, error) };
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
    id: RpcId,
    toolName: string,
    raw: McpRawRequest,
    token: Record<string, unknown>,
    rpc: JsonRpcRequest,
  ): Promise<McpVerdict> {
    const d = this.opts.delegate!;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), d.timeoutMs ?? 2000);
    try {
      const res = await this.fetchImpl(`${d.url.replace(/\/+$/, '')}/v1/mcp/check`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(d.apiKey ? { authorization: `Bearer ${d.apiKey}` } : {}),
        },
        body: JSON.stringify({
          config: {
            pep_label: this.pep,
            style: 'mcp',
            ...(this.opts.resource ? { resource: this.opts.resource } : {}),
            ...(this.opts.forwardAccessToken ? { forward_access_token: 'true' } : {}),
            ...(this.opts.failMode ? { fail_mode: this.opts.failMode } : {}),
            ...d.config,
          },
          method: raw.method ?? 'POST',
          path: raw.path ?? '/mcp',
          headers: raw.headers,
          body: typeof raw.body === 'string' ? raw.body : Buffer.from(raw.body).toString('utf8'),
        }),
        signal: controller.signal,
      });
      if (!res.ok) {
        const hint = res.status === 401 ? ' (set delegate.apiKey to its CHECK_API_TOKEN)' : '';
        return this.deny(id, CODE_PDP_ERROR, { allow: false, kind: 'pdp_error', reason: PDP_UNAVAILABLE_REASON, detail: `coaz-pep check returned ${res.status}${hint}` }, toolName, rpc);
      }
      const out = (await res.json()) as {
        decision?: boolean;
        response?: { status?: number; body?: string };
      };
      if (out.decision) return this.permit({ allow: true, kind: 'ok', reason: 'permit (delegated)' }, token, rpc, true, toolName);
      const relayed = safeJson(out.response?.body ?? '') as JsonRpcErrorResponse | null;
      const reason = relayed?.error?.message ?? 'Access denied.';
      const verdict: Verdict = { allow: false, kind: 'denied', reason };
      this.report(toolName, verdict);
      const error = relayed ?? jsonRpcError(id, CODE_DENIED, reason);
      return { allow: false, coazTool: true, verdict, jsonRpcError: error, response: jsonResponse(200, error), message: rpc };
    } catch (err) {
      const why = err instanceof Error && err.name === 'AbortError' ? 'coaz-pep check timed out' : message(err);
      return this.deny(id, CODE_PDP_ERROR, { allow: false, kind: 'pdp_error', reason: PDP_UNAVAILABLE_REASON, detail: why }, toolName, rpc);
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

/** The claims a check reads, whether it was handed PepClaims, a bare claims map, or nothing. */
function claimsMap(claims: unknown): Record<string, unknown> {
  if (isPepClaims(claims)) return claims.raw;
  return isObject(claims) ? claims : {};
}

/** X-Auth-* for the upstream request, from the caller's claims; an empty value removes the header. */
function assertedHeaders(token: Record<string, unknown>): Record<string, string> {
  const c = extractClaims(token);
  const values = [c.sub, c.actor, c.scope, c.acr];
  return Object.fromEntries(AUTH_HEADERS.map((h, i) => [h, sanitizeHeaderValue(values[i] ?? '')]));
}

function jsonResponse(status: number, error: JsonRpcErrorResponse): McpHttpResponse {
  return { status, headers: { 'Content-Type': 'application/json', 'X-PDP-Decision': 'DENY' }, body: JSON.stringify(error) };
}

/** Do two values say the same thing in JSON? A value JSON cannot say is never the same. */
function sameJson(a: unknown, b: unknown): boolean {
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
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
 * Build the AuthZEN request from a v2 `x-authzen-mapping`.
 *
 * Differences from v1 that matter: the envelope decides single vs boxcar (a list value
 * never fans out), only `$`-prefixed strings are expressions, and `subject.id` is
 * trust-anchored — where it resolves from the token's subject claim the PEP MUST verify
 * the resolved value equals that claim, which is what stops the MCP server being
 * authorized from naming a different subject.
 */
export function buildRequestV2(
  mapping: AuthzenMapping,
  params: Record<string, unknown>,
  token: Record<string, unknown>,
  extraContext?: Record<string, unknown>,
): BuiltRequest {
  const keys = Object.keys(mapping ?? {});
  if (keys.length !== 1 || (keys[0] !== 'evaluation' && keys[0] !== 'evaluations')) {
    throw new Error(
      'mapping must have exactly one top-level member (`evaluation` or `evaluations`), got ' +
        (keys.length ? keys.join(', ') : 'none'),
    );
  }
  const envelope = keys[0] as 'evaluation' | 'evaluations';
  const batch = envelope === 'evaluations';
  const template = (mapping as Record<string, unknown>)[envelope];
  if (!isObject(template)) throw new Error(`mapping envelope \`${envelope}\` must contain an object`);

  // Identity smuggling: with the evaluations envelope the single top-level subject
  // governs every entry, so an entry that sets its own subject is rejected.
  //
  // The structure itself must be literal. An expression-valued `evaluations` (or
  // `subject`) would defer the shape to evaluation time, where it is built from
  // caller-controlled params — the entries could then carry their own subjects and this
  // check would have inspected nothing. Structure is compile-time; only leaves may be
  // expressions.
  if (batch) {
    const entries = template['evaluations'];
    if (entries === undefined) throw new Error('evaluations envelope has no evaluations array');
    if (!Array.isArray(entries)) throw new Error('evaluations must be a literal array, not an expression');
    entries.forEach((e, i) => {
      if (!isObject(e)) throw new Error(`evaluations[${i}] must be an object`);
      if ('subject' in e) {
        throw new Error(`evaluations[${i}] sets subject; only the top-level subject may do so`);
      }
    });
  }
  if ('subject' in template && !isObject(template['subject'])) {
    throw new Error('subject must be a literal object, not an expression');
  }

  // Work on a copy: the default subject is supplied by mutation and the declaration is
  // shared across calls.
  const inner = structuredClone(template) as Record<string, unknown>;
  const anchored = normaliseSubjectV2(inner);

  const resolved = evaluateNodeV2(inner, params, token);
  if (!isObject(resolved)) throw new Error('mapping did not resolve to an object');

  if (anchored) {
    const want = token[SUBJECT_IDENTITY_CLAIM];
    const subject = resolved['subject'];
    const got = isObject(subject) ? subject['id'] : undefined;
    if (typeof want !== 'string' || want === '') {
      throw new Error(`access token carries no ${SUBJECT_IDENTITY_CLAIM} claim to anchor subject.id to`);
    }
    if (got !== want) {
      throw new Error(`subject.id ${JSON.stringify(got)} does not match the validated token's ${SUBJECT_IDENTITY_CLAIM} claim`);
    }
  }

  if (extraContext && Object.keys(extraContext).length > 0) {
    const ctx = isObject(resolved['context']) ? (resolved['context'] as Record<string, unknown>) : {};
    for (const [k, v] of Object.entries(extraContext)) if (!(k in ctx)) ctx[k] = v;
    resolved['context'] = ctx;
  }

  if (batch) {
    const entries = resolved['evaluations'];
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new Error('evaluations envelope resolved to an empty evaluations array');
    }
  }

  // Defence in depth: re-check the RESOLVED request. The checks above constrain the
  // declaration; this constrains what actually came out of it, so a future change that
  // lets structure through from an expression cannot silently reopen identity smuggling.
  if (batch && Array.isArray(resolved['evaluations'])) {
    (resolved['evaluations'] as unknown[]).forEach((e, i) => {
      if (isObject(e) && 'subject' in e) {
        throw new Error(`evaluations[${i}] resolved with its own subject; only the top-level subject may set one`);
      }
    });
  }

  // Absent optionals in CONTEXT are pruned — context is optional, and `"agent": null`
  // would invite a policy to match on null as a value. Absence in a required field is a
  // mapping error instead.
  pruneNilContext(resolved);
  if (batch) {
    for (const e of resolved['evaluations'] as unknown[]) if (isObject(e)) pruneNilContext(e);
  }

  // "subject, action, and resource are required for every evaluation. If an expression
  // yields absent or null for a required field ... this is a mapping error."
  requireFields(resolved, batch);

  return { batch, body: resolved as unknown as EvaluationRequest | EvaluationsRequest };
}

/**
 * Supply the default subject identifier where the mapping omits one, and report whether
 * subject.id ends up anchored to the token's subject claim. Mutates `inner`.
 */
function normaliseSubjectV2(inner: Record<string, unknown>): boolean {
  let subject = inner['subject'];
  if (!isObject(subject)) {
    if ('subject' in inner && subject !== undefined && subject !== null) {
      throw new Error('subject must be an object');
    }
    subject = {};
    inner['subject'] = subject;
  }
  const sub = subject as Record<string, unknown>;
  // AuthZEN subjects require a type, and the binding's own defaults use "identity".
  if (sub['type'] === undefined || sub['type'] === null || sub['type'] === '') {
    sub['type'] = DEFAULT_SUBJECT_TYPE;
  }
  const id = sub['id'];
  if (id === undefined || id === null || id === '') {
    // "the PEP MUST supply the default subject identifier ... so that every request
    // still carries a token-anchored subject."
    sub['id'] = DEFAULT_SUBJECT_EXPR;
    return true;
  }
  if (typeof id !== 'string') throw new Error('subject.id must be a string');
  // Anchored only when it IS the claim. `$token.sub + '-x'` is an override, not an
  // anchor, and must not be verified as one.
  return id.trim() === DEFAULT_SUBJECT_EXPR;
}

/** v2 node walk: only `$`-prefixed strings are expressions; everything else is literal. */
function evaluateNodeV2(node: unknown, params: Record<string, unknown>, token: Record<string, unknown>): unknown {
  if (typeof node === 'string') {
    const expr = v2Expression(node);
    return expr === null ? node.startsWith('$$') ? node.slice(1) : node : evaluateExpression(expr, params, token);
  }
  if (Array.isArray(node)) return node.map((n) => evaluateNodeV2(n, params, token));
  if (isObject(node)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) {
      // undefined (an absent optional) is KEPT here. Dropping it at this level would
      // silently delete an identifying field — a resource.id that vanishes turns "this
      // customer" into "every customer". Optional context keys are pruned in
      // buildRequestV2, which knows which fields are required.
      out[k] = evaluateNodeV2(v, params, token);
    }
    return out;
  }
  return node;
}

/**
 * Is subject.id the token's subject claim? Anything else — including an omitted subject,
 * which the builder fills with the anchored default — is reported here on the raw
 * declaration, so the warning reflects what the author actually wrote.
 */
export function isAnchoredSubject(mapping: AuthzenMapping): boolean {
  const inner = (mapping as Record<string, unknown>)['evaluation'] ?? (mapping as Record<string, unknown>)['evaluations'];
  if (!isObject(inner)) return false;
  const subject = inner['subject'];
  if (!isObject(subject)) return true; // omitted -> the anchored default is supplied
  const id = subject['id'];
  if (id === undefined || id === null || id === '') return true;
  return typeof id === 'string' && id.trim() === DEFAULT_SUBJECT_EXPR;
}

function pruneNilContext(req: Record<string, unknown>): void {
  const ctx = req['context'];
  if (!isObject(ctx)) return;
  for (const [k, v] of Object.entries(ctx)) if (v === undefined || v === null) delete ctx[k];
}

/**
 * Enforce AuthZEN's mandatory members. For the evaluations envelope a member may sit at
 * the top level as a default or inside an entry, so each entry is checked against the
 * merge of the two.
 */
function requireFields(req: Record<string, unknown>, batch: boolean): void {
  if (!batch) return checkOne(req, '');
  const entries = (req['evaluations'] as unknown[]) ?? [];
  entries.forEach((e, i) => {
    const { evaluations: _drop, ...defaults } = req;
    checkOne({ ...defaults, ...(isObject(e) ? e : {}) }, `evaluations[${i}].`);
  });
}

function checkOne(req: Record<string, unknown>, prefix: string): void {
  const need = (obj: unknown, name: string, field: string) => {
    if (!isObject(obj)) throw new Error(`${prefix}${name} is missing`);
    const v = obj[field];
    if (typeof v !== 'string' || v === '') {
      throw new Error(`${prefix}${name}.${field} resolved to absent or null`);
    }
  };
  need(req['subject'], 'subject', 'id');
  need(req['action'], 'action', 'name');
  need(req['resource'], 'resource', 'type');
  // resource.id is optional in AuthZEN, but a DECLARED one that resolves absent would
  // silently broaden the request, so it is an error rather than a dropped key.
  const resource = req['resource'];
  if (isObject(resource) && 'id' in resource) need(resource, 'resource', 'id');
}

/**
 * The leading-`$` discriminator. Returns the expression source, or null for a literal.
 *
 *   "$token.sub" -> `token.sub`   "$$5.00" -> literal `$5.00`
 *   "customer"   -> literal        "a$b"    -> literal (a `$` elsewhere means nothing)
 */
export function v2Expression(s: string): string | null {
  if (!s.startsWith('$')) return null;
  if (s.startsWith('$$')) return null;
  return s.slice(1);
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
    // The same rule as v2: an identifying field that resolves absent is a mapping error,
    // not a key JSON quietly drops — a missing subject.id or resource.id would otherwise
    // ask the PDP about nobody, or about every resource of the type.
    requireFields(body, false);
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
  requireFields(body, true);
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
 *   token.?client_id            optional selection — undefined when absent
 *   string(x)  int(x)  double(x)
 *   a + b + 'c'                 concatenation / addition
 */
export function evaluateExpression(
  expr: string,
  params: Record<string, unknown>,
  token: Record<string, unknown>,
): unknown {
  const conditional = evaluateConditional(expr.trim(), params, token);
  if (conditional) return conditional.value;

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

/**
 * A conditional, `cond ? a : b`, with `==`/`!=` comparison. Added because the binding's
 * own `completion/complete` default needs one — without it a REQUIRED default mapping
 * could not be evaluated. Still narrow on purpose: no ordering, no boolean operators.
 * Returns undefined when `expr` is not a conditional.
 */
function evaluateConditional(
  expr: string,
  params: Record<string, unknown>,
  token: Record<string, unknown>,
): { value: unknown } | undefined {
  // Skip `.?` — that is optional field selection (`token.?client_id`), not a
  // conditional. Missing this turns every default mapping into a parse error.
  let q = -1;
  for (let from = 0; ; ) {
    const at = indexTopLevel(expr.slice(from), '?');
    if (at < 0) break;
    const abs = from + at;
    if (abs > 0 && expr[abs - 1] === '.') {
      from = abs + 1;
      continue;
    }
    q = abs;
    break;
  }
  if (q < 0) return undefined;
  const colon = indexTopLevel(expr.slice(q + 1), ':');
  if (colon < 0) throw new Error(`conditional is missing its ':' branch: ${expr}`);
  const cond = expr.slice(0, q).trim();
  const whenTrue = expr.slice(q + 1, q + 1 + colon).trim();
  const whenFalse = expr.slice(q + 2 + colon).trim();

  for (const op of ['==', '!='] as const) {
    const at = indexTopLevel(cond, op);
    if (at < 0) continue;
    const left = evaluateExpression(cond.slice(0, at), params, token);
    const right = evaluateExpression(cond.slice(at + 2), params, token);
    const equal = left === right;
    const taken = (op === '==' ? equal : !equal) ? whenTrue : whenFalse;
    return { value: evaluateExpression(taken, params, token) };
  }
  throw new Error(`unsupported condition: ${cond} — only == and != are evaluated here`);
}

/** Index of `needle` at nesting/quoting depth zero, or -1. */
function indexTopLevel(expr: string, needle: string): number {
  let depth = 0;
  let quote: string | null = null;
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
    else if (depth === 0 && expr.startsWith(needle, i)) return i;
  }
  return -1;
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

  const pathMatch = /^(params|token)((?:\.\??[A-Za-z_$][\w$]*|\[(?:'[^']*'|"[^"]*")\])*)$/.exec(term);
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
  const re = /\.\??([A-Za-z_$][\w$]*)|\['([^']*)'\]|\["([^"]*)"\]/g;
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

/**
 * The first complete `data:` frame of an SSE stream.
 *
 * A frame's data may span several `data:` lines, which SSE joins into one payload; a
 * blank line terminates the frame. Parsing each line on its own would fail on any
 * multi-line frame, so the lines are accumulated and parsed once at the frame boundary.
 * Matches firstSSEData in the Go engine — two PEPs reading the same stream differently
 * is exactly the drift this repo exists to avoid.
 */
function parseSse(text: string): unknown {
  // Per the SSE processing model: strip ONE optional leading space after "data:" (the
  // rest of the line is payload), join multiple data lines with a NEWLINE, and treat a
  // blank line as the frame boundary. Matches firstSSEData in the Go engine exactly.
  const parts: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('data:')) {
      let payload = line.slice(5);
      if (payload.startsWith(' ')) payload = payload.slice(1);
      parts.push(payload);
    } else if (line === '' && parts.length > 0) {
      return safeJson(parts.join('\n'));
    }
    // `event:`, `id:`, `retry:` and `:` comment lines carry no payload.
  }
  // A stream that ended without a terminating blank line still has a usable frame.
  return parts.length === 0 ? null : safeJson(parts.join('\n'));
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

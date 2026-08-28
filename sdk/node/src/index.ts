/**
 * @id-partners/authzen-pep — an AuthZEN 1.0 Policy Enforcement Point for Node.
 *
 * Two entry points, one PDP contract:
 *   - `authzenMiddleware` (./express) guards a REST API;
 *   - `McpGuard` (./mcp) guards MCP `tools/call` under the AuthZEN MCP profile.
 *
 * Both fail closed and both render the same challenge vocabulary as the Kong plugin and
 * the Envoy ext_authz service in this repo, so a client sees one behaviour regardless of
 * which PEP said no.
 */

export { AuthzenClient, PdpError } from './client.js';
export type { AuthzenClientOptions, PdpTrace } from './client.js';

export { foldDecision, toChallenge, toHttpChallenge } from './challenge.js';
export type { HttpChallenge } from './challenge.js';

export {
  bearerToken,
  claimsFromToken,
  decodeJwtClaims,
  decodeJwtHeader,
  decodeJwtSegment,
  extractClaims,
  hasScope,
  jwkThumbprint,
} from './claims.js';
export type { PepClaims } from './claims.js';

export { authzenMiddleware, pathMapper } from './express.js';
export type {
  AuthzContext,
  AuthzenMiddlewareOptions,
  NextFunction,
  PepRequest,
  PepResponse,
  RouteRule,
} from './express.js';

export {
  CODE_DENIED,
  CODE_DENIED_V2,
  CODE_MAPPING_ERROR,
  CODE_PDP_ERROR,
  McpGuard,
  buildRequest,
  buildRequestV2,
  evaluateExpression,
  jsonRpcError,
  v2Expression,
} from './mcp.js';
export type {
  AuthzenMapping,
  CoazMapping,
  Dialect,
  JsonRpcErrorResponse,
  JsonRpcRequest,
  MappingElement,
  McpGuardOptions,
  McpVerdict,
  ToolDefinition,
} from './mcp.js';

export type {
  Action,
  AuthzChallenge,
  Context,
  DecisionContext,
  DenialKind,
  EvaluationRequest,
  EvaluationResponse,
  EvaluationsRequest,
  EvaluationsResponse,
  Resource,
  ResourceSearchRequest,
  ResourceSearchResponse,
  Subject,
  SubjectSearchRequest,
  SubjectSearchResponse,
  Verdict,
} from './types.js';

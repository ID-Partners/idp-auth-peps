/**
 * AuthZEN Authorization API 1.0 wire types, plus the decision-context vocabulary
 * this repo's PEPs agree on.
 *
 * Spec: https://openid.net/specs/authorization-api-1_0.html
 */

export interface Subject {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

export interface Resource {
  type: string;
  id?: string;
  properties?: Record<string, unknown>;
}

export interface Action {
  name: string;
  properties?: Record<string, unknown>;
}

export type Context = Record<string, unknown>;

/** POST /access/v1/evaluation */
export interface EvaluationRequest {
  subject: Subject;
  action: Action;
  resource: Resource;
  context?: Context;
}

/**
 * The `context` a PDP may return alongside `decision`. `reason` is AuthZEN's own
 * convention; the `step_up_*` / `identity_proofing_*` keys are the advice vocabulary
 * the Ping Authorize policies in this repo emit, and which every PEP here honours —
 * see `challenge.ts` for how they become a client-facing challenge.
 */
export interface DecisionContext {
  reason?: string;
  /** RFC 9470 step-up: the policy wants a scope the user has not yet consented to. */
  step_up_required?: boolean;
  step_up_scope?: string;
  /** Verified-credential presentation required (e.g. an mDL at account origination). */
  identity_proofing_required?: boolean;
  identity_proofing_doctype?: string;
  /** No authenticated end user at all. */
  authn_required?: boolean;
  acr_values?: string;
  [key: string]: unknown;
}

export interface EvaluationResponse {
  decision: boolean;
  context?: DecisionContext;
}

/**
 * POST /access/v1/evaluations — the boxcar API. Single-valued fields sit at the top
 * level as defaults; each entry in `evaluations` overrides the fields it names.
 */
export interface EvaluationsRequest {
  subject?: Subject;
  action?: Action;
  resource?: Resource;
  context?: Context;
  evaluations: Array<Partial<Pick<EvaluationRequest, 'subject' | 'action' | 'resource' | 'context'>>>;
  options?: Record<string, unknown>;
}

export interface EvaluationsResponse {
  evaluations: EvaluationResponse[];
}

/** POST /access/v1/search/subject */
export interface SubjectSearchRequest {
  subject?: Partial<Subject>;
  action: Action;
  resource: Resource;
  context?: Context;
  page?: { next_token?: string };
}

export interface SubjectSearchResponse {
  results: Subject[];
  page?: { next_token?: string };
}

/** POST /access/v1/search/resource */
export interface ResourceSearchRequest {
  subject: Subject;
  action: Action;
  resource?: Partial<Resource>;
  context?: Context;
  page?: { next_token?: string };
}

export interface ResourceSearchResponse {
  results: Resource[];
  page?: { next_token?: string };
}

/**
 * The reason a decision came out the way it did, in a form a PEP can act on without
 * re-parsing prose. `ok` is a permit; every other value is a deny with a distinct
 * remedy, which is what lets a client tell "you may never do this" apart from
 * "do one more thing and retry".
 */
export type DenialKind =
  /** Permitted. */
  | 'ok'
  /** PDP said no, and no advice suggests a remedy. */
  | 'denied'
  /** No usable token / no authenticated subject. */
  | 'unauthenticated'
  /** RFC 9470 scope step-up. */
  | 'step_up_required'
  /** Verified-credential presentation required. */
  | 'identity_proofing_required'
  /** The PEP could not build a valid AuthZEN request (bad mapping / bad params). */
  | 'mapping_error'
  /** The PDP was unreachable, slow, or answered with something unusable. Fails closed. */
  | 'pdp_error';

/**
 * A PEP's verdict: the raw PDP answer, folded into something enforceable.
 */
export interface Verdict {
  allow: boolean;
  kind: DenialKind;
  /** Human-readable, safe to log and to put in a challenge body. */
  reason: string;
  /** Whatever context the PDP returned, untouched. */
  context?: DecisionContext;
  /** The request that was sent to the PDP — for transcripts and tests. */
  request?: EvaluationRequest | EvaluationsRequest;
}

/**
 * The structured form of a policy challenge, carried as JSON in a deny body and — for
 * MCP — as the JSON-RPC error's `data.authz_challenge` member. The prose message is
 * what older clients string-matched; this is what an SDK parses.
 *
 * Type values are this repo's authorisation taxonomy, shared with the Go PEP
 * (`core/coaz/types.go`) so a challenge, the ceremony that resolves it, and the
 * record it leaves behind all use the same word:
 *
 *   resource_authorisation  RFC 9470 scope step-up            -> scope set
 *   identity_proofing       verified-credential presentation  -> doctype set
 *   authn                   no authenticated user at all      -> acr_values set
 *   consent / intent        reserved
 */
export interface AuthzChallenge {
  type: 'resource_authorisation' | 'identity_proofing' | 'authn' | 'consent' | 'intent';
  scope?: string;
  doctype?: string;
  acr_values?: string;
  reason?: string;
  /** Which PEP raised it — useful when two sit in one call path. */
  pep?: string;
}

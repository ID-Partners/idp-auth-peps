/**
 * Turning a PDP answer into something the caller can act on.
 *
 * A deny that a client can resolve is worth far more than a flat 403, so the PDP's
 * advice is folded into a typed `DenialKind` and then rendered two ways: an RFC 6750 /
 * RFC 9470 `WWW-Authenticate` challenge for HTTP, and a structured `AuthzChallenge`
 * for anything that parses JSON (the MCP guard puts it in the JSON-RPC error `data`).
 *
 * The Go PEP in `core/` renders the same two forms from the same advice keys — the
 * point is that a client gets an identical challenge whichever PEP denied it.
 */

import type { AuthzChallenge, DecisionContext, EvaluationResponse, Verdict } from './types.js';

/** Fold one AuthZEN decision + its advice into a Verdict. */
export function foldDecision(res: EvaluationResponse | undefined): Verdict {
  const ctx: DecisionContext | undefined = res?.context;
  const reason = typeof ctx?.reason === 'string' && ctx.reason ? ctx.reason : '';

  if (res?.decision === true) {
    return { allow: true, kind: 'ok', reason: reason || 'permit', context: ctx };
  }

  // Advice order matters: identity proofing is the more fundamental gate, so when a
  // policy asks for both, resolve identity first and let the retry surface the step-up.
  if (ctx?.identity_proofing_required) {
    return {
      allow: false,
      kind: 'identity_proofing_required',
      reason: reason || 'Identity verification required before this action.',
      context: ctx,
    };
  }
  if (ctx?.step_up_required) {
    return {
      allow: false,
      kind: 'step_up_required',
      reason: reason || 'This action requires additional authorisation.',
      context: ctx,
    };
  }
  if (ctx?.authn_required) {
    return {
      allow: false,
      kind: 'unauthenticated',
      reason: reason || 'Authentication required.',
      context: ctx,
    };
  }
  return { allow: false, kind: 'denied', reason: reason || 'Access denied.', context: ctx };
}

/**
 * The structured challenge for a verdict, or null when the deny offers no remedy
 * (a plain `denied`, a mapping error, a PDP failure — retrying changes nothing).
 */
export function toChallenge(verdict: Verdict, pep?: string): AuthzChallenge | null {
  const ctx = verdict.context;
  switch (verdict.kind) {
    case 'identity_proofing_required':
      return {
        type: 'identity_proofing',
        doctype: str(ctx?.identity_proofing_doctype),
        reason: verdict.reason,
        ...(pep ? { pep } : {}),
      };
    case 'step_up_required':
      return {
        type: 'resource_authorisation',
        scope: str(ctx?.step_up_scope),
        reason: verdict.reason,
        ...(pep ? { pep } : {}),
      };
    case 'unauthenticated':
      return {
        type: 'authn',
        acr_values: str(ctx?.acr_values),
        reason: verdict.reason,
        ...(pep ? { pep } : {}),
      };
    default:
      return null;
  }
}

export interface HttpChallenge {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/**
 * The HTTP rendering of a deny.
 *
 * 401 + `WWW-Authenticate` for anything the client can fix by getting a better token
 * (RFC 6750 `invalid_token` / `insufficient_scope`, RFC 9470 step-up); 403 for a
 * policy no with no remedy; 502 when the PDP itself failed, because that is our
 * problem and not the caller's, and a 403 would send them chasing permissions they
 * already have.
 */
export function toHttpChallenge(verdict: Verdict, pep?: string): HttpChallenge {
  const challenge = toChallenge(verdict, pep);
  const base = {
    ...(challenge ? { authz_challenge: challenge } : {}),
    ...(pep ? { pep } : {}),
    reason: verdict.reason,
  };

  switch (verdict.kind) {
    case 'identity_proofing_required': {
      const doctype = str(ctxVal(verdict, 'identity_proofing_doctype'));
      return {
        status: 401,
        headers: {
          'WWW-Authenticate': wwwAuthenticate('identity_verification_required', {
            ...(doctype ? { doctype } : {}),
            error_description: verdict.reason,
          }),
        },
        body: { error: 'identity_verification_required', ...(doctype ? { doctype } : {}), ...base },
      };
    }
    case 'step_up_required': {
      const scope = str(ctxVal(verdict, 'step_up_scope'));
      return {
        status: 401,
        headers: {
          'WWW-Authenticate': wwwAuthenticate('insufficient_scope', {
            ...(scope ? { scope } : {}),
            error_description: verdict.reason,
          }),
        },
        body: { error: 'insufficient_scope', ...(scope ? { scope } : {}), ...base },
      };
    }
    case 'unauthenticated': {
      const acr = str(ctxVal(verdict, 'acr_values'));
      return {
        status: 401,
        headers: {
          'WWW-Authenticate': wwwAuthenticate('login_required', {
            ...(acr ? { acr_values: acr } : {}),
            error_description: verdict.reason,
          }),
        },
        body: { error: 'login_required', ...(acr ? { acr_values: acr } : {}), ...base },
      };
    }
    case 'mapping_error':
      return { status: 400, headers: {}, body: { error: 'invalid_request', ...base } };
    case 'pdp_error':
      // Fail closed, but say whose fault it is.
      return { status: 502, headers: {}, body: { error: 'authorization_unavailable', ...base } };
    default:
      return { status: 403, headers: {}, body: { error: 'access_denied', ...base } };
  }
}

/**
 * RFC 6750 §3 challenge. Reasons come from policy and can carry anything, so every
 * value is quoted-string escaped — a header-injecting reason would otherwise let
 * policy text forge response headers.
 */
function wwwAuthenticate(error: string, params: Record<string, string | undefined>): string {
  const parts = [`error="${escapeQuoted(error)}"`];
  for (const [k, v] of Object.entries(params)) {
    if (!v) continue;
    parts.push(`${k}="${escapeQuoted(v)}"`);
  }
  return `Bearer ${parts.join(', ')}`;
}

function escapeQuoted(v: string): string {
  // Strip CR/LF outright (header injection), then escape " and \ per the grammar.
  return v.replace(/[\r\n]+/g, ' ').replace(/([\\"])/g, '\\$1');
}

function ctxVal(verdict: Verdict, key: keyof DecisionContext): unknown {
  return verdict.context?.[key as string];
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

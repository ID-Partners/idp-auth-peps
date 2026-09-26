/**
 * Reading an MCP message the way every PEP in this repo agrees to: anything that is not
 * positively understood is refused, never waved through as handshake traffic.
 *
 * A message must be exactly one JSON object — a request or notification with a string
 * `method`, or a JSON-RPC response (an `id` and exactly one of `result` / `error`, no
 * `method`). A batch is refused, not evaluated. Two members of the top-level object, or
 * of `params`, whose names differ only in case are refused: a case-insensitive decoder
 * upstream (Go's `encoding/json`) would read the one this PEP ignored. A `tools/call`
 * needs a non-empty string `params.name`.
 *
 * Given the raw body, it is read strictly first: no Content-Encoding but identity, valid
 * UTF-8, no byte-order mark, no trailing data, and no duplicate member names at any
 * depth — a parser that keeps the first of two keys and one that keeps the last would
 * otherwise disagree about what was asked.
 *
 * Internal: the guard in mcp.ts is the public surface.
 */

export const CODE_PARSE_ERROR = -32700;
export const CODE_INVALID_REQUEST = -32600;

/** A message the PEP will not read, and how to say so. */
export interface RpcRefusal {
  /** The HTTP status to answer with. */
  status: 400 | 415;
  code: typeof CODE_PARSE_ERROR | typeof CODE_INVALID_REQUEST;
  message: string;
  /** The request's id when it could be read; null otherwise. */
  id: string | number | null;
}

export type RpcId = string | number | null;

export type ReadMessage =
  | { kind: 'request'; method: string; id: RpcId; params: Record<string, unknown> | undefined; message: Record<string, unknown> }
  | { kind: 'response'; id: RpcId; message: Record<string, unknown> }
  | { kind: 'refused'; refusal: RpcRefusal };

/** Deeper than any MCP message has a reason to be; a guard against exhausting the stack. */
const MAX_DEPTH = 512;

const parseError = (): RpcRefusal => ({ status: 400, code: CODE_PARSE_ERROR, message: 'Parse error', id: null });
const invalid = (reason: string, id: RpcId = null): RpcRefusal => ({ status: 400, code: CODE_INVALID_REQUEST, message: `Invalid Request: ${reason}`, id });

/**
 * Classify one already-parsed message. Exact duplicate keys cannot be seen here — the
 * parse collapsed them — which is why a caller that has the raw body should pass it
 * through {@link parseBody} first.
 */
export function readMessage(value: unknown): ReadMessage {
  const refused = (refusal: RpcRefusal): ReadMessage => ({ kind: 'refused', refusal });
  if (Array.isArray(value)) return refused(invalid('JSON-RPC batches are not supported'));
  if (!isPlainObject(value)) return refused(invalid('the body must be one JSON-RPC object'));

  const hasId = 'id' in value && value['id'] !== undefined;
  if (hasId && !isRpcId(value['id'])) return refused(invalid('id must be a string, a number or null'));
  const id: RpcId = hasId ? (value['id'] as RpcId) : null;

  const dup = caseVariant(Object.keys(value));
  if (dup !== undefined) return refused(invalid(`duplicate member ${JSON.stringify(dup)}`, dup.toLowerCase() === 'id' ? null : id));

  if (!('method' in value) || value['method'] === undefined) {
    // A client's answer to a server-initiated request (sampling, elicitation).
    if (hasId && ('result' in value) !== ('error' in value)) return { kind: 'response', id, message: value };
    return refused(invalid('neither a request nor a response', id));
  }
  const method = value['method'];
  if (typeof method !== 'string') return refused(invalid('method must be a string', id));

  let params: Record<string, unknown> | undefined;
  if ('params' in value && value['params'] !== undefined) {
    if (!isPlainObject(value['params'])) return refused(invalid('params must be an object', id));
    params = value['params'];
    const pdup = caseVariant(Object.keys(params));
    if (pdup !== undefined) return refused(invalid(`duplicate member params.${pdup}`, id));
  }
  if (method === 'tools/call') {
    const name = params?.['name'];
    if (typeof name !== 'string' || name === '') return refused(invalid('tools/call needs a string params.name', id));
  }
  return { kind: 'request', method, id, params, message: value };
}

/**
 * Read a raw body strictly and parse it. The headers are consulted for
 * Content-Encoding only; a value that is an array is read by its first element.
 */
export function parseBody(
  body: string | Uint8Array,
  headers: Record<string, string | string[] | undefined> = {},
): { ok: true; value: unknown } | { ok: false; refusal: RpcRefusal } {
  const encoding = headerValue(headers, 'content-encoding').trim().toLowerCase();
  if (encoding !== '' && encoding !== 'identity') {
    return { ok: false, refusal: { status: 415, code: CODE_INVALID_REQUEST, message: 'Invalid Request: Content-Encoding not supported by the PEP', id: null } };
  }
  let text: string;
  if (typeof body === 'string') {
    text = body;
  } else if (body instanceof Uint8Array) {
    if (body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) return { ok: false, refusal: parseError() };
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body);
    } catch {
      return { ok: false, refusal: parseError() };
    }
  } else {
    return { ok: false, refusal: invalid('the body could not be read') };
  }
  if (text.charCodeAt(0) === 0xfeff) return { ok: false, refusal: parseError() };

  try {
    scan(text);
  } catch (err) {
    // MAX_DEPTH keeps the scan far from the stack's limit; anything else unforeseen is,
    // like a syntax error, a body the PEP could not read.
    if (err instanceof ScanFailure && err.kind === 'structure') {
      return { ok: false, refusal: invalid(err.message, err.key?.toLowerCase() === 'id' ? null : idOf(text)) };
    }
    return { ok: false, refusal: parseError() };
  }
  return { ok: true, value: JSON.parse(text) };
}

/** The first value of a header, looked up case-insensitively. Empty when absent. */
export function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string {
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (k.toLowerCase() !== name) continue;
    const first = Array.isArray(v) ? v[0] : v;
    if (typeof first === 'string') return first;
  }
  return '';
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

function isRpcId(v: unknown): v is RpcId {
  return v === null || typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v));
}

/** The id of a body that parses, when it is one; null otherwise. */
function idOf(text: string): RpcId {
  try {
    const v: unknown = JSON.parse(text);
    return isPlainObject(v) && isRpcId(v['id']) ? v['id'] : null;
  } catch {
    return null;
  }
}

/**
 * The name, if any, that repeats one before it in a case-insensitive comparison. The
 * fold is a superset of Go's `EqualFold`: upper-casing first maps the long s (U+017F) to
 * S and the Kelvin sign (U+212A) survives to k, both of which Go folds together with
 * their ASCII letters. Over-matching only refuses a name no client sends.
 */
function caseVariant(keys: string[]): string | undefined {
  const seen = new Set<string>();
  for (const k of keys) {
    const folded = fold(k);
    if (seen.has(folded)) return k;
    seen.add(folded);
  }
  return undefined;
}

function fold(k: string): string {
  return k.toUpperCase().toLowerCase();
}

class ScanFailure extends Error {
  constructor(
    readonly kind: 'syntax' | 'structure',
    message: string,
    readonly key?: string,
  ) {
    super(message);
  }
}

const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

/**
 * Validate `s` as exactly one JSON value (RFC 8259) and reject duplicate member names:
 * exact duplicates at every depth, case variants in the top-level object and in its
 * `params`. Throws a ScanFailure; returns nothing. Building the value is left to
 * JSON.parse once the text is known to be clean.
 */
function scan(s: string): void {
  let i = 0;
  const n = s.length;
  const syntax = (why: string): never => {
    throw new ScanFailure('syntax', why);
  };
  const ws = () => {
    while (i < n) {
      const c = s.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const str = () => {
    i++; // the opening quote
    while (i < n) {
      const c = s.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return;
      }
      if (c === 0x5c) {
        const e = s[i + 1];
        if (e === 'u') {
          if (!HEX4.test(s.slice(i + 2, i + 6))) syntax('bad \\u escape');
          i += 6;
          continue;
        }
        if (e !== undefined && '"\\/bfnrt'.includes(e)) {
          i += 2;
          continue;
        }
        syntax('bad escape');
      }
      if (c < 0x20) syntax('control character in a string');
      i++;
    }
    syntax('unterminated string');
  };
  const literal = (word: string) => {
    if (!s.startsWith(word, i)) syntax('unexpected token');
    i += word.length;
  };
  const value = (depth: number, foldKeys: boolean, top: boolean): void => {
    if (depth > MAX_DEPTH) throw new ScanFailure('structure', 'nested too deeply');
    ws();
    const c = s[i];
    if (c === '{') return object(depth, foldKeys, top);
    if (c === '[') return array(depth);
    if (c === '"') return str();
    if (c === 't') return literal('true');
    if (c === 'f') return literal('false');
    if (c === 'n') return literal('null');
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
      NUMBER.lastIndex = i;
      if (!NUMBER.exec(s)) syntax('bad number');
      i = NUMBER.lastIndex;
      return;
    }
    syntax(i >= n ? 'unexpected end' : 'unexpected character');
  };
  const object = (depth: number, foldKeys: boolean, top: boolean): void => {
    i++; // {
    ws();
    if (s[i] === '}') {
      i++;
      return;
    }
    const exact = new Set<string>();
    const folded = new Set<string>();
    for (;;) {
      ws();
      if (s[i] !== '"') syntax('expected a member name');
      const start = i;
      str();
      const key = JSON.parse(s.slice(start, i)) as string;
      if (exact.has(key)) throw new ScanFailure('structure', `duplicate member ${JSON.stringify(key)}`, key);
      exact.add(key);
      if (foldKeys) {
        const f = fold(key);
        if (folded.has(f)) throw new ScanFailure('structure', `duplicate member ${JSON.stringify(key)}`, key);
        folded.add(f);
      }
      ws();
      if (s[i] !== ':') syntax("expected ':'");
      i++;
      value(depth + 1, top && key === 'params', false);
      ws();
      if (s[i] === ',') {
        i++;
        continue;
      }
      if (s[i] === '}') {
        i++;
        return;
      }
      syntax("expected ',' or '}'");
    }
  };
  const array = (depth: number): void => {
    i++; // [
    ws();
    if (s[i] === ']') {
      i++;
      return;
    }
    for (;;) {
      value(depth + 1, false, false);
      ws();
      if (s[i] === ',') {
        i++;
        continue;
      }
      if (s[i] === ']') {
        i++;
        return;
      }
      syntax("expected ',' or ']'");
    }
  };

  value(0, true, true);
  ws();
  if (i !== n) syntax('trailing data');
}

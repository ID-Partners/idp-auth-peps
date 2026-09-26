/**
 * Reading an MCP message the way every PEP in this repo agrees to: anything that is not
 * positively understood is refused, never waved through as handshake traffic.
 *
 * A message must be exactly one JSON object — a request or notification with a string
 * `method`, or a JSON-RPC response (an `id` and exactly one of `result` / `error`, no
 * `method`). A batch is refused, not evaluated. A `tools/call` needs a non-empty string
 * `params.name`. And, as the Go engine (`core/coaz/jsonrpc.go`) refuses them, so does
 * this: any object, at any depth, holding two member names that are equal under Unicode
 * simple case folding — a case-insensitive decoder upstream (Go's `encoding/json`) would
 * read the one this PEP ignored, in `params.arguments` as much as at the top level — and
 * nesting deeper than 64.
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

/**
 * The Go engine's bound on nesting: the top-level value is at depth 0, and a value
 * deeper than this is refused. MCP messages are shallow; a deep one is a stack-depth
 * attack on some parser along the way, not a tool call.
 */
const MAX_DEPTH = 64;
const NESTED_TOO_DEEPLY = 'the body is nested too deeply';
/** `id` as foldKey sees it: a folded duplicate of it leaves no id to answer. */
const ID_FOLDED = 'ID';

const parseError = (): RpcRefusal => ({ status: 400, code: CODE_PARSE_ERROR, message: 'Parse error', id: null });
const invalid = (reason: string, id: RpcId = null): RpcRefusal => ({ status: 400, code: CODE_INVALID_REQUEST, message: `Invalid Request: ${reason}`, id });
const sameName = (a: string, b: string) => `member names ${JSON.stringify(a)} and ${JSON.stringify(b)} are the same name to a case-insensitive parser`;

/**
 * Classify one already-parsed message. Exact duplicate keys cannot be seen here — the
 * parse collapsed them — which is why a caller that has the raw body should pass it
 * through {@link parseBody} first. Case-folded duplicates and excess nesting can, and
 * are refused at every depth.
 */
export function readMessage(value: unknown): ReadMessage {
  const refused = (refusal: RpcRefusal): ReadMessage => ({ kind: 'refused', refusal });
  if (Array.isArray(value)) return refused(invalid('JSON-RPC batches are not supported'));
  if (!isPlainObject(value)) return refused(invalid('the body must be one JSON-RPC object'));

  const hasId = 'id' in value && value['id'] !== undefined;
  if (hasId && !isRpcId(value['id'])) return refused(invalid('id must be a string, a number or null'));
  const id: RpcId = hasId ? (value['id'] as RpcId) : null;

  const problem = structureProblem(value, 0);
  if (problem) return refused(invalid(problem.message, problem.topLevelId ? null : id));

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
      return { ok: false, refusal: invalid(err.message, err.topLevelId ? null : idOf(text)) };
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
 * What makes a parsed message ambiguous, as the Go engine's walkValue sees it: an
 * object, at any depth, holding two member names that fold to one, or a value nested
 * deeper than MAX_DEPTH. Anything that is not a plain object or an array is a leaf. The
 * depth bound also ends a walk round a cycle a caller built in memory.
 */
function structureProblem(value: unknown, depth: number): { message: string; topLevelId: boolean } | undefined {
  if (depth > MAX_DEPTH) return { message: NESTED_TOO_DEEPLY, topLevelId: false };
  if (Array.isArray(value)) {
    for (const v of value) {
      const p = structureProblem(v, depth + 1);
      if (p) return p;
    }
    return undefined;
  }
  if (!isPlainObject(value)) return undefined;
  const seen = new Map<string, string>();
  for (const [k, v] of Object.entries(value)) {
    const f = foldKey(k);
    const prev = seen.get(f);
    if (prev !== undefined) return { message: sameName(prev, k), topLevelId: depth === 0 && f === ID_FOLDED };
    seen.set(f, k);
    const p = structureProblem(v, depth + 1);
    if (p) return p;
  }
  return undefined;
}

/**
 * Go's unicode.SimpleFold orbits as Go 1.26 ships them (Unicode 15.0.0): every rune that
 * is not the smallest member of its orbit, mapped to that smallest member — which is
 * what core/coaz/jsonrpc.go's foldKey computes. Run-length encoded as
 * [start, count, delta, stride]: rune start + i*stride folds to start + i*stride + delta.
 *
 * Taken from Go rather than from this runtime's case mappings. Those change with the ICU
 * a Node release ships, and differ from simple folding besides: µ and Μ fold together
 * and ß and "ss" do not, while İ and ı fold to nothing but themselves.
 */
const FOLD_RUNS: ReadonlyArray<readonly [number, number, number, number]> = [
  [0x61, 26, -32, 1], [0xe0, 23, -32, 1], [0xf8, 7, -32, 1], [0x101, 24, -1, 2], [0x133, 3, -1, 2], [0x13a, 8, -1, 2],
  [0x14b, 23, -1, 2], [0x178, 1, -121, 1], [0x17a, 3, -1, 2], [0x17f, 1, -300, 1], [0x183, 2, -1, 2], [0x188, 1, -1, 1],
  [0x18c, 1, -1, 1], [0x192, 1, -1, 1], [0x199, 1, -1, 1], [0x1a1, 3, -1, 2], [0x1a8, 1, -1, 1], [0x1ad, 1, -1, 1],
  [0x1b0, 1, -1, 1], [0x1b4, 2, -1, 2], [0x1b9, 1, -1, 1], [0x1bd, 1, -1, 1], [0x1c5, 1, -1, 1], [0x1c6, 1, -2, 1],
  [0x1c8, 1, -1, 1], [0x1c9, 1, -2, 1], [0x1cb, 1, -1, 1], [0x1cc, 1, -2, 1], [0x1ce, 8, -1, 2], [0x1dd, 1, -79, 1],
  [0x1df, 9, -1, 2], [0x1f2, 1, -1, 1], [0x1f3, 1, -2, 1], [0x1f5, 1, -1, 1], [0x1f6, 1, -97, 1], [0x1f7, 1, -56, 1],
  [0x1f9, 20, -1, 2], [0x220, 1, -130, 1], [0x223, 9, -1, 2], [0x23c, 1, -1, 1], [0x23d, 1, -163, 1], [0x242, 1, -1, 1],
  [0x243, 1, -195, 1], [0x247, 5, -1, 2], [0x253, 1, -210, 1], [0x254, 1, -206, 1], [0x256, 2, -205, 1], [0x259, 1, -202, 1],
  [0x25b, 1, -203, 1], [0x260, 1, -205, 1], [0x263, 1, -207, 1], [0x268, 1, -209, 1], [0x269, 1, -211, 1], [0x26f, 1, -211, 1],
  [0x272, 1, -213, 1], [0x275, 1, -214, 1], [0x280, 1, -218, 1], [0x283, 1, -218, 1], [0x288, 1, -218, 1], [0x289, 1, -69, 1],
  [0x28a, 2, -217, 1], [0x28c, 1, -71, 1], [0x292, 1, -219, 1], [0x371, 2, -1, 2], [0x377, 1, -1, 1], [0x399, 1, -84, 1],
  [0x39c, 1, -743, 1], [0x3ac, 1, -38, 1], [0x3ad, 3, -37, 1], [0x3b1, 8, -32, 1], [0x3b9, 1, -116, 1], [0x3ba, 2, -32, 1],
  [0x3bc, 1, -775, 1], [0x3bd, 5, -32, 1], [0x3c2, 1, -31, 1], [0x3c3, 9, -32, 1], [0x3cc, 1, -64, 1], [0x3cd, 2, -63, 1],
  [0x3d0, 1, -62, 1], [0x3d1, 1, -57, 1], [0x3d5, 1, -47, 1], [0x3d6, 1, -54, 1], [0x3d7, 1, -8, 1], [0x3d9, 12, -1, 2],
  [0x3f0, 1, -86, 1], [0x3f1, 1, -80, 1], [0x3f3, 1, -116, 1], [0x3f4, 1, -92, 1], [0x3f5, 1, -96, 1], [0x3f8, 1, -1, 1],
  [0x3f9, 1, -7, 1], [0x3fb, 1, -1, 1], [0x3fd, 3, -130, 1], [0x430, 32, -32, 1], [0x450, 16, -80, 1], [0x461, 17, -1, 2],
  [0x48b, 27, -1, 2], [0x4c2, 7, -1, 2], [0x4cf, 1, -15, 1], [0x4d1, 48, -1, 2], [0x561, 38, -48, 1], [0x13f8, 6, -8, 1],
  [0x1c80, 1, -6254, 1], [0x1c81, 1, -6253, 1], [0x1c82, 1, -6244, 1], [0x1c83, 2, -6242, 1], [0x1c85, 1, -6243, 1], [0x1c86, 1, -6236, 1],
  [0x1c87, 1, -6181, 1], [0x1c90, 43, -3008, 1], [0x1cbd, 3, -3008, 1], [0x1e01, 75, -1, 2], [0x1e9b, 1, -59, 1], [0x1e9e, 1, -7615, 1],
  [0x1ea1, 48, -1, 2], [0x1f08, 8, -8, 1], [0x1f18, 6, -8, 1], [0x1f28, 8, -8, 1], [0x1f38, 8, -8, 1], [0x1f48, 6, -8, 1],
  [0x1f59, 4, -8, 2], [0x1f68, 8, -8, 1], [0x1f88, 8, -8, 1], [0x1f98, 8, -8, 1], [0x1fa8, 8, -8, 1], [0x1fb8, 2, -8, 1],
  [0x1fba, 2, -74, 1], [0x1fbc, 1, -9, 1], [0x1fbe, 1, -7289, 1], [0x1fc8, 4, -86, 1], [0x1fcc, 1, -9, 1], [0x1fd8, 2, -8, 1],
  [0x1fda, 2, -100, 1], [0x1fe8, 2, -8, 1], [0x1fea, 2, -112, 1], [0x1fec, 1, -7, 1], [0x1ff8, 2, -128, 1], [0x1ffa, 2, -126, 1],
  [0x1ffc, 1, -9, 1], [0x2126, 1, -7549, 1], [0x212a, 1, -8415, 1], [0x212b, 1, -8294, 1], [0x214e, 1, -28, 1], [0x2170, 16, -16, 1],
  [0x2184, 1, -1, 1], [0x24d0, 26, -26, 1], [0x2c30, 48, -48, 1], [0x2c61, 1, -1, 1], [0x2c62, 1, -10743, 1], [0x2c63, 1, -3814, 1],
  [0x2c64, 1, -10727, 1], [0x2c65, 1, -10795, 1], [0x2c66, 1, -10792, 1], [0x2c68, 3, -1, 2], [0x2c6d, 1, -10780, 1], [0x2c6e, 1, -10749, 1],
  [0x2c6f, 1, -10783, 1], [0x2c70, 1, -10782, 1], [0x2c73, 1, -1, 1], [0x2c76, 1, -1, 1], [0x2c7e, 2, -10815, 1], [0x2c81, 50, -1, 2],
  [0x2cec, 2, -1, 2], [0x2cf3, 1, -1, 1], [0x2d00, 38, -7264, 1], [0x2d27, 1, -7264, 1], [0x2d2d, 1, -7264, 1], [0xa641, 5, -1, 2],
  [0xa64a, 1, -35266, 1], [0xa64b, 1, -35267, 1], [0xa64d, 17, -1, 2], [0xa681, 14, -1, 2], [0xa723, 7, -1, 2], [0xa733, 31, -1, 2],
  [0xa77a, 2, -1, 2], [0xa77d, 1, -35332, 1], [0xa77f, 5, -1, 2], [0xa78c, 1, -1, 1], [0xa78d, 1, -42280, 1], [0xa791, 2, -1, 2],
  [0xa797, 10, -1, 2], [0xa7aa, 1, -42308, 1], [0xa7ab, 1, -42319, 1], [0xa7ac, 1, -42315, 1], [0xa7ad, 1, -42305, 1], [0xa7ae, 1, -42308, 1],
  [0xa7b0, 1, -42258, 1], [0xa7b1, 1, -42282, 1], [0xa7b2, 1, -42261, 1], [0xa7b5, 8, -1, 2], [0xa7c4, 1, -48, 1], [0xa7c5, 1, -42307, 1],
  [0xa7c6, 1, -35384, 1], [0xa7c8, 2, -1, 2], [0xa7d1, 1, -1, 1], [0xa7d7, 2, -1, 2], [0xa7f6, 1, -1, 1], [0xab53, 1, -928, 1],
  [0xab70, 80, -38864, 1], [0xff41, 26, -32, 1], [0x10428, 40, -40, 1], [0x104d8, 36, -40, 1], [0x10597, 11, -39, 1], [0x105a3, 15, -39, 1],
  [0x105b3, 7, -39, 1], [0x105bb, 2, -39, 1], [0x10cc0, 51, -64, 1], [0x118c0, 32, -32, 1], [0x16e60, 32, -32, 1], [0x1e922, 34, -34, 1],
];

let foldTable: Map<number, number> | undefined;

/**
 * A member name as Go's foldKey sees it: two names fold to the same string exactly when
 * strings.EqualFold says they are equal, which is the rule encoding/json matches a key to
 * a struct field by.
 */
export function foldKey(name: string): string {
  // ASCII is the common case, and there folding is upper-casing: k and s have orbits
  // beyond ASCII (the Kelvin sign, the long s), but the ASCII capital is still the
  // smallest member of each.
  if (/^[\x00-\x7f]*$/.test(name)) return name.toUpperCase();
  foldTable ??= new Map(FOLD_RUNS.flatMap(([start, count, delta, stride]) => Array.from({ length: count }, (_, i) => [start + i * stride, start + i * stride + delta] as const)));
  let out = '';
  for (const ch of name) {
    let cp = ch.codePointAt(0)!;
    // A lone surrogate can only arrive by a \u escape, and Go's decoder reads it as U+FFFD.
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    out += String.fromCodePoint(foldTable.get(cp) ?? cp);
  }
  return out;
}

class ScanFailure extends Error {
  constructor(
    readonly kind: 'syntax' | 'structure',
    message: string,
    /** A folded duplicate of the top-level id: there is then no id to answer. */
    readonly topLevelId = false,
  ) {
    super(message);
  }
}

const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

/**
 * Validate `s` as exactly one JSON value (RFC 8259), refusing what the Go engine's
 * walkValue refuses: an object, at any depth, holding two member names equal under
 * simple case folding (exact duplicates included), and a value nested deeper than
 * MAX_DEPTH. Throws a ScanFailure; returns nothing. Building the value is left to
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
  const value = (depth: number): void => {
    if (depth > MAX_DEPTH) throw new ScanFailure('structure', NESTED_TOO_DEEPLY);
    ws();
    const c = s[i];
    if (c === '{') return object(depth);
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
  const object = (depth: number): void => {
    i++; // {
    ws();
    if (s[i] === '}') {
      i++;
      return;
    }
    const seen = new Map<string, string>();
    for (;;) {
      ws();
      if (s[i] !== '"') syntax('expected a member name');
      const start = i;
      str();
      const key = JSON.parse(s.slice(start, i)) as string;
      const f = foldKey(key);
      const prev = seen.get(f);
      if (prev !== undefined) throw new ScanFailure('structure', sameName(prev, key), depth === 0 && f === ID_FOLDED);
      seen.set(f, key);
      ws();
      if (s[i] !== ':') syntax("expected ':'");
      i++;
      value(depth + 1);
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
      value(depth + 1);
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

  value(0);
  ws();
  if (i !== n) syntax('trailing data');
}

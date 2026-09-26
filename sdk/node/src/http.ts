/**
 * Small HTTP helpers shared by the client, discovery and the MCP guard. Internal: not
 * exported from the package entry points.
 */

/** A body larger than the caller was prepared to read. */
export class BodyTooLargeError extends Error {
  constructor(readonly limit: number) {
    super(`body exceeds ${limit} bytes`);
    this.name = 'BodyTooLargeError';
  }
}

/**
 * Read a response body as UTF-8 text, refusing one larger than `max` bytes without
 * buffering the rest of it. A read that breaks off part way rejects with the stream's
 * own error, so the caller can tell a truncated answer from a complete one.
 */
export async function readCapped(res: Response, max: number): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) {
    await discard(res);
    throw new BodyTooLargeError(max);
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      try {
        await reader.cancel();
      } catch {
        /* the stream is going away either way */
      }
      throw new BodyTooLargeError(max);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Let go of a body that will not be read, so its connection can be reused or closed. */
export async function discard(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    /* already closed or errored: nothing left to release */
  }
}

/**
 * A header value Node will accept and a client cannot use to start another header:
 * CR and LF become spaces, and anything else outside printable Latin-1 is dropped.
 * `setHeader` throws on those characters, so a PDP reason carrying one would otherwise
 * turn a 401 challenge into a 500.
 */
export function sanitizeHeaderValue(v: string): string {
  return v.replace(/[\r\n]+/g, ' ').replace(/[^\t\x20-\x7e\x80-\xff]/g, '');
}

/** Is this an absolute http(s) URL `fetch` can be pointed at? */
export function isHttpUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.host !== '';
  } catch {
    return false;
  }
}

/** JSON.stringify that refuses what JSON cannot say, rather than quietly saying something else. */
export function encodeJson(value: unknown): string {
  // Infinity and NaN serialise as `null`: a policy that compares an amount against a
  // limit would be asked about null while the caller's own code acts on Infinity.
  return JSON.stringify(value, (_k, v: unknown) => {
    if (typeof v === 'number' && !Number.isFinite(v)) throw new TypeError(`${String(v)} has no JSON representation`);
    return v;
  });
}

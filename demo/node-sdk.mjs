// The Node SDK doing the same discovery, against the running stubs (compose or
// run-local.sh). Build the SDK first: `cd sdk/node && npm ci && npm run build`.
//
//   node demo/node-sdk.mjs            # stubs reachable as localhost:900x
//
// The stubs are plain http and the token below is unsigned, so every client here sets
// allowInsecure: the SDK refuses both otherwise. The first client also leaves out the
// PDP allowlist, which resource mode will not start without in production, to show
// what the allowlist is for.
import { AuthzenClient } from '../sdk/node/dist/index.js';

const host = process.env.STUBS_HOST ?? 'localhost';
const S = `http://${host}`;
const BANK_A = `${S}:9002/tenants/bank-a`;
const BANK_B = `${S}:9008/tenants/bank-b`;

// An unsigned demo access token, forwarded for the PDP to examine: the stub PDPs hold
// it to the acr and scopes each resource publishes.
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const accessToken = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'customer', client_id: 'agent-1', acr: 'urn:idp:loa:mfa', scope: 'accounts:read' })}.`;

const request = {
  subject: { type: 'agent', id: 'agent-1', properties: { on_behalf_of: 'customer', client_id: 'agent-1' } },
  action: { name: 'get_balance' },
  resource: { type: 'account', id: 'a1' },
};

const say = (label, v) => console.log(`${label.padEnd(58)} allow=${v.allow} ${v.kind} — ${v.reason}${v.detail ? ` [${v.detail}]` : ''}`);
const quiet = { onWarning: () => {} };

// No PDP allowlist: whatever a resource names, this client asks.
const open = new AuthzenClient({
  url: BANK_A,
  discovery: { mode: 'resource', allowInsecure: true, resourceAllowlist: [`${S}:9004`, `${S}:9005`, `${S}:9007`], ...quiet },
});
// The production shape: the PDPs a resource may name are listed.
const strict = new AuthzenClient({
  url: BANK_A,
  discovery: { mode: 'resource', allowInsecure: true, pdpAllowlist: [BANK_A, BANK_B], resourceAllowlist: [`${S}:9004`, `${S}:9005`, `${S}:9007`], ...quiet },
});

for (const [label, client, resource, token] of [
  ['plain resource -> Bank A, token forwarded', open, `${S}:9004`, accessToken],
  ['plain resource -> Bank A, no token to examine', open, `${S}:9004`, undefined],
  ['impostor resource -> ROGUE PDP, no allowlist (!)', open, `${S}:9005`, accessToken],
  ['impostor resource, PDP allowlist -> refused', strict, `${S}:9005`, accessToken],
  ['stray resource publishes nothing -> static PDP', strict, `${S}:9007`, accessToken],
  ['no resource -> static PDP', strict, undefined, accessToken],
]) {
  say(label, await client.evaluate(request, { resource, ...(token ? { accessToken: token } : {}) }));
}
console.log('\nThe SDK has no federation source; a route that must take the federation\'s word delegates to coaz-pep.');

// The Node SDK doing the same discovery, against the running stubs (compose or
// run-local.sh). Build the SDK first: `cd sdk/node && npm install && npm run build`.
//
//   node demo/node-sdk.mjs            # stubs reachable as localhost:900x
import { AuthzenClient } from '../sdk/node/dist/index.js';

const host = process.env.STUBS_HOST ?? 'localhost';
const S = `http://${host}`;
const request = (human) => ({
  subject: { type: 'agent', id: 'agent-1', properties: { on_behalf_of: human } },
  action: { name: 'get_balance' },
  resource: { type: 'account', id: 'a1' },
});

const client = new AuthzenClient({
  url: `${S}:9002`,
  apiKey: 'static-pdp-key',
  discovery: { mode: 'resource', allowInsecure: true, resourceAllowlist: [`${S}:9004`, `${S}:9005`] },
});

for (const [label, resource, human] of [
  ['plain resource -> good PDP, alice', `${S}:9004`, 'alice'],
  ['plain resource -> good PDP, mallory', `${S}:9004`, 'mallory'],
  ['impostor resource -> ROGUE PDP, mallory (!)', `${S}:9005`, 'mallory'],
  ['no resource -> static PDP, mallory', undefined, 'mallory'],
]) {
  const v = await client.evaluate(request(human), { resource });
  console.log(`${label.padEnd(48)} allow=${v.allow} ${v.kind} — ${v.reason}`);
}
console.log('\nThe SDK has no federation source; a route that must take the federation\'s word delegates to coaz-pep.');

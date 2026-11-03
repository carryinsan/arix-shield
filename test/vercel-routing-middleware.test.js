import test from 'node:test';
import assert from 'node:assert/strict';
import { createEdgeClearanceTicket } from '../api/_lib/edge-clearance.js';
import { createEdgeClearanceProxy } from '../proxy-core.js';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const SECRET = 'test-only-arix-edge-secret-'.padEnd(48, 'x');
const ORIGIN = 'https://shield.example';

test('deployment config points at the framework-independent proxy and pins its runtime helper', async () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const vercel = JSON.parse(await readFile(resolve(root, 'vercel.json'), 'utf8'));
  const pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  assert.equal(vercel.proxy?.entrypoint, 'proxy.js');
  assert.ok(Array.isArray(vercel.proxy?.matcher) && vercel.proxy.matcher.length > 0);
  assert.deepEqual(pkg.dependencies, { '@vercel/functions': '3.10.5' });
  assert.equal(pkg.devDependencies, undefined);
  const entrypoint = await readFile(resolve(root, 'proxy.js'), 'utf8');
  assert.match(entrypoint, /from ['"]@vercel\/functions['"]/);
  assert.match(entrypoint, /export default/);
  assert.doesNotMatch(entrypoint, /next\/server/);
  await assert.rejects(readFile(resolve(root, 'middleware.js')));
});

function harness(env) {
  const calls = [];
  const proxy = createEdgeClearanceProxy({
    getEnv: () => env,
    next: (options) => {
      calls.push(options);
      return new Response('continued', { status: 200 });
    },
  });
  return { proxy, calls };
}

function ticket(options = {}) {
  return createEdgeClearanceTicket({
    audience: ORIGIN,
    pathPrefix: '/protected',
    methods: ['GET'],
    secret: SECRET,
    ...options,
  });
}

test('Vercel proxy passes through normally when optional edge proof is disabled', async () => {
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'false' });
  const response = await proxy(new Request(`${ORIGIN}/protected`));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'continued');
  assert.deepEqual(calls, [undefined]);
});

test('static exclusions pass through before clearance configuration is required', async () => {
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true' });
  const response = await proxy(new Request(`${ORIGIN}/_next/static/app.js`));
  assert.equal(response.status, 200);
  assert.deepEqual(calls, [undefined]);
});

test('required clearance fails closed when the master secret is missing or too short', async () => {
  for (const secret of [undefined, 'short']) {
    const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: secret });
    const response = await proxy(new Request(`${ORIGIN}/protected`));
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(calls, []);
  }
});

test('required clearance rejects absent, malformed, and tampered tickets', async () => {
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: SECRET });
  for (const value of ['', 'not-a-ticket', `${ticket().slice(0, -1)}x`]) {
    const response = await proxy(new Request(`${ORIGIN}/protected`, {
      headers: value ? { 'x-arix-edge-ticket': value } : {},
    }));
    assert.equal(response.status, 403);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
  assert.deepEqual(calls, []);
});

test('valid header ticket continues routing and adds only the verification response header', async () => {
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: SECRET });
  const response = await proxy(new Request(`${ORIGIN}/protected/resource?x=1`, {
    method: 'GET',
    headers: { 'x-arix-edge-ticket': ticket() },
  }));
  assert.equal(response.status, 200);
  assert.deepEqual(calls, [{ headers: { 'x-arix-edge-verified': '1' } }]);
});

test('valid cookie ticket continues routing using standard Web Request headers', async () => {
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: SECRET });
  const response = await proxy(new Request(`${ORIGIN}/protected/resource`, {
    headers: { cookie: `session=ok; arix_edge_clearance=${ticket()}` },
  }));
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].headers['x-arix-edge-verified'], '1');
});

test('duplicate clearance cookie names fail closed', async () => {
  const valid = ticket();
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: SECRET });
  const response = await proxy(new Request(`${ORIGIN}/protected`, {
    headers: { cookie: `arix_edge_clearance=${valid}; arix_edge_clearance=${valid}` },
  }));
  assert.equal(response.status, 403);
  assert.deepEqual(calls, []);
});

test('tickets remain bound to exact origin, path boundary, and method', async () => {
  const env = { ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: SECRET };
  const cases = [
    { url: 'https://other.example/protected', method: 'GET', value: ticket() },
    { url: `${ORIGIN}/protected-evil`, method: 'GET', value: ticket() },
    { url: `${ORIGIN}/protected`, method: 'POST', value: ticket() },
  ];
  for (const item of cases) {
    const { proxy, calls } = harness(env);
    const response = await proxy(new Request(item.url, {
      method: item.method,
      headers: { 'x-arix-edge-ticket': item.value },
    }));
    assert.equal(response.status, 403);
    assert.deepEqual(calls, []);
  }
});

test('unparseable request URL returns a bounded client error instead of throwing', async () => {
  const { proxy, calls } = harness({ ARIX_EDGE_PROOF_REQUIRED: 'true', ARIX_MASTER_SECRET: SECRET });
  const response = await proxy({ url: 'not a URL', method: 'GET', headers: new Headers() });
  assert.equal(response.status, 400);
  assert.deepEqual(calls, []);
});

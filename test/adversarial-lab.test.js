import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Readable } from 'node:stream';
import { readJson } from '../api/_lib/http.js';
import { inspectRequest } from '../api/_lib/waf-engine.js';
import { authorizeRequest } from '../api/_lib/authorization.js';
import { sealResourceId, rewriteCapabilityRequest, verifyDpopProof, base64urlEncode } from '../api/_lib/crypto-trap.js';
import { acquireConcurrency, releaseConcurrency, rateLimitMulti } from '../api/_lib/redis.js';

process.env.NODE_ENV = 'test';
process.env.ARIX_MASTER_SECRET = 'A'.repeat(64);
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;

function attackRequest(index) {
  const variant = index % 6;
  const marker = `v${index.toString(36)}`;
  if (variant === 0) {
    const payload = ["' OR 1=1 --", '%27%20OR%201%3D1%20--', '%2527%2520OR%25201%253D1%2520--'][Math.floor(index / 6) % 3];
    return { method: 'GET', url: `/search?q=${payload}&case=${marker}` };
  }
  if (variant === 1) {
    const payload = `<script>globalThis.${marker}=1</script>`;
    const encoded = index % 12 === 1 ? `&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;` : index % 12 === 7 ? String.raw`\u003cscript\u003ealert(1)\u003c/script\u003e` : encodeURIComponent(encodeURIComponent(payload));
    return { method: 'GET', url: `/lookup?q=${encodeURIComponent(encoded)}` };
  }
  if (variant === 2) {
    return { method: 'POST', url: '/comments', headers: { 'content-type': 'text/plain' }, body: index % 12 === 8 ? `/*!50000 UNION SELECT ${marker} FROM users*/` : `UNION SELECT ${marker} FROM users` };
  }
  if (variant === 3) {
    const body = JSON.parse('{"profile":{"__proto__":{"polluted":true}}}');
    return { method: 'POST', url: '/api/profile', headers: { 'content-type': 'application/json' }, body };
  }
  if (variant === 4) {
    return { method: 'GET', url: `/search?term=${marker}&term=forged` };
  }
  return { method: 'POST', url: '/comments', headers: { 'content-type': 'application/json' }, body: { pad: 'x'.repeat(16365), q: `' OR 1=1 -- ${marker}` }, streamSplitAt: 16384 };
}

test('adversarial lab blocks all 2,500 deterministic grammar/encoding/boundary mutations', async () => {
  let blocked = 0;
  const misses = [];
  for (let index = 0; index < 2500; index++) {
    const request = attackRequest(index);
    if (request.streamSplitAt) {
      const raw = Buffer.from(JSON.stringify(request.body));
      const split = request.streamSplitAt;
      const stream = Readable.from([raw.subarray(0, split), raw.subarray(split)]);
      stream.headers = {};
      request.body = await readJson(stream, 32768);
      assert.equal(raw.indexOf(Buffer.from(`' OR 1=1 --`)) < split, true);
      assert.equal(raw.indexOf(Buffer.from(`' OR 1=1 --`)) + Buffer.byteLength(`' OR 1=1 --`) > split, true);
      delete request.streamSplitAt;
    }
    const inspection = inspectRequest({ production: true, ...request });
    if (!inspection.allowed) blocked++;
    else if (misses.length < 10) misses.push({ index, url: request.url, bodyPreview: String(request.body || '').slice(-90) });
  }
  assert.equal(blocked, 2500, `Generated corpus block rate ${(blocked / 2500 * 100).toFixed(2)}%; misses: ${JSON.stringify(misses)}`);
});

test('adversarial lab keeps false-positive rate below 0.1% on 2,500 benign multilingual inputs', () => {
  const samples = [
    (n) => `O'Connor-${n} is a registered customer name; contact details are verified by the support team.`,
    (n) => `SQL tutorial ${n}: SELECT retrieves rows; the -- symbol begins a line comment, and /* ... */ is a block comment.`,
    (n) => `JavaScript tutorial ${n}: // begins a line comment, /* ... */ spans multiple lines, and strings may contain < and > characters.`,
    (n) => `Math ${n}: for x < 10, y > 2, x <= y, and z = x + y, evaluate the expression without changing the original values.`,
    (n) => `Formula ${n}: a != b && c >= d || total = left + right; compare the variables as mathematical notation.`,
    (n) => `नमस्ते ${n}, ગુજરાતી ભાષા, café crème, 東京, مرحباً بالعالم — UTF-8 content is supported.`,
    (n) => `User comment ${n}: I am learning about prepared statements, parameterized SQL queries, escaping, and safe JavaScript DOM APIs.`,
    (n) => `O'Neil-${n}: The lesson compares <section>, >, =, and & operators as literal examples in documentation.`
  ];
  let falsePositives = 0;
  const rejected = [];
  for (let index = 0; index < 2500; index++) {
    const body = samples[index % samples.length](index);
    const inspection = inspectRequest({ method: 'POST', url: '/comments', headers: { 'content-type': 'text/plain; charset=utf-8' }, body, production: true });
    if (!inspection.allowed) { falsePositives++; if (rejected.length < 10) rejected.push({ index, findings: inspection.findings.map((item) => item.id), body }); }
  }
  const rate = falsePositives / 2500;
  assert.ok(rate < 0.001, `False-positive rate ${(rate * 100).toFixed(3)}%: ${JSON.stringify(rejected)}`);
});

test('BOLA/BFLA matrix: five actor classes × four methods × four ID placements', async () => {
  const owner = { tenantId: 'tenant-a', userId: 'user-a' };
  const actors = [
    { name: 'User A', context: { ...owner, roles: ['admin'] }, expected: true },
    { name: 'User B', context: { tenantId: 'tenant-b', userId: 'user-b', roles: ['admin'] }, expected: false },
    { name: 'Tenant A peer', context: { tenantId: 'tenant-a', userId: 'user-peer', roles: ['member'] }, expected: false },
    { name: 'Tenant B admin', context: { tenantId: 'tenant-b', userId: 'user-c', roles: ['admin'] }, expected: false },
    { name: 'Anonymous', context: { tenantId: 'tenant-a', userId: 'anonymous', roles: [] }, expected: false }
  ];
  const methods = ['GET', 'POST', 'PATCH', 'DELETE'];
  let evaluated = 0;
  for (const actor of actors) for (const method of methods) {
    const mode = method === 'DELETE' ? 'delete' : ['POST', 'PATCH'].includes(method) ? 'write' : 'read';
    const ownerId = sealResourceId('42001', owner, mode);
    const variants = [
      { label: 'path', url: `/api/records/${encodeURIComponent(ownerId)}`, body: null },
      { label: 'query', url: `/api/records?recordId=${encodeURIComponent(ownerId)}`, body: null },
      { label: 'body', url: '/api/records', body: { recordId: ownerId } },
      { label: 'unsealed-or-forged', url: '/api/records/42001', body: { recordId: '42001' } }
    ];
    for (const variant of variants) {
      const capability = rewriteCapabilityRequest(variant.url, variant.body, actor.context, { method, requireSealed: true });
      const expectedAllow = actor.expected && variant.label !== 'unsealed-or-forged';
      const auth = await authorizeRequest({
        method, pathname: '/api/records/42001',
        routes: [{ path: '/api/records/:id', methods: [method], authenticated: true, roles: ['admin'], tenantIsolated: true, requirePreCheck: true,
          preCheck: async ({ context, request }) => request?.capabilityValid === true && request?.tenantId === context.tenantId && request?.ownerId === context.userId && context.tenantId === 'tenant-a' && context.userId === 'user-a' }],
        context: actor.context, defaultDenyMutations: true, requireScopedPrecheck: true,
        request: { tenantId: 'tenant-a', ownerId: 'user-a', capabilityValid: !capability.invalid, idPlacement: variant.label }
      });
      assert.equal(capability.invalid, !expectedAllow, `${actor.name}/${method}/${variant.label} capability decision`);
      assert.equal(auth.allowed, expectedAllow, `${actor.name}/${method}/${variant.label} authorization decision`);
      evaluated++;
    }
  }
  assert.equal(evaluated, 80);
});

function encodeJson(value) { return base64urlEncode(new TextEncoder().encode(JSON.stringify(value))); }
async function makeDpopProof(pair, jti) {
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const header = encodeJson({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk });
  const payload = encodeJson({ htm: 'POST', htu: 'https://service.example.test/api/lease', iat: Math.floor(Date.now() / 1000), jti });
  const signingInput = `${header}.${payload}`;
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

test('100-way quota leases and DPoP replay/outage chaos fail closed under concurrent load', async () => {
  const quotaKey = `arix:lab:quota:${Date.now()}`;
  const leaseKey = `arix:lab:lease:${Date.now()}`;
  const quota = await Promise.all(Array.from({ length: 100 }, (_, index) => rateLimitMulti({ dimensions: [{ key: quotaKey, limit: 13, windowMs: 60000 }, { key: `${quotaKey}:actor:${index}`, limit: 200, windowMs: 60000 }] })));
  assert.equal(quota.filter((result) => result.allowed).length, 13, 'quota bucket must not exceed its 13-request capacity');
  const leases = await Promise.all(Array.from({ length: 100 }, (_, index) => acquireConcurrency(leaseKey, `member-${index}`, { maximum: 9, ttlMs: 5000 })));
  const admitted = leases.filter((lease) => lease.allowed);
  assert.equal(admitted.length, 9, 'concurrency leases must not exceed maximum=9');
  await Promise.all(admitted.map((lease) => releaseConcurrency(lease.key, lease.member)));

  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const proofs = await Promise.all(Array.from({ length: 100 }, (_, index) => makeDpopProof(pair, `chaos-jti-${index.toString().padStart(4, '0')}-unique`)));
  const results = await Promise.all(proofs.map((proof, index) => verifyDpopProof({ proof, method: 'POST', url: 'https://service.example.test/api/lease', projectId: `lab-${index}`, redisGetSet: async () => { if (index % 7 === 0) throw new Error('injected mid-flight Redis timeout'); return 'OK'; } })));
  assert.equal(results.filter((result) => result.valid).length, 85, 'Redis timeout cases must fail closed; reachable cases must validate');
  const replayPair = await makeDpopProof(pair, 'concurrent-replay-jti-0001');
  const replayResults = await Promise.all(Array.from({ length: 100 }, () => verifyDpopProof({ proof: replayPair, method: 'POST', url: 'https://service.example.test/api/lease', projectId: 'same-actor', redisGetSet: async () => 'OK' })));
  assert.equal(replayResults.filter((result) => result.valid).length, 1, 'a concurrent DPoP replay must be accepted at most once in one process');
});

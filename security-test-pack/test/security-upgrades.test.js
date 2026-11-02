import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeRequest, filterReadFields, filterWriteFields, normalizeSecurityPath, scopeQuery } from '../api/_lib/authorization.js';
import { sealResourceId, rewriteCapabilityRequest, verifyResourceId } from '../api/_lib/crypto-trap.js';
import { inspectRequest, validateJsonSchema } from '../api/_lib/waf-engine.js';
import { validateOpenApiRequest } from '../api/_lib/schema.js';
import { rateLimitMulti, acquireConcurrency, releaseConcurrency, getJsonOnce, setJson, incrementWithExpiry, setMaxStringWithExpiry, getString } from '../api/_lib/redis.js';
import { runWithCircuit, getCircuitState, resetCircuit, CircuitOpenError } from '../api/_lib/circuit-breaker.js';
import { arixSafeFetch } from '../sdk/safe-fetch.js';
import { quotaDimensions, validateWorkflowRequest } from '../sdk/security-runtime.js';
import { generateTotpSecret, decryptTotpSecret, verifyTotp } from '../api/_lib/mfa.js';
import { decodeWebAuthnBase64url, verifyWebAuthnRegistration } from '../api/_lib/webauthn.js';

process.env.NODE_ENV = 'test';
process.env.ARIX_MASTER_SECRET = 'A'.repeat(64);

test('Node and Next adapters reject an ownership pre-check before invoking the route handler', async () => {
  const { createArixShield } = await import('../sdk/node.js');
  const { withArixShield } = await import('../sdk/next.js');
  const authorization = {
    routes: [{
      method: 'PATCH', path: '/api/orders/:id', roles: ['customer'],
      tenantIsolated: true, requirePreCheck: true,
      preCheck: async ({ request, context }) => request?.params?.id === '1002' && context.userId === 'user-a' && false
    }]
  };
  const nodeMiddleware = createArixShield({
    serverKey: 'ARIX_SECRET_TEST_NODE_MIDDLEWARE', mode: 'ENFORCE', globalRateLimit: false,
    mutationTripwire: true, reputationProtection: false, abuseProtection: false,
    getIdentity: (req) => req.user?.id,
    getAuthorizationContext: (req) => ({ userId: req.user.id, tenantId: req.user.tenantId, roles: ['customer'] }),
    authorization
  });
  let nodeHandlerCalled = false;
  const nodeResponse = { statusCode: 200, headers: {}, body: '', setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = value; } };
  await nodeMiddleware({ method: 'PATCH', url: '/api/orders/1002', originalUrl: '/api/orders/1002', headers: { 'content-type': 'application/json' }, body: { amount: 1 }, user: { id: 'user-a', tenantId: 'tenant-a' }, params: { id: '1002' }, socket: { remoteAddress: '203.0.113.10' } }, nodeResponse, () => { nodeHandlerCalled = true; });
  assert.equal(nodeResponse.statusCode, 403);
  assert.equal(nodeHandlerCalled, false);

  let nextHandlerCalled = false;
  const nextHandler = withArixShield(async () => { nextHandlerCalled = true; return Response.json({ ok: true }); }, {
    mode: 'ENFORCE', globalRateLimit: false, reputationProtection: false, abuseProtection: false,
    mutationTripwire: true,
    getIdentity: () => 'user-a',
    getAuthorizationContext: () => ({ userId: 'user-a', tenantId: 'tenant-a', roles: ['customer'] }),
    authorization: { routes: [{ method: 'PATCH', path: '/api/orders/:id', roles: ['customer'], tenantIsolated: true, requirePreCheck: true, preCheck: async () => false }] }
  });
  const nextResponse = await nextHandler(new Request('https://app.example.test/api/orders/1002', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ amount: 1 }) }));
  assert.equal(nextResponse.status, 403);
  assert.equal(nextHandlerCalled, false);
});

test('authorization matrix denies before route execution and enforces tenant and role constraints', async () => {
  const routes = { '/api/orders/:id': { methods: ['PATCH'], roles: ['billing'], tenantIsolated: true } };
  const deniedRole = await authorizeRequest({ method: 'PATCH', pathname: '/api/orders/1', routes, context: { userId: 'u1', tenantId: 't1', roles: ['reader'] } });
  const missingTenant = await authorizeRequest({ method: 'PATCH', pathname: '/api/orders/1', routes, context: { userId: 'u1', roles: ['billing'] } });
  const allowed = await authorizeRequest({ method: 'PATCH', pathname: '/api/orders/1', routes, context: { userId: 'u1', tenantId: 't1', roles: ['billing'] } });
  const defaultDenied = await authorizeRequest({ method: 'DELETE', pathname: '/api/new-route', routes, context: { userId: 'u1' }, defaultDenyMutations: true });
  assert.equal(deniedRole.reason, 'ROLE_REQUIRED');
  assert.equal(missingTenant.reason, 'TENANT_CONTEXT_REQUIRED');
  assert.equal(allowed.allowed, true);
  assert.equal(defaultDenied.reason, 'NO_AUTHORIZATION_POLICY');
});

test('mutation tripwire requires tenant isolation and a passing pre-handler ownership check', async () => {
  const noCheck = await authorizeRequest({ method: 'DELETE', pathname: '/api/orders/1', routes: { '/api/orders/*': { methods: ['DELETE'], roles: ['admin'], tenantIsolated: true } }, context: { userId: 'u1', tenantId: 't1', roles: ['admin'] }, defaultDenyMutations: true, requireScopedPrecheck: true });
  const falseCheck = await authorizeRequest({ method: 'DELETE', pathname: '/api/orders/1', routes: [{ path: '/api/orders/*', methods: ['DELETE'], roles: ['admin'], tenantIsolated: true, requirePreCheck: true, preCheck: async () => false }], context: { userId: 'u1', tenantId: 't1', roles: ['admin'] }, defaultDenyMutations: true, requireScopedPrecheck: true });
  const passCheck = await authorizeRequest({ method: 'DELETE', pathname: '/api/orders/1', routes: [{ path: '/api/orders/*', methods: ['DELETE'], roles: ['admin'], tenantIsolated: true, requirePreCheck: true, preCheck: async ({ request, context }) => request?.owner === context.userId }], context: { userId: 'u1', tenantId: 't1', roles: ['admin'] }, defaultDenyMutations: true, requireScopedPrecheck: true, request: { owner: 'u1' } });
  assert.equal(noCheck.reason, 'MUTATION_SCOPE_PRECHECK_REQUIRED');
  assert.equal(falseCheck.reason, 'AUTHORIZATION_PRECHECK_DENIED');
  assert.equal(passCheck.allowed, true);
});

test('BOPLA strips forbidden write properties and restricted output fields', () => {
  const write = filterWriteFields({ name: 'Ada', role: 'admin', balance: 999, profile: { nickname: 'A', isStaff: true } }, { member: ['name', 'profile.nickname'] }, ['member']);
  const read = filterReadFields({ id: '1', name: 'Ada', passwordHash: 'secret', profile: { city: 'Patan', internalNotes: 'x' } }, { member: ['passwordHash', 'internalNotes'] }, ['member']);
  assert.deepEqual(JSON.parse(JSON.stringify(write)), { name: 'Ada', profile: { nickname: 'A' } });
  assert.deepEqual(JSON.parse(JSON.stringify(filterWriteFields([{ name: 'Ada', role: 'admin' }, { name: 'Grace', balance: 10 }], { member: ['name'] }, ['member']))), [{ name: 'Ada' }, { name: 'Grace' }]);
  assert.deepEqual(JSON.parse(JSON.stringify(read)), { id: '1', name: 'Ada', profile: { city: 'Patan' } });
});

test('scopeQuery injects both tenant and owner predicates without accepting raw SQL', () => {
  const prisma = scopeQuery({ where: { status: 'OPEN' }, take: 10 }, { tenantId: 'tenant-a', userId: 'user-a' });
  const mongo = scopeQuery({ status: 'OPEN' }, { tenantId: 'tenant-a', userId: 'user-a' }, { adapter: 'mongo' });
  assert.deepEqual(prisma.where.AND[1], { tenantId: 'tenant-a', ownerId: 'user-a' });
  assert.deepEqual(mongo.$and[1], { tenantId: 'tenant-a', ownerId: 'user-a' });
  assert.throws(() => scopeQuery('DELETE FROM orders', { tenantId: 't', userId: 'u' }), /structured query/);
});

test('tenant/user/mode-bound capabilities cover resource IDs in path, query and JSON body', () => {
  const identity = { tenantId: 'tenant-a', userId: 'user-a' };
  const orderRead = sealResourceId('1002', identity, 'read');
  const path = rewriteCapabilityRequest(`/api/orders/${encodeURIComponent(orderRead)}?orderId=${encodeURIComponent(orderRead)}`, null, identity, { method: 'GET' });
  assert.equal(path.invalid, false);
  assert.equal(path.url, '/api/orders/1002?orderId=1002');
  const accountWrite = sealResourceId('77', identity, 'write');
  const body = rewriteCapabilityRequest('/api/account', { accountId: accountWrite }, identity, { method: 'PATCH' });
  assert.equal(body.invalid, false);
  assert.deepEqual(JSON.parse(JSON.stringify(body.body)), { accountId: '77' });
  assert.equal(rewriteCapabilityRequest('/api/account?accountId=77', null, identity, { method: 'GET' }).invalid, true);
  assert.equal(verifyResourceId(orderRead, { tenantId: 'tenant-b', userId: 'user-a' }), null);
  assert.equal(verifyResourceId(orderRead, { tenantId: 'tenant-a', userId: 'user-b' }), null);
  assert.equal(rewriteCapabilityRequest(`/api/orders/${encodeURIComponent(orderRead)}`, null, identity, { method: 'DELETE' }).invalid, true);
});

test('path canonicalization rejects encoded separators and resolves dot segments consistently', () => {
  assert.equal(normalizeSecurityPath('/api/orders/../accounts'), '/api/accounts');
  assert.equal(normalizeSecurityPath('/api%2Fadmin'), null);
  assert.equal(normalizeSecurityPath('/api/%252fadmin'), null);
});

test('WAF normalizes NFKC, detects duplicate JSON/query keys and request-smuggling headers', () => {
  const unicode = inspectRequest({ method: 'POST', url: '/search', headers: { 'content-type': 'application/json' }, body: { q: 'ＵＮＩＯＮ ＳＥＬＥＣＴ * FROM users' } });
  const duplicateJson = inspectRequest({ method: 'POST', url: '/api', headers: { 'content-type': 'application/json' }, rawBody: Buffer.from('{"role":"reader","role":"admin"}'), body: { role: 'admin' } });
  const duplicateQuery = inspectRequest({ method: 'GET', url: '/api?orderId=1&orderId=2' });
  const smuggling = inspectRequest({ method: 'POST', url: '/api', headers: { 'content-type': 'application/json', 'content-length': '4', 'transfer-encoding': 'chunked' }, body: {} });
  assert.ok(unicode.findings.some((item) => item.category === 'SQL_INJECTION'));
  assert.ok(duplicateJson.findings.some((item) => item.id === 'JSON_DUPLICATE_KEY'));
  assert.ok(duplicateQuery.findings.some((item) => item.id === 'HTTP_PARAMETER_POLLUTION'));
  assert.ok(smuggling.findings.some((item) => item.id === 'HTTP_SMUGGLING_HEADERS'));
});

test('WAF enforces GraphQL depth, aliases, production introspection, XML XXE and upload magic bytes', () => {
  const deep = inspectRequest({ method: 'POST', url: '/graphql', headers: { 'content-type': 'application/json' }, body: { query: '{ a { b { c { d { e { f { g { h { i } } } } } } } }' }, production: true });
  const aliases = inspectRequest({ method: 'POST', url: '/graphql', headers: { 'content-type': 'application/json' }, body: { query: '{ a1:u a2:u a3:u a4:u a5:u }' }, production: true });
  const introspection = inspectRequest({ method: 'POST', url: '/graphql', headers: { 'content-type': 'application/json' }, body: { query: '{ __schema { types { name } } }' }, production: true });
  const xml = inspectRequest({ method: 'POST', url: '/xml', headers: { 'content-type': 'application/xml' }, rawBody: Buffer.from('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>') });
  const badPng = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'image/png' }, rawBody: Buffer.from('MZ00EXE!') });
  const boundary = 'ArixBoundary42';
  const badMultipartBytes = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"attack.png\"\r\nContent-Type: image/png\r\n\r\n`),
    Buffer.from('MZ00EXE!'), Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);
  const badMultipart = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, rawBody: badMultipartBytes, contentLength: badMultipartBytes.length });
  const missingRawMultipart = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, body: { file: 'present' } });
  assert.ok(deep.findings.some((item) => item.id === 'GRAPHQL_DEPTH'));
  assert.ok(aliases.findings.some((item) => item.id === 'GRAPHQL_ALIASES'));
  assert.ok(introspection.findings.some((item) => item.id === 'GRAPHQL_INTROSPECTION'));
  assert.ok(xml.findings.some((item) => item.id === 'XML_DTD_XXE'));
  assert.ok(badPng.findings.some((item) => item.id === 'UPLOAD_MAGIC_MISMATCH'));
  assert.ok(badMultipart.findings.some((item) => item.id === 'UPLOAD_MAGIC_MISMATCH'));
  assert.ok(missingRawMultipart.findings.some((item) => item.id === 'UPLOAD_RAW_BODY_REQUIRED'));
});

test('OpenAPI validation covers path, query, headers, and request body', () => {
  const document = { paths: { '/api/orders/{orderId}': { patch: { parameters: [
    { name: 'orderId', in: 'path', required: true, schema: { type: 'integer', minimum: 1 } },
    { name: 'status', in: 'query', required: true, schema: { type: 'string', enum: ['OPEN', 'CLOSED'] } },
    { name: 'x-tenant', in: 'header', required: true, schema: { type: 'string', minLength: 3 } }
  ], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['note'], properties: { note: { type: 'string', minLength: 2 } }, additionalProperties: false } } } } } } } };
  const good = validateOpenApiRequest(document, { method: 'PATCH', url: 'https://example.test/api/orders/42?status=OPEN', headers: { 'x-tenant': 't-1' }, body: { note: 'ok' } });
  const bad = validateOpenApiRequest(document, { method: 'PATCH', url: 'https://example.test/api/orders/nope?status=BAD', headers: {}, body: { note: 'x', admin: true } });
  assert.equal(good.valid, true);
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.some((error) => error.startsWith('path.orderId')));
  assert.ok(bad.errors.some((error) => error.startsWith('header.x-tenant')));
});

test('OpenAPI JSON Schema composition validates allOf, anyOf and oneOf', () => {
  assert.equal(validateJsonSchema({ name: 'Ada', age: 20 }, { allOf: [{ type: 'object' }, { properties: { age: { type: 'integer', minimum: 18 } } }] }).valid, true);
  assert.equal(validateJsonSchema('Ada', { anyOf: [{ type: 'number' }, { type: 'string', minLength: 2 }] }).valid, true);
  assert.equal(validateJsonSchema('Ada', { oneOf: [{ type: 'string' }, { type: 'string', minLength: 2 }] }).valid, false);
});

test('four dimensional quota helper returns actor, subnet, tenant, and route buckets', () => {
  const dimensions = quotaDimensions({ actor: 'user-1', subnet: '203.0.113.0/24', tenant: 'tenant-1', method: 'GET', pathname: '/api/orders', limit: 50 });
  assert.deepEqual(dimensions.map((item) => item.name), ['actor', 'subnet', 'tenant', 'endpoint']);
  assert.equal(dimensions[0].limit, 50);
  assert.equal(dimensions[1].limit, 25000);
  assert.equal(dimensions[2].limit, 5000);
  assert.equal(dimensions[3].limit, 5000);
  assert.equal(dimensions[3].scope, 'GET:/api/orders');
});


test('signed workflow breadcrumbs enforce tenant/user binding, ordered steps and single-use replay protection', async () => {
  const config = { enabled: true, minStepMs: 0, workflows: [{ id: 'checkout-v1', steps: [{ method: 'GET', path: '/api/products' }, { method: 'POST', path: '/api/cart' }, { method: 'POST', path: '/api/checkout' }] }] };
  const first = await validateWorkflowRequest({ config, method: 'GET', pathname: '/api/products', headers: new Headers(), projectId: 'project-1', tenantId: 'tenant-1', actorId: 'user-1' });
  assert.equal(first.valid, true); assert.equal(first.matched, true); assert.equal(typeof first.ticket, 'string');
  let consumed = false;
  const headers = new Headers({ 'x-arix-flow': first.ticket });
  const second = await validateWorkflowRequest({ config, method: 'POST', pathname: '/api/cart', headers, projectId: 'project-1', tenantId: 'tenant-1', actorId: 'user-1', consumeNonce: async () => { if (consumed) return false; consumed = true; return true; } });
  assert.equal(second.valid, true); assert.equal(typeof second.ticket, 'string');
  const replay = await validateWorkflowRequest({ config, method: 'POST', pathname: '/api/cart', headers, projectId: 'project-1', tenantId: 'tenant-1', actorId: 'user-1', consumeNonce: async () => false });
  const foreign = await validateWorkflowRequest({ config, method: 'POST', pathname: '/api/cart', headers, projectId: 'project-1', tenantId: 'tenant-2', actorId: 'user-1', consumeNonce: async () => true });
  const outOfOrder = await validateWorkflowRequest({ config, method: 'POST', pathname: '/api/checkout', headers, projectId: 'project-1', tenantId: 'tenant-1', actorId: 'user-1', consumeNonce: async () => true });
  assert.equal(replay.reason, 'WORKFLOW_BREADCRUMB_REPLAY');
  assert.equal(foreign.reason, 'WORKFLOW_BREADCRUMB_INVALID');
  assert.equal(outOfOrder.reason, 'WORKFLOW_BREADCRUMB_INVALID');
});

test('multi-dimensional quota denies when any bucket is exhausted and leases concurrency atomically', async () => {
  const prefix = `arix:test:multi:${Date.now()}:${Math.random()}`;
  const dimensions = [{ key: `${prefix}:actor`, limit: 1, windowMs: 60000 }, { key: `${prefix}:tenant`, limit: 2, windowMs: 60000 }];
  assert.equal((await rateLimitMulti({ dimensions, weight: 1 })).allowed, true);
  assert.equal((await rateLimitMulti({ dimensions, weight: 1 })).allowed, false);
  const key = `${prefix}:concurrency`;
  const one = await acquireConcurrency(key, 'request-1', { maximum: 1, ttlMs: 5000 });
  const two = await acquireConcurrency(key, 'request-2', { maximum: 1, ttlMs: 5000 });
  assert.equal(one.allowed, true);
  assert.equal(two.allowed, false);
  assert.equal(await releaseConcurrency(key, 'request-1'), 1);
  assert.equal((await acquireConcurrency(key, 'request-3', { maximum: 1, ttlMs: 5000 })).allowed, true);
});

test('account failure counter increments with an atomic expiry window', async () => {
  const key = 'arix:test:account-fail:expiry-check';
  assert.equal(await incrementWithExpiry(key, 60), 1);
  assert.equal(await incrementWithExpiry(key, 60), 2);
  assert.equal(await incrementWithExpiry(key, 60), 3);
});

test('account retry deadline only moves forward under concurrent failure updates', async () => {
  const key = 'arix:test:account-backoff:max';
  await setMaxStringWithExpiry(key, 2000000000000, 60);
  await setMaxStringWithExpiry(key, 1999999999000, 60);
  assert.equal(Number(await getString(key)), 2000000000000);
});

test('GETDEL atomically consumes JSON challenges in the local adapter', async () => {
  const key = `arix:test:getdel:${Date.now()}`;
  await setJson(key, { nonce: 'once' }, 60);
  assert.deepEqual(await getJsonOnce(key), { nonce: 'once' });
  assert.equal(await getJsonOnce(key), null);
});

test('circuit breaker opens after three failures and allows one half-open recovery probe', async () => {
  const key = `test-circuit-${Date.now()}`;
  resetCircuit(key);
  for (let index = 0; index < 3; index++) await assert.rejects(runWithCircuit(key, async () => { throw new Error('offline'); }, { failureThreshold: 3, openMs: 60, timeoutMs: 50, tripAfterMs: 50 }));
  assert.equal(getCircuitState(key).state, 'OPEN');
  await assert.rejects(runWithCircuit(key, async () => 'not-yet'), CircuitOpenError);
  await new Promise((resolve) => setTimeout(resolve, 70));
  assert.equal(await runWithCircuit(key, async () => 'recovered', { failureThreshold: 3, openMs: 60, timeoutMs: 50, tripAfterMs: 50 }), 'recovered');
  assert.equal(getCircuitState(key).state, 'CLOSED');
  resetCircuit(key);
});

test('safe fetch rejects non-HTTPS and private, loopback, decimal and mapped destinations before network access', async () => {
  await assert.rejects(arixSafeFetch('http://example.com'), /HTTPS/);
  await assert.rejects(arixSafeFetch('https://127.0.0.1/'), /globally routable/);
  await assert.rejects(arixSafeFetch('https://2130706433/'), /globally routable/);
  await assert.rejects(arixSafeFetch('https://[::1]/'), /globally routable/);
  await assert.rejects(arixSafeFetch('https://[::ffff:127.0.0.1]/'), /globally routable/);
  await assert.rejects(arixSafeFetch('https://[64:ff9b::7f00:1]/'), /globally routable/);
  await assert.rejects(arixSafeFetch('https://[2002:7f00:1::]/'), /globally routable/);
});

test('TOTP encrypts secrets and verifies RFC 6238 SHA-1 six-digit vectors', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(verifyTotp(secret, '287082', { now: 59000, window: 0 }), true);
  assert.equal(verifyTotp(secret, '287083', { now: 59000, window: 0 }), false);
  const generated = generateTotpSecret();
  assert.equal(decryptTotpSecret(generated.encrypted), generated.secret);
});

test('WebAuthn parser rejects malformed credentials and non-canonical base64url', () => {
  assert.throws(() => decodeWebAuthnBase64url('not+base64', 64));
  assert.throws(() => verifyWebAuthnRegistration({ response: {} }, { challenge: 'x', origin: 'https://example.test', rpId: 'example.test' }));
});


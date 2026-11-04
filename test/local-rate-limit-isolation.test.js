import test from 'node:test';
import assert from 'node:assert/strict';
import { buildLocalQuotaDimensions, localNetworkPrefix, LocalQuotaStore } from '../sdk/local-rate-limit.js';

const testScope = `local-rate-isolation-${Date.now()}`;

test('anonymous local quota identity is stable across per-request random IDs and separates networks', () => {
  const first = buildLocalQuotaDimensions({ scope: testScope, identity: 'anonymous', actorIdentity: 'anonymous:request-one', networkIp: '198.51.100.24', method: 'POST', pathname: '/api/orders', routeLimit: 10, networkLimit: 100 });
  const second = buildLocalQuotaDimensions({ scope: testScope, identity: 'anonymous', actorIdentity: 'anonymous:request-two', networkIp: '198.51.100.24', method: 'POST', pathname: '/api/orders', routeLimit: 10, networkLimit: 100 });
  const other = buildLocalQuotaDimensions({ scope: testScope, identity: 'anonymous', actorIdentity: 'anonymous:request-three', networkIp: '198.51.101.24', method: 'POST', pathname: '/api/orders', routeLimit: 10, networkLimit: 100 });
  assert.equal(first[0].key, second[0].key, 'request UUID changes do not mint a new anonymous bucket');
  assert.notEqual(first[0].key, other[0].key, 'distinct IPv4 /24 prefixes receive separate aggregate network buckets');
  assert.equal(first[0].key, buildLocalQuotaDimensions({ scope: testScope, identity: 'anonymous', networkIp: '198.51.100.24', method: 'GET', pathname: '/another-route', routeLimit: 10, networkLimit: 100 })[0].key, 'aggregate network quota is shared across routes and methods');
  assert.notEqual(first[1].key, buildLocalQuotaDimensions({ scope: testScope, identity: 'anonymous', networkIp: '198.51.100.24', method: 'GET', pathname: '/another-route', routeLimit: 10, networkLimit: 100 })[1].key, 'route quota remains separated by method and path');
  assert.equal(localNetworkPrefix('2001:db8:abcd:1::1'), '2001:db8:abcd:1:0:0:0:0/64');
  assert.equal(localNetworkPrefix('not-an-ip'), 'unknown');
});


test('authenticated local quota is aggregate across methods and paths', () => {
  const store = new LocalQuotaStore({ maxBuckets: 32 });
  const makeDimensions = (pathname, method) => buildLocalQuotaDimensions({
    scope: `${testScope}-authenticated-aggregate`,
    identity: 'user:user-aggregate',
    actorIdentity: 'user:user-aggregate',
    authenticated: true,
    networkIp: '198.51.100.120',
    method,
    pathname,
    actorLimit: 10,
    routeLimit: 10
  });

  const first = makeDimensions('/api/path-0', 'GET');
  const second = makeDimensions('/api/path-1', 'POST');
  assert.equal(first.length, 1, 'authenticated users receive a stable aggregate actor dimension');
  assert.equal(first[0].key, second[0].key, 'method/path changes do not create new actor buckets');
  for (let index = 0; index < 10; index++) {
    assert.equal(store.consume(makeDimensions(`/api/churn-${index}`, index % 2 ? 'GET' : 'POST')).allowed, true);
  }
  for (let index = 10; index < 30; index++) {
    const result = store.consume(makeDimensions(`/api/churn-${index}`, index % 2 ? 'GET' : 'POST'));
    assert.equal(result.allowed, false, 'the aggregate user quota rejects requests on newly selected paths');
  }
  assert.equal(store.size, 1, 'authenticated path churn cannot allocate per-route buckets');
});

test('anonymous local quota also charges the verified device dimension when present', () => {
  const dimensions = buildLocalQuotaDimensions({ scope: testScope, identity: 'anonymous', actorIdentity: 'device:thumbprint-one', authenticated: false, networkIp: '203.0.113.20', method: 'GET', pathname: '/api/data', dpopVerified: true, actorLimit: 20, routeLimit: 10, networkLimit: 100 });
  assert.equal(dimensions.length, 3);
  assert.equal(dimensions[0].limit, 100);
  assert.equal(dimensions[1].limit, 10);
  assert.equal(dimensions[2].limit, 20);
});

test('LocalQuotaStore rejects repeated requests after the network quota and stays within a fixed capacity', () => {
  const store = new LocalQuotaStore({ maxBuckets: 2 });
  const dim = (key, limit = 10) => [{ key, limit }];
  for (let i = 0; i < 10; i++) assert.equal(store.consume(dim('same-client-route'), 60000, 1, i).allowed, true);
  assert.equal(store.consume(dim('same-client-route'), 60000, 1, 11).allowed, false);

  assert.equal(store.consume(dim('second-client-route'), 60000, 1, 12).allowed, true);
  const saturated = store.consume(dim('attacker-churn-route'), 60000, 1, 13);
  assert.equal(saturated.allowed, false);
  assert.equal(saturated.saturated, true);
  assert.equal(store.size, 2, 'live quota counters are not evicted to admit attacker-controlled new keys');

  assert.equal(store.consume(dim('attacker-churn-route'), 60000, 1, 180013).allowed, true, 'expired idle entries can be reclaimed');
  assert.ok(store.size <= 2);
});

test('Node SDK local fallback limits anonymous requests from the same IP despite random request IDs', async () => {
  const { createArixShield } = await import('../sdk/node.js');
  const middleware = createArixShield({
    serverKey: 'ARIX_SECRET_LOCAL_NODE_QUOTA_TEST', projectId: `node-local-quota-${Date.now()}`,
    mode: 'ENFORCE', rateLimitPerMinute: 10, globalRateLimit: false,
    abuseProtection: false, reputationProtection: false
  });
  let allowed = 0; let rejected = 0;
  for (let index = 0; index < 40; index++) {
    const res = {
      statusCode: 200, headers: {}, body: '',
      setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
      end(value = '') { this.body = String(value); }
    };
    await middleware({ method: 'POST', url: '/api/anonymous-limit', originalUrl: '/api/anonymous-limit', headers: { host: 'app.example.test', 'content-type': 'application/json' }, body: { index }, socket: { remoteAddress: '198.51.100.25' } }, res, () => { allowed++; });
    if (res.statusCode === 429) rejected++;
  }
  assert.equal(allowed, 10);
  assert.equal(rejected, 30);
});

test('Next.js SDK local fallback limits anonymous requests from the same IP despite random request IDs', async () => {
  const { protectRequest } = await import('../sdk/next.js');
  const options = {
    projectId: `next-local-quota-${Date.now()}`, mode: 'ENFORCE', rateLimitPerMinute: 10,
    globalRateLimit: false, reputationProtection: false, abuseProtection: false,
    getClientIp: () => '198.51.100.25'
  };
  let allowed = 0; let rejected = 0;
  for (let index = 0; index < 40; index++) {
    const request = new Request('https://app.example.test/api/anonymous-limit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ index }) });
    const result = await protectRequest(request, options);
    if (result.allowed) allowed++;
    else if (result.status === 429) rejected++;
    else assert.fail(`Unexpected SDK decision ${result.status}: ${result.response ? await result.response.text() : ''}`);
  }
  assert.equal(allowed, 10);
  assert.equal(rejected, 30);
});


test('Node SDK authenticated local fallback shares one quota across unique paths', async () => {
  const { createArixShield } = await import('../sdk/node.js');
  const middleware = createArixShield({
    serverKey: 'ARIX_SECRET_AUTH_NODE_QUOTA_TEST', projectId: `node-auth-local-${Date.now()}`,
    mode: 'ENFORCE', rateLimitPerMinute: 10, globalRateLimit: false,
    abuseProtection: false, reputationProtection: false,
    getIdentity: () => 'authenticated-user-1'
  });
  let allowed = 0; let rejected = 0;
  for (let index = 0; index < 20; index++) {
    const res = {
      statusCode: 200, headers: {}, body: '',
      setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
      end(value = '') { this.body = String(value); }
    };
    await middleware({ method: index % 2 ? 'GET' : 'POST', url: `/api/path-${index}`, originalUrl: `/api/path-${index}`, headers: { host: 'app.example.test' }, socket: { remoteAddress: '198.51.100.44' } }, res, () => { allowed++; });
    if (res.statusCode === 429) rejected++;
  }
  assert.equal(allowed, 10);
  assert.equal(rejected, 10);
});

test('Next.js SDK authenticated local fallback shares one quota across unique paths', async () => {
  const { protectRequest } = await import('../sdk/next.js');
  const options = {
    projectId: `next-auth-local-${Date.now()}`, mode: 'ENFORCE', rateLimitPerMinute: 10,
    globalRateLimit: false, reputationProtection: false, abuseProtection: false,
    getIdentity: () => 'authenticated-user-2', getClientIp: () => '198.51.100.44'
  };
  let allowed = 0; let rejected = 0;
  for (let index = 0; index < 20; index++) {
    const request = new Request(`https://app.example.test/api/path-${index}`, { method: index % 2 ? 'GET' : 'POST' });
    const result = await protectRequest(request, options);
    if (result.allowed) allowed++;
    else if (result.status === 429) rejected++;
    else assert.fail(`Unexpected SDK decision ${result.status}: ${result.response ? await result.response.text() : ''}`);
  }
  assert.equal(allowed, 10);
  assert.equal(rejected, 10);
});

test('anonymous network quota aggregates across different paths and methods', () => {
  const store = new LocalQuotaStore({ maxBuckets: 32 });
  let requestId = 0;
  const makeDimensions = (pathname, method) => buildLocalQuotaDimensions({
    scope: `${testScope}-network-aggregate`,
    identity: 'anonymous',
    actorIdentity: `anonymous:request-${++requestId}`,
    networkIp: '198.51.100.88',
    method,
    pathname,
    routeLimit: 10,
    networkLimit: 3
  });

  assert.equal(store.consume(makeDimensions('/api/one', 'GET')).allowed, true);
  assert.equal(store.consume(makeDimensions('/api/two', 'POST')).allowed, true);
  assert.equal(store.consume(makeDimensions('/api/three', 'DELETE')).allowed, true);
  const fourth = store.consume(makeDimensions('/api/four', 'GET'));
  assert.equal(fourth.allowed, false, 'changing method/path cannot reset the aggregate network quota');
  assert.equal(store.consume(makeDimensions('/api/five', 'GET')).allowed, false);
});

test('rotating verified anonymous DPoP keys cannot bypass the aggregate network quota', () => {
  const store = new LocalQuotaStore({ maxBuckets: 64 });
  const makeDimensions = (keyNumber) => buildLocalQuotaDimensions({
    scope: `${testScope}-dpop-rotation`,
    identity: 'anonymous',
    actorIdentity: `device:thumbprint-${keyNumber}`,
    authenticated: false,
    networkIp: '198.51.100.91',
    method: keyNumber % 2 ? 'GET' : 'POST',
    pathname: `/api/resource-${keyNumber}`,
    dpopVerified: true,
    actorLimit: 20,
    routeLimit: 10,
    networkLimit: 3
  });

  assert.equal(store.consume(makeDimensions(1)).allowed, true);
  assert.equal(store.consume(makeDimensions(2)).allowed, true);
  assert.equal(store.consume(makeDimensions(3)).allowed, true);
  const rotated = store.consume(makeDimensions(4));
  assert.equal(rotated.allowed, false, 'a new DPoP key and route do not reset the shared network dimension');
});

test('exhausted network quota does not allocate counters for attacker-churned paths or DPoP keys', () => {
  const store = new LocalQuotaStore({ maxBuckets: 1024 });
  const base = {
    scope: `${testScope}-denied-churn`, identity: 'anonymous', authenticated: false,
    networkIp: '198.51.100.99', dpopVerified: true,
    actorLimit: 20, routeLimit: 20, networkLimit: 1
  };
  const first = buildLocalQuotaDimensions({ ...base, actorIdentity: 'device:first', method: 'GET', pathname: '/api/first' });
  assert.equal(store.consume(first).allowed, true);
  const initialSize = store.size;
  for (let index = 0; index < 500; index++) {
    const dimensions = buildLocalQuotaDimensions({ ...base, actorIdentity: `device:rotated-${index}`, method: 'POST', pathname: `/api/churn-${index}` });
    const decision = store.consume(dimensions);
    assert.equal(decision.allowed, false);
  }
  assert.equal(store.size, initialSize, 'denied requests do not allocate unique route/device buckets');
});

test('verified anonymous request weights fit the local network, route and device dimensions', () => {
  const store = new LocalQuotaStore({ maxBuckets: 16 });
  const dimensions = buildLocalQuotaDimensions({
    scope: `${testScope}-weighted-dpop`, identity: 'anonymous', actorIdentity: 'device:weighted',
    authenticated: false, networkIp: '198.51.100.101', method: 'POST', pathname: '/api/weighted',
    dpopVerified: true, actorLimit: 25, routeLimit: 25, networkLimit: 100
  });
  assert.equal(store.consume(dimensions, 60000, 15).allowed, true, 'every configured dimension can admit the same request weight');
});


test('local fallback accepts 100 ms minimum window and rejects smaller windows', () => {
  const store = new LocalQuotaStore({ maxBuckets: 8 });
  const dimensions = [{ key: 'short-window', limit: 2 }];
  assert.equal(store.consume(dimensions, 100, 1, 1000).allowed, true);
  assert.equal(store.consume(dimensions, 100, 1, 1001).allowed, true);
  assert.equal(store.consume(dimensions, 100, 1, 1002).allowed, false);
  assert.throws(() => store.consume(dimensions, 99, 1, 1003), RangeError);
});

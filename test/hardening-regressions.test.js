import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { clientRateKey, sameOriginRequest, setSessionCookie } from '../api/_lib/http.js';
import { normalizeSecurityPath } from '../api/_lib/authorization.js';
import { inspectRequest } from '../api/_lib/waf-engine.js';
import { isBreachedPassword, validatePasswordPolicy } from '../api/_lib/password-policy.js';

function withEnv(name, value, callback) {
  const original = process.env[name];
  if (value === undefined) delete process.env[name]; else process.env[name] = value;
  try { return callback(); }
  finally { if (original === undefined) delete process.env[name]; else process.env[name] = original; }
}

test('client rate keys ignore blank and spoofed ingress headers, then use a validated peer IP', () => {
  withEnv('VERCEL', undefined, () => {
    const key = clientRateKey({ headers: { 'x-real-ip': '', 'x-vercel-forwarded-for': '203.0.113.5', 'user-agent': 'test-agent' }, socket: { remoteAddress: '203.0.113.17' } });
    assert.equal(key, '203.0.113.17:test-agent');
  });
});

test('same-origin validation ignores forwarded-host and compares the actual Host authority', () => {
  withEnv('VERCEL', undefined, () => withEnv('ARIX_TRUST_PROXY_HEADERS', undefined, () => {
    const req = { headers: { origin: 'https://attacker.example', host: 'app.example', 'x-forwarded-host': 'attacker.example' }, socket: { encrypted: true } };
    assert.equal(sameOriginRequest(req), false);
    req.headers.origin = 'https://app.example';
    assert.equal(sameOriginRequest(req), true);
  }));
});

test('path normalization rejects multi-layer encoded separators and encoded dot segments', () => {
  assert.equal(normalizeSecurityPath('/a/%25252fadmin'), null);
  assert.equal(normalizeSecurityPath('/a/%25252e%25252e/admin'), null);
  assert.equal(normalizeSecurityPath('/a/%2e%2e/admin'), null);
  assert.equal(normalizeSecurityPath('/a/../admin'), '/admin');
});

test('session cookies enforce the RFC-sized name/value budget and reject line breaks', () => {
  const response = { headers: {}, setHeader(name, value) { this.headers[name] = value; } };
  assert.throws(() => setSessionCookie(response, 'x'.repeat(4096), 3600, true), /4096 bytes/);
  setSessionCookie(response, 'bad\r\nvalue', 3600, true);
  assert.doesNotMatch(response.headers['Set-Cookie'], /[\r\n]/);
  setSessionCookie(response, 'normal-token', 3600, true);
  assert.match(response.headers['Set-Cookie'], /^__Host-arix_session=/);
});

test('WAF rejects CRLF header injection and standalone Transfer-Encoding on HTTP/2', () => {
  const crlf = inspectRequest({ method: 'GET', url: '/', headers: {}, rawHeaders: ['x-safe', 'ok\r\nInjected: yes'], httpVersion: '1.1' });
  assert.ok(crlf.findings.some((finding) => finding.id === 'HTTP_HEADER_INJECTION'));
  const h2 = inspectRequest({ method: 'POST', url: '/', headers: { 'transfer-encoding': 'chunked' }, httpVersion: '2.0' });
  assert.ok(h2.findings.some((finding) => finding.id === 'HTTP2_CONNECTION_SPECIFIC_HEADER'));
});

test('password policy checks exact common roots after predictable numeric and punctuation suffixes', async () => {
  let called = false;
  const result = await validatePasswordPolicy('P@ssw0rd2026!', {}, async () => { called = true; return false; });
  assert.equal(result.valid, false);
  assert.equal(result.code, 'PASSWORD_COMMON');
  assert.equal(called, false);
});

test('password policy rejects common and context-derived passwords without calling breach lookup', async () => {
  let lookups = 0;
  const lookup = async () => { lookups++; return false; };
  const common = await validatePasswordPolicy('Password123456', {}, lookup);
  const context = await validatePasswordPolicy('my-ArixShield-project-secret', { email: 'ada@example.test', projectName: 'My Project' }, lookup);
  assert.equal(common.code, 'PASSWORD_COMMON');
  assert.equal(context.code, 'PASSWORD_CONTEXT');
  assert.equal(lookups, 0);
});

test('password policy calls the breach checker for otherwise acceptable passwords', async () => {
  let checked = '';
  const result = await validatePasswordPolicy('a-long-random-passphrase-2026', {}, async (value) => { checked = value; return true; });
  assert.equal(checked, 'a-long-random-passphrase-2026');
  assert.equal(result.code, 'PASSWORD_BREACHED');
});

test('Pwned Passwords range lookup discloses only a SHA-1 prefix and matches suffix counts', async () => {
  const originalFetch = globalThis.fetch;
  const password = 'A-unique-Password-phrase-For-Testing-2026';
  const hash = createHash('sha1').update(password).digest('hex').toUpperCase();
  let requestedUrl = '';
  let options;
  globalThis.fetch = async (url, init) => {
    requestedUrl = String(url); options = init;
    return { ok: true, text: async () => `${hash.slice(5)}:7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n` };
  };
  try {
    assert.equal(await isBreachedPassword(password), true);
    assert.equal(requestedUrl, `https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`);
    assert.equal(options.headers['Add-Padding'], 'true');
    assert.equal(requestedUrl.includes(password), false);
  } finally { globalThis.fetch = originalFetch; }
});


test('offline password policy survives optional HIBP outage without converting to 503', async () => {
  const result = await validatePasswordPolicy('a-unique-long-passphrase-for-testing-2026', {}, async () => { throw new Error('network down'); });
  assert.equal(result.valid, true);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('offline'); };
  try { await assert.rejects(() => isBreachedPassword('an-otherwise-unique-password-phrase'), /BREACH_LOOKUP_UNAVAILABLE/); }
  finally { globalThis.fetch = originalFetch; }
  const weakFallback = await validatePasswordPolicy('abababababab', {}, async () => { throw new Error('network down'); });
  assert.equal(weakFallback.code, 'PASSWORD_STRENGTH_UNVERIFIED');
});

test('safe-fetch public address policy rejects special-purpose and non-global IPv6 ranges', async () => {
  const { assertPublicIp } = await import('../sdk/safe-fetch.js');
  for (const ip of ['2001:2::1', '2001:10::1', '2001:20::1', '2001:db8::1', '3fff::1', 'fd00::1', 'fe80::1']) assert.throws(() => assertPublicIp(ip));
  assert.equal(assertPublicIp('2001:4860:4860::8888'), '2001:4860:4860::8888');
  assert.equal(assertPublicIp('1.1.1.1'), '1.1.1.1');
});

test('identity sanitizer removes a trailing client IP without coupling identity to network handoffs', async () => {
  const { sanitizeArixIdentity } = await import('../sdk/identity.js');
  assert.equal(sanitizeArixIdentity('user-1:tenant-1:192.0.2.14', '192.0.2.14'), 'user-1:tenant-1');
  assert.equal(sanitizeArixIdentity('user-1:tenant-1:2001:db8::1', '2001:db8::1'), 'user-1:tenant-1');
  assert.equal(sanitizeArixIdentity('stable-identity', '192.0.2.14'), 'stable-identity');
});

test('Prisma wrapper fails closed without ALS scope and injects tenant+owner predicates with scope', async () => {
  const { runWithArixContext, protectPrismaClient, getArixContext } = await import('../sdk/context.js');
  const fake = { order: { findMany(args) { return args; }, create(args) { return args; }, update(args) { return args; } }, $queryRaw() { return 'unsafe'; } };
  const db = protectPrismaClient(fake);
  assert.throws(() => db.order.findMany({ where: { status: 'open' } }), { code: 'ARIX_UNSCOPED_DB_ACCESS' });
  assert.throws(() => db.$queryRaw('SELECT 1'), { code: 'ARIX_RAW_SQL_BLOCKED' });
  assert.throws(() => db.$extends({}), { code: 'ARIX_UNSUPPORTED_DB_OPERATION' });
  const result = await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
    assert.equal(getArixContext().tenantId, 'tenant-a');
    const readResult = await db.order.findMany({ where: { status: 'open' } });
    const createResult = await db.order.create({ data: { amount: 12 } });
    return { readResult, createResult };
  });
  assert.deepEqual(result.readResult.where, { status: 'open', tenantId: 'tenant-a', ownerId: 'user-a' });
  assert.deepEqual(result.createResult.data, { amount: 12, tenantId: 'tenant-a', ownerId: 'user-a' });
});

test('Prisma wrapper rejects foreign-scope writes and unsupported nested writes', async () => {
  const { runWithArixContext, protectPrismaClient } = await import('../sdk/context.js');
  const fake = { order: { update(args) { return args; }, create(args) { return args; } } };
  const db = protectPrismaClient(fake);
  await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
    assert.throws(() => db.order.update({ where: { id: 1, tenantId: 'tenant-b' }, data: { state: 'paid' } }), { code: 'ARIX_SCOPE_MISMATCH' });
    assert.throws(() => db.order.create({ data: { customer: { create: { name: 'x' } } } }), { code: 'ARIX_NESTED_WRITE_BLOCKED' });
  });
});

test('dashboard uses a masked native dialog for security re-authentication', async () => {
  const { readFile } = await import('node:fs/promises');
  const html = await readFile(new URL('../public/dashboard.html', import.meta.url), 'utf8');
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /<dialog[^>]+id="step-up-modal"/);
  assert.match(html, /id="step-up-password" type="password" autocomplete="current-password"/);
  assert.doesNotMatch(app, /window\.prompt\s*\(/);
  assert.match(app, /requestStepUp\(/);
});


test('rotated session replay revokes the replacement family only after the concurrency grace period', async () => {
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
  if (process.env.NODE_ENV === 'production') process.env.NODE_ENV = 'test';
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();
  const { createSession, getSession, rotateSession } = await import('../api/_lib/session.js');
  // Match the cookie selected by getSession(): Vercel and production runtimes
  // require the Secure __Host- cookie, while local development accepts the
  // unprefixed cookie. The build test inherits VERCEL=1, so hard-coding the
  // development name would test an absent cookie instead of session rotation.
  const sessionCookieName = process.env.VERCEL === '1' || process.env.NODE_ENV === 'production'
    ? '__Host-arix_session'
    : 'arix_session';
  const cookieFor = (token) => `${sessionCookieName}=${token}`;
  const originalNow = Date.now;
  const now = originalNow();
  try {
    Date.now = () => now;
    const original = await createSession('family-owner', 'family-project');
    const replacement = await rotateSession('family-owner', 'family-project', original.tokenHash);
    assert.ok(replacement?.token);
    assert.equal(replacement.familyId, original.familyId);
    Date.now = () => now + 1_000;
    const inFlightOldRequest = await getSession({ headers: { cookie: cookieFor(original.token) } });
    assert.equal(inFlightOldRequest, null, 'old token is never accepted during grace');
    const replacementDuringGrace = await getSession({ headers: { cookie: cookieFor(replacement.token) } });
    assert.ok(replacementDuringGrace, 'in-flight old requests do not revoke the replacement family');
    Date.now = () => now + 16_000;
    const replayed = await getSession({ headers: { cookie: cookieFor(original.token) } });
    assert.equal(replayed, null);
    const replacementAfterReplay = await getSession({ headers: { cookie: cookieFor(replacement.token) } });
    assert.equal(replacementAfterReplay, null, 'post-grace replay revokes its family');
  } finally { Date.now = originalNow; }
});


test('Redis REST configuration rejects insecure or ambiguous endpoint URLs', async () => {
  const { normalizeRedisRestUrl } = await import('../api/_lib/redis.js');
  assert.equal(normalizeRedisRestUrl('https://example.upstash.io'), 'https://example.upstash.io');
  assert.equal(normalizeRedisRestUrl('https://example.upstash.io/'), 'https://example.upstash.io');
  for (const value of [
    'http://example.upstash.io',
    'https://user:pass@example.upstash.io',
    'https://example.upstash.io/path',
    'https://example.upstash.io/?token=secret',
    'https://example.upstash.io/#fragment',
    'https://example.upstash.io:8443',
    'https://example.upstash.io\n.evil.test',
    ' https://example.upstash.io'
  ]) assert.equal(normalizeRedisRestUrl(value), null, value);
});

test('safe-fetch validates total timeout and redirect limits before network access', async () => {
  const { arixSafeFetch } = await import('../sdk/safe-fetch.js');
  await assert.rejects(arixSafeFetch('https://example.com', { timeoutMs: 0 }), /timeoutMs/);
  await assert.rejects(arixSafeFetch('https://example.com', { timeoutMs: Number.NaN }), /timeoutMs/);
  await assert.rejects(arixSafeFetch('https://example.com', { maxRedirects: 6 }), /maxRedirects/);
  await assert.rejects(arixSafeFetch('https://example.com', { allowedPorts: [] }), /allowedPorts/);
});

test('runtime integrity verifies the complete API source tree against the manifest', async () => {
  const { verifyRuntimeIntegrity } = await import('../api/_lib/integrity.js');
  const result = await verifyRuntimeIntegrity({ refresh: true });
  assert.equal(result.ok, true, JSON.stringify(result.issues));
  assert.deepEqual(result.issues, []);
});


test('partial or malformed Redis credentials never trigger process-local fallback', async () => {
  const { incrementWithExpiry, getRedisConfigurationStatus } = await import('../api/_lib/redis.js');
  const urlKey = ['UPSTASH', 'REDIS_REST', 'URL'].join('_');
  const tokenKey = ['UPSTASH', 'REDIS_REST', 'TOKEN'].join('_');
  const originalUrl = process.env[urlKey];
  const originalToken = process.env[tokenKey];
  const originalMode = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'test';
    delete process.env[urlKey];
    process.env[tokenKey] = 'present-but-no-url';
    assert.equal(getRedisConfigurationStatus().mode, 'invalid-configuration');
    await assert.rejects(() => incrementWithExpiry('hardening:test:partial', 60), /Invalid Upstash Redis configuration/);
    process.env[urlKey] = 'http://insecure.example.test';
    process.env[tokenKey] = 'token';
    assert.equal(getRedisConfigurationStatus().mode, 'invalid-configuration');
    await assert.rejects(() => incrementWithExpiry('hardening:test:invalid', 60), /Invalid Upstash Redis configuration/);
    delete process.env[urlKey];
    delete process.env[tokenKey];
    assert.equal(getRedisConfigurationStatus().mode, 'ephemeral-local');
  } finally {
    if (originalUrl === undefined) delete process.env[urlKey]; else process.env[urlKey] = originalUrl;
    if (originalToken === undefined) delete process.env[tokenKey]; else process.env[tokenKey] = originalToken;
    if (originalMode === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = originalMode;
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { buildBrowserVisitQuotaDimensions, isSuspiciousAutomation } from '../api/shield.js';
import { trustedClientIp, trustedClientNetworkPrefix } from '../api/_lib/http.js';
import { rateLimitMulti, getString, getJson, setString, compareAndSetString, compareAndDeleteString } from '../api/_lib/redis.js';

function responseRecorder() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
    getHeader(name) { return this.headers[String(name).toLowerCase()]; },
    end(value = '') { this.body = String(value); this.headersSent = true; }
  };
}

function requestFor(body, remoteAddress = '203.0.113.42') {
  return {
    method: 'POST',
    url: '/api/auth',
    headers: {
      host: 'localhost', origin: 'http://localhost',
      'x-forwarded-proto': 'http', 'content-type': 'application/json',
      'user-agent': 'arixshield-followup-test'
    },
    socket: { encrypted: false, remoteAddress },
    body
  };
}

test('browser telemetry quotas survive DPoP key rotation through shared network and project buckets', async () => {
  const previousNetwork = process.env.ARIX_BROWSER_NETWORK_RATE_LIMIT_PER_MINUTE;
  const previousProject = process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE;
  const previousVercel = process.env.VERCEL;
  delete process.env.VERCEL;
  process.env.ARIX_BROWSER_NETWORK_RATE_LIMIT_PER_MINUTE = '2';
  process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE = '100';
  try {
    const project = { id: `quota-rotation-${Date.now()}`, policy: { rateLimitPerMinute: 120 } };
    const req = (ip) => ({ headers: { 'user-agent': 'synthetic' }, socket: { remoteAddress: ip } });
    const first = await buildBrowserVisitQuotaDimensions(project, 'attacker-key-one', req('203.0.113.9'));
    const second = await buildBrowserVisitQuotaDimensions(project, 'attacker-key-two', req('203.0.113.88'));
    assert.notEqual(first[0].key, second[0].key, 'actor buckets remain independently keyed');
    assert.equal(first[1].key, second[1].key, 'same /24 shares a network quota across DPoP identities');
    assert.equal(first.at(-1).key, second.at(-1).key, 'all visitors share a project aggregate quota');
    assert.equal((await rateLimitMulti({ dimensions: first })).allowed, true);
    assert.equal((await rateLimitMulti({ dimensions: second })).allowed, true);
    const third = await buildBrowserVisitQuotaDimensions(project, 'attacker-key-three', req('203.0.113.201'));
    assert.equal((await rateLimitMulti({ dimensions: third })).allowed, false, 'third rotating key is stopped by the shared /24 budget');
    const otherNetwork = await buildBrowserVisitQuotaDimensions(project, 'attacker-key-four', req('198.51.100.3'));
    assert.notEqual(first[1].key, otherNetwork[1].key, 'distinct networks have separate network budgets');
    assert.equal(first.at(-1).key, otherNetwork.at(-1).key, 'project budget still spans different networks');
  } finally {
    if (previousNetwork === undefined) delete process.env.ARIX_BROWSER_NETWORK_RATE_LIMIT_PER_MINUTE;
    else process.env.ARIX_BROWSER_NETWORK_RATE_LIMIT_PER_MINUTE = previousNetwork;
    if (previousProject === undefined) delete process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE;
    else process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE = previousProject;
    if (previousVercel === undefined) delete process.env.VERCEL;
    else process.env.VERCEL = previousVercel;
  }
});

test('network quota identity trusts ingress IP only on Vercel and ignores direct spoofed forwarding headers', () => {
  const previousVercel = process.env.VERCEL;
  try {
    delete process.env.VERCEL;
    const direct = { headers: { 'x-real-ip': '198.51.100.88' }, socket: { remoteAddress: '203.0.113.14' } };
    assert.equal(trustedClientIp(direct), '203.0.113.14');
    assert.equal(trustedClientNetworkPrefix(direct), '203.0.113.0/24');
    process.env.VERCEL = '1';
    const hosted = { headers: { 'x-real-ip': '198.51.100.88' }, socket: { remoteAddress: '203.0.113.14' } };
    assert.equal(trustedClientIp(hosted), '198.51.100.88');
    assert.equal(trustedClientNetworkPrefix(hosted), '198.51.100.0/24');
    const ambiguousHosted = { headers: { 'x-real-ip': '198.51.100.88, 203.0.113.5', 'x-vercel-forwarded-for': '198.51.100.88' }, socket: { remoteAddress: '10.0.0.1' } };
    assert.equal(trustedClientIp(ambiguousHosted), null, 'ambiguous Vercel client address must not fall back to a shared platform socket');
    const ipv6 = { headers: {}, socket: { remoteAddress: '2001:db8:abcd:12::1234' } };
    assert.equal(trustedClientNetworkPrefix(ipv6), null, 'Vercel socket peer is not a client identity when ingress address is absent');
    delete process.env.VERCEL;
    assert.equal(trustedClientNetworkPrefix(ipv6), '2001:db8:abcd:12:0:0:0:0/64');
  } finally {
    if (previousVercel === undefined) delete process.env.VERCEL;
    else process.env.VERCEL = previousVercel;
  }
});

test('fabricated keyboard/focus samples never downgrade independent automation signals', () => {
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: true, signalCount: 1, keyboardHumanSignal: true }), true);
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: false, signalCount: 2, keyboardHumanSignal: true }), true);
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: false, signalCount: 1, keyboardHumanSignal: true }), false);
  // Zero reported signals remains unknown, not a cryptographic proof of humanity.
});

test('email-index compare-and-set/delete operations cannot overwrite or erase a newer owner', async () => {
  const key = `arix:test:email-index:${Date.now()}`;
  assert.equal(await setString(key, 'pending:registration-a', 600, true), 'OK');
  assert.equal(await compareAndSetString(key, 'pending:registration-b', 'owner-b'), false);
  assert.equal(await getString(key), 'pending:registration-a');
  assert.equal(await compareAndSetString(key, 'pending:registration-a', 'owner-a'), true);
  assert.equal(await getString(key), 'owner-a');
  assert.equal(await compareAndDeleteString(key, 'pending:registration-a'), false, 'stale cleanup cannot remove the published owner');
  assert.equal(await getString(key), 'owner-a');
  assert.equal(await compareAndDeleteString(key, 'owner-a'), true);
  assert.equal(await getString(key), null);
});

test('browser project quota rejects invalid oversized configuration rather than exceeding rateLimitMulti bounds', async () => {
  const previousProject = process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE;
  process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE = '500000';
  try {
    const project = { id: `quota-bound-${Date.now()}`, policy: { rateLimitPerMinute: 120 } };
    const dimensions = await buildBrowserVisitQuotaDimensions(project, 'key', requestFor({}));
    assert.equal(dimensions.at(-1).limit, 60000, 'invalid setting falls back to a supported safe default');
    assert.ok(dimensions.every((item) => item.limit <= 100000));
  } finally {
    if (previousProject === undefined) delete process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE;
    else process.env.ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE = previousProject;
  }
});

test('production-style signup requires mail verification and does not create an account before OTP confirmation', async () => {
  const previous = {
    nodeEnv: process.env.NODE_ENV,
    require: process.env.ARIX_REQUIRE_EMAIL_VERIFICATION,
    master: process.env.ARIX_MASTER_SECRET,
    resend: process.env.ARIX_RESEND_API_KEY,
    from: process.env.ARIX_EMAIL_FROM,
    hibp: process.env.ARIX_HIBP_LOOKUP,
    vercel: process.env.VERCEL,
    fetch: globalThis.fetch
  };
  process.env.NODE_ENV = 'test';
  process.env.ARIX_REQUIRE_EMAIL_VERIFICATION = 'true';
  process.env.ARIX_MASTER_SECRET = 'A'.repeat(48);
  process.env.ARIX_RESEND_API_KEY = 're_test_api_key_0123456789';
  process.env.ARIX_EMAIL_FROM = 'ArixShield <no-reply@example.test>';
  process.env.ARIX_HIBP_LOOKUP = 'false';
  delete process.env.VERCEL;
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();
  let delivered = null;
  globalThis.fetch = async (url, options) => {
    assert.equal(String(url), 'https://api.resend.com/emails');
    assert.equal(options.redirect, 'error');
    delivered = JSON.parse(options.body);
    return new Response('{"id":"email-test"}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const handler = (await import('../api/auth.js')).default;
    const email = `verified-${Date.now()}@example.test`;
    const password = 'Cobalt-Violet-Pineapple-47!Zebra-Long';
    const signupRes = responseRecorder();
    await handler(requestFor({ action: 'signup', email, password, name: 'Verified Owner', projectName: 'Verified Project', origin: 'https://app.example.test' }), signupRes);
    assert.equal(signupRes.statusCode, 202, signupRes.body);
    const signup = JSON.parse(signupRes.body);
    assert.equal(signup.verificationRequired, true);
    assert.equal(Object.hasOwn(signup, 'keys'), false, 'project credentials are not created or disclosed before email proof');
    assert.ok(delivered && delivered.to[0] === email);
    const code = delivered.text.match(/\b(\d{6})\b/)?.[1];
    assert.match(code || '', /^\d{6}$/);
    assert.equal(signupRes.body.includes(code), false, 'OTP is delivered only through email');

    const emailHash = await (await import('../api/_lib/crypto-trap.js')).sha256Hex(email);
    const reservation = await getString(`arix:user-email:${emailHash}`);
    assert.match(reservation || '', /^pending:/);
    const registrationId = reservation.slice('pending:'.length);
    const pending = await getJson(`arix:signup:pending:${registrationId}`);
    assert.ok(pending?.passwordRecord, 'only a password verifier is stored in the pending record');
    assert.equal(await getJson(`arix:user:${pending.ownerId}`), null, 'no active user record exists before verification');

    const badRes = responseRecorder();
    await handler(requestFor({ action: 'verify-email', email, code: code === '000000' ? '999999' : '000000' }), badRes);
    assert.equal(badRes.statusCode, 400);

    const verifyRes = responseRecorder();
    await handler(requestFor({ action: 'verify-email', email, code }), verifyRes);
    assert.equal(verifyRes.statusCode, 201, verifyRes.body);
    const verified = JSON.parse(verifyRes.body);
    assert.equal(verified.user.email, email);
    assert.ok(verified.keys.liveKey.startsWith('ARIX_LIVE_'));
    assert.ok(verified.keys.serverKey.startsWith('ARIX_SECRET_'));
    const ownerId = await getString(`arix:user-email:${emailHash}`);
    const user = await getJson(`arix:user:${ownerId}`);
    assert.equal(user.emailVerified, true);
    assert.ok(user.emailVerifiedAt);
    assert.match(String(verifyRes.getHeader('set-cookie')), /arix_session=/);

    const replayRes = responseRecorder();
    await handler(requestFor({ action: 'verify-email', email, code }), replayRes);
    assert.equal(replayRes.statusCode, 400, 'verification is single-use');
  } finally {
    globalThis.fetch = previous.fetch;
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.require === undefined) delete process.env.ARIX_REQUIRE_EMAIL_VERIFICATION; else process.env.ARIX_REQUIRE_EMAIL_VERIFICATION = previous.require;
    if (previous.master === undefined) delete process.env.ARIX_MASTER_SECRET; else process.env.ARIX_MASTER_SECRET = previous.master;
    if (previous.resend === undefined) delete process.env.ARIX_RESEND_API_KEY; else process.env.ARIX_RESEND_API_KEY = previous.resend;
    if (previous.from === undefined) delete process.env.ARIX_EMAIL_FROM; else process.env.ARIX_EMAIL_FROM = previous.from;
    if (previous.hibp === undefined) delete process.env.ARIX_HIBP_LOOKUP; else process.env.ARIX_HIBP_LOOKUP = previous.hibp;
    if (previous.vercel === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous.vercel;
  }
});

test('email delivery failure cleans up pending email reservation', async () => {
  const previous = {
    require: process.env.ARIX_REQUIRE_EMAIL_VERIFICATION,
    master: process.env.ARIX_MASTER_SECRET,
    resend: process.env.ARIX_RESEND_API_KEY,
    from: process.env.ARIX_EMAIL_FROM,
    hibp: process.env.ARIX_HIBP_LOOKUP,
    fetch: globalThis.fetch
  };
  process.env.NODE_ENV = 'test';
  process.env.ARIX_REQUIRE_EMAIL_VERIFICATION = 'true';
  process.env.ARIX_MASTER_SECRET = 'B'.repeat(48);
  process.env.ARIX_RESEND_API_KEY = 're_test_api_key_0123456789';
  process.env.ARIX_EMAIL_FROM = 'ArixShield <no-reply@example.test>';
  process.env.ARIX_HIBP_LOOKUP = 'false';
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();
  globalThis.fetch = async () => new Response('provider unavailable', { status: 503 });
  try {
    const handler = (await import('../api/auth.js')).default;
    const email = `mailfail-${Date.now()}@example.test`;
    const res = responseRecorder();
    await handler(requestFor({ action: 'signup', email, password: 'Magenta-Cloudberry-726!Tiger-Long', name: 'Mail Fail', projectName: 'Mail Fail Project', origin: 'https://app.example.test' }), res);
    assert.equal(res.statusCode, 503);
    const emailHash = await (await import('../api/_lib/crypto-trap.js')).sha256Hex(email);
    assert.equal(await getString(`arix:user-email:${emailHash}`), null);
  } finally {
    globalThis.fetch = previous.fetch;
    if (previous.require === undefined) delete process.env.ARIX_REQUIRE_EMAIL_VERIFICATION; else process.env.ARIX_REQUIRE_EMAIL_VERIFICATION = previous.require;
    if (previous.master === undefined) delete process.env.ARIX_MASTER_SECRET; else process.env.ARIX_MASTER_SECRET = previous.master;
    if (previous.resend === undefined) delete process.env.ARIX_RESEND_API_KEY; else process.env.ARIX_RESEND_API_KEY = previous.resend;
    if (previous.from === undefined) delete process.env.ARIX_EMAIL_FROM; else process.env.ARIX_EMAIL_FROM = previous.from;
    if (previous.hibp === undefined) delete process.env.ARIX_HIBP_LOOKUP; else process.env.ARIX_HIBP_LOOKUP = previous.hibp;
  }
});


test('signup has a shared service-wide hourly cap across distinct email addresses', async () => {
  const previous = {
    nodeEnv: process.env.NODE_ENV,
    require: process.env.ARIX_REQUIRE_EMAIL_VERIFICATION,
    master: process.env.ARIX_MASTER_SECRET,
    resend: process.env.ARIX_RESEND_API_KEY,
    from: process.env.ARIX_EMAIL_FROM,
    globalLimit: process.env.ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR,
    hibp: process.env.ARIX_HIBP_LOOKUP,
    vercel: process.env.VERCEL,
    fetch: globalThis.fetch
  };
  process.env.NODE_ENV = 'test';
  process.env.ARIX_REQUIRE_EMAIL_VERIFICATION = 'true';
  process.env.ARIX_MASTER_SECRET = 'C'.repeat(48);
  process.env.ARIX_RESEND_API_KEY = 're_test_api_key_0123456789';
  process.env.ARIX_EMAIL_FROM = 'ArixShield <no-reply@example.test>';
  process.env.ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR = '1';
  process.env.ARIX_HIBP_LOOKUP = 'false';
  delete process.env.VERCEL;
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();
  globalThis.fetch = async () => new Response('{"id":"email-test"}', { status: 200, headers: { 'content-type': 'application/json' } });
  try {
    const handler = (await import('../api/auth.js')).default;
    const first = responseRecorder();
    await handler(requestFor({ action: 'signup', email: `global-a-${Date.now()}@example.test`, password: 'Cobalt-Violet-Pineapple-47!Zebra-Long', name: 'Global First', projectName: 'Global One', origin: 'https://app.example.test' }), first);
    assert.equal(first.statusCode, 202, first.body);
    const second = responseRecorder();
    await handler(requestFor({ action: 'signup', email: `global-b-${Date.now()}@example.test`, password: 'Cobalt-Violet-Pineapple-48!Zebra-Long', name: 'Global Second', projectName: 'Global Two', origin: 'https://app.example.test' }), second);
    assert.equal(second.statusCode, 429, second.body);
  } finally {
    globalThis.fetch = previous.fetch;
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.require === undefined) delete process.env.ARIX_REQUIRE_EMAIL_VERIFICATION; else process.env.ARIX_REQUIRE_EMAIL_VERIFICATION = previous.require;
    if (previous.master === undefined) delete process.env.ARIX_MASTER_SECRET; else process.env.ARIX_MASTER_SECRET = previous.master;
    if (previous.resend === undefined) delete process.env.ARIX_RESEND_API_KEY; else process.env.ARIX_RESEND_API_KEY = previous.resend;
    if (previous.from === undefined) delete process.env.ARIX_EMAIL_FROM; else process.env.ARIX_EMAIL_FROM = previous.from;
    if (previous.globalLimit === undefined) delete process.env.ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR; else process.env.ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR = previous.globalLimit;
    if (previous.hibp === undefined) delete process.env.ARIX_HIBP_LOOKUP; else process.env.ARIX_HIBP_LOOKUP = previous.hibp;
    if (previous.vercel === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous.vercel;
  }
});

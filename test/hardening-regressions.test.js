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

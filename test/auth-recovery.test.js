import test from 'node:test';
import assert from 'node:assert/strict';
import { generateMfaRecoveryCodes } from '../api/_lib/recovery-codes.js';
import { derivePassword, sha256Hex } from '../api/_lib/crypto-trap.js';
import { setJson, setString, getJson } from '../api/_lib/redis.js';

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

function requestFor(body) {
  return {
    method: 'POST',
    url: '/api/auth',
    headers: {
      host: 'localhost',
      origin: 'http://localhost',
      // Vercel deployments set VERCEL=1; model the trusted proxy protocol
      // so this localhost-origin test exercises the same-origin path.
      'x-forwarded-proto': 'http',
      'content-type': 'application/json',
      'user-agent': 'arixshield-test'
    },
    socket: { encrypted: false, remoteAddress: '127.0.0.1' },
    body
  };
}

test('recover-mfa consumes one recovery code, resets factors, revokes credentials and issues a new session', async () => {
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
  if (process.env.NODE_ENV === 'production') process.env.NODE_ENV = 'test';
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();

  const ownerId = 'usr_recovery_test';
  const projectId = 'prj_recovery_test';
  const email = 'recovery@example.test';
  const password = 'a-long-random-password-for-recovery-test';
  const emailHash = await sha256Hex(email);
  const passwordRecord = await derivePassword(password);
  const passkeyId = Buffer.from('test-passkey-id').toString('base64url');
  const passkeyHash = await sha256Hex(passkeyId);
  const recovery = generateMfaRecoveryCodes();

  await Promise.all([
    setString(`arix:user-email:${emailHash}`, ownerId),
    setJson(`arix:user:${ownerId}`, {
      id: ownerId, name: 'Test User', email, password: passwordRecord,
      totpEnabled: true, totpSecret: { encrypted: 'test-only' },
      passkeys: [{ credentialId: passkeyId }],
      recoveryCodes: recovery.hashes
    }),
    setJson(`arix:project:${projectId}`, { id: projectId, ownerId, name: 'Recovery Test' }),
    setString(`arix:owner-project:${ownerId}`, projectId),
    setJson(`arix:webauthn:credential:${passkeyHash}`, { ownerId, projectId, credentialId: passkeyId })
  ]);

  const handler = (await import('../api/auth.js')).default;
  const response = responseRecorder();
  await handler(requestFor({ action: 'recover-mfa', email, password, recoveryCode: recovery.codes[0] }), response);
  assert.equal(response.statusCode, 200, response.body);
  const payload = JSON.parse(response.body);
  assert.equal(payload.recovered, true);
  assert.equal(payload.mfaReset, true);
  assert.equal(payload.requireMfaReenrollment, true);
  assert.match(String(response.getHeader('set-cookie')), /arix_session=/);

  const updated = await getJson(`arix:user:${ownerId}`);
  assert.equal(updated.totpEnabled, false);
  assert.equal(updated.totpSecret, undefined);
  assert.deepEqual(updated.passkeys, []);
  assert.equal(updated.recoveryCodes, undefined);
  assert.equal(await getJson(`arix:webauthn:credential:${passkeyHash}`), null);

  const replayResponse = responseRecorder();
  await handler(requestFor({ action: 'recover-mfa', email, password, recoveryCode: recovery.codes[0] }), replayResponse);
  assert.equal(replayResponse.statusCode, 401);
});

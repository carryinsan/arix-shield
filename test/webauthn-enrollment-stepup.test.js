import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signSignature } from 'node:crypto';
import { advanceWebAuthnCounter, deleteKeys, getJson, setJson } from '../api/_lib/redis.js';
import { createSession } from '../api/_lib/session.js';
import { derivePassword, sha256Hex } from '../api/_lib/crypto-trap.js';
import { generateTotpSecret } from '../api/_lib/mfa.js';
import { isWebAuthnCounterRegression, verifyWebAuthnAssertion } from '../api/_lib/webauthn.js';

function responseRecorder() {
  return { statusCode: 200, headers: {}, body: '', setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; }, getHeader(name) { return this.headers[String(name).toLowerCase()]; }, end(value = '') { this.body = String(value); this.headersSent = true; } };
}

function authRequest(token, body) {
  return {
    method: 'POST', url: '/api/auth',
    headers: { host: 'localhost', origin: 'http://localhost', 'x-forwarded-proto': 'http', 'content-type': 'application/json', cookie: `arix_session=${token}`, 'user-agent': 'webauthn-enrollment-regression' },
    socket: { encrypted: false, remoteAddress: '127.0.0.1' }, body
  };
}

test('WebAuthn counter policy detects positive-to-zero rollback and tolerates authenticators that always report zero', () => {
  assert.equal(isWebAuthnCounterRegression(5, 0), true, 'positive counter cannot reset to zero');
  assert.equal(isWebAuthnCounterRegression(5, 5), true, 'counter must advance strictly');
  assert.equal(isWebAuthnCounterRegression(5, 4), true, 'counter cannot decrease');
  assert.equal(isWebAuthnCounterRegression(0, 0), false, 'zero-counter authenticators remain supported');
  assert.equal(isWebAuthnCounterRegression(0, 1), false, 'counter may begin advancing later');
  assert.equal(isWebAuthnCounterRegression(0xffffffff, 0x100000000), true, 'out-of-range counter is invalid');
});


test('WebAuthn assertion verifier rejects a signed positive-to-zero counter rollback after signature verification', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const challengeRecord = { challenge: 'counter-anomaly-challenge-1234567890', origin: 'https://example.test', rpId: 'example.test' };
  const credentialId = Buffer.from('counter-anomaly-credential').toString('base64url');
  const clientDataBytes = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challengeRecord.challenge, origin: challengeRecord.origin }));
  const authenticatorData = Buffer.alloc(37);
  createHash('sha256').update(challengeRecord.rpId).digest().copy(authenticatorData, 0);
  authenticatorData[32] = 0x05; // user presence + user verification
  authenticatorData.writeUInt32BE(0, 33);
  const clientHash = createHash('sha256').update(clientDataBytes).digest();
  const signedBytes = Buffer.concat([authenticatorData, clientHash]);
  const signature = signSignature('sha256', signedBytes, privateKey);
  const credential = { id: credentialId, rawId: credentialId, response: { clientDataJSON: clientDataBytes.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'), signature: signature.toString('base64url') } };
  const stored = { credentialId, publicKeyJwk: publicKey.export({ format: 'jwk' }), signCount: 5 };
  assert.throws(() => verifyWebAuthnAssertion(credential, challengeRecord, stored), /counter regressed/);
  assert.equal(verifyWebAuthnAssertion(credential, challengeRecord, stored, { deferCounterCheck: true }).signCount, 0, 'cryptographic verification can defer only the atomic state comparison');

  const tampered = structuredClone(credential);
  tampered.response.signature = Buffer.from('not-a-valid-signature').toString('base64url');
  assert.throws(() => verifyWebAuthnAssertion(tampered, challengeRecord, stored), /signature is invalid/, 'an invalid signature is rejected before counter-anomaly reporting');
});

test('WebAuthn counter updates are atomic, monotonic, and reject positive-to-zero rollback', async () => {
  const previous = { nodeEnv: process.env.NODE_ENV, url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN };
  process.env.NODE_ENV = 'test'; delete process.env.UPSTASH_REDIS_REST_URL; delete process.env.UPSTASH_REDIS_REST_TOKEN;
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();
  try {
    const credentialHash = await sha256Hex(`counter-test-${Date.now()}`);
    assert.equal(await advanceWebAuthnCounter(credentialHash, 5, 0), false);
    assert.equal(await advanceWebAuthnCounter(credentialHash, 5, 6), true);
    assert.equal(await advanceWebAuthnCounter(credentialHash, 5, 6), false, 'replayed counter is rejected');
    assert.equal(await advanceWebAuthnCounter(credentialHash, 5, 7), true, 'larger counter is accepted');
    assert.equal(await advanceWebAuthnCounter(credentialHash, 5, 0), false, 'positive-to-zero transition is rejected');

    const concurrentHash = await sha256Hex(`counter-race-${Date.now()}`);
    const outcomes = await Promise.all(Array.from({ length: 20 }, () => advanceWebAuthnCounter(concurrentHash, 5, 6)));
    assert.equal(outcomes.filter(Boolean).length, 1, 'only one concurrent assertion with the same counter can win');

    const zeroHash = await sha256Hex(`counter-zero-${Date.now()}`);
    assert.equal(await advanceWebAuthnCounter(zeroHash, 0, 0), true);
    assert.equal(await advanceWebAuthnCounter(zeroHash, 0, 0), true, 'non-counter authenticators remain usable');
    assert.equal(await advanceWebAuthnCounter(zeroHash, 0, 2), true, 'an authenticator may start reporting a positive counter');
    assert.equal(await advanceWebAuthnCounter(zeroHash, 2, 0), false);
    await deleteKeys(`arix:webauthn:counter:${credentialHash}`, `arix:webauthn:counter:${concurrentHash}`, `arix:webauthn:counter:${zeroHash}`);
  } finally {
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.url === undefined) delete process.env.UPSTASH_REDIS_REST_URL; else process.env.UPSTASH_REDIS_REST_URL = previous.url;
    if (previous.token === undefined) delete process.env.UPSTASH_REDIS_REST_TOKEN; else process.env.UPSTASH_REDIS_REST_TOKEN = previous.token;
  }
});

test('passkey registration and TOTP enrollment/confirmation require fresh server-side step-up', async () => {
  const previous = { nodeEnv: process.env.NODE_ENV, vercel: process.env.VERCEL, master: process.env.ARIX_MASTER_SECRET, url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN };
  process.env.NODE_ENV = 'test'; delete process.env.VERCEL; delete process.env.UPSTASH_REDIS_REST_URL; delete process.env.UPSTASH_REDIS_REST_TOKEN;
  process.env.ARIX_MASTER_SECRET = 'W'.repeat(48);
  globalThis.__ARIXSHIELD_LOCAL_REDIS__?.clear?.();
  try {
    const handler = (await import('../api/auth.js')).default;
    const password = 'Passkey-Enrollment-StepUp-Strong-2026!';
    const passwordRecord = await derivePassword(password);

    const totpOwner = `passkey-stepup-totp-${Date.now()}`;
    const totpProject = `passkey-stepup-project-${Date.now()}`;
    const totp = generateTotpSecret();
    await setJson(`arix:user:${totpOwner}`, { id: totpOwner, name: 'TOTP Owner', email: `${totpOwner}@example.test`, password: passwordRecord, totpEnabled: true, totpSecret: totp.encrypted, passkeys: [] });
    await setJson(`arix:project:${totpProject}`, { id: totpProject, ownerId: totpOwner, name: 'Step-up project' });
    const totpSession = await createSession(totpOwner, totpProject, { headers: { 'user-agent': 'step-up-test' }, socket: { remoteAddress: '127.0.0.1' } });

    const options = responseRecorder();
    await handler(authRequest(totpSession.token, { action: 'passkey-register-options' }), options);
    assert.equal(options.statusCode, 200, options.body);
    const registrationChallenge = JSON.parse(options.body).challenge;

    const registrationDenied = responseRecorder();
    await handler(authRequest(totpSession.token, { action: 'passkey-register', challenge: registrationChallenge, credential: {} }), registrationDenied);
    assert.equal(registrationDenied.statusCode, 401, registrationDenied.body);
    const passwordOnlyRegistration = responseRecorder();
    await handler(authRequest(totpSession.token, { action: 'passkey-register', challenge: registrationChallenge, credential: {}, password }), passwordOnlyRegistration);
    assert.equal(passwordOnlyRegistration.statusCode, 401, passwordOnlyRegistration.body, 'TOTP-enabled account also requires the existing TOTP factor');
    assert.equal((await getJson(`arix:user:${totpOwner}`)).passkeys.length, 0, 'session-only/password-only requests cannot add a passkey to a TOTP-protected account');

    const passwordOnlyOwner = `totp-stepup-owner-${Date.now()}`;
    const passwordOnlyProject = `totp-stepup-project-${Date.now()}`;
    await setJson(`arix:user:${passwordOnlyOwner}`, { id: passwordOnlyOwner, name: 'Password Owner', email: `${passwordOnlyOwner}@example.test`, password: passwordRecord, totpEnabled: false, passkeys: [] });
    await setJson(`arix:project:${passwordOnlyProject}`, { id: passwordOnlyProject, ownerId: passwordOnlyOwner, name: 'TOTP project' });
    const passwordOnlySession = await createSession(passwordOnlyOwner, passwordOnlyProject, { headers: { 'user-agent': 'step-up-test' }, socket: { remoteAddress: '127.0.0.1' } });

    const enrollDenied = responseRecorder();
    await handler(authRequest(passwordOnlySession.token, { action: 'totp-enroll' }), enrollDenied);
    assert.equal(enrollDenied.statusCode, 401, enrollDenied.body);

    const enrollAllowed = responseRecorder();
    await handler(authRequest(passwordOnlySession.token, { action: 'totp-enroll', password }), enrollAllowed);
    assert.equal(enrollAllowed.statusCode, 200, enrollAllowed.body, 'password-only account can enroll after fresh password verification');

    const confirmDenied = responseRecorder();
    await handler(authRequest(passwordOnlySession.token, { action: 'totp-confirm', totpCode: '000000' }), confirmDenied);
    assert.equal(confirmDenied.statusCode, 401, confirmDenied.body, 'session plus a pending secret is insufficient to enable TOTP');
    assert.equal((await getJson(`arix:user:${passwordOnlyOwner}`)).totpEnabled, false);

    const passkeyOnlyOwner = `passkey-only-stepup-${Date.now()}`;
    const passkeyOnlyProject = `passkey-only-project-${Date.now()}`;
    await setJson(`arix:user:${passkeyOnlyOwner}`, { id: passkeyOnlyOwner, name: 'Passkey Owner', email: `${passkeyOnlyOwner}@example.test`, password: passwordRecord, totpEnabled: false, passkeys: [{ credentialId: Buffer.from('passkey-test-id').toString('base64url'), publicKeyJwk: {}, signCount: 0 }] });
    await setJson(`arix:project:${passkeyOnlyProject}`, { id: passkeyOnlyProject, ownerId: passkeyOnlyOwner, name: 'Passkey project' });
    const pendingSecret = generateTotpSecret();
    const passkeyOnlyUser = await getJson(`arix:user:${passkeyOnlyOwner}`);
    passkeyOnlyUser.totpSecret = pendingSecret.encrypted; passkeyOnlyUser.totpEnrolledAt = Date.now();
    await setJson(`arix:user:${passkeyOnlyOwner}`, passkeyOnlyUser);
    const passkeySession = await createSession(passkeyOnlyOwner, passkeyOnlyProject, { headers: { 'user-agent': 'step-up-test' }, socket: { remoteAddress: '127.0.0.1' } });
    const passkeyDenied = responseRecorder();
    await handler(authRequest(passkeySession.token, { action: 'totp-enroll', password }), passkeyDenied);
    assert.equal(passkeyDenied.statusCode, 428, passkeyDenied.body);
    assert.equal(JSON.parse(passkeyDenied.body).challengeType, 'passkey');
    const passkeyConfirmDenied = responseRecorder();
    await handler(authRequest(passkeySession.token, { action: 'totp-confirm', password, totpCode: '000000' }), passkeyConfirmDenied);
    assert.equal(passkeyConfirmDenied.statusCode, 428, passkeyConfirmDenied.body, 'passkey-only account must prove an existing passkey before confirming TOTP');
    assert.equal((await getJson(`arix:user:${passkeyOnlyOwner}`)).totpEnabled, false);
  } finally {
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.vercel === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous.vercel;
    if (previous.master === undefined) delete process.env.ARIX_MASTER_SECRET; else process.env.ARIX_MASTER_SECRET = previous.master;
    if (previous.url === undefined) delete process.env.UPSTASH_REDIS_REST_URL; else process.env.UPSTASH_REDIS_REST_URL = previous.url;
    if (previous.token === undefined) delete process.env.UPSTASH_REDIS_REST_TOKEN; else process.env.UPSTASH_REDIS_REST_TOKEN = previous.token;
  }
});

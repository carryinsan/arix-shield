import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { validateClearanceRequest } from '../sdk/security-runtime.js';
import { base64urlEncode, decryptClearanceJwe, getClearancePublicJwk, verifyDpopProof, verifyRequestDpopProof, dpopThumbprint, createSignedToken } from '../api/_lib/crypto-trap.js';
function encodeJson(value) { return base64urlEncode(new TextEncoder().encode(JSON.stringify(value))); }
test('browser clearance JWE encrypts and decrypts with configured RSA-OAEP-256/A256GCM keys', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 }); const kid = 'arix-test-clearance'; process.env.ARIX_CLEARANCE_KID = kid;
  process.env.ARIX_CLEARANCE_PRIVATE_JWK = JSON.stringify({ ...privateKey.export({ format: 'jwk' }), kid }); const publicJwk = getClearancePublicJwk(); assert.equal(publicJwk.kid, kid); assert.equal(publicJwk.alg, 'RSA-OAEP-256');
  const payload = { projectId: 'proj_test', path: '/checkout', iat: Date.now(), signals: { webdriver: false } }; const protectedHeader = encodeJson({ alg: 'RSA-OAEP-256', enc: 'A256GCM', kid, typ: 'JOSE' });
  const rsaKey = await webcrypto.subtle.importKey('jwk', publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']); const cek = webcrypto.getRandomValues(new Uint8Array(32)); const aesKey = await webcrypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12)); const ciphertextAndTag = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(protectedHeader), tagLength: 128 }, aesKey, new TextEncoder().encode(JSON.stringify(payload))));
  const encryptedKey = await webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKey, cek); const token = [protectedHeader, base64urlEncode(new Uint8Array(encryptedKey)), base64urlEncode(iv), base64urlEncode(ciphertextAndTag.slice(0, -16)), base64urlEncode(ciphertextAndTag.slice(-16))].join('.'); cek.fill(0);
  const decoded = await decryptClearanceJwe(token); assert.equal(decoded.projectId, payload.projectId); assert.equal(decoded.path, payload.path); assert.deepEqual(decoded.signals, payload.signals);
});
test('clearance JWK publication and JWE decryption reject a mismatched configured key identifier', async () => {
  const originalKid = process.env.ARIX_CLEARANCE_KID;
  try {
    process.env.ARIX_CLEARANCE_KID = 'wrong-clearance-kid';
    assert.equal(getClearancePublicJwk(), null);
    const protectedHeader = encodeJson({ alg: 'RSA-OAEP-256', enc: 'A256GCM', kid: 'arix-test-clearance' });
    await assert.rejects(() => decryptClearanceJwe([protectedHeader, 'AA', 'AA', 'AA', 'AA'].join('.')), /identifier does not match/);
  } finally {
    if (originalKid === undefined) delete process.env.ARIX_CLEARANCE_KID;
    else process.env.ARIX_CLEARANCE_KID = originalKid;
  }
});
test('request DPoP binds the exact raw body bytes, URL, method, thumbprint and clearance nonce', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const thumbprint = await dpopThumbprint(publicJwk);
  const body = new TextEncoder().encode('{\"amount\":10, \"currency\":\"USD\"}');
  const bodyHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', body));
  const protectedHeader = encodeJson({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk });
  const payload = encodeJson({ htm: 'POST', htu: 'https://app.example.test/api/checkout', iat: Math.floor(Date.now() / 1000), jti: 'request-body-jti-0001', ath: base64urlEncode(bodyHash), nonce: 'clearance-nonce-1234567890' });
  const signingInput = `${protectedHeader}.${payload}`;
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(signingInput));
  const proof = `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
  const verified = await verifyRequestDpopProof({ proof, method: 'POST', url: 'https://app.example.test/api/checkout', bodyBytes: body, expectedThumbprint: thumbprint, clearanceNonce: 'clearance-nonce-1234567890', projectId: 'project-a' });
  const wrongBody = await verifyRequestDpopProof({ proof, method: 'POST', url: 'https://app.example.test/api/checkout', bodyBytes: new TextEncoder().encode('{\"amount\":100}'), expectedThumbprint: thumbprint, clearanceNonce: 'clearance-nonce-1234567890', projectId: 'project-a' });
  const wrongNonce = await verifyRequestDpopProof({ proof, method: 'POST', url: 'https://app.example.test/api/checkout', bodyBytes: body, expectedThumbprint: thumbprint, clearanceNonce: 'another-nonce-123456', projectId: 'project-a' });
  assert.equal(verified.valid, true);
  assert.equal(wrongBody.reason, 'DPOP_BODY_HASH_MISMATCH');
  assert.equal(wrongNonce.reason, 'DPOP_CLEARANCE_NONCE_MISMATCH');
});

test('DPoP validates ES256 request binding and rejects replayed JTIs', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']); const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const protectedHeader = encodeJson({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk }); const payload = encodeJson({ htm: 'POST', htu: 'https://api.example.test/v1/payments', iat: Math.floor(Date.now() / 1000), jti: 'jti-replay-test-0001' });
  const signingInput = `${protectedHeader}.${payload}`; const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(signingInput)); const proof = `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`; const seen = new Set();
  const redisGetSet = async (key, _value, ttlSeconds) => { assert.equal(ttlSeconds, 121); return seen.has(key) ? null : (seen.add(key), 'OK'); }; const first = await verifyDpopProof({ proof, method: 'POST', url: 'https://api.example.test/v1/payments', projectId: 'proj_dpop', redisGetSet });
  const replay = await verifyDpopProof({ proof, method: 'POST', url: 'https://api.example.test/v1/payments', projectId: 'proj_dpop', redisGetSet }); const wrongTarget = await verifyDpopProof({ proof, method: 'GET', url: 'https://api.example.test/v1/payments', projectId: 'proj_dpop', redisGetSet: async () => 'OK' });
  assert.equal(first.valid, true); assert.equal(replay.reason, 'DPOP_REPLAY'); assert.equal(wrongTarget.reason, 'DPOP_TARGET_MISMATCH');
});


test('clearance continuity survives Wi-Fi/mobile IP and JA4 changes when the DPoP key remains valid', async () => {
  process.env.ARIX_MASTER_SECRET = 'B'.repeat(48);
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const thumbprint = await dpopThumbprint(publicJwk);
  const projectId = 'handoff-project';
  const nonce = 'handoff-clearance-nonce-123456789';
  const url = 'https://app.example.test/api/orders/42';
  const ticket = await createSignedToken({ projectId, dpopThumbprint: thumbprint, singleUseNonce: nonce, riskScore: 0, ipPrefix: '192.0.2.0/24', ja4Hash: 'old-network-fingerprint', exp: Date.now() + 60000 }, 'browser-clearance');
  const bodyBytes = new Uint8Array();
  const bodyHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', bodyBytes));
  const header = encodeJson({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk });
  const payload = encodeJson({ htm: 'GET', htu: url, iat: Math.floor(Date.now() / 1000), jti: 'handoff-proof-jti-0000001', ath: base64urlEncode(bodyHash), nonce });
  const signingInput = `${header}.${payload}`;
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(signingInput));
  const proof = `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
  const result = await validateClearanceRequest({
    headers: new Headers({ 'x-arix-clearance': ticket, 'x-arix-pop': proof }),
    method: 'GET', url, bodyBytes, projectId,
    clientIp: '198.51.100.77', // New carrier IP; it must not invalidate the ticket.
    consumeProofReplay: async () => true
  });
  assert.equal(result.valid, true);
  assert.equal(result.thumbprint, thumbprint);
});


test('password KDF writes bounded scrypt records and verifies legacy PBKDF2 records', async () => {
  const { derivePassword, verifyPassword } = await import('../api/_lib/crypto-trap.js');
  const { LEGACY_PBKDF2_ITERATIONS, PASSWORD_KDF } = await import('../api/_lib/security-constants.js');
  const password = 'correct-horse-battery-staple-v2';
  const record = await derivePassword(password);
  assert.equal(record.algorithm, 'scrypt');
  assert.equal(record.version, 2);
  assert.equal(record.N, PASSWORD_KDF.N);
  assert.equal(record.r, PASSWORD_KDF.r);
  assert.equal(record.p, PASSWORD_KDF.p);
  assert.equal(await verifyPassword(password, record), true);
  assert.equal(await verifyPassword('not-the-password', record), false);
  assert.equal(await verifyPassword(password, { ...record, N: 2 ** 30 }), false);

  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const material = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = new Uint8Array(await webcrypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: LEGACY_PBKDF2_ITERATIONS, hash: 'SHA-256' }, material, 256));
  const legacy = { salt: Buffer.from(salt).toString('base64url'), hash: Buffer.from(hash).toString('base64url'), iterations: LEGACY_PBKDF2_ITERATIONS };
  assert.equal(await verifyPassword(password, legacy), true);
  assert.equal(await verifyPassword('not-the-password', legacy), false);
});

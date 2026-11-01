import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { base64urlEncode, decryptClearanceJwe, getClearancePublicJwk, verifyDpopProof } from '../api/_lib/crypto-trap.js';
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
test('DPoP validates ES256 request binding and rejects replayed JTIs', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']); const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const protectedHeader = encodeJson({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk }); const payload = encodeJson({ htm: 'POST', htu: 'https://api.example.test/v1/payments', iat: Math.floor(Date.now() / 1000), jti: 'jti-replay-test-0001' });
  const signingInput = `${protectedHeader}.${payload}`; const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(signingInput)); const proof = `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`; const seen = new Set();
  const redisGetSet = async (key) => seen.has(key) ? null : (seen.add(key), 'OK'); const first = await verifyDpopProof({ proof, method: 'POST', url: 'https://api.example.test/v1/payments', projectId: 'proj_dpop', redisGetSet });
  const replay = await verifyDpopProof({ proof, method: 'POST', url: 'https://api.example.test/v1/payments', projectId: 'proj_dpop', redisGetSet }); const wrongTarget = await verifyDpopProof({ proof, method: 'GET', url: 'https://api.example.test/v1/payments', projectId: 'proj_dpop', redisGetSet: async () => 'OK' });
  assert.equal(first.valid, true); assert.equal(replay.reason, 'DPOP_REPLAY'); assert.equal(wrongTarget.reason, 'DPOP_TARGET_MISMATCH');
});

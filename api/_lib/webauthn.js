import { createHash, createPublicKey, timingSafeEqual, verify as verifySignature } from 'node:crypto';

function decodeB64url(value, maxBytes = 262144) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes * 4 / 3) + 8 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Malformed WebAuthn base64url field.');
  const result = Buffer.from(value, 'base64url');
  if (result.length > maxBytes) throw new Error('WebAuthn field exceeds the configured size limit.');
  return result;
}

function decodeCbor(buffer, offset = 0, depth = 0) {
  if (!Buffer.isBuffer(buffer) || offset >= buffer.length || depth > 12) throw new Error('Invalid or deeply nested CBOR payload.');
  const first = buffer[offset++]; const major = first >> 5; const additional = first & 31;
  let length;
  if (additional < 24) length = additional;
  else if (additional === 24) { if (offset + 1 > buffer.length) throw new Error('Truncated CBOR.'); length = buffer[offset++]; }
  else if (additional === 25) { if (offset + 2 > buffer.length) throw new Error('Truncated CBOR.'); length = buffer.readUInt16BE(offset); offset += 2; }
  else if (additional === 26) { if (offset + 4 > buffer.length) throw new Error('Truncated CBOR.'); length = buffer.readUInt32BE(offset); offset += 4; }
  else if (additional === 27) { if (offset + 8 > buffer.length) throw new Error('Truncated CBOR.'); const wide = buffer.readBigUInt64BE(offset); offset += 8; if (wide > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR integer is too large.'); length = Number(wide); }
  else throw new Error('Indefinite-length or reserved CBOR values are not accepted.');
  if (major === 0) return { value: length, offset };
  if (major === 1) return { value: -1 - length, offset };
  if (major === 2 || major === 3) {
    if (length > 262144 || offset + length > buffer.length) throw new Error('CBOR byte/string length is invalid.');
    const raw = buffer.subarray(offset, offset + length); return { value: major === 2 ? Buffer.from(raw) : raw.toString('utf8'), offset: offset + length };
  }
  if (major === 4) {
    if (length > 256) throw new Error('CBOR array is too large.');
    const values = []; for (let index = 0; index < length; index++) { const item = decodeCbor(buffer, offset, depth + 1); values.push(item.value); offset = item.offset; }
    return { value: values, offset };
  }
  if (major === 5) {
    if (length > 256) throw new Error('CBOR map is too large.');
    const map = new Map(); for (let index = 0; index < length; index++) { const key = decodeCbor(buffer, offset, depth + 1); const value = decodeCbor(buffer, key.offset, depth + 1); map.set(key.value, value.value); offset = value.offset; }
    return { value: map, offset };
  }
  if (major === 7 && additional === 20) return { value: false, offset };
  if (major === 7 && additional === 21) return { value: true, offset };
  if (major === 7 && additional === 22) return { value: null, offset };
  throw new Error('Unsupported CBOR value in WebAuthn payload.');
}

function parseClientData(encoded, expectedType, challenge) {
  const bytes = decodeB64url(encoded, 16384);
  let data;
  try { data = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('WebAuthn clientDataJSON is invalid.'); }
  if (data.type !== expectedType || data.crossOrigin === true || typeof data.challenge !== 'string' || typeof data.origin !== 'string') throw new Error('WebAuthn client data fields are invalid.');
  const left = Buffer.from(data.challenge); const right = Buffer.from(String(challenge));
  if (left.length !== right.length || !timingSafeEqual(left, right)) throw new Error('WebAuthn challenge does not match.');
  return { data, bytes };
}

function verifyAuthenticatorData(authData, rpId, requireUv = true) {
  if (!Buffer.isBuffer(authData) || authData.length < 37 || authData.length > 65536) throw new Error('WebAuthn authenticator data is invalid.');
  const expectedRpHash = createHash('sha256').update(rpId).digest(); const actualRpHash = authData.subarray(0, 32);
  if (!timingSafeEqual(expectedRpHash, actualRpHash)) throw new Error('WebAuthn RP ID hash mismatch.');
  const flags = authData[32];
  if ((flags & 0x01) === 0) throw new Error('WebAuthn user presence flag is missing.');
  if (requireUv && (flags & 0x04) === 0) throw new Error('WebAuthn user verification is required.');
  return { flags, signCount: authData.readUInt32BE(33) };
}

export function verifyWebAuthnRegistration(credential, challengeRecord, { requireUserVerification = true } = {}) {
  const response = credential?.response || {};
  const { data: clientData, bytes: clientDataBytes } = parseClientData(response.clientDataJSON, 'webauthn.create', challengeRecord.challenge);
  if (clientData.origin !== challengeRecord.origin) throw new Error('WebAuthn origin mismatch.');
  const attestationBytes = decodeB64url(response.attestationObject, 131072);
  const decoded = decodeCbor(attestationBytes);
  const attestation = decoded.value;
  if (!(attestation instanceof Map) || attestation.get('fmt') !== 'none' || !(attestation.get('authData') instanceof Buffer) || !(attestation.get('attStmt') instanceof Map)) throw new Error('Only WebAuthn none attestation is supported by this verifier.');
  const authData = attestation.get('authData');
  const authState = verifyAuthenticatorData(authData, challengeRecord.rpId, requireUserVerification);
  if ((authState.flags & 0x40) === 0 || authData.length < 55) throw new Error('WebAuthn attested credential data is missing.');
  const credentialLength = authData.readUInt16BE(53);
  if (credentialLength < 16 || credentialLength > 1024 || 55 + credentialLength >= authData.length) throw new Error('WebAuthn credential identifier is invalid.');
  const credentialIdBytes = authData.subarray(55, 55 + credentialLength);
  const cose = decodeCbor(authData, 55 + credentialLength);
  if (!(cose.value instanceof Map)) throw new Error('WebAuthn public key is not a COSE map.');
  const key = cose.value;
  if (key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1 || !Buffer.isBuffer(key.get(-2)) || !Buffer.isBuffer(key.get(-3)) || key.get(-2).length !== 32 || key.get(-3).length !== 32) throw new Error('Only ES256 P-256 WebAuthn credentials are supported.');
  const credentialId = credentialIdBytes.toString('base64url');
  if (credential.id && credential.id !== credentialId) throw new Error('WebAuthn credential ID mismatch.');
  return {
    credentialId,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: key.get(-2).toString('base64url'), y: key.get(-3).toString('base64url'), ext: true, key_ops: ['verify'] },
    signCount: authState.signCount,
    transports: Array.isArray(response.transports) ? response.transports.filter((item) => ['usb', 'nfc', 'ble', 'internal', 'hybrid'].includes(item)).slice(0, 5) : [],
    registeredAt: Date.now()
  };
}


/** A positive authenticator counter must strictly increase and may not reset to zero. */
export function isWebAuthnCounterRegression(priorCount, nextCount) {
  const prior = priorCount == null ? 0 : Number(priorCount);
  const next = Number(nextCount);
  if (!Number.isInteger(prior) || !Number.isInteger(next) || prior < 0 || next < 0 || prior > 0xffffffff || next > 0xffffffff) return true;
  return prior > 0 && (next === 0 || next <= prior);
}

export function verifyWebAuthnAssertion(credential, challengeRecord, storedCredential, { requireUserVerification = true, deferCounterCheck = false } = {}) {
  const response = credential?.response || {};
  const { data: clientData, bytes: clientDataBytes } = parseClientData(response.clientDataJSON, 'webauthn.get', challengeRecord.challenge);
  if (clientData.origin !== challengeRecord.origin) throw new Error('WebAuthn origin mismatch.');
  const credentialId = decodeB64url(credential.rawId || credential.id, 1024).toString('base64url');
  if (credentialId !== storedCredential.credentialId) throw new Error('WebAuthn credential is not registered to this account.');
  const authData = decodeB64url(response.authenticatorData, 65536);
  const authState = verifyAuthenticatorData(authData, challengeRecord.rpId, requireUserVerification);
  const priorCount = storedCredential.signCount == null ? 0 : Number(storedCredential.signCount);
  const signature = decodeB64url(response.signature, 4096);
  const clientHash = createHash('sha256').update(clientDataBytes).digest();
  const signed = Buffer.concat([authData, clientHash]);
  const publicKey = createPublicKey({ key: storedCredential.publicKeyJwk, format: 'jwk' });
  if (!verifySignature('sha256', signed, publicKey, signature)) throw new Error('WebAuthn assertion signature is invalid.');
  if (!deferCounterCheck && isWebAuthnCounterRegression(priorCount, authState.signCount)) throw new Error('WebAuthn authenticator counter regressed or did not increase.');
  return { signCount: authState.signCount, credentialId };
}

export function decodeWebAuthnBase64url(value, maxBytes) { return decodeB64url(value, maxBytes); }

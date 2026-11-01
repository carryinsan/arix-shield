import { webcrypto, timingSafeEqual } from 'node:crypto';
import { setString } from './redis.js';

const cryptoApi = globalThis.crypto ?? webcrypto;
const encoder = new TextEncoder();

export function base64urlEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  return Buffer.from(bytes).toString('base64url');
}

export function base64urlDecode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid base64url value.');
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  cryptoApi.getRandomValues(data);
  return base64urlEncode(data);
}

export async function sha256(value) {
  const data = typeof value === 'string' ? encoder.encode(value) : value;
  return new Uint8Array(await cryptoApi.subtle.digest('SHA-256', data));
}

export async function sha256Hex(value) {
  return [...await sha256(value)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hmacSha256(secret, value) {
  const key = await cryptoApi.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await cryptoApi.subtle.sign('HMAC', key, encoder.encode(value)));
}

export function constantTimeEqual(a, b) {
  const left = a instanceof Uint8Array ? Buffer.from(a) : Buffer.from(String(a));
  const right = b instanceof Uint8Array ? Buffer.from(b) : Buffer.from(String(b));
  if (left.length !== right.length) {
    const padded = Buffer.alloc(left.length);
    timingSafeEqual(left, padded);
    return false;
  }
  return timingSafeEqual(left, right);
}

export function getMasterSecret() {
  const secret = process.env.ARIX_MASTER_SECRET;
  if (secret && Buffer.byteLength(secret) >= 32) return secret;
  if (process.env.NODE_ENV === 'production') throw new Error('ARIX_MASTER_SECRET must contain at least 32 bytes in production.');
  if (!globalThis.__ARIX_LOCAL_MASTER_SECRET__) {
    globalThis.__ARIX_LOCAL_MASTER_SECRET__ = randomToken(48);
    console.warn('[ArixShield] ARIX_MASTER_SECRET is not set; a temporary process-only development secret was generated.');
  }
  return globalThis.__ARIX_LOCAL_MASTER_SECRET__;
}

export async function derivePassword(password, salt = randomToken(16), iterations = 240000) {
  const material = await cryptoApi.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await cryptoApi.subtle.deriveBits({ name: 'PBKDF2', salt: base64urlDecode(salt), iterations, hash: 'SHA-256' }, material, 256);
  return { salt, hash: base64urlEncode(bits), iterations };
}

export async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash || !Number.isInteger(record?.iterations)) return false;
  const derived = await derivePassword(password, record.salt, record.iterations);
  return constantTimeEqual(base64urlDecode(derived.hash), base64urlDecode(record.hash));
}

export async function dpopThumbprint(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || 'd' in jwk) throw new Error('Invalid public P-256 JWK.');
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return base64urlEncode(await sha256(canonical));
}

export async function verifyDpopProof({ proof, method, url, projectId, redisGetSet }) {
  try {
    if (typeof proof !== 'string' || proof.length > 12000) return { valid: false, reason: 'MISSING_OR_OVERSIZED_DPOP' };
    const parts = proof.split('.');
    if (parts.length !== 3) return { valid: false, reason: 'MALFORMED_DPOP' };
    const header = JSON.parse(Buffer.from(base64urlDecode(parts[0])).toString('utf8'));
    const payload = JSON.parse(Buffer.from(base64urlDecode(parts[1])).toString('utf8'));
    if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk || !payload.jti) return { valid: false, reason: 'INVALID_DPOP_HEADER' };
    const thumbprint = await dpopThumbprint(header.jwk);
    if (payload.htm !== String(method).toUpperCase() || payload.htu !== url) return { valid: false, reason: 'DPOP_TARGET_MISMATCH' };
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(payload.iat) || Math.abs(now - payload.iat) > 60) return { valid: false, reason: 'DPOP_EXPIRED' };
    if (typeof payload.jti !== 'string' || payload.jti.length < 12 || payload.jti.length > 128) return { valid: false, reason: 'INVALID_DPOP_JTI' };
    const publicKey = await cryptoApi.subtle.importKey('jwk', header.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const signingInput = encoder.encode(`${parts[0]}.${parts[1]}`);
    const signature = base64urlDecode(parts[2]);
    const verified = await cryptoApi.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, signingInput);
    if (!verified) return { valid: false, reason: 'DPOP_SIGNATURE_INVALID' };
    const replayKey = `arix:dpop:${projectId}:${await sha256Hex(payload.jti)}`;
    const inserted = await redisGetSet(replayKey, '1', 120, true);
    if (inserted !== 'OK') return { valid: false, reason: 'DPOP_REPLAY' };
    return { valid: true, thumbprint };
  } catch {
    return { valid: false, reason: 'DPOP_VALIDATION_ERROR' };
  }
}

export async function createSignedToken(payload, purpose) {
  const body = base64urlEncode(encoder.encode(JSON.stringify({ ...payload, purpose })));
  const mac = await hmacSha256(getMasterSecret(), body);
  return `${body}.${base64urlEncode(mac)}`;
}

export async function verifySignedToken(token, purpose) {
  if (typeof token !== 'string' || token.length > 4096) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  try {
    const expected = await hmacSha256(getMasterSecret(), parts[0]);
    const actual = base64urlDecode(parts[1]);
    if (!constantTimeEqual(expected, actual)) return null;
    const payload = JSON.parse(Buffer.from(base64urlDecode(parts[0])).toString('utf8'));
    if (payload.purpose !== purpose || !Number.isFinite(payload.exp) || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

export async function trapMirage(projectId, requestPath, reason) {
  const seed = await hmacSha256(getMasterSecret(), `${projectId}:${requestPath}:${reason}`);
  const id = base64urlEncode(seed.slice(0, 9));
  return {
    status: 'success',
    environment: 'production-primary',
    request_id: `mirage_${id}`,
    data: {
      records: [
        { id: `usr_${id.slice(0, 8)}`, name: 'Jordan Example', role: 'account_admin', status: 'active' },
        { id: `usr_${id.slice(8, 12)}`, name: 'Morgan Sample', role: 'billing_viewer', status: 'active' }
      ],
      integration: { region: 'ap-south-1', storage: 'arix-decoy-vault', credential_marker: `ARIX_DECOY_${id.toUpperCase()}` }
    },
    meta: { page: 1, total: 2, generated: 'synthetic', trap_reason: reason.slice(0, 80) }
  };
}

export async function hashCredential(value) {
  return sha256Hex(value);
}

export async function markDpopReplay(key) {
  return setString(key, '1', 120, true);
}

function parseClearanceJwk(raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 16000) return null;
  try {
    const jwk = JSON.parse(raw);
    if (jwk?.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return null;
    return jwk;
  } catch { return null; }
}

export function getClearancePublicJwk() {
  const privateJwk = parseClearanceJwk(process.env.ARIX_CLEARANCE_PRIVATE_JWK);
  if (!privateJwk) return null;
  return {
    kty: 'RSA', n: privateJwk.n, e: privateJwk.e,
    alg: 'RSA-OAEP-256', use: 'enc', kid: String(privateJwk.kid || 'arix-clearance-v1'), ext: true
  };
}

export async function decryptClearanceJwe(compact) {
  if (typeof compact !== 'string' || compact.length > 24000) throw new Error('Invalid clearance token size.');
  const parts = compact.split('.');
  if (parts.length !== 5 || parts.some((part) => !part)) throw new Error('Malformed compact JWE.');
  const [protectedHeader, encryptedKey, ivPart, cipherPart, tagPart] = parts;
  const header = JSON.parse(Buffer.from(base64urlDecode(protectedHeader)).toString('utf8'));
  if (header.alg !== 'RSA-OAEP-256' || header.enc !== 'A256GCM' || header.kid !== String(process.env.ARIX_CLEARANCE_KID || 'arix-clearance-v1')) throw new Error('Unsupported clearance encryption header.');
  const privateJwk = parseClearanceJwk(process.env.ARIX_CLEARANCE_PRIVATE_JWK);
  if (!privateJwk?.d) throw new Error('Clearance decryption key is not configured.');
  const subtle = cryptoApi.subtle;
  if (!subtle) throw new Error('WebCrypto is unavailable in this runtime.');
  const privateKey = await subtle.importKey('jwk', privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const cek = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, base64urlDecode(encryptedKey));
  const aesKey = await subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt']);
  const ciphertextAndTag = Buffer.concat([base64urlDecode(cipherPart), base64urlDecode(tagPart)]);
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: base64urlDecode(ivPart), additionalData: Buffer.from(protectedHeader), tagLength: 128 }, aesKey, ciphertextAndTag);
  const value = JSON.parse(Buffer.from(plaintext).toString('utf8'));
  if (!value || typeof value !== 'object' || !Number.isFinite(value.iat) || Math.abs(Date.now() - value.iat) > 120000) throw new Error('Clearance telemetry is expired or has an invalid timestamp.');
  return value;
}

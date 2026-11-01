import { webcrypto, timingSafeEqual, createHmac } from 'node:crypto';
import { setString } from './redis.js';

const cryptoApi = globalThis.crypto ?? webcrypto;
const encoder = new TextEncoder();
const dpopReplayRing = globalThis.__ARIX_DPOP_REPLAY_RING__ ??= new Map();

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

const RESOURCE_ID_KEYS = new Set(['id', 'orderid', 'docid', 'documentid', 'accountid', 'invoiceid', 'paymentid', 'resourceid']);
const OWNER_ID_KEYS = new Set(['userid', 'user_id', 'ownerid', 'owner_id', 'accountid', 'customerid']);

/** Deterministic user-bound capability marker. Requires the existing ARIX_MASTER_SECRET. */
export function sealResourceId(resourceId, identity) {
  const id = String(resourceId);
  const subject = String(identity || '').trim();
  if (!subject || subject.toLowerCase() === 'anonymous' || id.length < 1 || id.length > 128 || /[~/\\]/.test(id)) throw new Error('A stable authenticated identity and a safe resource ID are required.');
  const mac = createHmac('sha256', getMasterSecret()).update(`arix-capability-v1:${subject}:${id}`).digest('hex').slice(0, 32);
  return `${id}~${mac}`;
}

export function verifyResourceId(sealedId, identity) {
  if (typeof sealedId !== 'string' || typeof identity !== 'string' || !identity.trim()) return null;
  const match = sealedId.match(/^(.{1,128})~([a-f0-9]{32})$/i);
  if (!match || /[~/\\]/.test(match[1])) return null;
  try {
    const expected = sealResourceId(match[1], identity).split('~').at(-1);
    const actual = Buffer.from(match[2].toLowerCase(), 'hex');
    const wanted = Buffer.from(expected, 'hex');
    return actual.length === wanted.length && timingSafeEqual(actual, wanted) ? match[1] : null;
  } catch { return null; }
}

export function sealResourceIdsInPayload(payload, identity, depth = 0) {
  if (depth > 24 || payload === null || typeof payload !== 'object') return payload;
  if (Array.isArray(payload)) return payload.map((value) => sealResourceIdsInPayload(value, identity, depth + 1));
  const output = {};
  for (const [key, value] of Object.entries(payload)) {
    if (RESOURCE_ID_KEYS.has(key.toLowerCase()) && (typeof value === 'string' || typeof value === 'number') && String(value).length <= 128 && !String(value).includes('~')) {
      try { output[key] = sealResourceId(value, identity); } catch { output[key] = value; }
    } else output[key] = sealResourceIdsInPayload(value, identity, depth + 1);
  }
  return output;
}

/** Returns only an ownership mismatch; it never guesses ownership from arbitrary fields. */
export function findOwnershipMismatch(payload, identity, additionalFields = []) {
  const subject = String(identity || '').trim();
  if (!subject || subject.toLowerCase() === 'anonymous' || !payload || typeof payload !== 'object') return null;
  const fields = new Set([...OWNER_ID_KEYS, ...(Array.isArray(additionalFields) ? additionalFields.map((field) => String(field).toLowerCase()) : [])]);
  const emailIdentity = subject.includes('@');
  if (emailIdentity) fields.add('email');
  const candidates = [payload, ...(Array.isArray(payload.data) ? payload.data.slice(0, 100) : []), ...(Array.isArray(payload.records) ? payload.records.slice(0, 100) : [])];
  for (const record of candidates) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) continue;
    for (const [key, value] of Object.entries(record)) {
      if (!fields.has(key.toLowerCase()) || value === null || value === undefined || typeof value === 'object') continue;
      const left = String(value).trim();
      const matches = key.toLowerCase() === 'email' ? left.toLowerCase() === subject.toLowerCase() : left === subject;
      if (!matches) return { field: key, expectedIdentity: subject.slice(0, 80) };
    }
  }
  return null;
}

export function rewriteCapabilityPath(url, identity, { requireSealed = true, idPattern = null } = {}) {
  const parsed = new URL(String(url), 'https://arixshield.invalid');
  let invalid = false;
  const segments = parsed.pathname.split('/');
  for (let index = 0; index < segments.length; index++) {
    let decoded;
    try { decoded = decodeURIComponent(segments[index]); } catch { invalid = true; break; }
    if (!decoded.includes('~')) {
      let looksLikeResourceId = /^\d{1,20}$/.test(decoded) || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded);
      if (idPattern instanceof RegExp) { idPattern.lastIndex = 0; looksLikeResourceId ||= idPattern.test(decoded); }
      if (requireSealed && looksLikeResourceId) invalid = true;
      continue;
    }
    const clean = verifyResourceId(decoded, identity);
    if (clean === null) { invalid = true; break; }
    segments[index] = encodeURIComponent(clean);
  }
  parsed.pathname = segments.join('/');
  const rewritten = `${parsed.pathname}${parsed.search}`;
  return { url: rewritten, invalid };
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
    const jtiHash = await sha256Hex(payload.jti);
    const localReplayKey = `${projectId}:${jtiHash}`;
    const nowMs = Date.now();
    for (const [key, expiry] of dpopReplayRing) if (expiry <= nowMs) dpopReplayRing.delete(key);
    if (dpopReplayRing.has(localReplayKey)) return { valid: false, reason: 'DPOP_REPLAY' };
    dpopReplayRing.set(localReplayKey, nowMs + 15000);
    if (dpopReplayRing.size > 4096) dpopReplayRing.delete(dpopReplayRing.keys().next().value);
    const replayKey = `arix:dpop:${projectId}:${jtiHash}`;
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

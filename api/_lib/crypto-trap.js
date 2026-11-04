import { webcrypto, timingSafeEqual, createHmac, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
import { PASSWORD_KDF } from './security-constants.js';
import { setString } from './redis.js';
import { BoundedReplayCache } from './bounded-replay-cache.js';

const cryptoApi = globalThis.crypto ?? webcrypto;
const scryptAsync = promisify(scryptCallback);
const encoder = new TextEncoder();
// Per-process fallback is hard-bounded globally and partitioned by project and
// DPoP key thumbprint. Active replay records are never evicted; expired records
// are pruned from a min-heap instead of scanning the complete cache per request.
const DPOP_REPLAY_WINDOW_MS = 91_000; // Covers the inclusive +/-45s iat window, including second-boundary rounding.
const DPOP_REPLAY_CACHE_MAX = 131_072;
const existingDpopReplayCache = globalThis.__ARIX_DPOP_REPLAY_CACHE__;
const dpopReplayCache = existingDpopReplayCache && typeof existingDpopReplayCache.consume === 'function' && typeof existingDpopReplayCache.stats === 'function'
  ? existingDpopReplayCache
  : (globalThis.__ARIX_DPOP_REPLAY_CACHE__ = new BoundedReplayCache({ maxEntries: DPOP_REPLAY_CACHE_MAX, maxPerNamespace: 32768, maxPerPartition: 16384 }));

function consumeLocalDpopReplay(key, projectId, thumbprint, ttlMs) {
  const namespace = String(projectId || 'default').slice(0, 180);
  const result = dpopReplayCache.consume(key, { namespace, partition: thumbprint, ttlMs });
  if (result.accepted) return null;
  return result.reason === 'REPLAY' ? 'DPOP_REPLAY' : 'DPOP_REPLAY_CACHE_FULL';
}

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

const RESOURCE_ID_KEYS = new Set(['id', 'orderid', 'docid', 'documentid', 'accountid', 'invoiceid', 'paymentid', 'resourceid', 'recordid', 'customerid', 'userid', 'fileid', 'projectid']);
const OWNER_ID_KEYS = new Set(['userid', 'user_id', 'ownerid', 'owner_id', 'accountid', 'customerid']);
const CAPABILITY_MODES = new Set(['read', 'write', 'delete']);

function capabilityContext(identity) {
  if (identity && typeof identity === 'object') {
    const tenantId = String(identity.tenantId || identity.projectId || '').trim();
    const userId = String(identity.userId || identity.ownerId || '').trim();
    if (!tenantId || !userId || tenantId.length > 180 || userId.length > 180 || userId.toLowerCase() === 'anonymous') return null;
    return { version: 2, tenantId, userId };
  }
  const subject = String(identity || '').trim();
  if (!subject || subject.toLowerCase() === 'anonymous' || subject.length > 180) return null;
  return { version: 1, userId: subject };
}

function capabilityMode(mode) {
  const value = String(mode || 'read').toLowerCase();
  if (!CAPABILITY_MODES.has(value)) throw new TypeError('Capability mode must be read, write or delete.');
  return value;
}

function resourceMac(resourceId, context, mode) {
  const secret = getMasterSecret();
  const material = context.version === 2
    ? `arix-cap-v2:${context.tenantId}:${context.userId}:${mode}:${resourceId}`
    : `arix-capability-v1:${context.userId}:${resourceId}`;
  return createHmac('sha256', secret).update(material).digest('hex').slice(0, 32);
}

/**
 * Deterministic capability marker. Object identities use v2 and bind tenant, user,
 * permission and resource ID. String identities retain v1 compatibility only.
 */
export function sealResourceId(resourceId, identity, mode = 'read') {
  const id = String(resourceId);
  const context = capabilityContext(identity);
  if (!context || id.length < 1 || id.length > 128 || /[~\/\\\u0000-\u001f]/.test(id)) throw new Error('A stable authenticated tenant/user identity and a safe resource ID are required.');
  if (context.version === 1) return `${id}~${resourceMac(id, context, 'read')}`;
  const permission = capabilityMode(mode);
  return `${id}~${permission[0]}~${resourceMac(id, context, permission)}`;
}

export function verifyResourceId(sealedId, identity, requiredMode = 'read') {
  if (typeof sealedId !== 'string') return null;
  const context = capabilityContext(identity);
  if (!context) return null;
  try {
    if (context.version === 2) {
      const match = sealedId.match(/^(.{1,128})~([rwd])~([a-f0-9]{32})$/i);
      if (!match || /[~\/\\\u0000-\u001f]/.test(match[1])) return null;
      const mode = ({ r: 'read', w: 'write', d: 'delete' })[match[2].toLowerCase()];
      if (mode !== capabilityMode(requiredMode)) return null;
      const expected = resourceMac(match[1], context, mode);
      const actual = Buffer.from(match[3].toLowerCase(), 'hex');
      const wanted = Buffer.from(expected, 'hex');
      return actual.length === wanted.length && timingSafeEqual(actual, wanted) ? match[1] : null;
    }
    const match = sealedId.match(/^(.{1,128})~([a-f0-9]{32})$/i);
    if (!match || /[~\/\\\u0000-\u001f]/.test(match[1])) return null;
    const expected = resourceMac(match[1], context, 'read');
    const actual = Buffer.from(match[2].toLowerCase(), 'hex');
    const wanted = Buffer.from(expected, 'hex');
    return actual.length === wanted.length && timingSafeEqual(actual, wanted) ? match[1] : null;
  } catch { return null; }
}

function looksLikeId(value) {
  const text = String(value);
  return /^\d{1,20}$/.test(text)
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(text)
    || /^[A-Za-z0-9_-]{20,128}$/.test(text)
    || /^(?:usr|prj|org|acct|doc|inv|pay|res|rec|cus|file|proj)_[A-Za-z0-9_-]{4,120}$/i.test(text);
}

export function sealResourceIdsInPayload(payload, identity, depth = 0, mode = 'read') {
  if (depth > 24 || payload === null || typeof payload !== 'object') return payload;
  if (Array.isArray(payload)) return payload.map((value) => sealResourceIdsInPayload(value, identity, depth + 1, mode));
  const output = Object.create(null);
  for (const [key, value] of Object.entries(payload)) {
    if (RESOURCE_ID_KEYS.has(key.toLowerCase()) && (typeof value === 'string' || typeof value === 'number') && String(value).length <= 128 && !String(value).includes('~')) {
      try { output[key] = sealResourceId(value, identity, mode); } catch { output[key] = value; }
    } else output[key] = sealResourceIdsInPayload(value, identity, depth + 1, mode);
  }
  return output;
}

/** Returns only an ownership mismatch; it never guesses ownership from arbitrary fields. */
export function findOwnershipMismatch(payload, identity, additionalFields = []) {
  const context = capabilityContext(identity);
  const subject = context?.userId || '';
  if (!subject || !payload || typeof payload !== 'object') return null;
  const fields = new Set([...OWNER_ID_KEYS, ...(Array.isArray(additionalFields) ? additionalFields.map((field) => String(field).toLowerCase()) : [])]);
  const emailIdentity = subject.includes('@');
  if (emailIdentity) fields.add('email');
  const visited = new WeakSet();
  let nodes = 0;
  let structureExceeded = false;
  const walk = (value, depth = 0) => {
    if (depth > 24 || ++nodes > 10_000) { structureExceeded = true; return null; }
    if (value === null || typeof value !== 'object') return null;
    if (visited.has(value)) return null;
    visited.add(value);
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) {
        const mismatch = walk(value[index], depth + 1);
        if (mismatch) return mismatch;
        if (structureExceeded) return null;
      }
      return null;
    }
    let entries;
    try { entries = Object.entries(value); } catch { structureExceeded = true; return null; }
    for (const [key, child] of entries) {
      const lower = key.toLowerCase();
      if (fields.has(lower) && child !== null && child !== undefined && (typeof child === 'string' || typeof child === 'number' || typeof child === 'boolean')) {
        const left = String(child).trim();
        const matches = lower === 'email' ? left.toLowerCase() === subject.toLowerCase() : left === subject;
        if (!matches) return { field: key, expectedIdentity: subject.slice(0, 80) };
      } else {
        const mismatch = walk(child, depth + 1);
        if (mismatch) return mismatch;
        if (structureExceeded) return null;
      }
    }
    return null;
  };
  const mismatch = walk(payload);
  // An oversized/cyclic response is not accepted as ownership-safe: the caller
  // treats any returned marker as a mismatch and can fail closed.
  return mismatch || (structureExceeded ? { field: '[structure-limit]', expectedIdentity: subject.slice(0, 80) } : null);
}

function requiredModeForMethod(method) {
  const verb = String(method || 'GET').toUpperCase();
  return verb === 'DELETE' ? 'delete' : ['POST', 'PUT', 'PATCH'].includes(verb) ? 'write' : 'read';
}

function rewriteBodyCapabilities(value, identity, mode, { requireSealed = true, depth = 0 } = {}) {
  if (depth > 24 || value === null || typeof value !== 'object') return { value, invalid: false, verified: 0 };
  if (Array.isArray(value)) {
    let invalid = false; let verified = 0;
    const output = value.map((child) => { const result = rewriteBodyCapabilities(child, identity, mode, { requireSealed, depth: depth + 1 }); invalid ||= result.invalid; verified += result.verified || 0; return result.value; });
    return { value: output, invalid, verified };
  }
  const output = Object.create(null);
  let invalid = false; let verified = 0;
  for (const [key, child] of Object.entries(value)) {
    if (RESOURCE_ID_KEYS.has(key.toLowerCase())) {
      const rewriteScalar = (candidate) => {
        if (typeof candidate !== 'string' && typeof candidate !== 'number') {
          invalid = true;
          return candidate;
        }
        const raw = String(candidate);
        const clean = verifyResourceId(raw, identity, mode);
        if (clean !== null) { verified++; return clean; }
        if (requireSealed || raw.includes('~')) invalid = true;
        return candidate;
      };
      if (Array.isArray(child)) {
        // Singular resource-ID properties may be represented as a bounded list,
        // but every element must be an independently verified capability.
        if (child.length > 100) invalid = true;
        output[key] = child.slice(0, 100).map(rewriteScalar);
      } else if (child !== null && typeof child === 'object') {
        invalid = true;
        output[key] = child;
      } else {
        output[key] = rewriteScalar(child);
      }
    } else {
      const result = rewriteBodyCapabilities(child, identity, mode, { requireSealed, depth: depth + 1 });
      output[key] = result.value; invalid ||= result.invalid; verified += result.verified || 0;
    }
  }
  return { value: output, invalid, verified };
}

/** Verify and unseal resource capabilities in path, query string and JSON body. */
export function rewriteCapabilityRequest(url, body, identity, { requireSealed = true, idPattern = null, method = 'GET', arrayQueryFields = [] } = {}) {
  const parsed = new URL(String(url), 'https://arixshield.invalid');
  let invalid = false;
  let verifiedResourceIds = 0;
  const mode = requiredModeForMethod(method);
  const segments = parsed.pathname.split('/');
  for (let index = 0; index < segments.length; index++) {
    let decoded;
    try { decoded = decodeURIComponent(segments[index]); } catch { invalid = true; break; }
    if (!decoded.includes('~')) {
      let looksLikeResourceId = looksLikeId(decoded);
      if (idPattern instanceof RegExp) { idPattern.lastIndex = 0; looksLikeResourceId ||= idPattern.test(decoded); }
      if (requireSealed && looksLikeResourceId) invalid = true;
      continue;
    }
    const clean = verifyResourceId(decoded, identity, mode);
    if (clean === null) { invalid = true; break; }
    segments[index] = encodeURIComponent(clean);
    verifiedResourceIds++;
  }
  parsed.pathname = segments.join('/');
  const permittedArrays = new Set(arrayQueryFields.map((v) => String(v).toLowerCase()));
  const queryGroups = new Map();
  for (const [key, value] of parsed.searchParams.entries()) {
    const lower = key.toLowerCase();
    const group = queryGroups.get(lower) || { keys: new Set(), values: [] };
    group.keys.add(key);
    group.values.push(value);
    queryGroups.set(lower, group);
  }
  for (const [lower, group] of queryGroups) {
    if (group.values.length > 1 && !permittedArrays.has(lower)) invalid = true;
    if (!RESOURCE_ID_KEYS.has(lower)) continue;
    if (!permittedArrays.has(lower) && group.values.length !== 1) { invalid = true; continue; }
    if (group.values.length > 100) { invalid = true; continue; }
    const rewritten = [];
    for (const raw of group.values) {
      const clean = verifyResourceId(raw, identity, mode);
      if (clean === null) {
        if (requireSealed || raw.includes('~')) invalid = true;
        rewritten.push(raw);
      } else {
        verifiedResourceIds++;
        rewritten.push(clean);
      }
    }
    const canonicalKey = group.keys.values().next().value;
    for (const key of group.keys) parsed.searchParams.delete(key);
    for (const clean of rewritten) parsed.searchParams.append(canonicalKey, clean);
  }
  const bodyResult = rewriteBodyCapabilities(body, identity, mode, { requireSealed });
  invalid ||= bodyResult.invalid;
  verifiedResourceIds += bodyResult.verified || 0;
  return { url: `${parsed.pathname}${parsed.search}`, body: bodyResult.value, invalid, verifiedResourceIds, capabilityVerified: !invalid && verifiedResourceIds > 0 };
}

export function rewriteCapabilityPath(url, identity, { requireSealed = true, idPattern = null, method = 'GET' } = {}) {
  const result = rewriteCapabilityRequest(url, null, identity, { requireSealed, idPattern, method });
  return { url: result.url, invalid: result.invalid };
}

async function deriveLegacyPbkdf2(password, salt, iterations) {
  const material = await cryptoApi.subtle.importKey('raw', encoder.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await cryptoApi.subtle.deriveBits({ name: 'PBKDF2', salt: base64urlDecode(salt), iterations, hash: 'SHA-256' }, material, 256);
  return new Uint8Array(bits);
}

/** New password records use Node's memory-hard scrypt KDF. */
export async function derivePassword(password) {
  if (typeof password !== 'string') throw new TypeError('Password must be a string.');
  const salt = randomToken(16);
  const derived = await scryptAsync(password, Buffer.from(base64urlDecode(salt)), PASSWORD_KDF.keyLength, {
    N: PASSWORD_KDF.N, r: PASSWORD_KDF.r, p: PASSWORD_KDF.p, maxmem: PASSWORD_KDF.maxmem
  });
  return { algorithm: PASSWORD_KDF.algorithm, version: 2, salt, hash: base64urlEncode(derived), N: PASSWORD_KDF.N, r: PASSWORD_KDF.r, p: PASSWORD_KDF.p, keyLength: PASSWORD_KDF.keyLength };
}

/** Verify both current scrypt records and historical PBKDF2 records during migration. */
export async function verifyPassword(password, record) {
  if (typeof password !== 'string' || !record?.salt || !record?.hash) return false;
  try {
    const expected = base64urlDecode(record.hash);
    if (record.algorithm === 'scrypt') {
      // Do not let untrusted stored parameters request unbounded CPU or memory.
      if (record.version !== 2 || record.N !== PASSWORD_KDF.N || record.r !== PASSWORD_KDF.r || record.p !== PASSWORD_KDF.p || record.keyLength !== PASSWORD_KDF.keyLength) return false;
      const salt = base64urlDecode(record.salt);
      if (salt.length !== 16 || expected.length !== PASSWORD_KDF.keyLength) return false;
      const actual = await scryptAsync(password, Buffer.from(salt), PASSWORD_KDF.keyLength, {
        N: PASSWORD_KDF.N, r: PASSWORD_KDF.r, p: PASSWORD_KDF.p, maxmem: PASSWORD_KDF.maxmem
      });
      return constantTimeEqual(actual, Buffer.from(expected));
    }
    // Records without an algorithm marker are legacy PBKDF2-HMAC-SHA-256.
    const iterations = Number(record.iterations);
    if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 2_000_000 || expected.length !== 32) return false;
    const salt = base64urlDecode(record.salt);
    if (salt.length < 16 || salt.length > 64) return false;
    const actual = await deriveLegacyPbkdf2(password, record.salt, iterations);
    return constantTimeEqual(actual, Buffer.from(expected));
  } catch { return false; }
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
    const replayKey = `arix:dpop:${projectId}:${jtiHash}`;
    const inserted = await redisGetSet(replayKey, '1', 121, true); // Covers inclusive +/-60s iat window plus sub-second rounding.
    if (inserted !== 'OK') return { valid: false, reason: 'DPOP_REPLAY' };
    return { valid: true, thumbprint };
  } catch {
    return { valid: false, reason: 'DPOP_VALIDATION_ERROR' };
  }
}

/** Verify a body-bound DPoP proof for customer API requests without a control-plane lookup. */
export async function verifyRequestDpopProof({ proof, method, url, bodyBytes = new Uint8Array(), expectedThumbprint = null, clearanceNonce = null, projectId = 'arix', consumeReplay = null }) {
  try {
    if (typeof proof !== 'string' || proof.length > 12000) return { valid: false, reason: 'MISSING_OR_OVERSIZED_DPOP' };
    const parts = proof.split('.');
    if (parts.length !== 3) return { valid: false, reason: 'MALFORMED_DPOP' };
    const header = JSON.parse(Buffer.from(base64urlDecode(parts[0])).toString('utf8'));
    const payload = JSON.parse(Buffer.from(base64urlDecode(parts[1])).toString('utf8'));
    if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk || !payload.jti) return { valid: false, reason: 'INVALID_DPOP_HEADER' };
    const thumbprint = await dpopThumbprint(header.jwk);
    const expectedUrl = new URL(String(url)); expectedUrl.hash = '';
    if (payload.htm !== String(method).toUpperCase() || payload.htu !== expectedUrl.href) return { valid: false, reason: 'DPOP_TARGET_MISMATCH' };
    if (expectedThumbprint && thumbprint !== expectedThumbprint) return { valid: false, reason: 'DPOP_KEY_MISMATCH' };
    if (clearanceNonce && payload.nonce !== clearanceNonce) return { valid: false, reason: 'DPOP_CLEARANCE_NONCE_MISMATCH' };
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(payload.iat) || Math.abs(now - payload.iat) > 45) return { valid: false, reason: 'DPOP_EXPIRED' };
    if (typeof payload.jti !== 'string' || payload.jti.length < 12 || payload.jti.length > 128) return { valid: false, reason: 'INVALID_DPOP_JTI' };
    const digest = await sha256(bodyBytes instanceof Uint8Array ? bodyBytes : new Uint8Array(bodyBytes));
    if (payload.ath !== base64urlEncode(digest)) return { valid: false, reason: 'DPOP_BODY_HASH_MISMATCH' };
    const publicKey = await cryptoApi.subtle.importKey('jwk', header.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const verified = await cryptoApi.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, base64urlDecode(parts[2]), encoder.encode(`${parts[0]}.${parts[1]}`));
    if (!verified) return { valid: false, reason: 'DPOP_SIGNATURE_INVALID' };
    const jtiHash = await sha256Hex(payload.jti);
    if (typeof consumeReplay === 'function') {
      let consumed;
      try { consumed = await consumeReplay(jtiHash); }
      catch { return { valid: false, reason: 'DPOP_REPLAY_SERVICE_UNAVAILABLE', unavailable: true }; }
      if (!consumed) return { valid: false, reason: 'DPOP_REPLAY' };
      return { valid: true, thumbprint, jtiHash, replayConsumed: true };
    }
    // Standalone/local fallback is bounded and partitioned. Production clearance
    // validation supplies the durable replay consumer instead (see below).
    const replayKey = `${projectId}:${jtiHash}`;
    const localReplayFailure = consumeLocalDpopReplay(replayKey, projectId, thumbprint, DPOP_REPLAY_WINDOW_MS);
    if (localReplayFailure) return { valid: false, reason: localReplayFailure };
    return { valid: true, thumbprint, jtiHash, replayConsumed: false };
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
  const configuredKid = process.env.ARIX_CLEARANCE_KID;
  if (configuredKid && privateJwk.kid && configuredKid !== privateJwk.kid) return null;
  const kid = String(configuredKid || privateJwk.kid || 'arix-clearance-v1');
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(kid)) return null;
  return {
    kty: 'RSA', n: privateJwk.n, e: privateJwk.e,
    alg: 'RSA-OAEP-256', use: 'enc', kid, ext: true
  };
}

export async function decryptClearanceJwe(compact) {
  if (typeof compact !== 'string' || compact.length > 24000) throw new Error('Invalid clearance token size.');
  const parts = compact.split('.');
  if (parts.length !== 5 || parts.some((part) => !part)) throw new Error('Malformed compact JWE.');
  const [protectedHeader, encryptedKey, ivPart, cipherPart, tagPart] = parts;
  const privateJwk = parseClearanceJwk(process.env.ARIX_CLEARANCE_PRIVATE_JWK);
  if (!privateJwk?.d) throw new Error('Clearance decryption key is not configured.');
  const configuredKid = process.env.ARIX_CLEARANCE_KID;
  if (configuredKid && privateJwk.kid && configuredKid !== privateJwk.kid) throw new Error('Clearance key identifier does not match the configured private key.');
  const expectedKid = String(configuredKid || privateJwk.kid || 'arix-clearance-v1');
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(expectedKid)) throw new Error('Invalid clearance key identifier.');
  const header = JSON.parse(Buffer.from(base64urlDecode(protectedHeader)).toString('utf8'));
  if (header.alg !== 'RSA-OAEP-256' || header.enc !== 'A256GCM' || header.kid !== expectedKid) throw new Error('Unsupported clearance encryption header.');
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

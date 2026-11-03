import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

const DOMAIN = 'arixshield-edge-clearance-v1';
const SALT = Buffer.from('ArixShield Edge Clearance Salt v1', 'utf8');
const INFO = Buffer.from('edge-middleware-hmac-sha256', 'utf8');

function signingKey(secret) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) throw new Error('ARIX_MASTER_SECRET must contain at least 32 bytes for edge clearance signing.');
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), SALT, INFO, 32));
}
function b64url(bytes) { return Buffer.from(bytes).toString('base64url'); }
function safeAudience(value) {
  const url = new URL(String(value));
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new TypeError('Edge clearance audience must be a credential-free origin.');
  return url.origin;
}

/** Create a short-lived stateless ticket for the framework-independent Vercel Routing Middleware. */
export function createEdgeClearanceTicket({ audience, pathPrefix = '/', methods = null, ttlMs = 120_000, now = Date.now(), secret = process.env.ARIX_MASTER_SECRET } = {}) {
  const aud = safeAudience(audience);
  const prefix = String(pathPrefix);
  if (!prefix.startsWith('/') || prefix.startsWith('//') || prefix.length > 512 || /[\r\n\u0000-\u001f]/.test(prefix)) throw new TypeError('Edge clearance pathPrefix must be a safe absolute path.');
  const ttl = Number(ttlMs);
  if (!Number.isSafeInteger(ttl) || ttl < 1000 || ttl > 300_000 || !Number.isSafeInteger(now)) throw new RangeError('Edge clearance TTL must be 1–300 seconds.');
  const allowedMethods = methods == null ? null : [...new Set(methods.map((method) => String(method).toUpperCase()))];
  if (allowedMethods && (!allowedMethods.length || allowedMethods.length > 8 || allowedMethods.some((method) => !/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method)))) throw new TypeError('Edge clearance methods contain an unsupported method.');
  const payload = { v: 1, iat: now, exp: now + ttl, aud, pathPrefix: prefix, methods: allowedMethods, nonce: randomBytes(16).toString('base64url') };
  const encoded = b64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${DOMAIN}.${encoded}`;
  const signature = createHmac('sha256', signingKey(secret)).update(signingInput).digest();
  return `${encoded}.${b64url(signature)}`;
}

export function verifyEdgeClearanceTicket(ticket, { audience, path, method, now = Date.now(), secret = process.env.ARIX_MASTER_SECRET } = {}) {
  if (typeof ticket !== 'string' || ticket.length > 4096 || !ticket.includes('.')) return false;
  const [encoded, supplied, extra] = ticket.split('.');
  if (!encoded || !supplied || extra !== undefined || !/^[A-Za-z0-9_-]{43}$/.test(supplied)) return false;
  try {
    const expected = createHmac('sha256', signingKey(secret)).update(`${DOMAIN}.${encoded}`).digest();
    const actual = Buffer.from(supplied, 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return false;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (payload?.v !== 1 || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.exp <= now || payload.iat > now + 30_000 || payload.exp - payload.iat > 300_000) return false;
    if (safeAudience(audience) !== payload.aud) return false;
    const requestedPath = String(path || '/');
    const prefix = String(payload.pathPrefix || '');
    if (!requestedPath.startsWith(prefix) || (prefix !== '/' && requestedPath.length > prefix.length && !prefix.endsWith('/') && requestedPath[prefix.length] !== '/')) return false;
    if (Array.isArray(payload.methods) && !payload.methods.includes(String(method || 'GET').toUpperCase())) return false;
    return /^[A-Za-z0-9_-]{22}$/.test(String(payload.nonce || ''));
  } catch { return false; }
}

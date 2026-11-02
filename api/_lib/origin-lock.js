import { createHash, randomBytes, sign, verify } from 'node:crypto';

function bodyBytes(req) {
  const body = req?.rawBody ?? req?.body;
  if (body == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body);
  throw new TypeError('Origin proof requires raw request bytes; parsed objects are ambiguous');
}

export function originProofPayload({ timestamp, nonce, method, url, clientIp, body }) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body ?? '');
  const digest = createHash('sha256').update(bytes).digest('hex');
  return Buffer.from(`${timestamp}\n${nonce}\n${String(method).toUpperCase()}\n${url}\n${clientIp}\n${digest}`, 'utf8');
}

export function createOriginProof({ privateKey, timestamp = Date.now(), nonce = randomBytes(16).toString('base64url'), method, url, clientIp = '', body = Buffer.alloc(0) } = {}) {
  if (!privateKey || !method || typeof url !== 'string' || !url.startsWith('/') || url.length > 8192 || /[\r\n\u0000-\u001f]/.test(url) || !/^[A-Z]{1,12}$/i.test(String(method)) || !Number.isSafeInteger(Number(timestamp)) || !/^[A-Za-z0-9_-]{22}$/.test(String(nonce)) || /[\r\n\u0000-\u001f]/.test(String(clientIp)) || String(clientIp).length > 64) throw new TypeError('privateKey, canonical method/URL, timestamp, client IP and 128-bit nonce are required');
  const signature = sign(null, originProofPayload({ timestamp, nonce, method, url, clientIp, body }), privateKey).toString('base64url');
  return `${timestamp}.${nonce}.${signature}`;
}

/**
 * Verify the edge signature and atomically consume its 128-bit nonce. The
 * caller's consumeNonce implementation must be shared/durable (e.g. Redis
 * SET NX with TTL); absence or outage of that store fails closed.
 */
export async function verifyOriginProof(req, { publicKey, maxAgeMs = 30_000, now = Date.now(), consumeNonce, requirePeerCertificate = false, peerFingerprint256 = null } = {}) {
  if (!publicKey) return Object.freeze({ valid: false, reason: 'PUBLIC_KEY_NOT_CONFIGURED' });
  if (typeof consumeNonce !== 'function') return Object.freeze({ valid: false, reason: 'REPLAY_STORE_REQUIRED' });
  if (requirePeerCertificate) {
    let cert;
    try { cert = req.socket?.getPeerCertificate?.(); } catch { cert = null; }
    const authorized = req.socket?.authorized === true;
    const fingerprint = String(cert?.fingerprint256 || '').replaceAll(':', '').toLowerCase();
    const expected = String(peerFingerprint256 || '').replaceAll(':', '').toLowerCase();
    if (!authorized || !cert?.raw || (expected && fingerprint !== expected)) return Object.freeze({ valid: false, reason: 'MTLS_PEER_UNTRUSTED' });
  }
  const header = req?.headers?.['x-arix-origin-proof'];
  if (typeof header !== 'string' || header.length > 256) return Object.freeze({ valid: false, reason: 'PROOF_MISSING' });
  const parts = header.split('.');
  if (parts.length !== 3) return Object.freeze({ valid: false, reason: 'PROOF_MALFORMED' });
  const [timestampText, nonce, signature] = parts;
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > maxAgeMs) return Object.freeze({ valid: false, reason: 'PROOF_EXPIRED' });
  if (!/^[A-Za-z0-9_-]{22}$/.test(nonce) || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return Object.freeze({ valid: false, reason: 'PROOF_MALFORMED' });
  let body;
  try { body = bodyBytes(req); } catch { return Object.freeze({ valid: false, reason: 'BODY_NOT_CANONICAL' }); }
  const clientIp = String(req.headers['x-arix-client-ip'] || '').slice(0, 64);
  const url = String(req.originalUrl || req.url || '');
  if (url.length > 8192 || /[\r\n\u0000-\u001f]/.test(url)) return Object.freeze({ valid: false, reason: 'URL_NOT_CANONICAL' });
  let cryptographicallyValid = false;
  try {
    cryptographicallyValid = verify(null, originProofPayload({ timestamp, nonce, method: req.method || 'GET', url, clientIp, body }), publicKey, Buffer.from(signature, 'base64url'));
  } catch { cryptographicallyValid = false; }
  if (!cryptographicallyValid) return Object.freeze({ valid: false, reason: 'PROOF_INVALID' });
  let consumed = false;
  try { consumed = await consumeNonce(nonce, timestamp + maxAgeMs); } catch { return Object.freeze({ valid: false, reason: 'REPLAY_STORE_UNAVAILABLE' }); }
  if (!consumed) return Object.freeze({ valid: false, reason: 'PROOF_REPLAYED' });
  return Object.freeze({ valid: true, timestamp, nonce, clientIp });
}

export function createOriginLockMiddleware(options = {}) {
  return async function originLock(req, res, next) {
    let result;
    try { result = await verifyOriginProof(req, options); }
    catch { result = { valid: false, reason: 'PROOF_VERIFICATION_FAILED' }; }
    if (result.valid) return next();
    res.statusCode = 403;
    if (typeof res.setHeader === 'function') res.setHeader('content-type', 'application/json; charset=utf-8');
    const body = JSON.stringify({ error: 'Direct Origin Access Denied', code: 'ORIGIN_LOCK_FAILED', reason: result.reason });
    if (typeof res.end === 'function') return res.end(body);
    return false;
  };
}

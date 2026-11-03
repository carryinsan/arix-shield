const DOMAIN = 'arixshield-edge-clearance-v1';
const SALT = new TextEncoder().encode('ArixShield Edge Clearance Salt v1');
const INFO = new TextEncoder().encode('edge-middleware-hmac-sha256');
const encoder = new TextEncoder();

function decodeBase64Url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, (character) => character.charCodeAt(0));
}

function isExcluded(pathname) {
  return pathname.startsWith('/_next/static/') || pathname.startsWith('/_next/image/')
    || pathname === '/favicon.ico' || pathname === '/robots.txt' || pathname === '/sitemap.xml';
}

function readCookie(request, name) {
  const header = request.headers.get('cookie');
  if (typeof header !== 'string' || header.length > 8192) return '';

  let found = null;
  let start = 0;
  while (start < header.length) {
    const separator = header.indexOf(';', start);
    const end = separator === -1 ? header.length : separator;
    const item = header.slice(start, end).trim();
    const equals = item.indexOf('=');
    if (equals > 0 && item.slice(0, equals).trim() === name) {
      // Duplicate cookie names are ambiguous; fail closed instead of choosing one.
      if (found !== null) return '';
      found = item.slice(equals + 1).trim();
    }
    start = end + 1;
  }
  return found || '';
}

async function verifyTicket(ticket, requestUrl, method, secret) {
  if (typeof ticket !== 'string' || ticket.length > 4096) return false;
  const parts = ticket.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return false;
  try {
    const rootKey = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);
    const hmacKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: SALT, info: INFO },
      rootKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['verify'],
    );
    const payloadBytes = decodeBase64Url(parts[0]);
    const signature = decodeBase64Url(parts[1]);
    const valid = await crypto.subtle.verify('HMAC', hmacKey, signature, encoder.encode(`${DOMAIN}.${parts[0]}`));
    if (!valid) return false;

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    const now = Date.now();
    if (payload?.v !== 1 || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
      || payload.exp <= now || payload.iat > now + 30_000 || payload.exp - payload.iat > 300_000) return false;
    if (payload.aud !== requestUrl.origin) return false;

    const path = requestUrl.pathname;
    const prefix = String(payload.pathPrefix || '');
    if (!prefix.startsWith('/') || !path.startsWith(prefix)
      || (prefix !== '/' && path.length > prefix.length && !prefix.endsWith('/') && path[prefix.length] !== '/')) return false;
    if (Array.isArray(payload.methods) && !payload.methods.includes(method.toUpperCase())) return false;
    return /^[A-Za-z0-9_-]{22}$/.test(String(payload.nonce || ''));
  } catch {
    return false;
  }
}

function errorResponse(status, error) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

/**
 * Create framework-independent Vercel Routing Middleware.
 * `next` is injected so the security policy can be regression-tested without
 * loading the Vercel runtime package in local unit tests.
 */
export function createEdgeClearanceProxy({ next, getEnv = () => process.env } = {}) {
  if (typeof next !== 'function') throw new TypeError('A Vercel Routing Middleware next() function is required.');

  return async function edgeClearanceProxy(request) {
    let requestUrl;
    try {
      requestUrl = new URL(request.url);
    } catch {
      return errorResponse(400, 'Invalid request URL.');
    }

    const env = getEnv();
    if (env.ARIX_EDGE_PROOF_REQUIRED !== 'true' || isExcluded(requestUrl.pathname)) return next();

    const secret = env.ARIX_MASTER_SECRET;
    if (typeof secret !== 'string' || encoder.encode(secret).byteLength < 32) {
      return errorResponse(503, 'Edge origin proof is not configured.');
    }

    const headerTicket = request.headers.get('x-arix-edge-ticket');
    const cookieTicket = readCookie(request, 'arix_edge_clearance');
    const accepted = await verifyTicket(headerTicket || cookieTicket, requestUrl, request.method, secret);
    if (!accepted) return errorResponse(403, 'Edge clearance required.');

    return next({ headers: { 'x-arix-edge-verified': '1' } });
  };
}

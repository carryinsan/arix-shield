import { timingSafeEqual } from 'node:crypto';

export function sendJson(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  for (const [key, value] of Object.entries(extraHeaders)) res.setHeader(key, value);
  res.end(JSON.stringify(body));
}

export async function readJson(req, maxBytes = 32768) {
  const length = Number(req.headers?.['content-length'] ?? 0);
  if (length > maxBytes) throw Object.assign(new Error('Request body too large.'), { statusCode: 413 });
  if (req.body !== undefined && req.body !== null) {
    const raw = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    if (Buffer.byteLength(raw) > maxBytes) throw Object.assign(new Error('Request body too large.'), { statusCode: 413 });
    try { return typeof req.body === 'object' ? req.body : JSON.parse(raw); }
    catch { throw Object.assign(new Error('Invalid JSON body.'), { statusCode: 400 }); }
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('Request body too large.'), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!size) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('Invalid JSON body.'), { statusCode: 400 }); }
}

export function methodNotAllowed(res, allowed) {
  sendJson(res, 405, { error: 'Method not allowed.' }, { Allow: allowed.join(', ') });
}

export function setSessionCookie(res, token, maxAgeSeconds, secure = true) {
  const prefix = secure ? '__Host-' : '';
  res.setHeader('Set-Cookie', `${prefix}arix_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}${secure ? '; Secure' : ''}`);
}

export function clearSessionCookie(res, secure = true) {
  const prefix = secure ? '__Host-' : '';
  res.setHeader('Set-Cookie', `${prefix}arix_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`);
}

export function readCookie(req, name) {
  const header = String(req.headers?.cookie ?? '');
  for (const part of header.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) {
      try { return decodeURIComponent(value.join('=')); } catch { return null; }
    }
  }
  return null;
}

export function sameOriginRequest(req) {
  const origin = req.headers?.origin;
  const host = req.headers?.['x-forwarded-host'] || req.headers?.host;
  const forwardedProto = String(req.headers?.['x-forwarded-proto'] ?? 'https').split(',')[0].trim().toLowerCase();
  if (typeof origin !== 'string' || typeof host !== 'string' || !['https', 'http'].includes(forwardedProto)) return false;
  try {
    const parsed = new URL(origin);
    return parsed.origin === `${forwardedProto}://${String(host).toLowerCase()}`;
  } catch { return false; }
}

export function getNetworkHints(req) {
  // These headers are display/telemetry hints only. They are never used as proof of identity.
  const ip = typeof req.headers?.['x-real-ip'] === 'string' ? req.headers['x-real-ip'].slice(0, 64) : 'unavailable';
  const country = typeof req.headers?.['x-vercel-ip-country'] === 'string' ? req.headers['x-vercel-ip-country'].slice(0, 2) : '—';
  const city = typeof req.headers?.['x-vercel-ip-city'] === 'string' ? decodeURIComponentSafe(req.headers['x-vercel-ip-city']).slice(0, 80) : '—';
  const asn = typeof req.headers?.['x-vercel-ip-as-number'] === 'string' ? req.headers['x-vercel-ip-as-number'].slice(0, 16) : '—';
  const ja3 = typeof req.headers?.['x-vercel-ja3-digest'] === 'string' ? req.headers['x-vercel-ja3-digest'].slice(0, 128) : '—';
  const ja4 = typeof req.headers?.['x-vercel-ja4-digest'] === 'string' ? req.headers['x-vercel-ja4-digest'].slice(0, 128) : '—';
  const latValue = Number(req.headers?.['x-vercel-ip-latitude']);
  const lonValue = Number(req.headers?.['x-vercel-ip-longitude']);
  const hasCoordinates = Number.isFinite(latValue) && Number.isFinite(lonValue) && latValue >= -90 && latValue <= 90 && lonValue >= -180 && lonValue <= 180;
  return { ip, country, city, asn, ja3, ja4, ...(hasCoordinates ? { latitude: latValue, longitude: lonValue } : {}) };
}

function decodeURIComponentSafe(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

export function clientRateKey(req) {
  // Vercel documents x-real-ip as identical to its overwritten x-forwarded-for value;
  // treat it only as a rate-limit/telemetry hint, never as authentication proof.
  const ip = typeof req.headers?.['x-vercel-forwarded-for'] === 'string' ? req.headers['x-vercel-forwarded-for'] : typeof req.headers?.['x-real-ip'] === 'string' ? req.headers['x-real-ip'] : 'unknown';
  const agent = typeof req.headers?.['user-agent'] === 'string' ? req.headers['user-agent'].slice(0, 160) : 'unknown';
  return `${ip.slice(0, 64)}:${agent}`;
}

export function safeConstantStringEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    timingSafeEqual(left, Buffer.alloc(left.length));
    return false;
  }
  return timingSafeEqual(left, right);
}

export function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.length > 240) return null;
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
    if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) return null;
    return url.origin;
  } catch { return null; }
}

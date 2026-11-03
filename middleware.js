import { NextResponse } from 'next/server';

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
async function verifyTicket(ticket, request, secret) {
  if (typeof ticket !== 'string' || ticket.length > 4096) return false;
  const parts = ticket.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return false;
  try {
    const rootKey = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);
    const hmacKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: INFO }, rootKey, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['verify']);
    const payloadBytes = decodeBase64Url(parts[0]);
    const signature = decodeBase64Url(parts[1]);
    const valid = await crypto.subtle.verify('HMAC', hmacKey, signature, encoder.encode(`${DOMAIN}.${parts[0]}`));
    if (!valid) return false;
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    const now = Date.now();
    if (payload?.v !== 1 || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
      || payload.exp <= now || payload.iat > now + 30_000 || payload.exp - payload.iat > 300_000) return false;
    if (payload.aud !== request.nextUrl.origin) return false;
    const path = request.nextUrl.pathname;
    const prefix = String(payload.pathPrefix || '');
    if (!prefix.startsWith('/') || !path.startsWith(prefix)
      || (prefix !== '/' && path.length > prefix.length && !prefix.endsWith('/') && path[prefix.length] !== '/')) return false;
    if (Array.isArray(payload.methods) && !payload.methods.includes(request.method.toUpperCase())) return false;
    return /^[A-Za-z0-9_-]{22}$/.test(String(payload.nonce || ''));
  } catch { return false; }
}

export async function middleware(request) {
  if (process.env.ARIX_EDGE_PROOF_REQUIRED !== 'true' || isExcluded(request.nextUrl.pathname)) return NextResponse.next();
  const secret = process.env.ARIX_MASTER_SECRET;
  if (typeof secret !== 'string' || new TextEncoder().encode(secret).byteLength < 32) {
    return new Response(JSON.stringify({ error: 'Edge origin proof is not configured.' }), { status: 503, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  }
  const cookieTicket = request.cookies.get('arix_edge_clearance')?.value;
  const headerTicket = request.headers.get('x-arix-edge-ticket');
  const accepted = await verifyTicket(headerTicket || cookieTicket || '', request, secret);
  if (!accepted) return new Response(JSON.stringify({ error: 'Edge clearance required.' }), { status: 403, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  const response = NextResponse.next();
  response.headers.set('x-arix-edge-verified', '1');
  return response;
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)'] };

import { getJson, setJson, setAdd, setRemoveMany, setMembers, deleteKeys } from './redis.js';
import { sha256Hex, randomToken } from './crypto-trap.js';
import { readCookie } from './http.js';

const IDLE_TTL_MS = 30 * 60 * 1000;
const ABSOLUTE_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_SECONDS = 24 * 60 * 60;

function clientHints(req) {
  const ip = String(process.env.VERCEL === '1' ? (req?.headers?.['x-real-ip'] || req?.headers?.['x-vercel-forwarded-for'] || '') : (req?.socket?.remoteAddress || '')).split(',')[0].trim();
  const ua = String(req?.headers?.['user-agent'] || '').slice(0, 256);
  return { ipHint: ip ? (ip.includes(':') ? ip.split(':').slice(0, 4).join(':') : ip.split('.').slice(0, 3).join('.')) : '', uaHint: ua ? ua.slice(0, 120) : '' };
}

export async function createSession(ownerId, projectId, req = null) {
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const hints = clientHints(req);
  const record = { ownerId, projectId, createdAt: now, lastActiveAt: now, ...hints };
  await Promise.all([
    setJson(`arix:session:${tokenHash}`, record, SESSION_TTL_SECONDS),
    setAdd(`arix:user-sessions:${ownerId}`, tokenHash, SESSION_TTL_SECONDS)
  ]);
  return { token, tokenHash, ttl: SESSION_TTL_SECONDS };
}

export async function getSession(req) {
  const secure = process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';
  const token = readCookie(req, secure ? '__Host-arix_session' : 'arix_session') || (secure ? null : readCookie(req, '__Host-arix_session'));
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256Hex(token);
  const key = `arix:session:${tokenHash}`;
  const session = await getJson(key);
  if (!session?.ownerId || !session?.projectId || !Number.isFinite(Number(session.createdAt))) return null;
  const now = Date.now();
  const lastActiveAt = Number(session.lastActiveAt || session.createdAt);
  if (now - lastActiveAt > IDLE_TTL_MS || now - Number(session.createdAt) > ABSOLUTE_TTL_MS) {
    await Promise.all([deleteKeys(key), setRemoveMany(`arix:user-sessions:${session.ownerId}`, [tokenHash])]);
    return null;
  }
  // Sliding idle window, bounded by the immutable 24-hour absolute deadline.
  const updated = { ...session, lastActiveAt: now };
  const remainingSeconds = Math.max(1, Math.ceil((Number(session.createdAt) + ABSOLUTE_TTL_MS - now) / 1000));
  await setJson(key, updated, Math.min(remainingSeconds, SESSION_TTL_SECONDS));
  await setAdd(`arix:user-sessions:${session.ownerId}`, tokenHash, remainingSeconds);
  return { ...updated, tokenHash };
}

export async function listUserSessions(ownerId) {
  if (typeof ownerId !== 'string' || !ownerId) return [];
  const key = `arix:user-sessions:${ownerId}`;
  const hashes = await setMembers(key);
  const rows = [];
  for (const hash of (Array.isArray(hashes) ? hashes.slice(0, 50) : [])) {
    const session = await getJson(`arix:session:${hash}`);
    if (!session || session.ownerId !== ownerId) { await setRemoveMany(key, [hash]); continue; }
    rows.push({ tokenHash: hash, createdAt: session.createdAt, lastActiveAt: session.lastActiveAt, ipHint: session.ipHint || '', uaHint: session.uaHint || '' });
  }
  return rows.sort((a, b) => Number(b.lastActiveAt) - Number(a.lastActiveAt));
}

export async function revokeUserSession(ownerId, tokenHash) {
  if (typeof ownerId !== 'string' || !ownerId || typeof tokenHash !== 'string' || !/^[a-f0-9]{64}$/i.test(tokenHash)) return false;
  const key = `arix:session:${tokenHash}`;
  const session = await getJson(key);
  if (!session || session.ownerId !== ownerId) return false;
  await Promise.all([deleteKeys(key), setRemoveMany(`arix:user-sessions:${ownerId}`, [tokenHash])]);
  return true;
}

export async function requireSession(req) {
  const session = await getSession(req);
  if (!session) return null;
  const [user, project] = await Promise.all([
    getJson(`arix:user:${session.ownerId}`),
    getJson(`arix:project:${session.projectId}`)
  ]);
  if (!user || !project || project.ownerId !== session.ownerId) return null;
  return { session, user, project };
}

export const SESSION_SECURITY_LIMITS = Object.freeze({ idleMs: IDLE_TTL_MS, absoluteMs: ABSOLUTE_TTL_MS });

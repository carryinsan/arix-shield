import { getJson, getString, setJson, setAdd, setRemoveMany, setMembers, deleteKeys } from './redis.js';
import { sha256Hex, randomToken } from './crypto-trap.js';
import { readCookie } from './http.js';

const IDLE_TTL_MS = 30 * 60 * 1000;
const ABSOLUTE_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_SECONDS = 24 * 60 * 60;
const SESSION_ROTATION_GRACE_MS = 15_000;
const MAX_FAMILY_SESSIONS = 2000;

function clientHints(req) {
  const ip = String(process.env.VERCEL === '1' ? (req?.headers?.['x-real-ip'] || req?.headers?.['x-vercel-forwarded-for'] || '') : (req?.socket?.remoteAddress || '')).split(',')[0].trim();
  const ua = String(req?.headers?.['user-agent'] || '').slice(0, 256);
  return { ipHint: ip ? (ip.includes(':') ? ip.split(':').slice(0, 4).join(':') : ip.split('.').slice(0, 3).join('.')) : '', uaHint: ua ? ua.slice(0, 120) : '' };
}

export async function createSession(ownerId, projectId, req = null, { familyId = null } = {}) {
  if (typeof ownerId !== 'string' || !ownerId || typeof projectId !== 'string' || !projectId) throw new TypeError('Session owner and project IDs are required.');
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const hints = clientHints(req);
  const family = typeof familyId === 'string' && /^[A-Za-z0-9_-]{16,96}$/.test(familyId) ? familyId : randomToken(18);
  const record = { ownerId, projectId, familyId: family, createdAt: now, lastActiveAt: now, ...hints };
  await Promise.all([
    setJson(`arix:session:${tokenHash}`, record, SESSION_TTL_SECONDS),
    setAdd(`arix:user-sessions:${ownerId}`, tokenHash, SESSION_TTL_SECONDS),
    setAdd(`arix:session-family:${family}`, tokenHash, SESSION_TTL_SECONDS)
  ]);
  return { token, tokenHash, familyId: family, ttl: SESSION_TTL_SECONDS };
}

/** Revoke every session indexed to a family after detecting replay of a rotated token. */
export async function revokeSessionFamily(familyId) {
  if (typeof familyId !== 'string' || !/^[A-Za-z0-9_-]{16,96}$/.test(familyId)) return 0;
  const familyKey = `arix:session-family:${familyId}`;
  const members = await setMembers(familyKey);
  const allMembers = Array.isArray(members) ? members : [];
  if (allMembers.length > MAX_FAMILY_SESSIONS) throw new Error('SESSION_FAMILY_LIMIT_EXCEEDED: family revocation requires operator review.');
  const hashes = allMembers.filter((value) => /^[a-f0-9]{64}$/i.test(String(value)));
  const records = await Promise.all(hashes.map((hash) => getJson(`arix:session:${hash}`)));
  const owners = new Map();
  const keys = [];
  for (let index = 0; index < hashes.length; index++) {
    keys.push(`arix:session:${hashes[index]}`);
    const ownerId = records[index]?.ownerId;
    if (typeof ownerId === 'string' && ownerId) {
      if (!owners.has(ownerId)) owners.set(ownerId, []);
      owners.get(ownerId).push(hashes[index]);
    }
  }
  await Promise.all([
    ...(keys.length ? [deleteKeys(...keys)] : []),
    ...[...owners].map(([ownerId, values]) => setRemoveMany(`arix:user-sessions:${ownerId}`, values)),
    deleteKeys(familyKey)
  ]);
  return hashes.length;
}

export async function getSession(req) {
  const secure = process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';
  const token = readCookie(req, secure ? '__Host-arix_session' : 'arix_session') || (secure ? null : readCookie(req, '__Host-arix_session'));
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256Hex(token);
  const spent = await getJson(`arix:session-spent:${tokenHash}`);
  if (spent?.familyId) {
    const spentAt = Number(spent.spentAt);
    // In-flight requests may still carry the just-rotated cookie. They are
    // rejected, but do not revoke the replacement family during a short grace
    // window. Reuse after the grace interval is treated as replay and revokes
    // the family. No spent token is ever accepted during this window.
    if (!Number.isFinite(spentAt) || Date.now() - spentAt > SESSION_ROTATION_GRACE_MS) {
      await revokeSessionFamily(spent.familyId);
    }
    return null;
  }
  const key = `arix:session:${tokenHash}`;
  const session = await getJson(key);
  if (!session?.ownerId || !session?.projectId || !Number.isFinite(Number(session.createdAt))) return null;
  const now = Date.now();
  const lastActiveAt = Number(session.lastActiveAt || session.createdAt);
  if (now - lastActiveAt > IDLE_TTL_MS || now - Number(session.createdAt) > ABSOLUTE_TTL_MS) {
    await revokeUserSession(session.ownerId, tokenHash);
    return null;
  }
  // Sliding idle window, bounded by the immutable 24-hour absolute deadline.
  const updated = { ...session, lastActiveAt: now };
  const remainingSeconds = Math.max(1, Math.ceil((Number(session.createdAt) + ABSOLUTE_TTL_MS - now) / 1000));
  await Promise.all([
    setJson(key, updated, Math.min(remainingSeconds, SESSION_TTL_SECONDS)),
    setAdd(`arix:user-sessions:${session.ownerId}`, tokenHash, remainingSeconds),
    ...(session.familyId ? [setAdd(`arix:session-family:${session.familyId}`, tokenHash, remainingSeconds)] : [])
  ]);
  return { ...updated, tokenHash };
}

export async function listUserSessions(ownerId) {
  if (typeof ownerId !== 'string' || !ownerId) return [];
  const key = `arix:user-sessions:${ownerId}`;
  const hashes = await setMembers(key);
  const rows = [];
  for (const hash of (Array.isArray(hashes) ? hashes.slice(0, 200) : [])) {
    const session = await getJson(`arix:session:${hash}`);
    if (!session || session.ownerId !== ownerId) { await setRemoveMany(key, [hash]); continue; }
    rows.push({ tokenHash: hash, familyId: session.familyId || null, createdAt: session.createdAt, lastActiveAt: session.lastActiveAt, ipHint: session.ipHint || '', uaHint: session.uaHint || '' });
  }
  return rows.sort((a, b) => Number(b.lastActiveAt) - Number(a.lastActiveAt));
}

export async function revokeUserSession(ownerId, tokenHash) {
  if (typeof ownerId !== 'string' || !ownerId || typeof tokenHash !== 'string' || !/^[a-f0-9]{64}$/i.test(tokenHash)) return false;
  const key = `arix:session:${tokenHash}`;
  const session = await getJson(key);
  if (!session || session.ownerId !== ownerId) return false;
  await Promise.all([
    deleteKeys(key),
    setRemoveMany(`arix:user-sessions:${ownerId}`, [tokenHash]),
    ...(session.familyId ? [setRemoveMany(`arix:session-family:${session.familyId}`, [tokenHash])] : [])
  ]);
  return true;
}

async function indexedUserSessionRecords(ownerId) {
  const key = `arix:user-sessions:${ownerId}`;
  const members = await setMembers(key);
  const all = Array.isArray(members) ? members : [];
  if (all.length > MAX_FAMILY_SESSIONS) throw new Error('USER_SESSION_LIMIT_EXCEEDED: bulk revocation requires operator review.');
  const hashes = all.filter((value) => /^[a-f0-9]{64}$/i.test(String(value)));
  const records = await Promise.all(hashes.map((hash) => getJson(`arix:session:${hash}`)));
  return hashes.flatMap((tokenHash, index) => records[index]?.ownerId === ownerId ? [{ tokenHash, session: records[index] }] : []);
}

async function revokeRecords(ownerId, records, { preserveHash = null, deleteUserIndex = false } = {}) {
  const selected = records.filter((item) => item.tokenHash !== preserveHash);
  const familyMembers = new Map();
  for (const item of selected) {
    const familyId = item.session.familyId;
    if (!familyId) continue;
    if (!familyMembers.has(familyId)) familyMembers.set(familyId, []);
    familyMembers.get(familyId).push(item.tokenHash);
  }
  await Promise.all([
    ...(selected.length ? [deleteKeys(...selected.map((item) => `arix:session:${item.tokenHash}`))] : []),
    ...[...familyMembers].map(([familyId, hashes]) => setRemoveMany(`arix:session-family:${familyId}`, hashes)),
    ...(deleteUserIndex ? [deleteKeys(`arix:user-sessions:${ownerId}`)] : [setRemoveMany(`arix:user-sessions:${ownerId}`, selected.map((item) => item.tokenHash))])
  ]);
  return selected.length;
}

export async function revokeAllUserSessions(ownerId) {
  if (typeof ownerId !== 'string' || !ownerId) return 0;
  const records = await indexedUserSessionRecords(ownerId);
  return revokeRecords(ownerId, records, { deleteUserIndex: true });
}

export async function revokeUserSessionsExcept(ownerId, preserveHash) {
  if (typeof ownerId !== 'string' || !ownerId || typeof preserveHash !== 'string' || !/^[a-f0-9]{64}$/i.test(preserveHash)) return 0;
  const records = await indexedUserSessionRecords(ownerId);
  return revokeRecords(ownerId, records, { preserveHash });
}

/**
 * Rotate a live session while preserving its family. The spent-token marker is
 * written with Redis SET NX before the old record is removed. Reuse of that old
 * cookie revokes the entire family, including the replacement session.
 */
export async function rotateSession(ownerId, projectId, oldTokenHash, req = null) {
  if (typeof oldTokenHash !== 'string' || !/^[a-f0-9]{64}$/i.test(oldTokenHash)) return null;
  const old = await getJson(`arix:session:${oldTokenHash}`);
  if (!old || old.ownerId !== ownerId || old.projectId !== projectId) return null;
  const familyId = old.familyId || randomToken(18);
  const fresh = await createSession(ownerId, projectId, req, { familyId });
  const marked = await setJson(`arix:session-spent:${oldTokenHash}`, { familyId, ownerId, spentAt: Date.now() }, SESSION_TTL_SECONDS, true);
  if (marked !== 'OK') {
    // Another concurrent request already rotated this exact token. Retire only
    // this losing replacement; do not revoke the family containing the winner.
    await revokeUserSession(ownerId, fresh.tokenHash).catch(() => {});
    return null;
  }
  await revokeUserSession(ownerId, oldTokenHash);
  // Rotation is family-scoped. Other device families remain active.
  return fresh;
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

export const SESSION_SECURITY_LIMITS = Object.freeze({ idleMs: IDLE_TTL_MS, absoluteMs: ABSOLUTE_TTL_MS, familyMaxSessions: MAX_FAMILY_SESSIONS });

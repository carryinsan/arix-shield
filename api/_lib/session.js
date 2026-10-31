import { getJson, setJson } from './redis.js';
import { sha256Hex, randomToken } from './crypto-trap.js';
import { readCookie } from './http.js';

const SESSION_TTL = Math.max(3600, Math.min(2592000, Number(process.env.ARIX_SESSION_TTL_SECONDS) || 604800));

export async function createSession(ownerId, projectId) {
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  await setJson(`arix:session:${tokenHash}`, { ownerId, projectId, createdAt: Date.now() }, SESSION_TTL);
  return { token, ttl: SESSION_TTL };
}

export async function getSession(req) {
  const secure = process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';
  const token = readCookie(req, secure ? '__Host-arix_session' : 'arix_session') || (secure ? null : readCookie(req, '__Host-arix_session'));
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256Hex(token);
  const session = await getJson(`arix:session:${tokenHash}`);
  if (!session?.ownerId || !session?.projectId) return null;
  return { ...session, tokenHash };
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

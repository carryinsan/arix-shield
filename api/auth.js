import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, readJson, methodNotAllowed, setSessionCookie, clearSessionCookie, sameOriginRequest, normalizeOrigin, clientRateKey } from './_lib/http.js';
import { rateLimit, getJson, setJson, setString, deleteKeys } from './_lib/redis.js';
import { derivePassword, verifyPassword, randomToken, sha256Hex, hashCredential } from './_lib/crypto-trap.js';
import { createSession, getSession } from './_lib/session.js';

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const SESSION_TTL = Math.max(3600, Math.min(2592000, Number(process.env.ARIX_SESSION_TTL_SECONDS) || 604800));
const DUMMY_PASSWORD = Object.freeze({ salt: 'MDEyMzQ1Njc4OWFiY2RlZg', hash: 'm5zv3v3aA0-2p-2D8uZpT_Es4q4QO1Jr5FS3YxTzTYA', iterations: 240000 });

function isSecure(req) { return process.env.VERCEL === '1' || process.env.NODE_ENV === 'production' || String(req.headers?.['x-forwarded-proto'] ?? '').split(',')[0] === 'https'; }
function validName(value) { return typeof value === 'string' && value.trim().length >= 2 && value.trim().length <= 80; }

async function provisionAccount(body, req, res) {
  const email = String(body.email ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');
  const name = String(body.name ?? '').trim();
  const projectName = String(body.projectName ?? 'My Project').trim();
  const origin = normalizeOrigin(body.origin);
  if (!EMAIL_RE.test(email) || email.length > 254) return sendJson(res, 400, { error: 'Enter a valid email address.' });
  if (password.length < 12 || password.length > 128) return sendJson(res, 400, { error: 'Password must be 12–128 characters.' });
  if (!validName(name) || !validName(projectName) || !origin) return sendJson(res, 400, { error: 'Provide your name, a project name and an HTTPS site origin (localhost is allowed for development).' });

  const emailHash = await sha256Hex(email);
  const ownerId = `usr_${randomToken(12)}`;
  const projectId = `prj_${randomToken(9)}`;
  const emailIndex = `arix:user-email:${emailHash}`;
  const indexResult = await setString(emailIndex, ownerId, null, true);
  if (indexResult !== 'OK') return sendJson(res, 409, { error: 'An account with this email already exists. Sign in instead.' });

  try {
    const passwordRecord = await derivePassword(password);
    const liveKey = `ARIX_LIVE_${randomToken(18)}`;
    const serverKey = `ARIX_SECRET_${randomToken(32)}`;
    const canaryKey = `ARIX_CANARY_${randomToken(18)}`;
    const [liveHash, serverHash, canaryHash] = await Promise.all([
      hashCredential(liveKey), hashCredential(serverKey), hashCredential(canaryKey)
    ]);
    const now = new Date().toISOString();
    const user = { id: ownerId, name, email, password: passwordRecord, createdAt: now };
    const project = {
      id: projectId,
      ownerId,
      name: projectName,
      origin,
      allowedOrigins: [origin],
      liveKeyHash: liveHash,
      serverKeyHash: serverHash,
      canaryKeyHash: canaryHash,
      policy: { mode: 'ENFORCE', rateLimitPerMinute: 120, blockDatacenterAsn: false, canaryRowsEnabled: false, deceptionEnabled: true },
      createdAt: now
    };
    await Promise.all([
      setJson(`arix:user:${ownerId}`, user),
      setJson(`arix:project:${projectId}`, project),
      setString(`arix:owner-project:${ownerId}`, projectId),
      setJson(`arix:key:${liveHash}`, { projectId, type: 'live', createdAt: Date.now() }),
      setJson(`arix:key:${serverHash}`, { projectId, type: 'server', createdAt: Date.now() }),
      setJson(`arix:key:${canaryHash}`, { projectId, type: 'canary', createdAt: Date.now() })
    ]);
    const session = await createSession(ownerId, projectId);
    setSessionCookie(res, session.token, session.ttl, isSecure(req));
    return sendJson(res, 201, {
      ok: true,
      user: { id: ownerId, name, email },
      project: { id: projectId, name: projectName, origin },
      keys: { liveKey, serverKey, canaryKey },
      keyNotice: 'ARIX_LIVE is a publishable project identifier. Store ARIX_SECRET only in server-side environment variables. These credentials are shown once.'
    });
  } catch (error) {
    await deleteKeys(emailIndex);
    throw error;
  }
}

async function loginAccount(body, req, res) {
  const email = String(body.email ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');
  if (!EMAIL_RE.test(email) || password.length > 128 || password.length === 0) return sendJson(res, 401, { error: 'Email or password is incorrect.' });
  const emailHash = await sha256Hex(email);
  const ownerId = await import('./_lib/redis.js').then(({ getString }) => getString(`arix:user-email:${emailHash}`));
  const user = ownerId ? await getJson(`arix:user:${ownerId}`) : null;
  const passwordRecord = user?.password ?? DUMMY_PASSWORD;
  const valid = await verifyPassword(password, passwordRecord);
  if (!user || !valid) return sendJson(res, 401, { error: 'Email or password is incorrect.' });
  const projectId = await findOwnedProject(ownerId);
  if (!projectId) return sendJson(res, 403, { error: 'This account has no active project.' });
  const session = await createSession(ownerId, projectId);
  setSessionCookie(res, session.token, session.ttl, isSecure(req));
  return sendJson(res, 200, { ok: true, user: { id: user.id, name: user.name, email: user.email }, project: { id: projectId } });
}

async function findOwnedProject(ownerId) {
  // Project IDs are stored in a small owner index when provisioned; avoid global Redis key scans.
  return (await import('./_lib/redis.js').then(({ getString }) => getString(`arix:owner-project:${ownerId}`))) || null;
}

async function handler(req, res) {
  if (req.method === 'GET') {
    try {
      const session = await getSession(req);
      if (!session) return sendJson(res, 200, { authenticated: false });
      const user = await getJson(`arix:user:${session.ownerId}`);
      const project = await getJson(`arix:project:${session.projectId}`);
      if (!user || !project) return sendJson(res, 200, { authenticated: false });
      return sendJson(res, 200, { authenticated: true, user: { id: user.id, name: user.name, email: user.email }, project: { id: project.id, name: project.name, origin: project.origin } });
    } catch (error) {
      console.error('[ArixShield] /api/auth session lookup failed:', error?.stack || error);
      return sendJson(res, 503, { error: 'Account service unavailable. Check Upstash Redis configuration and function logs.' });
    }
  }
  if (req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  if (!sameOriginRequest(req)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });
  try {
    const limit = await rateLimit({ key: `arix:auth:limit:${await sha256Hex(clientRateKey(req))}`, algorithm: 'SLIDING_WINDOW', limit: 8, windowMs: 60000 });
    if (!limit.allowed) return sendJson(res, 429, { error: 'Too many account requests. Try again shortly.' }, { 'Retry-After': String(Math.ceil(limit.retryAfterMs / 1000)) });
    const body = await readJson(req, 12000);
    if (body.action === 'signup') return await provisionAccount(body, req, res);
    if (body.action === 'login') return await loginAccount(body, req, res);
    if (body.action === 'logout') {
      const session = await getSession(req);
      if (session) await deleteKeys(`arix:session:${session.tokenHash}`);
      clearSessionCookie(res, isSecure(req));
      return sendJson(res, 200, { ok: true });
    }
    return sendJson(res, 400, { error: 'Unknown account action.' });
  } catch (error) {
    console.error('[ArixShield] /api/auth request failed:', error?.stack || error);
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, { error: status === 503 ? 'Account service temporarily unavailable. Verify Upstash REST URL/token and inspect Vercel Function logs.' : error.message });
  }
}

export default createCompatibleHandler(handler);

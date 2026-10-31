import { command, getJSON, setJSON, rateLimit, assertProductionStore } from './_lib/redis.js';
import { randomId, randomBytes, derivePassword, constantTimeEqual, issueApiKey, hashIdentifier, assertMasterSecret } from './_lib/crypto-trap.js';
import { readJson, jsonResponse, errorResponse, getClientIp, sameOriginRequest, normalizeOrigin, safeString } from './_lib/http.js';
import { createSession, getSession, destroySession, sessionCookie } from './_lib/session.js';

const DEFAULT_POLICY = Object.freeze({
  mode: 'DRY_RUN',
  rateLimitRPM: 120,
  rateAlgorithm: 'SLIDING_WINDOW',
  blockDatacenter: false,
  backendDnaLock: true,
  tarpitEnabled: true,
  canaryRows: false,
  redactSecrets: true,
  redactEmails: false,
  blockBots: false,
  allowedOrigins: []
});

function isValidEmail(value) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}

async function makeKeys(projectId) {
  const liveKey = await issueApiKey('LIVE', projectId);
  const serverKey = await issueApiKey('SERVER', projectId);
  const canaryKey = await issueApiKey('CANARY', projectId);
  const liveHash = await hashIdentifier(liveKey);
  const serverHash = await hashIdentifier(serverKey);
  const canaryHash = await hashIdentifier(canaryKey);
  await Promise.all([
    setJSON(`arix:key:${liveHash}`, { projectId, kind: 'LIVE', createdAt: new Date().toISOString() }),
    setJSON(`arix:key:${serverHash}`, { projectId, kind: 'SERVER', createdAt: new Date().toISOString() }),
    setJSON(`arix:key:${canaryHash}`, { projectId, kind: 'CANARY', createdAt: new Date().toISOString() })
  ]);
  return { liveKey, serverKey, canaryKey, liveHash, serverHash, canaryHash };
}

async function createAccount(body, req) {
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const projectName = safeString(body.projectName || 'My first project', 80).trim() || 'My first project';
  if (!isValidEmail(email)) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
  if (password.length < 12 || password.length > 128) throw Object.assign(new Error('Use a password between 12 and 128 characters.'), { status: 400 });
  const origin = normalizeOrigin(body.allowedOrigin);
  const ipHash = await hashIdentifier(getClientIp(req));
  const registrationLimit = await rateLimit({ key: `arix:rl:signup:${ipHash}`, limit: 3, windowMs: 3600000 });
  if (!registrationLimit.allowed) throw Object.assign(new Error('Registration limit reached. Try again later.'), { status: 429 });
  const emailHash = await hashIdentifier(`email:${email}`);
  const accountId = `acc_${randomId(12)}`;
  const reserved = await command('SET', `arix:account:email:${emailHash}`, accountId, 'NX', 'EX', 31536000);
  if (reserved !== 'OK') throw Object.assign(new Error('An account with this email already exists. Sign in instead.'), { status: 409 });

  try {
    const salt = randomBytes(16);
    const passwordHash = await derivePassword(password, salt);
    const projectId = randomId(9);
    const keys = await makeKeys(projectId);
    const project = {
      id: projectId,
      ownerId: accountId,
      name: projectName,
      createdAt: new Date().toISOString(),
      keyVersion: 1,
      allowedOrigins: [origin],
      liveKeyHash: keys.liveHash,
      serverKeyHash: keys.serverHash,
      canaryKeyHash: keys.canaryHash,
      policy: { ...DEFAULT_POLICY, allowedOrigins: [origin] }
    };
    const account = { id: accountId, email, passwordHash, salt: Array.from(salt), createdAt: new Date().toISOString(), projectId };
    await Promise.all([
      setJSON(`arix:account:id:${accountId}`, account),
      setJSON(`arix:project:${projectId}`, project),
      setJSON(`arix:metrics:${projectId}`, { totalRequests: 0, blockedAttacks: 0, trappedHackers: 0, tarpitMsServed: 0, activeVisitorCount: 0 })
    ]);
    const token = await createSession(accountId);
    return {
      status: 201,
      body: {
        ok: true,
        user: { id: accountId, email },
        project: { id: projectId, name: projectName, allowedOrigins: [origin] },
        keys: { liveKey: keys.liveKey, serverKey: keys.serverKey, canaryKey: keys.canaryKey, shownOnce: true },
        policy: project.policy
      },
      cookie: sessionCookie(req, token)
    };
  } catch (error) {
    await command('DEL', `arix:account:email:${emailHash}`);
    throw error;
  }
}

async function login(body, req) {
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!isValidEmail(email) || password.length > 128) throw Object.assign(new Error('Invalid email or password.'), { status: 400 });
  const ipHash = await hashIdentifier(getClientIp(req));
  const emailHash = await hashIdentifier(`email:${email}`);
  const limits = await Promise.all([
    rateLimit({ key: `arix:rl:login:ip:${ipHash}`, limit: 10, windowMs: 900000 }),
    rateLimit({ key: `arix:rl:login:email:${emailHash}`, limit: 8, windowMs: 900000 })
  ]);
  if (limits.some((item) => !item.allowed)) throw Object.assign(new Error('Too many login attempts. Try again later.'), { status: 429 });
  const accountId = await command('GET', `arix:account:email:${emailHash}`);
  const account = accountId ? await getJSON(`arix:account:id:${accountId}`) : null;
  if (!account?.salt || !account?.passwordHash) throw Object.assign(new Error('Invalid email or password.'), { status: 401 });
  const supplied = await derivePassword(password, new Uint8Array(account.salt));
  if (!constantTimeEqual(supplied, account.passwordHash)) throw Object.assign(new Error('Invalid email or password.'), { status: 401 });
  const project = await getJSON(`arix:project:${account.projectId}`);
  if (!project) throw Object.assign(new Error('Project is unavailable. Contact support.'), { status: 503 });
  const token = await createSession(account.id);
  return {
    status: 200,
    body: { ok: true, user: { id: account.id, email: account.email }, project: { id: project.id, name: project.name, allowedOrigins: project.allowedOrigins || [] }, policy: project.policy },
    cookie: sessionCookie(req, token)
  };
}

async function rotateKeys(req) {
  const session = await getSession(req);
  if (!session) throw Object.assign(new Error('Authentication required.'), { status: 401 });
  const project = await getJSON(`arix:project:${session.account.projectId}`);
  if (!project || project.ownerId !== session.account.id) throw Object.assign(new Error('Project not found.'), { status: 404 });
  const keys = await makeKeys(project.id);
  if (project.liveKeyHash) await command('DEL', `arix:key:${project.liveKeyHash}`);
  if (project.serverKeyHash) await command('DEL', `arix:key:${project.serverKeyHash}`);
  if (project.canaryKeyHash) await command('DEL', `arix:key:${project.canaryKeyHash}`);
  project.liveKeyHash = keys.liveHash;
  project.serverKeyHash = keys.serverHash;
  project.canaryKeyHash = keys.canaryHash;
  project.keyVersion = Number(project.keyVersion || 1) + 1;
  project.rotatedAt = new Date().toISOString();
  await command('DEL', `arix:dna:${project.id}`);
  await setJSON(`arix:project:${project.id}`, project);
  return {
    status: 200,
    body: { ok: true, keys: { liveKey: keys.liveKey, serverKey: keys.serverKey, canaryKey: keys.canaryKey, shownOnce: true } }
  };
}

export default async function handler(req) {
  try {
    assertProductionStore();
    assertMasterSecret();
    if (req.method !== 'POST') return jsonResponse(req, { error: 'Method not allowed.' }, 405, { Allow: 'POST' });
    if (!sameOriginRequest(req)) return jsonResponse(req, { error: 'Cross-origin control-plane request rejected.' }, 403);
    const body = await readJson(req, 16384);
    const action = String(body.action || 'login').toLowerCase();
    let result;
    if (action === 'register') result = await createAccount(body, req);
    else if (action === 'login') result = await login(body, req);
    else if (action === 'logout') {
      const session = await getSession(req);
      await destroySession(session);
      result = { status: 200, body: { ok: true, loggedOut: true }, cookie: sessionCookie(req, '', true) };
    } else if (action === 'rotate_keys') result = await rotateKeys(req);
    else return jsonResponse(req, { error: 'Unsupported action.' }, 400);
    const headers = result.cookie ? { 'Set-Cookie': result.cookie } : {};
    return jsonResponse(req, result.body, result.status || 200, headers);
  } catch (error) {
    return errorResponse(req, error, 'Authentication service is temporarily unavailable.');
  }
}

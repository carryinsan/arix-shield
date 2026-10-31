import { sendJson, readJson, methodNotAllowed, getNetworkHints, clientRateKey } from './_lib/http.js';
import { rateLimit, getJson, setJson, setString, recordProjectEvent } from './_lib/redis.js';
import { sha256Hex, hashCredential, verifyDpopProof, trapMirage, createSignedToken, verifySignedToken, randomToken, sha256, hmacSha256, getMasterSecret, base64urlEncode, base64urlDecode, constantTimeEqual } from './_lib/crypto-trap.js';
import { inspectRequest } from './_lib/waf-engine.js';
import { embedInvisibleWatermark, decodeInvisibleWatermark } from './_lib/watermark.js';

const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);
const DEMO_ID = 'public-demo';
const DEMO_WINDOW_MS = 60000;
const DEMO_MAX_REQUESTS = 8;
const DEMO_ZERO = '\u200B';
const DEMO_ONE = '\u200C';
const DEMO_START = '\u200D\u200D';
const DEMO_END = '\u200D\u200D\u200D';
const demoRequestBuckets = new Map();
const demoWatermarks = new Map();

// The public showcase has a best-effort per-instance limiter. Customer protection
// and account endpoints still use shared Redis and remain fail-closed.
function allowDemoRequest(req) {
  const key = clientRateKey(req).slice(0, 256);
  const now = Date.now();
  const recent = (demoRequestBuckets.get(key) || []).filter((time) => time > now - DEMO_WINDOW_MS);
  if (recent.length >= DEMO_MAX_REQUESTS) {
    demoRequestBuckets.set(key, recent);
    return false;
  }
  recent.push(now);
  demoRequestBuckets.set(key, recent);
  if (demoRequestBuckets.size > 5000) {
    for (const [candidate, times] of demoRequestBuckets) {
      if (!times.length || times[times.length - 1] <= now - DEMO_WINDOW_MS) demoRequestBuckets.delete(candidate);
      if (demoRequestBuckets.size <= 4000) break;
    }
  }
  return true;
}

async function recordDemoEvent(event, options = {}) {
  try {
    await recordProjectEvent(DEMO_ID, event, options);
    return true;
  } catch (error) {
    console.warn('[ArixShield] Demo event was not persisted:', String(error?.message || error).slice(0, 180));
    return false;
  }
}

function encodeDemoWatermark(bytes) {
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  return DEMO_START + bits.replaceAll('0', DEMO_ZERO).replaceAll('1', DEMO_ONE) + DEMO_END;
}

async function createEphemeralDemoWatermark(text, context) {
  const id = randomToken(9);
  const signature = (await hmacSha256(getMasterSecret(), `${DEMO_ID}:${id}`)).slice(0, 12);
  const bytes = new Uint8Array(21);
  bytes.set(base64urlDecode(id), 0);
  bytes.set(signature, 9);
  const marker = encodeDemoWatermark(bytes);
  demoWatermarks.set(id, {
    record: {
      projectId: DEMO_ID,
      sessionId: String(context.sessionId).slice(0, 100),
      userId: String(context.userId || 'demo_user').slice(0, 100),
      ip: String(context.ip || 'unavailable').slice(0, 64),
      timestamp: new Date().toISOString(),
      attributionId: id
    },
    expiresAt: Date.now() + 15 * 60 * 1000
  });
  return text.length > 1 ? `${text[0]}${marker}${text.slice(1)}` : `${text}${marker}`;
}

async function decodeEphemeralDemoWatermark(text) {
  const start = text.indexOf(DEMO_START);
  if (start < 0) return { found: false, reason: 'NO_VALID_WATERMARK' };
  const from = start + DEMO_START.length;
  const end = text.indexOf(DEMO_END, from);
  if (end < 0) return { found: false, reason: 'INVALID_WATERMARK' };
  const encoded = text.slice(from, end);
  if (encoded.length !== 168 || /[^\u200B\u200C]/.test(encoded)) return { found: false, reason: 'INVALID_WATERMARK' };
  const bits = encoded.replaceAll(DEMO_ZERO, '0').replaceAll(DEMO_ONE, '1');
  const bytes = new Uint8Array(21);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const id = base64urlEncode(bytes.slice(0, 9));
  const expected = (await hmacSha256(getMasterSecret(), `${DEMO_ID}:${id}`)).slice(0, 12);
  if (!constantTimeEqual(expected, bytes.slice(9))) return { found: false, reason: 'SIGNATURE_MISMATCH' };
  const stored = demoWatermarks.get(id);
  if (!stored || stored.expiresAt <= Date.now()) {
    demoWatermarks.delete(id);
    return { found: true, attributed: false, attributionId: id, reason: 'EPHEMERAL_DEMO_RECORD_EXPIRED' };
  }
  return { found: true, attributed: true, ...stored.record, persistence: 'same-instance demo memory' };
}

function responseCors(req, res, allowOrigin = '*') {
  res.setHeader('Access-Control-Allow-Origin', allowOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Arix-Key, X-Arix-PoP, X-Arix-JWK, X-Arix-Server-Key');
  res.setHeader('Access-Control-Max-Age', '600');
  res.setHeader('Vary', 'Origin');
}

function requestUrl(req) {
  const host = String(req.headers?.host ?? 'localhost').replace(/[\r\n]/g, '');
  const proto = String(req.headers?.['x-forwarded-proto'] ?? 'https').split(',')[0].trim() === 'http' ? 'http' : 'https';
  return `${proto}://${host}${req.url || '/api/shield'}`;
}

function isProjectOriginAllowed(project, origin) {
  if (!origin || typeof origin !== 'string') return false;
  return Array.isArray(project.allowedOrigins) && project.allowedOrigins.includes(origin);
}

async function issuePowChallenge(projectId) {
  return createSignedToken({ projectId, nonce: randomToken(16), exp: Date.now() + 120000, difficulty: 12 }, 'browser-pow');
}

async function validatePow(projectId, token, solution) {
  if (typeof solution !== 'string' || solution.length > 16 || !/^\d{1,12}$/.test(solution)) return false;
  const payload = await verifySignedToken(token, 'browser-pow');
  if (!payload || payload.projectId !== projectId || payload.exp < Date.now()) return false;
  const digest = await sha256(`${payload.nonce}:${solution}`);
  return digest[0] === 0 && (digest[1] & 0xf0) === 0;
}

async function handleDemo(body, req, res) {
  if (String(process.env.ARIX_DEMO_ENABLED ?? 'true').toLowerCase() === 'false') return sendJson(res, 404, { error: 'Public demo is disabled.' });
  if (!allowDemoRequest(req)) return sendJson(res, 429, { error: 'Demo rate limit reached. Try again in a minute.' });
  const scenario = String(body.scenario ?? 'legitimate');
  const timestamp = new Date().toISOString();
  if (scenario === 'legitimate') {
    const inspection = inspectRequest({ method: 'GET', url: '/api/catalog/items', headers: { accept: 'application/json' }, body: null });
    const telemetryPersisted = await recordDemoEvent({ type: 'DEMO_ALLOWED', blocked: false, timestamp, path: '/api/catalog/items', riskScore: inspection.riskScore });
    return sendJson(res, 200, { ok: true, httpStatus: 200, result: 'ALLOWED', message: 'Request passed the same request-inspection engine used by the protection endpoint.', telemetryPersisted, inspection });
  }
  if (scenario === 'sqli') {
    const inspection = inspectRequest({ method: 'GET', url: "/api/products?id=1' OR 1=1 --", headers: { accept: 'application/json' } });
    const blocked = inspection.findings.length > 0;
    const telemetryPersisted = await recordDemoEvent({ type: 'DEMO_SQLI', blocked, timestamp, path: '/api/products', findings: inspection.findings, riskScore: inspection.riskScore }, { threat: true });
    return sendJson(res, 200, { ok: true, httpStatus: blocked ? 403 : 200, result: blocked ? 'BLOCKED' : 'ALLOWED', message: blocked ? 'The lexical WAF detected suspicious SQL syntax.' : 'No rule matched.', telemetryPersisted, inspection });
  }
  if (scenario === 'replay') {
    const mirage = await trapMirage(DEMO_ID, '/api/v1/accounts', 'DEMO_STOLEN_KEY_REPLAY');
    const telemetryPersisted = await recordDemoEvent({ type: 'TRAPPED_HACKER', blocked: true, timestamp, ip: getNetworkHints(req).ip, path: '/api/v1/accounts', reason: 'DEMO_STOLEN_KEY_REPLAY', mirage: mirage.data }, { threat: true });
    return sendJson(res, 200, { ok: true, httpStatus: 200, result: 'PHANTOM_SANDBOX', message: 'The demo replay path returned deterministic synthetic data and recorded a trap event.', telemetryPersisted, payload: mirage });
  }
  if (scenario === 'watermark') {
    const sessionId = `demo_${randomToken(8)}`;
    const original = 'Quarterly customer export for demonstration';
    let marked;
    let decoded;
    let persistence = 'Upstash Redis';
    try {
      marked = await embedInvisibleWatermark(original, { projectId: DEMO_ID, sessionId, userId: 'demo_user', ip: getNetworkHints(req).ip });
      decoded = await decodeInvisibleWatermark(marked, DEMO_ID);
    } catch (error) {
      marked = await createEphemeralDemoWatermark(original, { sessionId, userId: 'demo_user', ip: getNetworkHints(req).ip });
      decoded = await decodeEphemeralDemoWatermark(marked);
      persistence = 'ephemeral demo memory';
      console.warn('[ArixShield] Demo watermark used ephemeral storage:', String(error?.message || error).slice(0, 180));
    }
    const telemetryPersisted = await recordDemoEvent({ type: 'DEMO_WATERMARK', blocked: false, timestamp, path: '/demo/watermark', attributionId: decoded.attributionId || null });
    return sendJson(res, 200, { ok: true, httpStatus: 200, result: 'ATTRIBUTED', message: 'A signed invisible marker was embedded and resolved against an attribution record.', persistence, telemetryPersisted, preview: original, markedText: marked, decoded });
  }
  return sendJson(res, 400, { error: 'Unknown demo scenario.' });
}

async function resolveProjectFromApiKey(apiKey) {
  if (typeof apiKey !== 'string' || apiKey.length < 20 || apiKey.length > 160) return null;
  const hash = await hashCredential(apiKey);
  const mapping = await getJson(`arix:key:${hash}`);
  return mapping ? { mapping, hash } : null;
}

async function browserVisit(body, req, res, mapping, project, inspection) {
  const origin = req.headers?.origin;
  if (!isProjectOriginAllowed(project, origin)) {
    const hints = getNetworkHints(req);
    await recordProjectEvent(project.id, { type: 'TRAPPED_HACKER', blocked: true, reason: 'ORIGIN_MISMATCH', timestamp: new Date().toISOString(), ip: hints.ip, country: hints.country, asn: hints.asn, ja3: hints.ja3, ja4: hints.ja4, path: String(req.url).slice(0, 160) }, { threat: true });
    if (project.policy?.deceptionEnabled === false) return sendJson(res, 403, { error: 'Browser origin is not registered for this project.' });
    const mirage = await trapMirage(project.id, req.url || '/', 'ORIGIN_MISMATCH');
    return sendJson(res, 200, { ...mirage, arix: { mode: 'PHANTOM_SANDBOX' } });
  }

  const proof = req.headers?.['x-arix-pop'];
  const proofResult = await verifyDpopProof({ proof, method: req.method, url: requestUrl(req), projectId: project.id, redisGetSet: setString });
  if (!proofResult.valid) {
    if (project.policy?.deceptionEnabled === false) return sendJson(res, 401, { error: 'Browser proof-of-possession failed.' });
    const mirage = await trapMirage(project.id, req.url || '/', proofResult.reason || 'DPOP_FAILED');
    const hints = getNetworkHints(req);
    await recordProjectEvent(project.id, { type: 'TRAPPED_HACKER', blocked: true, reason: proofResult.reason, timestamp: new Date().toISOString(), ip: hints.ip, country: hints.country, asn: hints.asn, ja3: hints.ja3, ja4: hints.ja4, path: String(req.url).slice(0, 160), mirage: mirage.data }, { threat: true });
    return sendJson(res, 200, { ...mirage, arix: { mode: 'PHANTOM_SANDBOX', event: 'TRAPPED_HACKER' } });
  }

  const key = `arix:limit:${project.id}:${proofResult.thumbprint}`;
  const limit = await rateLimit({ key, algorithm: 'TOKEN_BUCKET', limit: project.policy?.rateLimitPerMinute ?? 120, windowMs: 60000 });
  if (!limit.allowed) return sendJson(res, 429, { error: 'Project visitor telemetry rate limit exceeded.' }, { 'Retry-After': String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))) });

  const pathForPolicy = String(body.path ?? req.url ?? '/');
  const asnForPolicy = String(req.headers?.['x-vercel-ip-as-number'] ?? '');
  const humanOnly = /\/(?:login|signup|checkout)(?:\/|\?|$)/i.test(pathForPolicy);
  const dcBlocked = Boolean(project.policy?.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(asnForPolicy));
  if ((inspection?.findings?.length || dcBlocked) && project.policy?.mode !== 'DRY_RUN') {
    const hints = getNetworkHints(req);
    await recordProjectEvent(project.id, { type: dcBlocked ? 'DATACENTER_ASN_BLOCK' : 'WAF_BLOCK', blocked: true, timestamp: new Date().toISOString(), path: pathForPolicy.slice(0, 180), ip: hints.ip, country: hints.country, asn: hints.asn, findings: inspection?.findings ?? [], riskScore: dcBlocked ? 90 : inspection?.riskScore ?? 0 }, { threat: true });
    return sendJson(res, 403, { error: 'Request blocked by ArixShield policy.', findings: inspection?.findings ?? [], riskScore: inspection?.riskScore ?? 0 });
  }
  if (inspection?.findings?.length || dcBlocked) {
    const hints = getNetworkHints(req);
    await recordProjectEvent(project.id, { type: 'WAF_OBSERVED', blocked: false, timestamp: new Date().toISOString(), path: pathForPolicy.slice(0, 180), ip: hints.ip, asn: hints.asn, findings: inspection?.findings ?? [], riskScore: inspection?.riskScore ?? 0 }, { threat: true });
  }

  if (!body.powToken || !(await validatePow(project.id, body.powToken, String(body.powSolution ?? '')))) {
    const challenge = await issuePowChallenge(project.id);
    return sendJson(res, 200, { ok: true, challenge, pow: { difficulty: 12, expiresInSeconds: 120 } });
  }

  const hints = getNetworkHints(req);
  const botSignals = body.signals && typeof body.signals === 'object' ? body.signals : {};
  const suspicious = botSignals.webdriver === true || botSignals.headless === true;
  const path = typeof body.path === 'string' ? body.path.slice(0, 180) : '/';
  const event = {
    type: 'VISIT',
    blocked: false,
    timestamp: new Date().toISOString(),
    visitorId: proofResult.thumbprint.slice(0, 20),
    ip: hints.ip,
    country: hints.country,
    city: hints.city,
    asn: hints.asn,
    ja3: hints.ja3,
    ja4: hints.ja4,
    userAgent: String(req.headers?.['user-agent'] || 'unknown').slice(0, 180),
    path,
    latencyMs: Math.max(0, Math.min(60000, Number(body.latencyMs) || 0)),
    status: 'OBSERVED',
    dpopVerified: true,
    riskScore: suspicious ? 75 : 0
  };
  await recordProjectEvent(project.id, event);
  return sendJson(res, 200, { ok: true, result: 'OBSERVED', dpopVerified: true, riskScore: event.riskScore });
}

async function serverEvent(body, req, res) {
  const serverKey = req.headers?.['x-arix-server-key'];
  const resolved = await resolveProjectFromApiKey(serverKey);
  if (!resolved || resolved.mapping.type !== 'server') return sendJson(res, 401, { error: 'Invalid server integration key.' });
  const project = await getJson(`arix:project:${resolved.mapping.projectId}`);
  if (!project) return sendJson(res, 401, { error: 'Project not found.' });
  if (body.action === 'get-policy') {
    const limit = await rateLimit({ key: `arix:server-policy-limit:${project.id}:${resolved.hash}`, algorithm: 'SLIDING_WINDOW', limit: 600, windowMs: 60000 });
    if (!limit.allowed) return sendJson(res, 429, { error: 'Policy-read quota exceeded.' }, { 'Retry-After': String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))) });
    return sendJson(res, 200, { ok: true, policy: project.policy ?? {} });
  }
  if (body.action === 'check-limit') {
    const control = await rateLimit({ key: `arix:server-quota-api:${project.id}:${resolved.hash}`, algorithm: 'SLIDING_WINDOW', limit: 30000, windowMs: 60000 });
    if (!control.allowed) return sendJson(res, 429, { error: 'Distributed quota API limit reached.' }, { 'Retry-After': String(Math.max(1, Math.ceil(control.retryAfterMs / 1000))) });
    const scope = typeof body.scope === 'string' ? body.scope : '';
    const algorithm = String(body.algorithm ?? 'TOKEN_BUCKET').toUpperCase();
    const requestedLimit = Number(body.limit ?? project.policy?.rateLimitPerMinute ?? 120);
    const windowMs = Number(body.windowMs ?? 60000);
    const weight = Number(body.weight ?? 1);
    if (!scope || scope.length > 256 || !['TOKEN_BUCKET', 'SLIDING_WINDOW', 'FIXED_WINDOW', 'LEAKY_BUCKET'].includes(algorithm)) return sendJson(res, 400, { error: 'Invalid distributed quota scope or algorithm.' });
    if (!Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 10000 || !Number.isInteger(windowMs) || windowMs < 100 || windowMs > 3600000 || !Number.isInteger(weight) || weight < 1 || weight > 10000) return sendJson(res, 400, { error: 'Invalid distributed quota limit, window or weight.' });
    const projectCeiling = Math.max(1, Math.min(10000, Number(project.policy?.rateLimitPerMinute) || 120));
    const effectiveLimit = Math.min(requestedLimit, projectCeiling);
    if (weight > effectiveLimit) return sendJson(res, 400, { error: 'Quota weight cannot exceed the effective project limit.' });
    const scopeHash = await sha256Hex(scope);
    const decision = await rateLimit({ key: `arix:customer-quota:${project.id}:${algorithm}:${windowMs}:${scopeHash}`, algorithm, limit: effectiveLimit, windowMs, weight });
    return sendJson(res, 200, { ok: true, decision: { ...decision, limit: effectiveLimit, algorithm, windowMs } });
  }
  const limit = await rateLimit({ key: `arix:server-event-limit:${project.id}:${resolved.hash}`, algorithm: 'SLIDING_WINDOW', limit: 600, windowMs: 60000 });
  if (!limit.allowed) return sendJson(res, 429, { error: 'Server telemetry quota exceeded.' }, { 'Retry-After': String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))) });
  const eventType = String(body.type ?? 'SERVER_EVENT').slice(0, 48).replace(/[^A-Z0-9_]/gi, '_').toUpperCase();
  const event = {
    type: eventType,
    blocked: body.blocked === true,
    timestamp: new Date().toISOString(),
    path: typeof body.path === 'string' ? body.path.slice(0, 180) : '/',
    method: typeof body.method === 'string' ? body.method.slice(0, 12).toUpperCase() : '—',
    riskScore: Math.max(0, Math.min(100, Number(body.riskScore) || 0)),
    findings: Array.isArray(body.findings) ? body.findings.slice(0, 20) : [],
    userId: typeof body.userId === 'string' ? body.userId.slice(0, 80) : 'anonymous',
    ip: 'not-collected-by-server-event'
  };
  await recordProjectEvent(project.id, event, { threat: event.blocked || eventType.includes('THREAT') });
  return sendJson(res, 202, { ok: true });
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    responseCors(req, res, '*');
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== 'POST') return methodNotAllowed(res, ['POST', 'OPTIONS']);
  responseCors(req, res, '*');
  try {
    const body = await readJson(req, 36000);
    if (body.action === 'demo') return await handleDemo(body, req, res);
    if (body.action === 'server-event' || body.action === 'get-policy' || body.action === 'check-limit') return await serverEvent(body, req, res);

    const apiKey = req.headers?.['x-arix-key'];
    const resolved = await resolveProjectFromApiKey(apiKey);
    if (!resolved) return sendJson(res, 401, { error: 'Unknown project key.' });
    const project = await getJson(`arix:project:${resolved.mapping.projectId}`);
    if (!project) return sendJson(res, 401, { error: 'Project is unavailable.' });

    if (resolved.mapping.type === 'canary' || apiKey.startsWith('ARIX_CANARY_')) {
      if (project.policy?.deceptionEnabled === false) return sendJson(res, 401, { error: 'Canary key detected.' });
      const mirage = await trapMirage(project.id, req.url || '/', 'CANARY_KEY_USED');
      const hints = getNetworkHints(req);
      await recordProjectEvent(project.id, { type: 'TRAPPED_HACKER', blocked: true, reason: 'CANARY_KEY_USED', timestamp: new Date().toISOString(), ip: hints.ip, country: hints.country, asn: hints.asn, path: String(req.url).slice(0, 160), mirage: mirage.data }, { threat: true });
      return sendJson(res, 200, { ...mirage, arix: { mode: 'PHANTOM_SANDBOX', event: 'CANARY_KEY_USED' } });
    }
    if (resolved.mapping.type !== 'live') return sendJson(res, 401, { error: 'This key type cannot be used for browser telemetry.' });

    const inspection = inspectRequest({ method: req.method, url: req.url, headers: req.headers, body });
    return await browserVisit(body, req, res, resolved.mapping, project, inspection);
  } catch (error) {
    console.error('[ArixShield] /api/shield request failed:', String(error?.stack || error).slice(0, 2000));
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, { error: status === 503 ? 'Protection service unavailable. Check Redis and master-secret configuration.' : error.message });
  }
}

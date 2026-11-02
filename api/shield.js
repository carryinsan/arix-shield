import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, readJson, methodNotAllowed, getNetworkHints, normalizeOrigin } from './_lib/http.js';
import { rateLimit, rateLimitMulti, acquireConcurrency, releaseConcurrency, increment, getJson, getString, setString, setMembers, setCard, getStrings, setRemoveMany, recordProjectEvent, recordApiTelemetryEvent } from './_lib/redis.js';
import { sha256Hex, hashCredential, verifyDpopProof, trapMirage, createSignedToken, verifySignedToken, randomToken, sha256, getClearancePublicJwk, decryptClearanceJwe } from './_lib/crypto-trap.js';
import { inspectRequest } from './_lib/waf-engine.js';
import { checkIpReputation, verifyForwardConfirmedCrawler, verifyConfiguredProviderIp } from './_lib/reputation.js';
import { isActorBackedOff, banActorForHoneypot, recordRequestOutcome, sanitizeForensicEvent, recordThreatCorrelation } from './_lib/abuse.js';
import { createInvisibleWatermarkMarker, createChameleonCanaryId, storeChameleonCanary, lookupChameleonCanary, storeChameleonExposedId, lookupChameleonCanaryByExposedId } from './_lib/watermark.js';
import { formatIpPrefix } from './_lib/cidr.js';
import { verifyRuntimeIntegrity } from './_lib/integrity.js';

const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);
const localApiKeyCache = globalThis.__ARIX_LOCAL_API_KEY_CACHE__ ??= new Map();

function responseCors(req, res, allowOrigin = '*') {
  res.setHeader('Access-Control-Allow-Origin', allowOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Arix-Key, X-Arix-PoP, X-Arix-JWK, X-Arix-Server-Key, X-Arix-Clearance, X-Arix-Outage-PoW');
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

async function issuePowChallenge(projectId, signals = {}) {
  const binding = await sha256Hex(JSON.stringify(signals && typeof signals === 'object' ? signals : {}));
  return createSignedToken({ projectId, nonce: randomToken(16), renderSeed: String(signals.renderSeed || ''), binding, exp: Date.now() + 120000, difficulty: 12 }, 'browser-pow');
}

async function validatePow(projectId, token, solution, signals = {}) {
  if (typeof solution !== 'string' || solution.length > 16 || !/^\d{1,12}$/.test(solution)) return false;
  const payload = await verifySignedToken(token, 'browser-pow');
  if (!payload || payload.projectId !== projectId || payload.exp < Date.now()) return false;
  const binding = await sha256Hex(JSON.stringify(signals && typeof signals === 'object' ? signals : {}));
  if (payload.binding !== binding) return false;
  const digest = await sha256(`${payload.nonce}:${payload.binding}:${solution}`);
  return digest[0] === 0 && (digest[1] & 0xf0) === 0;
}

async function resolveProjectFromApiKey(apiKey) {
  if (typeof apiKey !== 'string' || apiKey.length < 20 || apiKey.length > 160) return null;
  const hash = await hashCredential(apiKey);
  // Server integration keys are checked against Redis on every action. Do not
  // cache this mapping: an emergency revoke must take effect on the next
  // control-plane request, not after a worker-local TTL expires.
  const mapping = await getJson(`arix:key:${hash}`);
  if (!mapping || mapping.revokedAt) return null;
  return { mapping, hash };
}

async function getCachedProjectIdForApiKey(apiKey) {
  if (typeof apiKey !== 'string' || apiKey.length < 20 || apiKey.length > 160) return null;
  const hash = await hashCredential(apiKey);
  const cached = localApiKeyCache.get(hash);
  return cached && cached.expiresAt > Date.now() && !cached.mapping?.revokedAt ? String(cached.mapping.projectId || '') : null;
}

async function browserVisit(body, req, res, mapping, project, inspection) {
  const origin = req.headers?.origin;
  if (body.action === 'clearance-key') {
    if (!isProjectOriginAllowed(project, origin)) return sendJson(res, 403, { error: 'Browser origin is not registered for this project.' });
    const proofResult = await verifyDpopProof({ proof: req.headers?.['x-arix-pop'], method: req.method, url: requestUrl(req), projectId: project.id, redisGetSet: setString });
    if (!proofResult.valid) return sendJson(res, 401, { error: 'Browser proof-of-possession failed.' });
    const publicJwk = getClearancePublicJwk();
    if (!publicJwk) return sendJson(res, 503, { error: 'Encrypted client clearance is not configured.' });
    return sendJson(res, 200, { ok: true, publicJwk, projectId: project.id, renderSeed: randomToken(16) });
  }

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

  if (body.clearanceJwe) {
    try {
      const sealed = await decryptClearanceJwe(body.clearanceJwe);
      if (sealed.projectId !== project.id) return sendJson(res, 401, { error: 'Clearance token project mismatch.' });
      body.path = typeof sealed.path === 'string' ? sealed.path.slice(0, 180) : '/';
      body.latencyMs = Math.max(0, Math.min(60000, Number(sealed.latencyMs) || 0));
      body.signals = sealed.signals && typeof sealed.signals === 'object' ? sealed.signals : {};
    } catch {
      return sendJson(res, 400, { error: 'Encrypted client clearance could not be verified.' });
    }
  }
  const hints = getNetworkHints(req);
  if (project.policy?.threatFeedEnabled !== false && hints.ip !== 'unavailable') {
    // Threat-feed matches are network reputation, not proof that this browser/user is malicious.
    // Keep the signal for audit/analytics; actor-bound DPoP, authorization and WAF findings enforce.
    const reputation = await checkIpReputation(hints.ip);
    if (reputation.threatConfidence > 0) {
      await recordProjectEvent(project.id, { type: 'THREAT_FEED_IP_OBSERVED', blocked: false, timestamp: new Date().toISOString(), ip: hints.ip, country: hints.country, asn: hints.asn, path: String(body.path || '/').split('?')[0].slice(0, 180), threatConfidence: reputation.threatConfidence, signals: reputation.signals }, { threat: true });
    }
  }

  const key = `arix:limit:${project.id}:${proofResult.thumbprint}`;
  const limit = await rateLimit({ key, algorithm: 'TOKEN_BUCKET', limit: project.policy?.rateLimitPerMinute ?? 120, windowMs: 60000 });
  if (!limit.allowed) return sendJson(res, 429, { error: 'Project visitor telemetry rate limit exceeded.' }, { 'Retry-After': String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))) });

  const pathForPolicy = String(body.path ?? req.url ?? '/');
  const asnForPolicy = String(req.headers?.['x-vercel-ip-as-number'] ?? '');
  const humanOnly = /\/(?:login|signup|checkout)(?:\/|\?|$)/i.test(pathForPolicy);
  // A valid, single-use DPoP proof is an explicit clearance signal. ASN alone is never a hard block here.
  const dcSignal = Boolean(project.policy?.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(asnForPolicy));
  if (inspection?.findings?.length && project.policy?.mode !== 'DRY_RUN') {
    const hints = getNetworkHints(req);
    await recordProjectEvent(project.id, { type: 'WAF_BLOCK', blocked: true, timestamp: new Date().toISOString(), path: pathForPolicy.slice(0, 180), ip: hints.ip, country: hints.country, asn: hints.asn, findings: inspection?.findings ?? [], riskScore: inspection?.riskScore ?? 0, datacenterSignal: dcSignal }, { threat: true });
    return sendJson(res, 403, { error: 'Request blocked by ArixShield policy.', findings: inspection?.findings ?? [], riskScore: inspection?.riskScore ?? 0 });
  }
  if (inspection?.findings?.length || dcSignal) {
    const hints = getNetworkHints(req);
    await recordProjectEvent(project.id, { type: 'WAF_OBSERVED', blocked: false, timestamp: new Date().toISOString(), path: pathForPolicy.slice(0, 180), ip: hints.ip, asn: hints.asn, findings: inspection?.findings ?? [], riskScore: inspection?.riskScore ?? 0, datacenterSignal: dcSignal }, { threat: true });
  }

  if (!body.powToken || !(await validatePow(project.id, body.powToken, String(body.powSolution ?? ''), body.signals || {}))) {
    const challenge = await issuePowChallenge(project.id, body.signals || {});
    return sendJson(res, 200, { ok: true, challenge, pow: { difficulty: 12, expiresInSeconds: 120 } });
  }

  const botSignals = body.signals && typeof body.signals === 'object' ? body.signals : {};
  const userAgent = String(req.headers?.['user-agent'] || '');
  const ja4 = String(hints.ja4 || '');
  // Canvas/WebGL availability and software rendering are privacy/enterprise
  // capability signals, not proof of automation. Never score them as bot evidence.
  const nonBrowserClient = /(?:python-requests|go-http-client|curl\/|undici|node-fetch)/i.test(userAgent);
  const keyboardHumanSignal = Number(botSignals.keyboardSamples) >= 3 || Number(botSignals.focusTransitions) >= 3;
  const signalCount = ['webdriver', 'headless', 'automationFlag', 'screenMismatch', 'eventTimingAnomaly', 'prototypeTampered', 'kinematicAnomaly'].filter((name) => botSignals[name] === true).length + (nonBrowserClient ? 1 : 0);
  const strongAutomationSignal = botSignals.webdriver === true || botSignals.headless === true || nonBrowserClient;
  const suspicious = strongAutomationSignal || (signalCount >= 2 && !keyboardHumanSignal);
  const tlsMismatch = Boolean(nonBrowserClient && ja4);
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
    ...(hints.latitude !== undefined ? { latitude: Math.round(hints.latitude * 10) / 10, longitude: Math.round(hints.longitude * 10) / 10 } : {}),
    ja3: hints.ja3,
    ja4: hints.ja4,
    userAgent: String(req.headers?.['user-agent'] || 'unknown').slice(0, 180),
    path,
    latencyMs: Math.max(0, Math.min(60000, Number(body.latencyMs) || 0)),
    status: 'OBSERVED',
    dpopVerified: true,
    riskScore: suspicious ? Math.min(70, 45 + signalCount * 5 + (tlsMismatch ? 5 : 0)) : 0,
    botSignals: { webdriver: botSignals.webdriver === true, headless: botSignals.headless === true, automationFlag: botSignals.automationFlag === true, screenMismatch: botSignals.screenMismatch === true, eventTimingAnomaly: botSignals.eventTimingAnomaly === true, prototypeTampered: botSignals.prototypeTampered === true, kinematicAnomaly: botSignals.kinematicAnomaly === true, keyboardHumanSignal, keyboardSamples: Math.max(0, Math.min(1000, Number(botSignals.keyboardSamples) || 0)), focusTransitions: Math.max(0, Math.min(1000, Number(botSignals.focusTransitions) || 0)), nonBrowserClient, canvasAvailable: botSignals.canvasAvailable === true, webglAvailable: botSignals.webglAvailable === true, softwareRendererObserved: /swiftshader|llvmpipe|mesa offscreen|software rasterizer/i.test(String(botSignals.webglRenderer || '')), tlsFingerprintPresent: Boolean(ja4), canvasHashPresent: typeof botSignals.canvasPixelHash === 'string' && /^[a-f0-9]{64}$/i.test(botSignals.canvasPixelHash) }
  };
  await recordProjectEvent(project.id, event);
  const clearanceNonce = randomToken(24);
  const clearance = await createSignedToken({
    projectId: project.id,
    dpopThumbprint: proofResult.thumbprint,
    // Clearance continuity is cryptographic (DPoP thumbprint), not network-bound.
    riskScore: event.riskScore,
    singleUseNonce: clearanceNonce,
    issuedAt: Date.now(),
    exp: Date.now() + 60000
  }, 'browser-clearance');
  return sendJson(res, 200, { ok: true, result: 'CLEARED', dpopVerified: true, riskScore: event.riskScore, clearanceTicket: clearance, expiresInSeconds: 60 });
}

async function serverEvent(body, req, res) {
  const serverKey = req.headers?.['x-arix-server-key'];
  const resolved = await resolveProjectFromApiKey(serverKey);
  if (!resolved || !['server', 'server-retiring'].includes(resolved.mapping.type) || (resolved.mapping.type === 'server-retiring' && Number(resolved.mapping.retireAt || 0) <= Date.now())) return sendJson(res, 401, { error: 'Invalid or retired server integration key.' });
  const project = await getJson(`arix:project:${resolved.mapping.projectId}`);
  if (!project) return sendJson(res, 401, { error: 'Project not found.' });
  if (resolved.mapping.type === 'server' && resolved.hash !== project.serverKeyHash) return sendJson(res, 401, { error: 'Server integration key has been rotated or revoked.' });
  res.setHeader?.('X-Arix-Epoch', String(Math.max(0, Number(project.keyEpoch) || 0)));
  const action = String(body.action || 'server-event');
  const recordOutcomeLimit = Math.max(600, Math.min(100000, Number(process.env.ARIX_RECORD_OUTCOME_LIMIT_PER_MINUTE) || 10000));
  const actionLimits = { 'get-policy': 600, 'check-limit': 30000, 'check-abuse': 30000, 'check-reputation': 30000, 'record-outcome': recordOutcomeLimit, 'honeypot': 120, 'watermark-material': 5000, 'register-chameleon-id': 5000, 'server-event': 900, 'consume-clearance': 30000, 'consume-dpop': 30000, 'consume-flow': 30000, 'acquire-concurrency': 30000, 'release-concurrency': 30000, 'record-cost': 30000 };
  const actionQuota = await rateLimit({ key: `arix:server-action:${action}:${project.id}:${resolved.hash}`, algorithm: 'TOKEN_BUCKET', limit: actionLimits[action] || 300, windowMs: 60000 });
  if (!actionQuota.allowed) return sendJson(res, 429, { error: `ArixShield ${action} quota exceeded.` }, { 'Retry-After': String(Math.max(1, Math.ceil(actionQuota.retryAfterMs / 1000))) });
  if (body.action === 'honeypot') {
    const path = String(body.path || '/').split('?')[0].slice(0, 180);
    const mirage = await trapMirage(project.id, path, 'HONEYPOT_ROUTE');
    const actorId = String(body.actorId || 'anonymous').slice(0, 180);
    const ip = String(body.ip || '').slice(0, 64);
    const ban = await banActorForHoneypot(project.id, actorId, ip);
    const ja4 = process.env.VERCEL === '1' ? String(body.ja4 || '').slice(0, 160) : '';
    const ja4Hash = ja4 ? await sha256Hex(`${project.id}:${ja4}`) : null;
    if (ja4Hash && ban.actorHash) await setString(`arix:trap:ja4:${project.id}:${ja4Hash}:${ban.actorHash}`, String(Date.now()), 600);
    await recordProjectEvent(project.id, {
      type: 'HONEYPOT_ROUTE_HIT', blocked: Boolean(ban.actorHash), reason: 'Reconnaissance route accessed',
      timestamp: new Date().toISOString(), path, method: String(body.method || 'GET').toUpperCase().slice(0, 12),
      ipHint: ip, actorHash: ban.actorHash, ja4Hash, banUntil: new Date(ban.until).toISOString(),
      mirage: mirage.data
    }, { threat: true });
    return sendJson(res, 200, { ...mirage, arix: { mode: 'PHANTOM_SANDBOX', synthetic: true } });
  }
  if (body.action === 'register-chameleon-id') {
    const canaryId = String(body.canaryId || '').toLowerCase();
    const exposedId = String(body.exposedId ?? '');
    if (!/^[a-f0-9]{24}$/.test(canaryId) || !exposedId || exposedId.length > 128 || /[\u0000-\u001f\u007f]/.test(exposedId)) return sendJson(res, 400, { error: 'Invalid chameleon identifier registration.' });
    await storeChameleonExposedId(project.id, canaryId, exposedId);
    return sendJson(res, 200, { ok: true, registered: true });
  }
  if (body.action === 'watermark-material') {
    const sessionId = String(body.sessionId || '').slice(0, 100);
    if (!sessionId) return sendJson(res, 400, { error: 'A sessionId is required for watermark attribution.' });
    const marker = await createInvisibleWatermarkMarker({
      projectId: project.id, sessionId,
      userId: String(body.userId || 'anonymous').slice(0, 100),
      ip: String(body.ip || '').slice(0, 64) || 'unavailable'
    });
    const canaryRowsEnabled = typeof body.canaryRowsEnabled === 'boolean' ? body.canaryRowsEnabled : project.policy?.canaryRowsEnabled === true;
    let canaryKey = null;
    let canaryId = null;
    if (canaryRowsEnabled) {
      canaryId = await createChameleonCanaryId(project.id, sessionId);
      const sessionIdHash = await sha256Hex(`${project.id}:${sessionId}`);
      await storeChameleonCanary(project.id, canaryId, { sessionIdHash, userId: body.userId, ip: body.ip });
      const activeCanaryKey = `arix:canary:active:${project.id}`;
      canaryKey = await getString(activeCanaryKey);
      if (!canaryKey) {
        const candidate = `ARIX_CANARY_${randomToken(18)}`;
        const inserted = await setString(activeCanaryKey, candidate, 60 * 60 * 24 * 90, true);
        canaryKey = inserted === 'OK' ? candidate : await getString(activeCanaryKey);
      }
      if (canaryKey) {
        const canaryHash = await hashCredential(canaryKey);
        await setString(`arix:key:${canaryHash}`, JSON.stringify({ projectId: project.id, type: 'canary', createdAt: Date.now() }), 60 * 60 * 24 * 90);
      }
    }
    return sendJson(res, 200, { ok: true, marker, canaryKey, canaryId, projectId: project.id, attributionTtlDays: 90 });
  }
  if (body.action === 'check-abuse') {
    const actorId = String(body.actorId || 'anonymous').slice(0, 180);
    const result = await isActorBackedOff(project.id, actorId, String(body.ip || '').slice(0, 64));
    return sendJson(res, 200, { ok: true, ...result });
  }
  if (body.action === 'check-reputation') {
    const ip = String(body.ip || '').slice(0, 64);
    const userAgent = String(body.userAgent || '').slice(0, 240);
    const provider = String(body.provider || '').slice(0, 40);
    const asn = String(body.asn || '').slice(0, 16);
    const actorId = String(body.actorId || 'anonymous').slice(0, 180);
    const path = String(body.path || '/').split('?')[0].slice(0, 180);
    const [reputation, crawler] = await Promise.all([checkIpReputation(ip), verifyForwardConfirmedCrawler(ip, userAgent)]);
    const configuredProvider = provider ? verifyConfiguredProviderIp(ip, provider) : { verified: false, provider: null };
    const verifiedSource = crawler.verified === true || configuredProvider.verified === true;
    const datacenter = DATA_CENTER_ASNS.has(asn);
    const correlation = await isActorBackedOff(project.id, actorId, ip);
    const actorScore = Math.max(0, Math.min(100, Number(correlation.actorScore) || 0));
    const subnetScore = Math.max(0, Math.min(100, Number(correlation.subnetScore) || 0));
    let threatConfidence = Math.min(100, Number(reputation.threatConfidence) || 0) + (datacenter ? 20 : 0) + Math.max(actorScore, subnetScore);
    if (verifiedSource) threatConfidence = 0;
    threatConfidence = Math.max(0, Math.min(100, threatConfidence));
    // Only accumulated actor-specific evidence may enforce or step-up a visitor.
    // Shared IP/subnet/ASN reputation is retained as a signal, never a collateral block.
    const action = verifiedSource ? 'allow' : actorScore >= 65 ? 'block' : actorScore >= 40 ? 'challenge' : 'allow';
    return sendJson(res, 200, { ok: true, reputation, crawler, configuredProvider, datacenter, threatConfidence, action, correlation: { actorScore, subnetScore, blocked: correlation.blocked === true }, staleFeedWarning: Array.isArray(reputation.staleFeeds) && reputation.staleFeeds.length > 0 });
  }
  if (body.action === 'record-outcome') {
    const actorId = String(body.actorId || body.userId || 'anonymous').slice(0, 180);
    const path = String(body.path || '/').slice(0, 240);
    const status = Math.max(0, Math.min(599, Number(body.status) || 0));
    const outcome = await recordRequestOutcome({
      projectId: project.id, actorId, ip: String(body.ip || '').slice(0, 64),
      method: String(body.method || 'GET').slice(0, 12), path, status,
      latencyMs: body.latencyMs, country: body.country, city: body.city, asn: body.asn,
      latitude: body.latitude, longitude: body.longitude,
      geoVelocityEnabled: project.policy?.geoVelocityEnabled === true,
      shadowCatalogEnabled: project.policy?.shadowApiCatalogEnabled === true,
      resourceCapabilityVerified: body.resourceCapabilityVerified === true
    });
    const securityBlocked = [401, 403, 429].includes(status);
    const normalizedPathForRisk = path.split('?')[0].toLowerCase();
    const pathTokens = path.split(/[/?#=&]/).filter(Boolean);
    const possibleCanaryIds = [...new Set(pathTokens.filter((value) => /^[a-z0-9_-]{12,80}$/i.test(value) || /^\d{10,16}$/.test(value)))].slice(0, 8);
    for (const possibleId of possibleCanaryIds) {
      const attribution = await lookupChameleonCanaryByExposedId(project.id, possibleId)
        || (/^[a-f0-9]{24}$/i.test(possibleId) ? await lookupChameleonCanary(project.id, possibleId.toLowerCase()) : null);
      if (!attribution) continue;
      const ban = await banActorForHoneypot(project.id, actorId, String(body.ip || '').slice(0, 64));
      await recordProjectEvent(project.id, {
        type: 'CANARY_RECORD_ACCESSED', blocked: Boolean(ban.actorHash), reason: 'A protected record identifier was queried',
        actorHash: ban.actorHash || outcome.actorHash, canaryId: possibleId,
        sessionIdHash: attribution.sessionIdHash, leakedUserId: attribution.userId,
        timestamp: new Date().toISOString(), path: normalizedPathForRisk
      }, { threat: true, countRequest: false });
      break;
    }
    const riskPoints = (Array.isArray(body.findings) && body.findings.length ? 20 : 0)
      + (status === 404 && /\/api\/(?:[^/]+\/)*admin(?:\/|$)/i.test(normalizedPathForRisk) ? 25 : 0)
      + (/\/api\/(?:login|auth)(?:\/|$)/i.test(normalizedPathForRisk) ? 20 : 0);
    if (riskPoints > 0) {
      const correlation = await recordThreatCorrelation(project.id, outcome.actorHash, String(body.ip || ''), riskPoints, 'CROSS_ENDPOINT_BEHAVIOR');
      if (Math.max(correlation.actorScore, correlation.subnetScore) >= 65) {
        await recordProjectEvent(project.id, { type: 'CROSS_ENDPOINT_CORRELATION_ALERT', blocked: true, actorHash: outcome.actorHash, path: normalizedPathForRisk, riskScore: Math.max(correlation.actorScore, correlation.subnetScore), timestamp: new Date().toISOString() }, { threat: true, countRequest: false });
      }
    }
    await recordApiTelemetryEvent(project.id, {
      type: 'API_REQUEST', blocked: securityBlocked, timestamp: new Date().toISOString(),
      path: path.split('?')[0].slice(0, 220), method: String(body.method || 'GET').toUpperCase().slice(0, 12), status,
      latencyMs: Math.max(0, Math.min(600000, Number(body.latencyMs) || 0)),
      ip: String(body.ip || '').slice(0, 64), country: String(body.country || '').slice(0, 2),
      city: String(body.city || '').slice(0, 80), asn: String(body.asn || '').slice(0, 24),
      actorHash: outcome.actorHash
    });
    const forensic = sanitizeForensicEvent({ timestamp: new Date().toISOString(), method: body.method, path, status, blocked: securityBlocked, ip: body.ip, country: body.country, asn: body.asn, headers: body.safeHeaders, findings: body.findings });
    if (project.policy?.forensicReplayEnabled === true && (status >= 400 || (Array.isArray(body.findings) && body.findings.length))) {
      const { listPushTrim } = await import('./_lib/redis.js');
      await listPushTrim(`arix:forensic:${project.id}`, { type: 'FORENSIC_REQUEST', ...forensic, actorHash: outcome.actorHash, latencyMs: Math.max(0, Number(body.latencyMs) || 0) }, 1000);
    }
    const hasSecurityFindings = Array.isArray(body.findings) && body.findings.length > 0;
    if (securityBlocked || hasSecurityFindings) {
      await recordProjectEvent(project.id, { type: hasSecurityFindings ? 'WAF_OBSERVED' : 'SECURITY_RESPONSE', blocked: securityBlocked, path: forensic.route, method: forensic.method, status, actorHash: outcome.actorHash, timestamp: forensic.timestamp, findings: forensic.findings }, { threat: true, countRequest: false });
    }
    return sendJson(res, 202, { ok: true, outcome });
  }
  if (body.action === 'get-policy') {
    const limit = await rateLimit({ key: `arix:server-policy-limit:${project.id}:${resolved.hash}`, algorithm: 'SLIDING_WINDOW', limit: 600, windowMs: 60000 });
    if (!limit.allowed) return sendJson(res, 429, { error: 'Policy-read quota exceeded.' }, { 'Retry-After': String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))) });
    const actorIndexKey = `arix:abuse:ban-actors:${project.id}`;
    const maxEntries = 2000;
    const actorCount = await setCard(actorIndexKey);
    if (Number(actorCount) > maxEntries) {
      return sendJson(res, 200, { ok: true, projectId: project.id, keyEpoch: Math.max(0, Number(project.keyEpoch) || 0), policy: project.policy ?? {}, snapshot: { fetchedAt: Date.now(), actorHashes: [], complete: false } });
    }
    const actorHashes = await setMembers(actorIndexKey);
    const actorList = Array.isArray(actorHashes) ? actorHashes : [];
    // Actor-ban indexes are bounded and cleaned against their expiring source keys.
    // Legacy IP-ban indexes are deliberately ignored and never enter SDK snapshots.
    const actorBatch = actorList.slice(0, maxEntries);
    const actorStates = await getStrings(...actorBatch.map((hash) => `arix:abuse:ban:${project.id}:${hash}`));
    const now = Date.now();
    const activeActors = []; const staleActors = [];
    actorBatch.forEach((hash, index) => (Number(actorStates[index]) > now ? activeActors : staleActors).push(hash));
    await setRemoveMany(`arix:abuse:ban-actors:${project.id}`, staleActors);
    return sendJson(res, 200, {
      ok: true, projectId: project.id, keyEpoch: Math.max(0, Number(project.keyEpoch) || 0), policy: project.policy ?? {},
      snapshot: { fetchedAt: now, actorHashes: activeActors, complete: actorList.length <= maxEntries }
    });
  }
  if (body.action === 'consume-dpop') {
    const nonce = typeof body.nonce === 'string' ? body.nonce : '';
    if (!/^[a-f0-9]{64}$/i.test(nonce)) return sendJson(res, 400, { error: 'Invalid DPoP replay identifier.' });
    const result = await setString(`arix:dpop:customer:${project.id}:${nonce}`, '1', 120, true);
    if (result !== 'OK') return sendJson(res, 409, { error: 'DPoP proof has already been used.' });
    return sendJson(res, 200, { ok: true, consumed: true });
  }
  if (body.action === 'consume-flow') {
    const nonce = typeof body.nonce === 'string' ? body.nonce : '';
    if (!/^[a-f0-9-]{32,64}$/i.test(nonce)) return sendJson(res, 400, { error: 'Invalid workflow breadcrumb nonce.' });
    const nonceHash = await sha256Hex(nonce);
    const result = await setString(`arix:flow-used:${project.id}:${nonceHash}`, '1', 900, true);
    if (result !== 'OK') return sendJson(res, 409, { error: 'Workflow breadcrumb has already been consumed.' });
    return sendJson(res, 200, { ok: true, consumed: true });
  }
  if (body.action === 'consume-clearance') {
    const nonce = typeof body.nonce === 'string' ? body.nonce : '';
    if (nonce.length < 20 || nonce.length > 128) return sendJson(res, 400, { error: 'Invalid clearance nonce.' });
    const nonceHash = await sha256Hex(nonce);
    const result = await setString(`arix:clearance-used:${project.id}:${nonceHash}`, '1', 70, true);
    if (result !== 'OK') return sendJson(res, 409, { error: 'Clearance ticket has already been consumed.' });
    return sendJson(res, 200, { ok: true, consumed: true });
  }
  if (body.action === 'acquire-concurrency') {
    const actorHash = String(body.actorHash || '').slice(0, 128);
    const requestId = String(body.requestId || '').slice(0, 128);
    if (!actorHash || !requestId) return sendJson(res, 400, { error: 'Concurrency actor and request identifiers are required.' });
    const lease = await acquireConcurrency(`arix:conc:${project.id}:${actorHash}`, requestId, { maximum: Math.max(1, Math.min(20, Number(body.maximum) || 3)), ttlMs: Math.max(5000, Math.min(300000, Number(body.ttlMs) || 120000)) });
    return sendJson(res, lease.allowed ? 200 : 429, { ok: lease.allowed, ...lease });
  }
  if (body.action === 'release-concurrency') {
    const actorHash = String(body.actorHash || '').slice(0, 128);
    const requestId = String(body.requestId || '').slice(0, 128);
    if (!actorHash || !requestId) return sendJson(res, 400, { error: 'Concurrency actor and request identifiers are required.' });
    const removed = await releaseConcurrency(`arix:conc:${project.id}:${actorHash}`, requestId);
    return sendJson(res, 200, { ok: true, released: removed > 0 });
  }
  if (body.action === 'record-cost') {
    const cost = Math.max(0, Math.min(1000000, Number(body.actualCost) || 0));
    if (!Number.isFinite(cost)) return sendJson(res, 400, { error: 'Invalid actual cost.' });
    await increment(`arix:metrics:${project.id}:actual_cost_units`, Math.ceil(cost));
    return sendJson(res, 202, { ok: true, recorded: true });
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
    // SDK-provided limits are authenticated with the server integration key.
    // Permit only the documented maximum 4x actor trust multiplier, never an
    // arbitrary quota increase above the configured project policy.
    const effectiveLimit = Math.min(requestedLimit, projectCeiling * 4, 10000);
    if (weight > effectiveLimit) return sendJson(res, 400, { error: 'Quota weight cannot exceed the effective project limit.' });
    let decision;
    if (Array.isArray(body.dimensions) && body.dimensions.length > 0) {
      if (body.dimensions.length > 8) return sendJson(res, 400, { error: 'Too many quota dimensions.' });
      const dimensions = [];
      for (const item of body.dimensions) {
        const name = String(item?.name || '').toLowerCase();
        const dimensionScope = String(item?.scope || '');
        const allowedNames = ['actor', 'subnet', 'tenant', 'endpoint'];
        const aggregateCap = name === 'subnet' ? Math.min(100000, projectCeiling * 500) : (name === 'tenant' || name === 'endpoint') ? Math.min(100000, projectCeiling * 100) : effectiveLimit;
        const dimLimit = Math.min(aggregateCap, Math.max(1, Math.floor(Number(item?.limit) || effectiveLimit)));
        if (!allowedNames.includes(name) || !dimensionScope || dimensionScope.length > 256 || dimLimit > 100000) return sendJson(res, 400, { error: 'Invalid quota dimension.' });
        const hash = await sha256Hex(dimensionScope);
        dimensions.push({ key: `arix:customer-quota:${project.id}:${name}:${hash}`, limit: dimLimit, windowMs });
      }
      decision = await rateLimitMulti({ dimensions, weight });
    } else {
      const scopeHash = await sha256Hex(scope);
      decision = await rateLimit({ key: `arix:customer-quota:${project.id}:${algorithm}:${windowMs}:${scopeHash}`, algorithm, limit: effectiveLimit, windowMs, weight });
    }
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

async function handler(req, res) {
  const integrity = await verifyRuntimeIntegrity();
  if (!integrity.ok) return sendJson(res, 503, { error: 'Runtime integrity verification failed.', code: 'RUNTIME_INTEGRITY_FAILURE', issues: integrity.issues });
  if (req.method === 'OPTIONS') {
    responseCors(req, res, '*');
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== 'POST') return methodNotAllowed(res, ['POST', 'OPTIONS']);
  responseCors(req, res, '*');
  try {
    // Cheap header-only rejection precedes body reads/JSON parsing. These headers are
    // hints from the trusted Vercel ingress; they are not authentication credentials.
    const serverKeyHeader = req.headers?.['x-arix-server-key'];
    const browserKeyHeader = req.headers?.['x-arix-key'];
    const validServerKeyShape = typeof serverKeyHeader === 'string' && /^ARIX_SECRET_[A-Za-z0-9_-]{8,}$/.test(serverKeyHeader) && serverKeyHeader.length <= 160;
    const validBrowserKeyShape = typeof browserKeyHeader === 'string' && /^ARIX_(?:LIVE|CANARY)_[A-Za-z0-9_-]{8,}$/.test(browserKeyHeader) && browserKeyHeader.length <= 160;
    if (!validServerKeyShape && !validBrowserKeyShape) return sendJson(res, 401, { error: 'A valid ArixShield key is required.' });
    const contentLengthHeader = req.headers?.['content-length'];
    if (contentLengthHeader !== undefined) {
      if (!/^\d{1,10}$/.test(String(contentLengthHeader))) return sendJson(res, 400, { error: 'Invalid Content-Length header.' });
      if (Number(contentLengthHeader) > 36000) return sendJson(res, 413, { error: 'Request body too large.' });
    }
    const originHeader = req.headers?.origin;
    if (originHeader && !normalizeOrigin(originHeader)) return sendJson(res, 403, { error: 'Invalid request origin.' });
    // Reject parser-ambiguous headers before buffering or parsing an untrusted body.
    const headerInspection = inspectRequest({ method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders, httpVersion: req.httpVersion, contentLength: contentLengthHeader, maxBodyBytes: 36000 });
    if (headerInspection.findings.some((item) => ['HTTP_SMUGGLING_HEADERS', 'HTTP_HEADER_INJECTION', 'HTTP2_CONNECTION_SPECIFIC_HEADER', 'DUPLICATE_HEADER'].includes(item.id))) {
      return sendJson(res, 400, { error: 'Request header consistency check failed.' });
    }
    // Never pre-body hard-block by ingress IP: this endpoint serves users behind
    // shared carrier/office/VPN addresses. Actor bans are evaluated after auth.
    const body = await readJson(req, 36000);
    if (['server-event', 'get-policy', 'check-limit', 'check-abuse', 'check-reputation', 'record-outcome', 'honeypot', 'watermark-material', 'register-chameleon-id', 'consume-clearance', 'consume-dpop', 'consume-flow', 'acquire-concurrency', 'release-concurrency', 'record-cost'].includes(body.action)) return await serverEvent(body, req, res);

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

    const inspection = inspectRequest({ method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders, httpVersion: req.httpVersion, body });
    return await browserVisit(body, req, res, resolved.mapping, project, inspection);
  } catch (error) {
    console.error('[ArixShield] /api/shield request failed:', error?.stack || error);
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, { error: status === 503 ? 'Protection service unavailable. Verify Upstash REST URL/token and ARIX_MASTER_SECRET.' : error.message });
  }
}

export default createCompatibleHandler(handler, { maxBodyBytes: 36000 });

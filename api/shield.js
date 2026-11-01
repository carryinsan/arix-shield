import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, readJson, methodNotAllowed, getNetworkHints, normalizeOrigin } from './_lib/http.js';
import { rateLimit, getJson, getString, setString, setMembers, setCard, getStrings, setRemoveMany, recordProjectEvent, recordApiTelemetryEvent } from './_lib/redis.js';
import { sha256Hex, hashCredential, verifyDpopProof, trapMirage, createSignedToken, verifySignedToken, randomToken, sha256, getClearancePublicJwk, decryptClearanceJwe } from './_lib/crypto-trap.js';
import { inspectRequest } from './_lib/waf-engine.js';
import { checkIpReputation, verifyForwardConfirmedCrawler, verifyConfiguredProviderIp, isIpInLoadedThreatFeed } from './_lib/reputation.js';
import { isActorBackedOff, isIpLocallyBlocked, banActorForHoneypot, recordRequestOutcome, sanitizeForensicEvent } from './_lib/abuse.js';
import { createInvisibleWatermarkMarker } from './_lib/watermark.js';

const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);
const localApiKeyCache = globalThis.__ARIX_LOCAL_API_KEY_CACHE__ ??= new Map();

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
  const cached = localApiKeyCache.get(hash);
  if (cached && cached.expiresAt > Date.now()) return cached.mapping?.revokedAt ? null : { mapping: cached.mapping, hash };
  const mapping = await getJson(`arix:key:${hash}`);
  if (mapping && !mapping.revokedAt) {
    localApiKeyCache.set(hash, { mapping, expiresAt: Date.now() + 3000 });
    if (localApiKeyCache.size > 2000) for (const [key, value] of localApiKeyCache) if (value.expiresAt <= Date.now()) localApiKeyCache.delete(key);
    return { mapping, hash };
  }
  localApiKeyCache.delete(hash);
  return null;
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
    const reputation = await checkIpReputation(hints.ip);
    if (reputation.checked && reputation.listed && project.policy?.mode !== 'DRY_RUN') {
      await recordProjectEvent(project.id, { type: 'THREAT_FEED_IP_BLOCK', blocked: true, timestamp: new Date().toISOString(), ip: hints.ip, country: hints.country, asn: hints.asn, path: String(body.path || '/').split('?')[0].slice(0, 180), feedCount: reputation.feedCount }, { threat: true });
      return sendJson(res, 403, { error: 'Request blocked by ArixShield IP reputation policy.' });
    }
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

  if (!body.powToken || !(await validatePow(project.id, body.powToken, String(body.powSolution ?? ''), body.signals || {}))) {
    const challenge = await issuePowChallenge(project.id, body.signals || {});
    return sendJson(res, 200, { ok: true, challenge, pow: { difficulty: 12, expiresInSeconds: 120 } });
  }

  const botSignals = body.signals && typeof body.signals === 'object' ? body.signals : {};
  const userAgent = String(req.headers?.['user-agent'] || '');
  const ja4 = String(hints.ja4 || '');
  const softwareRenderer = /swiftshader|llvmpipe|mesa offscreen|software rasterizer/i.test(String(botSignals.webglRenderer || ''));
  const appleBrowserClaim = /(?:macintosh|iphone|ipad|ipod).*?(?:safari|applewebkit)/i.test(userAgent);
  const hardwareContradiction = appleBrowserClaim && softwareRenderer;
  const nonBrowserClient = /(?:python-requests|go-http-client|curl\/|undici|node-fetch)/i.test(userAgent);
  const signalCount = ['webdriver', 'headless', 'automationFlag', 'screenMismatch', 'eventTimingAnomaly', 'prototypeTampered', 'kinematicAnomaly', 'hardwareContradiction', 'nonBrowserClient'].filter((name) => botSignals[name] === true || ({ hardwareContradiction, nonBrowserClient })[name] === true).length;
  const suspicious = botSignals.webdriver === true || botSignals.headless === true || hardwareContradiction || nonBrowserClient || signalCount >= 2;
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
    riskScore: suspicious ? Math.min(95, 55 + signalCount * 5 + (tlsMismatch ? 5 : 0)) : 0,
    botSignals: { webdriver: botSignals.webdriver === true, headless: botSignals.headless === true, automationFlag: botSignals.automationFlag === true, screenMismatch: botSignals.screenMismatch === true, eventTimingAnomaly: botSignals.eventTimingAnomaly === true, prototypeTampered: botSignals.prototypeTampered === true, kinematicAnomaly: botSignals.kinematicAnomaly === true, hardwareContradiction, nonBrowserClient, tlsFingerprintPresent: Boolean(ja4), canvasHashPresent: typeof botSignals.canvasPixelHash === 'string' && /^[a-f0-9]{64}$/i.test(botSignals.canvasPixelHash) }
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
  const action = String(body.action || 'server-event');
  const recordOutcomeLimit = Math.max(600, Math.min(100000, Number(process.env.ARIX_RECORD_OUTCOME_LIMIT_PER_MINUTE) || 10000));
  const actionLimits = { 'get-policy': 600, 'check-limit': 30000, 'check-abuse': 30000, 'check-reputation': 30000, 'record-outcome': recordOutcomeLimit, 'honeypot': 120, 'watermark-material': 5000, 'server-event': 900 };
  const actionQuota = await rateLimit({ key: `arix:server-action:${action}:${project.id}:${resolved.hash}`, algorithm: 'TOKEN_BUCKET', limit: actionLimits[action] || 300, windowMs: 60000 });
  if (!actionQuota.allowed) return sendJson(res, 429, { error: `ArixShield ${action} quota exceeded.` }, { 'Retry-After': String(Math.max(1, Math.ceil(actionQuota.retryAfterMs / 1000))) });
  if (body.action === 'honeypot') {
    const path = String(body.path || '/').split('?')[0].slice(0, 180);
    const mirage = await trapMirage(project.id, path, 'HONEYPOT_ROUTE');
    const actorId = String(body.actorId || 'anonymous').slice(0, 180);
    const ip = String(body.ip || '').slice(0, 64);
    const ban = await banActorForHoneypot(project.id, actorId, ip);
    await recordProjectEvent(project.id, {
      type: 'HONEYPOT_ROUTE_HIT', blocked: true, reason: 'Configured honeypot path accessed',
      timestamp: new Date().toISOString(), path, method: String(body.method || 'GET').toUpperCase().slice(0, 12),
      ipHint: ip, actorHash: ban.actorHash, banUntil: new Date(ban.until).toISOString(),
      mirage: mirage.data
    }, { threat: true });
    return sendJson(res, 200, { ...mirage, arix: { mode: 'PHANTOM_SANDBOX', synthetic: true } });
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
    if (canaryRowsEnabled) {
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
    return sendJson(res, 200, { ok: true, marker, canaryKey, attributionTtlDays: 90 });
  }
  if (body.action === 'check-abuse') {
    const actorId = String(body.actorId || body.ip || 'anonymous').slice(0, 180);
    const result = await isActorBackedOff(project.id, actorId, String(body.ip || '').slice(0, 64));
    return sendJson(res, 200, { ok: true, ...result });
  }
  if (body.action === 'check-reputation') {
    const ip = String(body.ip || '').slice(0, 64);
    const userAgent = String(body.userAgent || '').slice(0, 240);
    const provider = String(body.provider || '').slice(0, 40);
    const [reputation, crawler] = await Promise.all([checkIpReputation(ip), verifyForwardConfirmedCrawler(ip, userAgent)]);
    const configuredProvider = provider ? verifyConfiguredProviderIp(ip, provider) : { verified: false, provider: null };
    return sendJson(res, 200, { ok: true, reputation, crawler, configuredProvider });
  }
  if (body.action === 'record-outcome') {
    const actorId = String(body.actorId || body.userId || body.ip || 'anonymous').slice(0, 180);
    const path = String(body.path || '/').slice(0, 240);
    const status = Math.max(0, Math.min(599, Number(body.status) || 0));
    const outcome = await recordRequestOutcome({
      projectId: project.id, actorId, ip: String(body.ip || '').slice(0, 64),
      method: String(body.method || 'GET').slice(0, 12), path, status,
      latencyMs: body.latencyMs, country: body.country, city: body.city, asn: body.asn,
      latitude: body.latitude, longitude: body.longitude,
      geoVelocityEnabled: project.policy?.geoVelocityEnabled === true,
      shadowCatalogEnabled: project.policy?.shadowApiCatalogEnabled === true
    });
    const securityBlocked = [401, 403, 429].includes(status);
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
    const ipIndexKey = `arix:abuse:ban-ips:${project.id}`;
    const maxEntries = 2000;
    const [actorCount, ipCount] = await Promise.all([setCard(actorIndexKey), setCard(ipIndexKey)]);
    if (Number(actorCount) > maxEntries || Number(ipCount) > maxEntries) {
      return sendJson(res, 200, { ok: true, projectId: project.id, policy: project.policy ?? {}, snapshot: { fetchedAt: Date.now(), actorHashes: [], ipHashes: [], complete: false } });
    }
    const [actorHashes, ipHashes] = await Promise.all([setMembers(actorIndexKey), setMembers(ipIndexKey)]);
    const actorList = Array.isArray(actorHashes) ? actorHashes : [];
    const ipList = Array.isArray(ipHashes) ? ipHashes : [];
    // Ban-index sets are indexes, not the source of truth. A hash remains in
    // the index until cleanup, so only currently unexpired ban keys may enter
    // a 30-second SDK snapshot. Bound each read and prune stale index members.
    const actorBatch = actorList.slice(0, maxEntries);
    const ipBatch = ipList.slice(0, maxEntries);
    const [actorStates, ipStates] = await Promise.all([
      getStrings(...actorBatch.map((hash) => `arix:abuse:ban:${project.id}:${hash}`)),
      getStrings(...ipBatch.map((hash) => `arix:abuse:ban:${project.id}:${hash}`))
    ]);
    const now = Date.now();
    const activeActors = []; const staleActors = [];
    const activeIps = []; const staleIps = [];
    actorBatch.forEach((hash, index) => (Number(actorStates[index]) > now ? activeActors : staleActors).push(hash));
    ipBatch.forEach((hash, index) => (Number(ipStates[index]) > now ? activeIps : staleIps).push(hash));
    await Promise.all([
      setRemoveMany(`arix:abuse:ban-actors:${project.id}`, staleActors),
      setRemoveMany(`arix:abuse:ban-ips:${project.id}`, staleIps)
    ]);
    return sendJson(res, 200, {
      ok: true, projectId: project.id, policy: project.policy ?? {},
      snapshot: {
        fetchedAt: now, actorHashes: activeActors, ipHashes: activeIps,
        complete: actorList.length <= maxEntries && ipList.length <= maxEntries
      }
    });
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

async function handler(req, res) {
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
    const ingressIp = typeof req.headers?.['x-real-ip'] === 'string' ? req.headers['x-real-ip'].split(',')[0].trim() : '';
    const cachedProjectId = await getCachedProjectIdForApiKey(validServerKeyShape ? serverKeyHeader : browserKeyHeader);
    if (cachedProjectId && isIpLocallyBlocked(cachedProjectId, ingressIp)) return sendJson(res, 429, { error: 'Request blocked by ArixShield abuse controls.' }, { 'Cache-Control': 'no-store', 'Retry-After': '60' });
    if (process.env.ARIX_PREBODY_THREAT_FEED_BLOCK === 'true' && isIpInLoadedThreatFeed(ingressIp)) return sendJson(res, 403, { error: 'Request blocked by ArixShield threat-feed policy.' }, { 'Cache-Control': 'no-store' });
    const body = await readJson(req, 36000);
    if (['server-event', 'get-policy', 'check-limit', 'check-abuse', 'check-reputation', 'record-outcome', 'honeypot', 'watermark-material'].includes(body.action)) return await serverEvent(body, req, res);

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
    console.error('[ArixShield] /api/shield request failed:', error?.stack || error);
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, { error: status === 503 ? 'Protection service unavailable. Verify Upstash REST URL/token and ARIX_MASTER_SECRET.' : error.message });
  }
}

export default createCompatibleHandler(handler, { maxBodyBytes: 36000 });

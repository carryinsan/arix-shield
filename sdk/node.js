import { randomUUID, createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { inspectRequest, redactSensitiveText } from '../api/_lib/waf-engine.js';
import { validatePayloadSchema, isOpenApiOperation } from '../api/_lib/schema.js';
import { watermarkPayloadWithMarker } from '../api/_lib/watermark.js';
import { findOwnershipMismatch, rewriteCapabilityPath, sealResourceIdsInPayload } from '../api/_lib/crypto-trap.js';

const processBuckets = new Map(); const quotaLeases = new Map(); const policyCache = new Map(); const securitySnapshotCache = new Map(); const reputationCache = new Map();
const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);

async function remotePolicy(endpoint, serverKey) {
  if (!endpoint || !serverKey) return null;
  const cacheKey = `${endpoint}:${serverKey.slice(-10)}`; const cached = policyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 30000) return cached.policy;
  const response = await fetch(`${endpoint.replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey }, body: JSON.stringify({ action: 'get-policy' }), signal: AbortSignal.timeout(2500) });
  if (!response.ok) throw new Error(`ArixShield policy fetch failed (${response.status}).`);
  const data = await response.json(); policyCache.set(cacheKey, { at: Date.now(), policy: data.policy ?? {} }); securitySnapshotCache.set(cacheKey, { at: Date.now(), projectId: data.projectId, ...(data.snapshot || {}) }); return data.policy ?? {};
}
async function serverAction(endpoint, serverKey, payload, timeout = 3500) {
  const response = await fetch(`${String(endpoint).replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey }, body: JSON.stringify(payload), signal: AbortSignal.timeout(timeout) });
  if (!response.ok) throw new Error(`ArixShield ${payload.action} failed (${response.status}).`); return response.json();
}
function hashHex(value) { return createHash('sha256').update(String(value)).digest('hex'); }
function snapshotBlocks(endpoint, serverKey, identity, ip) {
  const cacheKey = `${endpoint}:${serverKey.slice(-10)}`; const snapshot = securitySnapshotCache.get(cacheKey);
  if (!snapshot || Date.now() - snapshot.at >= 30000 || !snapshot.complete || !snapshot.projectId) return null;
  const actorHash = identity && identity !== 'anonymous' ? hashHex(`${snapshot.projectId}:${String(identity).slice(0, 180)}`) : null;
  const ipHash = isIP(String(ip || '')) ? hashHex(`${snapshot.projectId}:${ip}`) : null;
  return Boolean((actorHash && snapshot.actorHashes?.includes(actorHash)) || (ipHash && snapshot.ipHashes?.includes(ipHash)));
}
function localTokenBucket(key, capacity, windowMs, weight = 1) {
  const now = Date.now(); const refillPerMs = capacity / windowMs; const item = processBuckets.get(key) ?? { tokens: capacity, updated: now };
  item.tokens = Math.min(capacity, item.tokens + Math.max(0, now - item.updated) * refillPerMs); item.updated = now; const allowed = item.tokens >= weight; if (allowed) item.tokens -= weight; processBuckets.set(key, item);
  if (processBuckets.size > 10000) for (const [bucketKey, bucket] of processBuckets) if (now - bucket.updated > windowMs * 3) processBuckets.delete(bucketKey);
  return { allowed, remaining: Math.floor(item.tokens), retryAfterMs: allowed ? 0 : Math.ceil((weight - item.tokens) / refillPerMs) };
}
async function distributedTokenBucket({ endpoint, serverKey, scope, algorithm = 'TOKEN_BUCKET', limit, windowMs = 60000, weight = 1, leaseSize = 15 }) {
  const leaseKey = `${endpoint}:${serverKey.slice(-10)}:${algorithm}:${windowMs}:${scope}`;
  const now = Date.now();
  let lease = quotaLeases.get(leaseKey);
  if (lease && lease.expiresAt > now && lease.remaining >= weight && lease.limit === limit) {
    lease.remaining -= weight;
    return { allowed: true, remaining: lease.remaining, retryAfterMs: 0, leased: true };
  }
  quotaLeases.delete(leaseKey);
  const grant = Math.min(limit, Math.max(weight, Math.min(15, Math.floor(Number(leaseSize) || 15))));
  const requestLease = async (amount) => {
    const data = await serverAction(endpoint, serverKey, { action: 'check-limit', scope, algorithm, limit, windowMs, weight: amount });
    if (!data?.decision || typeof data.decision.allowed !== 'boolean') throw new Error('ArixShield returned an invalid distributed quota decision.');
    return data.decision;
  };
  let charged = grant;
  let decision = await requestLease(grant);
  if (!decision.allowed && grant > weight) { charged = weight; decision = await requestLease(weight); }
  if (!decision.allowed) return decision;
  const remaining = charged - weight;
  if (remaining > 0) {
    quotaLeases.set(leaseKey, { remaining, expiresAt: now + Math.min(15000, windowMs), limit });
    if (quotaLeases.size > 10000) for (const [key, item] of quotaLeases) if (item.expiresAt <= now) quotaLeases.delete(key);
  }
  return { ...decision, remaining: remaining || decision.remaining, leased: grant > weight };
}
function sendDecision(res, status, payload) {
  if (typeof res.status === 'function' && typeof res.json === 'function') return res.status(status).json(payload);
  res.statusCode = status; res.setHeader?.('Content-Type', 'application/json; charset=utf-8'); res.setHeader?.('Cache-Control', 'no-store'); res.end?.(JSON.stringify(payload));
}
function isHoneypotPath(pathname, configured) {
  if (!Array.isArray(configured)) return false;
  return configured.some((raw) => { if (typeof raw !== 'string' || raw.length > 220) return false; const path = raw.split('?')[0]; return path.endsWith('/*') ? pathname.startsWith(path.slice(0, -1)) : pathname === path; });
}
async function cachedReputation(endpoint, serverKey, ip, userAgent, provider) {
  const uaClass = /googlebot/i.test(userAgent) ? 'googlebot' : /bingbot/i.test(userAgent) ? 'bingbot' : ''; const key = `${ip}:${provider}:${uaClass}`; const cached = reputationCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await serverAction(endpoint, serverKey, { action: 'check-reputation', ip, userAgent, provider }); reputationCache.set(key, { value, expiresAt: Date.now() + 60000 });
  if (reputationCache.size > 10000) for (const [id, item] of reputationCache) if (item.expiresAt <= Date.now()) reputationCache.delete(id); return value;
}
function resolveClientIp(req, options) {
  if (typeof options.getClientIp === 'function') { const value = options.getClientIp(req); return typeof value === 'string' && value.length <= 64 ? value : ''; }
  if (process.env.VERCEL === '1' && typeof req.headers?.['x-real-ip'] === 'string') return req.headers['x-real-ip'].split(',')[0].trim().slice(0, 64);
  return String(req.socket?.remoteAddress || req.connection?.remoteAddress || '').slice(0, 64);
}
function getGeoHints(req) {
  const latitude = Number(req.headers?.['x-vercel-ip-latitude']); const longitude = Number(req.headers?.['x-vercel-ip-longitude']);
  const valid = Number.isFinite(latitude) && Number.isFinite(longitude) && latitude >= -90 && latitude <= 90 && longitude >= -180 && longitude <= 180;
  return { country: String(req.headers?.['x-vercel-ip-country'] || '').slice(0, 2), city: String(req.headers?.['x-vercel-ip-city'] || '').slice(0, 80), asn: String(req.headers?.['x-vercel-ip-as-number'] || '').slice(0, 24), ...(valid ? { latitude: Math.round(latitude * 10) / 10, longitude: Math.round(longitude * 10) / 10 } : {}) };
}
function safeHeaders(headers) { const result = {}; for (const name of ['accept', 'content-type', 'user-agent', 'x-request-id']) if (headers?.[name] !== undefined) result[name] = String(headers[name]).slice(0, 180); return result; }

export function createArixShield(options = {}) {
  const mode = options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE'; const limit = Math.max(10, Math.min(10000, Number(options.rateLimitPerMinute) || 120)); const endpoint = String(options.endpoint ?? '').replace(/\/$/, ''); const serverKey = options.serverKey;
  if (!serverKey || !serverKey.startsWith('ARIX_SECRET_')) throw new Error('createArixShield requires the server-only ARIX_SECRET_ key.');
  if (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length && !endpoint) throw new Error('Configured honeypotPaths require an ArixShield endpoint.');
  const useGlobalRateLimit = options.globalRateLimit !== false && Boolean(endpoint);
  if (useGlobalRateLimit && !endpoint) throw new Error('globalRateLimit requires an ArixShield endpoint.');
  const localBlockCache = new Map();
  const rememberBlock = (key, milliseconds) => { localBlockCache.set(key, Date.now() + Math.max(1000, Math.min(30000, milliseconds || 3000))); if (localBlockCache.size > 10000) for (const [id, expires] of localBlockCache) if (expires <= Date.now()) localBlockCache.delete(id); };

  return async function arixShieldMiddleware(req, res, next) {
    const started = Date.now(); let url = req.originalUrl || req.url || '/'; const method = String(req.method || 'GET').toUpperCase(); let pathname = String(url).split('?')[0];
    const clientIp = resolveClientIp(req, options);
    const identityValue = typeof options.getIdentity === 'function' ? await options.getIdentity(req, { ip: clientIp, method, path: pathname }) : (req.user?.id ?? req.auth?.userId ?? clientIp ?? '');
    const identity = String(identityValue || '').slice(0, 180) || 'anonymous';
    let ownershipIdentity = '';
    if (options.capabilitySealing === true || options.responseOwnershipGuard === true) {
      let ownerValue = typeof options.getOwnershipIdentity === 'function' ? options.getOwnershipIdentity(req) : (req.user?.id ?? req.auth?.userId ?? '');
      if (ownerValue && typeof ownerValue.then === 'function') return sendDecision(res, 500, { error: 'getOwnershipIdentity must be synchronous in the Node SDK.' });
      ownershipIdentity = String(ownerValue ?? '').trim();
      if (!ownershipIdentity || ownershipIdentity.toLowerCase() === 'anonymous' || ownershipIdentity.length > 180 || ownershipIdentity === clientIp) return sendDecision(res, 500, { error: 'A stable authenticated getOwnershipIdentity is required for this protection.' });
    }
    if (options.capabilitySealing === true) {
      const rewritten = rewriteCapabilityPath(url, ownershipIdentity, { idPattern: options.capabilityIdPattern });
      if (rewritten.invalid) return sendDecision(res, 403, { error: 'Invalid or user-mismatched resource capability.' });
      if (rewritten.url !== url) { url = rewritten.url; req.url = rewritten.url; req.originalUrl = rewritten.url; pathname = rewritten.url.split('?')[0]; }
    }
    const body = req.body ?? null;
    const maxBodyBytes = Math.max(1024, Math.min(262144, Number(options.maxBodyBytes) || 32768));
    const declaredBodyBytes = Number(req.headers?.['content-length'] || 0);
    let measuredBodyBytes = 0;
    try { measuredBodyBytes = body == null ? 0 : Buffer.byteLength(typeof body === 'string' ? body : JSON.stringify(body)); } catch { measuredBodyBytes = maxBodyBytes + 1; }
    if (declaredBodyBytes > maxBodyBytes || measuredBodyBytes > maxBodyBytes) return sendDecision(res, 413, { error: 'Request body too large.', maxBodyBytes });
    const inspection = inspectRequest({ method, url, headers: req.headers, body, contentLength: req.headers?.['content-length'], maxBodyBytes, maxLeafBytes: options.maxLeafBytes ?? 4096, allowedLongFields: options.allowedLongFields ?? [] });
    if (isHoneypotPath(pathname, options.honeypotPaths)) {
      try { const trap = await serverAction(endpoint, serverKey, { action: 'honeypot', path: pathname, method, actorId: identity, ip: clientIp }); return sendDecision(res, 200, trap); }
      catch (error) { options.onTelemetryError?.(error); return sendDecision(res, 503, { error: 'ArixShield honeypot service is unavailable.' }); }
    }
    const cacheKey = `${identity}:${method}:${pathname}`; const cachedUntil = localBlockCache.get(cacheKey) || 0;
    if (cachedUntil > Date.now()) return sendDecision(res, 429, { error: 'Request temporarily rate-limited by ArixShield.', retryAfterMs: cachedUntil - Date.now() }); if (cachedUntil) localBlockCache.delete(cacheKey);
    let policy = { mode, rateLimitPerMinute: limit, blockDatacenterAsn: false, threatFeedEnabled: true };
    try { policy = { ...policy, ...(await remotePolicy(endpoint, serverKey) ?? {}) }; } catch (error) { options.onTelemetryError?.(error); if (options.failClosedPolicy === true) return sendDecision(res, 503, { error: 'ArixShield policy service is unavailable.' }); }
    const abuseEnabled = options.abuseProtection === true || (options.abuseProtection !== false && policy.abuseProtectionEnabled === true);
    const reputationEnabled = options.reputationProtection === true || (options.reputationProtection !== false && policy.threatFeedEnabled !== false);
    const shadowCatalogEnabled = options.shadowApiCatalog === true || (options.shadowApiCatalog !== false && policy.shadowApiCatalogEnabled === true);
    const geoVelocityEnabled = options.geoVelocityProtection === true || (options.geoVelocityProtection !== false && policy.geoVelocityEnabled === true);
    const forensicEnabled = options.forensicReplay === true || (options.forensicReplay !== false && policy.forensicReplayEnabled === true);
    if (endpoint && (abuseEnabled || (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length > 0))) {
      const snapshotDenied = snapshotBlocks(endpoint, serverKey, identity, clientIp);
      if (snapshotDenied === true) { rememberBlock(cacheKey, 30000); return sendDecision(res, 429, { error: 'ArixShield credential-abuse backoff is active.', snapshot: true }); }
      if (snapshotDenied === null) { try { const abuse = await serverAction(endpoint, serverKey, { action: 'check-abuse', actorId: identity, ip: clientIp }); if (abuse.blocked) { rememberBlock(cacheKey, abuse.retryAfterMs); return sendDecision(res, 429, { error: 'ArixShield credential-abuse backoff is active.', retryAfterMs: abuse.retryAfterMs }); } }
      catch (error) { options.onTelemetryError?.(error); if (options.failClosedAbuse === true) return sendDecision(res, 503, { error: 'ArixShield abuse service is unavailable.' }); }
      }
    }
    if (endpoint && reputationEnabled && clientIp) {
      try { const result = await cachedReputation(endpoint, serverKey, clientIp, String(req.headers?.['user-agent'] || '').slice(0, 240), options.trustedProvider || ''); const verifiedCrawler = result.crawler?.verified === true || result.configuredProvider?.verified === true;
        if (result.reputation?.checked && result.reputation.listed && !verifiedCrawler && policy.mode !== 'DRY_RUN' && mode !== 'DRY_RUN') { rememberBlock(cacheKey, 5000); return sendDecision(res, 403, { error: 'Request blocked by ArixShield IP reputation policy.' }); }
        req.arixShieldGoodBot = verifiedCrawler ? result.crawler.provider : null;
      } catch (error) { options.onTelemetryError?.(error); if (options.failClosedReputation === true) return sendDecision(res, 503, { error: 'ArixShield reputation service is unavailable.' }); }
    }
    const quotaLimit = Math.max(10, Math.min(10000, Number(policy.rateLimitPerMinute) || limit)); let requestedWeight = options.rateLimitWeight ?? 1;
    const weightProvider = options.getRateLimitWeight || (typeof requestedWeight === 'function' ? requestedWeight : null);
    if (weightProvider) { try { requestedWeight = await weightProvider(req, { body: req.body, identity, ip: clientIp, method, path: pathname, policy }); } catch (error) { options.onPolicyError?.(error); if (options.failClosedRateLimitWeight === true) return sendDecision(res, 503, { error: 'ArixShield quota weight could not be calculated.' }); requestedWeight = 1; } }
    const weight = Math.max(1, Math.min(quotaLimit, Math.ceil(Number(requestedWeight) || 1))); let quota;
    try { quota = useGlobalRateLimit ? await distributedTokenBucket({ endpoint, serverKey, scope: `${identity}:${method}:${pathname}`, algorithm: options.rateLimitAlgorithm ?? 'TOKEN_BUCKET', limit: quotaLimit, windowMs: options.rateLimitWindowMs ?? 60000, weight }) : localTokenBucket(cacheKey, quotaLimit, options.rateLimitWindowMs ?? 60000, weight); }
    catch (error) { options.onTelemetryError?.(error); if (options.failOpen === true) quota = localTokenBucket(cacheKey, quotaLimit, 60000, weight); else return sendDecision(res, 503, { error: 'ArixShield distributed quota service is unavailable.' }); }
    const findings = [...inspection.findings];
    if (shadowCatalogEnabled && options.openapiDocument && !isOpenApiOperation(options.openapiDocument, method, pathname)) findings.push({ id: 'SHADOW_API_ROUTE', category: 'SHADOW_API', severity: 'medium', detail: `Observed route is not declared in the supplied OpenAPI document: ${method} ${pathname}`.slice(0, 180) });
    if (options.schema && !['GET', 'HEAD'].includes(method)) { const validation = validatePayloadSchema(body, options.schema); if (!validation.valid) findings.unshift({ id: 'SCHEMA_VALIDATION', category: 'SCHEMA', severity: 'high', detail: validation.errors.slice(0, 3).join('; ').slice(0, 180) }); }
    if (options.requestDlp === true && body && typeof body === 'object' && /application\/json/i.test(String(req.headers?.['content-type'] || ''))) {
      try { const redacted = redactSensitiveText(JSON.stringify(body)); if (redacted.detected.length) { req.body = JSON.parse(redacted.text); findings.unshift({ id: 'REQUEST_DLP_REDACTED', category: 'DLP', severity: 'info', detail: `Redacted request fields matching: ${redacted.detected.slice(0, 8).join(', ')}.` }); } }
      catch (error) { options.onDlpError?.(error); }
    }
    if (!quota.allowed) findings.unshift({ id: 'LOCAL_RATE_LIMIT', category: 'RATE_LIMIT', severity: 'high', detail: 'Configured per-identity quota exceeded.' });
    const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname); const asn = String(req.headers?.['x-vercel-ip-as-number'] ?? '');
    if (policy.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(asn)) findings.unshift({ id: 'DATACENTER_ASN', category: 'DATACENTER', severity: 'high', detail: 'Datacenter ASN policy matched a human-only endpoint.' });
    const effectiveMode = policy.mode === 'DRY_RUN' || mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE'; const enforceableFindings = findings.filter((finding) => finding.category !== 'SHADOW_API' && finding.category !== 'DLP'); const blocked = enforceableFindings.length > 0 && effectiveMode === 'ENFORCE';
    if (blocked) { const retry = findings.some((finding) => finding.category === 'RATE_LIMIT') ? (quota.retryAfterMs || 3000) : 0; if (retry) rememberBlock(cacheKey, retry); if (endpoint) serverAction(endpoint, serverKey, { action: 'server-event', type: 'SDK_THREAT_BLOCK', blocked: true, path: pathname, method, riskScore: inspection.riskScore, findings: findings.slice(0, 20), userId: identity }).catch((error) => options.onTelemetryError?.(error)); return sendDecision(res, findings.some((finding) => finding.category === 'RATE_LIMIT') ? 429 : 403, { error: 'Request blocked by ArixShield local policy.', riskScore: inspection.riskScore, findings: findings.slice(0, 20) }); }
    if ((options.responseDlp === true || options.responseOwnershipGuard === true || options.capabilitySealing === true) && typeof res.json === 'function') {
      const originalJson = res.json.bind(res);
      res.json = function arixSecureJson(payload) {
        let output = payload;
        if (options.responseOwnershipGuard === true && ownershipIdentity) {
          const mismatch = findOwnershipMismatch(output, ownershipIdentity, options.ownershipFields);
          if (mismatch) {
            res.statusCode = 403;
            if (endpoint) serverAction(endpoint, serverKey, { action: 'honeypot', path: pathname, method, actorId: identity, ip: clientIp }).catch((error) => options.onTelemetryError?.(error));
            return originalJson({ error: 'ArixShield blocked a response with mismatched resource ownership.' });
          }
        }
        if (options.capabilitySealing === true && output && typeof output === 'object') {
          try { output = sealResourceIdsInPayload(output, ownershipIdentity); } catch (error) { options.onPolicyError?.(error); res.statusCode = 500; return originalJson({ error: 'Resource capability sealing failed.' }); }
        }
        if (options.responseDlp === true) {
          try { const redacted = redactSensitiveText(JSON.stringify(output)); if (redacted.detected.length) output = JSON.parse(redacted.text); }
          catch (error) { options.onDlpError?.(error); }
        }
        return originalJson(output);
      };
    }
    req.arixShield = { allowed: true, mode: effectiveMode, riskScore: inspection.riskScore, findings, remaining: quota.remaining, goodBot: req.arixShieldGoodBot ?? null };
    const shouldRecordOutcome = endpoint && (options.reportAllRequests === true || abuseEnabled || shadowCatalogEnabled || geoVelocityEnabled || forensicEnabled || findings.length > 0);
    if (shouldRecordOutcome && typeof res.once === 'function') res.once('finish', () => { const geo = getGeoHints(req); const event = { action: 'record-outcome', actorId: identity, userId: identity, ip: clientIp, path: pathname, method, status: res.statusCode, latencyMs: Date.now() - started, ...geo, safeHeaders: safeHeaders(req.headers), findings: findings.slice(0, 20) }; serverAction(endpoint, serverKey, event, 2500).catch((error) => options.onTelemetryError?.(error)); });
    return next();
  };
}

export async function reportEvent({ endpoint, serverKey, type = 'APP_EVENT', path = '/', method = 'GET', blocked = false, riskScore = 0, findings = [], userId = 'anonymous' }) {
  if (!endpoint || !serverKey?.startsWith('ARIX_SECRET_')) throw new Error('ArixShield endpoint and server key are required.'); return serverAction(endpoint, serverKey, { action: 'server-event', type, path, method, blocked, riskScore, findings, userId }, 4000);
}
export async function reportResponseOutcome({ endpoint, serverKey, actorId = 'anonymous', ip = '', path = '/', method = 'GET', status = 200, latencyMs = 0, geo = {}, findings = [] }) {
  if (!endpoint || !serverKey?.startsWith('ARIX_SECRET_')) throw new Error('ArixShield endpoint and server key are required.'); return serverAction(endpoint, serverKey, { action: 'record-outcome', actorId, ip, path, method, status, latencyMs, ...geo, findings }, 4000);
}
export async function watermarkResponseData(payload, context = {}, options = {}) {
  if (!options.endpoint || !options.serverKey) throw new Error('watermarkResponseData requires the ArixShield endpoint and server key.');
  if (!context.sessionId) throw new Error('watermarkResponseData requires context.sessionId for attribution.');
  const material = await serverAction(options.endpoint, options.serverKey, { action: 'watermark-material', sessionId: String(context.sessionId).slice(0, 100), userId: String(context.userId || 'anonymous').slice(0, 100), ip: String(context.ip || '').slice(0, 64), ...(typeof options.canaryRowsEnabled === 'boolean' ? { canaryRowsEnabled: options.canaryRowsEnabled } : {}) }, 5000);
  let output = structuredClone(payload);
  if (material.canaryKey && Array.isArray(output?.data) && output.data.length >= 10) { const suffix = material.canaryKey.slice(-12).toLowerCase(); output.data.splice(Math.floor(output.data.length / 2), 0, { id: `arix_canary_${suffix}`, name: 'ArixShield Canary Record (synthetic)', email: `canary-${suffix}@example.invalid`, canary_api_key: material.canaryKey, synthetic: true }); }
  return watermarkPayloadWithMarker(output, material.marker);
}
export async function getArixPolicy({ endpoint, serverKey, fallback = {} } = {}) { try { return { ...fallback, ...(await remotePolicy(endpoint, serverKey) ?? {}) }; } catch { return fallback; } }
export function redactResponseText(text) { return redactSensitiveText(text); }
export { inspectRequest, redactSensitiveText, validatePayloadSchema };
export { compileOpenApiRequestSchema } from '../api/_lib/schema.js';

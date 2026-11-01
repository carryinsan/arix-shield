import { inspectRequest, redactSensitiveText } from '../api/_lib/waf-engine.js';
import { validatePayloadSchema, isOpenApiOperation } from '../api/_lib/schema.js';
import { watermarkPayloadWithMarker } from '../api/_lib/watermark.js';
import { findOwnershipMismatch, rewriteCapabilityPath, sealResourceIdsInPayload } from '../api/_lib/crypto-trap.js';

const buckets = new Map(); const quotaLeases = new Map(); const policyCache = new Map(); const securitySnapshotCache = new Map(); const reputationCache = new Map(); const blockCache = new Map();
const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);

async function serverAction(options, payload, timeout = 3500) {
  if (!options.endpoint || !options.serverKey) throw new Error('ArixShield endpoint and server key are required.');
  const response = await fetch(`${String(options.endpoint).replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': options.serverKey }, body: JSON.stringify(payload), signal: AbortSignal.timeout(timeout) });
  if (!response.ok) throw new Error(`ArixShield ${payload.action} failed (${response.status}).`); return response.json();
}
async function resolvePolicy(options) {
  if (!options.endpoint || !options.serverKey) return {}; const cacheKey = `${options.endpoint}:${options.serverKey.slice(-10)}`; const cached = policyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 30000) return cached.policy; const data = await serverAction(options, { action: 'get-policy' }, 2500); const policy = data.policy ?? {}; policyCache.set(cacheKey, { at: Date.now(), policy }); securitySnapshotCache.set(cacheKey, { at: Date.now(), projectId: data.projectId, ...(data.snapshot || {}) }); return policy;
}
async function snapshotBlocks(options, identity, ip) {
  const key = `${options.endpoint}:${options.serverKey.slice(-10)}`; const snapshot = securitySnapshotCache.get(key);
  if (!snapshot || Date.now() - snapshot.at >= 30000 || !snapshot.complete || !snapshot.projectId || !globalThis.crypto?.subtle) return null;
  const digest = async (value) => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const actorHash = identity && identity !== 'anonymous' ? await digest(`${snapshot.projectId}:${String(identity).slice(0, 180)}`) : null;
  const ipHash = ip ? await digest(`${snapshot.projectId}:${ip}`) : null;
  return Boolean((actorHash && snapshot.actorHashes?.includes(actorHash)) || (ipHash && snapshot.ipHashes?.includes(ipHash)));
}
function consume(key, limit, windowMs) {
  const now = Date.now(); const bucket = buckets.get(key) ?? { count: 0, start: now }; if (now - bucket.start >= windowMs) { bucket.count = 0; bucket.start = now; } bucket.count++; buckets.set(key, bucket);
  if (buckets.size > 10000) for (const [id, item] of buckets) if (now - item.start > windowMs * 3) buckets.delete(id);
  return { allowed: bucket.count <= limit, remaining: Math.max(0, limit - bucket.count), resetAt: bucket.start + windowMs };
}
async function distributedQuota(options, scope, { algorithm, limit, windowMs, weight, leaseSize = 15 }) {
  const leaseKey = `${options.endpoint}:${options.serverKey.slice(-10)}:${algorithm}:${windowMs}:${scope}`;
  const now = Date.now(); const cached = quotaLeases.get(leaseKey);
  if (cached && cached.expiresAt > now && cached.remaining >= weight && cached.limit === limit) {
    cached.remaining -= weight;
    return { allowed: true, remaining: cached.remaining, retryAfterMs: 0, leased: true };
  }
  quotaLeases.delete(leaseKey);
  const grant = Math.min(limit, Math.max(weight, Math.min(15, Math.floor(Number(leaseSize) || 15))));
  const ask = async (amount) => {
    const data = await serverAction(options, { action: 'check-limit', scope, algorithm, limit, windowMs, weight: amount });
    if (!data?.decision || typeof data.decision.allowed !== 'boolean') throw new Error('ArixShield returned an invalid distributed quota decision.');
    return data.decision;
  };
  let charged = grant; let decision = await ask(grant);
  if (!decision.allowed && grant > weight) { charged = weight; decision = await ask(weight); }
  if (!decision.allowed) return decision;
  const remaining = charged - weight;
  if (remaining > 0) {
    quotaLeases.set(leaseKey, { remaining, expiresAt: now + Math.min(15000, windowMs), limit });
    if (quotaLeases.size > 10000) for (const [key, item] of quotaLeases) if (item.expiresAt <= now) quotaLeases.delete(key);
  }
  return { ...decision, remaining: remaining || decision.remaining, leased: charged > weight };
}
function failure(status, error) { return { allowed: false, status, response: Response.json({ error }, { status }), findings: [] }; }
function isHoneypotPath(pathname, configured) { if (!Array.isArray(configured)) return false; return configured.some((raw) => { if (typeof raw !== 'string' || raw.length > 220) return false; const path = raw.split('?')[0]; return path.endsWith('/*') ? pathname.startsWith(path.slice(0, -1)) : pathname === path; }); }
async function cachedReputation(options, ip, userAgent, provider) {
  const uaClass = /googlebot/i.test(userAgent) ? 'googlebot' : /bingbot/i.test(userAgent) ? 'bingbot' : ''; const key = `${ip}:${provider}:${uaClass}`; const cached = reputationCache.get(key); if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await serverAction(options, { action: 'check-reputation', ip, userAgent, provider }); reputationCache.set(key, { value, expiresAt: Date.now() + 60000 }); if (reputationCache.size > 10000) for (const [id, item] of reputationCache) if (item.expiresAt <= Date.now()) reputationCache.delete(id); return value;
}
function getClientIp(request, options) {
  if (typeof options.getClientIp === 'function') { const value = options.getClientIp(request); return typeof value === 'string' ? value.slice(0, 64) : ''; }
  if (process.env.VERCEL === '1') return String(request.headers.get('x-real-ip') || request.headers.get('x-vercel-forwarded-for') || '').split(',')[0].trim().slice(0, 64);
  return '';
}
function geoHints(request) {
  const lat = Number(request.headers.get('x-vercel-ip-latitude')); const lon = Number(request.headers.get('x-vercel-ip-longitude')); const valid = Number.isFinite(lat) && Number.isFinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
  return { country: request.headers.get('x-vercel-ip-country') || '', city: request.headers.get('x-vercel-ip-city') || '', asn: request.headers.get('x-vercel-ip-as-number') || '', ...(valid ? { latitude: Math.round(lat * 10) / 10, longitude: Math.round(lon * 10) / 10 } : {}) };
}

async function readBoundedRequestText(request, maxBytes) {
  if (!request.body) return { text: '', bytes: 0, tooLarge: false };
  const reader = request.clone().body.getReader();
  const chunks = []; let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        // Request.clone() tees the stream. Cancel both branches; awaiting only
        // the clone branch can hang until the untouched original is cancelled.
        const cancellations = [reader.cancel().catch(() => {})];
        if (request.body) cancellations.push(request.body.cancel().catch(() => {}));
        await Promise.allSettled(cancellations);
        return { text: '', bytes, tooLarge: true };
      }
      chunks.push(value);
    }
  } finally { try { reader.releaseLock(); } catch { /* Reader already released. */ } }
  const buffer = new Uint8Array(bytes); let offset = 0;
  for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
  return { text: new TextDecoder('utf-8', { fatal: true }).decode(buffer), bytes, tooLarge: false };
}

export async function protectRequest(request, options = {}) {
  const method = request.method || 'GET'; const url = request.url || '/'; let pathname = new URL(url).pathname; let body = null; let requestText = '';
  const maxBodyBytes = Math.max(1024, Math.min(262144, Number(options.maxBodyBytes) || 32768));
  if (!['GET', 'HEAD'].includes(method.toUpperCase())) {
    const declaredLength = Number(request.headers.get('content-length') || 0);
    if (declaredLength > maxBodyBytes) return failure(413, 'Request body too large.');
    try {
      const bounded = await readBoundedRequestText(request, maxBodyBytes);
      if (bounded.tooLarge) return failure(413, 'Request body too large.');
      requestText = bounded.text;
      if (requestText) { try { body = JSON.parse(requestText); } catch { body = requestText; } }
    } catch { return failure(400, 'Request body could not be inspected.'); }
  }
  const inspection = inspectRequest({ method, url, headers: request.headers, body, contentLength: request.headers.get('content-length'), maxBodyBytes, maxLeafBytes: options.maxLeafBytes ?? 4096, allowedLongFields: options.allowedLongFields ?? [] });
  if (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length && !(options.endpoint && options.serverKey)) return failure(503, 'Configured honeypotPaths require an ArixShield endpoint.');
  let policy = { mode: options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE', rateLimitPerMinute: options.rateLimitPerMinute ?? 120, blockDatacenterAsn: false, threatFeedEnabled: true };
  if (options.endpoint && options.serverKey) { try { policy = { ...policy, ...(await resolvePolicy(options)) }; } catch (error) { options.onPolicyError?.(error); if (options.failClosedPolicy === true) return failure(503, 'ArixShield policy service is unavailable.'); } }
  const clientIp = getClientIp(request, options);
  const identityValue = typeof options.getIdentity === 'function' ? await options.getIdentity(request, { ip: clientIp, method, path: pathname }) : (options.userId ?? clientIp ?? '');
  const subject = String(identityValue || '').slice(0, 180) || 'anonymous';
  let ownershipIdentity = '';
  if (options.capabilitySealing === true || options.responseOwnershipGuard === true) {
    if (typeof options.getOwnershipIdentity !== 'function') return failure(500, 'A getOwnershipIdentity function is required for capability sealing or the response ownership guard.');
    const ownerValue = await options.getOwnershipIdentity(request, { ip: clientIp, identity: subject });
    ownershipIdentity = String(ownerValue ?? '').trim();
    if (!ownershipIdentity || ownershipIdentity.toLowerCase() === 'anonymous' || ownershipIdentity.length > 180 || ownershipIdentity === clientIp) return failure(500, 'A stable authenticated getOwnershipIdentity is required for this protection.');
  }
  let forwardedRequest = request;
  if (options.capabilitySealing === true) {
    const capability = rewriteCapabilityPath(url, ownershipIdentity, { idPattern: options.capabilityIdPattern });
    if (capability.invalid) return failure(403, 'Invalid or user-mismatched resource capability.');
    if (capability.url !== `${new URL(url).pathname}${new URL(url).search}`) {
      const rewrittenUrl = new URL(url); rewrittenUrl.pathname = capability.url.split('?')[0];
      forwardedRequest = new Request(rewrittenUrl, request);
      pathname = rewrittenUrl.pathname;
    }
  }
  const cacheKey = `${subject}:${method.toUpperCase()}:${pathname}`; const blockedUntil = blockCache.get(cacheKey) || 0;
  if (blockCache.size > 10000) for (const [id, expiry] of blockCache) if (expiry <= Date.now()) blockCache.delete(id); if (blockedUntil > Date.now()) return failure(429, 'Request temporarily rate-limited by ArixShield.'); if (blockedUntil) blockCache.delete(cacheKey);
  const ip = getClientIp(request, options);
  if (isHoneypotPath(pathname, options.honeypotPaths)) { try { const trap = await serverAction(options, { action: 'honeypot', path: pathname, method, actorId: subject, ip }); return { allowed: false, status: 200, response: Response.json(trap, { status: 200 }), findings: [], riskScore: 0, honeypot: true }; } catch (error) { options.onPolicyError?.(error); return failure(503, 'ArixShield honeypot service is unavailable.'); } }
  const abuseEnabled = options.abuseProtection === true || (options.abuseProtection !== false && policy.abuseProtectionEnabled === true);
  if (options.endpoint && options.serverKey && (abuseEnabled || (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length > 0))) {
    const snapshotDenied = await snapshotBlocks(options, subject, ip);
    if (snapshotDenied === true) { blockCache.set(cacheKey, Date.now() + 30000); return failure(429, 'ArixShield credential-abuse backoff is active.'); }
    if (snapshotDenied === null) { try { const abuse = await serverAction(options, { action: 'check-abuse', actorId: subject, ip }); if (abuse.blocked) { blockCache.set(cacheKey, Date.now() + Math.max(1000, Math.min(30000, abuse.retryAfterMs || 3000))); return failure(429, 'ArixShield credential-abuse backoff is active.'); } }
    catch (error) { options.onPolicyError?.(error); if (options.failClosedAbuse === true) return failure(503, 'ArixShield abuse service is unavailable.'); }
    }
  }
  const reputationEnabled = options.reputationProtection === true || (options.reputationProtection !== false && policy.threatFeedEnabled !== false);
  if (options.endpoint && options.serverKey && reputationEnabled && ip) { try { const reputation = await cachedReputation(options, ip, (request.headers.get('user-agent') || '').slice(0, 240), options.trustedProvider || ''); if (reputation.reputation?.checked && reputation.reputation.listed && reputation.crawler?.verified !== true && reputation.configuredProvider?.verified !== true && policy.mode !== 'DRY_RUN' && options.mode !== 'DRY_RUN') return failure(403, 'Request blocked by ArixShield IP reputation policy.'); } catch (error) { options.onPolicyError?.(error); if (options.failClosedReputation === true) return failure(503, 'ArixShield reputation service is unavailable.'); } }
  let quota; const quotaLimit = Math.max(1, Math.min(10000, Number(policy.rateLimitPerMinute) || 120)); let requestedWeight = options.rateLimitWeight ?? 1; const weightProvider = options.getRateLimitWeight || (typeof requestedWeight === 'function' ? requestedWeight : null);
  if (weightProvider) { try { requestedWeight = await weightProvider(request, { body, identity: subject, ip, method, path: pathname, policy }); } catch (error) { options.onPolicyError?.(error); if (options.failClosedRateLimitWeight === true) return failure(503, 'ArixShield quota weight could not be calculated.'); requestedWeight = 1; } }
  const weight = Math.max(1, Math.min(quotaLimit, Math.ceil(Number(requestedWeight) || 1)));
  try { const useGlobalRateLimit = options.globalRateLimit !== false && Boolean(options.endpoint && options.serverKey); quota = useGlobalRateLimit ? await distributedQuota(options, `${subject}:${method.toUpperCase()}:${pathname}`, { algorithm: options.rateLimitAlgorithm ?? 'TOKEN_BUCKET', limit: quotaLimit, windowMs: options.rateLimitWindowMs ?? 60000, weight, leaseSize: options.quotaLeaseSize ?? 15 }) : consume(cacheKey, quotaLimit, options.rateLimitWindowMs ?? 60000); if (!quota || typeof quota.allowed !== 'boolean') throw new Error('ArixShield returned an invalid distributed quota decision.'); }
  catch (error) { options.onPolicyError?.(error); if (options.failOpen === true) quota = consume(cacheKey, quotaLimit, 60000); else return failure(503, 'ArixShield distributed quota service is unavailable.'); }
  const findings = [...inspection.findings]; const shadowCatalogEnabled = options.shadowApiCatalog === true || (options.shadowApiCatalog !== false && policy.shadowApiCatalogEnabled === true);
  if (shadowCatalogEnabled && options.openapiDocument && !isOpenApiOperation(options.openapiDocument, method, pathname)) findings.push({ id: 'SHADOW_API_ROUTE', category: 'SHADOW_API', severity: 'medium', detail: `Observed route is not declared in the supplied OpenAPI document: ${method} ${pathname}`.slice(0, 180) });
  if (options.schema && !['GET', 'HEAD'].includes(method.toUpperCase())) { const validation = validatePayloadSchema(body, options.schema); if (!validation.valid) findings.unshift({ id: 'SCHEMA_VALIDATION', category: 'SCHEMA', severity: 'high', detail: validation.errors.slice(0, 3).join('; ').slice(0, 180) }); }
  if (options.requestDlp === true && body && typeof body === 'object' && !Array.isArray(body) && /application\/json/i.test(request.headers.get('content-type') || '')) { try { const redacted = redactSensitiveText(JSON.stringify(body)); if (redacted.detected.length) { const headers = new Headers((forwardedRequest || request).headers); headers.delete('content-length'); forwardedRequest = new Request(forwardedRequest || request, { body: redacted.text, headers, duplex: 'half' }); findings.unshift({ id: 'REQUEST_DLP_REDACTED', category: 'DLP', severity: 'info', detail: `Redacted request fields matching: ${redacted.detected.slice(0, 8).join(', ')}.` }); } } catch (error) { options.onDlpError?.(error); } }
  if (!quota.allowed) findings.unshift({ id: 'LOCAL_RATE_LIMIT', category: 'RATE_LIMIT', severity: 'high', detail: 'Configured request quota exceeded.' });
  const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname); if (policy.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(request.headers.get('x-vercel-ip-as-number') || '')) findings.unshift({ id: 'DATACENTER_ASN', category: 'DATACENTER', severity: 'high', detail: 'Datacenter ASN policy matched a human-only endpoint.' });
  const effectiveMode = policy.mode === 'DRY_RUN' || options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE'; const enforceableFindings = findings.filter((finding) => finding.category !== 'SHADOW_API' && finding.category !== 'DLP'); const blocked = enforceableFindings.length > 0 && effectiveMode === 'ENFORCE';
  if (blocked) { if (findings.some((finding) => finding.category === 'RATE_LIMIT')) blockCache.set(cacheKey, Date.now() + Math.max(1000, Math.min(30000, quota.retryAfterMs || 3000))); if (options.endpoint && options.serverKey) serverAction(options, { action: 'server-event', type: 'SDK_THREAT_BLOCK', blocked: true, path: pathname, method, riskScore: inspection.riskScore, findings: findings.slice(0, 20), userId: subject }).catch((error) => options.onPolicyError?.(error)); const status = findings.some((finding) => finding.category === 'RATE_LIMIT') ? 429 : 403; return { allowed: false, status, response: Response.json({ error: 'Request blocked by ArixShield.', findings, riskScore: inspection.riskScore }, { status }), findings, riskScore: inspection.riskScore }; }
  return { allowed: true, status: 200, findings, riskScore: inspection.riskScore, remaining: quota.remaining, policy: effectiveMode, actorId: subject, ip, geo: geoHints(request), path: pathname, method, forwardedRequest, identity: subject, clientIp: ip, ownershipIdentity, reportOutcome: Boolean(options.reportAllRequests === true || abuseEnabled || options.shadowApiCatalog === true || policy.shadowApiCatalogEnabled === true || options.geoVelocityProtection === true || policy.geoVelocityEnabled === true || options.forensicReplay === true || policy.forensicReplayEnabled === true || findings.length > 0) };
}

export async function reportResponseOutcome(request, response, options = {}) {
  if (!options.endpoint || !options.serverKey?.startsWith('ARIX_SECRET_')) throw new Error('ArixShield endpoint and server key are required.'); const decision = options.decision || {};
  return serverAction(options, { action: 'record-outcome', actorId: decision.actorId || options.userId || 'anonymous', ip: decision.ip || getClientIp(request, options), path: decision.path || new URL(request.url).pathname, method: request.method, status: response.status, latencyMs: Math.max(0, Number(options.latencyMs) || 0), ...(decision.geo || geoHints(request)), safeHeaders: { accept: request.headers.get('accept') || '', 'content-type': request.headers.get('content-type') || '', 'user-agent': (request.headers.get('user-agent') || '').slice(0, 180), 'x-request-id': (request.headers.get('x-request-id') || '').slice(0, 180) }, findings: decision.findings || [] });
}
export function withArixShield(handler, options = {}) {
  if (typeof handler !== 'function') throw new TypeError('withArixShield expects a request handler.');
  return async function arixProtectedRoute(request, context) {
    const started = Date.now(); const decision = await protectRequest(request, options); if (!decision.allowed) return decision.response; let response;
    try { response = await handler(decision.forwardedRequest || request, { ...context, arixDecision: decision }); }
    catch (error) { if (decision.reportOutcome) { const report = reportResponseOutcome(request, new Response(null, { status: 500 }), { ...options, decision, latencyMs: Date.now() - started }).catch((reportError) => options.onPolicyError?.(reportError)); if (typeof options.waitUntil === 'function') options.waitUntil(report); } throw error; }
    if (response instanceof Response && /application\/json/i.test(response.headers.get('content-type') || '') && (options.responseDlp === true || options.responseOwnershipGuard === true || options.capabilitySealing === true)) {
      try {
        let output = await response.clone().json();
        const ownershipIdentity = decision.ownershipIdentity;
        if (options.responseOwnershipGuard === true && ownershipIdentity) {
          const mismatch = findOwnershipMismatch(output, ownershipIdentity, options.ownershipFields);
          if (mismatch) {
            if (options.endpoint && options.serverKey) { const ban = serverAction(options, { action: 'honeypot', path: new URL(request.url).pathname, method: request.method, actorId: decision.identity, ip: decision.clientIp }).catch((error) => options.onPolicyError?.(error)); if (typeof options.waitUntil === 'function') options.waitUntil(ban); }
            return Response.json({ error: 'ArixShield blocked a response with mismatched resource ownership.' }, { status: 403, headers: { 'Cache-Control': 'no-store' } });
          }
        }
        if (options.capabilitySealing === true && output && typeof output === 'object') output = sealResourceIdsInPayload(output, ownershipIdentity);
        if (options.responseDlp === true) output = redactResponseData(output);
        if (options.responseDlp === true || options.capabilitySealing === true) {
          const headers = new Headers(response.headers); headers.delete('content-length');
          response = new Response(JSON.stringify(output), { status: response.status, statusText: response.statusText, headers });
        }
      } catch (error) {
        options.onDlpError?.(error);
        if (options.capabilitySealing === true || options.responseOwnershipGuard === true) return Response.json({ error: 'ArixShield response security processing failed.' }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
      }
    }
    if (decision.reportOutcome) { const report = reportResponseOutcome(request, response, { ...options, decision, latencyMs: Date.now() - started }).catch((error) => options.onPolicyError?.(error)); if (typeof options.waitUntil === 'function') options.waitUntil(report); }
    return response;
  };
}
export async function watermarkResponseData(payload, context = {}, options = {}) {
  if (!options.endpoint || !options.serverKey) throw new Error('watermarkResponseData requires the ArixShield endpoint and server key.'); if (!context.sessionId) throw new Error('watermarkResponseData requires context.sessionId for attribution.');
  const material = await serverAction(options, { action: 'watermark-material', sessionId: String(context.sessionId).slice(0, 100), userId: String(context.userId || 'anonymous').slice(0, 100), ip: String(context.ip || '').slice(0, 64), ...(typeof options.canaryRowsEnabled === 'boolean' ? { canaryRowsEnabled: options.canaryRowsEnabled } : {}) }, 5000);
  let output = structuredClone(payload); if (material.canaryKey && Array.isArray(output?.data) && output.data.length >= 10) { const suffix = material.canaryKey.slice(-12).toLowerCase(); output.data.splice(Math.floor(output.data.length / 2), 0, { id: `arix_canary_${suffix}`, name: 'ArixShield Canary Record (synthetic)', email: `canary-${suffix}@example.invalid`, canary_api_key: material.canaryKey, synthetic: true }); }
  return watermarkPayloadWithMarker(output, material.marker);
}
export function redactResponseData(payload) { try { const serialized = JSON.stringify(payload); const redacted = redactSensitiveText(serialized); return redacted.detected.length ? JSON.parse(redacted.text) : payload; } catch { return payload; } }
export { redactSensitiveText, validatePayloadSchema };
export { compileOpenApiRequestSchema } from '../api/_lib/schema.js';

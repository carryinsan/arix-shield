import { inspectRequest, redactSensitiveText } from '../api/_lib/waf-engine.js';
import { authorizeRequest, filterReadFields, filterWriteFields, isMutatingMethod, normalizeSecurityPath, scopeQuery } from '../api/_lib/authorization.js';
import { rewriteCapabilityRequest } from '../api/_lib/crypto-trap.js';
import { validateClearanceRequest, routeRequiresClearance, quotaDimensions, makeOutageChallenge, verifyOutageProof, validateWorkflowRequest } from './security-runtime.js';
import { randomUUID } from 'node:crypto';
import { sanitizeArixIdentity } from './identity.js';
import { runWithArixContext, hasScopedDataReceipt } from './context.js';
import { validateOpenApiRequest } from '../api/_lib/schema.js';
import { verifySignedToken, verifyRequestDpopProof, sha256Hex, createSignedToken } from '../api/_lib/crypto-trap.js';
import { formatIpPrefix } from '../api/_lib/cidr.js';
import { runWithCircuit } from '../api/_lib/circuit-breaker.js';
import { arixSafeFetch } from './safe-fetch.js';
import { validatePayloadSchema, isOpenApiOperation } from '../api/_lib/schema.js';
import { watermarkPayloadWithMarker, spliceCanaryRow, getChameleonRowIdentifier } from '../api/_lib/watermark.js';
import { findOwnershipMismatch, rewriteCapabilityPath, sealResourceIdsInPayload } from '../api/_lib/crypto-trap.js';
import { buildLocalQuotaDimensions, localNetworkPrefix, processLocalQuotaStore } from './local-rate-limit.js';

const quotaLeases = new Map(); const policyCache = new Map(); const securitySnapshotCache = new Map(); const reputationCache = new Map(); const blockCache = new Map(); const keyEpochCache = new Map();
const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);

function cacheIdentity(options) { return `${String(options.endpoint || '')}:${String(options.serverKey || '').slice(-10)}`; }
function applyKeyEpoch(options, epoch) {
  const key = cacheIdentity(options);
  if (!Number.isFinite(Number(epoch))) return;
  const next = Number(epoch);
  const previous = keyEpochCache.get(key);
  if (previous !== undefined && previous !== next) {
    policyCache.delete(key);
    securitySnapshotCache.delete(key);
    for (const id of quotaLeases.keys()) if (id.startsWith(`${key}:`)) quotaLeases.delete(id);
  }
  keyEpochCache.set(key, next);
}
async function serverAction(options, payload, timeout = 3500) {
  if (!options.endpoint || !options.serverKey) throw new Error('ArixShield endpoint and server key are required.');
  const base = `${String(options.endpoint).replace(/\/$/, '')}/api/shield`;
  const response = await runWithCircuit(`sdk:${cacheIdentity(options)}`, async (signal) => fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': options.serverKey }, body: JSON.stringify(payload), signal }), { tripAfterMs: 450, timeoutMs: Math.max(450, Math.min(5000, Number(timeout) || 3500)), openMs: 10000, failureThreshold: 3 });
  if (response.headers.has('x-arix-epoch')) applyKeyEpoch(options, Number(response.headers.get('x-arix-epoch')));
  if (!response.ok) throw new Error(`ArixShield ${payload.action} failed (${response.status}).`);
  return response.json();
}
async function resolvePolicy(options) {
  if (!options.endpoint || !options.serverKey) return {};
  const cacheKey = cacheIdentity(options); const cached = policyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 30000) return cached.policy;
  const data = await serverAction(options, { action: 'get-policy' }, 2500);
  applyKeyEpoch(options, data.keyEpoch);
  const policy = data.policy ?? {};
  policyCache.set(cacheKey, { at: Date.now(), policy });
  securitySnapshotCache.set(cacheKey, { at: Date.now(), projectId: data.projectId, keyEpoch: Number(data.keyEpoch) || 0, ...(data.snapshot || {}) });
  return policy;
}

async function snapshotBlocks(options, identity, _ip) {
  const key = `${options.endpoint}:${options.serverKey.slice(-10)}`; const snapshot = securitySnapshotCache.get(key);
  if (!snapshot || Date.now() - snapshot.at >= 30000 || !snapshot.complete || !snapshot.projectId || !globalThis.crypto?.subtle) return null;
  const digest = async (value) => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const actorHash = identity && identity !== 'anonymous' ? await digest(`${snapshot.projectId}:${String(identity).slice(0, 180)}`) : null;
  return Boolean(actorHash && snapshot.actorHashes?.includes(actorHash));
}
async function distributedQuota(options, scope, { algorithm, limit, windowMs, weight, leaseSize = 15, dimensions = null }) {
  const leaseKey = `${options.endpoint}:${options.serverKey.slice(-10)}:${algorithm}:${windowMs}:${scope}`;
  const now = Date.now(); const cached = quotaLeases.get(leaseKey);
  if (cached && cached.expiresAt > now && cached.remaining >= weight && cached.limit === limit) {
    cached.remaining -= weight;
    return { allowed: true, remaining: cached.remaining, retryAfterMs: 0, leased: true };
  }
  quotaLeases.delete(leaseKey);
  const grant = Math.min(limit, Math.max(weight, Math.min(15, Math.floor(Number(leaseSize) || 15))));
  const ask = async (amount) => {
    const data = await serverAction(options, { action: 'check-limit', scope, algorithm, limit, windowMs, weight: amount, ...(dimensions ? { dimensions } : {}) });
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
const BUILTIN_GHOST_PATHS = Object.freeze(['/.env', '/api/v1/admin/export', '/api/debug/config', '/graphql/schema']);
function isHoneypotPath(pathname, configured) {
  const routes = [...BUILTIN_GHOST_PATHS, ...(Array.isArray(configured) ? configured : [])];
  return routes.some((raw) => { if (typeof raw !== 'string' || raw.length > 220) return false; const path = raw.split('?')[0]; return path.endsWith('/*') ? pathname.startsWith(path.slice(0, -1)) : pathname === path; });
}
async function cachedReputation(options, ip, userAgent, provider, actorId = 'anonymous', asn = '', path = '/') {
  const uaClass = /googlebot/i.test(userAgent) ? 'googlebot' : /bingbot/i.test(userAgent) ? 'bingbot' : '';
  const key = `${ip}:${provider}:${uaClass}:${actorId}:${asn}:${path}`; const cached = reputationCache.get(key); if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await serverAction(options, { action: 'check-reputation', ip, userAgent, provider, actorId, asn, path });
  reputationCache.set(key, { value, expiresAt: Date.now() + 10000 });
  if (reputationCache.size > 10000) for (const [id, item] of reputationCache) if (item.expiresAt <= Date.now()) reputationCache.delete(id);
  return value;
}
function getClientIp(request, options) {
  if (typeof options.getClientIp === 'function') { const value = options.getClientIp(request); return typeof value === 'string' ? value.slice(0, 64) : ''; }
  if (process.env.VERCEL === '1') {
    const raw = request.headers.get('x-real-ip') || '';
    if (raw && raw === raw.trim() && !raw.includes(',') && localNetworkPrefix(raw) !== 'unknown') return raw;
  }
  // Self-hosted deployments must provide getClientIp from a trusted ingress.
  // Without one, anonymous traffic shares the conservative `unknown` bucket.
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
  return { text: new TextDecoder('utf-8', { fatal: true }).decode(buffer), rawBytes: buffer, bytes, tooLarge: false };
}

export async function protectRequest(request, options = {}) {
  const method = String(request.method || 'GET').toUpperCase();
  const originalUrl = request.url || '/';
  let parsedUrl;
  try { parsedUrl = new URL(originalUrl); } catch { return failure(400, 'Invalid request URL.'); }
  let pathname = normalizeSecurityPath(parsedUrl.pathname);
  if (!pathname) return failure(400, 'Invalid or ambiguous request path.');
  let body = null; let requestText = ''; let rawBodyBytes = new Uint8Array();
  const maxBodyBytes = Math.max(1024, Math.min(262144, Number(options.maxBodyBytes) || 32768));
  if (!['GET', 'HEAD'].includes(method)) {
    const declaredLength = Number(request.headers.get('content-length') || 0);
    if (declaredLength > maxBodyBytes) return failure(413, 'Request body too large.');
    try {
      const bounded = await readBoundedRequestText(request, maxBodyBytes);
      if (bounded.tooLarge) return failure(413, 'Request body too large.');
      requestText = bounded.text; rawBodyBytes = bounded.rawBytes || new Uint8Array();
      if (requestText) { try { body = JSON.parse(requestText); } catch { body = requestText; } }
    } catch { return failure(400, 'Request body could not be inspected.'); }
  }
  const clientIp = getClientIp(request, options);
  const identityValue = typeof options.getIdentity === 'function'
    ? await options.getIdentity(request, { ip: clientIp, method, path: pathname })
    : (options.userId ?? '');
  const subject = sanitizeArixIdentity(identityValue, clientIp) || 'anonymous';
  // Do not put every anonymous visitor into the same actor quota/ban bucket.
  let securityActor = subject === 'anonymous' ? `anonymous:${randomUUID()}` : subject;
  let dpopVerified = false;
  let resourceCapabilityVerified = false;
  const authProvider = options.getAuthorizationContext || options.getAuthContext;
  let authContext = {};
  if (typeof authProvider === 'function') {
    try { authContext = await authProvider(request, { ip: clientIp, identity: subject, method, pathname }) || {}; }
    catch (error) { options.onPolicyError?.(error); return failure(403, 'Authorization context could not be established.'); }
  }
  const authUserId = String(authContext.userId || authContext.ownerId || (subject !== 'anonymous' ? subject : '')).trim();
  if (authUserId) securityActor = `user:${authUserId}`;
  let tenantId = String(authContext.tenantId || authContext.projectId || options.tenantId || options.projectId || '').trim();
  if (!tenantId && typeof options.getTenantIdentity === 'function') {
    try { tenantId = String(await options.getTenantIdentity(request, authContext) || '').trim(); }
    catch (error) { options.onPolicyError?.(error); return failure(403, 'Tenant context could not be established.'); }
  }
  authContext = { ...authContext, userId: authUserId, tenantId, projectId: authContext.projectId || tenantId };
  let projectId = String(options.projectId || authContext.projectId || tenantId || '');

  const authorizationConfig = options.authorization || {};
  const authz = await authorizeRequest({
    method, pathname,
    routes: authorizationConfig.routes || options.authorizationMap || options.authorizationRoutes,
    context: authContext,
    defaultDenyMutations: authorizationConfig.defaultDenyMutations === true || options.mutationTripwire === true,
    requireScopedPrecheck: options.mutationTripwire === true, preCheck: authorizationConfig.preCheck || options.authorizationPreCheck, request
  });
  if (!authz.allowed) return failure(403, `Request authorization denied (${authz.reason || 'POLICY'}).`);
  const roles = authz.context?.roles || (Array.isArray(authContext.roles) ? authContext.roles : authContext.role ? [authContext.role] : []);

  let ownershipIdentity = null;
  if (options.capabilitySealing === true || options.responseOwnershipGuard === true) {
    let ownerValue = authUserId;
    if (typeof options.getOwnershipIdentity === 'function') {
      try { ownerValue = await options.getOwnershipIdentity(request, { ip: clientIp, identity: subject, authContext }); }
      catch (error) { options.onPolicyError?.(error); return failure(500, 'Ownership identity could not be established.'); }
    }
    const userId = String(ownerValue || '').trim();
    if (!userId || userId.toLowerCase() === 'anonymous' || userId.length > 180 || userId === clientIp || !tenantId) return failure(500, 'Capability sealing requires authenticated user and tenant identities.');
    ownershipIdentity = { tenantId, userId };
  }

  let forwardedRequest = request;
  const writeFieldPolicy = authorizationConfig.allowedWriteFields || options.allowedWriteFields;
  if (writeFieldPolicy && body && typeof body === 'object') {
    const filtered = filterWriteFields(body, writeFieldPolicy, roles);
    body = filtered;
  }

  let openApiArrayFields = [];
  if (options.openapiDocument) {
    const operation = options.openapiDocument.paths?.[pathname]?.[method.toLowerCase()];
    const params = [...(options.openapiDocument.paths?.[pathname]?.parameters || []), ...(operation?.parameters || [])];
    openApiArrayFields = params.filter((param) => String(param.in).toLowerCase() === 'query' && param.schema?.type === 'array').map((param) => String(param.name).toLowerCase());
  }
  if (options.capabilitySealing === true) {
    const capability = rewriteCapabilityRequest(originalUrl, body, ownershipIdentity, { idPattern: options.capabilityIdPattern, method, arrayQueryFields: openApiArrayFields });
    resourceCapabilityVerified = capability.capabilityVerified === true;
    if (capability.invalid) return failure(403, 'Invalid or user-mismatched resource capability.');
    body = capability.body;
    const rewrittenUrl = new URL(capability.url, parsedUrl.origin);
    pathname = normalizeSecurityPath(rewrittenUrl.pathname);
    if (!pathname) return failure(403, 'Invalid resource path.');
    if (body !== null && !['GET', 'HEAD'].includes(method)) {
      const headers = new Headers(request.headers); headers.delete('content-length');
      forwardedRequest = new Request(rewrittenUrl, { method, headers, body: typeof body === 'string' ? body : JSON.stringify(body), signal: request.signal });
    } else if (`${rewrittenUrl.pathname}${rewrittenUrl.search}` !== `${parsedUrl.pathname}${parsedUrl.search}`) {
      forwardedRequest = new Request(rewrittenUrl, request);
    }
  } else if (writeFieldPolicy && body && typeof body === 'object') {
    const headers = new Headers(request.headers); headers.delete('content-length');
    forwardedRequest = new Request(request.url, { method, headers, body: JSON.stringify(body), signal: request.signal });
  }

  const inspection = inspectRequest({ method, url: originalUrl, headers: request.headers, httpVersion: request.httpVersion || '', body, rawBody: rawBodyBytes, rawHeaders: request.headers.raw?.() || null, contentLength: request.headers.get('content-length'), maxBodyBytes, maxLeafBytes: options.maxLeafBytes ?? 4096, allowedLongFields: options.allowedLongFields ?? [], allowedQueryArrayFields: openApiArrayFields, production: process.env.NODE_ENV === 'production' });
  if (inspection.findings.some((item) => ['HTTP_SMUGGLING_HEADERS', 'HTTP_HEADER_INJECTION', 'HTTP2_CONNECTION_SPECIFIC_HEADER', 'JSON_DUPLICATE_KEY', 'HTTP_PARAMETER_POLLUTION', 'URL_PATH_NORMALIZATION', 'JSON_MALFORMED', 'XML_DTD_XXE'].includes(item.id))) return failure(400, 'Request parser consistency check failed.');
  if (options.strictOpenApi === true && options.openapiDocument) {
    const validation = validateOpenApiRequest(options.openapiDocument, { method, url: originalUrl, headers: request.headers, body });
    if (!validation.valid) return failure(400, 'Request does not match the declared OpenAPI contract.');
  }
  if (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length && !(options.endpoint && options.serverKey)) return failure(503, 'Configured honeypotPaths require an ArixShield endpoint.');

  let policy = { mode: options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE', rateLimitPerMinute: options.rateLimitPerMinute ?? 120, blockDatacenterAsn: false, threatFeedEnabled: true };
  if (options.endpoint && options.serverKey) {
    try { policy = { ...policy, ...(await resolvePolicy(options)) }; }
    catch (error) { options.onPolicyError?.(error); if (options.failClosedPolicy !== false) return failure(503, 'ArixShield policy service is unavailable.'); }
  }

  if (policy.deceptionEnabled !== false && isHoneypotPath(pathname, options.honeypotPaths)) {
    if (!options.endpoint || !options.serverKey) return failure(404, 'Not found.');
    try {
      const trap = await serverAction(options, { action: 'honeypot', path: pathname, method, actorId: securityActor, ip: clientIp, ja4: process.env.VERCEL === '1' ? String(request.headers.get('x-vercel-ja4-digest') || '').slice(0, 160) : '' });
      return { allowed: false, status: 200, response: Response.json(trap, { status: 200, headers: { 'Cache-Control': 'no-store' } }), findings: [], riskScore: 0, honeypot: true };
    } catch (error) { options.onPolicyError?.(error); return failure(404, 'Not found.'); }
  }

  let flowState = null;
  if (options.workflow?.enabled === true) {
    const snapshot = securitySnapshotCache.get(cacheIdentity(options));
    const flowProjectId = String(options.projectId || snapshot?.projectId || authContext.projectId || tenantId || '');
    flowState = await validateWorkflowRequest({
      config: options.workflow, method, pathname, headers: request.headers,
      projectId: flowProjectId, tenantId, actorId: authUserId || subject,
      consumeNonce: async (nonce) => (await serverAction(options, { action: 'consume-flow', nonce })).consumed === true
    });
    if (!flowState.valid) return failure(flowState.unavailable ? 503 : 403, 'Signed workflow step validation failed.');
  }

  if (routeRequiresClearance(pathname, options.botProtection)) {
    if (!options.endpoint || !options.serverKey) return failure(503, 'Server-enforced browser clearance requires ArixShield control-plane connectivity.');
    const snapshot = securitySnapshotCache.get(cacheIdentity(options));
    projectId = String(options.projectId || snapshot?.projectId || projectId || '');
    if (!projectId) return failure(503, 'ArixShield project identity is unavailable.');
    const clearance = await validateClearanceRequest({
      headers: request.headers, method, url: originalUrl, bodyBytes: rawBodyBytes,
      projectId, clientIp,
      botProtection: options.botProtection || {},
      consumeSingleUse: async (nonce) => (await serverAction(options, { action: 'consume-clearance', nonce })).consumed === true,
      consumeProofReplay: async (jtiHash) => (await serverAction(options, { action: 'consume-dpop', nonce: jtiHash })).consumed === true
    });
    if (!clearance.valid) return failure(clearance.unavailable ? 503 : 403, 'Valid single-use browser clearance and request-bound DPoP are required.');
    dpopVerified = true;
    if (subject === 'anonymous' && !authUserId && clearance.thumbprint) securityActor = `device:${clearance.thumbprint}`;
  }

  const blockActor = subject === 'anonymous' && !authUserId ? `network:${localNetworkPrefix(clientIp)}` : securityActor;
  const cacheKey = `${blockActor}:${method}:${pathname}`; const blockedUntil = blockCache.get(cacheKey) || 0;
  if (blockCache.size > 10000) for (const [id, expiry] of blockCache) if (expiry <= Date.now()) blockCache.delete(id);
  if (blockedUntil > Date.now()) return failure(429, 'Request temporarily rate-limited by ArixShield.');
  if (blockedUntil) blockCache.delete(cacheKey);
  const ip = clientIp;
  const abuseEnabled = options.abuseProtection === true || (options.abuseProtection !== false && policy.abuseProtectionEnabled === true);
  if (options.endpoint && options.serverKey && (abuseEnabled || (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length > 0))) {
    const snapshotDenied = await snapshotBlocks(options, securityActor, ip);
    if (snapshotDenied === true) { blockCache.set(cacheKey, Date.now() + 30000); return failure(429, 'ArixShield credential-abuse backoff is active.'); }
    if (snapshotDenied === null) {
      try { const abuse = await serverAction(options, { action: 'check-abuse', actorId: securityActor, ip }); if (abuse.blocked) { blockCache.set(cacheKey, Date.now() + Math.max(1000, Math.min(30000, abuse.retryAfterMs || 3000))); return failure(429, 'ArixShield credential-abuse backoff is active.'); } }
      catch (error) { options.onPolicyError?.(error); if (options.failClosedAbuse === true) return failure(503, 'ArixShield abuse service is unavailable.'); }
    }
  }
  const reputationEnabled = options.reputationProtection === true || (options.reputationProtection !== false && policy.threatFeedEnabled !== false);
  if (options.endpoint && options.serverKey && reputationEnabled && ip) {
    try {
      const asn = String(request.headers.get('x-vercel-ip-as-number') || '').slice(0, 16);
      const reputation = await cachedReputation(options, ip, (request.headers.get('user-agent') || '').slice(0, 240), options.trustedProvider || '', securityActor, asn, pathname);
      const verifiedCrawler = reputation.crawler?.verified === true || reputation.configuredProvider?.verified === true;
      const enforce = policy.mode !== 'DRY_RUN' && options.mode !== 'DRY_RUN';
      if (!verifiedCrawler && enforce && reputation.action === 'block') return failure(403, 'Request blocked by actor-specific ArixShield reputation policy.');
      if (!verifiedCrawler && enforce && reputation.action === 'challenge') return { allowed: false, status: 428, response: Response.json({ error: 'Additional verification is required.', stepUpRequired: true, challengeType: 'browser-clearance', threatConfidence: reputation.threatConfidence, staleFeedWarning: reputation.staleFeedWarning === true }, { status: 428, headers: { 'Cache-Control': 'no-store' } }), findings: [] };
      const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname);
      if (enforce && policy.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(asn) && (!subject || subject.toLowerCase() === 'anonymous')) return { allowed: false, status: 428, response: Response.json({ error: 'Additional verification is required for this anonymous datacenter request.', stepUpRequired: true, challengeType: 'browser-clearance', threatConfidence: 20 }, { status: 428, headers: { 'Cache-Control': 'no-store' } }), findings: [] };
    } catch (error) { options.onPolicyError?.(error); if (options.failClosedReputation === true) return failure(503, 'ArixShield reputation service is unavailable.'); }
  }
  let requestedWeight = options.rateLimitWeight ?? 1; const weightProvider = options.getRateLimitWeight || (typeof requestedWeight === 'function' ? requestedWeight : null);
  if (weightProvider) { try { requestedWeight = await weightProvider(request, { body, identity: subject, ip, method, path: pathname, policy }); } catch (error) { options.onPolicyError?.(error); if (options.failClosedRateLimitWeight === true) return failure(503, 'ArixShield quota weight could not be calculated.'); requestedWeight = 1; } }
  const baseQuotaLimit = Math.max(1, Math.min(10000, Number(policy.rateLimitPerMinute) || 120));
  const trustMultiplier = dpopVerified ? (authUserId ? 4 : 2.5) : 1;
  const quotaLimit = Math.max(1, Math.min(10000, Math.floor(baseQuotaLimit * trustMultiplier)));
  const weight = Math.max(1, Math.min(quotaLimit, Math.ceil(Number(requestedWeight) || 1)));
  const dimensions = quotaDimensions({ actor: securityActor, subnet: formatIpPrefix(ip), tenant: tenantId || projectId || cacheIdentity(options), method, pathname, limit: quotaLimit });
  const localDimensions = buildLocalQuotaDimensions({
    scope: `${String(options.endpoint || '')}\0${String(options.serverKey || '')}\0${tenantId || projectId || ''}`,
    identity: subject, actorIdentity: securityActor, authenticated: Boolean(authUserId || subject !== 'anonymous'),
    networkIp: ip, method, pathname, dpopVerified, actorLimit: quotaLimit, routeLimit: quotaLimit,
    networkLimit: Math.max(quotaLimit, Math.min(100000, Math.floor(Number(options.anonymousNetworkRateLimitPerMinute) || baseQuotaLimit * 10)))
  });
  let quota;
  try {
    const useGlobalRateLimit = options.globalRateLimit !== false && Boolean(options.endpoint && options.serverKey);
    quota = useGlobalRateLimit ? await distributedQuota(options, `${securityActor}:${method}:${pathname}`, { algorithm: options.rateLimitAlgorithm ?? 'TOKEN_BUCKET', limit: quotaLimit, windowMs: options.rateLimitWindowMs ?? 60000, weight, leaseSize: options.quotaLeaseSize ?? 15, dimensions }) : processLocalQuotaStore.consume(localDimensions, options.rateLimitWindowMs ?? 60000, weight);
    if (!quota || typeof quota.allowed !== 'boolean') throw new Error('ArixShield returned an invalid distributed quota decision.');
  } catch (error) {
    options.onPolicyError?.(error);
    const lowRiskRead = method === 'GET' && (/\/(?:docs|catalog)(?:\/|$)/i.test(pathname));
    if (!lowRiskRead || !options.endpoint || !options.serverKey) return failure(503, 'ArixShield distributed quota service is unavailable.');
    const powHeader = request.headers.get('x-arix-outage-pow');
    const outageProject = String(options.projectId || cacheIdentity(options) || 'default');
    const outageRequester = formatIpPrefix(ip) || 'unknown';
    const outageWindowMs = options.rateLimitWindowMs ?? 60000;
    const outageProof = await verifyOutageProof(powHeader, method, pathname, {
      projectId: outageProject,
      requesterKey: outageRequester,
      quotaKey: `${outageProject}:${outageRequester}:${subject}:degraded-read`,
      limit: quotaLimit,
      windowMs: outageWindowMs
    });
    if (!outageProof.valid) {
      if (outageProof.reason === 'OUTAGE_LOCAL_QUOTA') return failure(429, 'Degraded-mode read quota exceeded.');
      if (['OUTAGE_REPLAY_CAPACITY', 'OUTAGE_QUOTA_STORE_CAPACITY'].includes(outageProof.reason)) return failure(503, 'Degraded-mode local protection is at capacity.');
      if (outageProof.reason === 'OUTAGE_POW_REPLAY') return failure(429, 'The degraded-mode proof has already been used.');
      const challenge = await makeOutageChallenge({ method, pathname, difficulty: options.outagePowDifficulty ?? 12, projectId: outageProject, requesterKey: outageRequester });
      return { allowed: false, status: 428, response: Response.json({ error: 'Control plane unavailable; proof-of-work required.', challenge }, { status: 428, headers: { 'Cache-Control': 'no-store' } }), findings: [] };
    }
    quota = outageProof.quota;
  }

  const findings = [...inspection.findings];
  const shadowCatalogEnabled = options.shadowApiCatalog === true || (options.shadowApiCatalog !== false && policy.shadowApiCatalogEnabled === true);
  if (shadowCatalogEnabled && options.openapiDocument && !isOpenApiOperation(options.openapiDocument, method, pathname)) findings.push({ id: 'SHADOW_API_ROUTE', category: 'SHADOW_API', severity: 'medium', detail: `Observed route is not declared in the supplied OpenAPI document: ${method} ${pathname}`.slice(0, 180) });
  if (options.schema && !['GET', 'HEAD'].includes(method)) { const validation = validatePayloadSchema(body, options.schema); if (!validation.valid) findings.unshift({ id: 'SCHEMA_VALIDATION', category: 'SCHEMA', severity: 'high', detail: validation.errors.slice(0, 3).join('; ').slice(0, 180) }); }
  if (options.requestDlp === true && body && typeof body === 'object' && !Array.isArray(body) && /application\/json/i.test(request.headers.get('content-type') || '')) {
    try { const redacted = redactSensitiveText(JSON.stringify(body)); if (redacted.detected.length) { body = JSON.parse(redacted.text); const headers = new Headers((forwardedRequest || request).headers); headers.delete('content-length'); forwardedRequest = new Request(forwardedRequest || request, { body: redacted.text, headers }); findings.unshift({ id: 'REQUEST_DLP_REDACTED', category: 'DLP', severity: 'info', detail: `Redacted request fields matching: ${redacted.detected.slice(0, 8).join(', ')}.` }); } }
    catch (error) { options.onDlpError?.(error); }
  }
  if (!quota.allowed) findings.unshift({ id: 'LOCAL_RATE_LIMIT', category: 'RATE_LIMIT', severity: 'high', detail: 'Configured request quota exceeded.' });
  const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname);

  const effectiveMode = policy.mode === 'DRY_RUN' || options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE';
  const enforceableFindings = findings.filter((finding) => !['SHADOW_API', 'DLP', 'OBSERVED_RICH_TEXT'].includes(finding.category));
  if (enforceableFindings.length > 0 && effectiveMode === 'ENFORCE') {
    if (findings.some((finding) => finding.category === 'RATE_LIMIT')) blockCache.set(cacheKey, Date.now() + Math.max(1000, Math.min(30000, quota.retryAfterMs || 3000)));
    if (options.endpoint && options.serverKey) serverAction(options, { action: 'server-event', type: 'SDK_THREAT_BLOCK', blocked: true, path: pathname, method, riskScore: inspection.riskScore, findings: findings.slice(0, 20), userId: subject }).catch((error) => options.onPolicyError?.(error));
    const status = findings.some((finding) => finding.category === 'RATE_LIMIT') ? 429 : 403;
    return failure(status, 'Request blocked by ArixShield.');
  }

  let concurrencyLease = null;
  const expensiveRoute = options.concurrency === true || (Array.isArray(options.concurrencyPaths) && isHoneypotPath(pathname, options.concurrencyPaths)) || /\/(?:ai|video|research|llm)(?:\/|$)/i.test(pathname);
  if (expensiveRoute && options.endpoint && options.serverKey) {
    const requestId = randomUUID(); const actorHash = await sha256Hex(`${tenantId || cacheIdentity(options)}:${subject}`);
    try {
      const acquired = await serverAction(options, { action: 'acquire-concurrency', actorHash, requestId, maximum: Math.max(1, Math.min(20, Number(options.maxConcurrency) || 3)), ttlMs: options.concurrencyTtlMs || 120000 });
      if (!acquired.ok) return failure(429, 'ArixShield concurrent request limit exceeded.');
      concurrencyLease = { actorHash, requestId };
    } catch (error) { options.onPolicyError?.(error); return failure(503, 'ArixShield concurrency control is unavailable.'); }
  }
  return { allowed: true, status: 200, findings, riskScore: inspection.riskScore, remaining: quota.remaining, policy: effectiveMode, actorId: securityActor, ip, geo: geoHints(request), path: pathname, method, forwardedRequest, identity: securityActor, clientIp: ip, ownershipIdentity, authorizationContext: authContext, roles, flowState, concurrencyLease, quotaDimensions: dimensions, quotaLimit, baseQuotaLimit, trustMultiplier, resourceCapabilityVerified, dpopVerified, estimatedWeight: weight, reportOutcome: Boolean(options.reportAllRequests === true || abuseEnabled || options.shadowApiCatalog === true || policy.shadowApiCatalogEnabled === true || options.geoVelocityProtection === true || policy.geoVelocityEnabled === true || options.forensicReplay === true || policy.forensicReplayEnabled === true || findings.length > 0) };
}

export async function reportResponseOutcome(request, response, options = {}) {
  if (!options.endpoint || !options.serverKey?.startsWith('ARIX_SECRET_')) throw new Error('ArixShield endpoint and server key are required.'); const decision = options.decision || {};
  return serverAction(options, { action: 'record-outcome', actorId: decision.actorId || options.userId || 'anonymous', resourceCapabilityVerified: decision.resourceCapabilityVerified === true, ip: decision.ip || getClientIp(request, options), path: decision.path || new URL(request.url).pathname, method: request.method, status: response.status, latencyMs: Math.max(0, Number(options.latencyMs) || 0), ...(decision.geo || geoHints(request)), safeHeaders: { accept: request.headers.get('accept') || '', 'content-type': request.headers.get('content-type') || '', 'user-agent': (request.headers.get('user-agent') || '').slice(0, 180), 'x-request-id': (request.headers.get('x-request-id') || '').slice(0, 180) }, findings: decision.findings || [] });
}
async function releaseConcurrencyLease(decision, options) {
  if (!decision?.concurrencyLease || !options.endpoint || !options.serverKey) return;
  const lease = decision.concurrencyLease; decision.concurrencyLease = null;
  try { await serverAction(options, { action: 'release-concurrency', ...lease }, 1200); }
  catch (error) { options.onPolicyError?.(error); }
}

function attachConcurrencyRelease(response, decision, options) {
  if (!(response instanceof Response) || !decision?.concurrencyLease) return response;
  if (!response.body || [204, 205, 304].includes(response.status)) {
    response.body?.cancel().catch(() => {});
    void releaseConcurrencyLease(decision, options);
    return response;
  }
  const reader = response.body.getReader(); let finished = false;
  const releaseOnce = async () => { if (finished) return; finished = true; await releaseConcurrencyLease(decision, options); };
  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const result = await reader.read();
        if (result.done) { controller.close(); await releaseOnce(); }
        else controller.enqueue(result.value);
      } catch (error) { controller.error(error); await releaseOnce(); }
    },
    async cancel(reason) { try { await reader.cancel(reason); } finally { await releaseOnce(); } }
  });
  return new Response(stream, { status: response.status, statusText: response.statusText, headers: response.headers });
}

export function withArixShield(handler, options = {}) {
  if (typeof handler !== 'function') throw new TypeError('withArixShield expects a request handler.');
  return async function arixProtectedRoute(request, context) {
    const started = Date.now(); const decision = await protectRequest(request, options);
    if (!decision.allowed) return decision.response;
    let response;
    const authorizationApi = {
      authorize: async (args = {}) => {
        const result = await authorizeRequest({ method: args.method || request.method, pathname: args.pathname || decision.path, routes: args.routes || options.authorization?.routes || options.authorizationMap || options.authorizationRoutes, context: decision.authorizationContext, defaultDenyMutations: options.mutationTripwire === true, requireScopedPrecheck: options.mutationTripwire === true, preCheck: args.preCheck || options.authorization?.preCheck || options.authorizationPreCheck, request });
        return result.allowed;
      },
      scopeQuery: (query, args = {}) => scopeQuery(query, decision.authorizationContext, args)
    };
    const handlerContext = { ...context, arixDecision: decision, arixContext: authorizationApi };
    try {
      const context = decision.authorizationContext || {};
      response = await runWithArixContext({
        tenantId: context.tenantId || context.projectId || '',
        userId: context.userId || context.ownerId || '',
        roles: decision.roles || context.roles || [],
        permissions: context.permissions || [],
        method: request.method,
        path: decision.path || new URL(request.url).pathname
      }, async () => {
        const handled = await handler(decision.forwardedRequest || request, handlerContext);
        if (options.requireScopedDataReceipt === true && handled instanceof Response && handled.status === 200
          && /application\/(?:[a-z0-9.+-]+\+)?json/i.test(handled.headers.get('content-type') || '')
          && !hasScopedDataReceipt()) {
          return Response.json({ error: 'Unscoped Data Access Blocked' }, { status: 500, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
        }
        return handled;
      });
    }
    catch (error) {
      await releaseConcurrencyLease(decision, options);
      if (decision.reportOutcome) {
        const report = reportResponseOutcome(request, new Response(null, { status: 500 }), { ...options, decision, latencyMs: Date.now() - started }).catch((reportError) => options.onPolicyError?.(reportError));
        if (typeof options.waitUntil === 'function') options.waitUntil(report);
      }
      throw error;
    }
    if (response instanceof Response && /application\/json/i.test(response.headers.get('content-type') || '') && (options.responseDlp === true || options.responseOwnershipGuard === true || options.capabilitySealing === true || options.restrictedReadFields || options.authorization?.restrictedReadFields)) {
      try {
        let output = await response.clone().json();
        const ownershipIdentity = decision.ownershipIdentity;
        if (options.responseOwnershipGuard === true && ownershipIdentity) {
          const mismatch = findOwnershipMismatch(output, ownershipIdentity, options.ownershipFields);
          if (mismatch) {
            if (options.endpoint && options.serverKey) { const ban = serverAction(options, { action: 'honeypot', path: new URL(request.url).pathname, method: request.method, actorId: decision.identity, ip: decision.clientIp }).catch((error) => options.onPolicyError?.(error)); if (typeof options.waitUntil === 'function') options.waitUntil(ban); }
            await releaseConcurrencyLease(decision, options);
            return Response.json({ error: 'ArixShield blocked a response with mismatched resource ownership.' }, { status: 403, headers: { 'Cache-Control': 'no-store' } });
          }
        }
        const readFieldPolicy = options.authorization?.restrictedReadFields || options.restrictedReadFields;
        if (readFieldPolicy) output = filterReadFields(output, readFieldPolicy, decision.roles || []);
        if (options.capabilitySealing === true && output && typeof output === 'object') output = sealResourceIdsInPayload(output, ownershipIdentity, 0, options.capabilityReadMode || 'read');
        if (options.responseDlp === true) output = redactResponseData(output);
        if (options.responseDlp === true || options.capabilitySealing === true || readFieldPolicy) {
          const headers = new Headers(response.headers); headers.delete('content-length');
          response = new Response(JSON.stringify(output), { status: response.status, statusText: response.statusText, headers });
        }
      } catch (error) {
        options.onDlpError?.(error);
        if (options.capabilitySealing === true || options.responseOwnershipGuard === true || options.authorization?.restrictedReadFields || options.restrictedReadFields) {
          await releaseConcurrencyLease(decision, options);
          return Response.json({ error: 'ArixShield response security processing failed.' }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
        }
      }
    }
    if (response instanceof Response && decision.flowState?.matched) {
      const headers = new Headers(response.headers);
      if (decision.flowState.ticket) headers.set('X-Arix-Flow', decision.flowState.ticket);
      else if (decision.flowState.complete) headers.set('X-Arix-Flow', '');
      response = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    const actualCost = Number(response?.headers?.get?.('x-arix-actual-cost'));
    if (Number.isFinite(actualCost) && actualCost >= 0 && actualCost <= 1000000 && options.endpoint && options.serverKey) {
      const delta = Math.max(0, Math.ceil(actualCost - Number(decision.estimatedWeight || 0)));
      const reconciliation = delta > 0 ? serverAction(options, { action: 'check-limit', scope: `${decision.actorId}:${decision.method}:${decision.path}:actual-cost`, algorithm: options.rateLimitAlgorithm || 'TOKEN_BUCKET', limit: decision.quotaLimit || 120, windowMs: options.rateLimitWindowMs || 60000, weight: Math.min(delta, 10000), dimensions: decision.quotaDimensions }).catch((error) => options.onPolicyError?.(error)) : Promise.resolve();
      const metric = serverAction(options, { action: 'record-cost', actualCost }).catch((error) => options.onPolicyError?.(error));
      if (typeof options.waitUntil === 'function') { options.waitUntil(reconciliation); options.waitUntil(metric); }
    }
    if (decision.reportOutcome) {
      const report = reportResponseOutcome(request, response, { ...options, decision, latencyMs: Date.now() - started }).catch((error) => options.onPolicyError?.(error));
      if (typeof options.waitUntil === 'function') options.waitUntil(report);
    }
    if (response instanceof Response) {
      const headers = new Headers(response.headers);
      headers.set('X-RateLimit-Limit', String(decision.quotaLimit || 0));
      headers.set('X-RateLimit-Remaining', String(Math.max(0, Number(decision.remaining) || 0)));
      headers.set('X-Arix-Trust-Multiplier', String(decision.trustMultiplier || 1));
      response = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    if (!(response instanceof Response) && decision.concurrencyLease) await releaseConcurrencyLease(decision, options);
    return attachConcurrencyRelease(response, decision, options);
  };
}

export async function watermarkResponseData(payload, context = {}, options = {}) {
  if (!options.endpoint || !options.serverKey) throw new Error('watermarkResponseData requires the ArixShield endpoint and server key.'); if (!context.sessionId) throw new Error('watermarkResponseData requires context.sessionId for attribution.');
  const material = await serverAction(options, { action: 'watermark-material', sessionId: String(context.sessionId).slice(0, 100), userId: String(context.userId || 'anonymous').slice(0, 100), ip: String(context.ip || '').slice(0, 64), ...(typeof options.canaryRowsEnabled === 'boolean' ? { canaryRowsEnabled: options.canaryRowsEnabled } : {}) }, 5000);
  const originalLength = Array.isArray(payload?.data) ? payload.data.length : 0;
  const output = await spliceCanaryRow(payload, { projectId: material.projectId || '' }, Boolean(material.canaryId), material.canaryId);
  if (material.canaryId && Array.isArray(output?.data) && output.data.length === originalLength + 1) {
    const insertedIndex = Math.floor(originalLength / 2);
    const identifier = getChameleonRowIdentifier(output.data[insertedIndex]);
    if (identifier) {
      try { await serverAction(options, { action: 'register-chameleon-id', canaryId: material.canaryId, exposedId: String(identifier.value) }, 3500); }
      catch { output.data.splice(insertedIndex, 1); }
    }
  }
  return watermarkPayloadWithMarker(output, material.marker);
}
export function redactResponseData(payload) { try { const serialized = JSON.stringify(payload); const redacted = redactSensitiveText(serialized); return redacted.detected.length ? JSON.parse(redacted.text) : payload; } catch { return payload; } }
export { redactSensitiveText, validatePayloadSchema, scopeQuery, arixSafeFetch };
export { compileOpenApiRequestSchema } from '../api/_lib/schema.js';

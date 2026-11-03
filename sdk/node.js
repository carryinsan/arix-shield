import { randomUUID, createHash } from 'node:crypto';
import { sanitizeArixIdentity } from './identity.js';
import { runWithArixContext, hasScopedDataReceipt } from './context.js';
import { installProcessEgressFirewall } from './process-egress-firewall.js';

// Opt in before application handlers start; do not mutate global fetch by default.
if (process.env.ARIX_PROCESS_EGRESS_FIREWALL === 'true') installProcessEgressFirewall();
import { isIP } from 'node:net';
import { inspectRequest, redactSensitiveText } from '../api/_lib/waf-engine.js';
import { authorizeRequest, filterReadFields, filterWriteFields, normalizeSecurityPath, scopeQuery } from '../api/_lib/authorization.js';
import { validateOpenApiRequest } from '../api/_lib/schema.js';
import { rewriteCapabilityRequest, verifySignedToken, verifyRequestDpopProof, sha256Hex, createSignedToken } from '../api/_lib/crypto-trap.js';
import { formatIpPrefix } from '../api/_lib/cidr.js';
import { runWithCircuit } from '../api/_lib/circuit-breaker.js';
import { arixSafeFetch } from './safe-fetch.js';
import { validateClearanceRequest, routeRequiresClearance, quotaDimensions, makeOutageChallenge, verifyOutageProof, consumeLocalOutageRead, validateWorkflowRequest } from './security-runtime.js';
import { validatePayloadSchema, isOpenApiOperation } from '../api/_lib/schema.js';
import { watermarkPayloadWithMarker, spliceCanaryRow, getChameleonRowIdentifier } from '../api/_lib/watermark.js';
import { findOwnershipMismatch, sealResourceIdsInPayload } from '../api/_lib/crypto-trap.js';

const processBuckets = new Map(); const quotaLeases = new Map(); const policyCache = new Map(); const securitySnapshotCache = new Map(); const reputationCache = new Map(); const keyEpochCache = new Map();
const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);

async function remotePolicy(endpoint, serverKey) {
  if (!endpoint || !serverKey) return null;
  const cacheKey = `${endpoint}:${serverKey.slice(-10)}`; const cached = policyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 30000) return cached.policy;
  const response = await runWithCircuit(`sdk:${cacheKey}`, (signal) => fetch(`${endpoint.replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey }, body: JSON.stringify({ action: 'get-policy' }), signal }), { tripAfterMs: 450, timeoutMs: 450, openMs: 10000, failureThreshold: 3 });
  if (!response.ok) throw new Error(`ArixShield policy fetch failed (${response.status}).`);
  const data = await response.json(); const epoch = Number(data.keyEpoch) || 0; const previous = keyEpochCache.get(cacheKey); if (previous !== undefined && previous !== epoch) { policyCache.delete(cacheKey); securitySnapshotCache.delete(cacheKey); for (const id of quotaLeases.keys()) if (id.startsWith(`${cacheKey}:`)) quotaLeases.delete(id); } keyEpochCache.set(cacheKey, epoch); policyCache.set(cacheKey, { at: Date.now(), policy: data.policy ?? {} }); securitySnapshotCache.set(cacheKey, { at: Date.now(), projectId: data.projectId, keyEpoch: epoch, ...(data.snapshot || {}) }); return data.policy ?? {};
}
async function serverAction(endpoint, serverKey, payload, timeout = 3500) {
  const cacheKey = `${endpoint}:${serverKey.slice(-10)}`;
  const response = await runWithCircuit(`sdk:${cacheKey}`, (signal) => fetch(`${String(endpoint).replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey }, body: JSON.stringify(payload), signal }), { tripAfterMs: 450, timeoutMs: Math.max(450, Math.min(5000, Number(timeout) || 3500)), openMs: 10000, failureThreshold: 3 });
  const epoch = Number(response.headers.get('x-arix-epoch'));
  if (Number.isFinite(epoch)) { const previous = keyEpochCache.get(cacheKey); if (previous !== undefined && previous !== epoch) { policyCache.delete(cacheKey); securitySnapshotCache.delete(cacheKey); for (const id of quotaLeases.keys()) if (id.startsWith(`${cacheKey}:`)) quotaLeases.delete(id); } keyEpochCache.set(cacheKey, epoch); }
  if (!response.ok) throw new Error(`ArixShield ${payload.action} failed (${response.status}).`); return response.json();
}
function hashHex(value) { return createHash('sha256').update(String(value)).digest('hex'); }
function snapshotBlocks(endpoint, serverKey, identity, _ip) {
  const cacheKey = `${endpoint}:${serverKey.slice(-10)}`; const snapshot = securitySnapshotCache.get(cacheKey);
  if (!snapshot || Date.now() - snapshot.at >= 30000 || !snapshot.complete || !snapshot.projectId) return null;
  const actorHash = identity && identity !== 'anonymous' ? hashHex(`${snapshot.projectId}:${String(identity).slice(0, 180)}`) : null;
  return Boolean(actorHash && snapshot.actorHashes?.includes(actorHash));
}
function localTokenBucket(key, capacity, windowMs, weight = 1) {
  const now = Date.now(); const refillPerMs = capacity / windowMs; const item = processBuckets.get(key) ?? { tokens: capacity, updated: now };
  item.tokens = Math.min(capacity, item.tokens + Math.max(0, now - item.updated) * refillPerMs); item.updated = now; const allowed = item.tokens >= weight; if (allowed) item.tokens -= weight; processBuckets.set(key, item);
  if (processBuckets.size > 10000) for (const [bucketKey, bucket] of processBuckets) if (now - bucket.updated > windowMs * 3) processBuckets.delete(bucketKey);
  return { allowed, remaining: Math.floor(item.tokens), retryAfterMs: allowed ? 0 : Math.ceil((weight - item.tokens) / refillPerMs) };
}
async function distributedTokenBucket({ endpoint, serverKey, scope, algorithm = 'TOKEN_BUCKET', limit, windowMs = 60000, weight = 1, leaseSize = 15, dimensions = null }) {
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
    const data = await serverAction(endpoint, serverKey, { action: 'check-limit', scope, algorithm, limit, windowMs, weight: amount, ...(dimensions ? { dimensions } : {}) });
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
const BUILTIN_GHOST_PATHS = Object.freeze(['/.env', '/api/v1/admin/export', '/api/debug/config', '/graphql/schema']);
function isHoneypotPath(pathname, configured) {
  const routes = [...BUILTIN_GHOST_PATHS, ...(Array.isArray(configured) ? configured : [])];
  return routes.some((raw) => { if (typeof raw !== 'string' || raw.length > 220) return false; const path = raw.split('?')[0]; return path.endsWith('/*') ? pathname.startsWith(path.slice(0, -1)) : pathname === path; });
}
async function cachedReputation(endpoint, serverKey, ip, userAgent, provider, actorId = 'anonymous', asn = '', path = '/') {
  const uaClass = /googlebot/i.test(userAgent) ? 'googlebot' : /bingbot/i.test(userAgent) ? 'bingbot' : '';
  const key = `${ip}:${provider}:${uaClass}:${actorId}:${asn}:${path}`; const cached = reputationCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await serverAction(endpoint, serverKey, { action: 'check-reputation', ip, userAgent, provider, actorId, asn, path });
  reputationCache.set(key, { value, expiresAt: Date.now() + 10000 });
  if (reputationCache.size > 10000) for (const [id, item] of reputationCache) if (item.expiresAt <= Date.now()) reputationCache.delete(id);
  return value;
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
function requestHeader(req, name) { return req.headers?.[name] ?? req.headers?.[name.toLowerCase()]; }
function safeHeaders(headers) { const result = {}; for (const name of ['accept', 'content-type', 'user-agent', 'x-request-id']) if (headers?.[name] !== undefined) result[name] = String(headers[name]).slice(0, 180); return result; }

export function installScopedResponseReceiptGate(res) {
  if (!res || typeof res.end !== 'function' || res.__arixScopedReceiptGate) return;
  Object.defineProperty(res, '__arixScopedReceiptGate', { value: true });
  const originalEnd = res.end;
  const originalWrite = typeof res.write === 'function' ? res.write : null;
  const originalWriteHead = typeof res.writeHead === 'function' ? res.writeHead : null;
  const originalFlushHeaders = typeof res.flushHeaders === 'function' ? res.flushHeaders : null;
  const queued = [];
  const maxBufferedBytes = 4 * 1024 * 1024;
  let bufferedBytes = 0;
  let pendingHead = null;
  let flushed = false;
  let overflow = false;

  const applyPendingHeadersForInspection = (args) => {
    const extra = typeof args[1] === 'string' ? args[2] : args[1];
    try {
      if (Array.isArray(extra)) {
        for (let index = 0; index + 1 < extra.length; index += 2) res.setHeader?.(String(extra[index]), extra[index + 1]);
      } else if (extra && typeof extra === 'object') {
        for (const [name, value] of Object.entries(extra)) res.setHeader?.(name, value);
      }
    } catch { /* The original writeHead call remains authoritative at flush time. */ }
  };
  const isProtectedJson = () => Number(res.statusCode || 200) === 200
    && /application\/(?:[a-z0-9.+-]+\+)?json/i.test(String(res.getHeader?.('content-type') || ''));
  const flushHead = () => {
    if (flushed || !originalWriteHead) return;
    flushed = true;
    if (pendingHead) originalWriteHead.apply(res, pendingHead);
    else originalWriteHead.call(res, Number(res.statusCode || 200));
  };
  const asBuffer = (chunk, encoding) => {
    if (chunk === undefined || chunk === null) return null;
    if (Buffer.isBuffer(chunk)) return chunk;
    if (ArrayBuffer.isView(chunk)) return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    return Buffer.from(String(chunk), typeof encoding === 'string' ? encoding : 'utf8');
  };
  const queueChunk = (chunk, encoding, callback) => {
    const bytes = asBuffer(chunk, encoding);
    if (bytes?.length) {
      bufferedBytes += bytes.length;
      if (bufferedBytes > maxBufferedBytes) overflow = true;
      else queued.push(bytes);
    }
    if (typeof callback === 'function') queued.push(callback);
  };
  const flushQueued = () => {
    for (const item of queued) {
      if (typeof item === 'function') item();
      else if (item.length) originalWrite?.call(res, item);
    }
    queued.length = 0;
  };
  const reject = (callback) => {
    res.statusCode = 500;
    try { res.removeHeader?.('Content-Length'); res.removeHeader?.('content-length'); } catch { /* Optional framework API. */ }
    res.setHeader?.('Content-Type', 'application/json; charset=utf-8');
    res.setHeader?.('Cache-Control', 'no-store, max-age=0');
    res.setHeader?.('X-Content-Type-Options', 'nosniff');
    pendingHead = null;
    flushed = false;
    flushHead();
    const body = JSON.stringify({ error: overflow ? 'Scoped Data Response Too Large' : 'Unscoped Data Access Blocked' });
    queued.length = 0;
    return originalEnd.call(res, body, callback);
  };

  if (originalWriteHead) {
    res.writeHead = function arixScopedDeferredWriteHead(...args) {
      if (flushed) return originalWriteHead.apply(res, args);
      pendingHead = args;
      if (Number(args[0]) > 0) res.statusCode = Number(args[0]);
      if (typeof args[1] === 'string') res.statusMessage = args[1];
      applyPendingHeadersForInspection(args);
      // Headers are intentionally deferred until the first non-JSON write or
      // end(), so an unscoped JSON status/body can still be replaced atomically.
      return res;
    };
  }
  if (originalFlushHeaders) {
    res.flushHeaders = function arixScopedDeferredFlushHeaders() {
      if (isProtectedJson() && !hasScopedDataReceipt()) return res;
      flushHead();
      return originalFlushHeaders.call(res);
    };
  }
  if (originalWrite) {
    res.write = function arixScopedGuardedWrite(chunk, encoding, callback) {
      if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
      if (!flushed && isProtectedJson()) {
        queueChunk(chunk, encoding, callback);
        return !overflow;
      }
      flushHead();
      flushQueued();
      return originalWrite.call(res, chunk, encoding, callback);
    };
  }
  res.end = function arixScopedGuardedEnd(chunk, encoding, callback) {
    if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
    else if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (!flushed && isProtectedJson()) {
      queueChunk(chunk, encoding, null);
      if (!hasScopedDataReceipt() || overflow) return reject(callback);
      flushHead();
      flushQueued();
      return originalEnd.call(res, undefined, callback);
    }
    flushHead();
    flushQueued();
    return originalEnd.call(res, chunk, encoding, callback);
  };
}

export function createArixShield(options = {}) {
  const mode = options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE'; const limit = Math.max(10, Math.min(10000, Number(options.rateLimitPerMinute) || 120)); const endpoint = String(options.endpoint ?? '').replace(/\/$/, ''); const serverKey = options.serverKey;
  if (!serverKey || !serverKey.startsWith('ARIX_SECRET_')) throw new Error('createArixShield requires the server-only ARIX_SECRET_ key.');
  if (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length && !endpoint) throw new Error('Configured honeypotPaths require an ArixShield endpoint.');
  const useGlobalRateLimit = options.globalRateLimit !== false && Boolean(endpoint);
  if (useGlobalRateLimit && !endpoint) throw new Error('globalRateLimit requires an ArixShield endpoint.');
  const localBlockCache = new Map();
  const rememberBlock = (key, milliseconds) => { localBlockCache.set(key, Date.now() + Math.max(1000, Math.min(30000, milliseconds || 3000))); if (localBlockCache.size > 10000) for (const [id, expires] of localBlockCache) if (expires <= Date.now()) localBlockCache.delete(id); };

  return async function arixShieldMiddleware(req, res, next) {
    const started = Date.now();
    const method = String(req.method || 'GET').toUpperCase();
    let url = String(req.originalUrl || req.url || '/');
    let pathname = normalizeSecurityPath(url);
    if (!pathname) return sendDecision(res, 400, { error: 'Invalid or ambiguous request path.' });
    const clientIp = resolveClientIp(req, options);
    const identityValue = typeof options.getIdentity === 'function' ? await options.getIdentity(req, { ip: clientIp, method, path: pathname }) : (req.user?.id ?? req.auth?.userId ?? '');
    const identity = sanitizeArixIdentity(identityValue, clientIp) || 'anonymous';
    // Anonymous requests must not collapse into one project-wide `anonymous` bucket.
    // Use a per-request actor until an authenticated identity or verified DPoP key exists.
    let securityActor = identity === 'anonymous' ? `anonymous:${randomUUID()}` : identity;
    let dpopVerified = false;
    let resourceCapabilityVerified = false;
    const rawBody = Buffer.isBuffer(req.rawBody) || req.rawBody instanceof Uint8Array ? req.rawBody : Buffer.isBuffer(req.body) ? req.body : null;
    const body = Buffer.isBuffer(req.body) ? req.body : (req.body ?? null);
    const bodyBytes = rawBody ? Buffer.from(rawBody) : body == null ? Buffer.alloc(0) : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const maxBodyBytes = Math.max(1024, Math.min(262144, Number(options.maxBodyBytes) || 32768));
    if (Number(req.headers?.['content-length'] || 0) > maxBodyBytes || bodyBytes.length > maxBodyBytes) return sendDecision(res, 413, { error: 'Request body too large.' });

    let authContext = {};
    const authProvider = options.getAuthorizationContext || options.getAuthContext;
    if (typeof authProvider === 'function') {
      try { authContext = await authProvider(req, { ip: clientIp, identity, method, pathname }) || {}; }
      catch (error) { options.onPolicyError?.(error); return sendDecision(res, 403, { error: 'Authorization context could not be established.' }); }
    }
    // Capture the authenticated context before filling policy-compatible identity fallbacks.
    // The automatic Prisma scope adapter deliberately uses only these trusted context fields.
    const verifiedContextUserId = String(authContext.userId || authContext.ownerId || '').trim();
    let tenantId = String(authContext.tenantId || authContext.projectId || options.tenantId || options.projectId || '').trim();
    if (!tenantId && typeof options.getTenantIdentity === 'function') {
      try { tenantId = String(await options.getTenantIdentity(req, authContext) || '').trim(); }
      catch (error) { options.onPolicyError?.(error); return sendDecision(res, 403, { error: 'Tenant context could not be established.' }); }
    }
    const userId = String(verifiedContextUserId || (identity !== 'anonymous' ? identity : '')).trim();
    if (userId) securityActor = `user:${userId}`;
    authContext = { ...authContext, userId, tenantId, projectId: authContext.projectId || tenantId };
    const authorizationConfig = options.authorization || {};
    const authz = await authorizeRequest({ method, pathname, routes: authorizationConfig.routes || options.authorizationMap || options.authorizationRoutes, context: authContext, defaultDenyMutations: authorizationConfig.defaultDenyMutations === true || options.mutationTripwire === true, requireScopedPrecheck: options.mutationTripwire === true, preCheck: authorizationConfig.preCheck || options.authorizationPreCheck, request: req });
    if (!authz.allowed) return sendDecision(res, 403, { error: `Request authorization denied (${authz.reason || 'POLICY'}).` });
    const roles = authz.context?.roles || (Array.isArray(authContext.roles) ? authContext.roles : authContext.role ? [authContext.role] : []);

    let ownershipIdentity = null;
    if (options.capabilitySealing === true || options.responseOwnershipGuard === true) {
      let ownerValue = userId;
      if (typeof options.getOwnershipIdentity === 'function') {
        try { ownerValue = options.getOwnershipIdentity(req, { authContext, identity, ip: clientIp }); }
        catch (error) { options.onPolicyError?.(error); return sendDecision(res, 500, { error: 'Ownership identity could not be established.' }); }
        if (ownerValue && typeof ownerValue.then === 'function') return sendDecision(res, 500, { error: 'getOwnershipIdentity must be synchronous in the Node SDK.' });
      }
      const ownerId = String(ownerValue || '').trim();
      if (!ownerId || ownerId === clientIp || ownerId.toLowerCase() === 'anonymous' || !tenantId) return sendDecision(res, 500, { error: 'Capability sealing requires authenticated user and tenant identities.' });
      ownershipIdentity = { tenantId, userId: ownerId };
    }

    const writePolicy = authorizationConfig.allowedWriteFields || options.allowedWriteFields;
    let workingBody = body;
    if (writePolicy && workingBody && typeof workingBody === 'object' && !Buffer.isBuffer(workingBody)) {
      workingBody = filterWriteFields(workingBody, writePolicy, roles); req.body = workingBody;
    }
    let arrayFields = [];
    if (options.openapiDocument) {
      const operation = options.openapiDocument.paths?.[pathname]?.[method.toLowerCase()];
      const params = [...(options.openapiDocument.paths?.[pathname]?.parameters || []), ...(operation?.parameters || [])];
      arrayFields = params.filter((param) => String(param.in).toLowerCase() === 'query' && param.schema?.type === 'array').map((param) => String(param.name).toLowerCase());
    }
    if (options.capabilitySealing === true) {
      const rewritten = rewriteCapabilityRequest(url, workingBody, ownershipIdentity, { idPattern: options.capabilityIdPattern, method, arrayQueryFields: arrayFields });
      resourceCapabilityVerified = rewritten.capabilityVerified === true;
      if (rewritten.invalid) return sendDecision(res, 403, { error: 'Invalid or user-mismatched resource capability.' });
      workingBody = rewritten.body; req.body = workingBody;
      url = rewritten.url; req.url = rewritten.url; req.originalUrl = rewritten.url; pathname = normalizeSecurityPath(url);
      if (!pathname) return sendDecision(res, 403, { error: 'Invalid resource path.' });
      try { req.query = Object.fromEntries(new URLSearchParams(url.split('?')[1] || '')); } catch { return sendDecision(res, 400, { error: 'Invalid query parameters.' }); }
    }
    const inspection = inspectRequest({ method, url, headers: req.headers, rawHeaders: req.rawHeaders, httpVersion: req.httpVersion, body: workingBody, rawBody: rawBody || bodyBytes, contentLength: req.headers?.['content-length'], maxBodyBytes, maxLeafBytes: options.maxLeafBytes ?? 4096, allowedLongFields: options.allowedLongFields ?? [], allowedQueryArrayFields: arrayFields, production: process.env.NODE_ENV === 'production' });
    if (inspection.findings.some((item) => ['HTTP_SMUGGLING_HEADERS', 'HTTP_HEADER_INJECTION', 'HTTP2_CONNECTION_SPECIFIC_HEADER', 'DUPLICATE_HEADER', 'JSON_DUPLICATE_KEY', 'HTTP_PARAMETER_POLLUTION', 'URL_PATH_NORMALIZATION', 'JSON_MALFORMED', 'XML_DTD_XXE'].includes(item.id))) return sendDecision(res, 400, { error: 'Request parser consistency check failed.' });
    if (options.strictOpenApi === true && options.openapiDocument) {
      const valid = validateOpenApiRequest(options.openapiDocument, { method, url, headers: req.headers, body: workingBody });
      if (!valid.valid) return sendDecision(res, 400, { error: 'Request does not match the declared OpenAPI contract.' });
    }
    const cacheKey = `${securityActor}:${method}:${pathname}`; const cachedUntil = localBlockCache.get(cacheKey) || 0;
    if (cachedUntil > Date.now()) return sendDecision(res, 429, { error: 'Request temporarily rate-limited by ArixShield.', retryAfterMs: cachedUntil - Date.now() });
    if (cachedUntil) localBlockCache.delete(cacheKey);
    let policy = { mode, rateLimitPerMinute: limit, blockDatacenterAsn: false, threatFeedEnabled: true };
    try { policy = { ...policy, ...(await remotePolicy(endpoint, serverKey) ?? {}) }; }
    catch (error) { options.onTelemetryError?.(error); if (options.failClosedPolicy !== false) return sendDecision(res, 503, { error: 'ArixShield policy service is unavailable.' }); }

    if (policy.deceptionEnabled !== false && isHoneypotPath(pathname, options.honeypotPaths)) {
      if (!endpoint || !serverKey) return sendDecision(res, 404, { error: 'Not found.' });
      try {
        const trap = await serverAction(endpoint, serverKey, { action: 'honeypot', path: pathname, method, actorId: securityActor, ip: clientIp, ja4: process.env.VERCEL === '1' ? String(req.headers?.['x-vercel-ja4-digest'] || '').slice(0, 160) : '' });
        return sendDecision(res, 200, trap);
      } catch (error) { options.onTelemetryError?.(error); return sendDecision(res, 404, { error: 'Not found.' }); }
    }

    let flowState = null;
    if (options.workflow?.enabled === true) {
      const snapshot = securitySnapshotCache.get(`${endpoint}:${serverKey.slice(-10)}`);
      const flowProjectId = String(options.projectId || snapshot?.projectId || authContext.projectId || tenantId || '');
      flowState = await validateWorkflowRequest({
        config: options.workflow, method, pathname, headers: req.headers,
        projectId: flowProjectId, tenantId, actorId: userId || identity,
        consumeNonce: async (nonce) => (await serverAction(endpoint, serverKey, { action: 'consume-flow', nonce })).consumed === true
      });
      if (!flowState.valid) return sendDecision(res, flowState.unavailable ? 503 : 403, { error: 'Signed workflow step validation failed.' });
      if (flowState.matched) {
        if (flowState.ticket) res.setHeader?.('X-Arix-Flow', flowState.ticket);
        else if (flowState.complete) res.setHeader?.('X-Arix-Flow', '');
      }
    }
    if (routeRequiresClearance(pathname, options.botProtection)) {
      const snapshot = securitySnapshotCache.get(`${endpoint}:${serverKey.slice(-10)}`);
      const projectId = String(options.projectId || snapshot?.projectId || '');
      const proto = String(req.headers?.['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim() === 'http' ? 'http' : 'https';
      const host = String(req.headers?.host || '').replace(/[\r\n]/g, '');
      if (!projectId || !host) return sendDecision(res, 503, { error: 'ArixShield project identity or request host is unavailable.' });
      if (Number(req.headers?.['content-length'] || 0) > 0 && !rawBody) return sendDecision(res, 400, { error: 'Request-bound DPoP requires a raw-body parser hook (req.rawBody).'});
      const absoluteUrl = new URL(req.originalUrl || req.url || '/', `${proto}://${host}`).href;
      const clearance = await validateClearanceRequest({ headers: req.headers, method, url: absoluteUrl, bodyBytes: rawBody || new Uint8Array(), projectId, clientIp, botProtection: options.botProtection || {}, consumeSingleUse: async (nonce) => (await serverAction(endpoint, serverKey, { action: 'consume-clearance', nonce })).consumed === true, consumeProofReplay: async (nonce) => (await serverAction(endpoint, serverKey, { action: 'consume-dpop', nonce })).consumed === true });
      if (!clearance.valid) return sendDecision(res, clearance.unavailable ? 503 : 403, { error: 'Valid single-use browser clearance and request-bound DPoP are required.' });
      dpopVerified = true;
      if (identity === 'anonymous' && !userId && clearance.thumbprint) securityActor = `device:${clearance.thumbprint}`;
    }

    const abuseEnabled = options.abuseProtection === true || (options.abuseProtection !== false && policy.abuseProtectionEnabled === true);
    const reputationEnabled = options.reputationProtection === true || (options.reputationProtection !== false && policy.threatFeedEnabled !== false);
    const shadowCatalogEnabled = options.shadowApiCatalog === true || (options.shadowApiCatalog !== false && policy.shadowApiCatalogEnabled === true);
    const geoVelocityEnabled = options.geoVelocityProtection === true || (options.geoVelocityProtection !== false && policy.geoVelocityEnabled === true);
    const forensicEnabled = options.forensicReplay === true || (options.forensicReplay !== false && policy.forensicReplayEnabled === true);
    if (endpoint && (abuseEnabled || (Array.isArray(options.honeypotPaths) && options.honeypotPaths.length > 0))) {
      const snapshotDenied = snapshotBlocks(endpoint, serverKey, securityActor, clientIp);
      if (snapshotDenied === true) { rememberBlock(cacheKey, 30000); return sendDecision(res, 429, { error: 'ArixShield credential-abuse backoff is active.', snapshot: true }); }
      if (snapshotDenied === null) {
        try { const abuse = await serverAction(endpoint, serverKey, { action: 'check-abuse', actorId: securityActor, ip: clientIp }); if (abuse.blocked) { rememberBlock(cacheKey, abuse.retryAfterMs); return sendDecision(res, 429, { error: 'ArixShield credential-abuse backoff is active.', retryAfterMs: abuse.retryAfterMs }); } }
        catch (error) { options.onTelemetryError?.(error); if (options.failClosedAbuse === true) return sendDecision(res, 503, { error: 'ArixShield abuse service is unavailable.' }); }
      }
    }
    if (endpoint && reputationEnabled && clientIp) {
      try {
        const asn = String(req.headers?.['x-vercel-ip-as-number'] || '').slice(0, 16);
        const result = await cachedReputation(endpoint, serverKey, clientIp, String(req.headers?.['user-agent'] || '').slice(0, 240), options.trustedProvider || '', securityActor, asn, pathname);
        const verifiedCrawler = result.crawler?.verified === true || result.configuredProvider?.verified === true;
        const enforce = policy.mode !== 'DRY_RUN' && mode !== 'DRY_RUN';
        if (!verifiedCrawler && enforce && result.action === 'block') { rememberBlock(cacheKey, 5000); return sendDecision(res, 403, { error: 'Request blocked by actor-specific ArixShield reputation policy.', threatConfidence: result.threatConfidence }); }
        if (!verifiedCrawler && enforce && result.action === 'challenge') return sendDecision(res, 428, { error: 'Additional verification is required.', stepUpRequired: true, challengeType: 'browser-clearance', threatConfidence: result.threatConfidence, staleFeedWarning: result.staleFeedWarning === true });
        const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname);
        if (enforce && policy.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(asn) && (!identity || identity.toLowerCase() === 'anonymous')) return sendDecision(res, 428, { error: 'Additional verification is required for this anonymous datacenter request.', stepUpRequired: true, challengeType: 'browser-clearance', threatConfidence: 20 });
        req.arixShieldGoodBot = verifiedCrawler ? (result.crawler?.provider || result.configuredProvider?.provider || null) : null;
        req.arixShieldThreatConfidence = Number(result.threatConfidence) || 0;
        req.arixShieldStaleThreatFeeds = result.staleFeedWarning === true ? (result.reputation?.staleFeeds || []) : [];
      } catch (error) { options.onTelemetryError?.(error); if (options.failClosedReputation === true) return sendDecision(res, 503, { error: 'ArixShield reputation service is unavailable.' }); }
    }
    const baseQuotaLimit = Math.max(10, Math.min(10000, Number(policy.rateLimitPerMinute) || limit));
    // DPoP is server-verified. Authenticated + device-bound sessions get the
    // highest elastic burst; anonymous device-bound sessions get a smaller burst.
    const trustMultiplier = dpopVerified ? (userId ? 4 : 2.5) : 1;
    const quotaLimit = Math.max(10, Math.min(10000, Math.floor(baseQuotaLimit * trustMultiplier)));
    let requestedWeight = options.rateLimitWeight ?? 1; const weightProvider = options.getRateLimitWeight || (typeof requestedWeight === 'function' ? requestedWeight : null);
    if (weightProvider) { try { requestedWeight = await weightProvider(req, { body: workingBody, identity, ip: clientIp, method, path: pathname, policy }); } catch (error) { options.onPolicyError?.(error); if (options.failClosedRateLimitWeight === true) return sendDecision(res, 503, { error: 'ArixShield quota weight could not be calculated.' }); requestedWeight = 1; } }
    const weight = Math.max(1, Math.min(quotaLimit, Math.ceil(Number(requestedWeight) || 1)));
    const dimensions = quotaDimensions({ actor: securityActor, subnet: formatIpPrefix(clientIp), tenant: tenantId || options.projectId || endpoint, method, pathname, limit: quotaLimit });
    let quota;
    try { quota = useGlobalRateLimit ? await distributedTokenBucket({ endpoint, serverKey, scope: `${securityActor}:${method}:${pathname}`, algorithm: options.rateLimitAlgorithm ?? 'TOKEN_BUCKET', limit: quotaLimit, windowMs: options.rateLimitWindowMs ?? 60000, weight, dimensions }) : localTokenBucket(cacheKey, quotaLimit, options.rateLimitWindowMs ?? 60000, weight); }
    catch (error) {
      options.onTelemetryError?.(error);
      const lowRiskRead = method === 'GET' && /\/(?:docs|catalog)(?:\/|$)/i.test(pathname);
      if (!lowRiskRead) return sendDecision(res, 503, { error: 'ArixShield distributed quota service is unavailable.' });
      const challenge = requestHeader(req, 'x-arix-outage-pow');
      if (!await verifyOutageProof(challenge, method, pathname)) { const issued = await makeOutageChallenge({ method, pathname, difficulty: options.outagePowDifficulty ?? 12 }); return sendDecision(res, 428, { error: 'Control plane unavailable; proof-of-work required.', challenge: issued }); }
      quota = consumeLocalOutageRead({ key: `${endpoint}:${identity}:${pathname}`, limit: quotaLimit, windowMs: options.rateLimitWindowMs ?? 60000 });
      if (!quota.allowed) return sendDecision(res, 429, { error: 'Degraded-mode read quota exceeded.' });
    }
    const findings = [...inspection.findings];
    if (shadowCatalogEnabled && options.openapiDocument && !isOpenApiOperation(options.openapiDocument, method, pathname)) findings.push({ id: 'SHADOW_API_ROUTE', category: 'SHADOW_API', severity: 'medium', detail: `Observed route is not declared in the supplied OpenAPI document: ${method} ${pathname}`.slice(0, 180) });
    if (options.schema && !['GET', 'HEAD'].includes(method)) { const validation = validatePayloadSchema(workingBody, options.schema); if (!validation.valid) findings.unshift({ id: 'SCHEMA_VALIDATION', category: 'SCHEMA', severity: 'high', detail: validation.errors.slice(0, 3).join('; ').slice(0, 180) }); }
    if (options.requestDlp === true && workingBody && typeof workingBody === 'object' && !Buffer.isBuffer(workingBody) && /application\/json/i.test(String(req.headers?.['content-type'] || ''))) {
      try { const redacted = redactSensitiveText(JSON.stringify(workingBody)); if (redacted.detected.length) { req.body = JSON.parse(redacted.text); findings.unshift({ id: 'REQUEST_DLP_REDACTED', category: 'DLP', severity: 'info', detail: `Redacted request fields matching: ${redacted.detected.slice(0, 8).join(', ')}.` }); } }
      catch (error) { options.onDlpError?.(error); }
    }
    if (!quota.allowed) findings.unshift({ id: 'LOCAL_RATE_LIMIT', category: 'RATE_LIMIT', severity: 'high', detail: 'Configured per-identity quota exceeded.' });
    const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname); const asn = String(req.headers?.['x-vercel-ip-as-number'] ?? '');

    const effectiveMode = policy.mode === 'DRY_RUN' || mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE';
    const enforceableFindings = findings.filter((finding) => !['SHADOW_API', 'DLP', 'OBSERVED_RICH_TEXT'].includes(finding.category));
    if (enforceableFindings.length > 0 && effectiveMode === 'ENFORCE') {
      const retry = findings.some((finding) => finding.category === 'RATE_LIMIT') ? (quota.retryAfterMs || 3000) : 0; if (retry) rememberBlock(cacheKey, retry);
      if (endpoint) serverAction(endpoint, serverKey, { action: 'server-event', type: 'SDK_THREAT_BLOCK', blocked: true, path: pathname, method, riskScore: inspection.riskScore, findings: findings.slice(0, 20), userId: securityActor }).catch((error) => options.onTelemetryError?.(error));
      if (retry) res.setHeader?.('Retry-After', String(Math.max(1, Math.ceil(retry / 1000))));
      return sendDecision(res, findings.some((finding) => finding.category === 'RATE_LIMIT') ? 429 : 403, { error: 'Request blocked by ArixShield local policy.', riskScore: inspection.riskScore, findings: findings.slice(0, 20) });
    }

    let concurrencyLease = null;
    const expensiveRoute = options.concurrency === true || (Array.isArray(options.concurrencyPaths) && isHoneypotPath(pathname, options.concurrencyPaths)) || /\/(?:ai|video|research|llm)(?:\/|$)/i.test(pathname);
    if (expensiveRoute && endpoint) {
      const requestId = randomUUID(); const actorHash = hashHex(`${tenantId || endpoint}:${securityActor}`);
      try { const acquired = await serverAction(endpoint, serverKey, { action: 'acquire-concurrency', actorHash, requestId, maximum: Math.max(1, Math.min(20, Number(options.maxConcurrency) || 3)), ttlMs: options.concurrencyTtlMs || 120000 }); if (!acquired.ok) return sendDecision(res, 429, { error: 'ArixShield concurrent request limit exceeded.' }); concurrencyLease = { actorHash, requestId }; }
      catch (error) { options.onPolicyError?.(error); return sendDecision(res, 503, { error: 'ArixShield concurrency control is unavailable.' }); }
    }
    let released = false;
    const release = async () => { if (released || !concurrencyLease) return; released = true; try { await serverAction(endpoint, serverKey, { action: 'release-concurrency', ...concurrencyLease }, 1200); } catch (error) { options.onPolicyError?.(error); } };
    if (concurrencyLease && typeof res.once === 'function') { res.once('finish', () => { void release(); }); res.once('close', () => { void release(); }); }

    if ((options.responseDlp === true || options.responseOwnershipGuard === true || options.capabilitySealing === true || options.restrictedReadFields || authorizationConfig.restrictedReadFields) && typeof res.json === 'function') {
      const originalJson = res.json.bind(res);
      res.json = function arixSecureJson(payload) {
        let output = payload;
        try {
          if (options.responseOwnershipGuard === true && ownershipIdentity) {
            const mismatch = findOwnershipMismatch(output, ownershipIdentity, options.ownershipFields);
            if (mismatch) { res.statusCode = 403; if (endpoint) serverAction(endpoint, serverKey, { action: 'honeypot', path: pathname, method, actorId: securityActor, ip: clientIp }).catch((error) => options.onTelemetryError?.(error)); return originalJson({ error: 'ArixShield blocked a response with mismatched resource ownership.' }); }
          }
          const readFieldPolicy = authorizationConfig.restrictedReadFields || options.restrictedReadFields;
          if (readFieldPolicy) output = filterReadFields(output, readFieldPolicy, roles);
          if (options.capabilitySealing === true && output && typeof output === 'object') output = sealResourceIdsInPayload(output, ownershipIdentity, 0, options.capabilityReadMode || 'read');
          if (options.responseDlp === true) { const redacted = redactSensitiveText(JSON.stringify(output)); if (redacted.detected.length) output = JSON.parse(redacted.text); }
        } catch (error) { options.onPolicyError?.(error); res.statusCode = 500; return originalJson({ error: 'ArixShield response security processing failed.' }); }
        return originalJson(output);
      };
    }
    req.arixShield = { allowed: true, mode: effectiveMode, riskScore: inspection.riskScore, findings, remaining: quota.remaining, goodBot: req.arixShieldGoodBot ?? null };
    req.arixContext = {
      userId, tenantId, roles,
      authorize: async (args = {}) => (await authorizeRequest({ method: args.method || method, pathname: args.pathname || pathname, routes: args.routes || authorizationConfig.routes || options.authorizationMap || options.authorizationRoutes, context: authContext, defaultDenyMutations: options.mutationTripwire === true, requireScopedPrecheck: options.mutationTripwire === true, preCheck: args.preCheck || authorizationConfig.preCheck || options.authorizationPreCheck, request: req })).allowed,
      scopeQuery: (query, args = {}) => scopeQuery(query, authContext, args)
    };
    req.arixShieldQuota = { estimatedWeight: weight, limit: quotaLimit, baseLimit: baseQuotaLimit, trustMultiplier, remaining: quota.remaining, dimensions };
    res.setHeader?.('X-RateLimit-Limit', String(quotaLimit));
    res.setHeader?.('X-RateLimit-Remaining', String(Math.max(0, Number(quota.remaining) || 0)));
    res.setHeader?.('X-RateLimit-Reset', String(Math.ceil((Number(quota.resetAt) || (Date.now() + (quota.retryAfterMs || 0))) / 1000)));
    res.setHeader?.('X-Arix-Trust-Multiplier', String(trustMultiplier));
    if (flowState?.matched) req.arixFlow = { workflowId: flowState.workflowId, step: flowState.complete ? 'complete' : 'issued' };
    const shouldRecordOutcome = endpoint && (options.reportAllRequests === true || abuseEnabled || shadowCatalogEnabled || geoVelocityEnabled || forensicEnabled || findings.length > 0);
    if (shouldRecordOutcome && typeof res.once === 'function') res.once('finish', () => {
      const geo = getGeoHints(req); const actualCost = Number(res.getHeader?.('x-arix-actual-cost') || 0);
      if (Number.isFinite(actualCost) && actualCost > 0 && actualCost <= 1000000) {
        const delta = Math.max(0, Math.ceil(actualCost - Number(weight || 0)));
        if (delta > 0) serverAction(endpoint, serverKey, { action: 'check-limit', scope: `${identity}:${method}:${pathname}:actual-cost`, algorithm: options.rateLimitAlgorithm || 'TOKEN_BUCKET', limit: quotaLimit, windowMs: options.rateLimitWindowMs || 60000, weight: Math.min(delta, 10000), dimensions }).catch((error) => options.onPolicyError?.(error));
        serverAction(endpoint, serverKey, { action: 'record-cost', actualCost }).catch((error) => options.onPolicyError?.(error));
      }
      const event = { action: 'record-outcome', actorId: securityActor, userId: securityActor, ip: clientIp, path: pathname, method, status: res.statusCode, latencyMs: Date.now() - started, resourceCapabilityVerified, ...geo, safeHeaders: safeHeaders(req.headers), findings: findings.slice(0, 20) };
      serverAction(endpoint, serverKey, event, 2500).catch((error) => options.onTelemetryError?.(error));
    });
    return runWithArixContext({ userId: verifiedContextUserId, tenantId, roles, permissions: authz.context?.permissions || [], method, path: pathname }, () => {
      if (options.requireScopedDataReceipt === true) installScopedResponseReceiptGate(res);
      return next();
    });
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
  const originalLength = Array.isArray(payload?.data) ? payload.data.length : 0;
  const output = await spliceCanaryRow(payload, { projectId: material.projectId || '' }, Boolean(material.canaryId), material.canaryId);
  if (material.canaryId && Array.isArray(output?.data) && output.data.length === originalLength + 1) {
    const insertedIndex = Math.floor(originalLength / 2);
    const identifier = getChameleonRowIdentifier(output.data[insertedIndex]);
    if (identifier) {
      try { await serverAction(options.endpoint, options.serverKey, { action: 'register-chameleon-id', canaryId: material.canaryId, exposedId: String(identifier.value) }, 3500); }
      catch { output.data.splice(insertedIndex, 1); }
    }
  }
  return watermarkPayloadWithMarker(output, material.marker);
}
export async function getArixPolicy({ endpoint, serverKey, fallback = {} } = {}) { try { return { ...fallback, ...(await remotePolicy(endpoint, serverKey) ?? {}) }; } catch { return fallback; } }
export function redactResponseText(text) { return redactSensitiveText(text); }
export { inspectRequest, redactSensitiveText, validatePayloadSchema, scopeQuery, arixSafeFetch };
export { compileOpenApiRequestSchema } from '../api/_lib/schema.js';

export { getArixContext, protectPrismaClient } from './context.js';
export { runWithArixContext };

export { installProcessEgressFirewall } from './process-egress-firewall.js';
export { withPostgresTenantTransaction, provisionPostgresTenantRls } from '../api/_lib/postgres-rls.js';

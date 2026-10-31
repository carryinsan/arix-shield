import { inspectRequest, redactSensitiveText, validateJsonSchema } from '../api/_lib/waf-engine.js';
import { watermarkJson, spliceCanaryRow } from '../api/_lib/watermark.js';

const processBuckets = new Map();
const policyCache = new Map();
const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);

async function remotePolicy(endpoint, serverKey) {
  if (!endpoint || !serverKey) return null;
  const cacheKey = `${endpoint}:${serverKey.slice(-10)}`;
  const cached = policyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 30000) return cached.policy;
  const response = await fetch(`${endpoint.replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey }, body: JSON.stringify({ action: 'get-policy' }), signal: AbortSignal.timeout(2500) });
  if (!response.ok) throw new Error(`ArixShield policy fetch failed (${response.status}).`);
  const data = await response.json();
  policyCache.set(cacheKey, { at: Date.now(), policy: data.policy ?? {} });
  return data.policy ?? {};
}

export async function getArixPolicy({ endpoint, serverKey, fallback = {} } = {}) {
  try { return { ...fallback, ...(await remotePolicy(endpoint, serverKey) ?? {}) }; }
  catch { return fallback; }
}

function localTokenBucket(key, capacity, windowMs, weight = 1) {
  const now = Date.now();
  const refillPerMs = capacity / windowMs;
  const item = processBuckets.get(key) ?? { tokens: capacity, updated: now };
  item.tokens = Math.min(capacity, item.tokens + Math.max(0, now - item.updated) * refillPerMs);
  item.updated = now;
  const allowed = item.tokens >= weight;
  if (allowed) item.tokens -= weight;
  processBuckets.set(key, item);
  if (processBuckets.size > 10000) {
    for (const [bucketKey, bucket] of processBuckets) if (now - bucket.updated > windowMs * 3) processBuckets.delete(bucketKey);
  }
  return { allowed, remaining: Math.floor(item.tokens), retryAfterMs: allowed ? 0 : Math.ceil((weight - item.tokens) / refillPerMs) };
}


async function distributedTokenBucket({ endpoint, serverKey, scope, algorithm = 'TOKEN_BUCKET', limit, windowMs = 60000, weight = 1 }) {
  const response = await fetch(`${String(endpoint).replace(/\/$/, '')}/api/shield`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey },
    body: JSON.stringify({ action: 'check-limit', scope, algorithm, limit, windowMs, weight }),
    signal: AbortSignal.timeout(3500)
  });
  if (!response.ok) throw new Error(`ArixShield distributed quota check failed (${response.status}).`);
  const data = await response.json();
  if (!data?.decision || typeof data.decision.allowed !== 'boolean') throw new Error('ArixShield returned an invalid distributed quota decision.');
  return data.decision;
}

function sendDecision(res, status, payload) {
  if (typeof res.status === 'function' && typeof res.json === 'function') return res.status(status).json(payload);
  res.statusCode = status;
  res.setHeader?.('Content-Type', 'application/json; charset=utf-8');
  res.end?.(JSON.stringify(payload));
}

export function createArixShield(options = {}) {
  const mode = options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE';
  const limit = Math.max(10, Math.min(10000, Number(options.rateLimitPerMinute) || 120));
  const windowMs = 60000;
  const endpoint = String(options.endpoint ?? '').replace(/\/$/, '');
  const serverKey = options.serverKey;
  if (!serverKey || !serverKey.startsWith('ARIX_SECRET_')) throw new Error('createArixShield requires the server-only ARIX_SECRET_ key.');

  return async function arixShieldMiddleware(req, res, next) {
    const url = req.originalUrl || req.url || '/';
    const body = req.body ?? null;
    const inspection = inspectRequest({ method: req.method, url, headers: req.headers, body, contentLength: req.headers?.['content-length'] });
    const identity = String(req.user?.id ?? req.auth?.userId ?? req.ip ?? 'anonymous').slice(0, 160);
    let policy = { mode, rateLimitPerMinute: limit, blockDatacenterAsn: false };
    try { policy = { ...policy, ...(await remotePolicy(endpoint, serverKey) ?? {}) }; } catch (error) { options.onTelemetryError?.(error); }
    const quotaLimit = Math.max(10, Math.min(10000, Number(policy.rateLimitPerMinute) || limit));
    let quota;
    try {
      quota = options.globalRateLimit === true
        ? await distributedTokenBucket({ endpoint, serverKey, scope: `${identity}:${String(req.method || 'GET').toUpperCase()}:${url.split('?')[0]}`, algorithm: options.rateLimitAlgorithm ?? 'TOKEN_BUCKET', limit: quotaLimit, windowMs, weight: options.rateLimitWeight ?? 1 })
        : localTokenBucket(`${identity}:${String(req.method || 'GET').toUpperCase()}:${url.split('?')[0]}`, quotaLimit, windowMs);
    } catch (error) {
      options.onTelemetryError?.(error);
      if (options.failOpen === true) quota = localTokenBucket(`${identity}:${String(req.method || 'GET').toUpperCase()}:${url.split('?')[0]}`, quotaLimit, windowMs);
      else return sendDecision(res, 503, { error: 'ArixShield distributed quota service is unavailable.' });
    }
    const findings = [...inspection.findings];
    if (options.schema && !['GET', 'HEAD'].includes(String(req.method || 'GET').toUpperCase())) {
      const validation = validateJsonSchema(body, options.schema);
      if (!validation.valid) findings.unshift({ id: 'SCHEMA_VALIDATION', category: 'SCHEMA', severity: 'high', detail: validation.errors.slice(0, 3).join('; ').slice(0, 180) });
    }
    if (!quota.allowed) findings.unshift({ id: 'LOCAL_RATE_LIMIT', category: 'RATE_LIMIT', severity: 'high', detail: 'Configured per-identity quota exceeded.' });
    const pathname = String(url).split('?')[0];
    const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname);
    const asn = String(req.headers?.['x-vercel-ip-as-number'] ?? '');
    if (policy.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(asn)) findings.unshift({ id: 'DATACENTER_ASN', category: 'DATACENTER', severity: 'high', detail: 'Datacenter ASN policy matched a human-only endpoint.' });
    const blocked = findings.length > 0 && policy.mode !== 'DRY_RUN';

    const report = () => {
      if (!endpoint) return;
      const payload = {
        action: 'server-event',
        type: blocked ? 'SDK_THREAT_BLOCK' : findings.length ? 'SDK_THREAT_OBSERVED' : 'SDK_REQUEST',
        blocked,
        path: String(url).slice(0, 180),
        method: String(req.method || 'GET').slice(0, 12),
        riskScore: inspection.riskScore,
        findings: findings.slice(0, 20),
        userId: identity
      };
      fetch(`${endpoint}/api/shield`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(2500)
      }).catch((error) => options.onTelemetryError?.(error));
    };

    if (blocked) {
      report();
      return sendDecision(res, findings.some((f) => f.category === 'RATE_LIMIT') ? 429 : 403, {
        error: 'Request blocked by ArixShield local policy.',
        riskScore: inspection.riskScore,
        findings: findings.slice(0, 20)
      });
    }
    if (options.reportAllRequests === true || findings.length > 0) res.once?.('finish', report);
    req.arixShield = { allowed: true, mode: policy.mode, riskScore: inspection.riskScore, findings, remaining: quota.remaining };
    return next();
  };
}

export async function reportEvent({ endpoint, serverKey, type = 'APP_EVENT', path = '/', method = 'GET', blocked = false, riskScore = 0, findings = [], userId = 'anonymous' }) {
  if (!endpoint || !serverKey?.startsWith('ARIX_SECRET_')) throw new Error('ArixShield endpoint and server key are required.');
  const response = await fetch(`${String(endpoint).replace(/\/$/, '')}/api/shield`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': serverKey },
    body: JSON.stringify({ action: 'server-event', type, path, method, blocked, riskScore, findings, userId }),
    signal: AbortSignal.timeout(4000)
  });
  if (!response.ok) throw new Error(`ArixShield telemetry request failed (${response.status}).`);
  return response.json();
}

export async function watermarkResponseData(payload, context, options = {}) {
  const cloned = structuredClone(payload);
  let canaryEnabled = options.canaryRowsEnabled === true || context.canaryRowsEnabled === true;
  if (options.canaryRowsEnabled === undefined && context.canaryRowsEnabled === undefined && options.endpoint && options.serverKey) {
    const policy = await getArixPolicy(options);
    canaryEnabled = policy.canaryRowsEnabled === true;
  }
  const canary = await spliceCanaryRow(cloned, context, canaryEnabled);
  return watermarkJson(canary, context);
}

export function redactResponseText(text) {
  return redactSensitiveText(text);
}

export { inspectRequest, redactSensitiveText };

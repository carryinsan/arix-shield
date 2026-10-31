import { inspectRequest, validateJsonSchema, redactSensitiveText } from '../api/_lib/waf-engine.js';

const buckets = new Map();
const policyCache = new Map();
const DATA_CENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '9009']);

async function resolvePolicy(options) {
  if (!options.endpoint || !options.serverKey) return {};
  const cacheKey = `${options.endpoint}:${options.serverKey.slice(-10)}`;
  const cached = policyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 30000) return cached.policy;
  const response = await fetch(`${String(options.endpoint).replace(/\/$/, '')}/api/shield`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Arix-Server-Key': options.serverKey }, body: JSON.stringify({ action: 'get-policy' }), signal: AbortSignal.timeout(2500) });
  if (!response.ok) throw new Error(`ArixShield policy fetch failed (${response.status}).`);
  const data = await response.json();
  const policy = data.policy ?? {};
  policyCache.set(cacheKey, { at: Date.now(), policy });
  return policy;
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

function consume(key, limit, windowMs) {
  const now = Date.now();
  const bucket = buckets.get(key) ?? { count: 0, start: now };
  if (now - bucket.start >= windowMs) { bucket.count = 0; bucket.start = now; }
  bucket.count++;
  buckets.set(key, bucket);
  if (buckets.size > 10000) for (const [id, item] of buckets) if (now - item.start > windowMs * 3) buckets.delete(id);
  return { allowed: bucket.count <= limit, remaining: Math.max(0, limit - bucket.count), resetAt: bucket.start + windowMs };
}

export async function protectRequest(request, options = {}) {
  const method = request.method || 'GET';
  const url = request.url || '/';
  let body = null;
  if (!['GET', 'HEAD'].includes(method.toUpperCase())) {
    try {
      const text = await request.clone().text();
      if (text.length > 32768) return { allowed: false, status: 413, response: Response.json({ error: 'Request body too large.' }, { status: 413 }), findings: [] };
      if (text) {
        try { body = JSON.parse(text); } catch { body = text; }
      }
    } catch {
      return { allowed: false, status: 400, response: Response.json({ error: 'Request body could not be inspected.' }, { status: 400 }), findings: [] };
    }
  }
  const inspection = inspectRequest({ method, url, headers: request.headers, body, contentLength: request.headers.get('content-length') });
  let policy = { mode: options.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE', rateLimitPerMinute: options.rateLimitPerMinute ?? 120, blockDatacenterAsn: false };
  if (options.endpoint && options.serverKey) { try { policy = { ...policy, ...(await resolvePolicy(options)) }; } catch (error) { options.onPolicyError?.(error); } }
  const subject = String(options.userId ?? request.headers.get('x-arix-session-id') ?? 'anonymous').slice(0, 120);
  const pathname = new URL(url).pathname;
  const quotaLimit = Math.max(1, Math.min(10000, Number(policy.rateLimitPerMinute) || 120));
  let quota;
  try {
    quota = options.globalRateLimit === true
      ? await distributedTokenBucket({ endpoint: options.endpoint, serverKey: options.serverKey, scope: `${subject}:${method.toUpperCase()}:${pathname}`, algorithm: options.rateLimitAlgorithm ?? 'TOKEN_BUCKET', limit: quotaLimit, windowMs: options.rateLimitWindowMs ?? 60000, weight: options.rateLimitWeight ?? 1 })
      : consume(`${subject}:${method.toUpperCase()}:${pathname}`, quotaLimit, 60000);
  } catch (error) {
    options.onPolicyError?.(error);
    if (options.failOpen === true) quota = consume(`${subject}:${method.toUpperCase()}:${pathname}`, quotaLimit, 60000);
    else return { allowed: false, status: 503, response: Response.json({ error: 'ArixShield distributed quota service is unavailable.' }, { status: 503 }), findings: [] };
  }
  const findings = [...inspection.findings];
  if (options.schema && !['GET', 'HEAD'].includes(method.toUpperCase())) {
    const validation = validateJsonSchema(body, options.schema);
    if (!validation.valid) findings.unshift({ id: 'SCHEMA_VALIDATION', category: 'SCHEMA', severity: 'high', detail: validation.errors.slice(0, 3).join('; ').slice(0, 180) });
  }
  if (!quota.allowed) findings.unshift({ id: 'LOCAL_RATE_LIMIT', category: 'RATE_LIMIT', severity: 'high', detail: 'Configured request quota exceeded.' });
  const humanOnly = /\/(?:login|signup|checkout)(?:\/|$)/i.test(pathname);
  if (policy.blockDatacenterAsn && humanOnly && DATA_CENTER_ASNS.has(request.headers.get('x-vercel-ip-as-number') || '')) findings.unshift({ id: 'DATACENTER_ASN', category: 'DATACENTER', severity: 'high', detail: 'Datacenter ASN policy matched a human-only endpoint.' });
  const mode = policy.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE';
  const blocked = findings.length > 0 && mode === 'ENFORCE';
  return {
    allowed: !blocked,
    status: blocked ? findings.some((f) => f.category === 'RATE_LIMIT') ? 429 : 403 : 200,
    riskScore: inspection.riskScore,
    findings,
    remaining: quota.remaining,
    response: blocked ? Response.json({ error: 'Request blocked by ArixShield.', findings, riskScore: inspection.riskScore }, { status: findings.some((f) => f.category === 'RATE_LIMIT') ? 429 : 403 }) : null
  };
}

export { redactSensitiveText };

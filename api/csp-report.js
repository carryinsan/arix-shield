import { createHash } from 'node:crypto';
import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { clientRateKey, methodNotAllowed, sendJson, readJson } from './_lib/http.js';
import { rateLimit } from './_lib/redis.js';

function safeLocation(value) {
  if (typeof value !== 'string' || value.length > 2048) return '';
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`.slice(0, 500);
  } catch {
    return value.split(/[?#]/, 1)[0].slice(0, 200);
  }
}

function sanitizeViolation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const get = (key, alternate = '') => {
    const raw = value[key] ?? value[alternate];
    return typeof raw === 'string' ? raw.slice(0, 180) : '';
  };
  return {
    documentUri: safeLocation(get('document-uri', 'documentURL')),
    blockedUri: safeLocation(get('blocked-uri', 'blockedURL')),
    effectiveDirective: get('effective-directive', 'effectiveDirective'),
    violatedDirective: get('violated-directive', 'violatedDirective'),
    disposition: get('disposition'),
    sourceFile: safeLocation(get('source-file', 'sourceFile')),
    lineNumber: Number.isSafeInteger(Number(value['line-number'] ?? value.lineNumber)) ? Number(value['line-number'] ?? value.lineNumber) : 0,
    statusCode: Number.isSafeInteger(Number(value['status-code'] ?? value.statusCode)) ? Number(value['status-code'] ?? value.statusCode) : 0
  };
}

async function handler(req, res) {
  if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
  try {
    const scope = createHash('sha256').update(clientRateKey(req)).digest('hex');
    const limit = await rateLimit({ key: `arix:csp-report:${scope}`, algorithm: 'SLIDING_WINDOW', limit: 60, windowMs: 60000 });
    if (!limit.allowed) return sendJson(res, 429, { error: 'CSP report rate limit exceeded.' }, { 'Retry-After': String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))) });
    const payload = await readJson(req, 8192);
    const source = payload?.['csp-report'] ?? payload?.body ?? (Array.isArray(payload) ? payload.slice(0, 10).map((item) => item?.body ?? item) : payload);
    const reports = (Array.isArray(source) ? source : [source]).slice(0, 10).map(sanitizeViolation).filter(Boolean);
    if (!reports.length) return sendJson(res, 400, { error: 'No valid CSP violation report was supplied.' });
    for (const report of reports) console.warn('[ArixShield] CSP violation', JSON.stringify(report));
    res.statusCode = 204;
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    return res.end();
  } catch (error) {
    const status = Number(error?.statusCode) || 503;
    if (status === 400 || status === 413) return sendJson(res, status, { error: error.message });
    console.error('[ArixShield] CSP report processing unavailable:', error?.message || error);
    return sendJson(res, 503, { error: 'CSP report service is temporarily unavailable.' });
  }
}

export default createCompatibleHandler(handler);

// Keep raw request bytes available for origin-proof verification in the shared adapter.
export const config = { api: { bodyParser: false } };

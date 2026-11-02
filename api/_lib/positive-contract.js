import { validateJsonSchema, getDataBytes } from './waf-engine.js';

export function compilePositiveRouteContract(contract) {
  if (!contract || typeof contract !== 'object' || Array.isArray(contract)) throw new TypeError('Route contract must be an object');
  const methods = new Set((contract.methods || []).map((method) => String(method).toUpperCase()));
  if (!methods.size || [...methods].some((method) => !/^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)$/.test(method))) throw new TypeError('Contract requires an explicit supported methods list');
  const contentTypes = new Set((contract.contentTypes || []).map((type) => String(type).split(';')[0].trim().toLowerCase()));
  const allowedQueryKeys = new Set((contract.allowedQueryKeys || []).map(String));
  const paramPatterns = new Map();
  for (const [name, source] of Object.entries(contract.paramPatterns || {})) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(name) || String(source).length > 256) throw new TypeError('Invalid route parameter pattern');
    paramPatterns.set(name, new RegExp(`^(?:${source})$`));
  }
  const maxBytes = Math.min(10 * 1024 * 1024, Math.max(0, Number(contract.maxBytes ?? 32_768)));
  if (!Number.isFinite(maxBytes)) throw new TypeError('maxBytes must be finite');
  return Object.freeze({
    check(request) {
      const findings = [];
      const method = String(request?.method || 'GET').toUpperCase();
      if (!methods.has(method)) findings.push({ code: 'METHOD_NOT_ALLOWED', status: 405 });
      const headers = request?.headers || {};
      const contentType = String(headers['content-type'] || headers['Content-Type'] || '').split(';')[0].trim().toLowerCase();
      if (contentTypes.size && request?.body != null && !contentTypes.has(contentType)) findings.push({ code: 'CONTENT_TYPE_NOT_ALLOWED', status: 415 });
      let url;
      try { url = new URL(String(request?.url || '/'), 'http://arix.invalid'); } catch { findings.push({ code: 'URL_INVALID', status: 400 }); }
      if (url) {
        for (const key of new Set(url.searchParams.keys())) if (!allowedQueryKeys.has(key)) findings.push({ code: 'QUERY_KEY_NOT_ALLOWED', key, status: 400 });
        for (const key of allowedQueryKeys) if (url.searchParams.getAll(key).length > 1) findings.push({ code: 'QUERY_KEY_DUPLICATE', key, status: 400 });
      }
      let bodySize = 0;
      try { bodySize = request?.rawBody != null ? Buffer.byteLength(request.rawBody) : request?.body == null ? 0 : getDataBytes(request.body); }
      catch { findings.push({ code: 'BODY_UNSERIALIZABLE', status: 400 }); }
      if (bodySize > maxBytes) findings.push({ code: 'BODY_TOO_LARGE', status: 413 });
      if (contract.bodyRequired === true && request?.body == null && request?.rawBody == null) findings.push({ code: 'BODY_REQUIRED', status: 400 });
      if (contract.bodySchema && request?.body != null) {
        const validation = validateJsonSchema(request.body, contract.bodySchema);
        if (!validation.valid) findings.push({ code: 'BODY_SCHEMA_INVALID', errors: validation.errors, status: 400 });
      }
      const params = request?.params || {};
      for (const [name, pattern] of paramPatterns) if (params[name] == null || !pattern.test(String(params[name]))) findings.push({ code: 'PATH_PARAM_INVALID', name, status: 400 });
      const status = findings.reduce((highest, item) => Math.max(highest, item.status), 200);
      return Object.freeze({ allowed: findings.length === 0, status, findings: Object.freeze(findings), bodySize });
    }
  });
}

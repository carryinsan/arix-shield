import { createHash, createHmac, timingSafeEqual, randomUUID } from 'node:crypto';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const sortKeys = (value) => Array.isArray(value) ? value.map(sortKeys) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeys(value[key])])) : value;
const clone = (value) => sortKeys(JSON.parse(JSON.stringify(value)));
const stableStringify = (value) => JSON.stringify(sortKeys(value));

export function compileSecurityConfig(config, { previous = null, signingKey = process.env.ARIX_MASTER_SECRET } = {}) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError('Security config must be an object');
  const normalized = clone(config);
  const errors = [];
  const warnings = [];
  const routes = Array.isArray(normalized.routes) ? normalized.routes : [];
  const seen = new Set();
  for (const [index, route] of routes.entries()) {
    const method = String(route?.method || '').toUpperCase();
    const path = String(route?.path || '');
    const key = `${method} ${path}`;
    if (!MUTATING.has(method) && !['GET', 'HEAD', 'OPTIONS'].includes(method)) errors.push({ code: 'ROUTE_METHOD_INVALID', route: key, index });
    if (!path.startsWith('/') || path.includes('..') || path.length > 2048) errors.push({ code: 'ROUTE_PATH_INVALID', route: key, index });
    if (seen.has(key)) errors.push({ code: 'ROUTE_DUPLICATE', route: key, index });
    seen.add(key);
    if (MUTATING.has(method) && route.auth !== true) errors.push({ code: 'MUTATION_REQUIRES_AUTH', route: key, index });
    if (MUTATING.has(method) && route.tenantIsolated !== true) errors.push({ code: 'MUTATION_REQUIRES_TENANT_SCOPE', route: key, index });
    if (route.failOpen === true && (MUTATING.has(method) || route.critical === true)) errors.push({ code: 'CRITICAL_ROUTE_FAIL_OPEN', route: key, index });
  }
  const scanSecrets = (value, path = '$') => {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      const next = `${path}.${key}`;
      if (/^(?:ARIX_SECRET_|UPSTASH_)/i.test(key) && /public|client|browser|exposed/i.test(path)) errors.push({ code: 'SERVER_SECRET_IN_PUBLIC_CONFIG', path: next });
      if (child && typeof child === 'object') scanSecrets(child, next);
    }
  };
  scanSecrets(normalized);
  if (!Array.isArray(normalized.routes)) warnings.push('No route inventory supplied; route coverage cannot be established.');
  const diff = diffSecurityConfig(previous, normalized);
  const payload = stableStringify({ schema: 'arix.security-config.v1', config: normalized, diff });
  const digest = createHash('sha256').update(payload).digest('hex');
  let signature = null;
  if (typeof signingKey === 'string' && Buffer.byteLength(signingKey) >= 32) signature = createHmac('sha256', signingKey).update(payload).digest('hex');
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors), warnings: Object.freeze(warnings), config: normalized, diff, digest, signature, signatureAlgorithm: signature ? 'HMAC-SHA256' : null });
}

export function diffSecurityConfig(before, after) {
  const a = before ? stableStringify(before) : 'null';
  const b = stableStringify(after);
  if (a === b) return Object.freeze({ changed: false, beforeSha256: createHash('sha256').update(a).digest('hex'), afterSha256: createHash('sha256').update(b).digest('hex') });
  return Object.freeze({ changed: true, beforeSha256: createHash('sha256').update(a).digest('hex'), afterSha256: createHash('sha256').update(b).digest('hex') });
}

export function signDualApprovalProposal({ projectId, proposal, actorId, sessionId, secret, now = Date.now(), ttlMs = 300_000 } = {}) {
  if (!projectId || !proposal || !actorId || !sessionId || typeof secret !== 'string' || Buffer.byteLength(secret) < 32) throw new TypeError('Dual-approval fields and a 32-byte secret are required');
  const body = { schema: 'arix.dual-approval.v1', id: randomUUID(), projectId: String(projectId), proposal: sortKeys(proposal), proposer: String(actorId), proposerSessionId: String(sessionId), issuedAt: now, expiresAt: now + Math.min(Math.max(ttlMs, 30_000), 900_000) };
  const encoded = Buffer.from(JSON.stringify(body)).toString('base64url');
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

export async function verifyDualApprovalProposal(token, { secret, confirmerId, confirmerSessionId, consumeProposal, now = Date.now() } = {}) {
  if (typeof token !== 'string' || typeof secret !== 'string' || Buffer.byteLength(secret) < 32 || !confirmerId || !confirmerSessionId) return { valid: false, reason: 'INVALID_INPUT' };
  const [encoded, signature, extra] = token.split('.');
  if (!encoded || !signature || extra) return { valid: false, reason: 'MALFORMED' };
  const expected = createHmac('sha256', secret).update(encoded).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return { valid: false, reason: 'SIGNATURE_INVALID' };
  let body;
  try { body = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); } catch { return { valid: false, reason: 'PAYLOAD_INVALID' }; }
  if (body.schema !== 'arix.dual-approval.v1' || body.expiresAt < now) return { valid: false, reason: 'EXPIRED_OR_INVALID' };
  if (body.proposer === String(confirmerId) || body.proposerSessionId === String(confirmerSessionId)) return { valid: false, reason: 'SECOND_CUSTODIAN_REQUIRED' };
  if (typeof consumeProposal !== 'function') return { valid: false, reason: 'ATOMIC_APPROVAL_STORE_REQUIRED' };
  let consumed = false;
  try { consumed = await consumeProposal(body.id, body.expiresAt); } catch { return { valid: false, reason: 'APPROVAL_STORE_UNAVAILABLE' }; }
  if (!consumed) return { valid: false, reason: 'APPROVAL_ALREADY_USED' };
  return { valid: true, proposal: body };
}

export function verifyCompiledSecurityConfig(compiled, signingKey) {
  if (!compiled || !compiled.valid || typeof compiled.signature !== 'string' || typeof signingKey !== 'string' || Buffer.byteLength(signingKey) < 32) return false;
  const payload = stableStringify({ schema: 'arix.security-config.v1', config: compiled.config, diff: compiled.diff });
  const expected = createHmac('sha256', signingKey).update(payload).digest();
  const actual = Buffer.from(compiled.signature, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected) && createHash('sha256').update(payload).digest('hex') === compiled.digest;
}

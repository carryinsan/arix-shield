const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

export function normalizeSecurityPath(input) {
  const raw = String(input || '/');
  // Bound work and retain the original path spelling: WHATWG URL parsing may
  // normalize percent-encoded dot segments before a security check can see them.
  if (raw.length > 4096) return null;
  try {
    const url = new URL(raw, 'https://arixshield.invalid');
    let rawPath;
    const absoluteMatch = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.exec(raw);
    if (absoluteMatch) {
      const authorityStart = raw.indexOf('://') + 3;
      const pathStart = raw.indexOf('/', authorityStart);
      rawPath = pathStart < 0 ? '/' : raw.slice(pathStart).split(/[?#]/, 1)[0];
    } else {
      rawPath = (raw.startsWith('/') ? raw : `/${raw}`).split(/[?#]/, 1)[0];
    }
    if (!rawPath.startsWith('/') || /\\/.test(rawPath)) return null;
    const decoded = rawPath.split('/').map((part) => {
      let value = part;
      let depth = 0;
      while (true) {
        if (++depth > part.length + 1) throw new Error('Path decoding limit exceeded');
        const next = decodeURIComponent(value);
        if (/[\\/\0]/.test(next)) throw new Error('Encoded path separator');
        if ((next === '.' || next === '..') && next !== part) throw new Error('Encoded dot segment');
        if (next === value) break;
        value = next;
      }
      return value;
    });
    const stack = [];
    for (const segment of decoded) {
      if (!segment || segment === '.') continue;
      if (segment === '..') stack.pop();
      else stack.push(segment);
    }
    return `/${stack.join('/')}${rawPath.endsWith('/') && stack.length ? '/' : ''}`;
  } catch {
    return null;
  }
}

function routeMatches(pattern, pathname) {
  if (typeof pattern !== 'string' || pattern.length > 300) return false;
  const escaped = pattern.split('/').map((segment) => {
    if (segment === '*') return '[^/]+';
    if (segment === '**') return '.*';
    if (segment.startsWith(':')) return '[^/]+';
    return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('/');
  try { return new RegExp(`^${escaped}/?$`).test(pathname); } catch { return false; }
}

export function resolveAuthorizationRule(routes, method, pathname) {
  if (!routes || typeof routes !== 'object') return null;
  const verb = String(method || 'GET').toUpperCase();
  const path = normalizeSecurityPath(pathname);
  if (!path) return { deny: true, reason: 'INVALID_PATH' };
  const entries = Array.isArray(routes) ? routes : Object.entries(routes).map(([route, config]) => ({ path: route, ...config }));
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const methods = Array.isArray(entry.methods) ? entry.methods.map((v) => String(v).toUpperCase()) : [String(entry.method || '*').toUpperCase()];
    if (!methods.includes('*') && !methods.includes(verb)) continue;
    if (routeMatches(entry.path || entry.route, path)) return entry;
  }
  return null;
}

export async function authorizeRequest({ method, pathname, routes, context = {}, defaultDenyMutations = false, requireScopedPrecheck = false, preCheck, request = null }) {
  const verb = String(method || 'GET').toUpperCase();
  const rule = resolveAuthorizationRule(routes, verb, pathname);
  const mutating = MUTATING_METHODS.has(verb);
  if (!rule && defaultDenyMutations && mutating) return { allowed: false, status: 403, reason: 'NO_AUTHORIZATION_POLICY' };
  if (!rule) return { allowed: true, rule: null, context };
  if (requireScopedPrecheck && mutating && (rule.tenantIsolated !== true || rule.requirePreCheck !== true || (typeof rule.preCheck !== 'function' && typeof preCheck !== 'function'))) {
    return { allowed: false, status: 403, reason: 'MUTATION_SCOPE_PRECHECK_REQUIRED' };
  }
  if (rule.deny === true) return { allowed: false, status: 403, reason: 'ROUTE_DENIED' };
  const userId = String(context.userId || context.ownerId || '').trim();
  const tenantId = String(context.tenantId || context.projectId || '').trim();
  const roles = new Set((Array.isArray(context.roles) ? context.roles : context.role ? [context.role] : []).map((v) => String(v).toLowerCase()));
  const permissions = new Set(Array.isArray(context.permissions) ? context.permissions.map(String) : []);
  const requiredRoles = Array.isArray(rule.roles) ? rule.roles.map((v) => String(v).toLowerCase()) : [];
  const requiredPermissions = Array.isArray(rule.permissions) ? rule.permissions.map(String) : rule.permission ? [String(rule.permission)] : [];
  if (rule.authenticated !== false && !userId) return { allowed: false, status: 403, reason: 'AUTHENTICATION_REQUIRED' };
  if (requiredRoles.length && !requiredRoles.some((role) => roles.has(role))) return { allowed: false, status: 403, reason: 'ROLE_REQUIRED' };
  if (requiredPermissions.length && !requiredPermissions.every((permission) => permissions.has(permission))) return { allowed: false, status: 403, reason: 'PERMISSION_REQUIRED' };
  if (rule.tenantIsolated === true && !tenantId) return { allowed: false, status: 403, reason: 'TENANT_CONTEXT_REQUIRED' };
  if (rule.tenantId && String(rule.tenantId) !== tenantId) return { allowed: false, status: 403, reason: 'TENANT_MISMATCH' };
  const checks = [rule.preCheck, preCheck].filter((check, index, all) => typeof check === 'function' && all.indexOf(check) === index);
  if (rule.requirePreCheck === true && checks.length === 0) return { allowed: false, status: 403, reason: 'AUTHORIZATION_PRECHECK_REQUIRED' };
  for (const check of checks) {
    let allowed = false;
    try { allowed = (await check({ method: verb, pathname: normalizeSecurityPath(pathname), context, rule, request })) === true; }
    catch { return { allowed: false, status: 403, reason: 'AUTHORIZATION_PRECHECK_FAILED' }; }
    if (!allowed) return { allowed: false, status: 403, reason: 'AUTHORIZATION_PRECHECK_DENIED' };
  }
  return { allowed: true, rule, context: { ...context, userId, tenantId, roles: [...roles], permissions: [...permissions] } };
}

function roleFieldSet(policy, roles, mode) {
  if (!policy) return null;
  if (Array.isArray(policy)) return new Set(policy.map(String));
  if (typeof policy !== 'object') return null;
  const merged = new Set();
  let found = false;
  for (const role of roles) {
    const fields = policy[role];
    if (Array.isArray(fields)) { found = true; fields.forEach((field) => merged.add(String(field))); }
  }
  if (Array.isArray(policy['*'])) { found = true; policy['*'].forEach((field) => merged.add(String(field))); }
  return found ? merged : (mode === 'write' ? new Set() : null);
}

function copyAllowed(value, allowed, prefix = '', depth = 0) {
  if (depth > 24 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => copyAllowed(item, allowed, prefix, depth + 1));
  const out = Object.create(null);
  for (const [key, child] of Object.entries(value)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    const path = prefix ? `${prefix}.${key}` : key;
    const exact = allowed.has(path) || allowed.has(key);
    const nested = [...allowed].some((candidate) => candidate.startsWith(`${path}.`));
    if (exact) out[key] = child && typeof child === 'object' ? copyAllowed(child, allowed, path, depth + 1) : child;
    else if (nested && child && typeof child === 'object') out[key] = copyAllowed(child, allowed, path, depth + 1);
  }
  return out;
}

function stripRestricted(value, denied, prefix = '', depth = 0) {
  if (depth > 24 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => stripRestricted(item, denied, prefix, depth + 1));
  const out = Object.create(null);
  for (const [key, child] of Object.entries(value)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    const path = prefix ? `${prefix}.${key}` : key;
    if (denied.has(path) || denied.has(key)) continue;
    out[key] = stripRestricted(child, denied, path, depth + 1);
  }
  return out;
}

export function filterWriteFields(payload, policy, roles = []) {
  const allowed = roleFieldSet(policy, roles.map((v) => String(v).toLowerCase()), 'write');
  if (!allowed) return payload;
  return copyAllowed(payload, allowed);
}

export function filterReadFields(payload, policy, roles = []) {
  const denied = roleFieldSet(policy, roles.map((v) => String(v).toLowerCase()), 'read');
  if (!denied) return payload;
  return stripRestricted(payload, denied);
}

/**
 * Adds tenant and owner predicates to a Prisma-like `where` object or Mongo filter.
 * It deliberately refuses raw SQL strings: SQL must use bound parameters in the adapter.
 */
export function scopeQuery(query, context, { tenantField = 'tenantId', ownerField = 'ownerId', adapter = 'prisma' } = {}) {
  if (!query || typeof query !== 'object' || Array.isArray(query)) throw new TypeError('scopeQuery requires a structured query object.');
  const tenantId = String(context?.tenantId || context?.projectId || '').trim();
  const ownerId = String(context?.userId || context?.ownerId || '').trim();
  if (!tenantId || !ownerId) throw new Error('scopeQuery requires authenticated tenantId and userId values.');
  if (![tenantField, ownerField].every((v) => typeof v === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(v))) throw new TypeError('Invalid tenant or owner field name.');
  const scoped = { [tenantField]: tenantId, [ownerField]: ownerId };
  if (adapter === 'mongo') return { $and: [query, scoped] };
  if (adapter === 'prisma') return { ...query, where: { AND: [query.where || {}, scoped] } };
  if (adapter === 'sql-builder') return { ...query, arixPredicates: scoped };
  throw new Error('Unsupported scopeQuery adapter. Use prisma, mongo or sql-builder.');
}

export function isMutatingMethod(method) { return MUTATING_METHODS.has(String(method || '').toUpperCase()); }

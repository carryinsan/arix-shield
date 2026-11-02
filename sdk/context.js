import { AsyncLocalStorage } from 'node:async_hooks';

const storage = new AsyncLocalStorage();
const READ_OPS = new Set(['findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany', 'count', 'aggregate', 'groupBy']);
const WHERE_WRITE_OPS = new Set(['update', 'updateMany', 'delete', 'deleteMany']);
const UNSUPPORTED_RAW = new Set(['$queryRaw', '$queryRawUnsafe', '$executeRaw', '$executeRawUnsafe', '$runCommandRaw', '$runCommandRawUnsafe']);
const SAFE_CLIENT_METHODS = new Set(['$connect', '$disconnect', '$on']);
const NESTED_WRITE_KEYS = new Set(['create', 'createMany', 'connect', 'connectOrCreate', 'set', 'disconnect', 'update', 'updateMany', 'upsert', 'delete', 'deleteMany']);

export function runWithArixContext(context, callback) {
  if (!context || typeof context !== 'object' || typeof callback !== 'function') throw new TypeError('runWithArixContext requires a context object and callback.');
  const safe = Object.freeze({
    tenantId: String(context.tenantId || context.projectId || '').trim(),
    userId: String(context.userId || context.ownerId || '').trim(),
    roles: Object.freeze(Array.isArray(context.roles) ? context.roles.map(String).slice(0, 32) : []),
    permissions: Object.freeze(Array.isArray(context.permissions) ? context.permissions.map(String).slice(0, 64) : []),
    method: String(context.method || '').toUpperCase().slice(0, 12),
    path: String(context.path || '').slice(0, 2048)
  });
  return storage.run(safe, callback);
}

export function getArixContext() { return storage.getStore() || null; }

function requireIdentity() {
  const context = getArixContext();
  if (!context?.tenantId || !context?.userId || context.userId === 'anonymous') {
    throw Object.assign(new Error('ARIX_UNSCOPED_DB_ACCESS: a verified tenant and user context is required.'), { code: 'ARIX_UNSCOPED_DB_ACCESS' });
  }
  return context;
}

function hasNestedWrite(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 12) return false;
  if (Array.isArray(value)) return value.some((item) => hasNestedWrite(item, depth + 1));
  for (const [key, child] of Object.entries(value)) {
    if (NESTED_WRITE_KEYS.has(key)) return true;
    if (child && typeof child === 'object' && hasNestedWrite(child, depth + 1)) return true;
  }
  return false;
}

function scopedWhere(where, context, policy) {
  const result = { ...(where && typeof where === 'object' && !Array.isArray(where) ? where : {}) };
  for (const [field, expected] of [[policy.tenantField, context.tenantId], [policy.ownerField, context.userId]]) {
    if (Object.prototype.hasOwnProperty.call(result, field) && String(result[field]) !== expected) {
      throw Object.assign(new Error('ARIX_SCOPE_MISMATCH: query attempted to cross tenant or owner boundaries.'), { code: 'ARIX_SCOPE_MISMATCH' });
    }
    result[field] = expected;
  }
  return result;
}

function scopedData(data, context, policy) {
  const apply = (record) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new TypeError('Protected Prisma writes require plain object data.');
    const output = { ...record };
    for (const [field, expected] of [[policy.tenantField, context.tenantId], [policy.ownerField, context.userId]]) {
      if (Object.prototype.hasOwnProperty.call(output, field) && String(output[field]) !== expected) {
        throw Object.assign(new Error('ARIX_SCOPE_MISMATCH: write attempted to assign a foreign tenant or owner.'), { code: 'ARIX_SCOPE_MISMATCH' });
      }
      output[field] = expected;
    }
    return output;
  };
  return Array.isArray(data) ? data.map(apply) : apply(data);
}

function protectDelegate(delegate, model, options) {
  return new Proxy(delegate, {
    get(target, property, receiver) {
      const original = Reflect.get(target, property, receiver);
      if (typeof property !== 'string' || typeof original !== 'function') return original;
      return (...input) => {
        const context = requireIdentity();
        const policy = options.modelPolicies?.[model] || {};
        const tenantField = String(policy.tenantField || options.tenantField || 'tenantId');
        const ownerField = String(policy.ownerField || options.ownerField || 'ownerId');
        if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(tenantField) || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(ownerField) || tenantField === ownerField) throw new Error(`Invalid scope fields for Prisma model ${model}.`);
        const scope = { tenantField, ownerField };
        if (!READ_OPS.has(property) && !WHERE_WRITE_OPS.has(property) && !['create', 'createMany', 'upsert'].includes(property)) {
          throw Object.assign(new Error(`ARIX_UNSUPPORTED_DB_OPERATION: Prisma ${model}.${property} is not covered by the scope adapter.`), { code: 'ARIX_UNSUPPORTED_DB_OPERATION' });
        }
        const args = { ...(input[0] || {}) };
        if ((property === 'create' || property === 'createMany' || property === 'upsert' || WHERE_WRITE_OPS.has(property)) && hasNestedWrite(args.data ?? args.create ?? args.update ?? {})) {
          throw Object.assign(new Error('ARIX_NESTED_WRITE_BLOCKED: nested Prisma writes require an explicit, separately scoped operation.'), { code: 'ARIX_NESTED_WRITE_BLOCKED' });
        }
        if (READ_OPS.has(property) || WHERE_WRITE_OPS.has(property)) args.where = scopedWhere(args.where, context, scope);
        if (property === 'create' || property === 'createMany') args.data = scopedData(args.data, context, scope);
        if (property === 'upsert') {
          args.where = scopedWhere(args.where, context, scope);
          args.create = scopedData(args.create, context, scope);
          // Prevent ownership reassignment through an upsert update branch.
          args.update = scopedData(args.update || {}, context, scope);
        }
        return Reflect.apply(original, target, [args, ...input.slice(1)]);
      };
    }
  });
}

/**
 * Wrap a Prisma client once at application startup. Supported model operations
 * are automatically scoped to the current AsyncLocalStorage tenant+user. Raw SQL,
 * nested writes, client extensions/middleware, raw SQL, and unrecognized operations
 * are rejected; this intentionally favors false denials over silently unscoped data
 * access. This is not a universal
 * proxy for other ORMs/drivers and does not intercept an unwrapped client reference.
 */
export function protectPrismaClient(client, options = {}) {
  if (!client || typeof client !== 'object') throw new TypeError('protectPrismaClient requires a Prisma client object.');
  const cache = new WeakMap();
  return new Proxy(client, {
    get(target, property, receiver) {
      const original = Reflect.get(target, property, target);
      if (typeof property === 'string' && UNSUPPORTED_RAW.has(property)) {
        return () => { throw Object.assign(new Error('ARIX_RAW_SQL_BLOCKED: raw SQL bypasses the automatic tenant scope. Use a separately reviewed scoped repository method.'), { code: 'ARIX_RAW_SQL_BLOCKED' }); };
      }
      if (property === '$transaction' && typeof original === 'function') {
        return (...args) => {
          requireIdentity();
          if (typeof args[0] === 'function') {
            const callback = args[0];
            args[0] = (tx) => callback(protectPrismaClient(tx, options));
          }
          return Reflect.apply(original, target, args);
        };
      }
      if (typeof property === 'string' && property.startsWith('$')) {
        if (SAFE_CLIENT_METHODS.has(property) && typeof original === 'function') return original.bind(target);
        throw Object.assign(new Error(`ARIX_UNSUPPORTED_DB_OPERATION: Prisma client method ${property} is not exposed by the scoped client.`), { code: 'ARIX_UNSUPPORTED_DB_OPERATION' });
      }
      if (original && typeof original === 'object' && !Array.isArray(original)) {
        if (cache.has(original)) return cache.get(original);
        const wrapped = protectDelegate(original, String(property), options);
        cache.set(original, wrapped);
        return wrapped;
      }
      return original;
    }
  });
}

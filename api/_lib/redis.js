import { randomUUID, createHash, createHmac, randomBytes } from 'node:crypto';
import { createTenantDek, derivePurposeKey, encryptTenantData, decryptTenantData, wrapTenantDek, unwrapTenantDek } from './kms.js';
import { runWithCircuit } from './circuit-breaker.js';

const localStore = globalThis.__ARIXSHIELD_LOCAL_REDIS__ ??= new Map();
const localAuditChains = globalThis.__ARIX_AUDIT_LOCAL_CHAINS__ ??= new Map();
const localAuditQueues = globalThis.__ARIX_AUDIT_LOCAL_QUEUES__ ??= new Map();
let warned = false;

export function normalizeRedisRestUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 2048 || raw !== raw.trim() || /[\u0000-\u0020\u007f]/.test(raw)) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash || (url.port && url.port !== '443') || !['', '/'].includes(url.pathname)) return null;
    return url.origin;
  } catch { return null; }
}
function redisEndpoint() {
  const base = normalizeRedisRestUrl(process.env.UPSTASH_REDIS_REST_URL);
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || typeof token !== 'string' || !token || token.length > 8192 || /[\r\n\u0000]/.test(token)) return null;
  return { base, token };
}
function redisConfigured() {
  if (redisEndpoint()) return true;
  // A partially present or malformed remote configuration is an operator error,
  // never a reason to silently downgrade to process-local security state.
  if (process.env.UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_TOKEN) {
    throw new Error('Invalid Upstash Redis configuration: use a credential-free HTTPS REST root URL and a valid token.');
  }
  return false;
}
function localModeAllowed() { return process.env.NODE_ENV !== 'production'; }
function warnFallback() {
  if (!warned) { warned = true; console.warn('[ArixShield] Upstash Redis is not configured. Using an ephemeral in-memory store for local preview only; data is not shared between serverless instances and will be lost on restart.'); }
}
function getLocal(key) {
  const item = localStore.get(key);
  if (!item) return null;
  if (item.expiresAt && item.expiresAt <= Date.now()) { localStore.delete(key); return null; }
  return item;
}
function setLocal(key, type, value, ttlSeconds = null) {
  const expiresAt = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
  localStore.set(key, { type, value, expiresAt });
}

async function command(parts) {
  if (!Array.isArray(parts) || !parts.length) throw new TypeError('Redis command must be a non-empty array.');
  if (!redisConfigured()) {
    if (process.env.UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_TOKEN) throw new Error('Invalid Upstash Redis configuration: use a credential-free HTTPS REST root URL and a valid token.');
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in production.');
    warnFallback(); return localCommand(parts);
  }
  const endpoint = redisEndpoint();
  if (!endpoint) throw new Error('Invalid Upstash Redis configuration: use a credential-free HTTPS REST root URL and a valid token.');
  const { base, token } = endpoint;
  return runWithCircuit(`redis:${base}`, async (signal) => {
    const response = await fetch(base, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(parts), signal });
    if (!response.ok) throw new Error(`Upstash Redis REST request failed (${response.status}).`);
    const payload = await response.json();
    if (Object.hasOwn(payload, 'error')) throw new Error(`Upstash Redis error: ${String(payload.error).slice(0, 240)}`);
    return payload.result;
  }, { tripAfterMs: 450, timeoutMs: 450, openMs: 10000, failureThreshold: 3 });
}

async function pipeline(commands) {
  if (!Array.isArray(commands) || !commands.length) return [];
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback(); const results = []; for (const parts of commands) results.push(await localCommand(parts)); return results;
  }
  const endpoint = redisEndpoint();
  if (!endpoint) throw new Error('Invalid Upstash Redis configuration: use a credential-free HTTPS REST root URL and a valid token.');
  const { base, token } = endpoint;
  return runWithCircuit(`redis:${base}`, async (signal) => {
    const response = await fetch(`${base}/pipeline`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(commands), signal });
    if (!response.ok) throw new Error(`Upstash pipeline failed (${response.status}).`);
    const rows = await response.json();
    if (!Array.isArray(rows)) throw new Error('Unexpected Upstash pipeline response.');
    return rows.map((row) => { if (row && Object.hasOwn(row, 'error')) throw new Error(`Upstash Redis error: ${String(row.error).slice(0, 240)}`); return row?.result; });
  }, { tripAfterMs: 450, timeoutMs: 450, openMs: 10000, failureThreshold: 3 });
}

function localCommand(parts) {
  const [rawName, ...args] = parts; const name = String(rawName).toUpperCase(); const key = String(args[0] ?? ''); const item = getLocal(key);
  switch (name) {
    case 'PING': return 'PONG';
    case 'GET': return item?.type === 'string' ? item.value : null;
    case 'GETDEL': { const value = item?.type === 'string' ? item.value : null; localStore.delete(key); return value; }
    case 'MGET': return args.map((candidate) => { const value = getLocal(String(candidate)); return value?.type === 'string' ? value.value : null; });
    case 'SET': { const value = String(args[1] ?? ''); const nx = args.some((v) => String(v).toUpperCase() === 'NX'); const exIndex = args.findIndex((v) => String(v).toUpperCase() === 'EX'); if (nx && item) return null; setLocal(key, 'string', value, exIndex >= 0 ? Number(args[exIndex + 1]) : null); return 'OK'; }
    case 'DEL': { let count = 0; for (const k of args) if (localStore.delete(String(k))) count++; return count; }
    case 'EXPIRE': { if (!item) return 0; const ttl = Number(args[1]); if (!Number.isFinite(ttl) || ttl <= 0) { localStore.delete(key); return 1; } item.expiresAt = Date.now() + ttl * 1000; return 1; }
    case 'PTTL': return !item ? -2 : (item.expiresAt ? Math.max(0, item.expiresAt - Date.now()) : -1);
    case 'INCR': case 'INCRBY': { const by = name === 'INCR' ? 1 : Number(args[1]); const next = Number(item?.value ?? 0) + by; setLocal(key, 'string', String(next), item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null); return next; }
    case 'LPUSH': { const list = item?.type === 'list' ? item.value : []; for (const value of args.slice(1)) list.unshift(String(value)); setLocal(key, 'list', list, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null); return list.length; }
    case 'LTRIM': { if (!item || item.type !== 'list') return 'OK'; const start = Number(args[1]); const end = Number(args[2]); const stop = end < 0 ? item.value.length + end + 1 : end + 1; item.value = item.value.slice(start, Math.max(start, stop)); return 'OK'; }
    case 'LRANGE': { if (!item || item.type !== 'list') return []; const start = Number(args[1]); const end = Number(args[2]); const stop = end < 0 ? item.value.length + end + 1 : end + 1; return item.value.slice(start, Math.max(start, stop)); }
    case 'LLEN': return item?.type === 'list' ? item.value.length : 0;
    case 'RECOVERALERT': {
      const processingKey = String(args[0] ?? '');
      const queueKey = String(args[1] ?? '');
      const deadKey = String(args[2] ?? '');
      const maxAttempts = Math.max(1, Math.floor(Number(args[3]) || 8));
      const processing = getLocal(processingKey);
      if (!processing || processing.type !== 'list' || processing.value.length === 0) return 0;
      const raw = processing.value.pop();
      if (processing.value.length === 0) localStore.delete(processingKey);
      const queueItem = getLocal(queueKey);
      const queue = queueItem?.type === 'list' ? queueItem.value : [];
      const deadItem = getLocal(deadKey);
      const dead = deadItem?.type === 'list' ? deadItem.value : [];
      let payload;
      try { payload = JSON.parse(String(raw)); } catch { payload = null; }
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        dead.unshift(String(raw));
        setLocal(deadKey, 'list', dead.slice(0, 100), deadItem?.expiresAt ? Math.max(1, Math.ceil((deadItem.expiresAt - Date.now()) / 1000)) : null);
        return 2;
      }
      const attempts = Math.max(0, Number(payload.attempts) || 0) + 1;
      const recovered = JSON.stringify({ ...payload, attempts, recoveredAt: new Date().toISOString() });
      if (attempts >= maxAttempts) {
        dead.unshift(recovered);
        setLocal(deadKey, 'list', dead.slice(0, 100), deadItem?.expiresAt ? Math.max(1, Math.ceil((deadItem.expiresAt - Date.now()) / 1000)) : null);
        return 2;
      }
      queue.unshift(recovered);
      setLocal(queueKey, 'list', queue.slice(0, 1000), queueItem?.expiresAt ? Math.max(1, Math.ceil((queueItem.expiresAt - Date.now()) / 1000)) : null);
      return 1;
    }
    case 'RPOPLPUSH': {
      const sourceKey = String(args[0] ?? '');
      const destinationKey = String(args[1] ?? '');
      const source = getLocal(sourceKey);
      if (!source || source.type !== 'list' || source.value.length === 0) return null;
      const value = source.value.pop();
      if (source.value.length === 0) localStore.delete(sourceKey);
      else setLocal(sourceKey, 'list', source.value, source.expiresAt ? Math.max(1, Math.ceil((source.expiresAt - Date.now()) / 1000)) : null);
      const destination = getLocal(destinationKey);
      const list = destination?.type === 'list' ? destination.value : [];
      list.unshift(value);
      setLocal(destinationKey, 'list', list, destination?.expiresAt ? Math.max(1, Math.ceil((destination.expiresAt - Date.now()) / 1000)) : null);
      return value;
    }
    case 'LREM': {
      if (!item || item.type !== 'list') return 0;
      const count = Number(args[1]) || 0;
      const target = String(args[2] ?? '');
      let removed = 0;
      if (count >= 0) {
        const next = [];
        for (const value of item.value) {
          if (String(value) === target && (count === 0 || removed < count)) removed++;
          else next.push(value);
        }
        item.value = next;
      } else {
        const next = [];
        for (let index = item.value.length - 1; index >= 0; index--) {
          const value = item.value[index];
          if (String(value) === target && removed < Math.abs(count)) removed++;
          else next.push(value);
        }
        item.value = next.reverse();
      }
      if (item.value.length === 0) localStore.delete(key);
      return removed;
    }
    case 'RETRYALERT': case 'DEADALERT': {
      const processingKey = String(args[0] ?? '');
      const targetRaw = String(args[1] ?? '');
      const destinationKey = String(args[2] ?? '');
      const queuedRaw = String(args[3] ?? targetRaw);
      const processing = getLocal(processingKey);
      if (!processing || processing.type !== 'list') return 0;
      const index = processing.value.findIndex((entry) => String(entry) === targetRaw);
      if (index < 0) return 0;
      processing.value.splice(index, 1);
      if (!processing.value.length) localStore.delete(processingKey);
      const destination = getLocal(destinationKey);
      if (destination && destination.type !== 'list') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
      const list = destination?.value || [];
      list.unshift(queuedRaw);
      setLocal(destinationKey, 'list', list.slice(0, name === 'RETRYALERT' ? 1000 : 100), destination?.expiresAt ? Math.max(1, (destination.expiresAt - Date.now()) / 1000) : null);
      return 1;
    }
    case 'ZADD': { const zset = item?.type === 'zset' ? item.value : new Map(); let added = 0; for (let i = 1; i + 1 < args.length; i += 2) { const score = Number(args[i]); const member = String(args[i + 1]); if (!zset.has(member)) added++; zset.set(member, score); } setLocal(key, 'zset', zset, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null); return added; }
    case 'ZREMRANGEBYSCORE': { if (!item || item.type !== 'zset') return 0; const min = Number(args[1]); const max = Number(args[2]); let removed = 0; for (const [member, score] of item.value) if (score >= min && score <= max) { item.value.delete(member); removed++; } return removed; }
    case 'ZCARD': return item?.type === 'zset' ? item.value.size : 0;
    case 'PEXPIRE': { if (!item) return 0; item.expiresAt = Date.now() + Number(args[1]); return 1; }
    case 'SADD': {
      if (item && item.type !== 'set') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
      const set = item?.value || new Set(); let added = 0;
      for (const member of args.slice(1)) { const before = set.size; set.add(String(member)); if (set.size > before) added++; }
      setLocal(key, 'set', set, item?.expiresAt ? Math.max(1, (item.expiresAt - Date.now()) / 1000) : null);
      return added;
    }
    case 'SCARD': return item?.type === 'set' ? item.value.size : 0;
    case 'SREM': { if (!item || item.type !== 'set') return 0; let removed = 0; for (const member of args.slice(1)) if (item.value.delete(String(member))) removed++; return removed; }
    case 'SMEMBERS': return item?.type === 'set' ? [...item.value] : [];
    case 'HSET': { const hash = item?.type === 'hash' ? item.value : new Map(); let added = 0; for (let i = 1; i + 1 < args.length; i += 2) { const field = String(args[i]); if (!hash.has(field)) added++; hash.set(field, String(args[i + 1])); } setLocal(key, 'hash', hash, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null); return added; }
    case 'HMGET': { const hash = item?.type === 'hash' ? item.value : new Map(); return args.slice(1).map((field) => hash.get(String(field)) ?? null); }
    default: throw new Error(`Local preview Redis fallback does not implement ${name}.`);
  }
}

const TOKEN_BUCKET_LUA = `
local values = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local capacity = tonumber(ARGV[1])
local refillPerMs = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local tokens = tonumber(values[1]) or capacity
local updated = tonumber(values[2]) or now
local elapsed = math.max(0, now - updated)
tokens = math.min(capacity, tokens + elapsed * refillPerMs)
local allowed = 0
if tokens >= cost then tokens = tokens - cost; allowed = 1 end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated', now)
redis.call('PEXPIRE', KEYS[1], math.ceil(capacity / refillPerMs) + 60000)
local retry = 0
if allowed == 0 then retry = math.ceil((cost - tokens) / refillPerMs) end
return {allowed, math.floor(tokens), retry}
`;
const SLIDING_WINDOW_LUA = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local weight = tonumber(ARGV[4])
local member = ARGV[5]
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])
local allowed = 0
if count + weight <= limit then
  for i = 1, weight do redis.call('ZADD', KEYS[1], now, member .. ':' .. i) end
  count = count + weight
  allowed = 1
end
redis.call('PEXPIRE', KEYS[1], window + 60000)
local retry = 0
if allowed == 0 then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  if oldest[2] then retry = math.max(1, tonumber(oldest[2]) + window - now) end
end
return {allowed, math.max(0, limit - count), retry}
`;
const FIXED_WINDOW_LUA = `
local limit = tonumber(ARGV[1])
local weight = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local windowId = math.floor(now / window)
local bucketKey = KEYS[1] .. ':' .. windowId
local count = redis.call('INCRBY', bucketKey, weight)
if count == weight then redis.call('PEXPIRE', bucketKey, window + 1000) end
local allowed = 0
if count <= limit then allowed = 1 end
local retry = 0
if allowed == 0 then retry = (windowId + 1) * window - now end
return {allowed, math.max(0, limit - count), retry}
`;
const LEAKY_BUCKET_LUA = `
local values = redis.call('HMGET', KEYS[1], 'water', 'updated')
local capacity = tonumber(ARGV[1])
local leakPerMs = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local water = tonumber(values[1]) or 0
local updated = tonumber(values[2]) or now
water = math.max(0, water - math.max(0, now - updated) * leakPerMs)
local allowed = 0
if water + cost <= capacity then water = water + cost; allowed = 1 end
redis.call('HSET', KEYS[1], 'water', water, 'updated', now)
redis.call('PEXPIRE', KEYS[1], math.ceil(capacity / leakPerMs) + 60000)
local retry = 0
if allowed == 0 then retry = math.ceil((water + cost - capacity) / leakPerMs) end
return {allowed, math.max(0, math.floor(capacity - water)), retry}
`;

function localLimit(key, algorithm, options) {
  const now = Date.now(); const item = getLocal(key); const limit = Math.max(1, options.limit); const weight = Math.max(1, options.weight); const windowMs = Math.max(100, options.windowMs);
  if (algorithm === 'SLIDING_WINDOW') { const events = (item?.value ?? []).filter((t) => t > now - windowMs); const allowed = events.length + weight <= limit; if (allowed) for (let i = 0; i < weight; i++) events.push(now); setLocal(key, 'list', events, Math.ceil((windowMs + 60000) / 1000)); return { allowed, remaining: Math.max(0, limit - events.length), retryAfterMs: allowed ? 0 : Math.max(1, windowMs - (now - (events[0] ?? now))) }; }
  if (algorithm === 'FIXED_WINDOW') { const windowStart = Math.floor(now / windowMs) * windowMs; const count = item?.windowStart === windowStart ? Number(item.value) : 0; const next = count + weight; const allowed = next <= limit; localStore.set(key, { type: 'fixed', value: allowed ? next : count, windowStart, expiresAt: windowStart + windowMs }); return { allowed, remaining: Math.max(0, limit - (allowed ? next : count)), retryAfterMs: allowed ? 0 : windowStart + windowMs - now }; }
  const capacity = limit; const refillPerMs = limit / windowMs; let amount = item?.type === 'bucket' ? Number(item.value.amount) : (algorithm === 'LEAKY_BUCKET' ? 0 : capacity); const updated = item?.type === 'bucket' ? Number(item.value.updated) : now; const elapsed = Math.max(0, now - updated);
  if (algorithm === 'LEAKY_BUCKET') amount = Math.max(0, amount - elapsed * refillPerMs); else amount = Math.min(capacity, amount + elapsed * refillPerMs);
  const allowed = algorithm === 'LEAKY_BUCKET' ? amount + weight <= capacity : amount >= weight; amount = allowed ? (algorithm === 'LEAKY_BUCKET' ? amount + weight : amount - weight) : amount; setLocal(key, 'bucket', { amount, updated: now }, Math.ceil(windowMs / 1000) + 60);
  const retry = algorithm === 'LEAKY_BUCKET' ? Math.max(0, amount + weight - capacity) / refillPerMs : Math.max(0, weight - amount) / refillPerMs;
  return { allowed, remaining: Math.max(0, Math.floor(capacity - amount)), retryAfterMs: allowed ? 0 : Math.ceil(retry) };
}

export async function rateLimit({ key, algorithm = 'SLIDING_WINDOW', limit = 60, windowMs = 60000, weight = 1, capacity, refillPerMs }) {
  if (typeof key !== 'string' || !key || key.length > 512) throw new TypeError('A valid Redis rate-limit key is required.');
  const normalized = String(algorithm).toUpperCase(); const max = Math.max(1, Math.floor(Number(capacity ?? limit))); const cost = Math.max(1, Math.floor(Number(weight))); const period = Math.max(100, Math.floor(Number(windowMs)));
  if (!Number.isFinite(max) || !Number.isFinite(cost) || !Number.isFinite(period)) throw new TypeError('Rate-limit values must be finite numbers.');
  if (!['TOKEN_BUCKET', 'SLIDING_WINDOW', 'FIXED_WINDOW', 'LEAKY_BUCKET'].includes(normalized)) throw new Error('Unsupported rate-limit algorithm.');
  if (cost > max) throw new RangeError('Rate-limit weight cannot exceed bucket capacity.');
  if (!redisConfigured()) { if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.'); warnFallback(); return localLimit(key, normalized, { limit: max, windowMs: period, weight: cost }); }
  let result; const now = Date.now(); const refill = Number(refillPerMs) > 0 ? Number(refillPerMs) : max / period;
  if (normalized === 'TOKEN_BUCKET') result = await command(['EVAL', TOKEN_BUCKET_LUA, '1', key, String(max), String(refill), String(now), String(cost)]);
  else if (normalized === 'SLIDING_WINDOW') result = await command(['EVAL', SLIDING_WINDOW_LUA, '1', key, String(now), String(period), String(max), String(cost), randomUUID()]);
  else if (normalized === 'FIXED_WINDOW') result = await command(['EVAL', FIXED_WINDOW_LUA, '1', key, String(max), String(cost), String(period), String(now)]);
  else result = await command(['EVAL', LEAKY_BUCKET_LUA, '1', key, String(max), String(refill), String(now), String(cost)]);
  if (!Array.isArray(result) || result.length < 3) throw new Error('Invalid Redis rate-limit response.');
  return { allowed: Number(result[0]) === 1, remaining: Math.max(0, Number(result[1]) || 0), retryAfterMs: Math.max(0, Number(result[2]) || 0) };
}

const CUSTOMER_RECORD_SCHEMA = 'arix.customer-record.v1';
const CUSTOMER_RECORD_KEK_VERSION = process.env.ARIX_CUSTOMER_RECORD_KEK_VERSION || 'master-v1';
const CUSTOMER_RECORD_COMPARE_SET_LUA = `
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then return 0 end
local ttl = redis.call('PTTL', KEYS[1])
redis.call('SET', KEYS[1], ARGV[2])
if ttl > 0 then redis.call('PEXPIRE', KEYS[1], ttl) end
return 1
`;

function customerRecordType(key) {
  if (typeof key !== 'string' || key.length > 512) return null;
  if (key.startsWith('arix:user:')) return { type: 'user', recordId: key.slice('arix:user:'.length) };
  if (key.startsWith('arix:project:')) return { type: 'project', recordId: key.slice('arix:project:'.length) };
  return null;
}

function customerRecordMasterSecret() {
  const configured = process.env.ARIX_MASTER_SECRET;
  if (configured && Buffer.byteLength(configured) >= 32) return Buffer.from(configured, 'utf8');
  if (process.env.NODE_ENV === 'production') throw new Error('ARIX_MASTER_SECRET must contain at least 32 bytes for customer-record encryption.');
  globalThis.__ARIX_CUSTOMER_RECORD_MASTER__ ??= randomBytes(48);
  return Buffer.from(globalThis.__ARIX_CUSTOMER_RECORD_MASTER__);
}

function customerKek(tenantId, version = CUSTOMER_RECORD_KEK_VERSION) {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(String(version))) throw new TypeError('Invalid customer record KEK version.');
  const configured = process.env.ARIX_CUSTOMER_RECORD_KEKS_JSON;
  if (configured) {
    let map;
    try { map = JSON.parse(configured); } catch { throw new Error('ARIX_CUSTOMER_RECORD_KEKS_JSON is invalid.'); }
    const encoded = map?.[version];
    if (typeof encoded !== 'string') throw new Error(`Customer record KEK ${version} is not configured.`);
    if (!/^[A-Za-z0-9+/]{43}=$/.test(encoded)) throw new Error(`Customer record KEK ${version} must be canonical base64 for exactly 32 bytes.`);
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.length !== 32 || bytes.toString('base64') !== encoded) throw new Error(`Customer record KEK ${version} must decode to exactly 32 bytes.`);
    return bytes;
  }
  const master = customerRecordMasterSecret();
  try { return derivePurposeKey(master, `customer-record:${version}`, String(tenantId)); }
  finally { master.fill(0); }
}

function encryptCustomerRecord(key, value) {
  const identity = customerRecordType(key);
  if (!identity || !value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Customer record must be a user/project object.');
  const tenantId = identity.type === 'user' ? String(value.id || '') : String(value.ownerId || '');
  if (!tenantId || tenantId.length > 180 || identity.recordId !== (identity.type === 'user' ? String(value.id || '') : String(value.id || ''))) throw new Error('CUSTOMER_RECORD_SCOPE_INVALID');
  const version = CUSTOMER_RECORD_KEK_VERSION;
  const kek = customerKek(tenantId, version);
  const dek = createTenantDek();
  try {
    const keks = { [version]: kek };
    const wrappedDek = wrapTenantDek(dek, { tenantId, kekVersion: version, keks });
    const purpose = `customer-record:${identity.type}:${identity.recordId}`;
    const encrypted = encryptTenantData(JSON.stringify(value), { tenantId, dek, purpose });
    return { schema: CUSTOMER_RECORD_SCHEMA, recordType: identity.type, recordId: identity.recordId, tenantId, wrappedDek, encrypted };
  } finally { kek.fill(0); dek.fill(0); }
}

function decryptCustomerRecord(key, envelope) {
  const identity = customerRecordType(key);
  if (!identity || envelope?.schema !== CUSTOMER_RECORD_SCHEMA || envelope.recordType !== identity.type || envelope.recordId !== identity.recordId || typeof envelope.tenantId !== 'string' || !envelope.tenantId) throw new Error('CUSTOMER_RECORD_ENVELOPE_INVALID');
  const version = String(envelope.wrappedDek?.kekVersion || '');
  const kek = customerKek(envelope.tenantId, version);
  let dek;
  let plaintext;
  try {
    dek = unwrapTenantDek(envelope.wrappedDek, { tenantId: envelope.tenantId, keks: { [version]: kek } });
    plaintext = decryptTenantData(envelope.encrypted, { tenantId: envelope.tenantId, dek, purpose: `customer-record:${identity.type}:${identity.recordId}` });
    const value = JSON.parse(plaintext.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('CUSTOMER_RECORD_PLAINTEXT_INVALID');
    return value;
  } finally { kek.fill(0); dek?.fill(0); plaintext?.fill(0); }
}

async function compareAndSetLegacyCustomerRecord(key, previous, next) {
  if (!redisConfigured()) {
    if (process.env.UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_TOKEN) throw new Error('Invalid Redis configuration during customer record migration.');
    const current = getLocal(key);
    if (!current || current.type !== 'string' || current.value !== previous) return false;
    setLocal(key, 'string', next, current.expiresAt ? Math.max(1, Math.ceil((current.expiresAt - Date.now()) / 1000)) : null);
    return true;
  }
  return Number(await command(['EVAL', CUSTOMER_RECORD_COMPARE_SET_LUA, '1', key, previous, next])) === 1;
}

export async function getJson(key) {
  const raw = await command(['GET', key]);
  if (raw == null) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!customerRecordType(key)) return value;
  if (value?.schema === CUSTOMER_RECORD_SCHEMA) return decryptCustomerRecord(key, value);
  // Existing v1.4.1 plaintext account/project documents are transparently and
  // atomically upgraded on first read; concurrent writers cannot be overwritten.
  const encrypted = encryptCustomerRecord(key, value);
  const migrated = await compareAndSetLegacyCustomerRecord(key, raw, JSON.stringify(encrypted));
  if (migrated) return value;
  // A concurrent writer may have replaced the plaintext between GET and CAS.
  // Return the latest committed value rather than stale data read before the race.
  const latest = await command(['GET', key]);
  if (latest == null) return null;
  let latestValue;
  try { latestValue = JSON.parse(latest); } catch { throw new Error('CUSTOMER_RECORD_JSON_INVALID'); }
  if (latestValue?.schema === CUSTOMER_RECORD_SCHEMA) return decryptCustomerRecord(key, latestValue);
  if (process.env.NODE_ENV === 'production' || process.env.ARIX_CUSTOMER_RECORD_ENCRYPTION_REQUIRED === 'true') throw new Error('CUSTOMER_RECORD_ENCRYPTION_REQUIRED');
  return latestValue;
}
/** Atomically fetches and deletes a JSON value (one-time challenges/nonces). */
export async function getJsonOnce(key) { const value = await command(['GETDEL', key]); if (value == null) return null; try { return JSON.parse(value); } catch { return null; } }
export async function setJson(key, value, ttlSeconds = null, nx = false) {
  const stored = customerRecordType(key) ? encryptCustomerRecord(key, value) : value;
  const args = ['SET', key, JSON.stringify(stored)];
  if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) args.push('EX', String(Math.floor(ttlSeconds)));
  if (nx) args.push('NX');
  return command(args);
}
export async function setString(key, value, ttlSeconds = null, nx = false) { const args = ['SET', key, String(value)]; if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) args.push('EX', String(Math.floor(ttlSeconds))); if (nx) args.push('NX'); return command(args); }
export async function getString(key) { return command(['GET', key]); }

const STRING_COMPARE_AND_SET_LUA = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[1], ARGV[2])
return 1
`;
const STRING_COMPARE_AND_DELETE_LUA = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
`;

/** Atomically replace a string only while it still contains the expected value. */
export async function compareAndSetString(key, expected, replacement) {
  const values = [String(key), String(expected), String(replacement)];
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback();
    const current = getLocal(values[0]);
    if (!current || current.type !== 'string' || current.value !== values[1]) return false;
    // No await occurs between read and write: this is atomic within this local
    // preview isolate. Production uses the Redis Lua script below.
    setLocal(values[0], 'string', values[2], null);
    return true;
  }
  return Number(await command(['EVAL', STRING_COMPARE_AND_SET_LUA, '1', ...values])) === 1;
}

/** Atomically delete a reservation only if it is still owned by this caller. */
export async function compareAndDeleteString(key, expected) {
  const values = [String(key), String(expected)];
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback();
    const current = getLocal(values[0]);
    if (!current || current.type !== 'string' || current.value !== values[1]) return false;
    localStore.delete(values[0]);
    return true;
  }
  return Number(await command(['EVAL', STRING_COMPARE_AND_DELETE_LUA, '1', ...values])) === 1;
}

const WEBAUTHN_COUNTER_ADVANCE_LUA = `
local prior = tonumber(ARGV[1])
local next = tonumber(ARGV[2])
if not prior or not next or prior < 0 or next < 0 or prior > 4294967295 or next > 4294967295 then return -1 end
local raw = redis.call('GET', KEYS[1])
local current = tonumber(raw)
if raw and (not current or current < 0 or current > 4294967295) then return -1 end
if not current or prior > current then current = prior end
-- A previously incrementing authenticator may never silently reset to zero.
if current > 0 and (next == 0 or next <= current) then return 0 end
-- Authenticators that always report zero do not expose a usable counter.
if next > 0 then redis.call('SET', KEYS[1], tostring(next)) end
return 1
`;

/**
 * Atomically accept a WebAuthn signature counter transition for one credential.
 * `credentialHash` must be the SHA-256 hex digest of the credential ID. A
 * positive counter must strictly increase; once positive, it may not return to
 * zero. A zero-to-zero transition remains supported for authenticators that do
 * not implement counters. The durable Redis key is removed with the credential.
 */
export async function advanceWebAuthnCounter(credentialHash, priorCount, nextCount) {
  if (typeof credentialHash !== 'string' || !/^[a-f0-9]{64}$/i.test(credentialHash)) throw new TypeError('Invalid WebAuthn credential counter key.');
  const prior = Number(priorCount); const next = Number(nextCount);
  if (!Number.isInteger(prior) || !Number.isInteger(next) || prior < 0 || next < 0 || prior > 0xffffffff || next > 0xffffffff) return false;
  const key = `arix:webauthn:counter:${credentialHash}`;
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in production.');
    warnFallback();
    // Synchronous read/decision/write: atomic within this local Node isolate.
    const item = getLocal(key);
    if (item && item.type !== 'string') throw new Error('WebAuthn counter store has an invalid value type.');
    const stored = item ? Number(item.value) : null;
    if (item && (!Number.isInteger(stored) || stored < 0 || stored > 0xffffffff)) throw new Error('WebAuthn counter store is corrupt.');
    const current = Math.max(prior, stored ?? 0);
    if (current > 0 && (next === 0 || next <= current)) return false;
    if (next > 0) setLocal(key, 'string', String(next), null);
    return true;
  }
  return Number(await command(['EVAL', WEBAUTHN_COUNTER_ADVANCE_LUA, '1', key, String(prior), String(next)])) === 1;
}

export async function deleteKeys(...keys) { return keys.length ? command(['DEL', ...keys]) : 0; }
export async function increment(key, amount = 1) { return command(['INCRBY', key, String(amount)]); }
const INCREMENT_TTL_LUA = `
local value = redis.call('INCRBY', KEYS[1], tonumber(ARGV[1]))
if value == tonumber(ARGV[1]) then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2])) end
return value
`;
export async function incrementWithExpiry(key, ttlSeconds, amount = 1) {
  const ttl = Math.max(1, Math.min(31536000, Math.floor(Number(ttlSeconds) || 1)));
  const step = Math.max(1, Math.floor(Number(amount) || 1));
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
    warnFallback(); const value = await localCommand(['INCRBY', key, String(step)]);
    const item = getLocal(key); if (item && value === step) item.expiresAt = Date.now() + ttl * 1000;
    return Number(value);
  }
  return Number(await command(['EVAL', INCREMENT_TTL_LUA, '1', key, String(step), String(ttl)]));
}
const SET_MAX_WITH_TTL_LUA = `
local current = tonumber(redis.call('GET', KEYS[1])) or 0
local requested = tonumber(ARGV[1]) or 0
local ttl = math.max(1, tonumber(ARGV[2]) or 1)
if requested > current then
  redis.call('SET', KEYS[1], tostring(requested), 'EX', ttl)
  return requested
end
return current
`;
export async function setMaxStringWithExpiry(key, value, ttlSeconds) {
  const requested = Math.max(0, Math.floor(Number(value) || 0));
  const ttl = Math.max(1, Math.min(31536000, Math.floor(Number(ttlSeconds) || 1)));
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
    warnFallback(); const current = Number(await localCommand(['GET', key]) || 0);
    if (requested > current) await setString(key, String(requested), ttl);
    return Math.max(current, requested);
  }
  return Number(await command(['EVAL', SET_MAX_WITH_TTL_LUA, '1', key, String(requested), String(ttl)]));
}
// A Redis Set has one key-level TTL, not a per-member TTL. Only extend the
// index lifetime; never shorten it when a shorter-lived member is added.
const ADD_SET_MEMBER_LUA = `
local added = redis.call('SADD', KEYS[1], ARGV[1])
local ttl = tonumber(ARGV[2]) or 0
if ttl > 0 then
  local requested = ttl * 1000
  local current = redis.call('PTTL', KEYS[1])
  -- Extend an expiring index but never shorten it. A persistent existing set
  -- stays persistent; only a newly-created set receives its initial TTL.
  if current >= 0 and requested > current then
    redis.call('PEXPIRE', KEYS[1], requested)
  elseif current == -1 and added == 1 and redis.call('SCARD', KEYS[1]) == 1 then
    redis.call('PEXPIRE', KEYS[1], requested)
  end
end
return added
`;
const PUSH_TRIM_LUA = `
redis.call('LPUSH', KEYS[1], ARGV[1])
redis.call('LTRIM', KEYS[1], 0, tonumber(ARGV[2]) - 1)
return redis.call('LLEN', KEYS[1])
`;
export async function listPushTrim(key, event, keep = 500) {
  const serialized = JSON.stringify(event); const boundedKeep = Math.max(1, Math.min(100000, Math.floor(Number(keep) || 500)));
  if (!redisConfigured()) { if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.'); warnFallback(); await localCommand(['LPUSH', key, serialized]); await localCommand(['LTRIM', key, '0', String(boundedKeep - 1)]); return localCommand(['LLEN', key]); }
  return command(['EVAL', PUSH_TRIM_LUA, '1', key, serialized, String(boundedKeep)]);
}
export async function listRange(key, start = 0, end = 99) { return command(['LRANGE', key, String(start), String(end)]); }
export async function expire(key, seconds) { return command(['EXPIRE', key, String(seconds)]); }
export async function setAdd(key, member, ttlSeconds = null) {
  const ttl = Math.max(0, Math.min(31536000, Math.floor(Number(ttlSeconds) || 0)));
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
    warnFallback();
    const before = getLocal(key);
    if (before && before.type !== 'set') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
    const existed = Boolean(before?.type === 'set' && before.value.size > 0);
    const remainingMs = before?.expiresAt ? Math.max(0, before.expiresAt - Date.now()) : Infinity;
    const result = await localCommand(['SADD', key, String(member)]);
    if (ttl > 0 && ((!existed && result === 1) || (Number.isFinite(remainingMs) && ttl * 1000 > remainingMs))) {
      await localCommand(['EXPIRE', key, String(ttl)]);
    }
    return result;
  }
  return command(['EVAL', ADD_SET_MEMBER_LUA, '1', key, String(member), String(ttl)]);
}
export async function setMembers(key) { return command(['SMEMBERS', key]); }
export async function setCard(key) { return command(['SCARD', key]); }
export async function getStrings(...keys) { if (!keys.length) return []; const result = await command(['MGET', ...keys.map(String)]); return Array.isArray(result) ? result : []; }
export async function setRemoveMany(key, members = []) { const bounded = members.slice(0, 2000).map(String); return bounded.length ? command(['SREM', key, ...bounded]) : 0; }
export async function hashSet(key, values) { const args = ['HSET', key]; for (const [field, value] of Object.entries(values)) args.push(field, String(value)); return command(args); }
export async function hashGetMany(key, ...fields) { return command(['HMGET', key, ...fields]); }
export async function isUsingUpstash() { return redisConfigured(); }
export async function pingRedis() { return command(['PING']); }
export function getRedisConfigurationStatus() { const hasUrl = Boolean(process.env.UPSTASH_REDIS_REST_URL); const hasToken = Boolean(process.env.UPSTASH_REDIS_REST_TOKEN); const validUrl = Boolean(normalizeRedisRestUrl(process.env.UPSTASH_REDIS_REST_URL)); const configured = validUrl && hasToken && Boolean(redisEndpoint()); return { configured, hasUrl, hasToken, validUrl, mode: configured ? 'upstash' : (hasUrl || hasToken ? 'invalid-configuration' : (localModeAllowed() ? 'ephemeral-local' : 'unconfigured')) }; }

const AUDIT_GENESIS = '0'.repeat(64);
const AUDIT_CHAIN_CAS_LUA = `
local seqRaw = redis.call('GET', KEYS[1])
local headRaw = redis.call('GET', KEYS[2])
if (not seqRaw and not headRaw) then
  seqRaw = '0'
  headRaw = string.rep('0', 64)
elseif (not seqRaw or not headRaw) then
  return {-1, tonumber(seqRaw or '-1'), headRaw or ''}
end
local currentSeq = tonumber(seqRaw)
local currentHead = headRaw
if (not currentSeq) or currentSeq < 0 or currentSeq ~= math.floor(currentSeq) then return {-1, -1, currentHead} end
if (currentSeq == 0 and currentHead ~= string.rep('0', 64)) or (currentSeq > 0 and string.len(currentHead) ~= 64) then
  return {-1, currentSeq, currentHead}
end
if currentSeq ~= tonumber(ARGV[1]) or currentHead ~= ARGV[2] then return {0, currentSeq, currentHead} end
local nextSeq = currentSeq + 1
redis.call('SET', KEYS[1], tostring(nextSeq))
redis.call('SET', KEYS[2], ARGV[3])
redis.call('LPUSH', KEYS[3], ARGV[4])
redis.call('LTRIM', KEYS[3], 0, 9999)
redis.call('SADD', KEYS[4], ARGV[5])
return {1, nextSeq, ARGV[3]}
`;

function auditSecret() {
  if (typeof process.env.ARIX_MASTER_SECRET === 'string' && Buffer.byteLength(process.env.ARIX_MASTER_SECRET) >= 32) return process.env.ARIX_MASTER_SECRET;
  if (process.env.NODE_ENV === 'production') throw new Error('ARIX_MASTER_SECRET must contain at least 32 bytes for the audit hash-chain.');
  return globalThis.__ARIX_AUDIT_LOCAL_SECRET__ ??= `${randomUUID()}${randomUUID()}`;
}

function calculateAuditMac(secret, previousMac, sequence, digest) {
  return createHmac('sha256', secret)
    .update(Buffer.from(previousMac, 'hex'))
    .update(String(sequence), 'utf8')
    .update(Buffer.from(digest, 'hex'))
    .digest('hex');
}

async function withLocalAuditLock(projectId, operation) {
  const previous = localAuditQueues.get(projectId) || Promise.resolve();
  let release;
  const current = new Promise((resolve) => { release = resolve; });
  const tail = previous.then(() => current);
  localAuditQueues.set(projectId, tail);
  await previous;
  try { return await operation(); }
  finally { release(); if (localAuditQueues.get(projectId) === tail) localAuditQueues.delete(projectId); }
}

/** Append one real-time tamper-evident audit entry. Redis CAS serializes concurrent writers. */
export async function recordAuditChainEvent(projectId, event) {
  const id = String(projectId || '').slice(0, 100);
  if (!id) throw new TypeError('Audit project ID is required.');
  const canonical = JSON.stringify({ projectId: id, event });
  const digest = createHash('sha256').update(canonical).digest('hex');
  const secret = auditSecret();
  const keys = [`arix:audit:seq:${id}`, `arix:audit:head:${id}`, `arix:audit:chain:${id}`];
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis for audit-chain writes in production.');
    return withLocalAuditLock(id, async () => {
      const state = localAuditChains.get(id) || { seq: 0, head: AUDIT_GENESIS, rows: [] };
      const seq = state.seq + 1;
      const chainMac = calculateAuditMac(secret, state.head, seq, digest);
      const row = { version: 1, projectId: id, seq, digest, prevChainMac: state.head, chainMac, timestamp: new Date().toISOString(), type: String(event?.type || 'SECURITY_EVENT').slice(0, 64), event };
      state.seq = seq; state.head = chainMac; state.rows.unshift(row); state.rows.length = Math.min(state.rows.length, 10000);
      localAuditChains.set(id, state);
      return row;
    });
  }
  for (let attempt = 0; attempt < 12; attempt++) {
    const [rawSeq, rawHead] = await pipeline([['GET', keys[0]], ['GET', keys[1]]]);
    const expectedSeq = Math.max(0, Number(rawSeq) || 0);
    const previousMac = typeof rawHead === 'string' && /^[a-f0-9]{64}$/.test(rawHead) ? rawHead : AUDIT_GENESIS;
    const seq = expectedSeq + 1;
    const chainMac = calculateAuditMac(secret, previousMac, seq, digest);
    const row = { version: 1, projectId: id, seq, digest, prevChainMac: previousMac, chainMac, timestamp: new Date().toISOString(), type: String(event?.type || 'SECURITY_EVENT').slice(0, 64), event };
    const result = await command(['EVAL', AUDIT_CHAIN_CAS_LUA, '4', keys[0], keys[1], keys[2], 'arix:audit:projects', String(expectedSeq), previousMac, chainMac, JSON.stringify(row), id]);
    if (Array.isArray(result) && Number(result[0]) === 1) return row;
    if (Array.isArray(result) && Number(result[0]) === -1) throw new Error('Audit hash-chain sequence/head state is inconsistent; refusing to append.');
  }
  throw new Error('Audit hash-chain CAS contention exceeded the bounded retry budget.');
}

/** Return a verified, bounded witness window. HMACs are checked server-side before it is exposed. */
export async function getAuditChainSnapshot(projectId, limit = 250) {
  const id = String(projectId || '').slice(0, 100);
  const bounded = Math.max(1, Math.min(1000, Math.floor(Number(limit) || 250)));
  let seqRaw; let headRaw; let rawRows; let chainLength;
  if (!redisConfigured()) {
    const state = localAuditChains.get(id) || { seq: 0, head: AUDIT_GENESIS, rows: [] };
    seqRaw = String(state.seq); headRaw = state.head; rawRows = state.rows.slice(0, bounded).map((row) => JSON.stringify(row)); chainLength = state.rows.length;
  } else {
    [seqRaw, headRaw, rawRows, chainLength] = await pipeline([
      ['GET', `arix:audit:seq:${id}`], ['GET', `arix:audit:head:${id}`],
      ['LRANGE', `arix:audit:chain:${id}`, '0', String(bounded - 1)], ['LLEN', `arix:audit:chain:${id}`]
    ]);
  }
  const rows = (Array.isArray(rawRows) ? rawRows : []).flatMap((raw) => { try { const row = typeof raw === 'string' ? JSON.parse(raw) : raw; return row && typeof row === 'object' ? [row] : []; } catch { return []; } }).reverse();
  let verified = true; let previous = null;
  const secret = auditSecret();
  for (const row of rows) {
    if (!Number.isSafeInteger(Number(row.seq)) || !/^[a-f0-9]{64}$/.test(String(row.digest)) || !/^[a-f0-9]{64}$/.test(String(row.prevChainMac)) || !/^[a-f0-9]{64}$/.test(String(row.chainMac))) { verified = false; break; }
    const expectedDigest = row.event === undefined ? null : createHash('sha256').update(JSON.stringify({ projectId: id, event: row.event })).digest('hex');
    const expected = calculateAuditMac(secret, row.prevChainMac, Number(row.seq), row.digest);
    if (row.projectId !== id || row.version !== 1 || !expectedDigest || expectedDigest !== row.digest || expected !== row.chainMac || (previous && (Number(row.seq) !== Number(previous.seq) + 1 || row.prevChainMac !== previous.chainMac))) { verified = false; break; }
    previous = row;
  }
  const sequence = Math.max(0, Number(seqRaw) || 0);
  const head = typeof headRaw === 'string' && /^[a-f0-9]{64}$/.test(headRaw) ? headRaw : AUDIT_GENESIS;
  const retainedCount = Math.min(sequence, 10000);
  const actualChainLength = Math.max(0, Number(chainLength) || 0);
  if (actualChainLength !== retainedCount) verified = false;
  if (sequence === 0) verified = verified && rows.length === 0 && head === AUDIT_GENESIS && actualChainLength === 0;
  else {
    const expectedFirstSequence = Math.max(1, sequence - rows.length + 1);
    verified = verified && rows.length > 0 && Number(rows[0].seq) === expectedFirstSequence
      && Number(rows.at(-1).seq) === sequence && rows.at(-1).chainMac === head;
    if (Number(rows[0]?.seq) === 1 && rows[0]?.prevChainMac !== AUDIT_GENESIS) verified = false;
  }
  return { sequence, head, verified, rows, checkedAt: new Date().toISOString(), windowTruncated: sequence > rows.length, retainedCount: actualChainLength };
}

export async function processCriticalThreatEvent(projectId, safeEvent, {
  appendAudit = recordAuditChainEvent,
  readProject = getJson,
  saveProject = setJson,
  dispatchAlert = null,
  queueAlert = enqueueIncidentAlert
} = {}) {
  let auditRow = null;
  try {
    auditRow = await appendAudit(projectId, safeEvent);
  } catch (error) {
    // A bounded audit-chain CAS failure must be visible, but must never
    // prevent an independent critical containment action or alert enqueue.
    console.error('[ArixShield] Threat audit-chain append failed:', String(error?.message || error).slice(0, 180));
  }

  const criticalTypes = new Set(['BOLA_200_LEAK_BLOCKED', 'CANARY_KEY_USED', 'GITHUB_SECRET_EXPOSURE', 'AUDIT_CHAIN_BROKEN', 'REDIS_CIRCUIT_OPEN', 'HONEYPOT_ROUTE_HIT', 'CANARY_RECORD_ACCESSED', 'CROSS_ENDPOINT_CORRELATION_ALERT']);
  if (!criticalTypes.has(String(safeEvent?.type || ''))) return { auditRow, containmentApplied: false, alertQueued: false };

  let project = null;
  try { project = await readProject(`arix:project:${projectId}`); }
  catch (error) { console.error('[ArixShield] Critical project policy could not be loaded:', String(error?.message || error).slice(0, 180)); }

  let containmentApplied = false;
  if (project?.policy?.autoContainmentEnabled === true && project.policy.mode === 'DRY_RUN') {
    try {
      const enforced = { ...project, policy: { ...project.policy, mode: 'ENFORCE' }, updatedAt: new Date().toISOString() };
      await saveProject(`arix:project:${projectId}`, enforced);
      project = enforced;
      containmentApplied = true;
    } catch (error) {
      console.error('[ArixShield] Automatic enforcement transition failed:', String(error?.message || error).slice(0, 180));
    }
  }

  if (typeof project?.policy?.alertWebhookUrl !== 'string' || !project.policy.alertWebhookUrl) {
    return { auditRow, containmentApplied, alertQueued: false };
  }
  const incident = {
    projectId: String(projectId), event: safeEvent, audit: auditRow,
    auditUnavailable: auditRow === null,
    containment: containmentApplied || project?.policy?.mode === 'ENFORCE'
  };
  try {
    if (dispatchAlert) await dispatchAlert(project.policy.alertWebhookUrl, incident);
    else {
      const { dispatchIncidentAlert } = await import('./alerts.js');
      await dispatchIncidentAlert(project.policy.alertWebhookUrl, incident);
    }
    return { auditRow, containmentApplied, alertQueued: false };
  } catch (alertError) {
    try {
      await queueAlert(projectId, { ...incident, deliveryError: String(alertError?.message || alertError).slice(0, 160) });
      return { auditRow, containmentApplied, alertQueued: true };
    } catch (queueError) {
      console.error('[ArixShield] Critical incident could not be queued:', String(queueError?.message || queueError).slice(0, 160));
      return { auditRow, containmentApplied, alertQueued: false };
    }
  }
}

export async function recordProjectEvent(projectId, event, { threat = false, countRequest = true } = {}) {
  const keep = Math.max(100, Math.min(1000, Number(process.env.ARIX_EVENT_RETENTION) || 500));
  const kind = threat ? 'threat_logs' : 'live_visitors';
  const safeEvent = event && typeof event === 'object' ? event : { type: 'UNKNOWN_EVENT' };
  const metrics = `arix:metrics:${projectId}`;
  const commands = [
    ['LPUSH', `arix:${kind}:${projectId}`, JSON.stringify(safeEvent)],
    ['LTRIM', `arix:${kind}:${projectId}`, '0', String(keep - 1)]
  ];
  if (countRequest) commands.push(['INCRBY', `${metrics}:total_requests`, '1']);
  if (threat && safeEvent.blocked !== false) commands.push(['INCRBY', `${metrics}:blocked_attacks`, '1']);
  if (safeEvent.type === 'TRAPPED_HACKER') commands.push(['INCRBY', `${metrics}:trapped_hackers`, '1']);
  if (threat) {
    const digest = createHash('sha256').update(JSON.stringify({ projectId, event: safeEvent })).digest('hex');
    const auditRow = JSON.stringify({ hash: digest, timestamp: Date.now(), type: String(safeEvent.type || 'SECURITY_EVENT').slice(0, 64) });
    commands.push(['LPUSH', `arix:audit:pending:${projectId}`, auditRow], ['LTRIM', `arix:audit:pending:${projectId}`, '0', '9999'], ['SADD', 'arix:audit:projects', String(projectId)]);
  }
  const analytics = await import('./analytics.js');
  if (analytics.analyticsConfigured()) {
    const queueLimit = Math.max(5000, Math.min(100000, Number(process.env.ARIX_ANALYTICS_QUEUE_RETENTION) || 50000));
    commands.push(['SADD', 'arix:analytics:projects', String(projectId)], ['LPUSH', `arix:analytics:queue:${projectId}`, JSON.stringify(safeEvent)], ['LTRIM', `arix:analytics:queue:${projectId}`, '0', String(queueLimit - 1)]);
  }
  // One durable Redis pipeline replaces multiple sequential REST round-trips.
  await pipeline(commands);
  if (threat) await processCriticalThreatEvent(projectId, safeEvent);
}

export async function recordApiTelemetryEvent(projectId, event) {
  const metrics = `arix:metrics:${projectId}`;
  const commands = [['INCRBY', `${metrics}:total_requests`, '1']];
  const analytics = await import('./analytics.js');
  if (analytics.analyticsConfigured()) {
    const queueLimit = Math.max(5000, Math.min(100000, Number(process.env.ARIX_ANALYTICS_QUEUE_RETENTION) || 50000));
    commands.push(['SADD', 'arix:analytics:projects', String(projectId)], ['LPUSH', `arix:analytics:queue:${projectId}`, JSON.stringify(event)], ['LTRIM', `arix:analytics:queue:${projectId}`, '0', String(queueLimit - 1)]);
  }
  await pipeline(commands);
}

export async function getProjectDashboardSnapshot(projectId) {
  const metrics = `arix:metrics:${projectId}`;
  const [visitors, threats, forensic, values, catalog, auditLatest] = await pipeline([
    ['LRANGE', `arix:live_visitors:${projectId}`, '0', '199'], ['LRANGE', `arix:threat_logs:${projectId}`, '0', '199'],
    ['LRANGE', `arix:forensic:${projectId}`, '0', '99'], ['MGET', `${metrics}:total_requests`, `${metrics}:blocked_attacks`, `${metrics}:trapped_hackers`, `${metrics}:tarpit_seconds_burned`],
    ['SMEMBERS', `arix:api-catalog:${projectId}`], ['GET', `arix:audit:latest:${projectId}`]
  ]);
  const auditChain = await getAuditChainSnapshot(projectId, 250);
  const [total, blocked, trapped, tarpit] = Array.isArray(values) ? values : [];
  return {
    visitors: Array.isArray(visitors) ? visitors : [], threats: Array.isArray(threats) ? threats : [], forensicReplay: Array.isArray(forensic) ? forensic : [],
    apiCatalog: Array.isArray(catalog) ? catalog.slice(0, 1000) : [],
    auditAnchor: (() => { try { return auditLatest ? JSON.parse(auditLatest) : null; } catch { return null; } })(), auditChain,
    metrics: { totalRequests: Number(total || 0), blockedAttacks: Number(blocked || 0), trappedHackers: Number(trapped || 0), tarpitSecondsBurned: Number(tarpit || 0), activeVisitors: null }
  };
}

export async function enqueueIncidentAlert(projectId, incident) {
  const id = String(projectId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) throw new TypeError('A valid project ID is required for the alert outbox.');
  const payload = JSON.stringify({ id: randomUUID(), createdAt: new Date().toISOString(), attempts: 0, incident });
  const key = `arix:outbox:alerts:${id}`;
  await pipeline([['LPUSH', key, payload], ['LTRIM', key, '0', '999'], ['SADD', 'arix:outbox:projects', id]]);
  return true;
}

export async function acquireIncidentAlertLease(projectId, ttlSeconds = 300) {
  const id = String(projectId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) throw new TypeError('A valid project ID is required for the alert outbox lease.');
  const ttl = Math.max(30, Math.min(600, Math.floor(Number(ttlSeconds) || 300)));
  const token = randomUUID();
  const result = await command(['SET', `arix:outbox:alerts:lock:${id}`, token, 'NX', 'EX', String(ttl)]);
  return result === 'OK' ? token : null;
}

export async function releaseIncidentAlertLease(projectId, token) {
  const id = String(projectId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id) || typeof token !== 'string' || !/^[0-9a-f-]{36}$/.test(token)) return false;
  const script = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";
  return Number(await command(['EVAL', script, '1', `arix:outbox:alerts:lock:${id}`, token])) === 1;
}

const RECOVER_INCIDENT_ALERT_LUA = `
local raw = redis.call('RPOP', KEYS[1])
if not raw then return 0 end
local ok, payload = pcall(cjson.decode, raw)
if not ok or type(payload) ~= 'table' then
  redis.call('LPUSH', KEYS[3], raw)
  redis.call('LTRIM', KEYS[3], 0, 99)
  return 2
end
local attempts = tonumber(payload.attempts) or 0
payload.attempts = attempts + 1
payload.recoveredAt = ARGV[2]
local updated = cjson.encode(payload)
if payload.attempts >= tonumber(ARGV[1]) then
  redis.call('LPUSH', KEYS[3], updated)
  redis.call('LTRIM', KEYS[3], 0, 99)
  return 2
end
redis.call('LPUSH', KEYS[2], updated)
redis.call('LTRIM', KEYS[2], 0, 999)
return 1
`;

export async function recoverIncidentAlertClaims(projectId, maximum = 100, maxAttempts = 8) {
  const id = String(projectId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) throw new TypeError('A valid project ID is required for alert recovery.');
  const limit = Math.max(1, Math.min(1000, Math.floor(Number(maximum) || 100)));
  const attemptsLimit = Math.max(1, Math.min(20, Math.floor(Number(maxAttempts) || 8)));
  const queueKey = `arix:outbox:alerts:${id}`;
  const processingKey = `${queueKey}:processing`;
  const deadKey = `arix:outbox:alerts:dead:${id}`;
  let recovered = 0;
  for (let index = 0; index < limit; index++) {
    let status;
    if (!redisConfigured()) {
      if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
      warnFallback();
      status = await localCommand(['RECOVERALERT', processingKey, queueKey, deadKey, String(attemptsLimit)]);
    } else {
      status = await command(['EVAL', RECOVER_INCIDENT_ALERT_LUA, '3', processingKey, queueKey, deadKey, String(attemptsLimit), new Date().toISOString()]);
    }
    if (Number(status) === 0) break;
    recovered++;
  }
  return recovered;
}

export async function claimIncidentAlert(projectId) {
  const id = String(projectId || '').trim();
  return command(['RPOPLPUSH', `arix:outbox:alerts:${id}`, `arix:outbox:alerts:${id}:processing`]);
}
export async function ackIncidentAlert(projectId, raw) {
  const id = String(projectId || '').trim();
  return command(['LREM', `arix:outbox:alerts:${id}:processing`, '1', String(raw)]);
}
const RETRY_INCIDENT_ALERT_LUA = `
local removed = redis.call('LREM', KEYS[1], 1, ARGV[1])
if removed == 1 then
  redis.call('LPUSH', KEYS[2], ARGV[2])
  redis.call('LTRIM', KEYS[2], 0, 999)
end
return removed
`;
const DEADLETTER_INCIDENT_ALERT_LUA = `
local removed = redis.call('LREM', KEYS[1], 1, ARGV[1])
if removed == 1 then
  redis.call('LPUSH', KEYS[2], ARGV[1])
  redis.call('LTRIM', KEYS[2], 0, 99)
end
return removed
`;
export async function retryIncidentAlert(projectId, raw, nextRaw) {
  const id = String(projectId || '').trim();
  if (!redisConfigured()) return Number(await localCommand(['RETRYALERT', `arix:outbox:alerts:${id}:processing`, String(raw), `arix:outbox:alerts:${id}`, String(nextRaw)])) === 1;
  return Number(await command(['EVAL', RETRY_INCIDENT_ALERT_LUA, '2', `arix:outbox:alerts:${id}:processing`, `arix:outbox:alerts:${id}`, String(raw), String(nextRaw)])) === 1;
}
export async function deadLetterIncidentAlert(projectId, raw) {
  const id = String(projectId || '').trim();
  if (!redisConfigured()) return Number(await localCommand(['DEADALERT', `arix:outbox:alerts:${id}:processing`, String(raw), `arix:outbox:alerts:dead:${id}`, String(raw)])) === 1;
  return Number(await command(['EVAL', DEADLETTER_INCIDENT_ALERT_LUA, '2', `arix:outbox:alerts:${id}:processing`, `arix:outbox:alerts:dead:${id}`, String(raw)])) === 1;
}


const TRACK_WINDOW_LUA = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local member = ARGV[3]
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('ZADD', KEYS[1], now, member)
local count = redis.call('ZCARD', KEYS[1])
redis.call('PEXPIRE', KEYS[1], window + 60000)
return count
`;
export async function trackWindowEvent(key, member, windowMs = 60000) {
  if (typeof key !== 'string' || !key || key.length > 512) throw new TypeError('A valid sliding-window key is required.');
  const now = Date.now(); const period = Math.max(1000, Math.min(86400000, Math.floor(Number(windowMs) || 60000))); const safeMember = String(member).slice(0, 180);
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.'); warnFallback(); const item = getLocal(key); const values = item?.type === 'zset' ? item.value : new Map();
    for (const [id, score] of values) if (score <= now - period) values.delete(id);
    values.set(safeMember, now); setLocal(key, 'zset', values, Math.ceil((period + 60000) / 1000)); return values.size;
  }
  return Number(await command(['EVAL', TRACK_WINDOW_LUA, '1', key, String(now), String(period), safeMember])) || 0;
}

const POP_BATCH_LUA = `
local rows = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
if #rows > 0 then redis.call('LTRIM', KEYS[1], #rows, -1) end
return rows
`;
const RESOURCE_VELOCITY_LUA = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local resourceId = ARGV[3]
local numericId = tonumber(resourceId)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('ZADD', KEYS[1], now, resourceId)
redis.call('PEXPIRE', KEYS[1], window + 60000)
local distinct = redis.call('ZCARD', KEYS[1])
local sequential = 0
if numericId then
  local last = tonumber(redis.call('GET', KEYS[2]))
  local previous = tonumber(redis.call('GET', KEYS[3])) or 0
  if last and (numericId - last == 1 or numericId - last == -1) then sequential = previous + 1 end
  redis.call('SET', KEYS[2], numericId, 'PX', window + 60000)
  redis.call('SET', KEYS[3], sequential, 'PX', window + 60000)
else
  redis.call('DEL', KEYS[2], KEYS[3])
end
return {distinct, sequential}
`;

/** Atomically records distinct resource IDs and consecutive numeric-ID deltas. */
export async function trackResourceVelocity(key, resourceId, windowMs = 60000) {
  if (typeof key !== 'string' || !key || key.length > 480) throw new TypeError('A valid resource velocity key is required.');
  const member = String(resourceId).slice(0, 80);
  const period = Math.max(1000, Math.min(86400000, Math.floor(Number(windowMs) || 60000)));
  const now = Date.now();
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback();
    const zsetItem = getLocal(key);
    const zset = zsetItem?.type === 'zset' ? zsetItem.value : new Map();
    for (const [id, score] of zset) if (score <= now - period) zset.delete(id);
    zset.set(member, now);
    setLocal(key, 'zset', zset, Math.ceil((period + 60000) / 1000));
    let sequential = 0;
    if (/^\d{1,20}$/.test(member)) {
      const last = getLocal(`${key}:last`);
      const previous = getLocal(`${key}:seq`);
      const current = Number(member);
      if (last && (current - Number(last.value) === 1 || current - Number(last.value) === -1)) sequential = Number(previous?.value || 0) + 1;
      setLocal(`${key}:last`, 'string', String(current), Math.ceil((period + 60000) / 1000));
      setLocal(`${key}:seq`, 'string', String(sequential), Math.ceil((period + 60000) / 1000));
    } else {
      localStore.delete(`${key}:last`); localStore.delete(`${key}:seq`);
    }
    return { distinct: zset.size, sequential };
  }
  const result = await command(['EVAL', RESOURCE_VELOCITY_LUA, '3', key, `${key}:last`, `${key}:seq`, String(now), String(period), member]);
  if (!Array.isArray(result) || result.length < 2) throw new Error('Invalid resource velocity response.');
  return { distinct: Math.max(0, Number(result[0]) || 0), sequential: Math.max(0, Number(result[1]) || 0) };
}

export async function listPopBatch(key, count = 500) {
  const bounded = Math.max(1, Math.min(1000, Math.floor(Number(count) || 500)));
  if (!redisConfigured()) { if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.'); warnFallback(); const item = getLocal(key); if (!item || item.type !== 'list') return []; return item.value.splice(0, bounded); }
  const result = await command(['EVAL', POP_BATCH_LUA, '1', key, String(bounded)]); return Array.isArray(result) ? result : [];
}

const MULTI_TOKEN_BUCKET_LUA = `
local now = tonumber(ARGV[1])
local cost = tonumber(ARGV[2])
local allowed = 1
local minRemaining = math.huge
local maxRetry = 0
local calculated = {}
for i = 1, #KEYS do
  local base = 3 + ((i - 1) * 3)
  local capacity = tonumber(ARGV[base])
  local refillPerMs = tonumber(ARGV[base + 1])
  local ttlMs = tonumber(ARGV[base + 2])
  local values = redis.call('HMGET', KEYS[i], 'tokens', 'updated')
  local tokens = tonumber(values[1]) or capacity
  local updated = tonumber(values[2]) or now
  tokens = math.min(capacity, tokens + math.max(0, now - updated) * refillPerMs)
  if tokens < cost then
    allowed = 0
    maxRetry = math.max(maxRetry, math.ceil((cost - tokens) / refillPerMs))
  end
  minRemaining = math.min(minRemaining, math.floor(tokens))
  calculated[i] = { tokens, refillPerMs, ttlMs }
end
for i = 1, #KEYS do
  local tokens = calculated[i][1]
  if allowed == 1 then tokens = tokens - cost end
  redis.call('HSET', KEYS[i], 'tokens', tokens, 'updated', now)
  redis.call('PEXPIRE', KEYS[i], calculated[i][3])
end
if minRemaining == math.huge then minRemaining = 0 end
if allowed == 1 then minRemaining = math.max(0, minRemaining - cost) end
return { allowed, minRemaining, maxRetry }
`;

/** Atomically checks actor, subnet, tenant and normalized-route buckets in one Redis EVAL. */
export async function rateLimitMulti({ dimensions, weight = 1 }) {
  if (!Array.isArray(dimensions) || dimensions.length < 1 || dimensions.length > 8) throw new TypeError('rateLimitMulti requires 1–8 dimensions.');
  const now = Date.now();
  const cost = Math.max(1, Math.floor(Number(weight) || 1));
  const rows = dimensions.map((item) => {
    const key = String(item?.key || '');
    const limit = Math.floor(Number(item?.limit));
    const windowMs = Math.floor(Number(item?.windowMs || 60000));
    if (!key || key.length > 512 || !Number.isInteger(limit) || limit < 1 || limit > 100000 || !Number.isInteger(windowMs) || windowMs < 100 || windowMs > 3600000) throw new TypeError('Invalid multi-dimensional quota bucket.');
    if (cost > limit) throw new RangeError('Quota weight exceeds a bucket capacity.');
    return { key, limit, windowMs, refillPerMs: limit / windowMs, ttlMs: windowMs + 60000 };
  });
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
    warnFallback();
    const staged = rows.map((row) => {
      const item = getLocal(row.key);
      const amount = item?.type === 'bucket' ? Number(item.value.amount) : row.limit;
      const updated = item?.type === 'bucket' ? Number(item.value.updated) : now;
      return { ...row, amount: Math.min(row.limit, amount + Math.max(0, now - updated) * row.refillPerMs) };
    });
    const allowed = staged.every((row) => row.amount >= cost);
    let remaining = Infinity; let retryAfterMs = 0;
    for (const row of staged) {
      const next = allowed ? row.amount - cost : row.amount;
      setLocal(row.key, 'bucket', { amount: next, updated: now }, Math.ceil(row.ttlMs / 1000));
      remaining = Math.min(remaining, Math.floor(next));
      if (!allowed && row.amount < cost) retryAfterMs = Math.max(retryAfterMs, Math.ceil((cost - row.amount) / row.refillPerMs));
    }
    return { allowed, remaining: Number.isFinite(remaining) ? Math.max(0, remaining) : 0, retryAfterMs };
  }
  const args = [String(now), String(cost)];
  for (const row of rows) args.push(String(row.limit), String(row.refillPerMs), String(row.ttlMs));
  const result = await command(['EVAL', MULTI_TOKEN_BUCKET_LUA, String(rows.length), ...rows.map((row) => row.key), ...args]);
  if (!Array.isArray(result) || result.length < 3) throw new Error('Invalid multi-dimensional quota response.');
  return { allowed: Number(result[0]) === 1, remaining: Math.max(0, Number(result[1]) || 0), retryAfterMs: Math.max(0, Number(result[2]) || 0) };
}

const CONCURRENCY_ACQUIRE_LUA = `
local now = tonumber(ARGV[1])
local expires = tonumber(ARGV[2])
local maximum = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local count = redis.call('ZCARD', KEYS[1])
if count >= maximum then return {0, count} end
redis.call('ZADD', KEYS[1], expires, member)
redis.call('PEXPIRE', KEYS[1], expires - now + 1000)
return {1, count + 1}
`;
const CONCURRENCY_RELEASE_LUA = `return redis.call('ZREM', KEYS[1], ARGV[1])`;

export async function acquireConcurrency(key, member, { maximum = 3, ttlMs = 120000 } = {}) {
  if (typeof key !== 'string' || !key || key.length > 512) throw new TypeError('A valid concurrency key is required.');
  const now = Date.now(); const expiry = now + Math.max(1000, Math.min(600000, Number(ttlMs) || 120000));
  const max = Math.max(1, Math.min(100, Math.floor(Number(maximum) || 3)));
  const safeMember = String(member || randomUUID()).slice(0, 180);
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
    warnFallback();
    const item = getLocal(key); const set = item?.type === 'zset' ? item.value : new Map();
    for (const [id, score] of set) if (score <= now) set.delete(id);
    const allowed = set.size < max;
    if (allowed) set.set(safeMember, expiry);
    setLocal(key, 'zset', set, Math.ceil((expiry - now + 1000) / 1000));
    return { allowed, count: set.size, member: safeMember, key };
  }
  const result = await command(['EVAL', CONCURRENCY_ACQUIRE_LUA, '1', key, String(now), String(expiry), String(max), safeMember]);
  return { allowed: Number(result?.[0]) === 1, count: Number(result?.[1]) || 0, member: safeMember, key };
}

export async function releaseConcurrency(key, member) {
  if (!key || !member) return 0;
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH Redis in production.');
    const item = getLocal(String(key));
    return item?.type === 'zset' && item.value.delete(String(member)) ? 1 : 0;
  }
  return Number(await command(['EVAL', CONCURRENCY_RELEASE_LUA, '1', String(key), String(member)])) || 0;
}

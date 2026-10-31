import { randomUUID } from 'node:crypto';

const localStore = globalThis.__ARIXSHIELD_LOCAL_REDIS__ ??= new Map();
let warned = false;

function redisConfigured() {
  return Boolean(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);
}

function localModeAllowed() {
  return process.env.NODE_ENV !== 'production';
}

function warnFallback() {
  if (!warned) {
    warned = true;
    console.warn('[ArixShield] Upstash Redis is not configured. Using an ephemeral in-memory store for local preview only; data is not shared between serverless instances and will be lost on restart.');
  }
}

function getLocal(key) {
  const item = localStore.get(key);
  if (!item) return null;
  if (item.expiresAt && item.expiresAt <= Date.now()) {
    localStore.delete(key);
    return null;
  }
  return item;
}

function setLocal(key, type, value, ttlSeconds = null) {
  const expiresAt = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
  localStore.set(key, { type, value, expiresAt });
}

async function command(parts) {
  if (!Array.isArray(parts) || !parts.length) throw new TypeError('Redis command must be a non-empty array.');
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in production.');
    warnFallback();
    return localCommand(parts);
  }

  const base = process.env.UPSTASH_REDIS_REST_URL.replace(/\/+$/, '');
  const response = await fetch(base, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(parts),
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error(`Upstash Redis REST request failed (${response.status}).`);
  const payload = await response.json();
  if (Object.hasOwn(payload, 'error')) throw new Error(`Upstash Redis error: ${String(payload.error).slice(0, 240)}`);
  return payload.result;
}

async function pipeline(commands) {
  if (!Array.isArray(commands) || !commands.length) return [];
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback();
    const results = [];
    for (const parts of commands) results.push(await localCommand(parts));
    return results;
  }
  const base = process.env.UPSTASH_REDIS_REST_URL.replace(/\/+$/, '');
  const response = await fetch(`${base}/pipeline`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(commands),
    signal: AbortSignal.timeout(7000)
  });
  if (!response.ok) throw new Error(`Upstash pipeline failed (${response.status}).`);
  const rows = await response.json();
  if (!Array.isArray(rows)) throw new Error('Unexpected Upstash pipeline response.');
  return rows.map((row) => {
    if (row && Object.hasOwn(row, 'error')) throw new Error(`Upstash Redis error: ${String(row.error).slice(0, 240)}`);
    return row?.result;
  });
}

function localCommand(parts) {
  const [rawName, ...args] = parts;
  const name = String(rawName).toUpperCase();
  const key = String(args[0] ?? '');
  const item = getLocal(key);
  switch (name) {
    case 'PING': return 'PONG';
    case 'GET': return item?.type === 'string' ? item.value : null;
    case 'MGET': return args.map((candidate) => { const value = getLocal(String(candidate)); return value?.type === 'string' ? value.value : null; });
    case 'SET': {
      const value = String(args[1] ?? '');
      const nx = args.some((v) => String(v).toUpperCase() === 'NX');
      const exIndex = args.findIndex((v) => String(v).toUpperCase() === 'EX');
      if (nx && item) return null;
      setLocal(key, 'string', value, exIndex >= 0 ? Number(args[exIndex + 1]) : null);
      return 'OK';
    }
    case 'DEL': {
      let count = 0;
      for (const k of args) if (localStore.delete(String(k))) count++;
      return count;
    }
    case 'EXPIRE': {
      if (!item) return 0;
      item.expiresAt = Date.now() + Number(args[1]) * 1000;
      return 1;
    }
    case 'INCR':
    case 'INCRBY': {
      const by = name === 'INCR' ? 1 : Number(args[1]);
      const next = Number(item?.value ?? 0) + by;
      setLocal(key, 'string', String(next), item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null);
      return next;
    }
    case 'LPUSH': {
      const list = item?.type === 'list' ? item.value : [];
      for (const value of args.slice(1)) list.unshift(String(value));
      setLocal(key, 'list', list, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null);
      return list.length;
    }
    case 'LTRIM': {
      if (!item || item.type !== 'list') return 'OK';
      const start = Number(args[1]);
      const end = Number(args[2]);
      const stop = end < 0 ? item.value.length + end + 1 : end + 1;
      item.value = item.value.slice(start, Math.max(start, stop));
      return 'OK';
    }
    case 'LRANGE': {
      if (!item || item.type !== 'list') return [];
      const start = Number(args[1]);
      const end = Number(args[2]);
      const stop = end < 0 ? item.value.length + end + 1 : end + 1;
      return item.value.slice(start, Math.max(start, stop));
    }
    case 'LLEN': return item?.type === 'list' ? item.value.length : 0;
    case 'ZADD': {
      const zset = item?.type === 'zset' ? item.value : new Map();
      let added = 0;
      for (let i = 1; i + 1 < args.length; i += 2) {
        const score = Number(args[i]);
        const member = String(args[i + 1]);
        if (!zset.has(member)) added++;
        zset.set(member, score);
      }
      setLocal(key, 'zset', zset, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null);
      return added;
    }
    case 'ZREMRANGEBYSCORE': {
      if (!item || item.type !== 'zset') return 0;
      const min = Number(args[1]);
      const max = Number(args[2]);
      let removed = 0;
      for (const [member, score] of item.value) if (score >= min && score <= max) { item.value.delete(member); removed++; }
      return removed;
    }
    case 'ZCARD': return item?.type === 'zset' ? item.value.size : 0;
    case 'PEXPIRE': {
      if (!item) return 0;
      item.expiresAt = Date.now() + Number(args[1]);
      return 1;
    }
    case 'SADD': {
      const set = item?.type === 'set' ? item.value : new Set();
      let added = 0;
      for (const member of args.slice(1)) { const before = set.size; set.add(String(member)); if (set.size > before) added++; }
      setLocal(key, 'set', set, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null);
      return added;
    }
    case 'SMEMBERS': return item?.type === 'set' ? [...item.value] : [];
    case 'HSET': {
      const hash = item?.type === 'hash' ? item.value : new Map();
      let added = 0;
      for (let i = 1; i + 1 < args.length; i += 2) { const field = String(args[i]); if (!hash.has(field)) added++; hash.set(field, String(args[i + 1])); }
      setLocal(key, 'hash', hash, item?.expiresAt ? Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)) : null);
      return added;
    }
    case 'HMGET': {
      const hash = item?.type === 'hash' ? item.value : new Map();
      return args.slice(1).map((field) => hash.get(String(field)) ?? null);
    }
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
  const now = Date.now();
  const item = getLocal(key);
  const limit = Math.max(1, options.limit);
  const weight = Math.max(1, options.weight);
  const windowMs = Math.max(100, options.windowMs);
  if (algorithm === 'SLIDING_WINDOW') {
    const events = (item?.value ?? []).filter((t) => t > now - windowMs);
    const allowed = events.length + weight <= limit;
    if (allowed) for (let i = 0; i < weight; i++) events.push(now);
    setLocal(key, 'list', events, Math.ceil((windowMs + 60000) / 1000));
    return { allowed, remaining: Math.max(0, limit - events.length), retryAfterMs: allowed ? 0 : Math.max(1, windowMs - (now - (events[0] ?? now))) };
  }
  if (algorithm === 'FIXED_WINDOW') {
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const count = item?.windowStart === windowStart ? Number(item.value) : 0;
    const next = count + weight;
    const allowed = next <= limit;
    localStore.set(key, { type: 'fixed', value: allowed ? next : count, windowStart, expiresAt: windowStart + windowMs });
    return { allowed, remaining: Math.max(0, limit - (allowed ? next : count)), retryAfterMs: allowed ? 0 : windowStart + windowMs - now };
  }
  const capacity = limit;
  const refillPerMs = limit / windowMs;
  let amount = item?.type === 'bucket' ? Number(item.value.amount) : (algorithm === 'LEAKY_BUCKET' ? 0 : capacity);
  const updated = item?.type === 'bucket' ? Number(item.value.updated) : now;
  const elapsed = Math.max(0, now - updated);
  if (algorithm === 'LEAKY_BUCKET') amount = Math.max(0, amount - elapsed * refillPerMs);
  else amount = Math.min(capacity, amount + elapsed * refillPerMs);
  const allowed = algorithm === 'LEAKY_BUCKET' ? amount + weight <= capacity : amount >= weight;
  amount = allowed ? (algorithm === 'LEAKY_BUCKET' ? amount + weight : amount - weight) : amount;
  setLocal(key, 'bucket', { amount, updated: now }, Math.ceil(windowMs / 1000) + 60);
  const retry = algorithm === 'LEAKY_BUCKET' ? Math.max(0, amount + weight - capacity) / refillPerMs : Math.max(0, weight - amount) / refillPerMs;
  return { allowed, remaining: Math.max(0, Math.floor(capacity - amount)), retryAfterMs: allowed ? 0 : Math.ceil(retry) };
}

export async function rateLimit({ key, algorithm = 'SLIDING_WINDOW', limit = 60, windowMs = 60000, weight = 1, capacity, refillPerMs }) {
  if (typeof key !== 'string' || !key || key.length > 512) throw new TypeError('A valid Redis rate-limit key is required.');
  const normalized = String(algorithm).toUpperCase();
  const max = Math.max(1, Math.floor(Number(capacity ?? limit)));
  const cost = Math.max(1, Math.floor(Number(weight)));
  const period = Math.max(100, Math.floor(Number(windowMs)));
  if (!Number.isFinite(max) || !Number.isFinite(cost) || !Number.isFinite(period)) throw new TypeError('Rate-limit values must be finite numbers.');
  if (!['TOKEN_BUCKET', 'SLIDING_WINDOW', 'FIXED_WINDOW', 'LEAKY_BUCKET'].includes(normalized)) throw new Error('Unsupported rate-limit algorithm.');
  if (cost > max) throw new RangeError('Rate-limit weight cannot exceed bucket capacity.');
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback();
    return localLimit(key, normalized, { limit: max, windowMs: period, weight: cost });
  }

  let result;
  const now = Date.now();
  const refill = Number(refillPerMs) > 0 ? Number(refillPerMs) : max / period;
  if (normalized === 'TOKEN_BUCKET') result = await command(['EVAL', TOKEN_BUCKET_LUA, '1', key, String(max), String(refill), String(now), String(cost)]);
  else if (normalized === 'SLIDING_WINDOW') result = await command(['EVAL', SLIDING_WINDOW_LUA, '1', key, String(now), String(period), String(max), String(cost), randomUUID()]);
  else if (normalized === 'FIXED_WINDOW') result = await command(['EVAL', FIXED_WINDOW_LUA, '1', key, String(max), String(cost), String(period), String(now)]);
  else result = await command(['EVAL', LEAKY_BUCKET_LUA, '1', key, String(max), String(refill), String(now), String(cost)]);

  if (!Array.isArray(result) || result.length < 3) throw new Error('Invalid Redis rate-limit response.');
  return {
    allowed: Number(result[0]) === 1,
    remaining: Math.max(0, Number(result[1]) || 0),
    retryAfterMs: Math.max(0, Number(result[2]) || 0)
  };
}

export async function getJson(key) {
  const value = await command(['GET', key]);
  if (value == null) return null;
  try { return JSON.parse(value); } catch { return null; }
}

export async function setJson(key, value, ttlSeconds = null, nx = false) {
  const args = ['SET', key, JSON.stringify(value)];
  if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) args.push('EX', String(Math.floor(ttlSeconds)));
  if (nx) args.push('NX');
  return command(args);
}

export async function setString(key, value, ttlSeconds = null, nx = false) {
  const args = ['SET', key, String(value)];
  if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) args.push('EX', String(Math.floor(ttlSeconds)));
  if (nx) args.push('NX');
  return command(args);
}

export async function getString(key) { return command(['GET', key]); }
export async function deleteKeys(...keys) { return keys.length ? command(['DEL', ...keys]) : 0; }
export async function increment(key, amount = 1) { return command(['INCRBY', key, String(amount)]); }
const PUSH_TRIM_LUA = `
redis.call('LPUSH', KEYS[1], ARGV[1])
redis.call('LTRIM', KEYS[1], 0, tonumber(ARGV[2]) - 1)
return redis.call('LLEN', KEYS[1])
`;

export async function listPushTrim(key, event, keep = 500) {
  const serialized = JSON.stringify(event);
  const boundedKeep = Math.max(1, Math.min(5000, Math.floor(Number(keep) || 500)));
  if (!redisConfigured()) {
    if (!localModeAllowed()) throw new Error('ArixShield requires Upstash Redis in production.');
    warnFallback();
    await localCommand(['LPUSH', key, serialized]);
    await localCommand(['LTRIM', key, '0', String(boundedKeep - 1)]);
    return localCommand(['LLEN', key]);
  }
  return command(['EVAL', PUSH_TRIM_LUA, '1', key, serialized, String(boundedKeep)]);
}
export async function listRange(key, start = 0, end = 99) { return command(['LRANGE', key, String(start), String(end)]); }
export async function expire(key, seconds) { return command(['EXPIRE', key, String(seconds)]); }
export async function setAdd(key, member, ttlSeconds = null) {
  const result = await command(['SADD', key, String(member)]);
  if (ttlSeconds) await expire(key, ttlSeconds);
  return result;
}
export async function setMembers(key) { return command(['SMEMBERS', key]); }
export async function hashSet(key, values) {
  const args = ['HSET', key];
  for (const [field, value] of Object.entries(values)) args.push(field, String(value));
  return command(args);
}
export async function hashGetMany(key, ...fields) { return command(['HMGET', key, ...fields]); }
export async function isUsingUpstash() { return redisConfigured(); }

export async function recordProjectEvent(projectId, event, { threat = false } = {}) {
  const keep = Math.max(100, Math.min(1000, Number(process.env.ARIX_EVENT_RETENTION) || 500));
  const kind = threat ? 'threat_logs' : 'live_visitors';
  const key = `arix:${kind}:${projectId}`;
  await listPushTrim(key, event, keep);
  const metrics = `arix:metrics:${projectId}`;
  await increment(`${metrics}:total_requests`, 1);
  if (threat && event.blocked !== false) await increment(`${metrics}:blocked_attacks`, 1);
  if (event.type === 'TRAPPED_HACKER') await increment(`${metrics}:trapped_hackers`, 1);
}

export async function getProjectDashboardSnapshot(projectId) {
  const metrics = `arix:metrics:${projectId}`;
  // This read-only pipeline reduces REST round trips; Upstash pipelines are not atomic.
  const [visitors, threats, values] = await pipeline([
    ['LRANGE', `arix:live_visitors:${projectId}`, '0', '199'],
    ['LRANGE', `arix:threat_logs:${projectId}`, '0', '199'],
    ['MGET', `${metrics}:total_requests`, `${metrics}:blocked_attacks`, `${metrics}:trapped_hackers`, `${metrics}:tarpit_seconds_burned`]
  ]);
  const [total, blocked, trapped, tarpit] = Array.isArray(values) ? values : [];
  return {
    visitors: Array.isArray(visitors) ? visitors : [],
    threats: Array.isArray(threats) ? threats : [],
    metrics: {
      totalRequests: Number(total || 0),
      blockedAttacks: Number(blocked || 0),
      trappedHackers: Number(trapped || 0),
      tarpitSecondsBurned: Number(tarpit || 0),
      activeVisitors: null
    }
  };
}

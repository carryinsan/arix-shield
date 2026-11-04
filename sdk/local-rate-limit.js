import { createHash } from 'node:crypto';
import { formatIpPrefix } from '../api/_lib/cidr.js';

export const DEFAULT_LOCAL_QUOTA_BUCKET_CAPACITY = 10000;

function digest(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

/**
 * Convert a trusted client address to a stable network prefix. IPv4 uses /24;
 * IPv6 uses /64 so one delegated client subnet shares the anonymous budget.
 * Invalid or unavailable addresses deliberately map to one conservative
 * "unknown" bucket rather than receiving a fresh identity per request.
 */
export function localNetworkPrefix(ip) {
  if (typeof ip !== 'string' || !ip.trim()) return 'unknown';
  const address = ip.trim();
  return formatIpPrefix(address, address.includes(':') ? 64 : 24) || 'unknown';
}

/**
 * Build bounded, opaque quota dimensions. Anonymous requests always receive a
 * stable network-prefix dimension. A verified device proof adds a second
 * device dimension; the request UUID used for telemetry is never a quota key.
 */
export function buildLocalQuotaDimensions({
  scope,
  identity = 'anonymous',
  actorIdentity = '',
  authenticated = false,
  networkIp = '',
  method = 'GET',
  pathname = '/',
  dpopVerified = false,
  actorLimit = 120,
  routeLimit = actorLimit,
  networkLimit = Math.min(100000, actorLimit * 10)
} = {}) {
  const namespace = digest(`arix-local-quota-v1\0${scope || 'default'}`).slice(0, 32);
  const verb = String(method || 'GET').toUpperCase().slice(0, 16);
  const route = String(pathname || '/').slice(0, 2048);
  const dimensions = [];
  const makeKey = (kind, value, routeBound = true) => `arix-local:${digest(`${namespace}\0${kind}\0${value}${routeBound ? `\0${verb}\0${route}` : ''}`)}`;

  if (authenticated && typeof actorIdentity === 'string' && actorIdentity && !actorIdentity.startsWith('anonymous:')) {
    // Match the distributed actor quota: an authenticated principal has one
    // aggregate budget across methods and paths. A route-derived local key
    // would let the same principal obtain a fresh bucket for every URL and
    // would also let path churn consume the bounded process-local store.
    dimensions.push({ key: makeKey('actor', actorIdentity, false), limit: actorLimit });
    return dimensions;
  }

  const prefix = localNetworkPrefix(networkIp);
  dimensions.push({ key: makeKey('network', prefix, false), limit: networkLimit });
  dimensions.push({ key: makeKey('network-route', prefix), limit: routeLimit });
  if (dpopVerified && typeof actorIdentity === 'string' && actorIdentity.startsWith('device:')) {
    dimensions.push({ key: makeKey('device', actorIdentity), limit: actorLimit });
  }
  return dimensions;
}

/**
 * Process-local token-bucket store with fixed capacity. Expired idle buckets are
 * pruned; live buckets are never evicted to make room because eviction would
 * let an attacker reset another client's quota by churning identities. At
 * capacity, new dimensions fail closed until stale entries expire.
 */
export class LocalQuotaStore {
  #buckets = new Map();
  #operations = 0;
  #maxBuckets;

  constructor({ maxBuckets = DEFAULT_LOCAL_QUOTA_BUCKET_CAPACITY } = {}) {
    const value = Number(maxBuckets);
    if (!Number.isSafeInteger(value) || value < 1 || value > 100000) throw new RangeError('Invalid local quota bucket capacity.');
    this.#maxBuckets = value;
  }

  get size() { return this.#buckets.size; }

  #prune(now) {
    for (const [key, bucket] of this.#buckets) {
      if (bucket.expiresAt <= now) this.#buckets.delete(key);
    }
  }

  consume(dimensions, windowMs = 60000, weight = 1, now = Date.now()) {
    if (!Array.isArray(dimensions) || dimensions.length < 1 || dimensions.length > 4) throw new TypeError('One to four local quota dimensions are required.');
    const window = Number(windowMs);
    const charge = Number(weight);
    if (!Number.isFinite(window) || window < 100 || window > 3600000 || !Number.isFinite(charge) || charge <= 0) throw new RangeError('Invalid local quota window or weight.');

    const normalized = new Map();
    for (const dimension of dimensions) {
      const key = String(dimension?.key || '');
      const limit = Number(dimension?.limit);
      if (!key || key.length > 256 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100000) throw new TypeError('Invalid local quota dimension.');
      const current = normalized.get(key);
      normalized.set(key, current === undefined ? limit : Math.min(current, limit));
    }

    this.#operations++;
    if ((this.#operations & 255) === 0 || this.#buckets.size + [...normalized.keys()].filter((key) => !this.#buckets.has(key)).length > this.#maxBuckets) this.#prune(now);

    const missing = [...normalized.keys()].filter((key) => !this.#buckets.has(key)).length;
    if (this.#buckets.size + missing > this.#maxBuckets) {
      return { allowed: false, remaining: 0, retryAfterMs: Math.min(window, 1000), saturated: true };
    }

    const prepared = [];
    let allowed = true;
    let retryAfterMs = 0;
    let remaining = Number.POSITIVE_INFINITY;
    for (const [key, limit] of normalized) {
      const old = this.#buckets.get(key);
      const tokens = old
        ? Math.min(limit, old.tokens + Math.max(0, now - old.updatedAt) * (limit / window))
        : limit;
      const enough = tokens >= charge;
      if (!enough) {
        allowed = false;
        retryAfterMs = Math.max(retryAfterMs, Math.ceil((charge - tokens) / (limit / window)));
      }
      remaining = Math.min(remaining, Math.max(0, Math.floor(tokens)));
      prepared.push({ key, limit, tokens, chargedTokens: enough ? tokens - charge : tokens });
    }

    // Multi-dimensional admission is atomic: if any dimension is exhausted,
    // no other dimension is charged and no new per-route/device bucket is
    // allocated. This prevents denied path/key churn from filling the store.
    if (!allowed) {
      return {
        allowed: false,
        remaining: Number.isFinite(remaining) ? remaining : 0,
        retryAfterMs: Math.max(1, retryAfterMs),
        resetAt: now + Math.max(1, retryAfterMs),
        saturated: false
      };
    }

    remaining = Math.min(...prepared.map((bucket) => Math.max(0, Math.floor(bucket.chargedTokens))));
    for (const bucket of prepared) {
      this.#buckets.set(bucket.key, {
        tokens: bucket.chargedTokens,
        updatedAt: now,
        expiresAt: now + Math.max(60000, window * 3)
      });
    }

    return {
      allowed: true,
      remaining: Number.isFinite(remaining) ? remaining : 0,
      retryAfterMs: 0,
      resetAt: now + window,
      saturated: false
    };
  }
}

export const processLocalQuotaStore = new LocalQuotaStore();

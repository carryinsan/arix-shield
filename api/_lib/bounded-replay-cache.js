/**
 * Bounded, expiry-driven replay storage.
 *
 * - Never evicts an unexpired replay entry.
 * - Uses a min-heap so requests do not scan the entire cache.
 * - Enforces global, namespace (tenant/project), and requester/device caps.
 * - `admit` optionally runs a synchronous admission callback before insertion,
 *   allowing quota checks and replay insertion to be one event-loop-atomic step.
 */
function boundedScope(value, fallback) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  return (text || fallback).slice(0, 240);
}

function heapPush(heap, item) {
  let index = heap.length;
  heap.push(item);
  while (index > 0) {
    const parent = (index - 1) >> 1;
    if (heap[parent].expiresAt <= item.expiresAt) break;
    heap[index] = heap[parent];
    index = parent;
  }
  heap[index] = item;
}

function heapPop(heap) {
  if (!heap.length) return null;
  const first = heap[0];
  const last = heap.pop();
  if (heap.length && last) {
    let index = 0;
    while (true) {
      const left = index * 2 + 1;
      const right = left + 1;
      if (left >= heap.length) break;
      let child = left;
      if (right < heap.length && heap[right].expiresAt < heap[left].expiresAt) child = right;
      if (heap[child].expiresAt >= last.expiresAt) break;
      heap[index] = heap[child];
      index = child;
    }
    heap[index] = last;
  }
  return first;
}

export class BoundedReplayCache {
  constructor({ maxEntries = 16384, maxPerNamespace = 2048, maxPerPartition = 128 } = {}) {
    this.maxEntries = Math.max(1, Math.floor(Number(maxEntries) || 1));
    this.maxPerNamespace = Math.max(1, Math.min(this.maxEntries, Math.floor(Number(maxPerNamespace) || 1)));
    this.maxPerPartition = Math.max(1, Math.min(this.maxPerNamespace, Math.floor(Number(maxPerPartition) || 1)));
    this.entries = new Map();
    this.namespaceCounts = new Map();
    this.partitionCounts = new Map();
    this.expiryHeap = [];
    this.lastNow = 0;
  }

  _now(candidate) {
    const raw = Number(candidate);
    const clock = Number.isFinite(raw) && raw >= 0 ? raw : Date.now();
    this.lastNow = Math.max(this.lastNow, clock);
    return this.lastNow;
  }

  _prune(now) {
    while (this.expiryHeap.length && this.expiryHeap[0].expiresAt <= now) {
      const expired = heapPop(this.expiryHeap);
      const current = this.entries.get(expired.key);
      if (!current || current.expiresAt !== expired.expiresAt) continue;
      this.entries.delete(expired.key);
      const namespaceCount = (this.namespaceCounts.get(current.namespace) || 1) - 1;
      if (namespaceCount > 0) this.namespaceCounts.set(current.namespace, namespaceCount);
      else this.namespaceCounts.delete(current.namespace);
      const partitionCount = (this.partitionCounts.get(current.partition) || 1) - 1;
      if (partitionCount > 0) this.partitionCounts.set(current.partition, partitionCount);
      else this.partitionCounts.delete(current.partition);
    }
  }

  admit(key, { namespace = 'default', partition = namespace, ttlMs = 60000, now } = {}, beforeInsert = null) {
    if (typeof key !== 'string' || !key || key.length > 512) return { accepted: false, reason: 'INVALID_KEY' };
    const time = this._now(now);
    this._prune(time);
    if (this.entries.has(key)) return { accepted: false, reason: 'REPLAY' };

    const ns = boundedScope(namespace, 'default');
    const partitionScope = `${ns}\0${boundedScope(partition, ns)}`;
    if (this.entries.size >= this.maxEntries) return { accepted: false, reason: 'GLOBAL_CAPACITY' };
    if ((this.namespaceCounts.get(ns) || 0) >= this.maxPerNamespace) return { accepted: false, reason: 'NAMESPACE_CAPACITY' };
    if ((this.partitionCounts.get(partitionScope) || 0) >= this.maxPerPartition) return { accepted: false, reason: 'PARTITION_CAPACITY' };

    let admissionValue = true;
    if (typeof beforeInsert === 'function') {
      try { admissionValue = beforeInsert(); }
      catch { return { accepted: false, reason: 'ADMISSION_ERROR' }; }
      if (admissionValue && typeof admissionValue.then === 'function') return { accepted: false, reason: 'ASYNC_ADMISSION_NOT_ALLOWED' };
      if (admissionValue === false) return { accepted: false, reason: 'ADMISSION_DENIED', admissionValue };
    }

    const ttl = Math.max(1, Math.min(10 * 60 * 1000, Math.floor(Number(ttlMs) || 1)));
    const expiresAt = time + ttl;
    this.entries.set(key, { namespace: ns, partition: partitionScope, expiresAt });
    this.namespaceCounts.set(ns, (this.namespaceCounts.get(ns) || 0) + 1);
    this.partitionCounts.set(partitionScope, (this.partitionCounts.get(partitionScope) || 0) + 1);
    heapPush(this.expiryHeap, { key, expiresAt });
    return { accepted: true, expiresAt, admissionValue };
  }

  consume(key, options = {}) { return this.admit(key, options); }

  get size() { return this.entries.size; }

  stats() {
    return Object.freeze({ size: this.entries.size, namespaces: this.namespaceCounts.size, partitions: this.partitionCounts.size, maxEntries: this.maxEntries });
  }
}

/** Bounded fixed-window quota buckets with amortized O(log n) expiry cleanup. */
export class BoundedWindowQuotaStore {
  constructor({ maxEntries = 20000, maxPerNamespace = 4000 } = {}) {
    this.maxEntries = Math.max(1, Math.floor(Number(maxEntries) || 1));
    this.maxPerNamespace = Math.max(1, Math.min(this.maxEntries, Math.floor(Number(maxPerNamespace) || 1)));
    this.entries = new Map();
    this.namespaceCounts = new Map();
    this.expiryHeap = [];
    this.lastNow = 0;
  }

  _now() {
    this.lastNow = Math.max(this.lastNow, Date.now());
    return this.lastNow;
  }

  _prune(now) {
    while (this.expiryHeap.length && this.expiryHeap[0].expiresAt <= now) {
      const expired = heapPop(this.expiryHeap);
      const current = this.entries.get(expired.key);
      if (!current || current.version !== expired.version || current.expiresAt !== expired.expiresAt) continue;
      this.entries.delete(expired.key);
      const count = (this.namespaceCounts.get(current.namespace) || 1) - 1;
      if (count > 0) this.namespaceCounts.set(current.namespace, count);
      else this.namespaceCounts.delete(current.namespace);
    }
  }

  consume({ key, namespace = 'default', limit, windowMs = 60000 }) {
    if (typeof key !== 'string' || !key || key.length > 512) return { allowed: false, remaining: 0, capacity: 0, reason: 'INVALID_KEY' };
    const now = this._now();
    this._prune(now);
    const ns = boundedScope(namespace, 'default');
    const window = Math.max(100, Math.min(10 * 60 * 1000, Number(windowMs) || 60000));
    let row = this.entries.get(key);
    let scheduleExpiry = false;
    if (!row) {
      if (this.entries.size >= this.maxEntries || (this.namespaceCounts.get(ns) || 0) >= this.maxPerNamespace) {
        return { allowed: false, remaining: 0, capacity: Math.max(1, Math.floor(Number(limit) || 1)), retryAfterMs: 1000, reason: 'STORE_CAPACITY' };
      }
      row = { namespace: ns, start: now, used: 0, version: 1, expiresAt: now + window * 2 };
      this.entries.set(key, row);
      this.namespaceCounts.set(ns, (this.namespaceCounts.get(ns) || 0) + 1);
      scheduleExpiry = true;
    } else if (now - row.start >= window) {
      row.start = now;
      row.used = 0;
      row.version += 1;
      row.expiresAt = now + window * 2;
      scheduleExpiry = true;
    }
    if (scheduleExpiry) heapPush(this.expiryHeap, { key, version: row.version, expiresAt: row.expiresAt });
    // Stale heap nodes are bounded: rebuild from live buckets if they exceed 3x capacity.
    if (this.expiryHeap.length > this.maxEntries * 3) {
      this.expiryHeap.length = 0;
      for (const [entryKey, entry] of this.entries) heapPush(this.expiryHeap, { key: entryKey, version: entry.version, expiresAt: entry.expiresAt });
    }
    row.used += 1;
    const baseLimit = Math.max(1, Math.floor(Number(limit) || 1));
    const capacity = Math.max(1, Math.floor(baseLimit * 0.25));
    const allowed = row.used <= capacity;
    return { allowed, remaining: Math.max(0, capacity - row.used), capacity, retryAfterMs: allowed ? 0 : Math.max(100, row.start + window - now) };
  }

  get size() { return this.entries.size; }
}

/** In-process weighted deficit round-robin scheduler; not a distributed lease. */
export function createDrrScheduler({ quantum = 10, maxTenants = 10_000 } = {}) {
  if (!Number.isFinite(quantum) || quantum <= 0 || !Number.isInteger(maxTenants) || maxTenants < 1) throw new TypeError('Invalid DRR scheduler configuration');
  const tenants = new Map();
  let cursor = 0;
  return Object.freeze({
    schedule(tenantId, cost = 1) {
      const id = String(tenantId || '').slice(0, 256);
      const amount = Number(cost);
      if (!id || !Number.isFinite(amount) || amount <= 0 || amount > 1_000_000) throw new TypeError('tenantId and bounded positive cost are required');
      let entry = tenants.get(id);
      if (!entry) {
        if (tenants.size >= maxTenants) return Object.freeze({ allowed: false, reason: 'TENANT_CAPACITY' });
        entry = { deficit: 0, lastSeen: Date.now() };
        tenants.set(id, entry);
      }
      entry.lastSeen = Date.now();
      entry.deficit = Math.min(1_000_000, entry.deficit + quantum);
      const allowed = entry.deficit >= amount;
      if (allowed) entry.deficit -= amount;
      return Object.freeze({ allowed, deficit: entry.deficit, quantum });
    },
    prune({ idleMs = 300_000, now = Date.now() } = {}) {
      let removed = 0;
      for (const [id, entry] of tenants) if (now - entry.lastSeen > idleMs) { tenants.delete(id); removed++; }
      return removed;
    },
    get size() { return tenants.size; }
  });
}

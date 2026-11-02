import { randomBytes, createHash } from 'node:crypto';

const localIncidents = new Map();
const localActions = new Map();
const actorHash = (value) => createHash('sha256').update(String(value)).digest('hex');

export function createSocEngine({ store = null, maxAutoContainedActorsPerMinute = 25, now = () => Date.now() } = {}) {
  const requestedLimit = Number(maxAutoContainedActorsPerMinute);
  if (!Number.isFinite(requestedLimit) || requestedLimit < 1 || requestedLimit > 1000 || typeof now !== 'function') throw new TypeError('Invalid SOC rate limit or clock');
  const limit = Math.floor(requestedLimit);
  const perMinute = new Map();
  const maxLocalRecords = 10_000;
  if (store && (typeof store.get !== 'function' || typeof store.set !== 'function' || typeof store.consume !== 'function')) throw new TypeError('SOC store must provide get, set and atomic consume methods');
  const get = async (key) => { const remote = store?.get ? await store.get(key) : null; return remote ?? localIncidents.get(key) ?? localActions.get(key) ?? null; };
  const set = async (key, value, ttlMs) => {
    if (localActions.size >= maxLocalRecords) { const first = localActions.keys().next().value; if (first !== undefined) localActions.delete(first); }
    localActions.set(key, value);
    return store?.set ? store.set(key, value, ttlMs) : true;
  };
  const checkBlastRadius = ({ projectId, actorId, targetType = 'actor', confirm = false } = {}) => {
    if (!projectId || !actorId || targetType !== 'actor') return { allowed: false, reason: 'ACTOR_ONLY_CONTAINMENT' };
    if (confirm) return { allowed: true, requiresConfirmation: false };
    const bucket = Math.floor(now() / 60_000);
    const quotaKey = `${String(projectId)}:${bucket}`;
    const count = perMinute.get(quotaKey) || 0;
    if (count >= limit) return { allowed: false, reason: 'AUTO_CONTAINMENT_RATE_LIMIT', count, limit };
    perMinute.set(quotaKey, count + 1);
    for (const key of perMinute.keys()) { const oldBucket = Number(key.slice(key.lastIndexOf(':') + 1)); if (oldBucket < bucket - 1) perMinute.delete(key); }
    return { allowed: true, count: count + 1, limit };
  };
  return Object.freeze({
    async createOrUpdateIncident(projectId, event) {
      if (!projectId || !event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('projectId and event required');
      const id = String(event.incidentId || actorHash(`${projectId}:${event.fingerprint || event.type || 'event'}`).slice(0, 24));
      const current = await get(`incident:${projectId}:${id}`) || { id, projectId: String(projectId), severity: 'low', status: 'OPEN', actors: [], timeline: [], playbooksExecuted: [] };
      const incident = { ...current, severity: ['critical','high','medium','low'].includes(event.severity) ? event.severity : current.severity, status: current.status, actors: [...new Set([...current.actors, ...(event.actorId ? [actorHash(event.actorId)] : [])])].slice(0, 500), timeline: [...current.timeline, { at: now(), type: String(event.type || 'EVENT').slice(0, 64), summary: String(event.summary || '').slice(0, 256) }].slice(-500) };
      if (localIncidents.size >= maxLocalRecords) { const first = localIncidents.keys().next().value; if (first !== undefined) localIncidents.delete(first); }
      localIncidents.set(`incident:${projectId}:${id}`, incident);
      if (store?.set) await store.set(`incident:${projectId}:${id}`, incident);
      return structuredClone(incident);
    },
    checkBlastRadius,
    async containActor({ projectId, actorId, priorState = null, ttlMs = 300_000 } = {}) {
      if (!projectId || !actorId || !Number.isFinite(Number(ttlMs)) || Number(ttlMs) < 1000) throw new TypeError('projectId, actorId and a valid TTL are required for containment');
      let snapshot;
      try { snapshot = priorState == null ? null : JSON.parse(JSON.stringify(priorState)); } catch { throw new TypeError('priorState must be JSON-serializable'); }
      if (Buffer.byteLength(JSON.stringify(snapshot ?? null)) > 64 * 1024) throw new RangeError('priorState exceeds 64 KiB');
      const gate = checkBlastRadius({ projectId, actorId, targetType: 'actor' });
      if (!gate.allowed) return { contained: false, ...gate };
      const token = randomBytes(24).toString('base64url');
      const record = { projectId: String(projectId), actorHash: actorHash(actorId), priorState: snapshot, expiresAt: now() + Math.min(Math.max(ttlMs, 1_000), 86_400_000), tokenHash: actorHash(token) };
      await set(`soc-action:${record.tokenHash}`, record, record.expiresAt - now());
      return { contained: true, rollbackToken: token, actorHash: record.actorHash };
    },
    async revertContainmentAction(token, { projectId } = {}) {
      const tokenHash = actorHash(token || '');
      const record = await get(`soc-action:${tokenHash}`);
      if (!record || record.projectId !== String(projectId) || record.expiresAt < now()) return { reverted: false, reason: 'ROLLBACK_TOKEN_INVALID_OR_EXPIRED' };
      if (store?.consume) { if (!await store.consume(`soc-action:${tokenHash}`)) return { reverted: false, reason: 'ROLLBACK_ALREADY_USED' }; }
      localActions.delete(`soc-action:${tokenHash}`);
      return { reverted: true, actorHash: record.actorHash, priorState: record.priorState, allowlistUntil: now() + 300_000 };
    }
  });
}

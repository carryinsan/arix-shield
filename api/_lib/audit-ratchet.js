import { createHmac, createHash, sign, verify } from 'node:crypto';

function canonical(value) { return JSON.stringify(value); }

/**
 * Forward-evolving HMAC audit writer. The supplied store MUST provide a
 * durable read() and atomic commit(expectedVersion, nextState, record). The
 * commit must persist the record and advance the ratchet state in one
 * transaction. This is not a WORM store; external retention/anchoring remains
 * necessary, and compromise of the signing key can forge historical evidence.
 */
export function createAuditRatchet({ store, signingPrivateKey, initialKey, maxRetries = 8 } = {}) {
  if (!store || typeof store.read !== 'function' || typeof store.commit !== 'function') throw new TypeError('A durable store with read and atomic commit is required');
  if (!signingPrivateKey || !Buffer.isBuffer(initialKey) || initialKey.length !== 32) throw new TypeError('Ed25519 signing private key and 32-byte initial ratchet key are required');
  const appendEvent = async (event) => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('Audit event must be an object');
    for (let attempt = 0; attempt < Math.min(32, Math.max(1, maxRetries)); attempt++) {
      const current = await store.read();
      const sequence = Number(current?.sequence || 0) + 1;
      const priorKey = current?.key ? Buffer.from(current.key, 'base64') : Buffer.from(initialKey);
      if (priorKey.length < 32 || !Number.isSafeInteger(sequence)) throw new Error('AUDIT_RATCHET_STATE_INVALID');
      const nextKey = createHash('sha256').update(priorKey).update('arix-ratchet-v3').digest();
      const entry = { schema: 'arix.audit-ratchet.v1', sequence, previousHash: current?.headHash || null, at: Date.now(), event };
      const payload = Buffer.from(canonical(entry));
      if (payload.length > 64 * 1024) { priorKey.fill(0); throw new RangeError('AUDIT_EVENT_SIZE_LIMIT'); }
      const mac = createHmac('sha256', nextKey).update(payload).digest('hex');
      const hash = createHash('sha256').update(payload).update(mac).digest('hex');
      const signature = sign(null, Buffer.from(`${hash}:${sequence}`), signingPrivateKey).toString('base64url');
      const record = Object.freeze({ ...entry, mac, hash, signature });
      let committed = false;
      try { committed = await store.commit(current?.version ?? null, { version: sequence, sequence, key: nextKey.toString('base64'), headHash: hash }, record); }
      finally { priorKey.fill(0); nextKey.fill(0); }
      if (committed) return record;
    }
    throw new Error('AUDIT_RATCHET_CONCURRENCY_RETRY_EXHAUSTED');
  };
  return Object.freeze({ append: appendEvent });
}

export function verifyAuditRatchetRecords(records, publicKey) {
  if (!Array.isArray(records) || !publicKey) return { valid: false, reason: 'INVALID_INPUT' };
  let previousHash = null;
  for (let i = 0; i < records.length; i++) {
    const { mac, hash, signature, ...entry } = records[i] || {};
    if (entry.schema !== 'arix.audit-ratchet.v1' || entry.sequence !== i + 1 || entry.previousHash !== previousHash) return { valid: false, index: i, reason: 'CHAIN_MISMATCH' };
    const payload = Buffer.from(canonical(entry));
    const expectedHash = createHash('sha256').update(payload).update(String(mac)).digest('hex');
    if (expectedHash !== hash) return { valid: false, index: i, reason: 'ENTRY_HASH_MISMATCH' };
    try { if (!verify(null, Buffer.from(`${hash}:${entry.sequence}`), publicKey, Buffer.from(signature || '', 'base64url'))) return { valid: false, index: i, reason: 'SIGNATURE_INVALID' }; }
    catch { return { valid: false, index: i, reason: 'SIGNATURE_INVALID' }; }
    previousHash = hash;
  }
  return { valid: true, count: records.length, headHash: previousHash };
}

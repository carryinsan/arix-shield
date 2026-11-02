import { createHash, sign, verify } from 'node:crypto';

export function computeAttackSimHash(event = {}) {
  const features = [
    `route:${String(event.normalizedRoute || event.route || '/').slice(0, 256)}`,
    `method:${String(event.method || 'GET').toUpperCase().slice(0, 8)}`,
    ...(Array.isArray(event.findingCategories) ? event.findingCategories.slice(0, 32).map((v) => `finding:${String(v).slice(0, 64)}`) : []),
    `headers:${String(event.headerFingerprint || '').slice(0, 128)}`,
    `ja4:${String(event.ja4 || '').slice(0, 128)}`,
    `asn:${String(event.asn || '').slice(0, 32)}`
  ];
  const weights = new Int32Array(64);
  for (const feature of features) {
    const digest = createHash('sha256').update(feature).digest();
    const weight = feature.startsWith('finding:') ? 2 : 1;
    for (let bit = 0; bit < 64; bit++) weights[bit] += (digest[bit >> 3] & (1 << (bit & 7))) ? weight : -weight;
  }
  let result = 0n;
  for (let bit = 0; bit < 64; bit++) if (weights[bit] >= 0) result |= 1n << BigInt(bit);
  return result.toString(16).padStart(16, '0');
}

export function hammingDistance64(left, right) {
  if (!/^[a-f0-9]{16}$/i.test(String(left)) || !/^[a-f0-9]{16}$/i.test(String(right))) throw new TypeError('SimHash values must be 16 hexadecimal characters');
  let value = BigInt(`0x${left}`) ^ BigInt(`0x${right}`);
  let count = 0;
  while (value) { value &= value - 1n; count++; }
  return count;
}

export function clusterAttackCampaign(hash, candidates = [], { maxDistance = 3, limit = 1000 } = {}) {
  if (!/^[a-f0-9]{16}$/i.test(String(hash)) || !Array.isArray(candidates)) throw new TypeError('Invalid SimHash or candidate list');
  return candidates.slice(0, limit).map((candidate) => ({ candidate, distance: hammingDistance64(hash, candidate.hash) })).filter((item) => item.distance <= maxDistance).sort((a, b) => a.distance - b.distance);
}

export function signThreatFeedManifest({ name, fetchedAt = Date.now(), expiresAt, cidrs = [], privateKey } = {}) {
  if (!name || !Number.isFinite(expiresAt) || expiresAt <= fetchedAt || !Array.isArray(cidrs) || !privateKey) throw new TypeError('Feed manifest fields and privateKey are required');
  const normalized = [...new Set(cidrs.map(String))].sort();
  const manifest = { schema: 'arix.threat-feed.v1', name: String(name).slice(0, 128), fetchedAt, expiresAt, sourceCount: normalized.length, cidrSha256: createHash('sha256').update(JSON.stringify(normalized)).digest('hex') };
  const payload = Buffer.from(JSON.stringify(manifest));
  return Object.freeze({ ...manifest, signature: sign(null, payload, privateKey).toString('base64url') });
}

export function verifyThreatFeedManifest(manifest, cidrs, publicKey, { now = Date.now() } = {}) {
  if (!manifest || manifest.schema !== 'arix.threat-feed.v1' || !Array.isArray(cidrs) || !publicKey || !Number.isFinite(manifest.expiresAt) || manifest.expiresAt < now || manifest.fetchedAt > now + 60_000) return false;
  const normalized = [...new Set(cidrs.map(String))].sort();
  const expected = createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
  if (manifest.sourceCount !== normalized.length || manifest.cidrSha256 !== expected) return false;
  const { signature, ...payload } = manifest;
  try { return verify(null, Buffer.from(JSON.stringify(payload)), publicKey, Buffer.from(signature, 'base64url')); } catch { return false; }
}

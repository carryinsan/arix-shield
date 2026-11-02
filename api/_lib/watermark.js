import { randomToken, base64urlEncode, base64urlDecode, hmacSha256, getMasterSecret, constantTimeEqual, sha256Hex } from './crypto-trap.js';
import { getJson, setJson, getString, setString } from './redis.js';

const START = '\u200D\u200D';
const ZERO = '\u200B';
const ONE = '\u200C';
const END = '\u200D\u200D\u200D';
const RECORD_TTL_SECONDS = 60 * 60 * 24 * 90;
const STRUCTURAL_BITS = 96;
const PERMUTATIONS = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
const TIMESTAMP_FIELD = /created|updated|modified|issued|verified|timestamp|date|dob|birth/i;

function bytesToZeroWidth(bytes) {
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  return START + bits.replaceAll('0', ZERO).replaceAll('1', ONE) + END;
}

function zeroWidthToBytes(text) {
  const start = text.indexOf(START);
  if (start < 0) return null;
  const from = start + START.length;
  const end = text.indexOf(END, from);
  if (end < 0) return null;
  const encoded = text.slice(from, end);
  if (!encoded.length || encoded.length % 8 !== 0 || /[^\u200B\u200C]/.test(encoded)) return null;
  const bits = encoded.replaceAll(ZERO, '0').replaceAll(ONE, '1');
  const bytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return bytes;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function isoTimestamp(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value);
}

function bitString(bytes) {
  return [...bytes].map((byte) => byte.toString(2).padStart(8, '0')).join('');
}

function structuralDescriptors(data) {
  const descriptors = [];
  for (let rowIndex = 0; rowIndex < data.length; rowIndex++) {
    const row = data[rowIndex];
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const keys = Object.keys(row);
    const timestampKeys = keys.filter((key) => TIMESTAMP_FIELD.test(key.replace(/-/g, '_')) && isoTimestamp(row[key])).sort();
    for (const key of timestampKeys) descriptors.push({ kind: 'timestamp', rowIndex, key, width: 9 });
    const stableKeys = keys.filter((key) => !/^(?:0|[1-9]\d*)$/.test(key)).sort().slice(0, 3);
    if (stableKeys.length === 3) descriptors.push({ kind: 'permutation', rowIndex, keys: stableKeys, width: 2 });
  }
  return descriptors;
}

function rewriteKeyOrder(row, sortedKeys, rank) {
  const permutation = PERMUTATIONS[rank];
  const selected = new Set(sortedKeys);
  const orderedKeys = permutation.map((index) => sortedKeys[index]).concat(Object.keys(row).filter((key) => !selected.has(key)));
  const reordered = {};
  for (const key of orderedKeys) Object.defineProperty(reordered, key, { value: row[key], enumerable: true, configurable: true, writable: true });
  return reordered;
}

/**
 * Adds a 96-bit structural watermark only when the supplied record schema has
 * sufficient independent timestamp/key-order capacity. JSON values and schema
 * keys are preserved; object key ordering and timestamp milliseconds carry bits.
 */
function encodeStructuralWatermark(payload, marker) {
  const bytes = zeroWidthToBytes(marker);
  if (!bytes || bytes.length !== 21 || !Array.isArray(payload?.data)) return payload;
  const data = payload.data;
  const descriptors = structuralDescriptors(data);
  if (descriptors.reduce((sum, item) => sum + item.width, 0) < STRUCTURAL_BITS) return payload;
  const bits = bitString(bytes.slice(9));
  let offset = 0;
  for (const item of descriptors) {
    if (offset >= STRUCTURAL_BITS) break;
    const width = item.width;
    const code = parseInt(bits.slice(offset, offset + width), 2);
    offset += width;
    if (item.kind === 'timestamp') {
      const old = data[item.rowIndex][item.key];
      const next = String(code).padStart(3, '0');
      data[item.rowIndex][item.key] = `${old.replace(/(?:\.\d{1,9})?Z$/, '')}.${next}Z`;
    } else {
      data[item.rowIndex] = rewriteKeyOrder(data[item.rowIndex], item.keys, code);
    }
  }
  return payload;
}

function decodeStructuralSignature(leakedText) {
  let parsed;
  try { parsed = JSON.parse(leakedText); } catch { return null; }
  if (!Array.isArray(parsed?.data)) return null;
  const bits = [];
  for (const item of structuralDescriptors(parsed.data)) {
    if (bits.length >= STRUCTURAL_BITS) break;
    const row = parsed.data[item.rowIndex];
    if (item.kind === 'timestamp') {
      const match = String(row[item.key]).match(/\.(\d{1,3})Z$/);
      if (!match) continue;
      bits.push((Number(match[1]) % 512).toString(2).padStart(9, '0'));
    } else {
      const current = Object.keys(row).filter((key) => item.keys.includes(key));
      const rank = PERMUTATIONS.findIndex((permutation) => permutation.every((index, slot) => current[slot] === item.keys[index]));
      if (rank < 0 || rank > 3) continue;
      bits.push(rank.toString(2).padStart(2, '0'));
    }
  }
  const joined = bits.join('').slice(0, STRUCTURAL_BITS);
  if (joined.length !== STRUCTURAL_BITS) return null;
  const bytes = new Uint8Array(12);
  for (let index = 0; index < bytes.length; index++) bytes[index] = parseInt(joined.slice(index * 8, index * 8 + 8), 2);
  return bytes;
}

async function resolveWatermark(projectId, id, signature) {
  if (!/^[A-Za-z0-9_-]{12}$/.test(String(id || ''))) return { found: false, reason: 'INVALID_WATERMARK' };
  const expected = (await hmacSha256(getMasterSecret(), `${projectId}:${id}`)).slice(0, 12);
  if (!constantTimeEqual(expected, signature)) return { found: false, reason: 'SIGNATURE_MISMATCH' };
  const record = await getJson(`arix:watermark:${projectId}:${id}`);
  if (!record) return { found: true, attributed: false, attributionId: id, reason: 'ATTRIBUTION_RECORD_EXPIRED_OR_UNAVAILABLE' };
  return { found: true, attributed: true, ...record };
}

export async function createInvisibleWatermarkMarker(context) {
  if (!context?.projectId || !context?.sessionId) throw new Error('Watermark context requires projectId and sessionId.');
  const projectId = String(context.projectId).slice(0, 80);
  const sessionId = String(context.sessionId).slice(0, 100);
  const sessionIdHash = await sha256Hex(`${projectId}:${sessionId}`);
  const sessionKey = `arix:watermark-session:${projectId}:${sessionIdHash}`;
  const cached = await getJson(sessionKey);
  if (typeof cached?.marker === 'string') return cached.marker;

  const id = randomToken(9);
  const signature = (await hmacSha256(getMasterSecret(), `${projectId}:${id}`)).slice(0, 12);
  const token = concatBytes(base64urlDecode(id), signature);
  const marker = bytesToZeroWidth(token);
  const record = {
    projectId, sessionIdHash, sessionId,
    userId: String(context.userId ?? 'anonymous').slice(0, 100),
    ip: String(context.ip ?? 'unavailable').slice(0, 64),
    timestamp: new Date().toISOString(), attributionId: id
  };
  await setJson(`arix:watermark:${projectId}:${id}`, record, RECORD_TTL_SECONDS);
  await setJson(`arix:watermark-structural:${projectId}:${base64urlEncode(signature)}`, { id }, RECORD_TTL_SECONDS);
  const inserted = await setJson(sessionKey, { marker, attributionId: id }, RECORD_TTL_SECONDS, true);
  if (inserted === 'OK') return marker;
  const winner = await getJson(sessionKey);
  return typeof winner?.marker === 'string' ? winner.marker : marker;
}

export function insertInvisibleWatermarkMarker(text, marker) {
  if (typeof text !== 'string' || text.length > 100000) throw new Error('Watermark text must be a string of at most 100 KB.');
  if (typeof marker !== 'string' || marker.length > 1000 || !marker.startsWith(START) || !marker.endsWith(END)) throw new Error('Invalid invisible watermark marker.');
  return text.length > 1 ? `${text[0]}${marker}${text.slice(1)}` : `${text}${marker}`;
}

const SAFE_TEXT_FIELDS = new Set(['title', 'description', 'notes', 'message', 'summary', 'comment', 'bio', 'label', 'content']);

/** Watermark display text plus independent structural metadata where the schema permits it. */
export function watermarkPayloadWithMarker(payload, marker) {
  if (!payload || typeof payload !== 'object') return payload;
  const copy = encodeStructuralWatermark(structuredClone(payload), marker);
  const visit = (value, depth = 0, fieldName = '') => {
    if (depth > 12 || value == null) return { value, done: false };
    const normalizedField = String(fieldName).replace(/[_-]/g, '').toLowerCase();
    if (typeof value === 'string' && SAFE_TEXT_FIELDS.has(normalizedField) && value.length > 0 && value.length <= 100000) {
      return { value: insertInvisibleWatermarkMarker(value, marker), done: true };
    }
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) {
        const result = visit(value[index], depth + 1, fieldName);
        value[index] = result.value;
        if (result.done) return { value, done: true };
      }
      return { value, done: false };
    }
    if (typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        const result = visit(child, depth + 1, key);
        value[key] = result.value;
        if (result.done) return { value, done: true };
      }
    }
    return { value, done: false };
  };
  return visit(copy).value;
}

export async function embedInvisibleWatermark(text, context) {
  return insertInvisibleWatermarkMarker(text, await createInvisibleWatermarkMarker(context));
}

export async function decodeInvisibleWatermark(leakedText, projectId) {
  if (typeof leakedText !== 'string' || leakedText.length > 250000) throw new Error('Leaked text must be a string of at most 250 KB.');
  const bytes = zeroWidthToBytes(leakedText);
  if (bytes?.length === 21) {
    let id;
    try { id = base64urlEncode(bytes.slice(0, 9)); }
    catch { return { found: false, reason: 'INVALID_WATERMARK' }; }
    if (!/^[A-Za-z0-9_-]{12}$/.test(id)) return { found: false, reason: 'INVALID_WATERMARK' };
    return resolveWatermark(projectId, id, bytes.slice(9));
  }

  const signature = decodeStructuralSignature(leakedText);
  if (!signature) return { found: false, reason: 'NO_VALID_WATERMARK' };
  const structuralKey = `arix:watermark-structural:${projectId}:${base64urlEncode(signature)}`;
  const mapping = await getJson(structuralKey);
  if (!mapping?.id) return { found: false, reason: 'STRUCTURAL_SIGNATURE_NOT_RECOGNIZED' };
  const result = await resolveWatermark(projectId, mapping.id, signature);
  return result.found ? { ...result, channel: 'structural' } : result;
}

export async function watermarkJson(payload, context) {
  if (!payload || typeof payload !== 'object') return payload;
  return watermarkPayloadWithMarker(payload, await createInvisibleWatermarkMarker(context));
}

function deterministicCanaryValue(key, template, canaryId, depth = 0) {
  if (depth > 8 || template === null) return null;
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  const hex = canaryId;
  if (Array.isArray(template)) return template.slice(0, 4).map((value, index) => deterministicCanaryValue(`${key}${index}`, value, canaryId, depth + 1));
  if (typeof template === 'object') {
    const output = {};
    for (const [childKey, value] of Object.entries(template)) Object.defineProperty(output, childKey, { value: deterministicCanaryValue(childKey, value, canaryId, depth + 1), enumerable: true, configurable: true, writable: true });
    return output;
  }
  if (normalized === 'id' || normalized === '_id' || normalized === 'uuid' || normalized.endsWith('id')) {
    if (typeof template === 'number') return Number(8000000000000000n + (BigInt(`0x${hex}`) % 1000000000000000n));
    if (typeof template === 'string' && /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(template)) {
      const uuid = `${hex}${hex.slice(0, 8)}`;
      return `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-4${uuid.slice(13, 16)}-8${uuid.slice(17, 20)}-${uuid.slice(20, 32)}`;
    }
    if (typeof template === 'string' && /^\d+$/.test(template)) return String(8000000000000000n + (BigInt(`0x${hex}`) % 1000000000000000n));
    return hex;
  }
  if (typeof template === 'number') return Number.isInteger(template) ? Number(BigInt(`0x${hex.slice(0, 10)}`) % 1000000n) + 1 : Number((Number(BigInt(`0x${hex.slice(0, 10)}`) % 1000000n) / 100).toFixed(2));
  if (typeof template === 'boolean') return /active|enabled|verified|valid/i.test(normalized);
  if (typeof template !== 'string') return template;
  if (normalized.includes('email')) return `contact+${hex.slice(0, 10)}@example.org`;
  if (/(?:phone|mobile|telephone|cell)/.test(normalized)) return `+1-202-555-01${String(parseInt(hex.slice(0, 2), 16) % 100).padStart(2, '0')}`;
  if (normalized === 'name' || normalized.endsWith('fullname') || normalized === 'displayname') return 'Jordan Ellis';
  if (normalized === 'firstname' || normalized === 'givenname') return 'Jordan';
  if (normalized === 'lastname' || normalized === 'surname' || normalized === 'familyname') return 'Ellis';
  if (normalized.includes('company') || normalized.includes('organization')) return 'Northstar Meridian Group';
  if (normalized.includes('address')) return '4100 Meridian Avenue';
  if (/(?:created|updated|modified|issued|verified|timestamp|date|dob|birth)/.test(normalized) && isoTimestamp(template)) return `2025-06-15T10:24:${String(parseInt(hex.slice(4, 6), 16) % 60).padStart(2, '0')}.${String(parseInt(hex.slice(6, 8), 16) % 512).padStart(3, '0')}Z`;
  if (/(?:token|secret|credential|password|apikey|auth)/.test(normalized)) return hex.repeat(Math.ceil(template.length / hex.length)).slice(0, Math.max(12, Math.min(128, template.length)));
  if (/^(?:status|state|role|type|category)$/.test(normalized)) return 'standard';
  if (template.length === 0) return '';
  return 'Standard';
}

/** A tenant/session deterministic, non-obvious identifier for a schema-cloned chameleon row. */
export async function createChameleonCanaryId(projectId, sessionId) {
  const digest = await hmacSha256(getMasterSecret(), `arix:chameleon:v1:${String(projectId).slice(0, 80)}:${String(sessionId).slice(0, 100)}`);
  return Buffer.from(digest.slice(0, 12)).toString('hex');
}

export async function storeChameleonCanary(projectId, canaryId, attribution = {}) {
  if (!/^[a-f0-9]{24}$/.test(String(canaryId || ''))) throw new TypeError('Invalid chameleon record identifier.');
  await setJson(`arix:chameleon:${projectId}:${canaryId}`, {
    projectId: String(projectId).slice(0, 80), canaryId,
    sessionIdHash: String(attribution.sessionIdHash || '').slice(0, 64),
    userId: String(attribution.userId || 'anonymous').slice(0, 100),
    ip: String(attribution.ip || 'unavailable').slice(0, 64),
    timestamp: new Date().toISOString()
  }, RECORD_TTL_SECONDS);
}

export async function lookupChameleonCanary(projectId, canaryId) {
  if (!/^[a-f0-9]{24}$/.test(String(canaryId || ''))) return null;
  return getJson(`arix:chameleon:${projectId}:${canaryId}`);
}

export async function storeChameleonExposedId(projectId, canaryId, exposedId) {
  const value = String(exposedId ?? '');
  if (!/^[a-f0-9]{24}$/.test(String(canaryId || '')) || !value || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError('Invalid exposed chameleon identifier.');
  const attribution = await lookupChameleonCanary(projectId, canaryId);
  if (!attribution) throw new Error('Chameleon attribution record is missing; refusing to register an exposed identifier.');
  const key = await sha256Hex(`${String(projectId)}:${value}`);
  await setString(`arix:chameleon-exposed:${projectId}:${key}`, String(canaryId), RECORD_TTL_SECONDS);
  return true;
}

export async function lookupChameleonCanaryByExposedId(projectId, exposedId) {
  const value = String(exposedId ?? '');
  if (!value || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) return null;
  const key = await sha256Hex(`${String(projectId)}:${value}`);
  const canaryId = await getString(`arix:chameleon-exposed:${projectId}:${key}`);
  return canaryId ? lookupChameleonCanary(projectId, canaryId) : null;
}

export function getChameleonRowIdentifier(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  const entries = Object.entries(row);
  const candidates = entries.filter(([key, value]) => value !== null && ['string', 'number'].includes(typeof value) && /^(?:id|_id|uuid)$/i.test(key));
  const fallback = entries.filter(([key, value]) => value !== null && ['string', 'number'].includes(typeof value) && /id$/i.test(key));
  const entry = candidates[0] || fallback[0];
  return entry ? { key: entry[0], value: entry[1] } : null;
}

/** Insert a structure-cloned record without adding schema keys or tell-tale marker fields. */
export async function spliceCanaryRow(payload, context, enabled = false, suppliedCanaryId = null) {
  if (!enabled || !payload || typeof payload !== 'object' || !Array.isArray(payload.data) || payload.data.length < 10) return payload;
  if (!/^[a-f0-9]{24}$/.test(String(suppliedCanaryId || ''))) return payload;
  const output = structuredClone(payload);
  const template = output.data[0];
  if (!template || typeof template !== 'object' || Array.isArray(template) || !getChameleonRowIdentifier(template)) return payload;
  const cloned = {};
  for (const [key, value] of Object.entries(template)) Object.defineProperty(cloned, key, { value: deterministicCanaryValue(key, value, suppliedCanaryId), enumerable: true, configurable: true, writable: true });
  const identifier = getChameleonRowIdentifier(cloned);
  if (!identifier) return payload;
  output.data.splice(Math.floor(output.data.length / 2), 0, cloned);
  return output;
}

export function stripInvisibleWatermark(text) {
  return String(text).replace(/\u200D\u200D[\u200B\u200C]+\u200D\u200D\u200D/g, '');
}

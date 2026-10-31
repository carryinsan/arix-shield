import { randomToken, base64urlEncode, base64urlDecode, hmacSha256, getMasterSecret, constantTimeEqual } from './crypto-trap.js';
import { getJson, setJson } from './redis.js';

const START = '\u200D\u200D';
const ZERO = '\u200B';
const ONE = '\u200C';
const END = '\u200D\u200D\u200D';
const RECORD_TTL_SECONDS = 60 * 60 * 24 * 90;

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

export async function embedInvisibleWatermark(text, context) {
  if (typeof text !== 'string' || text.length > 100000) throw new Error('Watermark text must be a string of at most 100 KB.');
  if (!context?.projectId || !context?.sessionId) throw new Error('Watermark context requires projectId and sessionId.');
  const id = randomToken(9);
  const signature = (await hmacSha256(getMasterSecret(), `${context.projectId}:${id}`)).slice(0, 12);
  const token = concatBytes(base64urlDecode(id), signature);
  await setJson(`arix:watermark:${context.projectId}:${id}`, {
    projectId: context.projectId,
    sessionId: String(context.sessionId).slice(0, 100),
    userId: String(context.userId ?? 'anonymous').slice(0, 100),
    ip: String(context.ip ?? 'unavailable').slice(0, 64),
    timestamp: new Date().toISOString(),
    attributionId: id
  }, RECORD_TTL_SECONDS);
  const marker = bytesToZeroWidth(token);
  return text.length > 1 ? `${text[0]}${marker}${text.slice(1)}` : `${text}${marker}`;
}

export async function decodeInvisibleWatermark(leakedText, projectId) {
  if (typeof leakedText !== 'string' || leakedText.length > 250000) throw new Error('Leaked text must be a string of at most 250 KB.');
  const bytes = zeroWidthToBytes(leakedText);
  if (!bytes || bytes.length !== 21) return { found: false, reason: 'NO_VALID_WATERMARK' };
  let id;
  try { id = base64urlEncode(bytes.slice(0, 9)); }
  catch { return { found: false, reason: 'INVALID_WATERMARK' }; }
  if (!/^[A-Za-z0-9_-]{12}$/.test(id)) return { found: false, reason: 'INVALID_WATERMARK' };
  const expected = (await hmacSha256(getMasterSecret(), `${projectId}:${id}`)).slice(0, 12);
  if (!constantTimeEqual(expected, bytes.slice(9))) return { found: false, reason: 'SIGNATURE_MISMATCH' };
  const record = await getJson(`arix:watermark:${projectId}:${id}`);
  if (!record) return { found: true, attributed: false, attributionId: id, reason: 'ATTRIBUTION_RECORD_EXPIRED_OR_UNAVAILABLE' };
  return { found: true, attributed: true, ...record };
}

export async function watermarkJson(payload, context) {
  if (!payload || typeof payload !== 'object') return payload;
  const copy = structuredClone(payload);
  let changed = false;
  const visit = async (value, depth = 0) => {
    if (changed || depth > 12 || value == null) return;
    if (typeof value === 'string') {
      if (value.length > 0 && value.length <= 100000) {
        const marked = await embedInvisibleWatermark(value, context);
        changed = true;
        return marked;
      }
      return value;
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length && !changed; i++) value[i] = await visit(value[i], depth + 1);
      return value;
    }
    if (typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        if (changed) break;
        value[key] = await visit(child, depth + 1);
      }
    }
    return value;
  };
  await visit(copy);
  return copy;
}

export async function spliceCanaryRow(payload, context, enabled = false) {
  if (!enabled || !payload || typeof payload !== 'object' || !Array.isArray(payload.data) || payload.data.length < 10) return payload;
  const canaryId = randomToken(6);
  const canaryKey = `ARIX_CANARY_${canaryId}`;
  // Store a one-way detector mapping. The canary is visibly synthetic and has no external beacon URL.
  const { hashCredential } = await import('./crypto-trap.js');
  const hash = await hashCredential(canaryKey);
  await setJson(`arix:key:${hash}`, { projectId: context.projectId, type: 'canary', createdAt: Date.now() }, RECORD_TTL_SECONDS);
  const index = Math.floor(payload.data.length / 2);
  payload.data.splice(index, 0, {
    id: `arix_canary_${canaryId}`,
    name: 'ArixShield Canary Record (synthetic)',
    email: `canary-${canaryId}@example.invalid`,
    canary_api_key: canaryKey,
    synthetic: true
  });
  return payload;
}

export function stripInvisibleWatermark(text) {
  return String(text).replace(/\u200D\u200D[\u200B\u200C]+\u200D\u200D\u200D/g, '');
}

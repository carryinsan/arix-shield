import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

function normalizeCode(value) { return String(value || '').toUpperCase().replace(/[^A-F0-9]/g, ''); }
function digestCode(code, salt) { return createHash('sha256').update(salt).update(code, 'utf8').digest(); }

/** Generate eight independent 128-bit single-use MFA recovery codes. */
export function generateMfaRecoveryCodes({ count = 8 } = {}) {
  if (!Number.isInteger(count) || count < 1 || count > 16) throw new RangeError('Recovery code count must be between 1 and 16');
  const codes = [];
  const hashes = [];
  for (let index = 0; index < count; index++) {
    const raw = randomBytes(16).toString('hex').toUpperCase();
    const code = raw.match(/.{1,8}/g).join('-');
    const salt = randomBytes(16);
    codes.push(code);
    hashes.push(Object.freeze({ salt: salt.toString('base64url'), digest: digestCode(raw, salt).toString('base64url') }));
  }
  return Object.freeze({ codes: Object.freeze(codes), hashes: Object.freeze(hashes) });
}

/**
 * Verify a code and atomically consume its stored digest. consumeDigest must be
 * implemented with a single database/Redis transaction or compare-and-delete.
 */
export async function consumeMfaRecoveryCode(code, { hashes, consumeDigest } = {}) {
  if (!Array.isArray(hashes) || hashes.length > 16 || typeof consumeDigest !== 'function') throw new TypeError('Stored hashes and atomic consumeDigest callback are required');
  const normalized = normalizeCode(code);
  if (!/^[A-F0-9]{32}$/.test(normalized)) return { valid: false, reason: 'INVALID_CODE' };
  let matched = null;
  for (const record of hashes) {
    let salt; let expected;
    try { salt = Buffer.from(record.salt, 'base64url'); expected = Buffer.from(record.digest, 'base64url'); } catch { continue; }
    if (salt.length !== 16 || expected.length !== 32) continue;
    const actual = digestCode(normalized, salt);
    if (timingSafeEqual(actual, expected)) matched = record.digest;
    actual.fill(0);
  }
  if (!matched) return { valid: false, reason: 'INVALID_CODE' };
  const consumed = await consumeDigest(matched);
  return consumed ? { valid: true } : { valid: false, reason: 'ALREADY_USED' };
}

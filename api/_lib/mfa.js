import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { getMasterSecret, randomToken } from './crypto-trap.js';

function encryptionKey() {
  return createHmac('sha256', getMasterSecret()).update('arixshield:totp-secret:v1').digest();
}

function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0; let value = 0; let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const input = String(value || '').replace(/=+$/g, '').toUpperCase();
  let bits = 0; let buffer = 0; const bytes = [];
  for (const character of input) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error('Invalid base32 TOTP secret.');
    buffer = (buffer << 5) | digit; bits += 5;
    if (bits >= 8) { bytes.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}

export function generateTotpSecret() {
  const secret = base32Encode(randomBytes(20));
  return { secret, encrypted: encryptTotpSecret(secret) };
}

export function encryptTotpSecret(secret) {
  if (typeof secret !== 'string' || secret.length < 16 || secret.length > 128) throw new TypeError('Invalid TOTP secret.');
  const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return { version: 1, iv: iv.toString('base64url'), ciphertext: ciphertext.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
}

export function decryptTotpSecret(record) {
  if (!record || record.version !== 1 || typeof record.iv !== 'string' || typeof record.ciphertext !== 'string' || typeof record.tag !== 'string') throw new Error('Stored TOTP secret is invalid.');
  const iv = Buffer.from(record.iv, 'base64url'); const ciphertext = Buffer.from(record.ciphertext, 'base64url'); const tag = Buffer.from(record.tag, 'base64url');
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length < 8 || ciphertext.length > 128) throw new Error('Stored TOTP secret is invalid.');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), iv); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function codeAt(secret, counter) {
  const key = base32Decode(secret); const message = Buffer.alloc(8); message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(message).digest(); const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, '0');
}

export function matchTotpCounter(secret, suppliedCode, { now = Date.now(), window = 1 } = {}) {
  const code = String(suppliedCode || '');
  if (!/^\d{6}$/.test(code) || typeof secret !== 'string') return null;
  const counter = Math.floor(now / 30000); const tolerance = Math.max(0, Math.min(2, Number(window) || 0));
  let match = null;
  for (let offset = -tolerance; offset <= tolerance; offset++) {
    const candidate = counter + offset;
    if (candidate < 0) continue;
    const expected = Buffer.from(codeAt(secret, candidate)); const actual = Buffer.from(code);
    if (expected.length === actual.length && timingSafeEqual(expected, actual) && (match === null || Math.abs(offset) < Math.abs(match - counter))) match = candidate;
  }
  return match;
}

export function verifyTotp(secret, suppliedCode, options = {}) {
  return matchTotpCounter(secret, suppliedCode, options) !== null;
}

export function totpProvisioningUri(secret, accountName) {
  const label = `ArixShield:${String(accountName || 'account').slice(0, 180)}`;
  const query = new URLSearchParams({ secret, issuer: 'ArixShield', algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${encodeURIComponent(label)}?${query}`;
}

export function generateLoginPowSolutionDigest(nonce, solution) {
  return createHmac('sha256', 'arixshield-login-pow-v1').update(`${nonce}:${solution}`).digest('hex');
}

export function makeMfaChallengeNonce() { return randomToken(24); }

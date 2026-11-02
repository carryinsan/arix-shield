import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const enc = (value) => Buffer.from(value).toString('base64url');
const dec = (value) => Buffer.from(String(value), 'base64url');

export function derivePurposeKey(masterKey, purpose, contextId = '') {
  const key = Buffer.isBuffer(masterKey) ? masterKey : Buffer.from(String(masterKey || ''), 'utf8');
  if (key.length < 32) throw new TypeError('KMS master key must contain at least 32 bytes');
  if (!/^[a-z0-9._:-]{1,96}$/i.test(String(purpose)) || String(contextId).length > 256) throw new TypeError('Invalid KMS purpose or context');
  return Buffer.from(hkdfSync('sha256', key, Buffer.from('arix-kms-v3'), Buffer.from(`arix-kms-v3:${purpose}:${contextId}`), 32));
}

export function createTenantDek() { return randomBytes(32); }

function encryptAesGcm(key, plaintext, aad) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: enc(iv), ciphertext: enc(ciphertext), tag: enc(cipher.getAuthTag()) };
}

function decryptAesGcm(key, envelope, aad) {
  const decipher = createDecipheriv(ALGORITHM, key, dec(envelope.iv));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(dec(envelope.tag));
  return Buffer.concat([decipher.update(dec(envelope.ciphertext)), decipher.final()]);
}

function requireKek(keks, version) {
  const key = keks?.[version];
  const bytes = Buffer.isBuffer(key) ? key : Buffer.from(String(key || ''), 'base64');
  if (bytes.length !== 32) throw new TypeError(`KEK ${version} must be exactly 32 bytes`);
  return bytes;
}

export function wrapTenantDek(dek, { tenantId, kekVersion, keks } = {}) {
  if (!Buffer.isBuffer(dek) || dek.length !== 32 || !tenantId || !kekVersion) throw new TypeError('A 32-byte DEK, tenantId and kekVersion are required');
  const aad = `arix-tenant-dek:v1:${tenantId}:${kekVersion}`;
  return Object.freeze({ schema: 'arix.dek-envelope.v1', tenantId: String(tenantId), kekVersion: String(kekVersion), ...encryptAesGcm(requireKek(keks, kekVersion), dek, aad) });
}

export function unwrapTenantDek(envelope, { keks, tenantId } = {}) {
  if (!envelope || envelope.schema !== 'arix.dek-envelope.v1' || String(tenantId) !== envelope.tenantId) throw new Error('KMS_ENVELOPE_SCOPE_MISMATCH');
  return decryptAesGcm(requireKek(keks, envelope.kekVersion), envelope, `arix-tenant-dek:v1:${envelope.tenantId}:${envelope.kekVersion}`);
}

export function rewrapTenantDek(envelope, { keks, tenantId, newKekVersion } = {}) {
  const dek = unwrapTenantDek(envelope, { keks, tenantId });
  try { return wrapTenantDek(dek, { tenantId, kekVersion: newKekVersion, keks }); }
  finally { dek.fill(0); }
}

export function encryptTenantData(plaintext, { tenantId, dek, purpose = 'record' } = {}) {
  if (!tenantId || !Buffer.isBuffer(dek) || dek.length !== 32) throw new TypeError('tenantId and 32-byte DEK are required');
  const value = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext));
  const aad = `arix-tenant-data:v1:${tenantId}:${purpose}`;
  return Object.freeze({ schema: 'arix.tenant-data.v1', tenantId: String(tenantId), purpose: String(purpose), ...encryptAesGcm(dek, value, aad) });
}

export function decryptTenantData(envelope, { tenantId, dek, purpose = 'record' } = {}) {
  if (!envelope || envelope.schema !== 'arix.tenant-data.v1' || envelope.tenantId !== String(tenantId) || envelope.purpose !== String(purpose) || !Buffer.isBuffer(dek) || dek.length !== 32) throw new Error('KMS_DATA_SCOPE_MISMATCH');
  return decryptAesGcm(dek, envelope, `arix-tenant-data:v1:${tenantId}:${purpose}`);
}

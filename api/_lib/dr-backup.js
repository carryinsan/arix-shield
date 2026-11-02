import { createCipheriv, createDecipheriv, createHash, randomBytes, sign, verify } from 'node:crypto';

const b64 = (value) => Buffer.from(value).toString('base64url');

export function createDisasterRecoveryBackup(projectId, state, { encryptionKey, signingPrivateKey, createdAt = Date.now() } = {}) {
  if (!projectId || !state || typeof state !== 'object' || !Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 32 || !signingPrivateKey) throw new TypeError('projectId, state, 32-byte encryptionKey and signingPrivateKey are required');
  const payload = Buffer.from(JSON.stringify({ schema: 'arix.dr-payload.v1', projectId: String(projectId), createdAt, state }));
  if (payload.length > 10 * 1024 * 1024) throw new RangeError('DR backup exceeds 10 MiB');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
  cipher.setAAD(Buffer.from(`arix-dr:v1:${projectId}`));
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const envelope = { schema: 'arix.dr-backup.v1', projectId: String(projectId), createdAt, iv: b64(iv), tag: b64(cipher.getAuthTag()), ciphertext: b64(ciphertext), payloadSha256: createHash('sha256').update(payload).digest('hex') };
  const signed = Buffer.from(JSON.stringify(envelope));
  return Object.freeze({ ...envelope, signature: sign(null, signed, signingPrivateKey).toString('base64url') });
}

export function restoreDisasterRecoveryBackup(bundle, { projectId, encryptionKey, signingPublicKey, now = Date.now(), maxAgeMs = 365 * 24 * 60 * 60 * 1000 } = {}) {
  if (!bundle || bundle.schema !== 'arix.dr-backup.v1' || bundle.projectId !== String(projectId) || !Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 32 || !signingPublicKey) throw new Error('DR_BACKUP_SCOPE_OR_CONFIG_INVALID');
  if (!Number.isFinite(bundle.createdAt) || bundle.createdAt > now + 60_000 || now - bundle.createdAt > maxAgeMs) throw new Error('DR_BACKUP_AGE_INVALID');
  if (typeof bundle.ciphertext !== 'string' || bundle.ciphertext.length > 14 * 1024 * 1024 || typeof bundle.iv !== 'string' || bundle.iv.length > 32 || typeof bundle.tag !== 'string' || bundle.tag.length > 32 || typeof bundle.signature !== 'string' || bundle.signature.length > 256) throw new Error('DR_BACKUP_SIZE_LIMIT');
  const { signature, ...envelope } = bundle;
  if (!verify(null, Buffer.from(JSON.stringify(envelope)), signingPublicKey, Buffer.from(signature || '', 'base64url'))) throw new Error('DR_BACKUP_SIGNATURE_INVALID');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(bundle.iv, 'base64url'));
  decipher.setAAD(Buffer.from(`arix-dr:v1:${projectId}`));
  decipher.setAuthTag(Buffer.from(bundle.tag, 'base64url'));
  const payload = Buffer.concat([decipher.update(Buffer.from(bundle.ciphertext, 'base64url')), decipher.final()]);
  if (createHash('sha256').update(payload).digest('hex') !== bundle.payloadSha256) throw new Error('DR_BACKUP_PAYLOAD_HASH_INVALID');
  const parsed = JSON.parse(payload.toString('utf8'));
  if (parsed.schema !== 'arix.dr-payload.v1' || parsed.projectId !== String(projectId)) throw new Error('DR_BACKUP_PAYLOAD_SCOPE_INVALID');
  return parsed;
}

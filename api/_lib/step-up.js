import { getJson, getJsonOnce, setJson, setString } from './redis.js';
import { verifyPassword, sha256Hex } from './crypto-trap.js';
import { decryptTotpSecret, matchTotpCounter } from './mfa.js';
import { sameOriginRequest } from './http.js';
import { decodeWebAuthnBase64url, verifyWebAuthnAssertion } from './webauthn.js';

async function verifyPasskeyStepUp({ ownerId, projectId, req, challenge, credential, user }) {
  if (!req || req.method !== 'POST' || !sameOriginRequest(req)) return false;
  if (typeof challenge !== 'string' || challenge.length < 32 || challenge.length > 256 || !credential || typeof credential !== 'object') return false;
  let origin;
  try {
    origin = new URL(String(req.headers?.origin || ''));
    if ((origin.protocol !== 'https:' && !(origin.protocol === 'http:' && origin.hostname === 'localhost')) || origin.origin !== req.headers.origin) return false;
  } catch { return false; }
  const key = `arix:webauthn:challenge:${await sha256Hex(challenge)}`;
  // Challenges are atomically consumed before verification, so a failed
  // assertion cannot be replayed or raced against another sensitive action.
  const record = await getJsonOnce(key);
  if (!record || record.purpose !== 'step-up' || record.ownerId !== ownerId || record.projectId !== projectId || record.origin !== origin.origin || record.rpId !== origin.hostname || record.expiresAt < Date.now()) return false;
  let credentialId;
  try { credentialId = decodeWebAuthnBase64url(credential.rawId || credential.id, 1024).toString('base64url'); }
  catch { return false; }
  const credentials = Array.isArray(user.passkeys) ? user.passkeys : [];
  const index = credentials.findIndex((item) => item?.credentialId === credentialId);
  if (index < 0) return false;
  let assertion;
  try { assertion = verifyWebAuthnAssertion(credential, record, credentials[index], { requireUserVerification: true }); }
  catch { return false; }
  credentials[index] = { ...credentials[index], signCount: assertion.signCount, lastUsedAt: Date.now() };
  user.passkeys = credentials;
  await setJson(`arix:user:${ownerId}`, user);
  return true;
}

/**
 * Verify fresh password proof plus one enrolled second factor when present.
 * Passkey-only accounts use a one-time, origin-bound WebAuthn assertion. An
 * account with no second factor may still re-authenticate with its password;
 * unauthenticated failed-login counters are deliberately not a hard gate for
 * already-authenticated sensitive actions because an attacker can manipulate them.
 */
export async function verifyStepUpCredentials({ ownerId, projectId, password, totpCode, passkeyChallenge, passkeyCredential, req } = {}) {
  if (typeof ownerId !== 'string' || !ownerId) return { ok: false, status: 401, error: 'An authenticated account is required.' };
  const user = await getJson(`arix:user:${ownerId}`);
  if (!user) return { ok: false, status: 401, error: 'Account not found.' };
  if (typeof password !== 'string' || password.length === 0 || !await verifyPassword(password, user.password)) {
    return { ok: false, status: 401, error: 'Re-authentication failed.' };
  }

  const hasPasskeys = Array.isArray(user.passkeys) && user.passkeys.length > 0;
  const passkeyProofSupplied = passkeyChallenge !== undefined || passkeyCredential !== undefined;
  if (passkeyProofSupplied) {
    const verified = await verifyPasskeyStepUp({ ownerId, projectId, req, challenge: passkeyChallenge, credential: passkeyCredential, user });
    if (!verified) return { ok: false, status: 401, error: 'Passkey re-authentication failed or expired. Start a new verification.' };
    return { ok: true, user, factor: 'passkey' };
  }
  if (user.totpEnabled === true) {
    let secret;
    try { secret = decryptTotpSecret(user.totpSecret); }
    catch { return { ok: false, status: 503, error: 'MFA configuration is unavailable.' }; }
    const counter = matchTotpCounter(secret, totpCode);
    if (!Number.isSafeInteger(counter) || counter < 0) return { ok: false, status: 401, error: 'Authenticator re-authentication failed.' };
    const consumed = await setString(`arix:totp-used:${ownerId}:${counter}`, '1', 120, true);
    if (consumed !== 'OK') return { ok: false, status: 401, error: 'Authenticator code is invalid or has already been used.' };
    return { ok: true, user, factor: 'totp' };
  }
  if (hasPasskeys) return { ok: false, status: 428, error: 'A passkey assertion is required for this sensitive action.', stepUpRequired: true, challengeType: 'passkey' };
  return { ok: true, user, factor: 'password' };
}

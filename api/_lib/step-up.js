import { getJson, getString, setString } from './redis.js';
import { verifyPassword, sha256Hex } from './crypto-trap.js';
import { decryptTotpSecret, matchTotpCounter } from './mfa.js';
import { evaluateLoginRisk } from './identity-risk.js';

/** Verifies fresh password proof and, when enabled, a single-use TOTP proof. */
export async function verifyStepUpCredentials({ ownerId, password, totpCode } = {}) {
  if (typeof ownerId !== 'string' || !ownerId) return { ok: false, status: 401, error: 'An authenticated account is required.' };
  const user = await getJson(`arix:user:${ownerId}`);
  if (!user) return { ok: false, status: 401, error: 'Account not found.' };
  if (typeof password !== 'string' || password.length === 0 || !await verifyPassword(password, user.password)) {
    return { ok: false, status: 401, error: 'Re-authentication failed.' };
  }
  const emailHash = typeof user.email === 'string' ? await sha256Hex(user.email.toLowerCase()) : '';
  const riskFailures = Math.max(0, Math.min(5, Number(emailHash ? await getString(`arix:auth:acct-failure-count:${emailHash}`) : 0) || 0));
  const risk = evaluateLoginRisk({ failedLoginCount: riskFailures });
  if (user.totpEnabled === true) {
    let secret;
    try { secret = decryptTotpSecret(user.totpSecret); }
    catch { return { ok: false, status: 503, error: 'MFA configuration is unavailable.' }; }
    const counter = matchTotpCounter(secret, totpCode);
    if (!Number.isSafeInteger(counter) || counter < 0) return { ok: false, status: 401, error: 'Authenticator re-authentication failed.' };
    const consumed = await setString(`arix:totp-used:${ownerId}:${counter}`, '1', 120, true);
    if (consumed !== 'OK') return { ok: false, status: 401, error: 'Authenticator code is invalid or has already been used.' };
  } else if (risk.decision !== 'allow') {
    return { ok: false, status: 428, error: 'A fresh second factor is required for this sensitive action.' };
  }
  return { ok: true, user, risk };
}

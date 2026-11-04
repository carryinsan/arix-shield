import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { randomInt } from 'node:crypto';
import { sendJson, readJson, methodNotAllowed, setSessionCookie, clearSessionCookie, sameOriginRequest, normalizeOrigin, clientRateKey, trustedClientIp, trustedClientNetworkPrefix } from './_lib/http.js';
import { rateLimit, rateLimitMulti, getJson, getJsonOnce, getString, setJson, setString, compareAndSetString, compareAndDeleteString, deleteKeys, incrementWithExpiry, setMaxStringWithExpiry, advanceWebAuthnCounter } from './_lib/redis.js';
import { derivePassword, verifyPassword, randomToken, sha256Hex, hashCredential, createSignedToken, verifySignedToken, hmacSha256, constantTimeEqual, getMasterSecret } from './_lib/crypto-trap.js';
import { LEGACY_PBKDF2_ITERATIONS } from './_lib/security-constants.js';
import { createSession, getSession, listUserSessions, revokeUserSession, revokeAllUserSessions, rotateSession } from './_lib/session.js';
import { formatIpPrefix } from './_lib/cidr.js';
import { generateTotpSecret, decryptTotpSecret, matchTotpCounter, totpProvisioningUri } from './_lib/mfa.js';
import { validatePasswordPolicy } from './_lib/password-policy.js';
import { verifyStepUpCredentials } from './_lib/step-up.js';
import { evaluateLoginRisk } from './_lib/identity-risk.js';
import { verifyWebAuthnRegistration, verifyWebAuthnAssertion, decodeWebAuthnBase64url } from './_lib/webauthn.js';
import { generateMfaRecoveryCodes, consumeMfaRecoveryCode } from './_lib/recovery-codes.js';

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const SESSION_TTL = 86400;
const DUMMY_PASSWORD = Object.freeze({ salt: 'MDEyMzQ1Njc4OWFiY2RlZg', hash: 'm5zv3v3aA0-2p-2D8uZpT_Es4q4QO1Jr5FS3YxTzTYA', iterations: LEGACY_PBKDF2_ITERATIONS });

function isSecure(req) { return process.env.VERCEL === '1' || process.env.NODE_ENV === 'production' || String(req.headers?.['x-forwarded-proto'] ?? '').split(',')[0] === 'https'; }
function validName(value) { return typeof value === 'string' && value.trim().length >= 2 && value.trim().length <= 80; }

async function verifyAndConsumeTotp(ownerId, secret, code) {
  const counter = matchTotpCounter(secret, code);
  if (!Number.isSafeInteger(counter) || counter < 0) return false;
  const result = await setString(`arix:totp-used:${ownerId}:${counter}`, '1', 120, true);
  return result === 'OK';
}

const SIGNUP_VERIFICATION_TTL_SECONDS = 600;
const SIGNUP_VERIFICATION_ATTEMPTS = 5;

function emailVerificationRequired() {
  return process.env.NODE_ENV === 'production' || process.env.ARIX_REQUIRE_EMAIL_VERIFICATION === 'true';
}

function signupEmailConfig() {
  const apiKey = process.env.ARIX_RESEND_API_KEY;
  const from = process.env.ARIX_EMAIL_FROM;
  if (typeof apiKey !== 'string' || apiKey.length < 12 || apiKey.length > 512 || /[\r\n\u0000]/.test(apiKey)
    || typeof from !== 'string' || from.length < 5 || from.length > 254 || /[\r\n\u0000]/.test(from)) return null;
  return { apiKey, from };
}

async function deliverSignupVerificationEmail({ email, name, code }) {
  const config = signupEmailConfig();
  if (!config) throw Object.assign(new Error('New account registration is temporarily unavailable. Configure ARIX_RESEND_API_KEY and ARIX_EMAIL_FROM to enable email ownership verification.'), { statusCode: 503 });
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(8000),
    headers: { Authorization: `Bearer ${config.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: config.from,
      to: [email],
      subject: 'Verify your ArixShield account',
      text: `Hello ${name},\n\nYour ArixShield verification code is ${code}. It expires in 10 minutes and can be used once.\n\nIf you did not request this account, you can ignore this message.`
    })
  });
  if (!response.ok) throw Object.assign(new Error(`Email verification delivery failed (${response.status}).`), { statusCode: 503 });
}

function signupResponse(ownerId, projectId, name, email, projectName, origin, keys) {
  return {
    ok: true,
    user: { id: ownerId, name, email },
    project: { id: projectId, name: projectName, origin },
    keys,
    keyNotice: 'ARIX_LIVE is a publishable project identifier. Store ARIX_SECRET only in server-side environment variables. These credentials are shown once.'
  };
}

async function persistNewAccount(registration, req, res, { reservation = null, pendingRegistrationId = null } = {}) {
  const { email, emailHash, name, projectName, origin, passwordRecord } = registration;
  const ownerId = registration.ownerId || `usr_${randomToken(12)}`;
  const projectId = registration.projectId || `prj_${randomToken(9)}`;
  const emailIndex = `arix:user-email:${emailHash}`;

  // Reserve the address before writing any account records. In production the
  // reservation came from email verification; development uses an NX owner ID.
  if (reservation) {
    if (await getString(emailIndex) !== reservation) return sendJson(res, 409, { error: 'This verification request is no longer valid. Start registration again.' });
  } else if (await setString(emailIndex, ownerId, null, true) !== 'OK') {
    return sendJson(res, 409, { error: 'An account with this email already exists. Sign in instead.' });
  }

  const liveKey = `ARIX_LIVE_${randomToken(18)}`;
  const serverKey = `ARIX_SECRET_${randomToken(32)}`;
  const canaryKey = `ARIX_CANARY_${randomToken(18)}`;
  const recordKeys = [
    `arix:user:${ownerId}`, `arix:project:${projectId}`, `arix:owner-project:${ownerId}`,
    // Key mappings are hashed below and appended after credential derivation.
  ];
  let published = false;
  try {
    const [liveHash, serverHash, canaryHash] = await Promise.all([
      hashCredential(liveKey), hashCredential(serverKey), hashCredential(canaryKey)
    ]);
    const now = new Date().toISOString();
    const user = { id: ownerId, name, email, password: passwordRecord, emailVerified: true, emailVerifiedAt: now, createdAt: now };
    const project = {
      id: projectId,
      ownerId,
      name: projectName,
      origin,
      allowedOrigins: [origin],
      liveKeyHash: liveHash,
      serverKeyHash: serverHash,
      canaryKeyHash: canaryHash,
      policy: { mode: 'ENFORCE', rateLimitPerMinute: 120, blockDatacenterAsn: false, canaryRowsEnabled: false, deceptionEnabled: true, abuseProtectionEnabled: false, geoVelocityEnabled: false, threatFeedEnabled: true, shadowApiCatalogEnabled: false, forensicReplayEnabled: false, alertWebhookUrl: null, autoContainmentEnabled: false },
      createdAt: now
    };
    const credentialKeys = [`arix:key:${liveHash}`, `arix:key:${serverHash}`, `arix:key:${canaryHash}`];
    recordKeys.push(...credentialKeys);
    await Promise.all([
      setJson(recordKeys[0], user),
      setJson(recordKeys[1], project),
      setString(recordKeys[2], projectId),
      setJson(credentialKeys[0], { projectId, type: 'live', createdAt: Date.now() }),
      setJson(credentialKeys[1], { projectId, type: 'server', createdAt: Date.now() }),
      setJson(credentialKeys[2], { projectId, type: 'canary', createdAt: Date.now() })
    ]);

    const session = await createSession(ownerId, projectId, req);
    if (reservation) {
      // Replace the pending reservation atomically. A read-then-SET sequence
      // could otherwise overwrite a newer registration after a TTL/race.
      if (!(await compareAndSetString(emailIndex, reservation, ownerId))) {
        throw Object.assign(new Error('Registration reservation changed during verification.'), { statusCode: 409 });
      }
    } else if (await getString(emailIndex) !== ownerId) {
      throw Object.assign(new Error('Account email reservation changed during registration.'), { statusCode: 409 });
    }

    // The permanent email index is now published and the session exists.
    published = true;
    if (pendingRegistrationId) {
      try { await deleteKeys(`arix:signup:pending:${pendingRegistrationId}`, `arix:signup:attempts:${pendingRegistrationId}`); }
      catch { /* Pending material has a short TTL and no longer owns the email index. */ }
    }
    setSessionCookie(res, session.token, session.ttl, isSecure(req));
    return sendJson(res, 201, signupResponse(ownerId, projectId, name, email, projectName, origin, { liveKey, serverKey, canaryKey }));
  } catch (error) {
    if (!published) {
      await Promise.allSettled([
        deleteKeys(...recordKeys),
        revokeAllUserSessions(ownerId),
        compareAndDeleteString(emailIndex, reservation || ownerId),
        ...(pendingRegistrationId ? [deleteKeys(`arix:signup:pending:${pendingRegistrationId}`, `arix:signup:attempts:${pendingRegistrationId}`)] : [])
      ]);
    }
    throw error;
  }
}

async function beginEmailVerifiedSignup({ email, emailHash, name, projectName, origin, passwordRecord }, req, res) {
  if (!signupEmailConfig()) return sendJson(res, 503, { error: 'New account registration is temporarily unavailable. Email ownership verification is required; configure ARIX_RESEND_API_KEY and ARIX_EMAIL_FROM.' });
  const registrationId = randomToken(24);
  const reservation = `pending:${registrationId}`;
  const emailIndex = `arix:user-email:${emailHash}`;
  if (await setString(emailIndex, reservation, SIGNUP_VERIFICATION_TTL_SECONDS, true) !== 'OK') return sendJson(res, 409, { error: 'An account with this email already exists or is being registered. Sign in or try again later.' });
  const pendingKey = `arix:signup:pending:${registrationId}`;
  try {
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const mac = Buffer.from(await hmacSha256(getMasterSecret(), `arix-signup-otp-v1:${registrationId}:${emailHash}:${code}`)).toString('hex');
    const pending = {
      schema: 1, registrationId, email, emailHash, name, projectName, origin,
      ownerId: `usr_${randomToken(12)}`, projectId: `prj_${randomToken(9)}`,
      passwordRecord, codeMac: mac, createdAt: Date.now(),
      expiresAt: Date.now() + SIGNUP_VERIFICATION_TTL_SECONDS * 1000
    };
    if (await setJson(pendingKey, pending, SIGNUP_VERIFICATION_TTL_SECONDS, true) !== 'OK') throw new Error('Could not create the temporary registration record.');
    await deliverSignupVerificationEmail({ email, name, code });
    return sendJson(res, 202, { ok: true, verificationRequired: true, email, expiresInSeconds: SIGNUP_VERIFICATION_TTL_SECONDS, message: 'A one-time verification code has been sent to your email. Verify ownership to create your account and receive project credentials.' });
  } catch (error) {
    await Promise.allSettled([deleteKeys(pendingKey), compareAndDeleteString(emailIndex, reservation)]);
    throw error;
  }
}

async function verifySignupEmail(body, req, res) {
  const email = String(body.email ?? '').trim().toLowerCase();
  const code = String(body.code ?? '').trim();
  if (!EMAIL_RE.test(email) || email.length > 254 || !/^\d{6}$/.test(code)) return sendJson(res, 400, { error: 'The verification code is invalid or expired.' });
  const emailHash = await sha256Hex(email);
  const emailIndex = `arix:user-email:${emailHash}`;
  const reservation = await getString(emailIndex);
  if (typeof reservation !== 'string' || !reservation.startsWith('pending:')) return sendJson(res, 400, { error: 'The verification code is invalid or expired.' });
  const registrationId = reservation.slice('pending:'.length);
  if (!/^[A-Za-z0-9_-]{24,64}$/.test(registrationId)) return sendJson(res, 400, { error: 'The verification code is invalid or expired.' });
  const pendingKey = `arix:signup:pending:${registrationId}`;
  const pending = await getJson(pendingKey);
  if (!pending || pending.schema !== 1 || pending.registrationId !== registrationId || pending.emailHash !== emailHash || pending.expiresAt < Date.now()) {
    return sendJson(res, 410, { error: 'The verification code expired. Start registration again.' });
  }
  const attempts = await incrementWithExpiry(`arix:signup:attempts:${registrationId}`, SIGNUP_VERIFICATION_TTL_SECONDS);
  if (attempts > SIGNUP_VERIFICATION_ATTEMPTS) {
    await Promise.allSettled([deleteKeys(pendingKey), compareAndDeleteString(emailIndex, reservation)]);
    return sendJson(res, 429, { error: 'Too many incorrect verification attempts. Start registration again.' });
  }
  const suppliedMac = Buffer.from(await hmacSha256(getMasterSecret(), `arix-signup-otp-v1:${registrationId}:${emailHash}:${code}`));
  const expectedMac = Buffer.from(String(pending.codeMac || ''), 'hex');
  if (expectedMac.length !== 32 || !constantTimeEqual(suppliedMac, expectedMac)) return sendJson(res, 400, { error: 'The verification code is invalid or expired.' });

  const lockKey = `arix:signup:verify-lock:${registrationId}`;
  if (await setString(lockKey, randomToken(16), 30, true) !== 'OK') return sendJson(res, 409, { error: 'Verification is already being completed. Retry shortly.' });
  try {
    const currentPending = await getJson(pendingKey);
    if (!currentPending || currentPending.codeMac !== pending.codeMac || await getString(emailIndex) !== reservation) return sendJson(res, 410, { error: 'The verification code expired. Start registration again.' });
    return await persistNewAccount(pending, req, res, { reservation, pendingRegistrationId: registrationId });
  } finally {
    await deleteKeys(lockKey).catch(() => {});
  }
}

async function provisionAccount(body, req, res) {
  const email = String(body.email ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');
  const name = String(body.name ?? '').trim();
  const projectName = String(body.projectName ?? 'My Project').trim();
  const origin = normalizeOrigin(body.origin);
  if (!EMAIL_RE.test(email) || email.length > 254) return sendJson(res, 400, { error: 'Enter a valid email address.' });
  if (!validName(name) || !validName(projectName) || !origin) return sendJson(res, 400, { error: 'Provide your name, a project name and an HTTPS site origin (localhost is allowed for development).' });
  const passwordCheck = await validatePasswordPolicy(password, { email, projectName });
  if (!passwordCheck.valid) return sendJson(res, 400, { error: passwordCheck.message, code: passwordCheck.code });
  const emailHash = await sha256Hex(email);
  const passwordRecord = await derivePassword(password);
  const registration = { email, emailHash, name, projectName, origin, passwordRecord };
  if (emailVerificationRequired()) return beginEmailVerifiedSignup(registration, req, res);
  return persistNewAccount(registration, req, res);
}

async function issueLoginPowChallenge(res, emailHash, subnet) {
  const nonce = randomToken(24);
  const difficulty = 16;
  const challenge = await createSignedToken({ emailHash, subnet, nonce, difficulty, exp: Date.now() + 120000 }, 'arix-login-pow');
  return sendJson(res, 428, { error: 'Additional proof of work is required after repeated failed sign-in attempts.', challenge: { token: challenge, nonce, difficulty, expiresInSeconds: 120 } }, { 'Cache-Control': 'no-store' });
}

async function verifyLoginPow(body, emailHash, subnet) {
  const token = String(body.powToken || ''); const solution = String(body.powSolution || '');
  if (!token || !/^\d{1,16}$/.test(solution)) return false;
  const claims = await verifySignedToken(token, 'arix-login-pow');
  if (!claims || claims.emailHash !== emailHash || claims.subnet !== subnet || !claims.nonce) return false;
  const digest = await sha256Hex(`${claims.nonce}:${solution}`);
  if (!digest.startsWith('0000')) return false;
  const replayKey = `arix:auth:pow:${await sha256Hex(claims.nonce)}`;
  return (await setString(replayKey, '1', 120, true)) === 'OK';
}

async function recordAccountLoginFailure(emailHash) {
  const attempts = await incrementWithExpiry(`arix:auth:acct-failure-count:${emailHash}`, 15 * 60);
  const failures = await rateLimit({ key: `arix:auth:acct-failures:${emailHash}`, algorithm: 'SLIDING_WINDOW', limit: 5, windowMs: 15 * 60 * 1000 });
  if (attempts >= 5 || failures.remaining === 0 || !failures.allowed) {
    const delayMs = Math.min(30000, 1000 * (2 ** Math.min(5, Math.max(0, attempts - 5))));
    const backoffUntil = Date.now() + delayMs;
    await Promise.all([
      setString(`arix:auth:acct-lock:${emailHash}`, '1', 15 * 60),
      setMaxStringWithExpiry(`arix:auth:acct-backoff:${emailHash}`, backoffUntil, Math.ceil(delayMs / 1000) + 1)
    ]);
  }
}

function ensureMfaRecoveryCodes(user) {
  if (Array.isArray(user.recoveryCodes) && user.recoveryCodes.length > 0) return [];
  const generated = generateMfaRecoveryCodes();
  user.recoveryCodes = generated.hashes;
  user.recoveryCodesIssuedAt = Date.now();
  return [...generated.codes];
}

async function recoverMfaAccount(body, req, res) {
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const recoveryCode = String(body.recoveryCode || '');
  if (!EMAIL_RE.test(email) || password.length < 1 || password.length > 128 || recoveryCode.length > 64) {
    return sendJson(res, 401, { error: 'Account credentials or recovery code are invalid.' });
  }
  const emailHash = await sha256Hex(email);
  const ownerId = await getString(`arix:user-email:${emailHash}`);
  const user = ownerId ? await getJson(`arix:user:${ownerId}`) : null;
  const passwordValid = await verifyPassword(password, user?.password || DUMMY_PASSWORD);
  if (!user || !passwordValid || !Array.isArray(user.recoveryCodes) || user.recoveryCodes.length === 0) {
    await recordAccountLoginFailure(emailHash);
    return sendJson(res, 401, { error: 'Account credentials or recovery code are invalid.' });
  }
  // Confirm a valid owned project before burning the user's only recovery code.
  const projectId = await findOwnedProject(ownerId);
  const project = projectId ? await getJson(`arix:project:${projectId}`) : null;
  if (!project || project.ownerId !== ownerId) return sendJson(res, 403, { error: 'This account has no active project.' });
  const consumed = await consumeMfaRecoveryCode(recoveryCode, {
    hashes: user.recoveryCodes,
    consumeDigest: async (digest) => {
      const digestHash = await sha256Hex(digest);
      return (await setString(`arix:mfa:recovery-used:${ownerId}:${digestHash}`, '1', 315360000, true)) === 'OK';
    }
  });
  if (!consumed.valid) {
    await recordAccountLoginFailure(emailHash);
    return sendJson(res, 401, { error: 'Account credentials or recovery code are invalid.' });
  }

  const credentialIds = (Array.isArray(user.passkeys) ? user.passkeys : []).map((item) => item?.credentialId).filter((value) => typeof value === 'string' && value.length <= 2048);
  delete user.totpSecret;
  delete user.totpEnabledAt;
  delete user.totpEnrolledAt;
  delete user.recoveryCodes;
  delete user.recoveryCodesIssuedAt;
  user.totpEnabled = false;
  user.passkeys = [];
  user.mfaRecoveredAt = new Date().toISOString();
  await setJson(`arix:user:${ownerId}`, user);
  if (credentialIds.length) {
    const keys = await Promise.all(credentialIds.map(async (id) => { const hash = await sha256Hex(id); return [`arix:webauthn:credential:${hash}`, `arix:webauthn:counter:${hash}`]; }));
    await deleteKeys(...keys.flat());
  }
  await revokeAllUserSessions(ownerId);
  const fresh = await createSession(ownerId, projectId, req);
  setSessionCookie(res, fresh.token, fresh.ttl, isSecure(req));
  return sendJson(res, 200, { ok: true, recovered: true, mfaReset: true, requireMfaReenrollment: true, message: 'MFA factors were reset, existing sessions were revoked, and this browser received a new session. Re-enroll a passkey or authenticator now.' });
}

export function accountLoginRequiresPow(accountLocked, backoffUntil, now = Date.now()) {
  return Boolean(accountLocked) || (Number.isFinite(Number(backoffUntil)) && Number(backoffUntil) > now);
}

async function loginAccount(body, req, res) {
  const email = String(body.email ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');
  if (!EMAIL_RE.test(email) || password.length > 128 || password.length === 0) return sendJson(res, 401, { error: 'Email or password is incorrect.' });
  const emailHash = await sha256Hex(email);
  const rawIp = String(process.env.VERCEL === '1' ? (req.headers?.['x-real-ip'] || req.headers?.['x-vercel-forwarded-for'] || '') : (req.socket?.remoteAddress || '')).split(',')[0].trim();
  const subnet = formatIpPrefix(rawIp) || 'unknown-subnet';
  // A subnet is an aggregate abuse signal, not a single user's identity. Keep this
  // envelope intentionally broad; per-email failure counters provide the strict lockout.
  const subnetLimit = await rateLimit({ key: `arix:auth:subnet:${await sha256Hex(subnet)}`, algorithm: 'SLIDING_WINDOW', limit: 12000, windowMs: 15 * 60 * 1000 });
  if (!subnetLimit.allowed) return sendJson(res, 429, { error: 'Too many sign-in attempts from this network. Try again later.' }, { 'Retry-After': String(Math.ceil(subnetLimit.retryAfterMs / 1000)) });
  const accountLockKey = `arix:auth:acct-lock:${emailHash}`;
  const backoffUntil = Number(await getString(`arix:auth:acct-backoff:${emailHash}`) || 0);
  const accountLocked = await getString(accountLockKey);
  // Backoff must never hard-deny a correct password: an attacker can trigger
  // these counters anonymously. Require a one-use PoW instead of returning a
  // time-based 429 that lets the attacker hold the victim's account hostage.
  if (accountLoginRequiresPow(accountLocked, backoffUntil)) {
    const powValid = await verifyLoginPow(body, emailHash, subnet);
    if (!powValid) return issueLoginPowChallenge(res, emailHash, subnet);
  }
  const ownerId = await getString(`arix:user-email:${emailHash}`);
  const user = ownerId ? await getJson(`arix:user:${ownerId}`) : null;
  const passwordRecord = user?.password ?? DUMMY_PASSWORD;
  const valid = await verifyPassword(password, passwordRecord);
  if (!user?.password || !valid) {
     await recordAccountLoginFailure(emailHash);
    return sendJson(res, 401, { error: 'Email or password is incorrect.' });
  }
  let secondFactorVerified = false;
  if (user.totpEnabled === true) {
    let secret;
    try { secret = decryptTotpSecret(user.totpSecret); } catch { return sendJson(res, 503, { error: 'MFA configuration is unavailable. Contact the project administrator.' }); }
    if (!await verifyAndConsumeTotp(ownerId, secret, body.totpCode)) {
       await recordAccountLoginFailure(emailHash);
      return sendJson(res, 401, { error: 'Email or password is incorrect, or the authenticator code is invalid.' });
    }
    secondFactorVerified = true;
  }
  const recentFailures = Math.max(0, Math.min(5, Number(await getString(`arix:auth:acct-failure-count:${emailHash}`)) || 0));
  const loginRisk = evaluateLoginRisk({ failedLoginCount: recentFailures });
  const hasPasskey = Array.isArray(user.passkeys) && user.passkeys.length > 0;
  // Failed-password counters are attacker-controlled signals. They may require
  // an enrolled factor, but must never demand an impossible MFA enrollment from
  // an account that has no second factor configured.
  if (loginRisk.decision !== 'allow' && !secondFactorVerified && hasPasskey) {
    return sendJson(res, 428, { error: 'Additional passkey verification is required for this sign-in.', stepUpRequired: true, challengeType: 'passkey', riskScore: loginRisk.riskScore, reasons: loginRisk.reasons }, { 'Cache-Control': 'no-store' });
  }
  // A validated TOTP/passkey is treated as the second-factor step-up proof.
  // Upgrade every historical PBKDF2 record only after the risk decision passes.
  if (passwordRecord.algorithm !== 'scrypt') {
    user.password = await derivePassword(password);
    await setJson(`arix:user:${ownerId}`, user);
  }
  const projectId = await findOwnedProject(ownerId);
  if (!projectId) return sendJson(res, 403, { error: 'This account has no active project.' });
  await deleteKeys(accountLockKey, `arix:auth:acct-failures:${emailHash}`, `arix:auth:acct-failure-count:${emailHash}`, `arix:auth:acct-backoff:${emailHash}`);
  const session = await createSession(ownerId, projectId, req);
  setSessionCookie(res, session.token, session.ttl, isSecure(req));
  return sendJson(res, 200, { ok: true, user: { id: user.id, name: user.name, email: user.email }, project: { id: projectId }, mfaRequired: false });
}

async function changePassword(body, req, res, session) {
  if (!session) return sendJson(res, 401, { error: 'Sign in again before changing your password.' });
  const [user, project] = await Promise.all([
    getJson(`arix:user:${session.ownerId}`),
    getJson(`arix:project:${session.projectId}`)
  ]);
  if (!user || !project || project.ownerId !== session.ownerId) return sendJson(res, 403, { error: 'Account ownership could not be verified.' });
  const currentPassword = String(body.currentPassword ?? '');
  const stepUp = await verifyStepUpCredentials({ ownerId: session.ownerId, projectId: session.projectId, password: currentPassword, totpCode: body.totpCode, passkeyChallenge: body.passkeyChallenge, passkeyCredential: body.passkeyCredential, req });
  if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error });
  const newPassword = String(body.newPassword ?? '');
  if (body.confirmPassword !== undefined && body.confirmPassword !== newPassword) return sendJson(res, 400, { error: 'New password and confirmation do not match.' });
  if (newPassword === currentPassword) return sendJson(res, 400, { error: 'Choose a password different from your current password.' });
  const passwordCheck = await validatePasswordPolicy(newPassword, { email: user.email, projectName: project.name });
  if (!passwordCheck.valid) return sendJson(res, 400, { error: passwordCheck.message, code: passwordCheck.code });

  stepUp.user.password = await derivePassword(newPassword);
  stepUp.user.passwordChangedAt = new Date().toISOString();
  await setJson(`arix:user:${session.ownerId}`, stepUp.user);

  // Rotate the current session and revoke all other sessions. Reuse of the
  // spent cookie triggers a family-wide replay kill switch in getSession().
  const freshSession = await rotateSession(session.ownerId, session.projectId, session.tokenHash, req);
  if (!freshSession) return sendJson(res, 503, { error: 'Session rotation could not be completed. Sign in again and retry.' });
  setSessionCookie(res, freshSession.token, freshSession.ttl, isSecure(req));
  return sendJson(res, 200, { ok: true, changed: true, message: 'Password changed. Other sessions were revoked and this browser received a fresh session.' });
}

async function rotateServerKey(body, req, res, immediate = false) {
  const session = await getSession(req);
  if (!session) return sendJson(res, 401, { error: 'Sign in again before rotating server keys.' });
  const [user, project] = await Promise.all([getJson(`arix:user:${session.ownerId}`), getJson(`arix:project:${session.projectId}`)]);
  if (!user || !project || project.ownerId !== session.ownerId) return sendJson(res, 403, { error: 'Project ownership could not be verified.' });
  const stepUp = await verifyStepUpCredentials({ ownerId: session.ownerId, projectId: session.projectId, password: String(body.password || ''), totpCode: body.totpCode, passkeyChallenge: body.passkeyChallenge, passkeyCredential: body.passkeyCredential, req });
  if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error, stepUpRequired: stepUp.stepUpRequired === true, challengeType: stepUp.challengeType });
  const lockKey = `arix:project-key-rotation:${project.id}`;
  const lockToken = randomToken(18);
  const lock = await setString(lockKey, lockToken, 30, true);
  if (lock !== 'OK') return sendJson(res, 409, { error: 'A server-key rotation is already in progress.' });
  let newHash = null; let freshSession = null; let projectCommitted = false;
  let nextServerKey = '';
  let nextProject = null;
  let graceSeconds = 0;
  try {
    nextServerKey = `ARIX_SECRET_${randomToken(32)}`;
    newHash = await hashCredential(nextServerKey);
    const oldHash = String(project.serverKeyHash || '');
    graceSeconds = immediate ? 0 : Math.max(0, Math.min(86400, Math.floor(Number(body.graceSeconds ?? 3600))));
    nextProject = { ...project, serverKeyHash: newHash, keyEpoch: Math.max(0, Number(project.keyEpoch) || 0) + 1, serverKeyRotatedAt: Date.now() };

    // Prepare replacement credentials before committing the project pointer. If
    // either operation fails, the old server key remains authoritative.
    await setJson(`arix:key:${newHash}`, { projectId: project.id, type: 'server', createdAt: Date.now() });
    freshSession = await createSession(session.ownerId, session.projectId, req);
    await setJson(`arix:project:${project.id}`, nextProject);
    projectCommitted = true;

    // After the project pointer is committed, the control plane also checks
    // serverKeyHash on every request. Thus even a failed cleanup cannot revive
    // the old active key mapping.
    try {
      if (oldHash && /^[a-f0-9]{64}$/i.test(oldHash)) {
        if (graceSeconds > 0) await setJson(`arix:key:${oldHash}`, { projectId: project.id, type: 'server-retiring', createdAt: Date.now(), retireAt: Date.now() + graceSeconds * 1000 }, graceSeconds);
        else await deleteKeys(`arix:key:${oldHash}`);
      }
      const sessions = await listUserSessions(session.ownerId);
      await Promise.all(sessions.filter((item) => item.tokenHash !== freshSession.tokenHash).map((item) => revokeUserSession(session.ownerId, item.tokenHash)));
    } catch (cleanupError) {
      console.error('[ArixShield] Key rotation committed; post-commit cleanup needs review:', cleanupError?.message || cleanupError);
    }
    setSessionCookie(res, freshSession.token, freshSession.ttl, isSecure(req));
    return sendJson(res, 200, { ok: true, serverKey: nextServerKey, keyEpoch: nextProject.keyEpoch, oldKeyGraceSeconds: graceSeconds, message: 'The new server key is displayed once. Update your server environment variable; do not place it in browser code.' });
  } catch (error) {
    if (projectCommitted) {
      // Never delete the new key after the project record has committed: doing
      // so would strand the customer with an invalid server integration key.
      if (freshSession) setSessionCookie(res, freshSession.token, freshSession.ttl, isSecure(req));
      console.error('[ArixShield] Key rotation committed with a post-commit error:', error?.message || error);
      return sendJson(res, 200, { ok: true, serverKey: nextServerKey, keyEpoch: nextProject.keyEpoch, oldKeyGraceSeconds: graceSeconds, cleanupWarning: true, message: 'The new key is active. Update your server environment immediately; review the security event log for post-rotation cleanup.' });
    }
    if (newHash) await deleteKeys(`arix:key:${newHash}`).catch(() => {});
    if (freshSession) await revokeUserSession(session.ownerId, freshSession.tokenHash).catch(() => {});
    throw error;
  } finally {
    await deleteKeys(lockKey).catch((error) => console.error('[ArixShield] Could not release key-rotation lock:', error?.message || error));
  }
}

async function findOwnedProject(ownerId) {
  // Project IDs are stored in a small owner index when provisioned; avoid global Redis key scans.
  return (await import('./_lib/redis.js').then(({ getString }) => getString(`arix:owner-project:${ownerId}`))) || null;
}

function getWebAuthnOrigin(req) {
  const origin = String(req.headers?.origin || '');
  if (!origin || !sameOriginRequest(req)) return null;
  try {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' && !(parsed.hostname === 'localhost' && parsed.protocol === 'http:')) return null;
    return { origin: parsed.origin, rpId: parsed.hostname };
  } catch { return null; }
}

async function createWebAuthnChallenge({ purpose, origin, rpId, ownerId = null, projectId = null }) {
  const challenge = randomToken(32);
  const record = { purpose, challenge, origin, rpId, ownerId, projectId, expiresAt: Date.now() + 120000 };
  await setJson(`arix:webauthn:challenge:${await sha256Hex(challenge)}`, record, 120);
  return challenge;
}

async function registerPasskey(body, req, res) {
  const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to register a passkey.' });
  const origin = getWebAuthnOrigin(req); if (!origin) return sendJson(res, 403, { error: 'WebAuthn origin is not allowed.' });
  const [currentUser, project] = await Promise.all([getJson(`arix:user:${session.ownerId}`), getJson(`arix:project:${session.projectId}`)]);
  if (!currentUser || !project || project.ownerId !== session.ownerId) return sendJson(res, 403, { error: 'Account ownership could not be verified.' });
  // A live session alone is not sufficient to add a persistent authenticator.
  // Require the current password plus an already-enrolled factor where present.
  const stepUp = await verifyStepUpCredentials({ ownerId: session.ownerId, projectId: session.projectId, password: String(body.password || ''), totpCode: body.totpCode, passkeyChallenge: body.passkeyChallenge, passkeyCredential: body.passkeyCredential, req });
  if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error, stepUpRequired: stepUp.stepUpRequired === true, challengeType: stepUp.challengeType });
  const user = stepUp.user;
  const challenge = String(body.challenge || '');
  const recordKey = `arix:webauthn:challenge:${await sha256Hex(challenge)}`;
  const challengeRecord = await getJsonOnce(recordKey);
  if (!challengeRecord || challengeRecord.purpose !== 'register' || challengeRecord.ownerId !== session.ownerId || challengeRecord.projectId !== session.projectId || challengeRecord.origin !== origin.origin || challengeRecord.rpId !== origin.rpId || challengeRecord.expiresAt < Date.now()) return sendJson(res, 400, { error: 'Passkey registration challenge expired or invalid.' });
  let credential;
  try { credential = verifyWebAuthnRegistration(body.credential, challengeRecord, { requireUserVerification: true }); }
  catch (error) { return sendJson(res, 400, { error: `Passkey registration could not be verified: ${String(error.message || 'invalid credential').slice(0, 120)}` }); }
  const credentials = Array.isArray(user.passkeys) ? user.passkeys.slice(0, 10) : [];
  if (credentials.length >= 10) return sendJson(res, 409, { error: 'A maximum of ten passkeys can be registered.' });
  const credentialHash = await sha256Hex(credential.credentialId);
  const existing = await getJson(`arix:webauthn:credential:${credentialHash}`);
  if (existing) return sendJson(res, 409, { error: 'This passkey is already registered.' });
  user.passkeys = [...credentials, credential];
  const recoveryCodes = ensureMfaRecoveryCodes(user);
  await Promise.all([
    setJson(`arix:user:${session.ownerId}`, user),
    setJson(`arix:webauthn:credential:${credentialHash}`, { ownerId: session.ownerId, projectId: session.projectId, credentialId: credential.credentialId, createdAt: Date.now() })
  ]);
  return sendJson(res, 201, { ok: true, credentialId: credential.credentialId, registeredAt: credential.registeredAt, ...(recoveryCodes.length ? { recoveryCodes, recoveryCodesNotice: 'Save these eight recovery codes now. They are shown only once.' } : {}) });
}

async function loginWithPasskey(body, req, res) {
  const origin = getWebAuthnOrigin(req); if (!origin) return sendJson(res, 403, { error: 'WebAuthn origin is not allowed.' });
  const challenge = String(body.challenge || '');
  const recordKey = `arix:webauthn:challenge:${await sha256Hex(challenge)}`;
  const challengeRecord = await getJsonOnce(recordKey);
  if (!challengeRecord || challengeRecord.purpose !== 'authenticate' || challengeRecord.origin !== origin.origin || challengeRecord.rpId !== origin.rpId || challengeRecord.expiresAt < Date.now()) return sendJson(res, 401, { error: 'Passkey authentication failed.' });
  let credentialId;
  try { credentialId = decodeWebAuthnBase64url(body.credential?.rawId || body.credential?.id, 1024).toString('base64url'); }
  catch { return sendJson(res, 401, { error: 'Passkey authentication failed.' }); }
  const credentialHash = await sha256Hex(credentialId);
  const mapping = await getJson(`arix:webauthn:credential:${credentialHash}`);
  if (!mapping?.ownerId || !mapping.projectId) return sendJson(res, 401, { error: 'Passkey authentication failed.' });
  const passkeyLimit = await rateLimit({ key: `arix:auth:passkey:${mapping.ownerId}`, algorithm: 'SLIDING_WINDOW', limit: 10, windowMs: 15 * 60 * 1000 });
  if (!passkeyLimit.allowed) return sendJson(res, 429, { error: 'Too many passkey sign-in attempts. Try again later.' }, { 'Retry-After': String(Math.ceil(passkeyLimit.retryAfterMs / 1000)) });
  const [user, project] = await Promise.all([getJson(`arix:user:${mapping.ownerId}`), getJson(`arix:project:${mapping.projectId}`)]);
  if (!user || !project || project.ownerId !== user.id) return sendJson(res, 401, { error: 'Passkey authentication failed.' });
  const credentials = Array.isArray(user.passkeys) ? user.passkeys : [];
  const index = credentials.findIndex((item) => item.credentialId === credentialId);
  if (index < 0) return sendJson(res, 401, { error: 'Passkey authentication failed.' });
  let assertion;
  try { assertion = verifyWebAuthnAssertion(body.credential, challengeRecord, credentials[index], { requireUserVerification: true, deferCounterCheck: true }); }
  catch { return sendJson(res, 401, { error: 'Passkey authentication failed.' }); }
  if (!await advanceWebAuthnCounter(credentialHash, credentials[index].signCount ?? 0, assertion.signCount)) return sendJson(res, 401, { error: 'Passkey authentication failed.' });
  credentials[index] = { ...credentials[index], signCount: Math.max(credentials[index].signCount ?? 0, assertion.signCount), lastUsedAt: Date.now() };
  user.passkeys = credentials;
  await setJson(`arix:user:${user.id}`, user);
  const emailHash = typeof user.email === 'string' ? await sha256Hex(user.email.toLowerCase()) : '';
  if (emailHash) await deleteKeys(`arix:auth:acct-lock:${emailHash}`, `arix:auth:acct-failures:${emailHash}`, `arix:auth:acct-failure-count:${emailHash}`, `arix:auth:acct-backoff:${emailHash}`);
  const session = await createSession(user.id, project.id, req);
  setSessionCookie(res, session.token, session.ttl, isSecure(req));
  return sendJson(res, 200, { ok: true, user: { id: user.id, name: user.name, email: user.email }, project: { id: project.id }, authentication: 'passkey' });
}

async function handler(req, res) {
  if (req.method === 'GET') {
    try {
      const session = await getSession(req);
      if (!session) return sendJson(res, 200, { authenticated: false });
      const user = await getJson(`arix:user:${session.ownerId}`);
      const project = await getJson(`arix:project:${session.projectId}`);
      if (!user || !project) return sendJson(res, 200, { authenticated: false });
      return sendJson(res, 200, { authenticated: true, user: { id: user.id, name: user.name, email: user.email }, project: { id: project.id, name: project.name, origin: project.origin }, security: { totpEnabled: user.totpEnabled === true, passkeys: (Array.isArray(user.passkeys) ? user.passkeys : []).slice(0, 10).map((item) => ({ credentialId: item.credentialId, registeredAt: item.registeredAt, lastUsedAt: item.lastUsedAt || null, transports: Array.isArray(item.transports) ? item.transports.slice(0, 8) : [] })) } });
    } catch (error) {
      console.error('[ArixShield] /api/auth session lookup failed:', error?.stack || error);
      return sendJson(res, 503, { error: 'Account service unavailable. Check Upstash Redis configuration and function logs.' });
    }
  }
  if (req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  if (!sameOriginRequest(req)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });
  try {
    const body = await readJson(req, 12000);
    const action = String(body.action || 'unknown').slice(0, 48);
    const publicCredentialActions = new Set(['signup', 'verify-email', 'login', 'passkey-login-options', 'passkey-login', 'recover-mfa']);
    const session = publicCredentialActions.has(action) ? null : await getSession(req);
    let limitKey;
    let limitCount;
    let limitWindowMs;
    if (action === 'login' || action === 'signup' || action === 'verify-email' || action === 'recover-mfa') {
      // Signup/recovery remain tightly account-scoped. Login uses a broad account
      // ceiling plus the subnet envelope and one-use PoW after failed attempts;
      // a low per-email request ceiling would let an unauthenticated attacker
      // repeatedly deny the victim's own password sign-in.
      const email = String(body.email || '').trim().toLowerCase().slice(0, 254);
      const emailScope = EMAIL_RE.test(email) ? await sha256Hex(email) : await sha256Hex(`invalid:${clientRateKey(req)}`);
      limitKey = `${action}:email:${emailScope}`;
      limitCount = action === 'login' ? 12000 : action === 'verify-email' ? 10 : 5;
      limitWindowMs = action === 'login' ? 15 * 60 * 1000 : action === 'verify-email' ? 10 * 60 * 1000 : 60 * 60 * 1000;
    } else if (session?.ownerId) {
      limitKey = `account:${session.ownerId}:${action}`;
      limitCount = 120;
      limitWindowMs = 60000;
    } else {
      // Unauthenticated WebAuthn bootstrap actions have no account identity yet;
      // retain a deliberately broad network safety envelope rather than an 8/min NAT lockout.
      limitKey = `public:${action}:${await sha256Hex(clientRateKey(req))}`;
      limitCount = 3000;
      limitWindowMs = 60000;
    }
    const limitDimensions = [{ key: `arix:auth:limit:${await sha256Hex(limitKey)}`, limit: limitCount, windowMs: limitWindowMs }];
    if (action === 'signup' || action === 'verify-email') {
      const trustedIp = trustedClientIp(req);
      const networkPrefix = trustedClientNetworkPrefix(req);
      if (trustedIp) limitDimensions.push({
        key: `arix:auth:network-ip:${action}:${await sha256Hex(trustedIp)}`,
        limit: action === 'signup' ? 20 : 30,
        windowMs: action === 'signup' ? 60 * 60 * 1000 : 10 * 60 * 1000
      });
      if (networkPrefix) limitDimensions.push({
        key: `arix:auth:network-prefix:${action}:${await sha256Hex(networkPrefix)}`,
        limit: action === 'signup' ? 60 : 120,
        windowMs: action === 'signup' ? 60 * 60 * 1000 : 10 * 60 * 1000
      });
      if (action === 'signup') {
        const configuredGlobalLimit = Number(process.env.ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR);
        const globalLimit = Number.isSafeInteger(configuredGlobalLimit) && configuredGlobalLimit >= 1 && configuredGlobalLimit <= 100000 ? configuredGlobalLimit : 10000;
        limitDimensions.push({ key: 'arix:auth:global:signup', limit: globalLimit, windowMs: 60 * 60 * 1000 });
      }
    }
    const limit = await rateLimitMulti({ dimensions: limitDimensions });
    if (!limit.allowed) return sendJson(res, 429, { error: 'Too many account requests for this account or endpoint. Try again shortly.' }, { 'Retry-After': String(Math.ceil(limit.retryAfterMs / 1000)) });
    if (body.action === 'signup') return await provisionAccount(body, req, res);
    if (body.action === 'verify-email') return await verifySignupEmail(body, req, res);
    if (body.action === 'login') return await loginAccount(body, req, res);
    if (body.action === 'recover-mfa') return await recoverMfaAccount(body, req, res);
    if (body.action === 'change-password') return await changePassword(body, req, res, session);
    if (body.action === 'passkey-register-options') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to register a passkey.' });
      const origin = getWebAuthnOrigin(req); if (!origin) return sendJson(res, 403, { error: 'WebAuthn origin is not allowed.' });
      const [user, project] = await Promise.all([getJson(`arix:user:${session.ownerId}`), getJson(`arix:project:${session.projectId}`)]);
      if (!user || !project || project.ownerId !== session.ownerId) return sendJson(res, 403, { error: 'Account ownership could not be verified.' });
      const challenge = await createWebAuthnChallenge({ purpose: 'register', ...origin, ownerId: user.id, projectId: project.id });
      const excludeCredentials = (Array.isArray(user.passkeys) ? user.passkeys : []).map((item) => ({ type: 'public-key', id: item.credentialId, transports: item.transports || [] }));
      return sendJson(res, 200, { ok: true, challenge, publicKey: { challenge, rp: { name: 'ArixShield', id: origin.rpId }, user: { id: Buffer.from(user.id).toString('base64url'), name: user.email, displayName: user.name }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 120000, attestation: 'none', authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' }, excludeCredentials } });
    }
    if (body.action === 'passkey-register') return await registerPasskey(body, req, res);
    if (body.action === 'passkey-step-up-options') {
      if (!session) return sendJson(res, 401, { error: 'Sign in before requesting a passkey assertion.' });
      const origin = getWebAuthnOrigin(req); if (!origin) return sendJson(res, 403, { error: 'WebAuthn origin is not allowed.' });
      const [user, project] = await Promise.all([getJson(`arix:user:${session.ownerId}`), getJson(`arix:project:${session.projectId}`)]);
      if (!user || !project || project.ownerId !== session.ownerId || !Array.isArray(user.passkeys) || !user.passkeys.length) return sendJson(res, 409, { error: 'No passkey is available for this account.' });
      const challenge = await createWebAuthnChallenge({ purpose: 'step-up', ...origin, ownerId: session.ownerId, projectId: session.projectId });
      const allowCredentials = user.passkeys.slice(0, 10).map((item) => ({ type: 'public-key', id: item.credentialId, transports: Array.isArray(item.transports) ? item.transports.slice(0, 8) : [] }));
      return sendJson(res, 200, { ok: true, challenge, publicKey: { challenge, rpId: origin.rpId, timeout: 120000, userVerification: 'required', allowCredentials } });
    }
    if (body.action === 'passkey-login-options') {
      const origin = getWebAuthnOrigin(req); if (!origin) return sendJson(res, 403, { error: 'WebAuthn origin is not allowed.' });
      const challenge = await createWebAuthnChallenge({ purpose: 'authenticate', ...origin });
      return sendJson(res, 200, { ok: true, challenge, publicKey: { challenge, rpId: origin.rpId, timeout: 120000, userVerification: 'required' } });
    }
    if (body.action === 'passkey-login') return await loginWithPasskey(body, req, res);
    if (body.action === 'passkey-remove') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to remove a passkey.' });
      const stepUp = await verifyStepUpCredentials({ ownerId: session.ownerId, projectId: session.projectId, password: String(body.password || ''), totpCode: body.totpCode, passkeyChallenge: body.passkeyChallenge, passkeyCredential: body.passkeyCredential, req });
      if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error, stepUpRequired: stepUp.stepUpRequired === true, challengeType: stepUp.challengeType });
      const user = stepUp.user;
      const id = String(body.credentialId || ''); const index = (Array.isArray(user.passkeys) ? user.passkeys : []).findIndex((item) => item.credentialId === id);
      if (index < 0) return sendJson(res, 404, { error: 'Passkey not found.' });
      const [removed] = user.passkeys.splice(index, 1);
      if (user.passkeys.length === 0 && user.totpEnabled !== true) { delete user.recoveryCodes; delete user.recoveryCodesIssuedAt; }
      const credentialHash = await sha256Hex(removed.credentialId);
      await Promise.all([setJson(`arix:user:${session.ownerId}`, user), deleteKeys(`arix:webauthn:credential:${credentialHash}`, `arix:webauthn:counter:${credentialHash}`)]);
      return sendJson(res, 200, { ok: true, removed: true });
    }
    if (body.action === 'totp-enroll') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to enroll an authenticator.' });
      const currentUser = await getJson(`arix:user:${session.ownerId}`); if (!currentUser) return sendJson(res, 401, { error: 'Account not found.' });
      if (currentUser.totpEnabled === true) return sendJson(res, 409, { error: 'An authenticator is already enabled.' });
      const stepUp = await verifyStepUpCredentials({ ownerId: session.ownerId, projectId: session.projectId, password: String(body.password || ''), totpCode: body.stepUpTotpCode, passkeyChallenge: body.passkeyChallenge, passkeyCredential: body.passkeyCredential, req });
      if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error, stepUpRequired: stepUp.stepUpRequired === true, challengeType: stepUp.challengeType });
      const user = stepUp.user;
      const generated = generateTotpSecret(); user.totpSecret = generated.encrypted; user.totpEnabled = false; user.totpEnrolledAt = Date.now();
      await setJson(`arix:user:${session.ownerId}`, user);
      return sendJson(res, 200, { ok: true, secret: generated.secret, otpauthUri: totpProvisioningUri(generated.secret, user.email), expiresInSeconds: 600 });
    }
    if (body.action === 'totp-confirm') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to confirm authenticator enrollment.' });
      const pendingUser = await getJson(`arix:user:${session.ownerId}`); if (!pendingUser?.totpSecret) return sendJson(res, 400, { error: 'Start authenticator enrollment first.' });
      const stepUp = await verifyStepUpCredentials({ ownerId: session.ownerId, projectId: session.projectId, password: String(body.password || ''), totpCode: body.stepUpTotpCode, passkeyChallenge: body.passkeyChallenge, passkeyCredential: body.passkeyCredential, req });
      if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error, stepUpRequired: stepUp.stepUpRequired === true, challengeType: stepUp.challengeType });
      const user = stepUp.user;
      if (Date.now() - Number(user.totpEnrolledAt || 0) > 10 * 60 * 1000) { delete user.totpSecret; delete user.totpEnrolledAt; await setJson(`arix:user:${session.ownerId}`, user); return sendJson(res, 410, { error: 'Authenticator enrollment expired. Start again.' }); }
      let secret; try { secret = decryptTotpSecret(user.totpSecret); } catch { return sendJson(res, 503, { error: 'Authenticator secret could not be opened.' }); }
      if (!await verifyAndConsumeTotp(session.ownerId, secret, body.totpCode)) return sendJson(res, 400, { error: 'Authenticator code is invalid or has already been used.' });
      user.totpEnabled = true; user.totpEnabledAt = Date.now(); delete user.totpEnrolledAt;
      const recoveryCodes = ensureMfaRecoveryCodes(user);
      await setJson(`arix:user:${session.ownerId}`, user);
      const fresh = await rotateSession(session.ownerId, session.projectId, session.tokenHash, req);
      if (!fresh) return sendJson(res, 503, { error: 'MFA was enabled, but session rotation failed. Sign in again with your authenticator.' });
      setSessionCookie(res, fresh.token, fresh.ttl, isSecure(req));
      return sendJson(res, 200, { ok: true, enabled: true, ...(recoveryCodes.length ? { recoveryCodes, recoveryCodesNotice: 'Save these eight recovery codes now. They are shown only once.' } : {}), message: 'Authenticator MFA is enabled.' });
    }
    if (body.action === 'totp-disable') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to change MFA settings.' });
      const user = await getJson(`arix:user:${session.ownerId}`); if (!user) return sendJson(res, 401, { error: 'Account not found.' });
      if (!await verifyPassword(String(body.password || ''), user.password)) return sendJson(res, 401, { error: 'Re-authentication failed.' });
      if (user.totpEnabled === true) { let secret; try { secret = decryptTotpSecret(user.totpSecret); } catch { return sendJson(res, 503, { error: 'MFA configuration is unavailable.' }); } if (!await verifyAndConsumeTotp(session.ownerId, secret, body.totpCode)) return sendJson(res, 401, { error: 'Authenticator code is invalid or has already been used.' }); }
      delete user.totpSecret; delete user.totpEnrolledAt; delete user.totpEnabledAt; user.totpEnabled = false;
      if (!Array.isArray(user.passkeys) || user.passkeys.length === 0) { delete user.recoveryCodes; delete user.recoveryCodesIssuedAt; }
      await setJson(`arix:user:${session.ownerId}`, user);
      const fresh = await rotateSession(session.ownerId, session.projectId, session.tokenHash, req);
      if (!fresh) return sendJson(res, 503, { error: 'MFA was disabled, but session rotation failed. Sign in again.' });
      setSessionCookie(res, fresh.token, fresh.ttl, isSecure(req));
      return sendJson(res, 200, { ok: true, enabled: false });
    }
    if (body.action === 'list-sessions') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to view active sessions.' });
      return sendJson(res, 200, { ok: true, sessions: await listUserSessions(session.ownerId) });
    }
    if (body.action === 'revoke-session') {
      const session = await getSession(req); if (!session) return sendJson(res, 401, { error: 'Sign in to revoke sessions.' });
      const revoked = await revokeUserSession(session.ownerId, String(body.tokenHash || ''));
      return sendJson(res, revoked ? 200 : 404, { ok: revoked, revoked });
    }
    if (body.action === 'rotate-server-key') return await rotateServerKey(body, req, res, false);
    if (body.action === 'revoke-server-key') return await rotateServerKey(body, req, res, true);
    if (body.action === 'logout') {
      const session = await getSession(req);
      if (session) await revokeUserSession(session.ownerId, session.tokenHash);
      clearSessionCookie(res, isSecure(req));
      return sendJson(res, 200, { ok: true });
    }
    return sendJson(res, 400, { error: 'Unknown account action.' });
  } catch (error) {
    console.error('[ArixShield] /api/auth request failed:', error?.stack || error);
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, { error: status === 503 ? 'Account service temporarily unavailable. Verify Upstash Redis REST URL/token and inspect Vercel Function logs.' : error.message });
  }
}

export default createCompatibleHandler(handler);

// Keep raw request bytes available for origin-proof verification in the shared adapter.
export const config = { api: { bodyParser: false } };

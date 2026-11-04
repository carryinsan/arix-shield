# ArixShield v1.4.4 — F-14 / F-15 Remediation Report

Date: 2026-11-04  
Scope: The uploaded `arix-shield-chat5-audit-final-v1.4.4-f13` archive and the two new independent WebAuthn/MFA findings.

## Executive summary

Two reported issues were confirmed at source level and remediated:

- **F-14 — High: session-only passkey enrollment.** The registration handler previously relied on `getSession()` and a registration challenge. It now requires fresh password verification and an already-enrolled second factor where one exists, before accepting a new passkey.
- **F-15 — Low: WebAuthn counter rollback.** The assertion verifier previously accepted a transition from a positive stored counter to zero. Positive counters now must strictly increase and may not return to zero. The transition is enforced atomically in shared Redis for production paths, rather than relying only on a process-local value.

The related TOTP enrollment and confirmation operations are also step-up protected. Existing authenticator compatibility is preserved for authenticators that always report counter zero.

## F-14 — Passkey registration and TOTP enrollment step-up

### Before

`api/auth.js` accepted a valid session and a valid WebAuthn registration challenge. It did not require fresh password authentication or proof from an already-enrolled factor. The TOTP enrollment-start and enrollment-confirm routes also relied on the existing session.

### Changes

1. `registerPasskey()` calls `verifyStepUpCredentials()` on the server before consuming the registration challenge or persisting a credential.
2. The step-up always requires the current account password. If TOTP is enabled, a fresh one-time TOTP code is required. For passkey-only accounts, an origin-bound, single-use WebAuthn assertion from an existing registered passkey is required. Password-only accounts may enroll their first factor after fresh password verification.
3. `totp-enroll` and `totp-confirm` use the same server-side step-up mechanism. The new TOTP code used to confirm the pending authenticator remains a separate value from the step-up TOTP code.
4. `public/app.js` now gathers the correct proof before passkey registration and both TOTP enrollment phases. Existing passkey-removal proof collection uses the same factor-selection helper.
5. The endpoint checks are authoritative; hiding or changing dashboard controls cannot bypass them.

### Regression evidence

`test/webauthn-enrollment-stepup.test.js` exercises the actual `/api/auth` handler:

- A TOTP-protected account cannot register a passkey with session-only credentials.
- A password-only account cannot begin TOTP enrollment without fresh password authentication.
- A password-only account can begin enrollment after supplying the correct password.
- A pending TOTP enrollment cannot be confirmed using only the session and new TOTP code.
- A passkey-only account with password but without an existing passkey assertion receives `428` with `challengeType: "passkey"`.

The legitimate success path for password-only TOTP enrollment is retained. Full physical-authenticator ceremonies were not available in this environment.

## F-15 — WebAuthn counter anomaly and concurrency handling

### Before

The verifier checked `signCount <= priorCount` only when the new counter was also greater than zero. A previously positive counter could therefore revert to zero without triggering the check.

### Changes

1. `isWebAuthnCounterRegression()` defines the counter policy: if the prior counter is positive, the next value must be strictly greater and non-zero; out-of-range/invalid values are rejected.
2. `verifyWebAuthnAssertion()` applies that policy by default. Production login and step-up callers defer the local comparison until after signature verification and then use `advanceWebAuthnCounter()`.
3. `advanceWebAuthnCounter()` performs a per-credential atomic monotonic update. In Upstash/Redis it uses a Lua script; local preview uses a synchronous in-isolate update. A second concurrent assertion with the same counter loses the atomic race.
4. Authenticators that report zero on every assertion remain supported because a zero-to-zero transition is not treated as proof of cloning. A zero-to-positive transition is accepted; once positive, the counter must continue increasing.
5. Counter state is deleted when a passkey is removed or when MFA recovery removes all passkeys.

### Regression evidence

Tests cover positive-to-zero rollback, equal/decreasing counters, zero-counter authenticators, transition from zero to positive, out-of-range values, replay of a counter, and concurrent same-counter assertions. Only one of twenty competing local updates with the same positive counter succeeds.

The shared Redis Lua operation is covered by source/static checks and its local atomic behavior by regression tests; no live Upstash instance was available for an end-to-end remote Lua execution test.

## Previous findings

The earlier F-01–F-13 remediation files and their regression tests are retained in this archive. This change does not intentionally remove the previous WAF, Redis, SDK, PostgreSQL, egress, dashboard, or session fixes.

## Verification

Environment: Node.js v22.16.0, npm 10.9.2.

- Focused new tests: **4 passed, 0 failed**, including a synthetically generated, valid ES256-signed WebAuthn assertion with a counter rollback.
- `npm test`: **270 passed, 0 failed, 0 skipped**.
- `npm run check`: passed; **121** JavaScript/MJS syntax checks, **67** API/SDK imports, static scanner passed, **124** integrity-manifest source entries.
- `npm run build`: passed with disposable local-only secrets, a temporary RSA-3072 clearance key, and a dummy HTTPS-shaped Redis configuration. The build removed Redis credentials from its isolated test subprocess. Temporary credentials and key material were not included in the archive.
- After build verification, the temporary HMAC signature was removed and both distributed manifests were reset to unsigned form for trusted CI signing with the real production `ARIX_MASTER_SECRET`.
- Final ZIP was extracted into a new directory and its `npm run check` and `npm test` were rerun there.

## Remaining production-release limitations

- No physical security key/passkey device, production browser ceremony, or live WebAuthn authenticator was available.
- No live Upstash instance was available; distributed Lua atomicity must be confirmed in staging.
- No live Vercel deployment was performed.
- The repository still has no `package-lock.json`; `npm ci` and `npm audit --omit=dev --audit-level=low` remain open supply-chain release gates. Do not claim the transitive dependency graph has been audited.
- The distributed integrity manifest is unsigned in the archive by design; trusted CI must sign it using the production master secret.

These results establish that the listed regressions are addressed in the tested code paths. They do not prove that the repository is bug-free, free of undiscovered vulnerabilities, or formally ASVS-certified.

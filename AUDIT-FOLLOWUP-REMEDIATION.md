# Independent audit follow-up — 2026-11-03

Scope: the four findings in the follow-up audit against the supplied `arix-shield-chat5-audit-fixed(1).zip`. All results below refer to this source tree and its local test run; they are not a live Vercel or third-party infrastructure penetration test.

## Findings and dispositions

### 1. DPoP key rotation can reset a visitor-only quota — mitigated

The original per-thumbprint bucket is retained, but is no longer the only quota. Browser telemetry now consumes three independent dimensions atomically:

- DPoP thumbprint bucket (default 120/minute, using the project policy value when valid).
- Trusted ingress network-prefix bucket (default 3,600/minute; IPv4 `/24`, IPv6 `/64`).
- Project-wide aggregate bucket (default 60,000/minute; configurable maximum 100,000/minute to match `rateLimitMulti`'s hard input bound).

The `clearance-key` bootstrap action is charged against the same three dimensions. A new DPoP key therefore does not mint a fresh network or project budget. On Vercel, only one syntactically valid platform-provided `x-real-ip` is trusted; ambiguous or missing values are treated as unknown rather than taking the Vercel socket peer (which is platform infrastructure). On self-hosted deployments, the direct socket peer is used; forwarded headers are ignored unless the operator explicitly adapts the trusted ingress.

This mitigates simple key rotation and bounds aggregate volume. It does **not** prevent a distributed proxy network, source-IP churn across many networks, or L3/L4 volumetric attacks before traffic reaches the application.

### 2. Client-side automation signals are forgeable — limitation made explicit and enforcement hardened

This is a real trust-boundary limitation, not a cryptographic bug. Browser flags, keyboard/focus counters, canvas/WebGL values and claimed device properties originate on the client. Encryption to a server public key does not attest the sender's hardware or physical presence. A custom client can fabricate plausible values. The existing one-use PoW has already been raised to 16 bits and is bound to a DPoP thumbprint; that is computational friction, not proof of humanity.

The server-side classifier no longer treats keyboard/focus activity as a positive signal that cancels independent automation indicators. Strong automation indicators or correlated signals remain actionable in `ENFORCE` mode. Clearance responses explicitly include `humanVerified: false` and `botAssessment: "UNTRUSTED_CLIENT_TELEMETRY"`; `CLEARED` denotes completion of the DPoP/telemetry flow only. Sensitive business operations must still require application authentication, authorization, and appropriate step-up verification.

There is no honest code-only way to make arbitrary client telemetry unforgeable without a supported attestation system. The remaining limitation is documented rather than misrepresented as a complete bot-prevention solution.

### 3. Registration did not verify email ownership — remediated for new production signups

New production account registrations require a single-use six-digit verification code delivered through the configured Resend API. Codes expire after ten minutes, are stored only as an HMAC, and have five attempts. The active user, project, session, and integration credentials are created only after verification. Signup initiation and verification are limited by email, trusted source IP/network prefix, and a shared service-wide signup budget (`ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR`, default 10,000/hour, max 100,000/hour).

Email-index transitions and cleanup use compare-and-set / compare-and-delete Redis Lua operations; a failed registration cannot overwrite a newer reservation or delete another registration's index. Partial user/project/key/session records are removed before an account is published.

Production deployment requires `ARIX_RESEND_API_KEY` and `ARIX_EMAIL_FROM` configured with a verified sender. Signup fails closed if email delivery is unavailable or misconfigured; sign-in for existing accounts is unaffected. Accounts created before this control are grandfathered and have not been retroactively verified.

### 4. Dependency tree is not lockfile-reproducible — not completed in this environment

The repository still has no `package-lock.json`. `npm audit --omit=dev --audit-level=low` was run and returned `ENOLOCK`. Generating a correct lockfile requires resolving the complete transitive dependency tree and authenticating registry-provided package integrity metadata. The npm registry could not be resolved from this build environment, and `npm install --package-lock-only` did not complete. No guessed versions or fabricated integrity hashes have been committed.

This is an outstanding supply-chain assurance item, not a demonstrated exploitable runtime vulnerability. Before release, in a network-connected trusted environment using Node 22/npm 10:

```sh
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm ci
npm audit --omit=dev --audit-level=low
npm test
npm run check
```

Review and commit the generated `package-lock.json`. Use `npm ci` for subsequent CI/deploy jobs. Do not treat the lockfile item as fixed until the lockfile is committed and the dependency audit succeeds.

## Verification performed

- `npm test`: **231 passed, 0 failed, 0 skipped**.
- `npm run check`: passed; 116 JavaScript/MJS syntax checks, 66 API/SDK import checks, static scanner passed, 119-source-file manifest verified.
- Controlled `node scripts/build.mjs`: passed with disposable local-only secrets, a generated temporary RSA-3072 test key, and a dummy Upstash-shaped HTTPS endpoint/token. Build subprocess removed Redis credentials for tests. Manifest was reset to unsigned afterwards; no production secrets are bundled.
- Targeted regressions cover rotating DPoP identities, trusted ingress handling, fabricated keyboard/focus signals, email OTP signup, email-delivery cleanup, CAS/conditional deletion, configured rate-limit bounds and global signup throttling.
- `npm audit`: **not available** because the lockfile is absent (`ENOLOCK`).
- Real Vercel deployment, live Upstash Redis Lua execution, Resend delivery/domain verification and production traffic behavior were not independently verified.

No claim of zero undiscovered bugs, full bot detection, L3/L4 DDoS mitigation, or OWASP ASVS certification is made.

# Latest independent audit follow-up — 2026-11-04

Scope: the three new observations against the supplied `arix-shield-chat5-followup-fixed(1).zip`. This report records source-level corrections and local test results. It is not a live Vercel, Upstash, or external penetration-test certification.

## 1. Anonymous local-fallback quota identity — confirmed and remediated

The audited code previously assigned each anonymous request a fresh random actor ID and used that ID as the local quota key. That made a new bucket for each anonymous request in both SDK adapters.

The Node and Next.js SDKs now use a shared `sdk/local-rate-limit.js` implementation. For anonymous requests it builds these independently enforced dimensions:

- A stable aggregate network-prefix bucket (IPv4 `/24`, IPv6 `/64`) shared across routes and methods.
- A network + normalized method + path bucket for route-specific limits.
- A device bucket when a DPoP thumbprint has actually been verified by the SDK's clearance verifier.

The random per-request identity remains available for telemetry and abuse correlation. It is never used as the anonymous quota identity. Authenticated calls continue to use the server-provided stable actor identity.

The store is process-local and hard-capped at 10,000 live dimensions. Expired entries are pruned; live entries are not evicted to make room. Multi-dimensional admission is atomic: if any dimension is exhausted, no other bucket is charged and no new path/device bucket is allocated. This prevents an attacker from filling the store by rotating paths or keys after exhausting the aggregate network bucket. The implementation accepts the same 100 ms minimum window supported by the distributed quota API and caps windows at one hour.

Trusted network identity:

- Vercel: one syntactically valid, bare platform-provided `x-real-ip` value; ambiguous/missing values use the shared `unknown` bucket.
- Node self-hosted: direct socket peer by default. A custom `getClientIp` callback is explicitly an operator-trusted ingress integration and must not read untrusted forwarding headers.
- Next.js self-hosted: provide `getClientIp` from a verified ingress; otherwise anonymous traffic shares the `unknown` bucket.

Default aggregate network budget is 10 times the base route limit (minimum of route quota and configurable `anonymousNetworkRateLimitPerMinute`, capped at 100,000/minute). A network prefix can represent many users behind NAT, so operators should tune this value for their audience. These counters are per process/worker, reset on restart, and do not provide fleet-wide or volumetric DDoS protection. Use the distributed Redis/control-plane quota path for cross-instance enforcement.

Regression coverage runs both actual SDK adapters with 40 anonymous requests from the same IP, route and method at a limit of 10/minute: 10 are admitted and 30 return 429. Additional tests rotate DPoP keys, routes and methods; verify a shared aggregate network budget; fill attacker-controlled paths after quota exhaustion; and exercise bounded-store behavior.

## 2. Security-policy mutations without consistent step-up — confirmed and remediated

The telemetry `policy` action now compares the stored policy with the proposed policy. Every actual change to an accepted security-policy field requires `verifyStepUpCredentials` before persistence, not only a transition from `ENFORCE` to `DRY_RUN`.

Step-up rules:

- Fresh password proof is required.
- TOTP is required when the account has TOTP enabled.
- Passkey-only accounts require a one-time origin-bound WebAuthn assertion; password-only attempts receive HTTP 428 with `challengeType: "passkey"`.
- Accounts with no enrolled second factor may re-authenticate with their password; the server does not demand a factor the owner cannot possess.

The dashboard now prompts for the required step-up proof before submitting policy changes. Successful policy changes are appended to the tamper-evident audit chain with the changed fields and before/after policy view. The raw incident webhook URL is not written to the audit event; only a configured flag and one-way fingerprint are recorded. If persistence succeeds but the audit append fails, the API reports `saved: true` and `auditRecorded: false` with HTTP 503 so the UI/operator can reconcile instead of blindly retrying.

Regression tests verify that policy changes require fresh authentication, passkey-only accounts cannot use password-only re-authentication, and audit events are produced without exposing the raw webhook URL.

## 3. Dependency lockfile and package audit — outstanding release gate

The supplied archive has no `package-lock.json`. A genuine lockfile could not be generated in this environment because npm registry DNS resolution failed:

```text
EAI_AGAIN registry.npmjs.org
```

`npm audit --omit=dev --audit-level=low` therefore returned `ENOLOCK`. No guessed dependency versions or fabricated integrity hashes were added. The direct runtime dependency remains pinned in `package.json`, but the full transitive dependency graph is not reproducible or independently vulnerability-audited yet.

Before production release, use a trusted network-connected Node.js 22/npm 10 environment:

```sh
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm ci
npm audit --omit=dev --audit-level=low
npm test
npm run check
```

Review and commit the generated lockfile only after all commands succeed. Configure subsequent CI/deploy jobs to use `npm ci`. Do not mark supply-chain verification complete until the lockfile and audit report exist.

## 4. Runtime integrity coverage — documented boundary, not a new defect

The runtime integrity verifier intentionally checks the API route/shared-library tree covered by its documented contract. It does not claim whole-repository runtime attestation for `sdk/`, `edge/`, `proxy.js`, or `public/`. This scope is explicitly documented in the operations and hardening notes. No unsupported claim of whole-repository runtime attestation is made.

## Verification performed

- `npm run check`: passed; 119 JavaScript/MJS syntax checks, 67 API/SDK import checks, static scanner passed, and 122 source-file integrity manifest entries verified.
- `npm test`: **242 passed, 0 failed, 0 skipped**.
- `npm run build`: passed using disposable local-only preflight values, a temporary RSA-3072 key and a dummy Upstash-shaped HTTPS endpoint/token; the build's own 242-test suite passed. No temporary secrets were included in the archive.
- After the controlled build, manifests were regenerated unsigned for the source archive so the operator's own Vercel `ARIX_MASTER_SECRET` can sign the deployment build; there are no fixture signatures or secrets in the ZIP.
- Fresh ZIP extraction, CRC verification, `npm run check`, and `npm test` are release checks to be run against the final packaged copy before delivery.
- `npm audit`: not available; no lockfile and registry resolution failed (`EAI_AGAIN`, then `ENOLOCK`).
- Live Vercel deployment, multi-instance Upstash behavior, real ingress IP behavior, WebAuthn browser ceremonies, and independent penetration testing were not performed.

No claim of zero undiscovered defects, global rate-limit enforcement in process-local mode, DDoS scrubbing, or OWASP ASVS certification is made.

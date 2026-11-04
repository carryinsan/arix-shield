# ArixShield v1.4.4 consolidated hardening build report

## Release scope

Package version: **1.4.4**. This consolidated source tree uses v1.4.3 as its coherent base and selectively integrates compatible security controls from both supplied v1.4.2 archives. The merge policy, exact source inputs, deduplication decisions, and exclusions are recorded in `docs/CONSOLIDATION-REPORT.md`.

The repository includes the hybrid API security SDK and Vercel control plane, a bounded Node.js 22 edge reverse proxy, Ed25519 origin proofs, Redis-backed shared replay/rate-limit state, AES-256-GCM envelope encryption helpers, identity-risk and recovery controls, WAF/parser validation, threat-feed and audit helpers, PostgreSQL RLS helpers, optional Linux host attestation, optional SNI/mTLS gateway admission, framework-independent Vercel edge-clearance proxy (`proxy.js`), request-scoped DB access receipts, explicit database adapters, bounded process-fetch egress guard, optional egress-agent/firewall tooling, incident-alert outbox retry, and hardened deployment examples.

One pinned first-party runtime helper, `@vercel/functions@3.10.5`, is declared for framework-independent Vercel Routing Middleware; no production credential is bundled. The existing Upstash Redis primary remains the shared distributed security-state dependency. The alternate independent Redis failover path from one source archive was intentionally not imported because it could permit security-state divergence. The optional WAL-backed state service is not a Redis/Lua replacement and is not automatically enabled.

## v1.4.4 consolidation additions

- SNI allowlisting and TLS listener admission, optional client-certificate mTLS, bounded connection ceilings, and pressure-based shedding in `edge/gateway.mjs`. These are process-local application-gateway controls, not volumetric DDoS or SYN-flood protection.
- Optional Vercel Routing Middleware edge-clearance support (framework-independent `proxy.js`, no Next.js runtime dependency), canonical base64url validation for both HMAC ticket segments in Node and edge runtimes, and request-scoped database-access receipts. The dashboard explicitly binds its threat-feed warning and audit-witness controls instead of relying on browser-created ID globals.
- Explicit PostgreSQL/MySQL/SQLite adapter guardrails and an RLS migration generator that uses a transaction-scoped advisory lock and refuses privileged migration roles. The operator must supply and review the real schema allowlist.
- Optional process fetch egress guard and host firewall rule generation. The process guard intercepts `globalThis.fetch`; it does not intercept raw sockets, Node `http`/`https`, native add-ons, child processes, or kernel traffic.
- Durable alert retry/dead-letter support layered on the existing Upstash primary. Delivery is at-least-once; downstream consumers should deduplicate by event/outbox identifier.
- Hardened Docker/Compose examples, a strict seccomp allowlist, optional single-primary WAL/quorum service for separate evaluation, CIDR-scoped host nftables bootstrap, and an opt-in Node egress preload. The host bootstrap changes no state without an explicit apply flag.

## Generated integrity metadata

The canonical source manifest is `docs/INTEGRITY-MANIFEST.json`, mirrored byte-for-byte at `api/_integrity-manifest.json`. The distributed files contain SHA-256 hashes but no HMAC signature; they are intentionally unsigned so the operator can sign them with the actual production master secret in trusted CI. `npm run check` validates the manifest, its mirror, imported modules, syntax, and the repository's static scanner. Do not manually edit the generated metadata markers.

<!-- ARIX-MANIFEST-FILE-COUNT:126 -->
<!-- ARIX-MANIFEST-ROOT:e04cc3e36b13878c1bd3fb7f18a53ca88364431091bc61bb24031f3ab4f9a99c -->
<!-- ARIX-SECURITY-CONSTANTS:RSA_MIN_BITS=3072;SCRYPT_N=32768;SCRYPT_R=8;SCRYPT_P=3;LEGACY_PBKDF2_ITERATIONS=600000;HIBP_LOOKUP_TIMEOUT_MS=400 -->

## Local verification

Runtime: Node.js v22.16.0, Linux x64. Results are local and deterministic unless explicitly described otherwise. The Vercel runtime integration was validated against the published framework-independent Routing Middleware contract, but not deployed to the live Vercel project from this environment.

| Verification | Result |
|---|---:|
| `npm test` (current replay-cache final tree) | **276 passed, 0 failed, 0 skipped**; 251 top-level TAP test records; ~16.0 seconds on clean extraction |
| `npm run check` (current replay-cache final tree) | **123 JS/MJS syntax checks, 68 API/SDK imports; static scanner passed; exact dependency allowlist passed (`@vercel/functions@3.10.5`); 126-file source manifest verified** |
| `node scripts/build.mjs` (current replay-cache final tree) | **Controlled production build preflight passed** with disposable test-only secrets, a generated temporary RSA-3072 key and a dummy Upstash-shaped HTTPS URL/token; the isolated test subprocess removed Redis credentials; all 276 tests passed; manifest reset to unsigned afterwards |
| `npm audit --omit=dev --audit-level=low` | **Not available: `ENOLOCK`**, because this repository still lacks `package-lock.json`; see `docs/DEPENDENCY-LOCKFILE.md` and `AUDIT-FOLLOWUP-REMEDIATION.md` |
| `npm run audit:verify` | Not run; requires a real signed audit bundle and production signing secret |
| Compose deployment profiles | Not run; Docker/Podman was unavailable |
| Customer infrastructure / production PKI / database | Not available; not tested |
| Vercel Routing Middleware | **10 targeted local regression tests passed**; real Vercel deployment/runtime package installation not executed |
| Supplied brutal test pack v1.0.0 | **Previous backend candidate clean-extraction run: 30 passed, 0 failed, 0 skipped**; 50,000 soak operations; 12 OS race workers; 256 KiB inspection p50 2.41 ms / p99 4.54 ms / max 32.20 ms (5 ms p99 gate). Not rerun after the latest replay-cache changes; treat these stress figures as historical, not current validation. One earlier local run measured 5.05 ms and missed only this host-sensitive timing gate; it was not relaxed. Event-loop p99 53.90 ms raised `EVENT_LOOP_LAG`; authenticated-traffic preservation passed |
| Independent ASVS / penetration assessment | Not performed |

A current test transcript and fuller limitations are in `results/TEST-RESULTS-SUMMARY.md` and `results/full-test.tap.txt`. Historical lab/endurance files in `results/` are retained as historical evidence and were not rerun on this v1.4.4 consolidation.


## Dashboard runtime correction (2026-11-03)

The dashboard rendered `feedWarning` without declaring a DOM reference. This raised `ReferenceError: feedWarning is not defined` during the first telemetry poll, which caused the dashboard connection status to flip to `DISCONNECTED`. The same initialization block also used `witnessStatus` and `auditDownload` without explicit declarations; those failures would have surfaced after the first error was corrected.

- Added explicit bindings for `#threat-feed-warning`, `#audit-witness-status`, and `#download-audit-bundle` in `initDashboard()`.
- Made the audit export button's completion-state reset null-safe.
- Added `test/dashboard-dom-bindings.test.js` to ensure all three elements exist in the dashboard markup and are explicitly bound in the client script.
- Verification after this patch: **208/208 tests passed**, **114 JavaScript/MJS syntax checks**, **66 API/SDK imports**, static scanner passed, and the **117-file integrity manifest** was regenerated and verified.
- Controlled `node scripts/build.mjs` production preflight passed with disposable local-only secrets and a temporary RSA-3072 clearance key. The distributed manifest was reset to unsigned for trusted CI signing.
- A real browser session and live Vercel deployment were not available for this patch; confirm the dashboard returns to `LIVE · 5S POLL` after deploying the new archive.

## Password corpus limitations

The built-in XOR filter is generated from 89 curated weak-password examples. A bounded exact-root check strips predictable trailing digits and punctuation before checking known roots. This is not a verified large breach corpus. `scripts/compile-breach-filter.mjs` can compile an operator-supplied, licensed local word list. A negative lookup is not proof that a password has never been breached.

## Production release procedure

The distributed archive contains **no production master secret, cron secret, Upstash token, origin private key, clearance private JWK, or customer PKI material**. In trusted CI, configure independent production values for `ARIX_MASTER_SECRET`, `CRON_SECRET`, `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `ARIX_CLEARANCE_KID`, and `ARIX_CLEARANCE_PRIVATE_JWK`, then run:

```bash
NODE_ENV=production npm run build
```

Do not use the disposable smoke-test credentials from the local verification. Configure all operator-managed SNI/mTLS certificates, TLS termination trust, origin proofs, network allowlists, container/kernel controls, DB allowlists/RLS, shared Redis, alert destinations and host policies in the actual deployment environment. Verify through the real ingress before cutover.

## Engineering boundaries and known limitations

- The edge gateway is an application-layer HTTP/1 proxy with per-process connection/request limits, TLS/mTLS options and optional SNI allowlisting. It does not provide global L3/L4 DDoS scrubbing, SYN-cookie protection, volumetric flood absorption, or network-layer origin restriction; managed ingress mitigation and firewall allowlisting remain required.
- PostgreSQL RLS helpers act only on explicitly supplied table allowlists and adapter transactions. They are not automatically connected to an unknown customer schema. Runtime roles must be non-superuser and NOBYPASSRLS; migrations and actual access paths require customer validation.
- MySQL/SQLite guard helpers are explicit adapters, not universal ORM/client interception. Unsupported query paths or raw clients can bypass wrappers; inventory and code review are required.
- The process egress guard covers `globalThis.fetch` only. Other network mechanisms require OS/container/network policy.
- The optional state service is a WAL-backed single-primary/quorum design, not a drop-in Upstash Redis or Redis Lua runtime, and must not be treated as active-active consensus without a separate fault-model review.
- Incident alert retries are at-least-once, not exactly-once. A downstream endpoint must deduplicate event identifiers. The existing primary Redis store must be configured and monitored.
- Audit ratchet helpers require an atomic persistent storage adapter and independent key custody/retention; they are not by themselves a WORM platform.
- File/archive scanning remains bounded and heuristic; no complete AV/YARA corpus, full hostile-file sandbox or exhaustive parser implementation is claimed. Prompt canaries do not make prompt injection impossible. MCP approvals must be enforced at every tool invocation.
- Process-local test/default adapters do not establish cross-region correctness. Distributed quotas, replay protection, SOC retention, backup, disaster recovery and RPO/RTO require live shared infrastructure and fault-injection tests.
- The repository's static scanner is lexical and is not a complete AST/data-flow SAST, SCA, secret scanner, SLSA provenance generator, DAST or penetration test.

## OWASP ASVS 5.0.0 status

**This archive is not claimed to be OWASP ASVS 5.0.0 Level 3 compliant or certified, and no highest-Level-3 score is claimed.** Selected controls have tests and supporting evidence, but complete Level 3 verification requires a full applicable-requirement assessment against the real application, infrastructure, data flows, configuration and operational evidence, followed by independent assessor review.

## Required pre-production work

1. Sign integrity manifests in trusted CI with production secrets; protect and rotate all key material and credentials.
2. Inventory all API routes, identities, ORM/database clients, jobs, webhooks, GraphQL resolvers, and outbound connections.
3. Provision and verify tenant RLS on every relevant table using the real schema and a non-BYPASSRLS runtime role.
4. Validate TLS/SNI/mTLS handshakes, origin isolation, certificate rotation, firewall rules, rate limits and managed DDoS controls against the production ingress.
5. Configure shared Redis and verify quota/replay/session/audit/alert consistency during outage and recovery.
6. Apply and verify host/container seccomp, non-root, capabilities, `NoNewPrivs`, filesystem, egress and secret-management policies.
7. Run live integration, backup/restore, disaster-recovery, external SAST/SCA/secret scans, DAST and independent penetration tests. Map all applicable ASVS 5.0.0 Level 3 requirements before making any compliance statement.

## Follow-up audit — 11 implementation findings (2026-11-03)

The follow-up audit identified defects in decrypted browser-clearance inspection, account risk/lockout handling, Redis index TTL updates, browser PoW replay, capability-bearing IDs, WAF path/multipart inspection, PostgreSQL transaction/SQL parsing, sensitive-action step-up, automation verdict handling, alert outbox retry/local commands, and BOLA route normalization. The remediation and important qualifications are recorded in `AUDIT-11-REMEDIATION.md`.

- Repository tests after the audit fixes: **223 passed, 0 failed**.
- Static integrity check: **118 files**, 115 JavaScript/MJS syntax checks, 66 import checks, static scanner passed.
- Deterministic WAF corpus: **200,000 cases** (100,000 adversarial and 100,000 benign), with 100,000 attack detections, 0 misses, 100,000 benign allowed, and 0 false positives on this corpus.
- Local in-process endurance: **801,000 operations over 15 seconds**, concurrency 8, 0 invariant errors; approximately 53,390 operations/second, peak RSS approximately 68.7 MiB.
- Controlled `node scripts/build.mjs` preflight: passed with isolated, disposable local test settings; all 223 tests passed inside the build.

These local results are not proof of zero vulnerabilities. No live Upstash Redis, production PostgreSQL instance, actual Vercel deployment, external webhook receiver, or real-device WebAuthn ceremony was available. Rich-text SQL grammar exclusions remain intentional and are documented in `AUDIT-11-REMEDIATION.md`; non-SQL WAF checks still apply to those fields. A production-like staging test and independent security assessment remain release gates.


## Follow-up independent audit (2026-11-03)

A second independent review identified four further concerns. The browser quota now has per-DPoP, trusted-network and project-wide dimensions, including the `clearance-key` bootstrap action; client-side automation signals are explicitly treated as forgeable risk inputs rather than proof of humanity; new production signups require email OTP before credentials are created and use atomic email-index publication/cleanup; and the signup path has a shared service-wide rate budget. The follow-up tests pass **231/231**.

**Open supply-chain item:** no lockfile was generated because npm registry resolution was unavailable in this environment. The attempted `npm audit --omit=dev --audit-level=low` returned `ENOLOCK`. No lockfile with guessed transitive dependencies or fabricated integrity hashes was added. Generate and commit a registry-resolved `package-lock.json` in a trusted network-connected environment, then run `npm ci` and `npm audit` before release. See `AUDIT-FOLLOWUP-REMEDIATION.md` for exact dispositions and the remaining limitations.

## Latest independent audit follow-up — 2026-11-04

- Anonymous Node and Next.js SDK local-fallback quotas now use stable network-prefix, route and verified-device dimensions; random request IDs are not quota identities. The process-local store is capped, atomically charges dimensions, and does not allocate per-route/device counters for denied requests. The documented process/worker limitation remains.
- Every actual security-policy mutation now requires fresh password proof and the enrolled second factor (TOTP or passkey-only WebAuthn step-up), and successful policy changes are added to the audit chain without logging raw webhook URLs.
- `npm run check` passed with 119 JavaScript/MJS syntax checks, 67 API/SDK imports, static scanner pass and 122 manifest entries.
- `npm test` passed with 243 tests after the final 100 ms local-quota window compatibility regression was added.
- `npm run build` passed using disposable build-fixture secrets and key material; the complete build test suite passed. Fixture secrets were not packaged and the source manifests were reset unsigned for the operator's deployment secret.
- Dependency lockfile remains an outstanding release gate: npm registry DNS resolution returned `EAI_AGAIN`, and `npm audit --omit=dev --audit-level=low` returned `ENOLOCK`. No fabricated lockfile was added.
- See `AUDIT-LATEST-FOLLOWUP-REMEDIATION.md` for detailed findings, assumptions, test scope and outstanding production checks.


## Latest independent audit remediation — 2026-11-04 (F-11 to F-13)

The latest code review reported three additional implementation defects. The supplied source reproduced all three:

- **Authenticated local quota path bypass:** the authenticated local quota key previously included HTTP method and pathname. The local fallback now uses one stable actor bucket across all methods and paths. This avoids both path-based quota resets and route-key churn for authenticated actors. Anonymous network-prefix and optional verified-device controls remain unchanged.
- **PostgreSQL RLS quoted-column false acceptance:** policy-expression normalization previously lowercased and removed all identifier quotes, conflating case-sensitive quoted identifiers with lowercase unquoted names. The normalizer now preserves quoted identifier spelling, and the migration's idempotence check additionally queries `pg_depend` / `pg_attribute` to verify the actual referenced tenant-column attribute number. A mismatching existing policy fails closed as a conflict.
- **Configured egress response-size cap ignored:** `arixSafeFetch` now validates the `maxResponseBytes` option and its HTTPS response reader checks both a declared Content-Length and streamed bytes, aborting the request immediately when the configured cap is exceeded. The process egress firewall already forwarded this option; the safe transport now enforces it.

Regression coverage includes authenticated path/method churn through both Node and Next SDKs, quoted mixed-case RLS tenant-column false-match and catalog-dependency verification, and response streaming at, below, and above the configured byte ceiling. Focused regression tests passed before the full suite.

**Production qualification:** PostgreSQL catalog behavior was validated by SQL-shape and mocked migration-client tests, not a live PostgreSQL instance. No network-backed HTTPS response integration was run; the streaming enforcement helper and firewall option propagation were tested locally. The dependency lockfile remains absent, so npm SCA audit and reproducible `npm ci` remain open release gates. Production Vercel deployment was not performed. These changes do not establish that the repository is bug-free or formally certified.

### Final follow-up verification — 2026-11-04 (F-11 to F-13)

- Full repository test suite: **266 passed, 0 failed, 0 skipped** (`npm test`).
- Targeted local-quota, PostgreSQL RLS and process-egress regression group: **33 passed, 0 failed**.
- `npm run check`: passed; **120** JavaScript/MJS syntax checks, **67** API/SDK imports, static scanner passed, **123** source entries in the verified manifest.
- `npm run build`: passed with disposable, locally generated test credentials and a temporary RSA-3072 clearance key. The temporary signing secret/key and fake Upstash values were not included in the archive. The build's signed manifest was reset to unsigned for trusted CI signing before packaging.
- Final follow-up tests cover authenticated SDK local quota aggregation across unique paths in both adapters, exact quoted PostgreSQL tenant-column matching plus `pg_depend` catalog checks, and configured egress response-size enforcement during streaming.
- A genuine lockfile generation was attempted with Node.js 22/npm 10, but `registry.npmjs.org` returned `EAI_AGAIN`. No lockfile was fabricated; `npm ci` and `npm audit --omit=dev --audit-level=low` remain open release gates.
- No live Vercel deployment, real Upstash instance, or PostgreSQL server was used. See `AUDIT-F11-F13-REMEDIATION.md` for scope and limitations.

## Latest independent WebAuthn/MFA follow-up — 2026-11-04 (F-14 to F-15)

- Passkey registration now requires server-side fresh password proof plus an existing enrolled factor where configured. TOTP enrollment start and confirmation receive equivalent protection. The dashboard collects password/TOTP or password/existing-passkey proof; the API remains the enforcement authority.
- WebAuthn counter policy now rejects positive-to-zero, equal, or decreasing transitions. A per-credential atomic counter update is applied after cryptographic signature verification in login and passkey step-up paths. Authenticators that continually report zero remain compatible; once an authenticator reports a positive counter, it must continue increasing.
- Counter keys are removed when the associated passkey is removed or MFA recovery resets passkeys.
- New focused regressions: 4 passed, including a genuinely signed ES256 WebAuthn assertion with positive-to-zero rollback, API-handler checks for passkey/TOTP enrollment step-up, and concurrent counter-update checks.
- `npm test`: **270 passed, 0 failed, 0 skipped**.
- `npm run check`: passed; **121** JavaScript/MJS syntax checks, **67** imports, static scanner passed, **124** integrity source entries verified.
- Controlled `npm run build`: passed with disposable build-only credentials and a temporary RSA-3072 key. Temporary credentials were not packaged; manifests were reset to unsigned form for trusted production signing.
- No live Vercel, Upstash, or physical WebAuthn authenticator was available. The atomic Redis Lua path still requires staging confirmation.
- Dependency release gate remains open: no `package-lock.json` is present, so `npm ci` and `npm audit --omit=dev --audit-level=low` have not been completed. See `docs/DEPENDENCY-LOCKFILE.md`.
- Full disposition, code paths, tests, and limitations are in `AUDIT-F14-F15-REMEDIATION.md`.

## Latest independent replay-cache audit remediation — 2026-11-04

The latest independent review identified an unbounded degraded-mode outage-proof replay map and a process-wide DPoP replay cache that performed a full-map expiry scan and had no per-project fairness.

- Degraded-mode outage proofs are now signed with project and trusted requester-prefix scope binding. Proof-of-work validation checks signature, target, expiry and difficulty before admission. The local read quota is synchronously admitted before the replay record is inserted; a quota-denied proof does not consume replay-cache capacity. Duplicate proofs return HTTP 429, and replay/quota-store capacity exhaustion fails closed with HTTP 503.
- Outage replay storage is hard-bounded at 32,768 records globally, 8,192 per project and 256 per project/requester prefix. It retains every unexpired replay record and refuses new entries when a cap is reached; it never evicts live proofs.
- Expiry cleanup uses a min-heap rather than scanning the entire replay map on each request. The degraded-mode read quota store is also bounded at 20,000 buckets globally and 4,000 per project, with expiry-driven cleanup and fail-closed capacity handling.
- DPoP replay records use a bounded expiry-heap cache with 131,072 global, 32,768 per-project and 16,384 per-project/key-thumbprint limits for local verification fallback. Active entries are never evicted to make room. Local request-bound fallback retains entries for 91 seconds; Redis-backed standard DPoP replay records use a 121-second TTL to cover inclusive timestamp boundaries.
- The Redis-backed DPoP verifier relies on Redis atomic one-use consumption instead of duplicating every durable replay record in the process-local map. Production clearance verification passes its durable replay-consumption callback into request-bound DPoP verification. The process-local fallback remains for standalone/local verification and is documented as process-specific.
- Regression coverage added in `test/replay-cache-hardening.test.js`: hard-cap enforcement, per-project/requester fairness, expiry pruning, replay rejection, proof-to-project/requester binding, quota-before-insertion, bounded local quota buckets, and durable DPoP callback behavior. The adversarial test's Redis fake now models atomic `SET NX` semantics rather than returning `OK` for every duplicate.
- `npm test`: **276 passed, 0 failed, 0 skipped**.
- `npm run check`: passed; **123** JavaScript/MJS syntax checks, **68** API/SDK imports, static scanner passed, and **126** integrity-manifest source entries verified.
- Controlled `npm run build`: passed with disposable build-only secrets, a temporary RSA-3072 clearance key and dummy Upstash-shaped HTTPS configuration. The build runs all 276 tests in an isolated local test environment. Temporary values were not packaged; manifests were reset to unsigned form for trusted CI signing.

**Remaining release gates:** no `package-lock.json` is included; `npm ci` and `npm audit --omit=dev --audit-level=low` remain outstanding. No live Vercel deployment, Upstash instance, PostgreSQL server, or external replay/cache cluster was exercised. The replay caches described here are process-local protections; distributed replay correctness depends on the production Redis callback and must be checked in staging.

## Vercel build regression correction — 2026-11-04

The user-reported Vercel build failure was reproduced locally with `VERCEL=1`: the session-rotation grace regression test sent the development-only `arix_session` cookie while the production session reader correctly requires `__Host-arix_session` on Vercel. The test fixture now selects the cookie name from the same `VERCEL`/production condition as `getSession()`. Its security assertions were retained; no production cookie or session enforcement was weakened.

- Pre-fix reproduction: focused regression failed under `VERCEL=1` and passed without it.
- Post-fix focused regression: passed under `VERCEL=1`.
- Full Vercel-like suite (`VERCEL=1 NODE_ENV=test npm test`): **276 passed, 0 failed, 0 skipped**.
- `npm run check` equivalent (`NODE_ENV=test node scripts/check.mjs`): passed; **123** JavaScript/MJS syntax checks, **68** API/SDK imports, static scanner passed, **126** integrity-manifest entries verified.
- Controlled Vercel-like production build (`VERCEL=1 VERCEL_ENV=production NODE_ENV=production npm run build`): passed, including all **276** tests. Temporary build-only secrets and RSA key material were not packaged. The manifests were reset unsigned for trusted deployment signing.
- This is local Vercel-environment verification, not a deployment to the live Vercel project. Existing dependency-lockfile/SCA and live-infrastructure release gates remain open.

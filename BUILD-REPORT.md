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

<!-- ARIX-MANIFEST-FILE-COUNT:122 -->
<!-- ARIX-MANIFEST-ROOT:bf91ab4077572ed87847c2e1a4e453802c1c3a17bb2feb5c13fa93aa12633d88 -->
<!-- ARIX-SECURITY-CONSTANTS:RSA_MIN_BITS=3072;SCRYPT_N=32768;SCRYPT_R=8;SCRYPT_P=3;LEGACY_PBKDF2_ITERATIONS=600000;HIBP_LOOKUP_TIMEOUT_MS=400 -->

## Local verification

Runtime: Node.js v22.16.0, Linux x64. Results are local and deterministic unless explicitly described otherwise. The Vercel runtime integration was validated against the published framework-independent Routing Middleware contract, but not deployed to the live Vercel project from this environment.

| Verification | Result |
|---|---:|
| `npm test` (latest follow-up tree) | **231 passed, 0 failed, 0 skipped**; 206 top-level TAP test records; ~11.9 seconds |
| `npm run check` (latest follow-up tree) | **116 JS/MJS syntax checks, 66 API/SDK imports; static scanner passed; exact dependency allowlist passed (`@vercel/functions@3.10.5`); 119-file source manifest verified** |
| `node scripts/build.mjs` (latest follow-up tree) | **Controlled production build preflight passed** with disposable test-only secrets, a generated temporary RSA-3072 key and a dummy Upstash-shaped HTTPS URL/token; the isolated test subprocess removed Redis credentials; manifest reset to unsigned afterwards |
| `npm audit --omit=dev --audit-level=low` | **Not available: `ENOLOCK`**, because this repository still lacks `package-lock.json`; see `docs/DEPENDENCY-LOCKFILE.md` and `AUDIT-FOLLOWUP-REMEDIATION.md` |
| `npm run audit:verify` | Not run; requires a real signed audit bundle and production signing secret |
| Compose deployment profiles | Not run; Docker/Podman was unavailable |
| Customer infrastructure / production PKI / database | Not available; not tested |
| Vercel Routing Middleware | **10 targeted local regression tests passed**; real Vercel deployment/runtime package installation not executed |
| Supplied brutal test pack v1.0.0 | **Previous backend candidate clean-extraction run: 30 passed, 0 failed, 0 skipped**; 50,000 soak operations; 12 OS race workers; 256 KiB inspection p50 2.41 ms / p99 4.54 ms / max 32.20 ms (5 ms p99 gate). Not rerun after the dashboard-only JavaScript correction. One earlier local run measured 5.05 ms and missed only this host-sensitive timing gate; it was not relaxed. Event-loop p99 53.90 ms raised `EVENT_LOOP_LAG`; authenticated-traffic preservation passed |
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

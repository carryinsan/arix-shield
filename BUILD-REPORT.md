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

<!-- ARIX-MANIFEST-FILE-COUNT:117 -->
<!-- ARIX-MANIFEST-ROOT:03fba4ea80d11daa4445c4c2d5dd9b4cd4958cc0b018e8f3421ea20c7cf6a257 -->
<!-- ARIX-SECURITY-CONSTANTS:RSA_MIN_BITS=3072;SCRYPT_N=32768;SCRYPT_R=8;SCRYPT_P=3;LEGACY_PBKDF2_ITERATIONS=600000;HIBP_LOOKUP_TIMEOUT_MS=400 -->

## Local verification

Runtime: Node.js v22.16.0, Linux x64. Results are local and deterministic unless explicitly described otherwise. The Vercel runtime integration was validated against the published framework-independent Routing Middleware contract, but not deployed to the live Vercel project from this environment.

| Verification | Result |
|---|---:|
| `npm test` | **208 passed, 0 failed, 0 skipped**; 183 top-level TAP tests; ~5.8 seconds |
| `npm run check` | **114 JS/MJS syntax checks, 66 API/SDK imports; static scanner passed; exact dependency allowlist passed (`@vercel/functions@3.10.5`); 117-file manifest verified** |
| `node scripts/build.mjs` | **Controlled production build preflight passed** with disposable test-only secrets, a generated temporary RSA-3072 key and a dummy Upstash-shaped HTTPS URL/token; the isolated test subprocess removed Redis credentials; manifests reset to unsigned afterwards |
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

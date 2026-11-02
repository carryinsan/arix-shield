# ArixShield v1.4.2 hardening build report

## Release scope

This archive is a complete copy of the supplied repository with an additional hardening increment. Package version: **1.4.2**. It adds reusable security primitives and offline compiler tools across several of the submitted domains while preserving a strict distinction between code present in the repository and end-to-end controls that still require application, database, key-custody, edge, container, or operator integration. The exact matrix is `docs/V3-IMPLEMENTATION-STATUS.md`; the incremental change log is `docs/V3.1-HARDENING-NOTES.md`.

Notable additions in this release include a runnable independent application-layer `edge/` reverse proxy with bounded HTTP handling, TLS/mTLS options, absolute upstream deadlines, header/framing sanitization and Ed25519 origin proofs; origin proof verification before API handler dispatch with shared Redis nonce replay protection; transparent AES-256-GCM envelope encryption for user and project Redis records with tenant-bound DEKs and atomic plaintext migration; login/password-step-up risk decisions; and a corrected high-confidence bot-signal threshold. Existing breach-filter, account recovery, file/archive inspectors, policy/RLS compilers, WAF signatures, MCP guard, threat-feed and SimHash, SOC, audit-ratchet and DR helpers remain, with the integration boundaries listed below.

No third-party runtime dependency or new vendor API key was added. The Ed25519 origin keypair is optional key material generated locally by the operator; it is not an API key. These modules are not all automatically activated by the SDK. The repository still does not contain global DDoS scrubbing, universal ORM interception, a native distributed consensus cluster, process-wide egress enforcement, a complete YARA/signature malware scanner or isolated hostile-file sandbox, signed SLSA provenance, a durable active-active outbox, or customer network policy.

## Generated integrity metadata

The canonical manifest is generated at `docs/INTEGRITY-MANIFEST.json`; `npm run integrity:update` writes an identical API-bundled mirror at `api/_integrity-manifest.json`. Both contain hashes only and are unsigned in the distributed archive. `npm run check` verifies source hashes, generated metadata and exact mirror equality. Do not edit generated markers manually.

<!-- ARIX-MANIFEST-FILE-COUNT:108 -->
<!-- ARIX-MANIFEST-ROOT:94ebd13d305fb3665299fa5d3306e15000363c82e4645bbad06b9482b2e0d359 -->
<!-- ARIX-SECURITY-CONSTANTS:RSA_MIN_BITS=3072;SCRYPT_N=32768;SCRYPT_R=8;SCRYPT_P=3;LEGACY_PBKDF2_ITERATIONS=600000;HIBP_LOOKUP_TIMEOUT_MS=400 -->

## Local verification

Environment: Node.js 22.16.0. Results are from local deterministic tests and static checks, not a production deployment.

| Verification | Result |
|---|---:|
| `npm test` | **149 passed, 0 failed** |
| v1.4.2 focused regressions | **7 focused tests** for bot risk boundaries, edge-to-origin signing/replay rejection, user/project record encryption, and atomic legacy-record migration |
| Supplied regression adversarial input corpus | **2,500 / 2,500** deterministic grammar/encoding/boundary mutation cases blocked |
| Supplied regression benign input corpus | **2,500 inputs; no false positives observed in this test corpus** |
| Existing actor / tenant / method / identifier placement matrix | **80 local mocked cases** |
| Existing concurrent quota / DPoP / outage harness | **100-way local/injected-adapter harness** |
| `npm run check` | **105 JS/MJS syntax checks, 55 API/SDK imports; lexical and secret-pattern scanner passed; zero third-party dependencies; 108-source-file manifest and API runtime mirror verified** |
| 50,000-entry synthetic XOR-filter benchmark | **~324 ms, 0 false negatives across the synthetic build test; not a real breach-corpus validation** |
| `npm run audit:verify` | Not run; requires a real audit bundle and its signing secret |
| Fresh 200k deterministic lab | **100,000 adversarial + 100,000 benign; 100,000/100,000 adversarial blocked, 100,000/100,000 benign allowed; 0 misses, 0 false positives** on the generated corpus. Runtime 13.17 s; ~15,182 vectors/s. |
| Fresh endurance smoke | **253,170 requests in 10 seconds, 8 in-process workers, 0 invariant errors**; ~25,317 requests/s and peak RSS ~57.1 MiB. This is not network/database endurance. |
| `npm run build` | **Controlled smoke run passed** using throwaway non-deployable master/cron secrets, a generated temporary RSA-3072 key and a dummy HTTPS-shaped Redis endpoint; 149 tests passed. The temporary production signature was removed by regenerating both distributed manifests unsigned. The test subprocess dropped Redis credentials and `VERCEL_ENV` to avoid touching live services. The signed manifest was re-generated unsigned before packaging; no real customer credentials or live Redis were used. |
| Production runtime attestation | Not run against a production-like deployment |

These tests are regression evidence, not proof of a universal block rate, a real-world false-positive rate, security against all attackers, or absence of defects. New tests exercise helpers with local/injected adapters; they do not verify integration into every customer route or production storage provider. The concurrency harness uses local/injected test adapters and is not a live distributed Redis chaos test. No production customer origin, database, cloud account, or external webhook was available.

## Password corpus and XOR filter limitations

The bundled default XOR filter is generated from **89 curated weak-password examples**. A bounded exact-root check also strips predictable trailing digits and punctuation before checking known roots. It is not the requested verified 50,000/250,000-password breach dataset, and it must not be marketed as one. `scripts/compile-breach-filter.mjs` compiles an operator-supplied, licensed local word list into a deterministic 16-bit three-part XOR filter. At the configured load factor this representation uses approximately 2.6 bytes per unique entry and has an approximate 1/65,536 fingerprint false-positive probability. A negative lookup is not proof that a candidate password has never been breached. No network download occurs during build.

## Production release steps

The distributed archive contains **no production master secret, origin private key, or private JWK**. Both integrity manifest copies are intentionally unsigned. Before production deployment, run the production build in trusted CI with the existing production secrets and key material; it signs both manifests, validates the source tree, and runs the deterministic tests:

```sh
# Export the existing production values in trusted CI, then run:
NODE_ENV=production npm run build
```

Configure the same existing master secret, shared Redis URL/token, `CRON_SECRET`, and the generated `ARIX_CLEARANCE_KID` / `ARIX_CLEARANCE_PRIVATE_JWK` in the production environment. Keep private values server-side. Generate origin key material only for a deployment that also installs the matching origin gateway/ingress controls. Verify `/api/health` after deployment and exercise the application through its actual ingress. Do not commit deployment secrets into this archive.

## Engineering boundaries and known limitations

- The supplied brief named Domains 1–17 but referred to 18. No Domain 18 definition was supplied.
- `edge/gateway.mjs` is a deployable HTTP/1.1 application reverse proxy. `api/_lib/vercel-handler.js` verifies its signed proof before dispatch when origin lock is enabled. This does not provide global DDoS scrubbing or network-layer origin restriction; a valid signed proof is not a substitute for managed ingress DDoS mitigation, firewall allowlisting and live key/certificate operations.
- The Prisma proxy only guards calls made through the wrapped client and supported operations. No universal SQL AST, Mongo, MySQL or SQLite interception is claimed. The policy compiler and PostgreSQL RLS SQL generator produce artifacts for review; they do not automatically guard production boot or apply migrations.
- Account recovery is wired through `recover-mfa`; login and password-based step-up also consult recent-failure identity risk. First MFA enrollment returns eight recovery codes once. A passkey follow-up uses the dedicated passkey login flow; it is not transaction-bound to the preceding password challenge. Shared Redis `SET NX` is required for cross-instance atomicity; local preview is process-local.
- ZIP inspection checks central-directory/local-header agreement, data descriptors and CRC-32 of expanded entries. File inspection remains bounded and heuristic: there is no full PDF xref/object-stream parser, full OOXML/OLE2 parser, complete AV signature feed, YARA engine, or isolated hostile-file process sandbox. Quarantine records still need a durable caller.
- Prompt delimiters/canaries do not make prompt injection impossible. MCP authorization and one-time approvals must be placed on every tool invocation; no hostile-code sandbox is supplied.
- Bot, DRR, runtime and SOC helpers include process-local state in their default/test paths. They are not a distributed state cluster or durable incident platform. Integrate a durable transactional store before production use.
- The audit ratchet requires an atomic persistent store adapter. It is not a WORM system; a compromised long-term Ed25519 signing key can undermine historical signature trust. External anchoring and independently controlled retention remain required.
- The zero-dependency static scanner includes lexical tripwires for several direct database-client constructor patterns, but it is **not** a complete AST/data-flow taint analyzer or universal DB-client detector. It is not an SCA scanner or SLSA v1.0 provenance attestation. Add independent SAST, SCA, secret scanning, DAST and penetration tests.
- `arixSafeFetch` now applies a total DNS-to-body deadline, pins public DNS answers, enforces request/response byte limits and rejects cross-origin redirects, but remains opt-in. No process-wide socket/fetch interception or kernel-level egress firewall is enabled.
- Local in-memory Redis fallback is not distributed security state and is unsuitable for production enforcement. Any partially present or malformed Upstash URL/token configuration now fails closed rather than silently selecting that fallback.
- A Node.js repository cannot activate customer L3/L4 DDoS scrubbing, host mTLS policy, firewall, container/seccomp policy, database RLS, or regional quorum merely by shipping JavaScript files. The production build preflight validates required configuration shape and signs the manifest; it does not provision or contact these services.

## OWASP ASVS 5.0.0 status

**This archive is not claimed to be OWASP ASVS 5.0.0 Level 3 compliant, certified, or to have the highest Level 3 score.** Selected controls have been implemented and regression-tested, but the 17-domain architecture is not complete end-to-end. Formal Level 3 verification requires a complete requirement-by-requirement mapping, evidence from the actual application and environment, testing of every relevant route and data flow, and independent assessor review.

## Required pre-production work

1. Configure and protect production secrets and shared state; sign the integrity manifest in trusted CI.
2. Inventory all application routes, identities, ORM clients, database models, jobs, webhooks, GraphQL resolvers and outbound connections.
3. Integrate route contracts and policy coverage into route registration/production boot; add database-native RLS and test every tenant-owned table with real database roles.
4. Integrate recovery codes/session revocation, origin proof verification, MCP approval consumption, versioned KEK rotation/custody, SOC persistence, and atomic audit storage into the real application lifecycle.
5. Configure ingress/edge DDoS mitigation, origin isolation/mTLS, firewall, egress and runtime/container controls on infrastructure that supports them.
6. Test quota, DPoP replay, Redis outage, feed freshness, alert delivery, audit custody, disaster restore and RPO/RTO against the real deployment.
7. Perform independent SAST/SCA/secret, DAST, API penetration and infrastructure reviews; map evidence to all applicable ASVS 5.0.0 Level 3 requirements before making a compliance claim.

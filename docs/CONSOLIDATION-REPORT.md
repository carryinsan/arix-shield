# ArixShield v1.4.4 — source consolidation report

## Source archives

The following user-supplied archives were examined; each passed ZIP CRC validation and had no duplicate ZIP entry paths:

| Source | Files | Uncompressed bytes |
|---|---:|---:|
| `ArixShield-v1.4.2-hardened-final(1).zip` | 155 | 1,372,467 |
| `ArixShield-v1.4.3-hardened-final(1).zip` | 157 | 1,381,842 |
| `ArixShield-v1.4.2-hardened-integrated (1).zip` | 165 | 1,452,326 |

## Merge policy

The v1.4.3 source tree is the base because it contains the newest coherent core, tests, PostgreSQL RLS helpers, host-attestation controls, and the existing Upstash primary integration. Same-path files were resolved by reviewing implementation behavior and tests, not by timestamp or file size. Additive files were retained where they extend rather than silently replace existing trust boundaries.

Selected v1.4.2/integrated additions retained in this tree include the SNI allowlist and TLS listener logic, optional inbound mTLS admission, per-process connection/pressure shedding, Vercel middleware and edge clearance, request-scoped database receipts, database guard/adapters, egress-agent and firewall-rule helpers, alert outbox/retry logic on the existing Redis primary, hardened Docker/Compose profiles, seccomp profile, and the optional WAL-backed state service. The older transaction-locked RLS migration generator and additional boundary regression suite were also carried forward. The unique host nftables bootstrapper (`scripts/bootstrap-host.mjs`), guarded Node preload (`sdk/register-egress-firewall.js`), and edge-specific Compose profile (`edge/compose.yaml`) were restored and reviewed. The preload now honors the documented opt-in flag; the bootstrapper uses a private temporary directory and an atomic idempotent nftables batch.

The older `edge/seccomp-profile.json` denylist was not copied because it overrides Docker's default seccomp filter with a broader `SCMP_ACT_ALLOW` default; the edge Compose profile now reuses the stricter root allowlist `seccomp-profile.json`. The owner-signed `docs/BUILD-PROVENANCE.json` was not copied because its signing key is not supplied and its signature cannot be independently validated; `Dockerfile.hardened` was corrected to avoid referencing that unavailable file.

The integrated archive's alternate Redis failover implementation was not merged: independent or partially synchronized security-state backends can break replay, quota, session, or rate-limit consistency. The v1.4.3 Upstash-backed Redis remains the single configured primary; alert retries are layered on that primary. The optional state service is not a drop-in Redis/Lua implementation or a fully replicated Raft consensus system and is not enabled by default.

## Deduplication

All three source trees were merged into one canonical repository tree; duplicate archive paths were resolved once. The previous `security-test-pack/` contained byte-identical copies of root tests, scripts, evidence documents, and historical result files. Those duplicate payloads have been removed; the full canonical copies remain in `test/`, `scripts/`, `docs/`, and `results/`. The `security-test-pack/` directory is now a short index explaining where the canonical material lives.

The only intentional byte-identical mirror is `docs/INTEGRITY-MANIFEST.json` and `api/_integrity-manifest.json`: the root tooling requires these two manifests to match, and the API runtime reads its bundled copy. The final ZIP contains no repeated ZIP entry paths.

## Validation

See `results/TEST-RESULTS-SUMMARY.md` for the measured checks and their limitations. The final tree passed 193 tests, syntax/import/static checks, and a controlled build smoke using temporary non-production credentials. The distributed manifests are unsigned so operators can sign them in trusted CI with their own production secret.

## Release boundary

This archive is a consolidated **production-oriented release candidate**. It is not certified bug-free or vulnerability-free, and it is not an OWASP ASVS 5.0.0 Level 3 certification. Customer-specific secrets, origin keys, PKI, Redis, database schema/RLS, ingress firewall/DDoS controls, container policy, durable storage, and external assurance must be configured and independently verified before production cutover.

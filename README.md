# ArixShield

ArixShield is a hybrid application-layer API security SDK and Vercel-hosted control plane. It runs inside the customer application, where authenticated identity, route parameters, request schemas, and final response status can be inspected, while using the cloud control plane for distributed quotas, reputation data, telemetry, and audit coordination.

## Security capabilities in this release

- A deployable `edge/` Node.js 22 reverse-proxy gateway signs exact method/path/client-IP/raw-body requests with Ed25519; the API adapter verifies proofs before handler dispatch and consumes nonces in shared Redis. The gateway includes bounded buffering/concurrency, strict framing checks, TLS/mTLS options, timeout bounds, a non-root Docker image and an operations runbook.
- User and project records written through Redis JSON helpers receive transparent AES-256-GCM envelope encryption at rest with tenant-scoped data keys and atomic legacy-record migration.
- Login and password-based sensitive-action flows now consult recent-failure identity risk; single strong automation signals are scored above the default clearance threshold.

- Multi-dimensional actor/subnet/tenant/endpoint quotas backed by a single Upstash Redis Lua operation, conservative token leases, distributed AI concurrency locks and cost reconciliation.
- Bounded JSON request streaming, NFKC normalization, duplicate JSON/header/query key and request-smuggling checks, OpenAPI path/query/header/body validation, GraphQL/XML/upload guards, SQL grammar scanning and NoSQL/prototype-pollution checks.
- IPv4/IPv6 CIDR and prefix-trie reputation checks, bounded Spamhaus DROP, FireHOL, and Tor feed refresh; optional AbuseIPDB enrichment.
- Encrypted browser clearance telemetry, 60-second single-use-capable clearance tickets, request-bound DPoP over the exact URL/method/body, server-bound SHA-256 proof-of-work, and spoofable browser risk signals.
- Verified Googlebot/Bingbot reverse-DNS plus forward-DNS checks and explicit operator-maintained provider CIDR allowlists.
- Pre-handler role/permission/tenant authorization, mutation tripwire and ownership pre-check hooks; BOPLA write/read field filters; tenant/user/mode-bound capabilities for path, query and recognized JSON body IDs; and outbound ownership mismatch detection.
- Shared credential backoff, optional geo-velocity signals, route cataloguing, and sanitized forensic replay (requires SDK outcome reporting).
- Active-ban policy snapshots, bounded local deny caches, durable batched Redis pipeline writes, and pre-body control-plane header checks.
- Optional response DLP, data watermarking, and explicitly configured bounded honeypot routes.
- ClickHouse JSONEachRow / Tinybird event sinks, external metrics query adapter, SHA-256 Merkle audit roots, and optional GitHub Contents API audit anchoring.
- HMAC-authenticated GitHub secret-scanning webhook receiver with key-revocation support when a raw secret value is delivered.
- TOTP MFA, P-256 WebAuthn passkeys, device-session listing/revocation, server-key grace/immediate rotation and epoch-based cache invalidation; dashboard policy switches, sanitized forensic event view, analytics panels and audit-root status.
- DNS-pinned `arixSafeFetch` with non-public IP denial and per-redirect revalidation; circuit-breaker and risk-stratified Redis-outage policy.
- Additional opt-in primitives in v1.4.1: a deterministic 16-bit XOR password filter/compiler with suffix-root denylist checks, risk and bot-signal helpers, integrated one-use MFA recovery/reset and session-family replay revocation, Ed25519 origin-proof verification, purpose-derived tenant envelope encryption, CRC-checked ZIP/image/PDF heuristics, positive route contracts, MCP tool/approval checks, signed threat manifests/SimHash, bounded runtime/SOC helpers, an atomic-store audit ratchet, and encrypted/signed DR backup functions.

## Install and deploy

The repository is a Vercel project and Node.js 22 ESM package. Deploy this repository to Vercel, configure the existing required environment variables from `.env.example`, then deploy the matching SDK files/package to customer services.

Read [docs/OPERATIONS.md](docs/OPERATIONS.md), [docs/SECURITY-UPGRADES.md](docs/SECURITY-UPGRADES.md), and [docs/SECURITY-UPGRADES-6-10.md](docs/SECURITY-UPGRADES-6-10.md) before production rollout; [docs/SECURITY-BOUNDARIES.md](docs/SECURITY-BOUNDARIES.md) documents integration limits, and [BUILD-REPORT.md](BUILD-REPORT.md) records verification results and ASVS status.

## Local checks

```sh
npm run check
npm test
npm run generate:clearance-keys
npm run compile:breach-filter -- ./wordlist.txt ./filter.json
npm run compile:policy -- ./openapi.json ./route-policy.json ./compiled-policy.json
npm run generate:rls -- ./schema.sql ./tenant-rls.sql
npm run generate:origin-keys -- ./secrets/origin-private.pem ./secrets/origin-public.pem
```

`npm run generate:clearance-keys` prints a private RSA JWK. Treat it as a secret and only set it in the server environment. Do not commit it. The origin-key command writes an Ed25519 private/public PEM pair with restrictive file permissions; these are key materials, not third-party API keys, and must be managed as deployment secrets.

## Production requirements

Upstash Redis and the existing `ARIX_MASTER_SECRET` are required for real distributed limits, shared bans, DPoP replay protection, and HMAC capabilities. The security additions do not introduce a new third-party API key. The 89-entry default password filter is a small curated seed list, not a 50,000/250,000-password breach corpus. The CLI can compile an operator-supplied local list into a 16-bit XOR filter; its 16-bit fingerprint needs approximately 2.6 bytes per unique entry at the configured load factor and has an approximate 1/65,536 false-positive bound, not a Binary Fuse 1.125-byte representation. Optional analytics, threat-intelligence enrichment, and audit anchoring require their corresponding external configuration. The app does not fabricate sample metrics when external services are unavailable.

## Security posture

This is an application-layer defense SDK, not a network-layer DDoS service. No zero-vulnerability guarantee is made. The package has not been independently verified/certified against OWASP ASVS 5.0.0 Level 3; the build report documents local test results, customer integration obligations and unverified areas. Client-reported browser signals are spoofable risk indicators, and database authorization remains the application's responsibility. The new modules are not all automatically wired into every route, ORM, worker, tool call, or host. The edge gateway is a deployable application reverse proxy, but is not a global DDoS-scrubbing network or a substitute for cloud ingress/firewall services. See `docs/V3-IMPLEMENTATION-STATUS.md` and the security-boundaries document before integrating them.

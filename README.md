# ArixShield

ArixShield is a hybrid application-layer API security SDK and Vercel-hosted control plane. It runs inside the customer application, where authenticated identity, route parameters, request schemas, and final response status can be inspected, while using the cloud control plane for distributed quotas, reputation data, telemetry, and audit coordination.

## Security capabilities in this release

- Distributed Token Bucket, Sliding Window, Fixed Window, and Leaky Bucket limits backed by Upstash Redis Lua scripts, including conservative 15-token local quota leases.
- Bounded JSON request streaming, 32 KiB default SDK body limits (configurable up to 256 KiB), leaf-level JSON inspection, bounded canonicalization, SQL grammar-token scanning, and structural NoSQL/prototype-pollution checks.
- IPv4/IPv6 CIDR and prefix-trie reputation checks, bounded Spamhaus DROP, FireHOL, and Tor feed refresh; optional AbuseIPDB enrichment.
- Encrypted browser clearance telemetry, DPoP ES256 proof-of-possession, server-bound SHA-256 proof-of-work, and risk signals derived from canvas/WebGL, browser integrity, and coarse interaction summaries.
- Verified Googlebot/Bingbot reverse-DNS plus forward-DNS checks and explicit operator-maintained provider CIDR allowlists.
- Successful (`200`) as well as denied (`403`/`404`) resource-ID velocity monitoring, optional HMAC user-bound capability sealing, and outbound JSON ownership-mismatch detection.
- Shared credential backoff, optional geo-velocity signals, route cataloguing, and sanitized forensic replay (requires SDK outcome reporting).
- Active-ban policy snapshots, bounded local deny caches, durable batched Redis pipeline writes, and pre-body control-plane header checks.
- Optional response DLP, data watermarking, and explicitly configured bounded honeypot routes.
- ClickHouse JSONEachRow / Tinybird event sinks, external metrics query adapter, SHA-256 Merkle audit roots, and optional GitHub Contents API audit anchoring.
- HMAC-authenticated GitHub secret-scanning webhook receiver with key-revocation support when a raw secret value is delivered.
- Dashboard policy switches, sanitized forensic event view, analytics panels, audit-root status, and a 2D event correlation canvas.

## Install and deploy

The repository is a Vercel project and Node.js 22 ESM package. Deploy this repository to Vercel, configure the existing required environment variables from `.env.example`, then deploy the matching SDK files/package to customer services.

Read [docs/OPERATIONS.md](docs/OPERATIONS.md) before production rollout, [docs/SECURITY-BOUNDARIES.md](docs/SECURITY-BOUNDARIES.md) for implementation boundaries and non-goals, and [BUILD-REPORT.md](BUILD-REPORT.md) for local verification status.

## Local checks

```sh
npm run check
npm test
npm run generate:clearance-keys
```

`npm run generate:clearance-keys` prints a private RSA JWK. Treat it as a secret and only set it in the server environment. Do not commit it.

## Production requirements

Upstash Redis and the existing `ARIX_MASTER_SECRET` are required for real distributed limits, shared bans, DPoP replay protection, and HMAC capabilities. The security additions do not introduce a new third-party API key. Optional analytics, threat-intelligence enrichment, and audit anchoring require their corresponding external configuration. The app does not fabricate sample metrics when external services are unavailable.

## Security posture

This is an application-layer defense SDK, not a network-layer DDoS service. It cannot guarantee zero vulnerabilities or replace application-layer authorization. Client-reported browser/GPU signals are risk indicators, not attestations. The stateless Redis-outage ratchet, memory-hard PoW, and automatic schema-learning mechanisms from the proposal are not implemented because the described versions do not provide the asserted guarantees safely. Reserved-ID traps remain opt-in and require the application to reserve the relevant ID space. See the security-boundaries document.

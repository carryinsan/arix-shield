# ArixShield

ArixShield is a hybrid application-layer API security SDK and Vercel-hosted control plane. It protects APIs from inside the customer application (where authenticated identity, request schema, and final response status are available) while using the cloud service for distributed quotas, reputation feeds, telemetry, and audit coordination.

## What is included in this release

- Distributed Token Bucket, Sliding Window, Fixed Window and Leaky Bucket limits through Upstash Redis Lua scripts, with short-lived SDK-local block caches.
- IPv4/IPv6 CIDR validation and prefix-trie reputation checks, fed by bounded Spamhaus DROP, FireHOL, and Tor exit-node downloads; optional AbuseIPDB enrichment.
- Cryptographic browser DPoP and proof-of-work, plus optional RSA-OAEP/AES-GCM encrypted browser clearance telemetry.
- Verified Googlebot/Bingbot reverse-DNS + forward-DNS checks and explicit operator-maintained provider CIDR allowlists.
- JavaScript WAF checks, request-size/depth limits, JSON schema validation, parsed OpenAPI operation schema compilation, and Zod-like `.safeParse()` support.
- Shared sliding-window credential backoff, 403/404 object-ID cardinality detection, optional geo-velocity signals, route cataloguing and sanitized forensic replay (requires SDK outcome reporting).
- Optional outbound response DLP, data watermarking, and explicitly configured bounded synthetic honeypot routes.
- ClickHouse JSONEachRow / Tinybird event sinks, external metrics query adapter, SHA-256 Merkle audit roots, and optional GitHub Contents API audit anchoring.
- HMAC-authenticated GitHub secret-scanning webhook receiver with key-revocation support when a raw secret value is delivered.
- Dashboard policy switches, sanitized forensic event view, analytics panels, audit-root status and a 2D event correlation canvas.

## Install / deploy

The repository is a Vercel project and Node.js 22 ESM package. Deploy this repository to Vercel, configure the required environment variables from `.env.example`, then deploy the matching SDK files/package to customer services.

Read [docs/OPERATIONS.md](docs/OPERATIONS.md) before production rollout, [docs/NEXTJS-INTEGRATION.md](docs/NEXTJS-INTEGRATION.md) for the supported Next.js multi-website integration, [docs/SECURITY-BOUNDARIES.md](docs/SECURITY-BOUNDARIES.md) for limitations and intentionally excluded countermeasures, and [BUILD-REPORT.md](BUILD-REPORT.md) for the exact verification status and feature boundaries.

## Local checks

```sh
npm run check
npm test
npm run generate:clearance-keys
```

`npm run generate:clearance-keys` prints a private RSA JWK. Treat it as a secret and only set it in the server environment. Do not commit it.

## Production requirements

Upstash Redis is required for real distributed limits and shared state. Analytics and audit anchoring need external ClickHouse/Tinybird or GitHub configuration. The app does not fabricate sample metrics when those services are unavailable. For Vercel Hobby compatibility, cron jobs are scheduled daily; Pro/Enterprise operators may raise cadence after reviewing plan quotas and database costs.

## Security posture

This is an application-layer defense SDK, not a network-layer DDoS service. It does not claim to be zero-vulnerability, and its test suite is not an independent security audit. Rust/libinjection Wasm, a 3D WebGL globe, and invasive or destructive countermeasures from the broader proposal are not included. See the security-boundaries document.

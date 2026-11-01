# ArixShield security upgrade build report

Release: `1.1.0` (existing project version retained)  
Verification target: Node.js `22.x` / Vercel Node Functions  
Upgrade date: 2026-11-01

## Changes applied to the existing project

### WAF and request-size boundaries

- Replaced flat whole-body regex-only inspection with bounded canonicalization, SQL grammar tokenization, structural JSON key inspection, per-leaf scanning, depth/node limits, symbol-density checks, and chunk overlap handling.
- SDK adapters enforce request byte limits while reading streams. SDK default is 32 KiB, configurable up to 256 KiB; `/api/shield` uses a 36,000-byte cap.
- Kept application schemas explicit: OpenAPI/JSON Schema/Zod-like validation remains supported; automatic schema inference/locking is intentionally not enabled.

### Bot and browser signals

- Clearance challenges are HMAC-signed, short-lived, and bind the encrypted signal bundle into SHA-256 proof-of-work.
- Browser telemetry includes a seeded canvas/WebGL pixel digest, optional renderer/hardware hints, prototype integrity status, and bounded coarse interaction-kinematic summaries.
- Server-side risk scoring compares available TLS metadata with the reported browser/hardware context. These are spoofable risk signals, not proof of a physical GPU or a human.
- The proposed interactive 1.2-second hold flow and memory-hard 4–16 MiB scratchpad proof are not implemented; the proposed sparse proof verification does not establish honest work and full verification can amplify server resource consumption.

### BOLA/IDOR and response protections

- Outcome telemetry now tracks resource IDs returned with `200` as well as `403`/`404`, with distinct-ID and sequential numeric-ID velocity signals.
- Added user-bound HMAC capability sealing with 128-bit tags and path verification for every numeric/UUID resource-like segment, gated by the SDK's `capabilitySealing` option; opaque IDs can be matched with a developer-supplied pattern.
- Added an outbound JSON owner-field mismatch guard for successful responses when a stable authenticated identity is provided.
- Reserved Knuth trap IDs are gated behind `ARIX_RESERVED_TRAP_ID_SPACE=true`; the application must guarantee those IDs are never allocated to real users.

### Redis, quotas and latency

- Added 30-second SDK caching of project policy and active actor/IP ban snapshots. Snapshot building filters expired bans and prunes stale index members; incomplete snapshots fall back to direct abuse checks.
- Added 15-token distributed quota leases with a 15-second maximum local lease lifetime.
- Added a local 15-second DPoP replay ring while retaining the shared Redis replay check.
- Batched project-event and analytics/audit queue writes into a durable Redis pipeline request rather than six sequential REST operations.
- Added header-only `/api/shield` validation before body parsing and a short-lived local API-key/project mapping cache for early local IP-ban rejection.

## Local verification

Run the following in this repository:

```sh
npm run check
npm test
```

Final local verification: `npm run check` passed (31 JavaScript files syntax-checked; 24 server modules imported) and `npm test` passed (28 tests, 0 failures). Unit tests and syntax/import checks do not validate Vercel deployment behavior, real Upstash connectivity, external API credentials, or application-specific ownership integration. No production credentials were supplied, so external hosted services were not live-account tested.

## Deliberate security limits

- No stateless client-carried rate-limit ratchet is claimed for total Redis outages. The default is fail-closed (`503`); explicit `failOpen` uses a process-local bucket and is not globally consistent.
- No automatic schema learning, full threat-feed trie shipping in SDK snapshots, universal JA3/JA4 browser classification, or human attestation based on GPU/timing/kinematics is claimed.
- No Rust/libinjection Wasm, Wasm Bloom filter, 3D globe, connection tarpits, decompression-bomb payloads, prompt-secret exfiltration, or WebRTC/LAN deanonymization is included.
- The project remains an application-layer security product, not L3/L4 DDoS scrubbing or a compliance certification.

No software can be guaranteed bug-free or vulnerability-free. Review [docs/OPERATIONS.md](docs/OPERATIONS.md) and [docs/SECURITY-BOUNDARIES.md](docs/SECURITY-BOUNDARIES.md), configure real production services, test representative routes in staging, and obtain an independent penetration test before production reliance.

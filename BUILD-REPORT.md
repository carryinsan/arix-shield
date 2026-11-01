# ArixShield upgrade build report

Release: `1.1.0`  
Runtime target: Node.js `22.x` / Vercel Node Functions  
Verification run: 2026-11-01

## Included in this repository

- Preserved the existing Vercel project layout, API route entrypoints, project-key formats, and dashboard pages.
- Four Redis Lua quota algorithms remain available; SDKs support identity scopes, weighted quotas, and short-lived local deny caches.
- Added IPv4/IPv6 CIDR parsing and prefix-trie reputation evaluation, bounded feed refresh, verified Google/Bing crawler DNS checks, and operator-maintained provider CIDR allowlists.
- Added shared 401 backoff, stateful distinct-object-ID tracking based on reported 403/404 outcomes, geo-velocity signals, optional route cataloguing, and sanitized forensic events.
- Added parsed OpenAPI JSON-schema body compilation with local `$ref` support, plus synchronous Zod-like `.safeParse()` support.
- Extended DLP/schema checks and added encrypted browser clearance telemetry using RSA-OAEP-256/AES-GCM and DPoP ES256 replay protection.
- Added ClickHouse/Tinybird ingestion adapters, dashboard metrics query adapters, GitHub Contents API Merkle-root anchoring, and a signature-verified GitHub secret-scanning webhook receiver.
- Added control-plane-issued watermark attribution, opt-in synthetic canary rows, honeypot response handling, and a browser/dashboard telemetry refresh interval that avoids aggressive polling.
- Added operational documentation, ClickHouse DDL, Vercel cron examples, environment templates, key generation, and automated tests.

## Verification performed

- `npm run check`: syntax-checks all JavaScript files and imports all 24 server-side API/SDK modules successfully.
- `npm test`: 20 tests pass, 0 fail. Coverage includes DPoP ES256 verification and replay rejection, encrypted JWE round-trip, IPv4/IPv6 CIDR matching, WAF checks, schema and OpenAPI validation, DLP, Merkle hashing, BOLA aggregation, honeypot identity/IP handling, and safe watermark attribution.

These are local automated checks, not a production deployment test or an independent penetration test. No customer credentials, hosted Upstash instance, threat-feed credentials, ClickHouse/Tinybird account, or GitHub token were supplied; those external integrations are therefore implemented but not live-account verified in this build.

## Required production configuration

At minimum configure `ARIX_MASTER_SECRET`, `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, and `CRON_SECRET`. Browser encrypted telemetry additionally requires `ARIX_CLEARANCE_KID` and `ARIX_CLEARANCE_PRIVATE_JWK`. Advanced analytics and anchoring require the corresponding ClickHouse/Tinybird and GitHub settings in `.env.example`. See `docs/OPERATIONS.md`.

The local Redis mock is only for development. Distributed limits, DPoP replay protection, sessions, shared bans, watermark attribution, and cron state require real Upstash Redis in production.

## Explicitly not claimed or included

- No compiled Rust/libinjection WebAssembly artifact or Wasm Bloom filter is present; WAF inspection remains JavaScript heuristics and the prefix trie is JavaScript.
- No 3D WebGL globe or complete attacker graph is claimed; the dashboard has a 2D event-correlation canvas.
- The browser clearance is an encrypted JWE telemetry body, not an HttpOnly `arix_clearance` cookie.
- GitHub Secret Scanning Partner enrollment is external; a normal webhook that omits raw secret values cannot automatically identify and revoke a matching key.
- No decompression bombs, connection-holding tarpits, prompt/system-secret exfiltration instructions, or browser WebRTC/LAN deanonymization are implemented.
- The app is not network-layer DDoS protection and is not certified for SOC 2/PCI/HIPAA by this code change.

No software can be guaranteed bug-free or vulnerability-free. Complete provider configuration, dependency review, staging traffic validation, and an independent penetration test before production enforcement.

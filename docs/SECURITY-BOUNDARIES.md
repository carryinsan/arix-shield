# Security boundaries and non-goals

ArixShield is an application-layer security SDK and telemetry/control-plane service. It runs inside a customer application, where route parameters, authenticated identity, request schemas, and final response status may be available. It is not an Anycast network, TLS termination proxy, volumetric DDoS scrubbing network, or replacement for the hosting provider's edge controls.

No software can honestly guarantee zero vulnerabilities, bug-free behavior, or perfect bot/BOLA detection. ArixShield is defense-in-depth: applications must still authorize every resource access at the data/query layer, validate their own inputs, and keep secrets server-side.

## Implemented in this release

### Request inspection and WAF

- Standard JSON bodies default to a 32 KiB inspection limit. Configurable routes may raise the limit up to 256 KiB; SDK adapters enforce byte limits while reading the request stream, before JSON parsing/allocation. `/api/shield` has a separate 36,000-byte control-plane cap.
- Parsed JSON is traversed structurally. String leaves are inspected individually (4 KiB default leaf cap), with bounded depth/node counts. Large accepted strings can be explicitly allowlisted using `allowedLongFields`; the body itself remains bounded.
- Raw serialized request text is scanned in 16 KiB chunks with a 512-byte overlap. Canonicalization performs at most three decoding/normalization passes and detects continued nested encoding. A deterministic SQL grammar tokenizer supplements the non-SQL XSS, SSRF, traversal, shell, and prompt-injection rules.
- Structural object-key checks flag NoSQL `$` operators, dotted keys, and prototype-pollution names (`__proto__`, `constructor`, `prototype`). A 50-character symbol-density check provides another signal on free-text leaves.
- Explicit developer-provided JSON Schema, OpenAPI, or Zod-like validators remain the authority for application-specific field types and allowed properties.

### Bot and browser clearance signals

- Browser clearance uses encrypted telemetry, DPoP ES256 proof-of-possession, a server-signed short-lived challenge, and SHA-256 proof-of-work. Canvas/WebGL pixel digest, renderer/hardware hints, prototype-integrity status, and bounded coarse interaction-kinematic summaries are mixed into the challenge binding.
- The service can compare browser claims with available Vercel JA3/JA4 headers and flag known software-renderer/browser inconsistencies as risk signals.
- Client-side values are not attestations. A custom HTTP client can forge JSON telemetry, a renderer string, pointer summaries, and reported timing. TLS digests are only useful when supplied by a trusted ingress and are not a universal browser/non-browser classifier. These signals must never be used as the sole authorization factor.
- The 1.2-second interactive hold UI and 4–16 MiB memory-hard scratchpad puzzle described in the proposal are not enabled. The proposal's suggested sparse server verification cannot prove that a client performed the full memory-hard work; full server recomputation would create an avoidable CPU/memory amplification risk. The existing signed, signal-bound SHA-256 PoW remains the real implemented challenge.

### BOLA / IDOR telemetry and capability sealing

- SDK outcome reporting tracks distinct resource IDs for successful `200` responses as well as `403` and `404`. Repeated sequential numeric IDs or more than the configured distinct-ID threshold on successful responses trigger an enumeration signal and actor backoff.
- Optional capability sealing binds outgoing resource IDs to a stable authenticated user identity with a 128-bit truncated HMAC-SHA256 tag using the existing `ARIX_MASTER_SECRET`. When enabled, SDK response wrappers seal recognized resource-ID fields and inbound SDK middleware verifies seals for every numeric/UUID resource-like path segment and rewrites the path before calling the application handler. Opaque string IDs require a carefully scoped `capabilityIdPattern`; query-string IDs are not covered.
- An outbound `200` JSON ownership guard checks recognized top-level owner fields and bounded `data[]` / `records[]` entries. This is a useful leak detector, not a substitute for route/database ownership checks. It only works when the SDK is given a stable authenticated identity and the response schema uses owner fields that can be compared to that identity.
- The Knuth-derived reserved-ID trap is disabled unless `ARIX_RESERVED_TRAP_ID_SPACE=true`. Enable it only after the application/database has permanently reserved the entire matching numeric ID subset and guarantees those IDs can never be real records. The formula does not guarantee that an attacker hits a trap within a few dozen requests; it identifies roughly one in 97 integer IDs. Never turn this on for an unreserved ID space.

### Redis, limits, and telemetry

- SDKs cache policy plus active indexed actor/IP bans for up to 30 seconds. Incomplete or oversized ban indexes cause a direct control-plane abuse check instead of trusting a partial snapshot. Expired indexed bans are filtered and pruned while building snapshots.
- Distributed rate-limit requests can lease up to 15 tokens from Upstash and spend the remaining lease locally for at most 15 seconds. Because unused tokens are reserved and may expire, this reduces round trips at the cost of conservative quota under-utilization; it does not increase the configured global allowance.
- DPoP replay protection uses a bounded 15-second per-instance ring as an early duplicate filter and retains the shared Redis `SET NX` replay check for cross-instance enforcement.
- Project events and telemetry writes use a durable Redis `/pipeline` request rather than six sequential REST round trips. This is not a lossy in-memory write-behind queue. SDK response-outcome reporting may use the host-provided `waitUntil` hook when available.
- The `/api/shield` control plane validates API-key shape, content length, and Origin before reading/parsing the request body. A short-lived local API-key-to-project cache supports early rejection of locally cached IP bans. Revocation may therefore take up to the cache TTL to propagate on that instance.
- Optional `ARIX_PREBODY_THREAT_FEED_BLOCK=true` checks the currently loaded in-memory threat feed before body parsing. It is disabled by default because a feed-wide block can create false positives; validate feed quality and policy before enabling.

## Explicit non-goals and proposal items not implemented

- **Stateless cross-instance HMAC rate-limit ratchet during Redis outage:** not implemented. A signed client-carried counter can be replayed or forked across instances without shared anti-replay state; it cannot provide strict globally consistent counters during a total Redis outage. Default behavior is fail-closed (`503`) when the distributed limiter is unavailable. `failOpen: true` is an explicit compatibility override that falls back to a process-local bucket and is not globally distributed or strict.
- **Automatic schema learning/locking:** not enabled. Inferring schemas from early live traffic can let malicious requests poison the learned schema and reject valid future data. Supply trusted application schemas explicitly.
- **Full threat-feed trie shipping in every SDK snapshot:** not implemented. The SDK snapshot carries active ban hashes; threat-feed lookups remain server-side/cached to avoid repeatedly transferring a large CIDR structure to every serverless instance.
- **Universal JA3/JA4 browser classification:** not implemented. TLS digest classification requires trusted, current reference data and cannot be inferred reliably from a digest's presence alone.
- **Guaranteed human detection from GPU timings, pointer kinematics, or micro-hold behavior:** not implemented; all client-reported values can be fabricated.
- **Reverse-Slowloris / connection tarpits:** deliberately excluded because holding open connections consumes customer/provider resources and billing is not zero-cost.
- **Decompression-bomb generation, parser starvation payloads, or destructive active countermeasures:** deliberately excluded.
- **WebRTC/STUN or cross-origin probing to deanonymize users:** not performed.
- **Prompt-injection exfiltration:** the product does not attempt to make third-party agents reveal hidden prompts, credentials, or private tool configuration.
- **Automatic provider abuse reports/takedowns:** operator review and evidence validation are required.
- Rust/libinjection WebAssembly, a Wasm Bloom filter, a 3D WebGL globe, and a full attacker graph are not included; the WAF and CIDR prefix trie remain JavaScript.

## Production boundaries

- Upstash Redis is required for shared quotas, ban state, DPoP replay prevention, and other distributed guarantees. The local Redis emulator is development-only and is not shared between serverless instances.
- ClickHouse/Tinybird, AbuseIPDB, GitHub webhook delivery, and GitHub audit anchoring require external accounts, current credentials, schema/pipe setup, and appropriate permissions.
- Threat-feed freshness and provider allowlists depend on upstream feeds and operator maintenance. False positives and false negatives remain possible.
- Geo-velocity uses hosting-provider or explicitly supplied location metadata; IP geolocation is approximate.
- Request replay is sanitized. Raw bodies, cookies, and authorization headers are not retained.

Passing local tests is not a production deployment test, independent penetration test, certification, or proof of zero vulnerabilities. Run dependency audits, staging validation, a threat-model review, and an independent penetration test before relying on this as an enterprise security control.

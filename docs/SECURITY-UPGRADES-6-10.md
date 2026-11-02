# Security upgrade notes: upgrades 6–10

This document records the implementation added for the adversarial testing, risk scoring, audit integrity, supply-chain checks, and forensic watermarking work. It is an implementation note, not a claim of formal certification or a guarantee that every attack is blocked.

## 6. Adversarial verification laboratory

`test/adversarial-lab.test.js` uses Node.js built-ins and `node:test`. It exercises 2,500 deterministic attack mutations (including actual streamed JSON split across byte 16,384), 2,500 benign inputs, an 80-case actor/tenant/method/identifier-placement matrix, and 100-way Promise concurrency for quota/DPoP behavior with injected Redis failures. The tests are deterministic regression examples. They do not prove universal 100% attack detection, measure a representative production false-positive rate, exercise a live tenant database, or replace distributed Upstash load testing.

`api/_lib/security-self-test.js` provides 10 in-memory probes. `api/cron/audit-anchor.js` runs them on each scheduled invocation and emits `CRITICAL_SELF_TEST_FAILURE` with a failing status when any probe fails. A cron endpoint must actually be scheduled, authorized, and operational for the probe to run in production.

## 7. Confidence-based reputation and correlation

`api/_lib/reputation.js` scores fresh Spamhaus DROP matches at +85, FireHOL/Tor matches at +45, and datacenter ASN observations at +20. Feed-derived confidence is halved after 24 hours. A stale-feed banner is exposed to the dashboard. Feed data is retained in Redis through the 48-hour feed expiry plus a seven-day grace period so a stale snapshot remains available for decay and warning; the original freshness/expiry timestamp is not extended.

Verified crawlers and configured provider CIDRs are explicit allow signals. Actor and subnet risk accumulates over a rolling ten-minute window in `api/_lib/abuse.js`; repeated blocked actors add subnet risk. SDK actions distinguish block, challenge/backoff, and allow rather than treating all cloud ASN observations as an unconditional block. A datacenter ASN by itself is not proof of malicious behavior.

The score thresholds are policy heuristics, not threat-intelligence ground truth. Provider CIDRs must be sourced, reviewed, and maintained by the operator. Do not enable automatic enforcement until traffic has been observed in the intended deployment.

## 8. Audit chain, incident webhook, and browser witness

`recordProjectEvent` appends security events to a rolling HMAC-SHA256 chain. The Redis Lua compare-and-set operation updates sequence, head, and retained event list atomically; the local fallback is intended for tests/development only. Snapshots validate event digests, sequence continuity, the retained list length, and the current head. The list retains at most 10,000 recent events; older events require separately retained evidence exports/anchors.

Critical incidents can be delivered to an operator-configured HTTPS webhook. The JSON body is signed with the existing `ARIX_MASTER_SECRET`; this feature does not require a new vendor API key. An operator may opt into the supported DRY_RUN-to-ENFORCE containment transition. It does not rotate third-party credentials because safe rotation requires provider-specific credentials and application-specific ownership logic. Webhook destination ownership, availability, rate limits, and downstream processing remain operational responsibilities.

The dashboard pins verified chain heads in browser IndexedDB and can export a JSONL evidence bundle. The first pin is trust-on-first-use (TOFU): it protects continuity after the browser has observed a root, but cannot prove that the server was honest before that first observation. A compromised browser profile or device can also erase or alter its local witness. Redis HMAC chaining is tamper-evident relative to the master secret; an attacker controlling Redis and the master secret, or the application process before event creation, can forge data. It is not independent WORM storage.

## 9. Build integrity and runtime attestation

`npm run check` performs Node syntax checks, imports API/SDK modules, enforces zero third-party entries in package dependency sections, scans source for selected dangerous constructs, scans repository text files for selected credential patterns, and verifies a deterministic SHA-256 manifest covering `.js`, `.mjs`, and `.html` files. Runtime production attestation checks manifest coverage of the `api/_lib` JavaScript files, their hashes, manifest structure/signature, a 32-byte minimum master secret, an RSA private JWK of at least 3072 bits, and HTTPS security configuration.

The static scanner is a dependency-free lexical pattern gate, not a complete JavaScript AST parser or a general-purpose SAST engine. It can miss obfuscated or semantically dangerous code and can flag benign patterns. It does not inspect deployment platform settings, customer applications, transitive runtime code outside this repository, or every binary artifact.

The distributed ZIP intentionally contains no production master secret and therefore has an unsigned integrity manifest. Before production deployment, in a trusted CI/release environment, sign the manifest using the existing production `ARIX_MASTER_SECRET`:

```sh
ARIX_MASTER_SECRET="$ARIX_MASTER_SECRET" npm run integrity:update
NODE_ENV=production ARIX_MASTER_SECRET="$ARIX_MASTER_SECRET" npm run check
```

Do not commit or expose the master secret. If a source file changes after signing, regenerate and review the manifest, then sign it again. A production runtime intentionally fails closed when its manifest is absent/unsigned, drifted, or the required configuration is invalid.

## 10. Chameleon records, watermarking, and ghost paths

When enabled by project policy and when a response has at least ten records with a stable top-level `id`, `_id`, or `uuid`-style field, `spliceCanaryRow` clones the row schema and value types without adding a synthetic marker property. The canary identifier is derived using HMAC from the existing master secret and session/project context. The SDK registers the exposed row identifier with the control plane before returning it; if registration fails, it removes the inserted row. Identifiers without an explicit ID-like field are not modified. The values are schema-shaped decoys, not guaranteed to be semantically indistinguishable from a particular customer's dataset.

The watermark embeds an invisible text signature and, only when the response has sufficient timestamp/key-order capacity, a second structural channel. Structural extraction depends on preserving JSON object-key order and timestamp precision; serializers, database normalization, CSV conversion, or clients may remove that channel. Zero-width characters can be stripped. No claim is made that the combined watermark is impossible to remove.

The SDK adapters recognize common reconnaissance paths such as `/.env`, `/api/v1/admin/export`, `/api/debug/config`, and `/graphql/schema` as honeypot candidates. This applies only when the request passes through the SDK middleware; it is not a network-wide or platform-level route intercept. JA4 is recorded only where the trusted deployment runtime supplies it, and client-supplied values are not treated as cryptographic identity. PHANTOM_SANDBOX/trap mirage responses are deception and correlation signals, not a separate sandbox or proof that subsequent traffic is isolated at infrastructure level.

## No-new-key and compliance boundary

The upgrades reuse the existing `ARIX_MASTER_SECRET`, existing server integration key, and existing Redis credentials. The optional incident webhook uses an HMAC signature derived from the master secret, so it does not add a third-party API key. Existing optional provider integrations retain their own configuration requirements.

This work is not an OWASP ASVS 5.0.0 Level 3 certification. Local tests and source scans are limited evidence. A Level 3 assessment must map every applicable requirement to architecture, deployment, identity lifecycle, data-layer, CI/CD, operations, and independently verified evidence; the customer's application and runtime environment are in scope too.

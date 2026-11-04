# ArixShield v1.4.4 — outage and DPoP replay-cache remediation

## Audit disposition

The latest supplied audit describes two real cache-design weaknesses:

1. `sdk/security-runtime.js` kept every accepted degraded-mode proof in an unbounded `Map`, pruned it with a full-map scan on every valid candidate, and inserted the replay record before checking the local degraded-read quota.
2. `api/_lib/crypto-trap.js` used one process-wide DPoP replay `Map` for projects and key thumbprints, scanned that map on each verification, and rejected all projects after a single shared global capacity was exhausted.

The second finding was a conditional availability weakness, not a demonstrated DPoP replay bypass. This remediation does not evict active records to make room.

## Changes made

### F-16 — bounded degraded-mode outage replay

- Added `api/_lib/bounded-replay-cache.js` with a min-heap expiry queue and hard global, namespace, and requester-partition caps.
- Outage challenge tokens now bind to a hash of the configured project identity and trusted requester network prefix. Raw IP addresses are not embedded in the token.
- Outage replay storage is limited to **32,768 records globally**, **8,192 per project**, and **256 per project/requester-prefix**; each record is retained for 60 seconds.
- Proof verification checks token authenticity/expiry, HTTP method, path, project/requester scope, and proof-of-work before replay admission.
- The local degraded-read quota is checked synchronously inside the cache-admission operation before a replay record is inserted. A quota-denied proof does not occupy replay storage. Duplicate checks happen before quota charging.
- Cache saturation is fail-closed and returns HTTP 503. A consumed proof returns HTTP 429. Unexpired entries are never evicted.
- The related local read-quota bucket store is also bounded at **20,000 buckets globally** and **4,000 per project**, and uses expiry-driven cleanup. It does not allocate new buckets after capacity is reached.

### F-17 — tenant-fair DPoP replay storage

- Replaced the shared DPoP `Map` with the bounded expiry-heap cache. The local fallback is capped at **131,072 records globally**, **32,768 per project**, and **16,384 per project/key-thumbprint**.
- Expiration is heap-driven; verification no longer loops through all live entries on each request.
- No unexpired record is evicted. The relevant verifier rejects new proofs when a global, project, or key partition reaches its cap.
- The Redis-backed `verifyDpopProof` path now relies on its existing atomic Redis `SET NX EX` replay-consumption operation instead of duplicating every durable entry in process memory.
- Production browser-clearance validation now passes the durable `consumeProofReplay` callback into `verifyRequestDpopProof`; the local cache is only the standalone/local fallback. Durable replay-service failures fail closed.
- Replay retention was tightened for inclusive `iat` boundaries: standalone request-bound local fallback is retained for **91 seconds** for a ±45-second timestamp window; Redis-backed standard DPoP entries use **121 seconds** for a ±60-second timestamp window.

## Regression coverage

`test/replay-cache-hardening.test.js` covers:

- Global, project, and requester/device capacity limits.
- Heap expiry and successful admission after expired entries are pruned.
- No eviction of active replay entries.
- Synchronous pre-insertion admission and no storage on denied quota.
- Outage challenge project/requester binding.
- Replayed outage proof rejection.
- No replay-cache insertion when the local read quota is exhausted.
- Hard limits on local degraded-read quota buckets.
- Durable DPoP replay callback success, replay rejection, and service-unavailable failure.

The adversarial DPoP test mock was also corrected to model atomic Redis `SET NX` semantics. A mock that always returns `OK` does not model a replay store and is not a valid replay test.

## Verification

- Focused replay-cache regression tests: **6 passed, 0 failed**.
- Full repository suite: **276 passed, 0 failed, 0 skipped**.
- `npm run check`: passed; **123** JavaScript/MJS syntax checks, **68** API/SDK imports, static scanner passed, and **126** integrity-manifest source entries verified.
- Controlled `npm run build`: passed; its isolated build suite also ran **276 tests** successfully.
- The build used disposable local-only secrets, a temporary RSA-3072 key, and a placeholder Upstash-shaped HTTPS configuration. No temporary value was packaged. The generated manifest was reset to unsigned form for trusted CI signing with the real production secret.
- A fresh ZIP extraction is separately checked before delivery.

## Remaining limitations

- The replay caches are process-local. They provide bounded local fallback behavior, not globally coordinated replay state across separate serverless instances.
- Production clearance verification depends on the durable Redis `consumeProofReplay` callback. The standard DPoP verifier depends on Redis atomic `SET NX EX`. Those paths must be verified against the actual Upstash deployment.
- No live Vercel deployment, Upstash service, PostgreSQL server, external multi-instance replay cluster, or production traffic load test was available.
- The repository still has no `package-lock.json`; `npm ci` and `npm audit --omit=dev --audit-level=low` remain open supply-chain release gates. No lockfile was fabricated.
- These tests do not establish that ArixShield is bug-free, immune to all availability attacks, or formally certified.

# Replay-cache behavior and capacity

## Degraded-mode outage proofs

The SDK's low-risk documentation/catalog fallback uses a process-local replay cache because this path is entered when the distributed quota service is unavailable. Challenges are signed and bound to the configured project identity and the trusted requester network prefix. A proof is entered into replay storage only after its signature, expiry, target, proof-of-work, replay status, cache capacity, and local read quota have been checked.

The replay cache has a hard global capacity of 32,768 records, a per-project capacity of 8,192, and a per-project/requester-prefix capacity of 256. Records live for 60 seconds. Active records are never evicted to make room. Capacity exhaustion fails closed with HTTP 503; a quota-exhausted caller receives HTTP 429. Expiry cleanup uses a min-heap, so request handling does not scan the full cache.

Local degraded-read quota buckets are separately bounded at 20,000 globally and 4,000 per project. Their expiry queue is heap-driven; new buckets are denied when capacity is exhausted. The local bucket store is process-local and resets with the process.

## DPoP replay protection

The control-plane DPoP verifier uses Redis `SET NX EX` as its durable replay-consumption primitive. It does not depend on the process-local cache for replay correctness.

Body-bound request DPoP verification accepts a durable `consumeReplay` callback in the production clearance path. The callback must atomically consume the JTI hash in the control plane. The bounded process-local cache is retained only as a fail-closed fallback for standalone/local verification calls where no durable callback is supplied.

That fallback has a global limit of 131,072 records, a per-project limit of 32,768, and a per-project/key-thumbprint limit of 16,384. The local request-bound fallback retains proofs for 91 seconds to cover the inclusive +/-45-second `iat` window plus integer-second boundary rounding. The Redis-backed standard DPoP verifier stores replay keys for 121 seconds to cover the inclusive +/-60-second `iat` window plus sub-second rounding. It never evicts unexpired records; capacity exhaustion rejects new proofs. Expiry is heap-driven rather than a full-map scan.

These caches are process-local protections, not globally coordinated quota or replay stores. Production deployments must keep the documented durable Redis replay-consumption path available. When that dependency is unavailable, protected requests fail closed rather than silently accepting proofs.

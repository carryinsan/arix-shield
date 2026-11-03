# Optional replicated state service

ArixShield's production serverless control plane continues to use the configured Upstash Redis REST service. This optional Node.js 22 service is separate and does not remove, replace, or silently migrate that dependency.

## Design

- One configured primary and one or more read-only replicas.
- Monotonic sequence numbers and SHA-256 hash-chained WAL records.
- Local WAL append + fsync before replication.
- HMAC-SHA256 peer authentication derived from the existing `ARIX_MASTER_SECRET`.
- Primary requires `floor((nodes)/2) + 1` acknowledgements, counting its own durable write, for prepare, commit and finalization.
- WAL finalization markers make a crash between commit and quorum completion recover read-only instead of assuming the write completed. Recovered unresolved prepare/commit records freeze the node pending operator reconciliation.
- REST bearer auth reuses the existing `UPSTASH_REDIS_REST_TOKEN`.

This is **not Raft**. It does not implement leader election, autonomous failover/promotion, fencing leases, multi-region conflict resolution or automatic stale-replica catch-up. Operators must maintain exactly one primary, fence it before promotion, monitor each node's sequence/hash and restore/rebuild stale replicas from a consistent WAL backup.

## Important compatibility limit

The service implements a bounded JSON command subset (strings, expiry, lists, sets, hashes and sorted-set primitives used by a limited group of workflows). It intentionally rejects Lua `EVAL`. The existing `api/_lib/redis.js` uses many Lua scripts for quota buckets, CAS, audit serialization and other security-critical atomic operations. Consequently this service is **not a drop-in replacement for the complete ArixShield Upstash contract**. Do not configure it as the production Upstash endpoint or fallback for the full app until all required Lua semantics and concurrency guarantees have been implemented and independently tested.

## Hardened Compose profile

The state node is separated from the edge-only Compose file so its TLS files and secrets are not required for ordinary gateway deployments. To intentionally start this optional node, merge `docker-compose.hardened.yml` and `docker-compose.state.yml`, enable the `state` profile, and prepare `./state-data` with owner UID/GID 65532. This service is supplementary; it does not replace or become the application's Upstash primary.

## Run a standalone local node

```sh
export ARIX_MASTER_SECRET='(existing random 32+ byte secret)'
export UPSTASH_REDIS_REST_TOKEN  # set it in your secret manager before starting
export ARIX_STATE_ROLE=primary
export ARIX_STATE_DATA_DIR=/var/lib/arixshield-state
export ARIX_STATE_TLS_CERT_FILE=/run/secrets/state-cert.pem
export ARIX_STATE_TLS_KEY_FILE=/run/secrets/state-key.pem
npm run state
```

Use HTTPS peer origins in `ARIX_STATE_PEERS`, comma-separated, on the primary. Replica nodes use `ARIX_STATE_ROLE=replica` and no peer list. Remote peers must use HTTPS; plain HTTP is accepted only for loopback tests. Put the REST listener on a private network and firewall it. The server exposes `/health`, `POST /` and `POST /pipeline` using Upstash-style JSON command payloads. `/__arix/replicate` is reserved for HMAC-authenticated peer traffic.

A quorum write that cannot complete commit/finalization replication returns 503 and freezes the primary read-only. A client may not know whether a timed-out mutation committed; reconcile by inspecting `/health` sequence/hash and the WAL before retrying non-idempotent operations. WAL entries contain Redis keys and values in plaintext; protect the data directory and backups with host-level encryption, strict access controls and retention. The hash chain detects inconsistent/tampered records only when compared against trusted state; it is not a signed, externally anchored tamper-proof log and there is no WAL compactor yet.
